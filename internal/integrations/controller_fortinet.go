package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const fortiGateVAPCollection = "/api/v2/cmdb/wireless-controller/vap"

type fortiGateVAPResource struct {
	Name    string
	Payload map[string]any
}

type fortiGateClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func buildFortiGatePreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadFortiGateVAPResources(cfg)
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{"name": resource.Name, "payload": resource.Payload})
	}
	payload := map[string]any{
		"adapter":        "fortinet-fortigate",
		"vdom":           strings.TrimSpace(cfg.Integrations.Controller.Site),
		"radius_profile": strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile),
		"resources":      items,
	}
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeFortiGateOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	token := controllerToken(cfg)
	if token == "" {
		return nil, fmt.Errorf("controller API token env %q is empty", strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv))
	}
	resources, warnings, err := loadFortiGateVAPResources(cfg)
	if err != nil {
		return nil, err
	}
	targetURL, err := fortiGateTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &fortiGateClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "fortinet-fortigate",
		TargetURL:          targetURL,
		AuthScheme:         "bearer",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"vdom":           strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(resources),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}
	if len(resources) == 0 {
		if _, _, probeErr := client.doJSON(ctx, http.MethodGet, fortiGateVAPPath(cfg.Integrations.Controller.Site, ""), nil); probeErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			return result, probeErr
		}
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": resource.Payload})
		path := fortiGateVAPPath(cfg.Integrations.Controller.Site, resource.Name)
		body, status, readErr := client.doJSON(ctx, http.MethodGet, path, nil)
		if readErr != nil && status == http.StatusNotFound {
			driftItems = append(driftItems, "vap:"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, _, createErr := client.doJSON(ctx, http.MethodPost, fortiGateVAPPath(cfg.Integrations.Controller.Site, ""), resource.Payload); createErr != nil {
					result.FailedCount++
					continue
				}
				result.AppliedCount++
			}
			continue
		}
		if readErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "vap:"+resource.Name+":read-failed")
			continue
		}
		observed, decodeErr := decodeFortiGateResult(body)
		if decodeErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "vap:"+resource.Name+":decode-failed")
			continue
		}
		projected := projectControllerState(observed, resource.Payload)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": projected})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Payload}) {
			continue
		}
		driftItems = append(driftItems, "vap:"+resource.Name+":changed")
		if operation == "push" {
			if _, _, updateErr := client.doJSON(ctx, http.MethodPut, path, resource.Payload); updateErr != nil {
				result.FailedCount++
				continue
			}
			result.AppliedCount++
		}
	}

	desiredState := map[string]any{"vaps": desiredItems}
	observedState := map[string]any{"vaps": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = fortiGateCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("FortiGate reconciliation applied %d VAP resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("FortiGate inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("FortiGate operation failed for %d VAP resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadFortiGateVAPResources(cfg *config.Config) ([]fortiGateVAPResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	radiusProfile := strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile)
	resources := make([]fortiGateVAPResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("FortiGate VAP %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		var security string
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			security = "wpa2-only-enterprise"
		case "wpa3-enterprise":
			security = "wpa3-only-enterprise"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the FortiGate adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusProfile == "" {
			return nil, warnings, fmt.Errorf("FortiGate enterprise VAP sync requires integrations.controller.radius_profile")
		}
		payload := map[string]any{
			"name":              name,
			"ssid":              name,
			"security":          security,
			"auth":              "radius",
			"radius-server":     radiusProfile,
			"broadcast-ssid":    fortiGateToggle(!ssid.Hidden),
			"dynamic-vlan":      fortiGateToggle(ssid.DynamicVLAN),
			"intra-vap-privacy": fortiGateToggle(ssid.ClientIsolation),
			"max-clients":       ssid.MaxClients,
			"vlanid":            ssid.VLAN,
		}
		resources = append(resources, fortiGateVAPResource{Name: name, Payload: payload})
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, or identity-source settings outside the current FortiGate VAP contract.", name))
		}
	}
	return resources, warnings, nil
}

func fortiGateToggle(enabled bool) string {
	if enabled {
		return "enable"
	}
	return "disable"
}

func fortiGateTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	vdom := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if vdom == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "fortinet")
	}
	return base + fortiGateVAPPath(vdom, ""), nil
}

func fortiGateVAPPath(vdom, name string) string {
	path := fortiGateVAPCollection
	if strings.TrimSpace(name) != "" {
		path += "/" + url.PathEscape(strings.TrimSpace(name))
	}
	query := url.Values{}
	query.Set("vdom", strings.TrimSpace(vdom))
	return path + "?" + query.Encode()
}

func decodeFortiGateResult(body []byte) (map[string]any, error) {
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode FortiGate CMDB response: %w", err)
	}
	switch results := envelope["results"].(type) {
	case map[string]any:
		return results, nil
	case []any:
		if len(results) == 0 {
			return nil, fmt.Errorf("decode FortiGate CMDB response: empty results")
		}
		result, ok := results[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decode FortiGate CMDB response: invalid result object")
		}
		return result, nil
	default:
		return nil, fmt.Errorf("decode FortiGate CMDB response: missing results")
	}
}

func (c *fortiGateClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
	var encoded []byte
	var err error
	if payload != nil {
		encoded, err = json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(encoded))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, 0, err
		}
		body, readErr := ioReadAllLimit(resp, 4<<20)
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			if err := waitForControllerRetry(ctx, resp.Header.Get("Retry-After"), 2*time.Second); err != nil {
				return body, resp.StatusCode, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			summary := strings.ReplaceAll(strings.TrimSpace(string(body)), c.token, "[redacted]")
			return body, resp.StatusCode, fmt.Errorf("FortiGate %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("FortiGate request remained rate limited")
}

func fortiGateCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
