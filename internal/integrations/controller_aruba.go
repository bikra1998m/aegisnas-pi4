package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const (
	arubaCentralWLANCollection = "/configuration/v2/wlan"
	arubaCentralWLANList       = "/configuration/v1/wlan"
)

type arubaCentralWLANResource struct {
	Name    string
	Payload map[string]any
}

type arubaCentralClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func buildArubaCentralPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadArubaCentralWLANResources(cfg)
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{
			"name":    resource.Name,
			"path":    arubaCentralWLANPath(cfg.Integrations.Controller.Site, resource.Name),
			"payload": resource.Payload,
		})
	}
	payload := map[string]any{
		"adapter":        "aruba-central-classic",
		"group":          strings.TrimSpace(cfg.Integrations.Controller.Site),
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

func executeArubaCentralOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	token := controllerToken(cfg)
	if token == "" {
		return nil, fmt.Errorf("controller API token env %q is empty", strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv))
	}
	resources, warnings, err := loadArubaCentralWLANResources(cfg)
	if err != nil {
		return nil, err
	}
	targetURL, err := arubaCentralTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &arubaCentralClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "aruba-central-classic",
		TargetURL:          targetURL,
		AuthScheme:         "bearer",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"group":          strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(resources),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}

	if len(resources) == 0 {
		path := arubaCentralWLANList + "/" + url.PathEscape(strings.TrimSpace(cfg.Integrations.Controller.Site))
		if _, _, probeErr := client.doJSON(ctx, http.MethodGet, path, nil); probeErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			result.CompatibilityScore = arubaCentralCompatibilityScore(result.WarningCount, result.FailedCount)
			return result, probeErr
		}
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": resource.Payload})
		path := arubaCentralWLANPath(cfg.Integrations.Controller.Site, resource.Name)
		body, status, readErr := client.doJSON(ctx, http.MethodGet, path, nil)
		if readErr != nil && arubaCentralWLANMissing(status, body) {
			driftItems = append(driftItems, "wlan:"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, _, createErr := client.doJSON(ctx, http.MethodPost, path, resource.Payload); createErr != nil {
					result.FailedCount++
					continue
				}
				result.AppliedCount++
			}
			continue
		}
		if readErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "wlan:"+resource.Name+":read-failed")
			continue
		}
		observedWLAN, decodeErr := decodeArubaCentralWLAN(body)
		if decodeErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "wlan:"+resource.Name+":decode-failed")
			continue
		}
		desiredWLAN := resource.Payload["wlan"].(map[string]any)
		projected := projectControllerState(observedWLAN, desiredWLAN)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": map[string]any{"wlan": projected}})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": desiredWLAN}) {
			continue
		}
		driftItems = append(driftItems, "wlan:"+resource.Name+":changed")
		if operation == "push" {
			if _, _, updateErr := client.doJSON(ctx, http.MethodPut, path, resource.Payload); updateErr != nil {
				result.FailedCount++
				continue
			}
			result.AppliedCount++
		}
	}

	desiredState := map[string]any{"wlans": desiredItems}
	observedState := map[string]any{"wlans": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = arubaCentralCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("Aruba Central reconciliation applied %d WLAN resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("Aruba Central inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("Aruba Central operation failed for %d WLAN resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadArubaCentralWLANResources(cfg *config.Config) ([]arubaCentralWLANResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	radiusProfile := strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile)
	resources := make([]arubaCentralWLANResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		var opmode string
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			opmode = "wpa2-aes"
		case "wpa3-enterprise":
			opmode = "wpa3-aes-ccm-128"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the Aruba Central adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusProfile == "" {
			return nil, warnings, fmt.Errorf("Aruba Central enterprise WLAN sync requires integrations.controller.radius_profile")
		}
		vlan := ""
		if ssid.VLAN > 0 {
			vlan = strconv.Itoa(ssid.VLAN)
		}
		wlan := map[string]any{
			"name":                   name,
			"essid":                  name,
			"type":                   "employee",
			"opmode":                 opmode,
			"vlan":                   vlan,
			"hide_ssid":              ssid.Hidden,
			"auth_server1":           radiusProfile,
			"accounting_server1":     radiusProfile,
			"radius_accounting":      true,
			"radius_accounting_mode": "user-authentication",
			"download_role":          true,
		}
		resources = append(resources, arubaCentralWLANResource{Name: name, Payload: map[string]any{"wlan": wlan}})
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.MaxClients > 0 || ssid.ClientIsolation {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, client-limit, or isolation settings outside the current Aruba Central WLAN contract.", name))
		}
	}
	return resources, warnings, nil
}

func arubaCentralTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	group := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if group == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "aruba")
	}
	return base + arubaCentralWLANCollection + "/" + url.PathEscape(group), nil
}

func arubaCentralWLANPath(group, wlan string) string {
	return arubaCentralWLANCollection + "/" + url.PathEscape(strings.TrimSpace(group)) + "/" + url.PathEscape(strings.TrimSpace(wlan))
}

func decodeArubaCentralWLAN(body []byte) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode Aruba Central WLAN response: %w", err)
	}
	wlan, ok := payload["wlan"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("decode Aruba Central WLAN response: missing wlan object")
	}
	return wlan, nil
}

func arubaCentralWLANMissing(status int, body []byte) bool {
	if status == http.StatusNotFound {
		return true
	}
	if status != http.StatusBadRequest {
		return false
	}
	message := strings.ToLower(string(body))
	return strings.Contains(message, "not found") || strings.Contains(message, "does not exist") || strings.Contains(message, "doesn't exist")
}

func (c *arubaCentralClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
			if err := waitForArubaCentralRetry(ctx, resp.Header.Get("Retry-After")); err != nil {
				return body, resp.StatusCode, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return body, resp.StatusCode, fmt.Errorf("Aruba Central %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("Aruba Central request remained rate limited")
}

func waitForArubaCentralRetry(ctx context.Context, value string) error {
	delay := time.Second
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	} else if retryAt, err := http.ParseTime(value); err == nil {
		delay = time.Until(retryAt)
	}
	if delay < 0 {
		delay = 0
	}
	if delay > 2*time.Second {
		delay = 2 * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func arubaCentralCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
