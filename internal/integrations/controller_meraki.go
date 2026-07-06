package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type merakiSSIDResource struct {
	Name    string
	Payload map[string]any
}

type merakiClient struct {
	baseURL      string
	apiKey       string
	radiusSecret string
	http         *http.Client
}

func buildMerakiPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadMerakiSSIDResources(cfg, "redacted")
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{
			"name":    resource.Name,
			"payload": resource.Payload,
		})
	}
	payload := map[string]any{
		"adapter":     "cisco-meraki-dashboard",
		"network_id":  strings.TrimSpace(cfg.Integrations.Controller.Site),
		"resources":   items,
		"slot_policy": "match-existing-name",
	}
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeMerakiOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	apiKey, radiusSecret, err := merakiCredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadMerakiSSIDResources(cfg, radiusSecret)
	if err != nil {
		return nil, err
	}
	targetURL, err := merakiTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &merakiClient{
		baseURL:      strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		apiKey:       apiKey,
		radiusSecret: radiusSecret,
		http:         &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "cisco-meraki-dashboard",
		TargetURL:          targetURL,
		AuthScheme:         "api-key",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":        true,
			"network_id":        strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count":    len(resources),
			"slot_policy":       "match-existing-name",
			"write_only_secret": true,
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}

	networkID := strings.TrimSpace(cfg.Integrations.Controller.Site)
	collectionPath := merakiSSIDCollectionPath(networkID)
	observed, err := client.listSSIDs(ctx, collectionPath)
	if err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = merakiCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, err
	}
	byName := make(map[string]map[string]any, len(observed))
	for _, ssid := range observed {
		name := firstNonEmptyString(ssid["name"])
		if name == "" {
			continue
		}
		if _, exists := byName[name]; exists {
			warning := fmt.Sprintf("Meraki returned duplicate SSID name %s; the first slot was used.", name)
			warnings = append(warnings, warning)
			result.WarningCount++
			result.ResponseDetails["response_warnings"] = warnings
			continue
		}
		byName[name] = ssid
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	secretRefreshCount := 0
	for _, resource := range resources {
		comparableDesired := merakiComparablePayload(resource.Payload)
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": comparableDesired})
		current, found := byName[resource.Name]
		if !found {
			driftItems = append(driftItems, "ssid:"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"name": resource.Name, "state": "missing"})
			if operation == "push" {
				result.FailedCount++
			}
			continue
		}

		number, ok := controllerInt(current["number"])
		if !ok || number < 0 {
			driftItems = append(driftItems, "ssid:"+resource.Name+":invalid-number")
			result.FailedCount++
			continue
		}
		projected := projectControllerState(current, comparableDesired)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": projected})
		changed := controllerDesiredStateHash(map[string]any{"value": projected}) != controllerDesiredStateHash(map[string]any{"value": comparableDesired})
		if changed {
			driftItems = append(driftItems, "ssid:"+resource.Name+":changed")
		}
		if operation != "push" {
			continue
		}

		// Dashboard reads intentionally omit RADIUS secrets. Refresh every matched
		// SSID on push so secret rotation remains deterministic and auditable.
		path := collectionPath + "/" + strconv.Itoa(number)
		if _, _, updateErr := client.doJSON(ctx, http.MethodPut, path, resource.Payload); updateErr != nil {
			result.FailedCount++
			continue
		}
		result.AppliedCount++
		if !changed {
			secretRefreshCount++
		}
	}

	desiredState := map[string]any{"ssids": desiredItems}
	observedState := map[string]any{"ssids": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = merakiCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if secretRefreshCount > 0 {
		result.ResponseDetails["write_only_secret_refresh_count"] = secretRefreshCount
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("Meraki Dashboard reconciliation refreshed %d SSID slot(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("Meraki Dashboard inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("Meraki Dashboard operation failed for %d SSID resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadMerakiSSIDResources(cfg *config.Config, secret string) ([]merakiSSIDResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	radiusServer := strings.TrimSpace(cfg.Integrations.Controller.RadiusServer)
	resources := make([]merakiSSIDResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("Meraki SSID %q is configured more than once", name)
		}
		seen[name] = struct{}{}

		wpaMode := ""
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			wpaMode = "WPA2 only"
		case "wpa3-enterprise":
			wpaMode = "WPA3 only"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the Meraki adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusServer == "" || secret == "" {
			return nil, warnings, fmt.Errorf("Meraki enterprise SSID sync requires integrations.controller.radius_server and a configured radius_secret_env")
		}
		if ssid.VLAN < 0 || ssid.VLAN > 4094 {
			return nil, warnings, fmt.Errorf("Meraki SSID %q has VLAN %d outside the supported range", name, ssid.VLAN)
		}

		payload := map[string]any{
			"name":                    name,
			"enabled":                 true,
			"authMode":                "8021x-radius",
			"encryptionMode":          "wpa",
			"wpaEncryptionMode":       wpaMode,
			"visible":                 !ssid.Hidden,
			"lanIsolationEnabled":     ssid.ClientIsolation,
			"radiusServers":           []map[string]any{{"host": radiusServer, "port": cfg.Radius.AuthPort, "secret": secret}},
			"radiusAccountingEnabled": true,
			"radiusAccountingServers": []map[string]any{{"host": radiusServer, "port": cfg.Radius.AcctPort, "secret": secret}},
			"radiusCoaEnabled":        cfg.Radius.DynamicAuth.Enabled,
		}
		if wpaMode == "WPA3 only" {
			payload["dot11w"] = map[string]any{"enabled": true, "required": true}
		}
		if ssid.VLAN > 0 || ssid.DynamicVLAN {
			payload["ipAssignmentMode"] = "Bridge mode"
			payload["useVlanTagging"] = true
		}
		if ssid.VLAN > 0 {
			payload["defaultVlanId"] = ssid.VLAN
		}
		if ssid.DynamicVLAN {
			payload["radiusOverride"] = true
		}
		resources = append(resources, merakiSSIDResource{Name: name, Payload: payload})
		if ssid.MaxClients > 0 || ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has client-limit, portal, bandwidth, or identity-source settings outside the current Meraki SSID contract.", name))
		}
	}
	return resources, warnings, nil
}

func merakiCredentials(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", fmt.Errorf("controller config is required")
	}
	apiKeyEnv := strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)
	radiusSecretEnv := strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv)
	apiKey := strings.TrimSpace(os.Getenv(apiKeyEnv))
	radiusSecret := os.Getenv(radiusSecretEnv)
	if apiKeyEnv == "" || apiKey == "" {
		return "", "", fmt.Errorf("Meraki Dashboard API key environment variable %q must be present", apiKeyEnv)
	}
	if merakiHasEnterpriseSSIDs(cfg) && (radiusSecretEnv == "" || radiusSecret == "") {
		return "", "", fmt.Errorf("Meraki RADIUS secret environment variable %q must be present", radiusSecretEnv)
	}
	return apiKey, radiusSecret, nil
}

func merakiHasEnterpriseSSIDs(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise", "wpa3-enterprise":
			return true
		}
	}
	return false
}

func merakiTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	networkID := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if networkID == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "meraki")
	}
	return base + merakiSSIDCollectionPath(networkID), nil
}

func merakiSSIDCollectionPath(networkID string) string {
	return "/networks/" + url.PathEscape(strings.TrimSpace(networkID)) + "/wireless/ssids"
}

func merakiComparablePayload(payload map[string]any) map[string]any {
	comparable, _ := stripMerakiSecrets(payload).(map[string]any)
	return comparable
}

func stripMerakiSecrets(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			if strings.EqualFold(strings.TrimSpace(key), "secret") {
				continue
			}
			out[key] = stripMerakiSecrets(nested)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, nested := range typed {
			cleaned, _ := stripMerakiSecrets(nested).(map[string]any)
			out = append(out, cleaned)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			out = append(out, stripMerakiSecrets(nested))
		}
		return out
	default:
		return value
	}
}

func (c *merakiClient) listSSIDs(ctx context.Context, path string) ([]map[string]any, error) {
	body, _, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("decode Meraki SSID collection %s: %w", path, err)
	}
	return items, nil
}

func (c *merakiClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
		req.Header.Set("X-Cisco-Meraki-API-Key", c.apiKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, 0, err
		}
		body, readErr := ioReadAllLimit(resp, 10<<20)
		resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}
		if (method == http.MethodGet || method == http.MethodPut) && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
			if err := waitForControllerRetry(ctx, resp.Header.Get("Retry-After"), 2*time.Second); err != nil {
				return body, resp.StatusCode, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			summary := strings.TrimSpace(string(body))
			for _, sensitive := range []string{c.apiKey, c.radiusSecret} {
				if sensitive != "" {
					summary = strings.ReplaceAll(summary, sensitive, "[redacted]")
				}
			}
			return body, resp.StatusCode, fmt.Errorf("Meraki Dashboard %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("Meraki Dashboard request remained unavailable after retry")
}

func merakiCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
