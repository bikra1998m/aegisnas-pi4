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

const unifiSiteCollection = "/v1/sites"

type unifiWiFiSpec struct {
	Name            string
	SecurityType    string
	VLAN            int
	Hidden          bool
	ClientIsolation bool
	CoAEnabled      bool
}

type unifiWiFiResource struct {
	Name    string
	Payload map[string]any
}

type unifiClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

type unifiPage struct {
	Offset     int              `json:"offset"`
	Limit      int              `json:"limit"`
	Count      int              `json:"count"`
	TotalCount int              `json:"totalCount"`
	Data       []map[string]any `json:"data"`
}

func buildUniFiPreviewPayload(cfg *config.Config) map[string]any {
	specs, warnings, err := loadUniFiWiFiSpecs(cfg)
	items := make([]map[string]any, 0, len(specs))
	for _, spec := range specs {
		network := map[string]any{"type": "NATIVE"}
		if spec.VLAN > 0 {
			network = map[string]any{"type": "SPECIFIC", "vlanId": spec.VLAN}
		}
		items = append(items, map[string]any{
			"name": spec.Name,
			"payload": map[string]any{
				"type": "STANDARD", "name": spec.Name, "enabled": true, "network": network,
				"securityConfiguration": map[string]any{
					"type": spec.SecurityType, "radiusProfile": strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile),
					"nasIdSource": "DEVICE_MAC_ADDRESS", "coaEnabled": spec.CoAEnabled,
				},
				"clientIsolationEnabled": spec.ClientIsolation, "hideName": spec.Hidden,
			},
		})
	}
	payload := map[string]any{
		"adapter":   "unifi-network",
		"site_id":   strings.TrimSpace(cfg.Integrations.Controller.Site),
		"resources": items,
	}
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeUniFiOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	apiKey, err := unifiCredentials(cfg)
	if err != nil {
		return nil, err
	}
	specs, warnings, err := loadUniFiWiFiSpecs(cfg)
	if err != nil {
		return nil, err
	}
	targetURL, err := unifiTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &unifiClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "unifi-network",
		TargetURL:          targetURL,
		AuthScheme:         "api-key",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"site_id":        strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(specs),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}

	site := strings.TrimSpace(cfg.Integrations.Controller.Site)
	collectionPath := unifiWiFiCollectionPath(site)
	if len(specs) == 0 {
		if _, probeErr := client.listCollection(ctx, collectionPath); probeErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			result.CompatibilityScore = unifiCompatibilityScore(result.WarningCount, result.FailedCount)
			return result, probeErr
		}
	}

	radiusProfileID := ""
	if len(specs) > 0 {
		radiusProfileID, err = client.resolveRadiusProfile(ctx, site, cfg.Integrations.Controller.RadiusProfile)
		if err != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			result.CompatibilityScore = unifiCompatibilityScore(result.WarningCount, result.FailedCount)
			return result, err
		}
	}
	networkIDs, err := client.resolveNetworks(ctx, site, specs)
	if err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = unifiCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, err
	}
	resources := make([]unifiWiFiResource, 0, len(specs))
	for _, spec := range specs {
		resources = append(resources, unifiWiFiResource{
			Name: spec.Name, Payload: buildUniFiWiFiPayload(spec, radiusProfileID, networkIDs[spec.VLAN]),
		})
	}

	overviews, err := client.listCollection(ctx, collectionPath)
	if err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = unifiCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, err
	}
	byName := make(map[string]map[string]any, len(overviews))
	for _, overview := range overviews {
		name := firstNonEmptyString(overview["name"])
		if name == "" {
			continue
		}
		if _, exists := byName[name]; exists {
			warning := fmt.Sprintf("UniFi returned duplicate WiFi broadcast name %s; the first object was used.", name)
			warnings = append(warnings, warning)
			result.WarningCount++
			result.ResponseDetails["response_warnings"] = warnings
			continue
		}
		byName[name] = overview
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": resource.Payload})
		overview, found := byName[resource.Name]
		if !found {
			driftItems = append(driftItems, "wifi:"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, _, createErr := client.doJSON(ctx, http.MethodPost, collectionPath, resource.Payload); createErr != nil {
					result.FailedCount++
					continue
				}
				result.AppliedCount++
			}
			continue
		}
		id := firstNonEmptyString(overview["id"])
		if id == "" {
			result.FailedCount++
			driftItems = append(driftItems, "wifi:"+resource.Name+":missing-id")
			continue
		}
		detail, detailErr := client.getObject(ctx, collectionPath+"/"+url.PathEscape(id))
		if detailErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "wifi:"+resource.Name+":read-failed")
			continue
		}
		projected := projectControllerState(detail, resource.Payload)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": projected})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Payload}) {
			continue
		}
		driftItems = append(driftItems, "wifi:"+resource.Name+":changed")
		if operation == "push" {
			updatePayload := mergeUniFiWiFiUpdate(detail, resource.Payload)
			if _, _, updateErr := client.doJSON(ctx, http.MethodPut, collectionPath+"/"+url.PathEscape(id), updatePayload); updateErr != nil {
				result.FailedCount++
				continue
			}
			result.AppliedCount++
		}
	}

	desiredState := map[string]any{"wifi_broadcasts": desiredItems}
	observedState := map[string]any{"wifi_broadcasts": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = unifiCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("UniFi Network reconciliation applied %d WiFi broadcast(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("UniFi Network inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("UniFi Network operation failed for %d WiFi broadcast(s)", result.FailedCount)
	}
	return result, nil
}

func loadUniFiWiFiSpecs(cfg *config.Config) ([]unifiWiFiSpec, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	if strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile) == "" && unifiHasEnterpriseSSIDs(cfg) {
		return nil, nil, fmt.Errorf("UniFi enterprise WiFi sync requires integrations.controller.radius_profile")
	}
	specs := make([]unifiWiFiSpec, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("UniFi WiFi broadcast %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		if ssid.VLAN < 0 || ssid.VLAN > 4094 {
			return nil, warnings, fmt.Errorf("UniFi WiFi broadcast %q has VLAN %d outside the supported range", name, ssid.VLAN)
		}
		securityType := ""
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			securityType = "WPA2_ENTERPRISE"
		case "wpa3-enterprise":
			securityType = "WPA3_ENTERPRISE"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the UniFi adapter.", name, ssid.AuthMode))
			continue
		}
		specs = append(specs, unifiWiFiSpec{
			Name: name, SecurityType: securityType, VLAN: ssid.VLAN, Hidden: ssid.Hidden,
			ClientIsolation: ssid.ClientIsolation, CoAEnabled: cfg.Radius.DynamicAuth.Enabled,
		})
		if ssid.DynamicVLAN {
			warnings = append(warnings, fmt.Sprintf("SSID %s requests dynamic VLAN assignment; verify RADIUS VLAN behavior on the target UniFi Network release because the official WiFi API exposes only the fallback network reference.", name))
		}
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" || ssid.MaxClients > 0 {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, identity-source, or client-limit settings outside the current UniFi WiFi broadcast contract.", name))
		}
	}
	return specs, warnings, nil
}

func buildUniFiWiFiPayload(spec unifiWiFiSpec, radiusProfileID, networkID string) map[string]any {
	network := map[string]any{"type": "NATIVE"}
	if spec.VLAN > 0 {
		network = map[string]any{"type": "SPECIFIC", "networkId": networkID}
	}
	security := map[string]any{
		"type": spec.SecurityType,
		"radiusConfiguration": map[string]any{
			"profileId": radiusProfileID,
			"nasId":     map[string]any{"type": "DERIVED", "source": "DEVICE_MAC_ADDRESS"},
		},
		"coaEnabled": spec.CoAEnabled,
	}
	if spec.SecurityType == "WPA3_ENTERPRISE" {
		security["securityMode"] = "DEFAULT"
	} else {
		security["pmfMode"] = "OPTIONAL"
	}
	return map[string]any{
		"type": "STANDARD", "name": spec.Name, "network": network, "enabled": true,
		"securityConfiguration":               security,
		"multicastToUnicastConversionEnabled": false,
		"clientIsolationEnabled":              spec.ClientIsolation,
		"hideName":                            spec.Hidden,
		"uapsdEnabled":                        true,
	}
}

func mergeUniFiWiFiUpdate(existing, desired map[string]any) map[string]any {
	merged := cloneControllerMap(existing)
	delete(merged, "id")
	delete(merged, "metadata")
	for key, value := range desired {
		if key != "securityConfiguration" {
			merged[key] = value
		}
	}
	desiredSecurity, _ := desired["securityConfiguration"].(map[string]any)
	existingSecurity, _ := existing["securityConfiguration"].(map[string]any)
	if firstNonEmptyString(existingSecurity["type"]) != firstNonEmptyString(desiredSecurity["type"]) {
		merged["securityConfiguration"] = desiredSecurity
		return merged
	}
	security := cloneControllerMap(existingSecurity)
	for key, value := range desiredSecurity {
		security[key] = value
	}
	merged["securityConfiguration"] = security
	return merged
}

func unifiCredentials(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	tokenEnv := strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if tokenEnv == "" || token == "" {
		return "", fmt.Errorf("UniFi Network API key environment variable %q must be present", tokenEnv)
	}
	return token, nil
}

func unifiHasEnterpriseSSIDs(cfg *config.Config) bool {
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

func unifiTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	site := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if site == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "unifi")
	}
	return base + unifiWiFiCollectionPath(site), nil
}

func unifiWiFiCollectionPath(site string) string {
	return unifiSiteCollection + "/" + url.PathEscape(strings.TrimSpace(site)) + "/wifi/broadcasts"
}

func unifiRadiusCollectionPath(site string) string {
	return unifiSiteCollection + "/" + url.PathEscape(strings.TrimSpace(site)) + "/radius/profiles"
}

func unifiNetworkCollectionPath(site string) string {
	return unifiSiteCollection + "/" + url.PathEscape(strings.TrimSpace(site)) + "/networks"
}

func (c *unifiClient) resolveRadiusProfile(ctx context.Context, site, profileName string) (string, error) {
	profiles, err := c.listCollection(ctx, unifiRadiusCollectionPath(site))
	if err != nil {
		return "", err
	}
	profileName = strings.TrimSpace(profileName)
	profileID := ""
	for _, profile := range profiles {
		if firstNonEmptyString(profile["name"]) != profileName {
			continue
		}
		if profileID != "" {
			return "", fmt.Errorf("UniFi returned more than one RADIUS profile named %q", profileName)
		}
		profileID = firstNonEmptyString(profile["id"])
	}
	if profileID == "" {
		return "", fmt.Errorf("UniFi RADIUS profile %q was not found in site %q", profileName, site)
	}
	return profileID, nil
}

func (c *unifiClient) resolveNetworks(ctx context.Context, site string, specs []unifiWiFiSpec) (map[int]string, error) {
	required := make(map[int]struct{})
	for _, spec := range specs {
		if spec.VLAN > 0 {
			required[spec.VLAN] = struct{}{}
		}
	}
	resolved := make(map[int]string, len(required))
	if len(required) == 0 {
		return resolved, nil
	}
	networks, err := c.listCollection(ctx, unifiNetworkCollectionPath(site))
	if err != nil {
		return nil, err
	}
	for _, network := range networks {
		vlan, ok := controllerInt(network["vlanId"])
		if !ok {
			continue
		}
		if _, wanted := required[vlan]; !wanted {
			continue
		}
		if resolved[vlan] != "" {
			return nil, fmt.Errorf("UniFi returned more than one network for VLAN %d", vlan)
		}
		resolved[vlan] = firstNonEmptyString(network["id"])
	}
	for vlan := range required {
		if resolved[vlan] == "" {
			return nil, fmt.Errorf("UniFi network for VLAN %d was not found in site %q", vlan, site)
		}
	}
	return resolved, nil
}

func controllerInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), typed == float64(int(typed))
	case int:
		return typed, true
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (c *unifiClient) listCollection(ctx context.Context, collection string) ([]map[string]any, error) {
	const pageSize = 100
	items := make([]map[string]any, 0)
	for offset := 0; offset < 100000; offset += pageSize {
		path := collection + "?offset=" + strconv.Itoa(offset) + "&limit=" + strconv.Itoa(pageSize)
		body, _, err := c.doJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var page unifiPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode UniFi collection %s: %w", collection, err)
		}
		items = append(items, page.Data...)
		if len(page.Data) == 0 || len(items) >= page.TotalCount || len(page.Data) < pageSize {
			return items, nil
		}
	}
	return nil, fmt.Errorf("UniFi collection %s pagination exceeded 100000 records", collection)
}

func (c *unifiClient) getObject(ctx context.Context, path string) (map[string]any, error) {
	body, _, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		return nil, fmt.Errorf("decode UniFi object %s: %w", path, err)
	}
	return object, nil
}

func (c *unifiClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
		req.Header.Set("X-API-Key", c.apiKey)
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
		retryableMethod := method == http.MethodGet || method == http.MethodPut
		if retryableMethod && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
			if err := waitForControllerRetry(ctx, resp.Header.Get("Retry-After"), 2*time.Second); err != nil {
				return body, resp.StatusCode, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			summary := strings.ReplaceAll(strings.TrimSpace(string(body)), c.apiKey, "[redacted]")
			return body, resp.StatusCode, fmt.Errorf("UniFi Network %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("UniFi Network request remained unavailable after retry")
}

func unifiCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
