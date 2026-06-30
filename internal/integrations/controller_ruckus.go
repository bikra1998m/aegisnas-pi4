package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const ruckusSmartZoneAPIBase = "/wsg/api/public/v13_1"

type ruckusSmartZoneWLANResource struct {
	Name    string
	Payload map[string]any
}

type ruckusSmartZoneClient struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

type ruckusSmartZoneWLANList struct {
	TotalCount int              `json:"totalCount"`
	HasMore    bool             `json:"hasMore"`
	FirstIndex int              `json:"firstIndex"`
	List       []map[string]any `json:"list"`
}

func buildRuckusSmartZonePreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadRuckusSmartZoneWLANResources(cfg)
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{"name": resource.Name, "payload": resource.Payload})
	}
	payload := map[string]any{
		"adapter":                "ruckus-smartzone",
		"api_version":            "v13_1",
		"zone_id":                strings.TrimSpace(cfg.Integrations.Controller.Site),
		"authentication_service": strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile),
		"resources":              items,
	}
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeRuckusSmartZoneOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	username, password, err := ruckusSmartZoneCredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadRuckusSmartZoneWLANResources(cfg)
	if err != nil {
		return nil, err
	}
	targetURL, err := ruckusSmartZoneTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	jar, _ := cookiejar.New(nil)
	client := &ruckusSmartZoneClient{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		username: username,
		password: password,
		http:     &http.Client{Timeout: 15 * time.Second, Jar: jar},
	}
	result := &controllerSyncResult{
		Adapter:            "ruckus-smartzone",
		TargetURL:          targetURL,
		AuthScheme:         "session",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"api_version":    "v13_1",
			"zone_id":        strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(resources),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}
	if err := client.login(ctx); err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		return result, err
	}
	defer client.logout()

	observedWLANs, listWarnings, err := client.listZoneWLANs(ctx, cfg.Integrations.Controller.Site)
	if err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		return result, err
	}
	if len(listWarnings) > 0 {
		result.WarningCount += len(listWarnings)
		warnings = append(warnings, listWarnings...)
		result.ResponseDetails["response_warnings"] = warnings
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	collectionPath := ruckusSmartZoneWLANPath(cfg.Integrations.Controller.Site)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": resource.Payload})
		summary, found := observedWLANs[resource.Name]
		if !found {
			driftItems = append(driftItems, "wlan:"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, _, createErr := client.doJSON(ctx, http.MethodPost, collectionPath+"/standard8021X", resource.Payload); createErr != nil {
					result.FailedCount++
					continue
				}
				result.AppliedCount++
			}
			continue
		}
		id := firstNonEmptyString(summary["id"])
		if id == "" {
			result.FailedCount++
			driftItems = append(driftItems, "wlan:"+resource.Name+":missing-id")
			continue
		}
		body, _, readErr := client.doJSON(ctx, http.MethodGet, collectionPath+"/"+url.PathEscape(id), nil)
		if readErr != nil {
			result.FailedCount++
			driftItems = append(driftItems, "wlan:"+resource.Name+":read-failed")
			continue
		}
		var observed map[string]any
		if err := json.Unmarshal(body, &observed); err != nil {
			result.FailedCount++
			driftItems = append(driftItems, "wlan:"+resource.Name+":decode-failed")
			continue
		}
		projected := projectControllerState(observed, resource.Payload)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": projected})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Payload}) {
			continue
		}
		driftItems = append(driftItems, "wlan:"+resource.Name+":changed")
		if operation == "push" {
			if _, _, updateErr := client.doJSON(ctx, http.MethodPatch, collectionPath+"/"+url.PathEscape(id), resource.Payload); updateErr != nil {
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
	result.CompatibilityScore = ruckusSmartZoneCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("Ruckus SmartZone reconciliation applied %d WLAN resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("Ruckus SmartZone inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("Ruckus SmartZone operation failed for %d WLAN resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadRuckusSmartZoneWLANResources(cfg *config.Config) ([]ruckusSmartZoneWLANResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	authService := strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile)
	resources := make([]ruckusSmartZoneWLANResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("Ruckus SmartZone WLAN %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		encryption := map[string]any{}
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			encryption = map[string]any{"method": "WPA2", "algorithm": "AES", "mfp": "disabled"}
		case "wpa3-enterprise":
			encryption = map[string]any{"method": "WPA3"}
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the Ruckus SmartZone adapter.", name, ssid.AuthMode))
			continue
		}
		if authService == "" {
			return nil, warnings, fmt.Errorf("Ruckus SmartZone enterprise WLAN sync requires integrations.controller.radius_profile")
		}
		advanced := map[string]any{
			"hideSsidEnabled":                 ssid.Hidden,
			"clientIsolationEnabled":          ssid.ClientIsolation,
			"clientIsolationUnicastEnabled":   ssid.ClientIsolation,
			"clientIsolationMulticastEnabled": ssid.ClientIsolation,
		}
		if ssid.MaxClients > 0 {
			advanced["maxClientsPerRadio"] = ssid.MaxClients
		}
		wlan := map[string]any{
			"name":                 name,
			"ssid":                 name,
			"description":          "Managed by AegisNAS",
			"accessTunnelType":     "APLBO",
			"encryption":           encryption,
			"authServiceOrProfile": map[string]any{"throughController": false, "name": authService},
			"advancedOptions":      advanced,
		}
		if ssid.VLAN > 0 || ssid.DynamicVLAN {
			vlan := map[string]any{"aaaVlanOverride": ssid.DynamicVLAN}
			if ssid.VLAN > 0 {
				vlan["accessVlan"] = ssid.VLAN
			}
			wlan["vlan"] = vlan
		}
		resources = append(resources, ruckusSmartZoneWLANResource{Name: name, Payload: wlan})
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, or identity-source settings outside the current Ruckus SmartZone WLAN contract.", name))
		}
	}
	return resources, warnings, nil
}

func ruckusSmartZoneCredentials(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", fmt.Errorf("controller config is required")
	}
	usernameEnv := strings.TrimSpace(cfg.Integrations.Controller.APIUsernameEnv)
	passwordEnv := strings.TrimSpace(cfg.Integrations.Controller.APIPasswordEnv)
	username := strings.TrimSpace(os.Getenv(usernameEnv))
	password := os.Getenv(passwordEnv)
	if usernameEnv == "" || passwordEnv == "" || username == "" || password == "" {
		return "", "", fmt.Errorf("Ruckus SmartZone credential environment variables %q and %q must both be present", usernameEnv, passwordEnv)
	}
	return username, password, nil
}

func ruckusSmartZoneTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	zone := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if zone == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "ruckus")
	}
	return base + ruckusSmartZoneWLANPath(zone), nil
}

func ruckusSmartZoneWLANPath(zone string) string {
	return ruckusSmartZoneAPIBase + "/rkszones/" + url.PathEscape(strings.TrimSpace(zone)) + "/wlans"
}

func (c *ruckusSmartZoneClient) login(ctx context.Context) error {
	_, _, err := c.doJSON(ctx, http.MethodPost, ruckusSmartZoneAPIBase+"/session", map[string]any{
		"username": c.username, "password": c.password, "timeZoneUtcOffset": "+00:00",
	})
	return err
}

func (c *ruckusSmartZoneClient) logout() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = c.doJSON(ctx, http.MethodDelete, ruckusSmartZoneAPIBase+"/session", nil)
}

func (c *ruckusSmartZoneClient) listZoneWLANs(ctx context.Context, zone string) (map[string]map[string]any, []string, error) {
	const pageSize = 1000
	index := 0
	byName := make(map[string]map[string]any)
	warnings := make([]string, 0)
	for page := 0; page < 100; page++ {
		path := ruckusSmartZoneWLANPath(zone) + "?index=" + strconv.Itoa(index) + "&listSize=" + strconv.Itoa(pageSize)
		body, _, err := c.doJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, warnings, err
		}
		var response ruckusSmartZoneWLANList
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, warnings, fmt.Errorf("decode Ruckus SmartZone WLAN list: %w", err)
		}
		for _, wlan := range response.List {
			name := firstNonEmptyString(wlan["name"], wlan["ssid"])
			if name == "" {
				continue
			}
			if _, exists := byName[name]; exists {
				warnings = append(warnings, fmt.Sprintf("SmartZone returned duplicate WLAN name %s; the first object was used.", name))
				continue
			}
			byName[name] = wlan
		}
		index += len(response.List)
		if !response.HasMore {
			return byName, warnings, nil
		}
		if len(response.List) == 0 {
			return nil, warnings, fmt.Errorf("Ruckus SmartZone WLAN pagination reported more data without returning entries")
		}
	}
	return nil, warnings, fmt.Errorf("Ruckus SmartZone WLAN pagination exceeded 100 pages")
}

func (c *ruckusSmartZoneClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
			summary := strings.TrimSpace(string(body))
			for _, sensitive := range []string{c.username, c.password} {
				if sensitive != "" {
					summary = strings.ReplaceAll(summary, sensitive, "[redacted]")
				}
			}
			return body, resp.StatusCode, fmt.Errorf("Ruckus SmartZone %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("Ruckus SmartZone request remained rate limited")
}

func ruckusSmartZoneCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
