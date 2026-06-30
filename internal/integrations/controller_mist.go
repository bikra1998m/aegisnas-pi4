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

const mistSiteWLANCollection = "/api/v1/sites"

type mistWLANResource struct {
	Name    string
	Payload map[string]any
}

type mistClient struct {
	baseURL string
	token   string
	secret  string
	http    *http.Client
}

func buildMistPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadMistWLANResources(cfg, "redacted")
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{"name": resource.Name, "payload": resource.Payload})
	}
	payload := map[string]any{
		"adapter":   "juniper-mist",
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

func executeMistOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	token, secret, err := mistCredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadMistWLANResources(cfg, secret)
	if err != nil {
		return nil, err
	}
	targetURL, err := mistTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &mistClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		token:   token,
		secret:  secret,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "juniper-mist",
		TargetURL:          targetURL,
		AuthScheme:         "token",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"site_id":        strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(resources),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}

	observedWLANs, listWarnings, listErr := client.listSiteWLANs(ctx, cfg.Integrations.Controller.Site)
	if listErr != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = mistCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, listErr
	}
	if len(listWarnings) > 0 {
		result.WarningCount += len(listWarnings)
		warnings = append(warnings, listWarnings...)
		result.ResponseDetails["response_warnings"] = warnings
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	collectionPath := mistSiteWLANPath(cfg.Integrations.Controller.Site)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{"name": resource.Name, "payload": resource.Payload})
		observed, found := observedWLANs[resource.Name]
		if !found {
			driftItems = append(driftItems, "wlan:"+resource.Name+":missing")
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
		projected := projectControllerState(observed, resource.Payload)
		observedItems = append(observedItems, map[string]any{"name": resource.Name, "payload": projected})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Payload}) {
			continue
		}
		driftItems = append(driftItems, "wlan:"+resource.Name+":changed")
		if operation == "push" {
			id := firstNonEmptyString(observed["id"])
			if id == "" {
				result.FailedCount++
				continue
			}
			if _, _, updateErr := client.doJSON(ctx, http.MethodPut, collectionPath+"/"+url.PathEscape(id), resource.Payload); updateErr != nil {
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
	result.CompatibilityScore = mistCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("Juniper Mist reconciliation applied %d WLAN resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("Juniper Mist inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("Juniper Mist operation failed for %d WLAN resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadMistWLANResources(cfg *config.Config, secret string) ([]mistWLANResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	radiusServer := strings.TrimSpace(cfg.Integrations.Controller.RadiusServer)
	if strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv) == "" {
		secret = ""
	}
	resources := make([]mistWLANResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("Juniper Mist WLAN %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		var pairwise string
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			pairwise = "wpa2-ccmp"
		case "wpa3-enterprise":
			pairwise = "wpa3"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the Juniper Mist adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusServer == "" || secret == "" {
			return nil, warnings, fmt.Errorf("Juniper Mist enterprise WLAN sync requires integrations.controller.radius_server and a configured radius_secret_env")
		}
		wlan := map[string]any{
			"ssid":            name,
			"enabled":         true,
			"hide_ssid":       ssid.Hidden,
			"auth":            map[string]any{"type": "eap", "pairwise": []string{pairwise}},
			"auth_servers":    []map[string]any{{"host": radiusServer, "port": cfg.Radius.AuthPort, "secret": secret}},
			"acct_servers":    []map[string]any{{"host": radiusServer, "port": cfg.Radius.AcctPort, "secret": secret}},
			"isolation":       ssid.ClientIsolation,
			"max_num_clients": ssid.MaxClients,
			"vlan_enabled":    ssid.VLAN > 0 || ssid.DynamicVLAN,
		}
		if ssid.VLAN > 0 {
			wlan["vlan_id"] = ssid.VLAN
		}
		if ssid.DynamicVLAN {
			dynamic := map[string]any{"enabled": true, "type": "standard"}
			if ssid.VLAN > 0 {
				dynamic["default_vlan_ids"] = []int{ssid.VLAN}
			}
			wlan["dynamic_vlan"] = dynamic
		}
		if cfg.Radius.DynamicAuth.Enabled {
			wlan["coa_servers"] = []map[string]any{{
				"ip": radiusServer, "port": cfg.Radius.DynamicAuth.Port, "secret": secret, "enabled": true,
			}}
		}
		resources = append(resources, mistWLANResource{Name: name, Payload: wlan})
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, or identity-source settings outside the current Juniper Mist WLAN contract.", name))
		}
	}
	return resources, warnings, nil
}

func mistCredentials(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", fmt.Errorf("controller config is required")
	}
	tokenEnv := strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)
	secretEnv := strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv)
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	secret := os.Getenv(secretEnv)
	if tokenEnv == "" || token == "" {
		return "", "", fmt.Errorf("Juniper Mist API token environment variable %q must be present", tokenEnv)
	}
	if mistHasEnterpriseSSIDs(cfg) && (secretEnv == "" || secret == "") {
		return "", "", fmt.Errorf("Juniper Mist RADIUS secret environment variable %q must be present", secretEnv)
	}
	return token, secret, nil
}

func mistHasEnterpriseSSIDs(cfg *config.Config) bool {
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

func mistTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	site := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if site == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "juniper-mist")
	}
	return base + mistSiteWLANPath(site), nil
}

func mistSiteWLANPath(site string) string {
	return mistSiteWLANCollection + "/" + url.PathEscape(strings.TrimSpace(site)) + "/wlans"
}

func (c *mistClient) listSiteWLANs(ctx context.Context, site string) (map[string]map[string]any, []string, error) {
	const pageSize = 100
	byName := make(map[string]map[string]any)
	warnings := make([]string, 0)
	for page := 1; page <= 100; page++ {
		path := mistSiteWLANPath(site) + "?limit=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		body, _, err := c.doJSON(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, warnings, err
		}
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, warnings, fmt.Errorf("decode Juniper Mist WLAN list: %w", err)
		}
		for _, wlan := range batch {
			name := firstNonEmptyString(wlan["ssid"])
			if name == "" {
				continue
			}
			if _, exists := byName[name]; exists {
				warnings = append(warnings, fmt.Sprintf("Mist returned duplicate WLAN name %s; the first object was used.", name))
				continue
			}
			byName[name] = wlan
		}
		if len(batch) < pageSize {
			return byName, warnings, nil
		}
	}
	return nil, warnings, fmt.Errorf("Juniper Mist WLAN pagination exceeded 100 pages")
}

func (c *mistClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
		req.Header.Set("Authorization", "Token "+c.token)
		req.Header.Set("Accept", "application/json, application/vnd.api+json")
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
			for _, sensitive := range []string{c.token, c.secret} {
				if sensitive != "" {
					summary = strings.ReplaceAll(summary, sensitive, "[redacted]")
				}
			}
			return body, resp.StatusCode, fmt.Errorf("Juniper Mist %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("Juniper Mist request remained rate limited")
}

func mistCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
