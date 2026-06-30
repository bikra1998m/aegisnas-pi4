package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const (
	mikroTikRadiusCollection        = "/rest/radius"
	mikroTikSecurityCollection      = "/rest/interface/wifi/security"
	mikroTikDatapathCollection      = "/rest/interface/wifi/datapath"
	mikroTikConfigurationCollection = "/rest/interface/wifi/configuration"
)

type mikroTikResource struct {
	Kind       string
	Collection string
	Name       string
	MatchField string
	MatchValue string
	Payload    map[string]any
	Comparable map[string]any
}

type mikroTikClient struct {
	baseURL  string
	username string
	password string
	secret   string
	http     *http.Client
}

func buildMikroTikPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadMikroTikResources(cfg, "redacted")
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{
			"kind":       resource.Kind,
			"collection": resource.Collection,
			"name":       resource.Name,
			"payload":    redactMikroTikPayload(resource.Payload),
		})
	}
	payload := map[string]any{
		"adapter":   "mikrotik-routeros",
		"site":      strings.TrimSpace(cfg.Integrations.Controller.Site),
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

func executeMikroTikOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	username, password, secret, err := mikroTikCredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadMikroTikResources(cfg, secret)
	if err != nil {
		return nil, err
	}
	targetURL, err := mikroTikTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &mikroTikClient{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		username: username,
		password: password,
		secret:   secret,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter:            "mikrotik-routeros",
		TargetURL:          targetURL,
		AuthScheme:         "basic",
		ControllerHealth:   "healthy",
		WarningCount:       len(warnings),
		CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api":     true,
			"site":           strings.TrimSpace(cfg.Integrations.Controller.Site),
			"resource_count": len(resources),
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}
	if len(resources) == 0 {
		if _, _, probeErr := client.doJSON(ctx, http.MethodGet, mikroTikConfigurationCollection, nil); probeErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			result.CompatibilityScore = mikroTikCompatibilityScore(result.WarningCount, result.FailedCount)
			return result, probeErr
		}
	}

	collections := make(map[string]map[string]map[string]any)
	for _, resource := range resources {
		if _, loaded := collections[resource.Collection]; loaded {
			continue
		}
		observed, listWarnings, listErr := client.listCollection(ctx, resource.Collection, resource.MatchField)
		if listErr != nil {
			result.ControllerHealth = "degraded"
			result.FailedCount = 1
			result.CompatibilityScore = mikroTikCompatibilityScore(result.WarningCount, result.FailedCount)
			return result, listErr
		}
		collections[resource.Collection] = observed
		if len(listWarnings) > 0 {
			warnings = append(warnings, listWarnings...)
			result.WarningCount += len(listWarnings)
			result.ResponseDetails["response_warnings"] = warnings
		}
	}

	desiredItems := make([]map[string]any, 0, len(resources))
	observedItems := make([]map[string]any, 0, len(resources))
	driftItems := make([]string, 0)
	for _, resource := range resources {
		desiredItems = append(desiredItems, map[string]any{
			"kind": resource.Kind, "name": resource.Name, "payload": resource.Comparable,
		})
		observed, found := collections[resource.Collection][resource.MatchValue]
		if !found {
			driftItems = append(driftItems, resource.Kind+":"+resource.Name+":missing")
			observedItems = append(observedItems, map[string]any{"kind": resource.Kind, "name": resource.Name, "state": "missing"})
			if operation == "push" {
				if _, _, createErr := client.doJSON(ctx, http.MethodPut, resource.Collection, resource.Payload); createErr != nil {
					result.FailedCount++
					continue
				}
				result.AppliedCount++
			}
			continue
		}
		projected := projectControllerState(observed, resource.Comparable)
		observedItems = append(observedItems, map[string]any{"kind": resource.Kind, "name": resource.Name, "payload": projected})
		if controllerDesiredStateHash(map[string]any{"value": projected}) == controllerDesiredStateHash(map[string]any{"value": resource.Comparable}) {
			continue
		}
		driftItems = append(driftItems, resource.Kind+":"+resource.Name+":changed")
		if operation == "push" {
			id := firstNonEmptyString(observed[".id"])
			if id == "" {
				result.FailedCount++
				continue
			}
			path := resource.Collection + "/" + url.PathEscape(id)
			if _, _, updateErr := client.doJSON(ctx, http.MethodPatch, path, resource.Payload); updateErr != nil {
				result.FailedCount++
				continue
			}
			result.AppliedCount++
		}
	}

	desiredState := map[string]any{"resources": desiredItems}
	observedState := map[string]any{"resources": observedItems}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = mikroTikCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("MikroTik RouterOS reconciliation applied %d managed resource(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("MikroTik RouterOS inspection found %d drift item(s).", result.DriftCount)
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("MikroTik RouterOS operation failed for %d managed resource(s)", result.FailedCount)
	}
	return result, nil
}

func loadMikroTikResources(cfg *config.Config, secret string) ([]mikroTikResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	site := strings.TrimSpace(cfg.Integrations.Controller.Site)
	radiusServer := strings.TrimSpace(cfg.Integrations.Controller.RadiusServer)
	if strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv) == "" {
		secret = ""
	}
	resources := make([]mikroTikResource, 0, 1+len(cfg.Wireless.SSIDs)*3)
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	enterpriseCount := 0
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("MikroTik WiFi profile %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		authenticationTypes := ""
		managementProtection := "allowed"
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			authenticationTypes = "wpa2-eap"
		case "wpa3-enterprise":
			authenticationTypes = "wpa3-eap"
			managementProtection = "required"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the MikroTik adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusServer == "" || secret == "" {
			return nil, warnings, fmt.Errorf("MikroTik enterprise WiFi sync requires integrations.controller.radius_server and a configured radius_secret_env")
		}
		enterpriseCount++
		base := mikroTikManagedName(site, name)
		securityName := base + "-sec"
		datapathName := base + "-dp"
		configurationName := base + "-cfg"
		managedComment := "aegisnas:" + site + ":" + name

		security := map[string]any{
			"name": securityName, "authentication-types": authenticationTypes,
			"eap-accounting": "yes", "management-protection": managementProtection,
			"comment": managedComment,
		}
		datapath := map[string]any{
			"name": datapathName, "client-isolation": mikroTikYesNo(ssid.ClientIsolation), "comment": managedComment,
		}
		if ssid.VLAN > 0 {
			datapath["vlan-id"] = strconv.Itoa(ssid.VLAN)
		}
		configuration := map[string]any{
			"name": configurationName, "ssid": name, "security": securityName, "datapath": datapathName,
			"mode": "ap", "hide-ssid": mikroTikYesNo(ssid.Hidden), "disabled": "no", "comment": managedComment,
		}
		if ssid.MaxClients > 0 {
			configuration["max-clients"] = strconv.Itoa(ssid.MaxClients)
		}
		resources = append(resources,
			newMikroTikResource("wifi-security", mikroTikSecurityCollection, securityName, "name", security),
			newMikroTikResource("wifi-datapath", mikroTikDatapathCollection, datapathName, "name", datapath),
			newMikroTikResource("wifi-configuration", mikroTikConfigurationCollection, configurationName, "name", configuration),
		)
		if ssid.DynamicVLAN {
			warnings = append(warnings, fmt.Sprintf("SSID %s relies on RADIUS VLAN assignment; verify bridge VLAN filtering and CAP radio package compatibility on RouterOS.", name))
		}
		if ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has portal, bandwidth, or identity-source settings outside the current MikroTik WiFi profile contract.", name))
		}
	}
	if enterpriseCount > 0 {
		comment := "aegisnas:" + site + ":radius"
		radius := map[string]any{
			"address": radiusServer, "secret": secret, "service": "wireless", "comment": comment,
		}
		if cfg.Radius.AuthPort > 0 {
			radius["authentication-port"] = strconv.Itoa(cfg.Radius.AuthPort)
		}
		if cfg.Radius.AcctPort > 0 {
			radius["accounting-port"] = strconv.Itoa(cfg.Radius.AcctPort)
		}
		comparable := cloneControllerMap(radius)
		delete(comparable, "secret")
		resources = append([]mikroTikResource{{
			Kind: "radius", Collection: mikroTikRadiusCollection, Name: radiusServer,
			MatchField: "comment", MatchValue: comment, Payload: radius, Comparable: comparable,
		}}, resources...)
		warnings = append(warnings, "MikroTik WiFi profiles are reconciled without CAPsMAN provisioning rules; assign the managed configuration profiles to hardware-specific radios or provisioning rules after validation.")
	}
	return resources, warnings, nil
}

func newMikroTikResource(kind, collection, name, matchField string, payload map[string]any) mikroTikResource {
	return mikroTikResource{
		Kind: kind, Collection: collection, Name: name, MatchField: matchField, MatchValue: firstNonEmptyString(payload[matchField]),
		Payload: payload, Comparable: cloneControllerMap(payload),
	}
}

func cloneControllerMap(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func redactMikroTikPayload(payload map[string]any) map[string]any {
	redacted := cloneControllerMap(payload)
	if _, exists := redacted["secret"]; exists {
		redacted["secret"] = "redacted"
	}
	return redacted
}

func mikroTikManagedName(site, name string) string {
	raw := strings.TrimSpace(site) + "\x00" + strings.TrimSpace(name)
	digest := sha256.Sum256([]byte(raw))
	slug := strings.Trim(strings.ToLower(strings.TrimSpace(site)+"-"+strings.TrimSpace(name)), "-")
	var normalized strings.Builder
	lastDash := false
	for _, char := range slug {
		valid := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
		if valid {
			normalized.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash && normalized.Len() > 0 {
			normalized.WriteByte('-')
			lastDash = true
		}
	}
	clean := strings.Trim(normalized.String(), "-")
	if clean == "" {
		clean = "profile"
	}
	if len(clean) > 36 {
		clean = strings.TrimRight(clean[:36], "-")
	}
	return "aegis-" + clean + "-" + hex.EncodeToString(digest[:4])
}

func mikroTikYesNo(enabled bool) string {
	if enabled {
		return "yes"
	}
	return "no"
}

func mikroTikCredentials(cfg *config.Config) (string, string, string, error) {
	if cfg == nil {
		return "", "", "", fmt.Errorf("controller config is required")
	}
	usernameEnv := strings.TrimSpace(cfg.Integrations.Controller.APIUsernameEnv)
	passwordEnv := strings.TrimSpace(cfg.Integrations.Controller.APIPasswordEnv)
	secretEnv := strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv)
	username := strings.TrimSpace(os.Getenv(usernameEnv))
	password := os.Getenv(passwordEnv)
	secret := os.Getenv(secretEnv)
	if usernameEnv == "" || passwordEnv == "" || username == "" || password == "" {
		return "", "", "", fmt.Errorf("MikroTik RouterOS API username/password environment variables %q and %q must be present", usernameEnv, passwordEnv)
	}
	if mikroTikHasEnterpriseSSIDs(cfg) && (secretEnv == "" || secret == "") {
		return "", "", "", fmt.Errorf("MikroTik RADIUS secret environment variable %q must be present", secretEnv)
	}
	return username, password, secret, nil
}

func mikroTikHasEnterpriseSSIDs(cfg *config.Config) bool {
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

func mikroTikTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if strings.TrimSpace(cfg.Integrations.Controller.Site) == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "mikrotik")
	}
	return base + mikroTikConfigurationCollection, nil
}

func (c *mikroTikClient) listCollection(ctx context.Context, collection, matchField string) (map[string]map[string]any, []string, error) {
	body, _, err := c.doJSON(ctx, http.MethodGet, collection, nil)
	if err != nil {
		return nil, nil, err
	}
	var records []map[string]any
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, nil, fmt.Errorf("decode MikroTik RouterOS collection %s: %w", collection, err)
	}
	byKey := make(map[string]map[string]any, len(records))
	warnings := make([]string, 0)
	for _, record := range records {
		key := firstNonEmptyString(record[matchField])
		if key == "" {
			continue
		}
		if _, exists := byKey[key]; exists {
			warnings = append(warnings, fmt.Sprintf("RouterOS returned duplicate %s value %s in %s; the first record was used.", matchField, key, collection))
			continue
		}
		byKey[key] = record
	}
	return byKey, warnings, nil
}

func (c *mikroTikClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
		req.SetBasicAuth(c.username, c.password)
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
			for _, sensitive := range []string{c.username, c.password, c.secret} {
				if sensitive != "" {
					summary = strings.ReplaceAll(summary, sensitive, "[redacted]")
				}
			}
			return body, resp.StatusCode, fmt.Errorf("MikroTik RouterOS %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("MikroTik RouterOS request remained rate limited")
}

func mikroTikCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
