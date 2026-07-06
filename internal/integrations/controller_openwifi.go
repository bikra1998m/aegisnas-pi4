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

const openWiFiDeviceCollection = "/devices"

type openWiFiSSIDResource struct {
	Name        string
	VLAN        int
	DynamicVLAN bool
	Payload     map[string]any
}

type openWiFiDevice struct {
	SerialNumber   string
	Venue          string
	UUID           int
	Connected      bool
	ConnectedKnown bool
	Sanity         int
	Configuration  map[string]any
	ConfigErr      error
}

type openWiFiSSIDLocation struct {
	Interface map[string]any
	SSID      map[string]any
}

type openWiFiClient struct {
	baseURL      string
	apiKey       string
	radiusSecret string
	http         *http.Client
}

func buildOpenWiFiPreviewPayload(cfg *config.Config) map[string]any {
	resources, warnings, err := loadOpenWiFiSSIDResources(cfg, "redacted")
	items := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		items = append(items, map[string]any{
			"name": resource.Name, "vlan": resource.VLAN, "dynamic_vlan": resource.DynamicVLAN,
			"payload": resource.Payload,
		})
	}
	payload := map[string]any{
		"adapter":          "tip-openwifi-owgw",
		"device_selector":  strings.TrimSpace(cfg.Integrations.Controller.Site),
		"selection_policy": "exact-serial-or-venue",
		"ssid_policy":      "match-existing-name",
		"resources":        items,
	}
	if len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if err != nil {
		payload["load_error"] = err.Error()
	}
	return payload
}

func executeOpenWiFiOperation(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	apiKey, radiusSecret, err := openWiFiCredentials(cfg)
	if err != nil {
		return nil, err
	}
	resources, warnings, err := loadOpenWiFiSSIDResources(cfg, radiusSecret)
	if err != nil {
		return nil, err
	}
	targetURL, err := openWiFiTargetURL(cfg)
	if err != nil {
		return nil, err
	}
	client := &openWiFiClient{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/"),
		apiKey:  apiKey, radiusSecret: radiusSecret, http: &http.Client{Timeout: 15 * time.Second},
	}
	result := &controllerSyncResult{
		Adapter: "tip-openwifi-owgw", TargetURL: targetURL, AuthScheme: "api-key",
		ControllerHealth: "healthy", WarningCount: len(warnings), CompatibilityScore: 100,
		ResponseDetails: map[string]any{
			"native_api": true, "device_selector": strings.TrimSpace(cfg.Integrations.Controller.Site),
			"selection_policy": "exact-serial-or-venue", "ssid_policy": "match-existing-name",
		},
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}

	devices, err := client.listAPs(ctx)
	if err != nil {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = openWiFiCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, err
	}
	selected, selectionMode := selectOpenWiFiDevices(devices, cfg.Integrations.Controller.Site)
	if len(selected) == 0 {
		result.ControllerHealth = "degraded"
		result.FailedCount = 1
		result.CompatibilityScore = openWiFiCompatibilityScore(result.WarningCount, result.FailedCount)
		return result, fmt.Errorf("OpenWiFi selector %q did not match an AP serial number or venue", strings.TrimSpace(cfg.Integrations.Controller.Site))
	}
	result.ResponseDetails["selection_mode"] = selectionMode
	result.ResponseDetails["selected_device_count"] = len(selected)
	for index := range selected {
		summary := selected[index]
		detail, detailErr := client.getDevice(ctx, summary.SerialNumber)
		if detailErr != nil {
			selected[index].Configuration = nil
			selected[index].ConfigErr = detailErr
			continue
		}
		detail.Connected = summary.Connected
		detail.ConnectedKnown = summary.ConnectedKnown
		if detail.Venue == "" {
			detail.Venue = summary.Venue
		}
		selected[index] = detail
	}

	desiredDevices := make([]map[string]any, 0, len(selected))
	observedDevices := make([]map[string]any, 0, len(selected))
	driftItems := make([]string, 0)
	disconnected := 0
	for _, device := range selected {
		if device.ConnectedKnown && !device.Connected {
			disconnected++
		}
		if device.ConfigErr != nil {
			warning := fmt.Sprintf("OpenWiFi device %s configuration is unavailable: %v", device.SerialNumber, device.ConfigErr)
			warnings = append(warnings, warning)
			result.WarningCount++
			result.FailedCount++
			driftItems = append(driftItems, "device:"+device.SerialNumber+":invalid-configuration")
			continue
		}
		if _, exists := device.Configuration["uuid"]; !exists {
			result.FailedCount++
			driftItems = append(driftItems, "device:"+device.SerialNumber+":missing-configuration-uuid")
			continue
		}

		desiredSSIDs := make([]map[string]any, 0, len(resources))
		observedSSIDs := make([]map[string]any, 0, len(resources))
		deviceChanged := false
		deviceBlocked := false
		for _, resource := range resources {
			publicDesired := openWiFiPublicMap(resource.Payload)
			desiredSSIDs = append(desiredSSIDs, map[string]any{
				"name": resource.Name, "vlan": resource.VLAN, "dynamic_vlan": resource.DynamicVLAN,
				"payload": publicDesired,
			})
			locations := findOpenWiFiSSIDs(device.Configuration, resource.Name)
			if len(locations) == 0 {
				driftItems = append(driftItems, "device:"+device.SerialNumber+":ssid:"+resource.Name+":missing")
				observedSSIDs = append(observedSSIDs, map[string]any{"name": resource.Name, "state": "missing"})
				deviceBlocked = true
				continue
			}
			if len(locations) > 1 {
				driftItems = append(driftItems, "device:"+device.SerialNumber+":ssid:"+resource.Name+":ambiguous")
				observedSSIDs = append(observedSSIDs, map[string]any{"name": resource.Name, "state": "ambiguous"})
				deviceBlocked = true
				continue
			}

			location := locations[0]
			interfaceVLAN := openWiFiInterfaceVLAN(location.Interface)
			publicObserved := projectControllerState(openWiFiPublicMap(location.SSID), publicDesired)
			observedSSIDs = append(observedSSIDs, map[string]any{
				"name": resource.Name, "interface_vlan": interfaceVLAN, "payload": publicObserved,
			})
			if resource.VLAN > 0 && interfaceVLAN != resource.VLAN {
				driftItems = append(driftItems, "device:"+device.SerialNumber+":ssid:"+resource.Name+":vlan-placement")
				deviceBlocked = true
				continue
			}
			if resource.DynamicVLAN && !strings.EqualFold(firstNonEmptyString(location.Interface["role"]), "upstream") {
				warning := fmt.Sprintf("OpenWiFi device %s SSID %s requests dynamic VLANs on a non-upstream interface; verify forwarding behavior.", device.SerialNumber, resource.Name)
				warnings = append(warnings, warning)
				result.WarningCount++
			}

			fullObserved := projectControllerState(location.SSID, resource.Payload)
			changed := controllerDesiredStateHash(map[string]any{"value": fullObserved}) != controllerDesiredStateHash(map[string]any{"value": resource.Payload})
			if !changed {
				continue
			}
			driftItems = append(driftItems, "device:"+device.SerialNumber+":ssid:"+resource.Name+":changed")
			deviceChanged = true
			if operation == "push" {
				openWiFiMergeManagedMap(location.SSID, resource.Payload)
			}
		}
		desiredDevices = append(desiredDevices, map[string]any{"serial_number": device.SerialNumber, "ssids": desiredSSIDs})
		observedDevices = append(observedDevices, map[string]any{"serial_number": device.SerialNumber, "ssids": observedSSIDs})

		if operation != "push" {
			continue
		}
		if deviceBlocked {
			result.FailedCount++
			continue
		}
		if !deviceChanged {
			continue
		}
		configuration, marshalErr := json.Marshal(device.Configuration)
		if marshalErr != nil {
			result.FailedCount++
			continue
		}
		payload := map[string]any{
			"serialNumber": device.SerialNumber, "UUID": device.UUID,
			"configuration": string(configuration), "when": 0,
		}
		if _, _, updateErr := client.doJSON(ctx, http.MethodPost, openWiFiConfigurePath(device.SerialNumber), payload); updateErr != nil {
			result.FailedCount++
			continue
		}
		result.AppliedCount++
	}

	result.ResponseDetails["disconnected_device_count"] = disconnected
	if disconnected > 0 {
		result.ControllerHealth = "degraded"
	}
	if len(warnings) > 0 {
		result.ResponseDetails["response_warnings"] = warnings
	}
	desiredState := map[string]any{"devices": desiredDevices}
	observedState := map[string]any{"devices": observedDevices}
	result.DesiredStateHash = controllerDesiredStateHash(desiredState)
	result.ObservedStateHash = controllerDesiredStateHash(observedState)
	result.DriftCount = len(driftItems)
	result.DriftDetected = result.DriftCount > 0
	result.CompatibilityScore = openWiFiCompatibilityScore(result.WarningCount, result.FailedCount)
	if len(driftItems) > 0 {
		result.ResponseDetails["drift_items"] = driftItems
	}
	if operation == "push" && result.FailedCount == 0 {
		result.DriftDetected = false
		result.DriftCount = 0
		result.ObservedStateHash = result.DesiredStateHash
		result.ResponseDetails["remediated_count"] = len(driftItems)
		result.ResponseSummary = fmt.Sprintf("OpenWiFi Gateway queued %d AP configuration command(s).", result.AppliedCount)
	} else if operation == "pull" {
		result.ResponseSummary = fmt.Sprintf("OpenWiFi Gateway inspection found %d drift item(s) across %d AP(s).", result.DriftCount, len(selected))
	}
	result.ResponseStatus = "200 " + http.StatusText(http.StatusOK)
	if result.FailedCount > 0 {
		result.ControllerHealth = "degraded"
		result.ResponseStatus = "207 " + http.StatusText(http.StatusMultiStatus)
		return result, fmt.Errorf("OpenWiFi Gateway operation failed for %d AP configuration(s)", result.FailedCount)
	}
	return result, nil
}

func loadOpenWiFiSSIDResources(cfg *config.Config, secret string) ([]openWiFiSSIDResource, []string, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("controller config is required")
	}
	radiusServer := strings.TrimSpace(cfg.Integrations.Controller.RadiusServer)
	resources := make([]openWiFiSSIDResource, 0, len(cfg.Wireless.SSIDs))
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			warnings = append(warnings, "An unnamed SSID was skipped.")
			continue
		}
		if _, exists := seen[name]; exists {
			return nil, warnings, fmt.Errorf("OpenWiFi SSID %q is configured more than once", name)
		}
		seen[name] = struct{}{}
		proto := ""
		pmf := "optional"
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise":
			proto = "wpa2"
		case "wpa3-enterprise":
			proto = "wpa3"
			pmf = "required"
		default:
			warnings = append(warnings, fmt.Sprintf("SSID %s uses unsupported auth mode %s and was not reconciled by the OpenWiFi adapter.", name, ssid.AuthMode))
			continue
		}
		if radiusServer == "" || secret == "" {
			return nil, warnings, fmt.Errorf("OpenWiFi enterprise SSID sync requires integrations.controller.radius_server and a configured radius_secret_env")
		}
		if ssid.VLAN < 0 || ssid.VLAN > 4094 {
			return nil, warnings, fmt.Errorf("OpenWiFi SSID %q has VLAN %d outside the supported range", name, ssid.VLAN)
		}
		payload := map[string]any{
			"name": name, "bss-mode": "ap", "hidden-ssid": ssid.Hidden,
			"encryption": map[string]any{"proto": proto, "ieee80211w": pmf},
			"radius": map[string]any{
				"authentication": map[string]any{"host": radiusServer, "port": cfg.Radius.AuthPort, "secret": secret},
				"accounting":     map[string]any{"host": radiusServer, "port": cfg.Radius.AcctPort, "secret": secret},
			},
		}
		resources = append(resources, openWiFiSSIDResource{
			Name: name, VLAN: ssid.VLAN, DynamicVLAN: ssid.DynamicVLAN, Payload: payload,
		})
		if ssid.ClientIsolation || ssid.MaxClients > 0 || ssid.PortalProfile != "" || ssid.BandwidthProfile != "" || ssid.IdentitySource != "" {
			warnings = append(warnings, fmt.Sprintf("SSID %s has isolation, client-limit, portal, bandwidth, or identity-source settings outside the current OpenWiFi SSID contract.", name))
		}
	}
	return resources, warnings, nil
}

func openWiFiCredentials(cfg *config.Config) (string, string, error) {
	if cfg == nil {
		return "", "", fmt.Errorf("controller config is required")
	}
	apiKeyEnv := strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)
	secretEnv := strings.TrimSpace(cfg.Integrations.Controller.RadiusSecretEnv)
	apiKey := strings.TrimSpace(os.Getenv(apiKeyEnv))
	secret := os.Getenv(secretEnv)
	if apiKeyEnv == "" || apiKey == "" {
		return "", "", fmt.Errorf("OpenWiFi Gateway API key environment variable %q must be present", apiKeyEnv)
	}
	if openWiFiHasEnterpriseSSIDs(cfg) && (secretEnv == "" || secret == "") {
		return "", "", fmt.Errorf("OpenWiFi RADIUS secret environment variable %q must be present", secretEnv)
	}
	return apiKey, secret, nil
}

func openWiFiHasEnterpriseSSIDs(cfg *config.Config) bool {
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

func openWiFiTargetURL(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("controller config is required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if strings.TrimSpace(cfg.Integrations.Controller.Site) == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", "openwifi")
	}
	return base + openWiFiDeviceListPath(1), nil
}

func openWiFiDeviceListPath(offset int) string {
	values := url.Values{}
	values.Set("deviceWithStatus", "true")
	values.Set("limit", "100")
	values.Set("offset", strconv.Itoa(offset))
	values.Set("platform", "ap")
	return openWiFiDeviceCollection + "?" + values.Encode()
}

func openWiFiConfigurePath(serialNumber string) string {
	return "/device/" + url.PathEscape(strings.TrimSpace(serialNumber)) + "/configure"
}

func openWiFiDevicePath(serialNumber string) string {
	return "/device/" + url.PathEscape(strings.TrimSpace(serialNumber))
}

func selectOpenWiFiDevices(devices []openWiFiDevice, selector string) ([]openWiFiDevice, string) {
	selector = strings.TrimSpace(selector)
	serialMatches := make([]openWiFiDevice, 0, 1)
	for _, device := range devices {
		if strings.EqualFold(device.SerialNumber, selector) {
			serialMatches = append(serialMatches, device)
		}
	}
	if len(serialMatches) > 0 {
		return serialMatches, "serial-number"
	}
	venueMatches := make([]openWiFiDevice, 0)
	for _, device := range devices {
		if strings.EqualFold(device.Venue, selector) {
			venueMatches = append(venueMatches, device)
		}
	}
	return venueMatches, "venue"
}

func findOpenWiFiSSIDs(configuration map[string]any, name string) []openWiFiSSIDLocation {
	interfaces, _ := configuration["interfaces"].([]any)
	locations := make([]openWiFiSSIDLocation, 0, 1)
	for _, rawInterface := range interfaces {
		iface, _ := rawInterface.(map[string]any)
		ssids, _ := iface["ssids"].([]any)
		for _, rawSSID := range ssids {
			ssid, _ := rawSSID.(map[string]any)
			if firstNonEmptyString(ssid["name"]) == name {
				locations = append(locations, openWiFiSSIDLocation{Interface: iface, SSID: ssid})
			}
		}
	}
	return locations
}

func openWiFiInterfaceVLAN(iface map[string]any) int {
	vlan, _ := iface["vlan"].(map[string]any)
	id, _ := controllerInt(vlan["id"])
	return id
}

func openWiFiMergeManagedMap(target, desired map[string]any) {
	for key, value := range desired {
		desiredMap, desiredIsMap := value.(map[string]any)
		targetMap, targetIsMap := target[key].(map[string]any)
		if desiredIsMap && targetIsMap {
			openWiFiMergeManagedMap(targetMap, desiredMap)
			continue
		}
		target[key] = value
	}
}

func openWiFiPublicMap(value map[string]any) map[string]any {
	cleaned, _ := stripOpenWiFiSecrets(value).(map[string]any)
	return cleaned
}

func stripOpenWiFiSecrets(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			if strings.EqualFold(strings.TrimSpace(key), "secret") {
				continue
			}
			out[key] = stripOpenWiFiSecrets(nested)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			out = append(out, stripOpenWiFiSecrets(nested))
		}
		return out
	default:
		return value
	}
}

func (c *openWiFiClient) listAPs(ctx context.Context) ([]openWiFiDevice, error) {
	const pageSize = 100
	devices := make([]openWiFiDevice, 0)
	seen := make(map[string]struct{})
	for offset := 1; offset < 100000; offset += pageSize {
		body, _, err := c.doJSON(ctx, http.MethodGet, openWiFiDeviceListPath(offset), nil)
		if err != nil {
			return nil, err
		}
		page, err := decodeOpenWiFiDevicePage(body)
		if err != nil {
			return nil, err
		}
		for _, device := range page {
			if device.SerialNumber == "" {
				continue
			}
			if _, exists := seen[device.SerialNumber]; exists {
				return nil, fmt.Errorf("OpenWiFi Gateway returned duplicate AP serial number %q", device.SerialNumber)
			}
			seen[device.SerialNumber] = struct{}{}
			devices = append(devices, device)
		}
		if len(page) < pageSize {
			return devices, nil
		}
	}
	return nil, fmt.Errorf("OpenWiFi Gateway pagination exceeded 100000 devices")
}

func (c *openWiFiClient) getDevice(ctx context.Context, serialNumber string) (openWiFiDevice, error) {
	body, _, err := c.doJSON(ctx, http.MethodGet, openWiFiDevicePath(serialNumber), nil)
	if err != nil {
		return openWiFiDevice{}, err
	}
	var item map[string]any
	if err := json.Unmarshal(body, &item); err != nil {
		return openWiFiDevice{}, fmt.Errorf("decode OpenWiFi device %s: %w", serialNumber, err)
	}
	device := decodeOpenWiFiDevice(item, true)
	if device.SerialNumber == "" {
		device.SerialNumber = strings.TrimSpace(serialNumber)
	}
	if device.ConfigErr != nil {
		return device, device.ConfigErr
	}
	return device, nil
}

func decodeOpenWiFiDevicePage(body []byte) ([]openWiFiDevice, error) {
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode OpenWiFi device list: %w", err)
	}
	rawDevices, _ := envelope["devicesWithStatus"].([]any)
	if rawDevices == nil {
		rawDevices, _ = envelope["devices"].([]any)
	}
	if rawDevices == nil {
		return nil, fmt.Errorf("OpenWiFi device list did not contain devicesWithStatus or devices")
	}
	devices := make([]openWiFiDevice, 0, len(rawDevices))
	for _, raw := range rawDevices {
		item, _ := raw.(map[string]any)
		devices = append(devices, decodeOpenWiFiDevice(item, false))
	}
	return devices, nil
}

func decodeOpenWiFiDevice(item map[string]any, requireConfiguration bool) openWiFiDevice {
	device := openWiFiDevice{
		SerialNumber: firstNonEmptyString(item["serialNumber"]), Venue: firstNonEmptyString(item["venue"]),
	}
	device.UUID, _ = controllerInt(item["UUID"])
	device.Connected, device.ConnectedKnown = controllerResponseBool(item["connected"])
	device.Sanity, _ = controllerInt(item["sanity"])
	switch configuration := item["configuration"].(type) {
	case string:
		if err := json.Unmarshal([]byte(configuration), &device.Configuration); err != nil {
			device.ConfigErr = fmt.Errorf("decode OpenWiFi device %s configuration: %w", device.SerialNumber, err)
		}
	case map[string]any:
		device.Configuration = configuration
	default:
		if requireConfiguration {
			device.ConfigErr = fmt.Errorf("OpenWiFi device %s did not return a configuration document", device.SerialNumber)
		}
	}
	return device
}

func (c *openWiFiClient) doJSON(ctx context.Context, method, path string, payload map[string]any) ([]byte, int, error) {
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
		req.Header.Set("X-API-KEY", c.apiKey)
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
		if (method == http.MethodGet || method == http.MethodPost) && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
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
			return body, resp.StatusCode, fmt.Errorf("OpenWiFi Gateway %s %s returned %s: %s", method, path, resp.Status, summary)
		}
		return body, resp.StatusCode, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("OpenWiFi Gateway request remained unavailable after retry")
}

func openWiFiCompatibilityScore(warnings, failures int) int {
	score := 100 - warnings*5 - failures*10
	if score < 0 {
		return 0
	}
	return score
}
