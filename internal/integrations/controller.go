package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const controllerComponent = "controller_automation"

type controllerRequest struct {
	Adapter    string
	Method     string
	URL        string
	AuthScheme string
	Headers    map[string]string
	Payload    map[string]any
}

type controllerSyncResult struct {
	Adapter         string
	TargetURL       string
	AuthScheme      string
	ResponseStatus  string
	ResponseSummary string
	WarningCount    int
	ResponseDetails map[string]any
}

func ControllerComponent() string {
	return controllerComponent
}

func StartControllerAutomation(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg == nil || !cfg.Integrations.Controller.Enabled {
		_ = db.UpsertRuntimeStatus(controllerComponent, "disabled", "Controller automation is disabled in config.", nil)
		return
	}

	syncOnce := func() {
		startedAt := time.Now().UTC()
		lastStatus, _ := db.GetRuntimeStatus(controllerComponent)
		syncCount, successCount, failureCount := controllerStatusCounters(lastStatus)
		result, err := pushControllerState(ctx, cfg)
		details := map[string]any{
			"platform":         cfg.Integrations.Controller.Platform,
			"endpoint":         cfg.Integrations.Controller.Endpoint,
			"sync_mode":        cfg.Integrations.Controller.SyncMode,
			"site":             cfg.Integrations.Controller.Site,
			"last_sync_at":     startedAt.Format(time.RFC3339),
			"last_duration_ms": time.Since(startedAt).Milliseconds(),
		}
		mergeControllerResultDetails(details, result)
		if err != nil {
			syncCount++
			failureCount++
			logger.Warn("controller automation sync failed", zap.Error(err))
			details["sync_count"] = syncCount
			details["success_count"] = successCount
			details["failure_count"] = failureCount
			details["last_error"] = err.Error()
			_ = db.UpsertRuntimeStatus(controllerComponent, "degraded", err.Error(), details)
			return
		}
		syncCount++
		successCount++
		details["sync_count"] = syncCount
		details["success_count"] = successCount
		details["failure_count"] = failureCount
		details["last_error"] = ""
		message := "Controller automation sync completed."
		if result != nil && strings.TrimSpace(result.ResponseSummary) != "" {
			message = fmt.Sprintf("Controller automation sync completed. %s", strings.TrimSpace(result.ResponseSummary))
		}
		_ = db.UpsertRuntimeStatus(controllerComponent, "ok", message, details)
	}

	syncOnce()
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}

func pushControllerState(ctx context.Context, cfg *config.Config) (*controllerSyncResult, error) {
	token := controllerToken(cfg)
	if token == "" {
		return nil, fmt.Errorf("controller API token env %q is empty", strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv))
	}
	request, err := buildControllerRequest(cfg, token)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(request.Payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range request.Headers {
		req.Header.Set(key, value)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return &controllerSyncResult{
			Adapter:    request.Adapter,
			TargetURL:  request.URL,
			AuthScheme: request.AuthScheme,
		}, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return &controllerSyncResult{
			Adapter:        request.Adapter,
			TargetURL:      request.URL,
			AuthScheme:     request.AuthScheme,
			ResponseStatus: resp.Status,
		}, readErr
	}

	summary, warningCount, responseDetails := parseControllerResponse(body)
	result := &controllerSyncResult{
		Adapter:         request.Adapter,
		TargetURL:       request.URL,
		AuthScheme:      request.AuthScheme,
		ResponseStatus:  resp.Status,
		ResponseSummary: summary,
		WarningCount:    warningCount,
		ResponseDetails: responseDetails,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if summary != "" {
			return result, fmt.Errorf("controller endpoint returned %s: %s", resp.Status, summary)
		}
		return result, fmt.Errorf("controller endpoint returned %s", resp.Status)
	}
	return result, nil
}

func buildControllerRequest(cfg *config.Config, token string) (*controllerRequest, error) {
	if cfg == nil {
		return nil, fmt.Errorf("controller config is required")
	}
	platform := normalizeControllerPlatform(cfg.Integrations.Controller.Platform)
	targetURL, err := controllerEndpointForPlatform(cfg, platform)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"X-AegisNAS-Controller-Platform": platform,
		"X-AegisNAS-Sync-Mode":           strings.TrimSpace(cfg.Integrations.Controller.SyncMode),
		"X-AegisNAS-Controller-Adapter":  controllerAdapterName(platform),
	}
	authScheme := "bearer"
	switch platform {
	case "juniper-mist":
		headers["Authorization"] = "Token " + token
		authScheme = "token"
	case "mikrotik":
		headers["X-MikroTik-API-Token"] = token
		authScheme = "header-token"
	default:
		headers["Authorization"] = "Bearer " + token
	}

	return &controllerRequest{
		Adapter:    controllerAdapterName(platform),
		Method:     http.MethodPost,
		URL:        targetURL,
		AuthScheme: authScheme,
		Headers:    headers,
		Payload:    buildControllerPayloadForPlatform(cfg, platform),
	}, nil
}

func controllerEndpointForPlatform(cfg *config.Config, platform string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
	site := strings.TrimSpace(cfg.Integrations.Controller.Site)
	if base == "" {
		return "", fmt.Errorf("controller endpoint is empty")
	}
	if controllerPlatformRequiresSite(platform) && site == "" {
		return "", fmt.Errorf("controller platform %q requires integrations.controller.site", platform)
	}
	if !controllerPlatformRequiresSite(platform) {
		return base, nil
	}
	escapedSite := url.PathEscape(site)
	switch platform {
	case "cisco":
		return base + "/api/v1/aegisnas/sites/" + escapedSite + "/sync", nil
	case "aruba":
		return base + "/configuration/v1/aegisnas/sites/" + escapedSite + "/sync", nil
	case "juniper-mist":
		return base + "/api/v1/sites/" + escapedSite + "/aegisnas/sync", nil
	case "ruckus":
		return base + "/wsg/api/public/v11_1/aegisnas/sites/" + escapedSite + "/sync", nil
	case "fortinet":
		return base + "/api/v2/cmdb/aegisnas/sites/" + escapedSite + "/sync", nil
	case "mikrotik":
		return base + "/rest/aegisnas/sites/" + escapedSite + "/sync", nil
	default:
		return base, nil
	}
}

func buildControllerPayloadForPlatform(cfg *config.Config, platform string) map[string]any {
	switch platform {
	case "cisco":
		return buildCiscoControllerPayload(cfg)
	case "aruba":
		return buildArubaControllerPayload(cfg)
	case "juniper-mist":
		return buildMistControllerPayload(cfg)
	case "ruckus":
		return buildRuckusControllerPayload(cfg)
	case "fortinet":
		return buildFortinetControllerPayload(cfg)
	case "mikrotik":
		return buildMikroTikControllerPayload(cfg)
	default:
		return buildGenericControllerPayload(cfg)
	}
}

func buildGenericControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"deployment": map[string]any{
			"profile": cfg.Deployment.Profile,
			"form":    cfg.Deployment.Form,
			"mode":    cfg.Mode,
		},
		"controller": map[string]any{
			"platform":  cfg.Integrations.Controller.Platform,
			"sync_mode": cfg.Integrations.Controller.SyncMode,
			"site":      cfg.Integrations.Controller.Site,
		},
		"portal":            buildControllerPortalSection(cfg),
		"radius":            buildControllerRadiusSection(cfg),
		"wireless_profiles": buildControllerSSIDProfiles(cfg),
	}
}

func buildCiscoControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
		"adapter":            "cisco-ise",
		"site":               strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":          cfg.Integrations.Controller.SyncMode,
		"deployment_profile": cfg.Deployment.Profile,
		"aaa": map[string]any{
			"radius_servers": []map[string]any{buildControllerRadiusSection(cfg)},
			"dynamic_auth":   buildControllerDynamicAuthSection(cfg),
		},
		"guest_portal":  buildControllerPortalSection(cfg),
		"ssid_policies": buildControllerSSIDProfiles(cfg),
	}
}

func buildArubaControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at":       time.Now().UTC().Format(time.RFC3339),
		"adapter":            "aruba-central",
		"site":               strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":          cfg.Integrations.Controller.SyncMode,
		"deployment_profile": cfg.Deployment.Profile,
		"aaa_profiles":       []map[string]any{buildControllerRadiusSection(cfg)},
		"guest":              buildControllerPortalSection(cfg),
		"wireless_networks":  buildControllerSSIDProfiles(cfg),
	}
}

func buildMistControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"adapter":        "juniper-mist",
		"site_id":        strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":      cfg.Integrations.Controller.SyncMode,
		"radius_config":  buildControllerRadiusSection(cfg),
		"portal_config":  buildControllerPortalSection(cfg),
		"wlan_overrides": buildControllerSSIDProfiles(cfg),
	}
}

func buildRuckusControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"adapter":      "ruckus-smartzone",
		"zone":         strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":    cfg.Integrations.Controller.SyncMode,
		"aaa_servers":  []map[string]any{buildControllerRadiusSection(cfg)},
		"guest_access": buildControllerPortalSection(cfg),
		"wlans":        buildControllerSSIDProfiles(cfg),
	}
}

func buildFortinetControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"adapter":        "fortinet-fortigate",
		"scope":          strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":      cfg.Integrations.Controller.SyncMode,
		"radius_servers": []map[string]any{buildControllerRadiusSection(cfg)},
		"captive_portal": buildControllerPortalSection(cfg),
		"wireless_vaps":  buildControllerSSIDProfiles(cfg),
	}
}

func buildMikroTikControllerPayload(cfg *config.Config) map[string]any {
	return map[string]any{
		"generated_at":      time.Now().UTC().Format(time.RFC3339),
		"adapter":           "mikrotik-hotspot",
		"router_site":       strings.TrimSpace(cfg.Integrations.Controller.Site),
		"sync_mode":         cfg.Integrations.Controller.SyncMode,
		"radius_profile":    buildControllerRadiusSection(cfg),
		"hotspot_portal":    buildControllerPortalSection(cfg),
		"wireless_profiles": buildControllerSSIDProfiles(cfg),
	}
}

func buildControllerPortalSection(cfg *config.Config) map[string]any {
	return map[string]any{
		"enabled":         cfg.Portal.Enabled,
		"listen_ip":       cfg.Portal.ListenIP,
		"port":            cfg.Portal.Port,
		"branding":        cfg.Portal.Branding,
		"guest_workflows": cfg.Portal.GuestWorkflows,
	}
}

func buildControllerRadiusSection(cfg *config.Config) map[string]any {
	return map[string]any{
		"listen_ip":         cfg.Portal.ListenIP,
		"auth_port":         cfg.Radius.AuthPort,
		"acct_port":         cfg.Radius.AcctPort,
		"dynamic_auth":      cfg.Radius.DynamicAuth.Enabled,
		"dynamic_auth_port": cfg.Radius.DynamicAuth.Port,
		"request_timeout":   cfg.Radius.RequestTimeoutSeconds,
	}
}

func buildControllerDynamicAuthSection(cfg *config.Config) map[string]any {
	return map[string]any{
		"enabled": cfg.Radius.DynamicAuth.Enabled,
		"port":    cfg.Radius.DynamicAuth.Port,
	}
}

func buildControllerSSIDProfiles(cfg *config.Config) []map[string]any {
	ssids := make([]map[string]any, 0, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		ssids = append(ssids, map[string]any{
			"name":              ssid.Name,
			"auth_mode":         ssid.AuthMode,
			"vlan":              ssid.VLAN,
			"portal_profile":    ssid.PortalProfile,
			"identity_source":   ssid.IdentitySource,
			"bandwidth_profile": ssid.BandwidthProfile,
		})
	}
	return ssids
}

func parseControllerResponse(body []byte) (string, int, map[string]any) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", 0, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return trimmed, 0, nil
	}

	details := map[string]any{}
	summary := firstNonEmptyString(payload["summary"], payload["message"], payload["status"])
	warningCount := 0
	if warnings, ok := payload["warnings"].([]any); ok {
		warningCount = len(warnings)
		if warningCount > 0 {
			details["response_warnings"] = warnings
		}
	}
	if applied, ok := payload["applied"]; ok {
		details["response_applied"] = applied
	}
	if siteID := firstNonEmptyString(payload["site"], payload["site_id"], payload["network"], payload["zone"]); siteID != "" {
		details["response_scope"] = siteID
	}
	if len(details) == 0 {
		details = nil
	}
	return summary, warningCount, details
}

func mergeControllerResultDetails(details map[string]any, result *controllerSyncResult) {
	if details == nil || result == nil {
		return
	}
	details["adapter"] = result.Adapter
	details["request_url"] = result.TargetURL
	details["auth_scheme"] = result.AuthScheme
	if result.ResponseStatus != "" {
		details["response_status"] = result.ResponseStatus
	}
	if result.ResponseSummary != "" {
		details["response_summary"] = result.ResponseSummary
	}
	if result.WarningCount > 0 {
		details["warning_count"] = result.WarningCount
	}
	for key, value := range result.ResponseDetails {
		details[key] = value
	}
}

func normalizeControllerPlatform(platform string) string {
	return strings.ToLower(strings.TrimSpace(platform))
}

func controllerPlatformRequiresSite(platform string) bool {
	switch normalizeControllerPlatform(platform) {
	case "", "generic":
		return false
	default:
		return true
	}
}

func controllerAdapterName(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		return "cisco-ise"
	case "aruba":
		return "aruba-central"
	case "juniper-mist":
		return "juniper-mist"
	case "ruckus":
		return "ruckus-smartzone"
	case "fortinet":
		return "fortinet-fortigate"
	case "mikrotik":
		return "mikrotik-hotspot"
	default:
		return "generic-rest"
	}
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		text, ok := value.(string)
		if ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func controllerToken(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(os.Getenv(strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)))
}

func controllerStatusCounters(status *db.RuntimeStatus) (int64, int64, int64) {
	if status == nil || status.Details == nil {
		return 0, 0, 0
	}
	return int64ControllerDetail(status.Details, "sync_count"),
		int64ControllerDetail(status.Details, "success_count"),
		int64ControllerDetail(status.Details, "failure_count")
}

func int64ControllerDetail(details map[string]any, key string) int64 {
	if details == nil {
		return 0
	}
	switch value := details[key].(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	case json.Number:
		number, _ := value.Int64()
		return number
	default:
		return 0
	}
}
