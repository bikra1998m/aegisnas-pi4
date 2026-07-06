package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	Adapter            string
	TargetURL          string
	AuthScheme         string
	ResponseStatus     string
	ResponseSummary    string
	WarningCount       int
	DriftDetected      bool
	DriftCount         int
	AppliedCount       int
	FailedCount        int
	ControllerHealth   string
	CompatibilityScore int
	ObservedStateHash  string
	DesiredStateHash   string
	ResponseDetails    map[string]any
}

type ControllerSyncPreview struct {
	Operation        string         `json:"operation"`
	Adapter          string         `json:"adapter"`
	Method           string         `json:"method"`
	TargetURL        string         `json:"target_url"`
	AuthScheme       string         `json:"auth_scheme"`
	DesiredStateHash string         `json:"desired_state_hash"`
	Payload          map[string]any `json:"payload,omitempty"`
}

type ControllerOperationResult struct {
	Operation          string         `json:"operation"`
	Adapter            string         `json:"adapter"`
	TargetURL          string         `json:"target_url"`
	AuthScheme         string         `json:"auth_scheme"`
	ResponseStatus     string         `json:"response_status,omitempty"`
	ResponseSummary    string         `json:"response_summary,omitempty"`
	WarningCount       int            `json:"warning_count"`
	DriftDetected      bool           `json:"drift_detected"`
	DriftCount         int            `json:"drift_count"`
	AppliedCount       int            `json:"applied_count"`
	FailedCount        int            `json:"failed_count"`
	ControllerHealth   string         `json:"controller_health,omitempty"`
	CompatibilityScore int            `json:"compatibility_score,omitempty"`
	ObservedStateHash  string         `json:"observed_state_hash,omitempty"`
	DesiredStateHash   string         `json:"desired_state_hash,omitempty"`
	Details            map[string]any `json:"details,omitempty"`
}

type ControllerAdapterDescriptor struct {
	Platform            string   `json:"platform"`
	Label               string   `json:"label"`
	Adapter             string   `json:"adapter"`
	AuthScheme          string   `json:"auth_scheme"`
	RequiresSite        bool     `json:"requires_site"`
	EndpointTemplate    string   `json:"endpoint_template"`
	SupportedSyncModes  []string `json:"supported_sync_modes"`
	NativePolicyPush    bool     `json:"native_policy_push"`
	DriftDetection      bool     `json:"drift_detection"`
	HealthReport        bool     `json:"health_report"`
	DesiredStateHash    bool     `json:"desired_state_hash"`
	RadiusProfiles      bool     `json:"radius_profiles"`
	GuestPortal         bool     `json:"guest_portal"`
	WirelessProfiles    bool     `json:"wireless_profiles"`
	DynamicACL          bool     `json:"dynamic_acl"`
	CoA                 bool     `json:"coa"`
	DownloadableACL     bool     `json:"downloadable_acl,omitempty"`
	UserRoles           bool     `json:"user_roles,omitempty"`
	CloudInventory      bool     `json:"cloud_inventory,omitempty"`
	ZonePolicy          bool     `json:"zone_policy,omitempty"`
	PolicyProfiles      bool     `json:"policy_profiles,omitempty"`
	AddressLists        bool     `json:"address_lists,omitempty"`
	SiteProfiles        bool     `json:"site_profiles,omitempty"`
	GuestHotspot        bool     `json:"guest_hotspot,omitempty"`
	OperationalState    string   `json:"operational_state"`
	OperationalGuidance string   `json:"operational_guidance"`
}

func ControllerComponent() string {
	return controllerComponent
}

func ControllerAdapterCatalog() []ControllerAdapterDescriptor {
	platforms := []string{"generic", "cisco", "aruba", "juniper-mist", "ruckus", "fortinet", "mikrotik", "unifi", "meraki"}
	out := make([]ControllerAdapterDescriptor, 0, len(platforms))
	for _, platform := range platforms {
		out = append(out, ControllerAdapterDescriptorForPlatform(platform))
	}
	return out
}

func ControllerAdapterDescriptorForPlatform(platform string) ControllerAdapterDescriptor {
	platform = normalizeControllerPlatform(platform)
	if platform == "" {
		platform = "generic"
	}
	capabilities := controllerAdapterCapabilities(platform)
	return ControllerAdapterDescriptor{
		Platform:            platform,
		Label:               controllerAdapterLabel(platform),
		Adapter:             controllerAdapterName(platform),
		AuthScheme:          controllerAuthScheme(platform),
		RequiresSite:        controllerPlatformRequiresSite(platform),
		EndpointTemplate:    controllerEndpointTemplate(platform),
		SupportedSyncModes:  stringSliceCapability(capabilities["supported_sync_modes"]),
		NativePolicyPush:    boolCapability(capabilities["native_policy_push"]),
		DriftDetection:      boolCapability(capabilities["drift_detection"]),
		HealthReport:        boolCapability(capabilities["health_report"]),
		DesiredStateHash:    boolCapability(capabilities["desired_state_hash"]),
		RadiusProfiles:      boolCapability(capabilities["radius_profiles"]),
		GuestPortal:         boolCapability(capabilities["guest_portal"]),
		WirelessProfiles:    boolCapability(capabilities["wireless_profiles"]),
		DynamicACL:          boolCapability(capabilities["dynamic_acl"]),
		CoA:                 boolCapability(capabilities["coa"]),
		DownloadableACL:     boolCapability(capabilities["downloadable_acl"]),
		UserRoles:           boolCapability(capabilities["user_roles"]),
		CloudInventory:      boolCapability(capabilities["cloud_inventory"]),
		ZonePolicy:          boolCapability(capabilities["zone_policy"]),
		PolicyProfiles:      boolCapability(capabilities["policy_profiles"]),
		AddressLists:        boolCapability(capabilities["address_lists"]),
		SiteProfiles:        boolCapability(capabilities["site_profiles"]),
		GuestHotspot:        boolCapability(capabilities["guest_hotspot"]),
		OperationalState:    controllerAdapterOperationalState(platform),
		OperationalGuidance: controllerAdapterOperationalGuidance(platform),
	}
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
		result, err := syncControllerState(ctx, cfg)
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
			_ = db.RecordIntegrationHistory(controllerComponent, "degraded", err.Error(), details)
			_ = db.UpsertRuntimeStatus(controllerComponent, "degraded", err.Error(), details)
			return
		}
		syncCount++
		successCount++
		details["sync_count"] = syncCount
		details["success_count"] = successCount
		details["failure_count"] = failureCount
		details["last_error"] = ""
		status := controllerResultRuntimeStatus(result)
		message := "Controller automation sync completed."
		if result != nil && result.FailedCount > 0 {
			message = fmt.Sprintf("Controller automation sync completed with %d failed controller item(s).", result.FailedCount)
		} else if result != nil && result.DriftDetected {
			message = fmt.Sprintf("Controller automation sync completed with %d drift item(s).", result.DriftCount)
		} else if result != nil && strings.TrimSpace(result.ResponseSummary) != "" {
			message = fmt.Sprintf("Controller automation sync completed. %s", strings.TrimSpace(result.ResponseSummary))
		}
		_ = db.RecordIntegrationHistory(controllerComponent, status, message, details)
		_ = db.UpsertRuntimeStatus(controllerComponent, status, message, details)
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
	return executeControllerState(ctx, cfg, "push")
}

func pullControllerState(ctx context.Context, cfg *config.Config) (*controllerSyncResult, error) {
	return executeControllerState(ctx, cfg, "pull")
}

func syncControllerState(ctx context.Context, cfg *config.Config) (*controllerSyncResult, error) {
	if cfg != nil && controllerSyncModePulls(cfg.Integrations.Controller.SyncMode) {
		return pullControllerState(ctx, cfg)
	}
	return pushControllerState(ctx, cfg)
}

func controllerSyncModePulls(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "monitor", "pull-config":
		return true
	default:
		return false
	}
}

func BuildControllerSyncPreview(cfg *config.Config, operation string) (*ControllerSyncPreview, error) {
	operation, err := normalizeControllerOperation(operation)
	if err != nil {
		return nil, err
	}
	request, err := buildControllerOperationRequest(cfg, "redacted", operation)
	if err != nil {
		return nil, err
	}
	return &ControllerSyncPreview{
		Operation:        operation,
		Adapter:          request.Adapter,
		Method:           request.Method,
		TargetURL:        request.URL,
		AuthScheme:       request.AuthScheme,
		DesiredStateHash: firstNonEmptyString(request.Payload["desired_state_hash"]),
		Payload:          request.Payload,
	}, nil
}

func ExecuteControllerOperation(ctx context.Context, cfg *config.Config, operation string) (*ControllerOperationResult, error) {
	operation, err := normalizeControllerOperation(operation)
	if err != nil {
		return nil, err
	}
	result, executeErr := executeControllerState(ctx, cfg, operation)
	if result == nil {
		return nil, executeErr
	}
	return &ControllerOperationResult{
		Operation: operation, Adapter: result.Adapter, TargetURL: result.TargetURL, AuthScheme: result.AuthScheme,
		ResponseStatus: result.ResponseStatus, ResponseSummary: result.ResponseSummary, WarningCount: result.WarningCount,
		DriftDetected: result.DriftDetected, DriftCount: result.DriftCount, AppliedCount: result.AppliedCount,
		FailedCount: result.FailedCount, ControllerHealth: result.ControllerHealth, CompatibilityScore: result.CompatibilityScore,
		ObservedStateHash: result.ObservedStateHash, DesiredStateHash: result.DesiredStateHash, Details: result.ResponseDetails,
	}, executeErr
}

func executeControllerState(ctx context.Context, cfg *config.Config, operation string) (*controllerSyncResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("controller config is required")
	}
	switch normalizeControllerPlatform(cfg.Integrations.Controller.Platform) {
	case "cisco":
		return executeCiscoISEOperation(ctx, cfg, operation)
	case "aruba":
		return executeArubaCentralOperation(ctx, cfg, operation)
	case "juniper-mist":
		return executeMistOperation(ctx, cfg, operation)
	case "ruckus":
		return executeRuckusSmartZoneOperation(ctx, cfg, operation)
	case "fortinet":
		return executeFortiGateOperation(ctx, cfg, operation)
	case "mikrotik":
		return executeMikroTikOperation(ctx, cfg, operation)
	case "unifi":
		return executeUniFiOperation(ctx, cfg, operation)
	case "meraki":
		return executeMerakiOperation(ctx, cfg, operation)
	}
	token := controllerToken(cfg)
	if token == "" {
		return nil, fmt.Errorf("controller API token env %q is empty", strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv))
	}
	request, err := buildControllerOperationRequest(cfg, token, operation)
	if err != nil {
		return nil, err
	}
	var requestBody io.Reader
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		payload, err := json.Marshal(request.Payload)
		if err != nil {
			return nil, err
		}
		requestBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, requestBody)
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
			Adapter:          request.Adapter,
			TargetURL:        request.URL,
			AuthScheme:       request.AuthScheme,
			DesiredStateHash: firstNonEmptyString(request.Payload["desired_state_hash"]),
		}, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return &controllerSyncResult{
			Adapter:          request.Adapter,
			TargetURL:        request.URL,
			AuthScheme:       request.AuthScheme,
			ResponseStatus:   resp.Status,
			DesiredStateHash: firstNonEmptyString(request.Payload["desired_state_hash"]),
		}, readErr
	}

	summary, warningCount, responseDetails := parseControllerResponse(body)
	result := &controllerSyncResult{
		Adapter:          request.Adapter,
		TargetURL:        request.URL,
		AuthScheme:       request.AuthScheme,
		ResponseStatus:   resp.Status,
		ResponseSummary:  summary,
		WarningCount:     warningCount,
		DesiredStateHash: firstNonEmptyString(request.Payload["desired_state_hash"]),
		ResponseDetails:  responseDetails,
	}
	applyControllerResponseDetails(result, responseDetails)
	if result.ObservedStateHash != "" && result.DesiredStateHash != "" && !strings.EqualFold(result.ObservedStateHash, result.DesiredStateHash) {
		result.DriftDetected = true
		if result.DriftCount == 0 {
			result.DriftCount = 1
		}
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
	return buildControllerOperationRequest(cfg, token, "push")
}

func buildControllerOperationRequest(cfg *config.Config, token, operation string) (*controllerRequest, error) {
	if cfg == nil {
		return nil, fmt.Errorf("controller config is required")
	}
	operation, err := normalizeControllerOperation(operation)
	if err != nil {
		return nil, err
	}
	platform := normalizeControllerPlatform(cfg.Integrations.Controller.Platform)
	targetURL, err := controllerOperationEndpoint(cfg, platform, operation)
	if err != nil {
		return nil, err
	}

	syncMode := strings.TrimSpace(cfg.Integrations.Controller.SyncMode)
	method := http.MethodPost
	if operation == "pull" {
		syncMode = "pull-config"
		method = http.MethodGet
	}
	headers := map[string]string{
		"X-AegisNAS-Controller-Platform":  platform,
		"X-AegisNAS-Sync-Mode":            syncMode,
		"X-AegisNAS-Controller-Adapter":   controllerAdapterName(platform),
		"X-AegisNAS-Controller-Operation": operation,
	}
	authScheme := "bearer"
	switch platform {
	case "cisco", "mikrotik":
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
		authScheme = "basic"
	case "juniper-mist":
		headers["Authorization"] = "Token " + token
		authScheme = "token"
	case "unifi":
		headers["X-API-Key"] = token
		authScheme = "api-key"
	case "meraki":
		headers["X-Cisco-Meraki-API-Key"] = token
		authScheme = "api-key"
	default:
		headers["Authorization"] = "Bearer " + token
	}

	payload := buildControllerPayloadForPlatform(cfg, platform)
	attachControllerPayloadMetadata(payload, platform)
	headers["X-AegisNAS-Desired-State-Hash"] = firstNonEmptyString(payload["desired_state_hash"])

	return &controllerRequest{
		Adapter:    controllerAdapterName(platform),
		Method:     method,
		URL:        targetURL,
		AuthScheme: authScheme,
		Headers:    headers,
		Payload:    payload,
	}, nil
}

func normalizeControllerOperation(operation string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "", "push", "push-config":
		return "push", nil
	case "pull", "pull-config", "monitor", "check":
		return "pull", nil
	default:
		return "", fmt.Errorf("controller operation %q is invalid", strings.TrimSpace(operation))
	}
}

func controllerOperationEndpoint(cfg *config.Config, platform, operation string) (string, error) {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		base := strings.TrimRight(strings.TrimSpace(cfg.Integrations.Controller.Endpoint), "/")
		if base == "" {
			return "", fmt.Errorf("controller endpoint is empty")
		}
		return base + ciscoISEDACLCollection, nil
	case "aruba":
		return arubaCentralTargetURL(cfg)
	case "juniper-mist":
		return mistTargetURL(cfg)
	case "ruckus":
		return ruckusSmartZoneTargetURL(cfg)
	case "fortinet":
		return fortiGateTargetURL(cfg)
	case "mikrotik":
		return mikroTikTargetURL(cfg)
	case "unifi":
		return unifiTargetURL(cfg)
	case "meraki":
		return merakiTargetURL(cfg)
	}
	targetURL, err := controllerEndpointForPlatform(cfg, platform)
	if err != nil || operation != "pull" || normalizeControllerPlatform(platform) == "generic" {
		return targetURL, err
	}
	if strings.HasSuffix(targetURL, "/sync") {
		return strings.TrimSuffix(targetURL, "/sync") + "/state", nil
	}
	return strings.TrimRight(targetURL, "/") + "/state", nil
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
	case "unifi":
		return base + "/proxy/network/api/s/" + escapedSite + "/aegisnas/sync", nil
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
	case "unifi":
		return buildUniFiControllerPayload(cfg)
	case "meraki":
		return buildMerakiControllerPayload(cfg)
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
	return buildCiscoISEPreviewPayload(cfg)
}

func buildArubaControllerPayload(cfg *config.Config) map[string]any {
	return buildArubaCentralPreviewPayload(cfg)
}

func buildMistControllerPayload(cfg *config.Config) map[string]any {
	return buildMistPreviewPayload(cfg)
}

func buildRuckusControllerPayload(cfg *config.Config) map[string]any {
	return buildRuckusSmartZonePreviewPayload(cfg)
}

func buildFortinetControllerPayload(cfg *config.Config) map[string]any {
	return buildFortiGatePreviewPayload(cfg)
}

func buildMikroTikControllerPayload(cfg *config.Config) map[string]any {
	return buildMikroTikPreviewPayload(cfg)
}

func buildUniFiControllerPayload(cfg *config.Config) map[string]any {
	return buildUniFiPreviewPayload(cfg)
}

func buildMerakiControllerPayload(cfg *config.Config) map[string]any {
	return buildMerakiPreviewPayload(cfg)
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
	if appliedCount, ok := controllerResponseInt(payload["applied_count"]); ok {
		details["applied_count"] = appliedCount
	}
	if failedCount, ok := controllerResponseInt(payload["failed_count"]); ok {
		details["failed_count"] = failedCount
	}
	if unsupportedCount, ok := controllerResponseInt(payload["unsupported_count"]); ok {
		details["unsupported_count"] = unsupportedCount
	}
	if compatibilityScore, ok := controllerResponseInt(payload["compatibility_score"]); ok {
		details["compatibility_score"] = compatibilityScore
	}
	if health := firstNonEmptyString(payload["controller_health"], payload["health"]); health != "" {
		details["controller_health"] = health
	}
	if generation := firstNonEmptyString(payload["sync_generation"], payload["generation"]); generation != "" {
		details["sync_generation"] = generation
	}
	if observedHash := firstNonEmptyString(payload["observed_state_hash"], payload["observed_hash"]); observedHash != "" {
		details["observed_state_hash"] = observedHash
	}
	if observedState, ok := payload["observed_state"].(map[string]any); ok {
		details["observed_state"] = observedState
		if _, exists := details["observed_state_hash"]; !exists {
			details["observed_state_hash"] = controllerDesiredStateHash(observedState)
		}
	}
	appendControllerDriftDetails(details, payload)
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
	if result.DesiredStateHash != "" {
		details["desired_state_hash"] = result.DesiredStateHash
	}
	if result.ResponseStatus != "" {
		details["response_status"] = result.ResponseStatus
	}
	if result.ResponseSummary != "" {
		details["response_summary"] = result.ResponseSummary
	}
	if result.WarningCount > 0 {
		details["warning_count"] = result.WarningCount
	}
	if result.DriftDetected {
		details["drift_detected"] = true
		details["drift_count"] = result.DriftCount
	}
	if result.AppliedCount > 0 {
		details["applied_count"] = result.AppliedCount
	}
	if result.FailedCount > 0 {
		details["failed_count"] = result.FailedCount
	}
	if result.ControllerHealth != "" {
		details["controller_health"] = result.ControllerHealth
	}
	if result.CompatibilityScore > 0 {
		details["compatibility_score"] = result.CompatibilityScore
	}
	if result.ObservedStateHash != "" {
		details["observed_state_hash"] = result.ObservedStateHash
	}
	for key, value := range result.ResponseDetails {
		details[key] = value
	}
}

func attachControllerPayloadMetadata(payload map[string]any, platform string) {
	if payload == nil {
		return
	}
	payload["adapter_capabilities"] = controllerAdapterCapabilities(platform)
	payload["desired_state_hash"] = controllerDesiredStateHash(payload)
}

func controllerAdapterCapabilities(platform string) map[string]any {
	normalized := normalizeControllerPlatform(platform)
	nativeAdapter := normalized == "cisco" || normalized == "aruba" || normalized == "juniper-mist" || normalized == "ruckus" || normalized == "fortinet" || normalized == "mikrotik" || normalized == "unifi" || normalized == "meraki"
	contractPayload := normalized == "generic"
	supportedSyncModes := []string{"monitor", "pull-config", "push-config", "coa-only"}
	if nativeAdapter {
		supportedSyncModes = []string{"monitor", "pull-config", "push-config"}
	}
	capabilities := map[string]any{
		"platform":             normalized,
		"adapter":              controllerAdapterName(normalized),
		"policy_sync":          true,
		"drift_detection":      true,
		"health_report":        true,
		"desired_state_hash":   true,
		"radius_profiles":      contractPayload,
		"guest_portal":         contractPayload,
		"wireless_profiles":    contractPayload,
		"dynamic_acl":          false,
		"coa":                  false,
		"native_policy_push":   nativeAdapter,
		"supported_sync_modes": supportedSyncModes,
	}
	switch normalized {
	case "cisco":
		capabilities["dynamic_acl"] = true
		capabilities["downloadable_acl"] = true
		capabilities["user_roles"] = true
	case "aruba":
		capabilities["wireless_profiles"] = true
	case "juniper-mist":
		capabilities["wireless_profiles"] = true
	case "ruckus":
		capabilities["wireless_profiles"] = true
	case "fortinet":
		capabilities["wireless_profiles"] = true
	case "mikrotik":
		capabilities["radius_profiles"] = true
		capabilities["wireless_profiles"] = true
	case "unifi":
		capabilities["wireless_profiles"] = true
	case "meraki":
		capabilities["wireless_profiles"] = true
	}
	return capabilities
}

func controllerDesiredStateHash(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	normalized := normalizeControllerHashValue(payload)
	data, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeControllerHashValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, nested := range typed {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "generated_at", "desired_state_hash":
				continue
			default:
				normalized[key] = normalizeControllerHashValue(nested)
			}
		}
		return normalized
	case []map[string]any:
		normalized := make([]any, 0, len(typed))
		for _, item := range typed {
			normalized = append(normalized, normalizeControllerHashValue(item))
		}
		return normalized
	case []any:
		normalized := make([]any, 0, len(typed))
		for _, item := range typed {
			normalized = append(normalized, normalizeControllerHashValue(item))
		}
		return normalized
	default:
		return value
	}
}

func applyControllerResponseDetails(result *controllerSyncResult, details map[string]any) {
	if result == nil || details == nil {
		return
	}
	if driftCount, ok := controllerResponseInt(details["drift_count"]); ok {
		result.DriftCount = driftCount
	}
	if driftDetected, ok := controllerResponseBool(details["drift_detected"]); ok {
		result.DriftDetected = driftDetected
	}
	if result.DriftCount > 0 {
		result.DriftDetected = true
	}
	if result.DriftDetected && result.DriftCount == 0 {
		result.DriftCount = 1
	}
	if appliedCount, ok := controllerResponseInt(details["applied_count"]); ok {
		result.AppliedCount = appliedCount
	}
	if failedCount, ok := controllerResponseInt(details["failed_count"]); ok {
		result.FailedCount = failedCount
	}
	if compatibilityScore, ok := controllerResponseInt(details["compatibility_score"]); ok {
		result.CompatibilityScore = compatibilityScore
	}
	result.ControllerHealth = firstNonEmptyString(details["controller_health"])
	result.ObservedStateHash = firstNonEmptyString(details["observed_state_hash"])
}

func appendControllerDriftDetails(details map[string]any, payload map[string]any) {
	if details == nil || payload == nil {
		return
	}
	if driftDetected, ok := controllerResponseBool(payload["drift_detected"]); ok {
		details["drift_detected"] = driftDetected
	}
	if driftCount, ok := controllerResponseInt(payload["drift_count"]); ok {
		details["drift_count"] = driftCount
		if driftCount > 0 {
			details["drift_detected"] = true
		}
	}
	switch drift := payload["drift"].(type) {
	case map[string]any:
		if driftDetected, ok := controllerResponseBool(drift["detected"]); ok {
			details["drift_detected"] = driftDetected
		}
		if driftCount, ok := controllerResponseInt(drift["count"]); ok {
			details["drift_count"] = driftCount
			if driftCount > 0 {
				details["drift_detected"] = true
			}
		}
		if items, ok := drift["items"]; ok {
			details["drift_items"] = items
		}
		if summary := firstNonEmptyString(drift["summary"], drift["message"]); summary != "" {
			details["drift_summary"] = summary
		}
	case []any:
		if len(drift) > 0 {
			details["drift_detected"] = true
			details["drift_count"] = len(drift)
			details["drift_items"] = drift
		}
	}
	if driftDetected, ok := controllerResponseBool(details["drift_detected"]); ok && driftDetected {
		if _, ok := details["drift_count"]; !ok {
			details["drift_count"] = 1
		}
	}
}

func controllerResponseInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case uint:
		return int(typed), true
	case uint8:
		return int(typed), true
	case uint16:
		return int(typed), true
	case uint32:
		return int(typed), true
	case uint64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		number, err := typed.Int64()
		if err == nil {
			return int(number), true
		}
		decimal, err := typed.Float64()
		if err == nil {
			return int(decimal), true
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func controllerResponseBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "yes", "y", "1", "detected":
			return true, true
		case "false", "no", "n", "0", "none", "clear":
			return false, true
		}
	}
	return false, false
}

func controllerResultRuntimeStatus(result *controllerSyncResult) string {
	if result == nil {
		return "ok"
	}
	if result.FailedCount > 0 || result.DriftDetected || controllerHealthIsDegraded(result.ControllerHealth) {
		return "degraded"
	}
	return "ok"
}

func controllerHealthIsDegraded(health string) bool {
	switch strings.ToLower(strings.TrimSpace(health)) {
	case "", "ok", "up", "healthy", "available", "synced", "ready":
		return false
	case "degraded", "down", "failed", "error", "unhealthy", "offline", "critical":
		return true
	default:
		return false
	}
}

func normalizeControllerPlatform(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "ubnt", "ubiquiti":
		return "unifi"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
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
		return "cisco-ise-ers"
	case "aruba":
		return "aruba-central-classic"
	case "juniper-mist":
		return "juniper-mist"
	case "ruckus":
		return "ruckus-smartzone"
	case "fortinet":
		return "fortinet-fortigate"
	case "mikrotik":
		return "mikrotik-routeros"
	case "unifi":
		return "unifi-network"
	case "meraki":
		return "cisco-meraki-dashboard"
	default:
		return "generic-rest"
	}
}

func controllerAdapterLabel(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		return "Cisco ISE ERS"
	case "aruba":
		return "HPE Aruba Networking Central Classic"
	case "juniper-mist":
		return "Juniper Mist"
	case "ruckus":
		return "Ruckus SmartZone"
	case "fortinet":
		return "Fortinet FortiGate / FortiWLC"
	case "mikrotik":
		return "MikroTik RouterOS"
	case "unifi":
		return "Ubiquiti UniFi Network"
	case "meraki":
		return "Cisco Meraki Dashboard"
	default:
		return "Generic REST Controller"
	}
}

func controllerAuthScheme(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		return "basic"
	case "juniper-mist":
		return "token"
	case "ruckus":
		return "session"
	case "mikrotik":
		return "basic"
	case "unifi", "meraki":
		return "api-key"
	default:
		return "bearer"
	}
}

func controllerEndpointTemplate(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		return "{endpoint}/ers/config/downloadableacl and /ers/config/authorizationprofile"
	case "aruba":
		return "{endpoint}/configuration/v2/wlan/{group}/{wlan}"
	case "juniper-mist":
		return "{endpoint}/api/v1/sites/{site_id}/wlans"
	case "ruckus":
		return "{endpoint}/wsg/api/public/v13_1/rkszones/{zone_id}/wlans"
	case "fortinet":
		return "{endpoint}/api/v2/cmdb/wireless-controller/vap/{name}?vdom={vdom}"
	case "mikrotik":
		return "{endpoint}/rest/radius and /rest/interface/wifi/{security,datapath,configuration}"
	case "unifi":
		return "{endpoint}/v1/sites/{siteId}/wifi/broadcasts"
	case "meraki":
		return "{endpoint}/networks/{networkId}/wireless/ssids/{number}"
	default:
		return "{endpoint}"
	}
}

func controllerAdapterOperationalState(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "generic":
		return "contract"
	case "cisco", "aruba", "juniper-mist", "ruckus", "fortinet", "mikrotik", "unifi", "meraki":
		return "native-adapter"
	default:
		return "unsupported"
	}
}

func controllerAdapterOperationalGuidance(platform string) string {
	switch normalizeControllerPlatform(platform) {
	case "cisco":
		return "Uses Cisco ISE ERS Basic authentication to inspect and reconcile downloadable ACL and authorization profile resources."
	case "aruba":
		return "Uses Aruba Central Classic Configuration v2 bearer APIs to inspect and reconcile enterprise WLANs against an existing Central RADIUS profile; guest, role, ACL, and CoA resources are not yet mutated."
	case "juniper-mist":
		return "Uses the Mist site WLAN API with Token authentication to inspect and reconcile WPA2/WPA3 Enterprise WLANs, including RADIUS, accounting, CoA, VLAN, isolation, and client-limit fields."
	case "ruckus":
		return "Uses SmartZone Public API v13_1 session authentication to inspect and reconcile zone-scoped WPA2/WPA3 Enterprise WLANs against an existing authentication service."
	case "fortinet":
		return "Uses the FortiOS CMDB bearer API to inspect and reconcile FortiAP enterprise VAPs against an existing FortiGate RADIUS profile."
	case "mikrotik":
		return "Uses RouterOS v7 REST Basic authentication to reconcile managed RADIUS, WiFi security, datapath, and configuration profiles; radio-specific CAPsMAN provisioning remains an explicit operator step."
	case "unifi":
		return "Uses the official UniFi Network integration API with X-API-Key authentication to reconcile site WiFi broadcasts against existing RADIUS profiles and VLAN networks."
	case "meraki":
		return "Uses the Meraki Dashboard API with X-Cisco-Meraki-API-Key authentication to reconcile existing network SSID slots by exact name, including RADIUS, accounting, CoA, VLAN, visibility, and isolation fields."
	default:
		return "Use when an external system implements the AegisNAS generic controller sync contract."
	}
}

func boolCapability(value any) bool {
	typed, _ := value.(bool)
	return typed
}

func stringSliceCapability(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, value := range typed {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	default:
		return nil
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

func waitForControllerRetry(ctx context.Context, value string, maxDelay time.Duration) error {
	delay := time.Second
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	} else if retryAt, err := http.ParseTime(value); err == nil {
		delay = time.Until(retryAt)
	}
	if delay < 0 {
		delay = 0
	}
	if maxDelay > 0 && delay > maxDelay {
		delay = maxDelay
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
