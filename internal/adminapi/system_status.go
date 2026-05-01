package adminapi

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type serviceStatus struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Port      int    `json:"port,omitempty"`
	URL       string `json:"url,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func HandleGetSystemStatus(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	runtimeStatuses, err := db.GetRuntimeStatuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeMap := make(map[string]db.RuntimeStatus, len(runtimeStatuses))
	for _, item := range runtimeStatuses {
		runtimeMap[item.Component] = item
	}

	services := []serviceStatus{
		httpServiceStatus("admin_api", "Admin API", cfg.AdminPort),
		httpServiceStatus("gateway", "Gateway", cfg.Health.Port),
		httpServiceStatus("portal", "Portal", cfg.Portal.Port),
		httpServiceStatus("policy", "Policy", cfg.Health.Port+2),
		httpServiceStatus("ai_lite", "AI Engine", cfg.Health.Port+4),
		httpServiceStatus("radius", "RADIUS Broker", cfg.Health.Port+5),
		httpServiceStatus("telemetry", "Telemetry", cfg.Health.Port+6),
		httpServiceStatus("session", "Session Service", cfg.Health.Port+7),
		systemdServiceStatus("freeradius", "FreeRADIUS"),
		systemdServiceStatus("dnsmasq", "dnsmasq"),
		systemdServiceStatus("nftables", "nftables"),
		systemdServiceStatus("hostapd", "hostapd"),
	}

	if !cfg.AILite.Enabled {
		services = replaceServiceStatus(services, "ai_lite", serviceStatus{
			Key:     "ai_lite",
			Label:   "AI Engine",
			Kind:    "http",
			Status:  "disabled",
			Message: "AI engine is disabled in config",
		})
	}
	if !cfg.Telemetry.Enabled {
		services = replaceServiceStatus(services, "telemetry", serviceStatus{
			Key:     "telemetry",
			Label:   "Telemetry",
			Kind:    "http",
			Status:  "disabled",
			Message: "Telemetry is disabled in config",
		})
	}
	if !cfg.Wireless.Enabled {
		services = replaceServiceStatus(services, "hostapd", serviceStatus{
			Key:     "hostapd",
			Label:   "hostapd",
			Kind:    "systemd",
			Status:  "disabled",
			Message: "Wireless is disabled in config",
		})
	}

	users, _ := enforcement.CountUsers()
	activeSessions, _ := enforcement.CountActiveSessions()
	quarantinedSessions, _ := enforcement.CountQuarantinedSessions()
	pendingChanges, _ := enforcement.CountPendingChanges()
	unackedAlerts, _ := enforcement.CountUnacknowledgedAlerts()
	enabledRadiusClients, _ := enforcement.CountEnabledRadiusClients()
	authMethods, _ := enforcement.CountSessionsByAuthMethod()
	shapedSessions := 0
	if enforcement.RuntimeShapingEnabled(cfg) {
		shapedSessions, _ = enforcement.CountShapedSessions()
	}

	healthyServices := 0
	for _, service := range services {
		if service.Status == "ok" {
			healthyServices++
		}
	}

	upstreamStatuses, probeErr := radius.ProbeUpstreamServers(r.Context(), cfg)

	radiusStatus := map[string]any{
		"upstream_enabled":        cfg.Radius.Upstream.Enabled,
		"realm":                   cfg.Radius.Upstream.Realm,
		"pool_strategy":           cfg.Radius.Upstream.PoolStrategy,
		"configured_servers":      cfg.Radius.Upstream.Servers,
		"server_statuses":         upstreamStatuses,
		"enabled_radius_clients":  enabledRadiusClients,
		"broker_auth":             runtimeMap["radius_broker_auth"],
		"broker_accounting":       runtimeMap["radius_broker_accounting"],
		"dynamic_authorization":   cfg.Radius.DynamicAuth,
		"request_timeout_seconds": cfg.Radius.RequestTimeoutSeconds,
	}
	if probeErr != nil {
		radiusStatus["probe_error"] = probeErr.Error()
	}
	if !cfg.Radius.Upstream.Enabled {
		radiusStatus["broker_auth"] = map[string]any{"status": "disabled", "message": "Upstream AAA is disabled"}
		radiusStatus["broker_accounting"] = map[string]any{"status": "disabled", "message": "Upstream AAA is disabled"}
	}

	wirelessStatus := map[string]any{
		"enabled":             cfg.Wireless.Enabled,
		"interface":           cfg.Wireless.Interface,
		"country_code":        cfg.Wireless.CountryCode,
		"channel":             cfg.Wireless.Channel,
		"hostapd_config_path": cfg.Wireless.HostapdConfigPath,
		"ssid_count":          len(cfg.Wireless.SSIDs),
		"auth_modes":          ssidAuthModes(cfg.Wireless.SSIDs),
	}

	enforcementStatus := map[string]any{
		"shaping_enabled":   enforcement.RuntimeShapingEnabled(cfg) && enforcement.ShapingInterface(cfg) != "",
		"shaping_interface": enforcement.ShapingInterface(cfg),
		"shaped_sessions":   shapedSessions,
		"shaper":            runtimeMap["runtime_shaper"],
	}
	if !enforcement.RuntimeShapingEnabled(cfg) {
		enforcementStatus["shaper"] = map[string]any{"status": "disabled", "message": "Runtime shaping is disabled by deployment or policy config"}
	} else if enforcement.ShapingInterface(cfg) == "" {
		enforcementStatus["shaper"] = map[string]any{"status": "disabled", "message": "No downstream interface is configured for runtime shaping"}
	}

	integrationsStatus := map[string]any{
		"admin_sso": map[string]any{
			"enabled":      cfg.Integrations.AdminSSO.Enabled,
			"provider":     cfg.Integrations.AdminSSO.Provider,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"groups_claim": cfg.Integrations.AdminSSO.GroupsClaim,
			"session":      runtimeMap["admin_sso"],
		},
		"siem": map[string]any{
			"enabled":    cfg.Integrations.SIEM.Enabled,
			"provider":   cfg.Integrations.SIEM.Provider,
			"endpoint":   cfg.Integrations.SIEM.Endpoint,
			"batch_size": cfg.Integrations.SIEM.BatchSize,
			"export":     runtimeMap["siem_export"],
		},
	}
	if !cfg.Integrations.AdminSSO.Enabled {
		integrationsStatus["admin_sso"] = map[string]any{
			"enabled":      false,
			"provider":     cfg.Integrations.AdminSSO.Provider,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"groups_claim": cfg.Integrations.AdminSSO.GroupsClaim,
			"session":      map[string]any{"status": "disabled", "message": "Admin SSO is disabled in config"},
		}
	} else if !strings.EqualFold(strings.TrimSpace(cfg.Integrations.AdminSSO.Provider), "oidc") {
		integrationsStatus["admin_sso"] = map[string]any{
			"enabled":      true,
			"provider":     cfg.Integrations.AdminSSO.Provider,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"groups_claim": cfg.Integrations.AdminSSO.GroupsClaim,
			"session":      map[string]any{"status": "degraded", "message": "Only OIDC admin SSO is available in this release."},
		}
	}
	if !cfg.Integrations.SIEM.Enabled {
		integrationsStatus["siem"] = map[string]any{
			"enabled":    false,
			"provider":   cfg.Integrations.SIEM.Provider,
			"endpoint":   cfg.Integrations.SIEM.Endpoint,
			"batch_size": cfg.Integrations.SIEM.BatchSize,
			"export":     map[string]any{"status": "disabled", "message": "SIEM export is disabled in config"},
		}
	} else if !cfg.Telemetry.Enabled {
		integrationsStatus["siem"] = map[string]any{
			"enabled":    true,
			"provider":   cfg.Integrations.SIEM.Provider,
			"endpoint":   cfg.Integrations.SIEM.Endpoint,
			"batch_size": cfg.Integrations.SIEM.BatchSize,
			"export":     map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so SIEM export is not running."},
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary": map[string]any{
			"users":                 users,
			"active_sessions":       activeSessions,
			"quarantined_sessions":  quarantinedSessions,
			"shaped_sessions":       shapedSessions,
			"pending_changes":       pendingChanges,
			"unacknowledged_alerts": unackedAlerts,
			"healthy_services":      healthyServices,
			"total_services":        len(services),
			"session_methods":       authMethods,
		},
		"services":     services,
		"deployment":   config.DeploymentSummary(cfg),
		"radius":       radiusStatus,
		"wireless":     wirelessStatus,
		"enforcement":  enforcementStatus,
		"integrations": integrationsStatus,
	})
}

func httpServiceStatus(key, label string, port int) serviceStatus {
	status := serviceStatus{
		Key:   key,
		Label: label,
		Kind:  "http",
		Port:  port,
		URL:   fmt.Sprintf("http://127.0.0.1:%d/health", port),
	}
	client := http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get(status.URL)
	if err != nil {
		status.Status = "down"
		status.Message = err.Error()
		return status
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		status.Status = "ok"
		status.Message = resp.Status
		return status
	}
	status.Status = "degraded"
	status.Message = resp.Status
	return status
}

func systemdServiceStatus(name, label string) serviceStatus {
	status := serviceStatus{
		Key:   strings.ToLower(strings.ReplaceAll(name, " ", "_")),
		Label: label,
		Kind:  "systemd",
	}
	cmd := exec.Command("systemctl", "is-active", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			status.Status = "unknown"
			status.Message = err.Error()
			return status
		}
		status.Status = "down"
		status.Message = trimmed
		return status
	}
	trimmed := strings.TrimSpace(string(output))
	switch trimmed {
	case "active":
		status.Status = "ok"
	default:
		status.Status = "degraded"
	}
	status.Message = trimmed
	return status
}

func replaceServiceStatus(services []serviceStatus, key string, replacement serviceStatus) []serviceStatus {
	for index, service := range services {
		if service.Key == key {
			services[index] = replacement
			return services
		}
	}
	return append(services, replacement)
}

func ssidAuthModes(ssids []config.SSIDConfig) []string {
	seen := map[string]struct{}{}
	var modes []string
	for _, ssid := range ssids {
		mode := strings.TrimSpace(ssid.AuthMode)
		if mode == "" {
			continue
		}
		if _, exists := seen[mode]; exists {
			continue
		}
		seen[mode] = struct{}{}
		modes = append(modes, mode)
	}
	return modes
}
