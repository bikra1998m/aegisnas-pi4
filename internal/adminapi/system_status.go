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
	applyStats, err := db.GetNetworkApplyStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	leaseTrends, err := db.GetDHCPLeaseTrendSummary(24 * time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	haHistoryStats, err := db.GetHAHistoryStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	recoveryState, err := CurrentNetworkRecoveryState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
			"metadata_url": adminSSOMetadataURL(cfg),
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
		"controller": map[string]any{
			"enabled":   cfg.Integrations.Controller.Enabled,
			"platform":  cfg.Integrations.Controller.Platform,
			"endpoint":  cfg.Integrations.Controller.Endpoint,
			"sync_mode": cfg.Integrations.Controller.SyncMode,
			"site":      cfg.Integrations.Controller.Site,
			"sync":      runtimeMap["controller_automation"],
		},
	}
	if !cfg.Integrations.AdminSSO.Enabled {
		integrationsStatus["admin_sso"] = map[string]any{
			"enabled":      false,
			"provider":     cfg.Integrations.AdminSSO.Provider,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"metadata_url": adminSSOMetadataURL(cfg),
			"groups_claim": cfg.Integrations.AdminSSO.GroupsClaim,
			"session":      map[string]any{"status": "disabled", "message": "Admin SSO is disabled in config"},
		}
	} else if !adminSSOProviderSupported(cfg.Integrations.AdminSSO.Provider) {
		integrationsStatus["admin_sso"] = map[string]any{
			"enabled":      true,
			"provider":     cfg.Integrations.AdminSSO.Provider,
			"issuer_url":   cfg.Integrations.AdminSSO.IssuerURL,
			"redirect_url": cfg.Integrations.AdminSSO.RedirectURL,
			"metadata_url": adminSSOMetadataURL(cfg),
			"groups_claim": cfg.Integrations.AdminSSO.GroupsClaim,
			"session":      map[string]any{"status": "degraded", "message": "This admin SSO provider is not supported by the runtime."},
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
	if !cfg.Integrations.Controller.Enabled {
		integrationsStatus["controller"] = map[string]any{
			"enabled":   false,
			"platform":  cfg.Integrations.Controller.Platform,
			"endpoint":  cfg.Integrations.Controller.Endpoint,
			"sync_mode": cfg.Integrations.Controller.SyncMode,
			"site":      cfg.Integrations.Controller.Site,
			"sync":      map[string]any{"status": "disabled", "message": "Controller automation is disabled in config"},
		}
	} else if !cfg.Telemetry.Enabled {
		integrationsStatus["controller"] = map[string]any{
			"enabled":   true,
			"platform":  cfg.Integrations.Controller.Platform,
			"endpoint":  cfg.Integrations.Controller.Endpoint,
			"sync_mode": cfg.Integrations.Controller.SyncMode,
			"site":      cfg.Integrations.Controller.Site,
			"sync":      map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so controller automation is not running."},
		}
	}

	profilingStatus := map[string]any{
		"mac_inventory_enabled": cfg.Profiling.MACInventoryEnabled,
		"passive_enabled":       cfg.Profiling.PassiveEnabled,
		"posture_enabled":       cfg.Profiling.PostureEnabled,
		"mdm_sync_enabled":      cfg.Profiling.MDMSyncEnabled,
		"mdm_provider":          cfg.Profiling.MDMProvider,
		"mdm_endpoint":          cfg.Profiling.MDMEndpoint,
		"compliance_webhook":    cfg.Profiling.ComplianceWebhook,
		"device_inventory":      runtimeMap["device_inventory"],
		"mdm_sync":              runtimeMap["mdm_sync"],
		"posture_checks":        runtimeMap["posture_checks"],
	}
	if !cfg.Profiling.MACInventoryEnabled && !cfg.Profiling.PassiveEnabled && !cfg.Profiling.PostureEnabled && !cfg.Profiling.MDMSyncEnabled {
		profilingStatus["device_inventory"] = map[string]any{"status": "disabled", "message": "Profiling runtime is disabled in config"}
		profilingStatus["mdm_sync"] = map[string]any{"status": "disabled", "message": "MDM sync is disabled in config"}
		profilingStatus["posture_checks"] = map[string]any{"status": "disabled", "message": "Posture checks are disabled in config"}
	} else if !cfg.Telemetry.Enabled {
		profilingStatus["device_inventory"] = map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so profiling runtime is not running."}
		profilingStatus["mdm_sync"] = map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so MDM sync is not running."}
		profilingStatus["posture_checks"] = map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so posture checks are not running."}
	}

	telemetryStatus := map[string]any{
		"enabled":                    cfg.Telemetry.Enabled,
		"prometheus_port":            cfg.Telemetry.PrometheusPort,
		"lease_history_poll_seconds": cfg.Telemetry.LeaseHistoryPollSeconds,
		"support_bundle_exports": map[string]any{
			"enabled":          cfg.Telemetry.SupportBundleExports.Enabled,
			"directory":        cfg.Telemetry.SupportBundleExports.Directory,
			"interval_minutes": cfg.Telemetry.SupportBundleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SupportBundleExports.RetentionCount,
			"runtime":          runtimeMap[supportBundleExportsComponent],
		},
		"diagnostics_exports": map[string]any{
			"enabled":          cfg.Telemetry.DiagnosticsExports.Enabled,
			"directory":        cfg.Telemetry.DiagnosticsExports.Directory,
			"format":           cfg.Telemetry.DiagnosticsExports.Format,
			"interval_minutes": cfg.Telemetry.DiagnosticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.DiagnosticsExports.RetentionCount,
			"runtime":          runtimeMap[diagnosticsExportsComponent],
		},
		"audit_exports": map[string]any{
			"enabled":          cfg.Telemetry.AuditExports.Enabled,
			"directory":        cfg.Telemetry.AuditExports.Directory,
			"format":           cfg.Telemetry.AuditExports.Format,
			"interval_minutes": cfg.Telemetry.AuditExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.AuditExports.RetentionCount,
			"runtime":          runtimeMap[auditExportsComponent],
		},
		"session_exports": map[string]any{
			"enabled":          cfg.Telemetry.SessionExports.Enabled,
			"directory":        cfg.Telemetry.SessionExports.Directory,
			"format":           cfg.Telemetry.SessionExports.Format,
			"interval_minutes": cfg.Telemetry.SessionExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionExports.RetentionCount,
			"runtime":          runtimeMap[sessionExportsComponent],
		},
		"session_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.SessionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.SessionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.SessionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.SessionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[sessionAnalyticsExportsComponent],
		},
		"guest_lifecycle_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestLifecycleExports.Enabled,
			"directory":        cfg.Telemetry.GuestLifecycleExports.Directory,
			"format":           cfg.Telemetry.GuestLifecycleExports.Format,
			"interval_minutes": cfg.Telemetry.GuestLifecycleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestLifecycleExports.RetentionCount,
			"runtime":          runtimeMap[guestLifecycleExportsComponent],
		},
		"integration_exports": map[string]any{
			"enabled":          cfg.Telemetry.IntegrationExports.Enabled,
			"directory":        cfg.Telemetry.IntegrationExports.Directory,
			"format":           cfg.Telemetry.IntegrationExports.Format,
			"interval_minutes": cfg.Telemetry.IntegrationExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.IntegrationExports.RetentionCount,
			"runtime":          runtimeMap[integrationExportsComponent],
		},
		"ha_exports": map[string]any{
			"enabled":          cfg.Telemetry.HAExports.Enabled,
			"directory":        cfg.Telemetry.HAExports.Directory,
			"format":           cfg.Telemetry.HAExports.Format,
			"interval_minutes": cfg.Telemetry.HAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.HAExports.RetentionCount,
			"runtime":          runtimeMap[haExportsComponent],
		},
		"network_exports": map[string]any{
			"enabled":          cfg.Telemetry.NetworkExports.Enabled,
			"directory":        cfg.Telemetry.NetworkExports.Directory,
			"format":           cfg.Telemetry.NetworkExports.Format,
			"interval_minutes": cfg.Telemetry.NetworkExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.NetworkExports.RetentionCount,
			"runtime":          runtimeMap[networkExportsComponent],
		},
		"upstream_aaa_exports": map[string]any{
			"enabled":          cfg.Telemetry.UpstreamAAAExports.Enabled,
			"directory":        cfg.Telemetry.UpstreamAAAExports.Directory,
			"format":           cfg.Telemetry.UpstreamAAAExports.Format,
			"interval_minutes": cfg.Telemetry.UpstreamAAAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpstreamAAAExports.RetentionCount,
			"runtime":          runtimeMap[upstreamAAAExportsComponent],
		},
		"upgrade_readiness_exports": map[string]any{
			"enabled":          cfg.Telemetry.UpgradeReadinessExports.Enabled,
			"directory":        cfg.Telemetry.UpgradeReadinessExports.Directory,
			"format":           cfg.Telemetry.UpgradeReadinessExports.Format,
			"interval_minutes": cfg.Telemetry.UpgradeReadinessExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpgradeReadinessExports.RetentionCount,
			"runtime":          runtimeMap[upgradeReadinessExportsComponent],
		},
	}
	if !cfg.Telemetry.Enabled {
		telemetryStatus["support_bundle_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.SupportBundleExports.Enabled,
			"directory":        cfg.Telemetry.SupportBundleExports.Directory,
			"interval_minutes": cfg.Telemetry.SupportBundleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SupportBundleExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled support bundle exports are not running."},
		}
		telemetryStatus["diagnostics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.DiagnosticsExports.Enabled,
			"directory":        cfg.Telemetry.DiagnosticsExports.Directory,
			"format":           cfg.Telemetry.DiagnosticsExports.Format,
			"interval_minutes": cfg.Telemetry.DiagnosticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.DiagnosticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled diagnostics exports are not running."},
		}
		telemetryStatus["audit_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.AuditExports.Enabled,
			"directory":        cfg.Telemetry.AuditExports.Directory,
			"format":           cfg.Telemetry.AuditExports.Format,
			"interval_minutes": cfg.Telemetry.AuditExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.AuditExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled audit exports are not running."},
		}
		telemetryStatus["session_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.SessionExports.Enabled,
			"directory":        cfg.Telemetry.SessionExports.Directory,
			"format":           cfg.Telemetry.SessionExports.Format,
			"interval_minutes": cfg.Telemetry.SessionExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled session exports are not running."},
		}
		telemetryStatus["session_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.SessionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.SessionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.SessionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.SessionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled session analytics exports are not running."},
		}
		telemetryStatus["guest_lifecycle_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestLifecycleExports.Enabled,
			"directory":        cfg.Telemetry.GuestLifecycleExports.Directory,
			"format":           cfg.Telemetry.GuestLifecycleExports.Format,
			"interval_minutes": cfg.Telemetry.GuestLifecycleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestLifecycleExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest lifecycle exports are not running."},
		}
		telemetryStatus["integration_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.IntegrationExports.Enabled,
			"directory":        cfg.Telemetry.IntegrationExports.Directory,
			"format":           cfg.Telemetry.IntegrationExports.Format,
			"interval_minutes": cfg.Telemetry.IntegrationExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.IntegrationExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled integration exports are not running."},
		}
		telemetryStatus["ha_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.HAExports.Enabled,
			"directory":        cfg.Telemetry.HAExports.Directory,
			"format":           cfg.Telemetry.HAExports.Format,
			"interval_minutes": cfg.Telemetry.HAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.HAExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled HA exports are not running."},
		}
		telemetryStatus["network_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.NetworkExports.Enabled,
			"directory":        cfg.Telemetry.NetworkExports.Directory,
			"format":           cfg.Telemetry.NetworkExports.Format,
			"interval_minutes": cfg.Telemetry.NetworkExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.NetworkExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled network exports are not running."},
		}
		telemetryStatus["upstream_aaa_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.UpstreamAAAExports.Enabled,
			"directory":        cfg.Telemetry.UpstreamAAAExports.Directory,
			"format":           cfg.Telemetry.UpstreamAAAExports.Format,
			"interval_minutes": cfg.Telemetry.UpstreamAAAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpstreamAAAExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled upstream AAA exports are not running."},
		}
		telemetryStatus["upgrade_readiness_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.UpgradeReadinessExports.Enabled,
			"directory":        cfg.Telemetry.UpgradeReadinessExports.Directory,
			"format":           cfg.Telemetry.UpgradeReadinessExports.Format,
			"interval_minutes": cfg.Telemetry.UpgradeReadinessExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpgradeReadinessExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled upgrade readiness exports are not running."},
		}
	} else if !cfg.Telemetry.DiagnosticsExports.Enabled {
		telemetryStatus["diagnostics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.DiagnosticsExports.Directory,
			"format":           cfg.Telemetry.DiagnosticsExports.Format,
			"interval_minutes": cfg.Telemetry.DiagnosticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.DiagnosticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled diagnostics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.SupportBundleExports.Enabled {
		telemetryStatus["support_bundle_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.SupportBundleExports.Directory,
			"interval_minutes": cfg.Telemetry.SupportBundleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SupportBundleExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled support bundle exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.AuditExports.Enabled {
		telemetryStatus["audit_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.AuditExports.Directory,
			"format":           cfg.Telemetry.AuditExports.Format,
			"interval_minutes": cfg.Telemetry.AuditExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.AuditExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled audit exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.SessionExports.Enabled {
		telemetryStatus["session_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.SessionExports.Directory,
			"format":           cfg.Telemetry.SessionExports.Format,
			"interval_minutes": cfg.Telemetry.SessionExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled session exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.SessionAnalyticsExports.Enabled {
		telemetryStatus["session_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.SessionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.SessionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.SessionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.SessionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled session analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestLifecycleExports.Enabled {
		telemetryStatus["guest_lifecycle_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestLifecycleExports.Directory,
			"format":           cfg.Telemetry.GuestLifecycleExports.Format,
			"interval_minutes": cfg.Telemetry.GuestLifecycleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestLifecycleExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest lifecycle exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.IntegrationExports.Enabled {
		telemetryStatus["integration_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.IntegrationExports.Directory,
			"format":           cfg.Telemetry.IntegrationExports.Format,
			"interval_minutes": cfg.Telemetry.IntegrationExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.IntegrationExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled integration exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.HAExports.Enabled {
		telemetryStatus["ha_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.HAExports.Directory,
			"format":           cfg.Telemetry.HAExports.Format,
			"interval_minutes": cfg.Telemetry.HAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.HAExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled HA exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.NetworkExports.Enabled {
		telemetryStatus["network_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.NetworkExports.Directory,
			"format":           cfg.Telemetry.NetworkExports.Format,
			"interval_minutes": cfg.Telemetry.NetworkExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.NetworkExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled network exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.UpstreamAAAExports.Enabled {
		telemetryStatus["upstream_aaa_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.UpstreamAAAExports.Directory,
			"format":           cfg.Telemetry.UpstreamAAAExports.Format,
			"interval_minutes": cfg.Telemetry.UpstreamAAAExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpstreamAAAExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled upstream AAA exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.UpgradeReadinessExports.Enabled {
		telemetryStatus["upgrade_readiness_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.UpgradeReadinessExports.Directory,
			"format":           cfg.Telemetry.UpgradeReadinessExports.Format,
			"interval_minutes": cfg.Telemetry.UpgradeReadinessExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.UpgradeReadinessExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled upgrade readiness exports are disabled in config."},
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
		"services":    services,
		"deployment":  config.DeploymentSummary(cfg),
		"radius":      radiusStatus,
		"wireless":    wirelessStatus,
		"enforcement": enforcementStatus,
		"high_availability": map[string]any{
			"enabled":                                  cfg.HighAvailability.Enabled,
			"role":                                     cfg.HighAvailability.Role,
			"peer_api_url":                             cfg.HighAvailability.PeerAPIURL,
			"virtual_ip":                               cfg.HighAvailability.VirtualIP,
			"heartbeat_interval_seconds":               cfg.HighAvailability.HeartbeatIntervalSeconds,
			"failover_timeout_seconds":                 cfg.HighAvailability.FailoverTimeoutSeconds,
			"replication_interval_seconds":             cfg.HighAvailability.ReplicationIntervalSeconds,
			"replication_stale_after_seconds":          cfg.HighAvailability.ReplicationStaleAfterSeconds,
			"split_brain_protection_enabled":           cfg.HighAvailability.SplitBrainProtectionEnabled,
			"auto_stage_shared_package":                cfg.HighAvailability.AutoStageSharedPackage,
			"auto_activate_on_failover":                cfg.HighAvailability.AutoActivateOnFailover,
			"witness_api_url":                          cfg.HighAvailability.WitnessAPIURL,
			"witness_urls":                             cfg.HighAvailability.WitnessURLs,
			"witness_quorum":                           cfg.HighAvailability.WitnessQuorum,
			"witness_weights":                          cfg.HighAvailability.WitnessWeights,
			"witness_weight_threshold":                 cfg.HighAvailability.WitnessWeightThreshold,
			"witness_groups":                           cfg.HighAvailability.WitnessGroups,
			"witness_min_distinct_groups":              cfg.HighAvailability.WitnessMinDistinctGroups,
			"witness_required_groups":                  cfg.HighAvailability.WitnessRequiredGroups,
			"witness_sources":                          cfg.HighAvailability.WitnessSources,
			"witness_source_confidence":                cfg.HighAvailability.WitnessSourceConfidence,
			"witness_required_sources":                 cfg.HighAvailability.WitnessRequiredSources,
			"witness_required_urls":                    cfg.HighAvailability.WitnessRequiredURLs,
			"witness_required_sources_by_tier":         cfg.HighAvailability.WitnessRequiredSourcesByTier,
			"witness_required_urls_by_tier":            cfg.HighAvailability.WitnessRequiredURLsByTier,
			"witness_required_groups_by_tier":          cfg.HighAvailability.WitnessRequiredGroupsByTier,
			"witness_policy_mode":                      cfg.HighAvailability.WitnessPolicyMode,
			"witness_policy_mode_by_tier":              cfg.HighAvailability.WitnessPolicyModeByTier,
			"witness_failure_tolerance":                cfg.HighAvailability.WitnessFailureTolerance,
			"witness_failure_weight_tolerance":         cfg.HighAvailability.WitnessFailureWeightTolerance,
			"witness_min_approvals_by_tier":            cfg.HighAvailability.WitnessMinApprovalsByTier,
			"witness_min_weight_by_tier":               cfg.HighAvailability.WitnessMinWeightByTier,
			"witness_min_distinct_groups_by_tier":      cfg.HighAvailability.WitnessMinDistinctGroupsByTier,
			"witness_min_distinct_sources_by_tier":     cfg.HighAvailability.WitnessMinDistinctSourcesByTier,
			"witness_max_age_by_tier":                  cfg.HighAvailability.WitnessMaxAgeByTier,
			"witness_required_node_by_tier":            cfg.HighAvailability.WitnessRequiredNodeByTier,
			"witness_signature_required_tiers":         cfg.HighAvailability.WitnessSignatureRequiredTiers,
			"witness_replay_required_tiers":            cfg.HighAvailability.WitnessReplayRequiredTiers,
			"witness_failure_tolerance_by_tier":        cfg.HighAvailability.WitnessFailureToleranceByTier,
			"witness_failure_weight_tolerance_by_tier": cfg.HighAvailability.WitnessFailureWeightByTier,
			"witness_blocking_tiers":                   cfg.HighAvailability.WitnessBlockingTiers,
			"witness_token_env":                        cfg.HighAvailability.WitnessTokenEnv,
			"witness_signing_key_env":                  cfg.HighAvailability.WitnessSigningKeyEnv,
			"witness_max_age_seconds":                  cfg.HighAvailability.WitnessMaxAgeSeconds,
			"witness_required_node":                    cfg.HighAvailability.WitnessRequiredNode,
			"witness_replay_protection_enabled":        cfg.HighAvailability.WitnessReplayProtectionEnabled,
			"preempt":                                  cfg.HighAvailability.Preempt,
			"preempt_holdoff_seconds":                  cfg.HighAvailability.PreemptHoldoffSeconds,
			"shared_state_dir":                         cfg.HighAvailability.SharedStateDir,
			"runtime":                                  runtimeMap["high_availability"],
			"replication_runtime":                      runtimeMap["ha_replication"],
			"post_failover_recovery":                   runtimeMap["ha_post_failover_recovery"],
			"history_stats":                            haHistoryStats,
		},
		"integrations": integrationsStatus,
		"profiling":    profilingStatus,
		"telemetry":    telemetryStatus,
		"network_observability": map[string]any{
			"apply_stats":     applyStats,
			"lease_trends":    leaseTrends,
			"recovery":        recoveryState,
			"controller_sync": runtimeMap["controller_automation"],
		},
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
