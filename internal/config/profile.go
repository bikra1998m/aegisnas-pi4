package config

import (
	"strconv"
	"strings"
)

type deploymentPreset struct {
	Profile                        string
	Form                           string
	Label                          string
	Summary                        string
	RecommendedMinMemoryMB         int
	RecommendedMinCPUCores         int
	RecommendedAILite              bool
	RecommendedAIMode              string
	RecommendedAIProvider          string
	RecommendedTelemetry           bool
	RecommendedRuntimeShaping      bool
	RecommendedWireless            bool
	RecommendedPreferExternalAP    bool
	RecommendedUpstreamStatusCheck string
	RecommendedRadiusMaxSessions   int
	RecommendedRecommendationLimit int
}

type HardwareScalingPlan struct {
	Mode                 string                  `json:"mode"`
	SelectedProfile      string                  `json:"selected_profile"`
	RecommendedProfile   string                  `json:"recommended_profile"`
	HardwareKnown        bool                    `json:"hardware_known"`
	StorageKnown         bool                    `json:"storage_known"`
	CanRunSelected       bool                    `json:"can_run_selected"`
	Summary              string                  `json:"summary"`
	Reason               string                  `json:"reason"`
	ResourceSummary      string                  `json:"resource_summary"`
	RecommendedRetention HardwareRetentionPlan   `json:"recommended_retention"`
	RecommendedLimits    HardwareScalingLimits   `json:"recommended_limits"`
	GatingActions        []HardwareScalingAction `json:"gating_actions"`
}

type HardwareRetentionPlan struct {
	AnalyticsRetentionHours int    `json:"analytics_retention_hours"`
	ProfilingRetentionHours int    `json:"profiling_retention_hours"`
	LeaseHistoryPollSeconds int    `json:"lease_history_poll_seconds"`
	Description             string `json:"description"`
}

type HardwareScalingLimits struct {
	RadiusMaxSessions   int    `json:"radius_max_sessions"`
	RecommendationLimit int    `json:"recommendation_limit"`
	ControllerSyncMode  string `json:"controller_sync_mode"`
	PreferredAPModel    string `json:"preferred_ap_model"`
}

type HardwareScalingAction struct {
	Key            string   `json:"key"`
	Label          string   `json:"label"`
	State          string   `json:"state"`
	Active         bool     `json:"active"`
	ConfigPaths    []string `json:"config_paths,omitempty"`
	Current        string   `json:"current,omitempty"`
	Recommended    string   `json:"recommended,omitempty"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
}

func EffectiveDeploymentProfile(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "", "branch":
		return "branch"
	case "lite", "enterprise", "custom":
		return strings.ToLower(strings.TrimSpace(input))
	default:
		return strings.ToLower(strings.TrimSpace(input))
	}
}

func EffectiveDeploymentForm(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "", "physical":
		return "physical"
	case "virtual":
		return "virtual"
	default:
		return strings.ToLower(strings.TrimSpace(input))
	}
}

func EffectiveAIMode(cfg *Config) string {
	if cfg == nil {
		return "lite"
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.AILite.Mode))
	if mode == "" {
		return "lite"
	}
	return mode
}

func EffectiveAIProvider(cfg *Config) string {
	if cfg == nil {
		return "local"
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.AILite.Provider))
	if provider == "" {
		if EffectiveAIMode(cfg) == "full" {
			return "openai-compatible"
		}
		return "local"
	}
	return provider
}

func DeploymentSummary(cfg *Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}

	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	form := EffectiveDeploymentForm(cfg.Deployment.Form)
	preset := deploymentPresetFor(profile, form)
	capabilities := EvaluateFeatureCapabilities(cfg)

	return map[string]any{
		"profile":                profile,
		"form":                   form,
		"label":                  preset.Label,
		"summary":                preset.Summary,
		"recommended_min_memory": preset.RecommendedMinMemoryMB,
		"recommended_min_cores":  preset.RecommendedMinCPUCores,
		"hardware": map[string]any{
			"memory_mb":            cfg.Deployment.Hardware.MemoryMB,
			"cpu_cores":            cfg.Deployment.Hardware.CPUCores,
			"storage_gb":           cfg.Deployment.Hardware.StorageGB,
			"prefer_external_ap":   cfg.Deployment.Hardware.PreferExternalAP,
			"wireless_passthrough": cfg.Deployment.Hardware.WirelessPassthrough,
		},
		"scaling": EvaluateHardwareScalingPlan(cfg),
		"recommended": map[string]any{
			"ai_lite_enabled":       preset.RecommendedAILite,
			"ai_mode":               preset.RecommendedAIMode,
			"ai_provider":           preset.RecommendedAIProvider,
			"telemetry_enabled":     preset.RecommendedTelemetry,
			"runtime_shaping":       preset.RecommendedRuntimeShaping,
			"wireless_enabled":      preset.RecommendedWireless,
			"prefer_external_ap":    preset.RecommendedPreferExternalAP,
			"upstream_status_check": preset.RecommendedUpstreamStatusCheck,
			"radius_max_sessions":   preset.RecommendedRadiusMaxSessions,
			"recommendation_limit":  preset.RecommendedRecommendationLimit,
		},
		"effective": map[string]any{
			"ai_lite_enabled":         cfg.AILite.Enabled,
			"ai_mode":                 EffectiveAIMode(cfg),
			"ai_provider":             EffectiveAIProvider(cfg),
			"ai_model":                cfg.AILite.Model,
			"telemetry_enabled":       cfg.Telemetry.Enabled,
			"runtime_shaping":         cfg.Policy.RuntimeShapingEnabled,
			"wireless_enabled":        cfg.Wireless.Enabled,
			"prefer_external_ap":      cfg.Deployment.Hardware.PreferExternalAP,
			"guest_self_registration": cfg.Portal.GuestWorkflows.SelfRegistrationEnabled,
			"sponsor_approval":        cfg.Portal.GuestWorkflows.SponsorApprovalEnabled,
			"guest_invite_delivery":   cfg.Portal.GuestWorkflows.InviteDelivery,
			"device_inventory":        cfg.Onboarding.DeviceInventoryEnabled,
			"onboarding_portal":       cfg.Onboarding.PortalEnabled,
			"certificate_enrollment":  cfg.Onboarding.CertificateEnrollmentEnabled,
			"eap_tls_onboarding":      cfg.Onboarding.EAPTLSEnabled,
			"passive_profiling":       cfg.Profiling.PassiveEnabled,
			"posture_checks":          cfg.Profiling.PostureEnabled,
			"mdm_uem_integration":     cfg.Profiling.MDMSyncEnabled,
			"siem_webhook_export":     cfg.Integrations.SIEM.Enabled,
			"controller_automation":   cfg.Integrations.Controller.Enabled,
			"high_availability":       cfg.HighAvailability.Enabled,
			"admin_sso":               cfg.Integrations.AdminSSO.Enabled,
			"delegated_admin_rbac":    cfg.Governance.DelegatedAdminEnabled,
			"multi_tenant_governance": cfg.Governance.MultiTenantEnabled,
			"upstream_status_check":   cfg.Radius.Upstream.StatusCheck,
			"radius_max_sessions":     cfg.Radius.MaxSessions,
			"recommendation_limit":    cfg.AILite.RecommendationLimit,
		},
		"service_plan": map[string]any{
			"always_on":           deploymentAlwaysOnServices(),
			"optional":            deploymentOptionalServices(cfg),
			"disabled_by_profile": deploymentDisabledServices(cfg),
		},
		"capabilities": capabilities,
		"warnings":     deploymentWarnings(cfg, preset, capabilities),
	}
}

func deploymentPresetFor(profile, form string) deploymentPreset {
	switch profile {
	case "lite":
		return deploymentPreset{
			Profile:                        profile,
			Form:                           form,
			Label:                          "Lite Edge Profile",
			Summary:                        "Constrained hardware profile for very small sites, labs, and reduced-service appliances.",
			RecommendedMinMemoryMB:         1024,
			RecommendedMinCPUCores:         2,
			RecommendedAILite:              false,
			RecommendedAIMode:              "lite",
			RecommendedAIProvider:          "local",
			RecommendedTelemetry:           false,
			RecommendedRuntimeShaping:      false,
			RecommendedWireless:            form == "physical",
			RecommendedPreferExternalAP:    form == "virtual",
			RecommendedUpstreamStatusCheck: "none",
			RecommendedRadiusMaxSessions:   256,
			RecommendedRecommendationLimit: 25,
		}
	case "enterprise":
		return deploymentPreset{
			Profile:                        profile,
			Form:                           form,
			Label:                          "Enterprise Edge Profile",
			Summary:                        "Higher-capacity profile for heavier EAP, more clients, and richer operational visibility.",
			RecommendedMinMemoryMB:         8192,
			RecommendedMinCPUCores:         4,
			RecommendedAILite:              true,
			RecommendedAIMode:              "full",
			RecommendedAIProvider:          "openai-compatible",
			RecommendedTelemetry:           true,
			RecommendedRuntimeShaping:      true,
			RecommendedWireless:            form == "physical",
			RecommendedPreferExternalAP:    form == "virtual",
			RecommendedUpstreamStatusCheck: "status-server",
			RecommendedRadiusMaxSessions:   4096,
			RecommendedRecommendationLimit: 250,
		}
	case "custom":
		return deploymentPreset{
			Profile:                        profile,
			Form:                           form,
			Label:                          "Custom Profile",
			Summary:                        "Operator-managed profile with no opinionated resource preset beyond the selected deployment form.",
			RecommendedMinMemoryMB:         4096,
			RecommendedMinCPUCores:         2,
			RecommendedAILite:              true,
			RecommendedAIMode:              "lite",
			RecommendedAIProvider:          "local",
			RecommendedTelemetry:           true,
			RecommendedRuntimeShaping:      true,
			RecommendedWireless:            form == "physical",
			RecommendedPreferExternalAP:    form == "virtual",
			RecommendedUpstreamStatusCheck: "status-server",
			RecommendedRadiusMaxSessions:   1024,
			RecommendedRecommendationLimit: 100,
		}
	default:
		return deploymentPreset{
			Profile:                        "branch",
			Form:                           form,
			Label:                          "Branch Profile",
			Summary:                        "Balanced default for branch appliances, pilot production, and most customer-facing edge deployments.",
			RecommendedMinMemoryMB:         4096,
			RecommendedMinCPUCores:         2,
			RecommendedAILite:              true,
			RecommendedAIMode:              "lite",
			RecommendedAIProvider:          "local",
			RecommendedTelemetry:           true,
			RecommendedRuntimeShaping:      true,
			RecommendedWireless:            form == "physical",
			RecommendedPreferExternalAP:    form == "virtual",
			RecommendedUpstreamStatusCheck: "status-server",
			RecommendedRadiusMaxSessions:   1024,
			RecommendedRecommendationLimit: 100,
		}
	}
}

func EvaluateHardwareScalingPlan(cfg *Config) HardwareScalingPlan {
	if cfg == nil {
		return HardwareScalingPlan{}
	}
	selected := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	if selected == "custom" {
		selected = "branch"
	}
	mode := RecommendedHardwareScalingMode(cfg)
	recommended := mode
	if recommended == "" {
		recommended = selected
	}
	plan := HardwareScalingPlan{
		Mode:                 mode,
		SelectedProfile:      EffectiveDeploymentProfile(cfg.Deployment.Profile),
		RecommendedProfile:   recommended,
		HardwareKnown:        hardwareCPUAndMemoryKnown(cfg),
		StorageKnown:         cfg.Deployment.Hardware.StorageGB > 0,
		CanRunSelected:       profileRank(selected) <= profileRank(recommended),
		RecommendedRetention: hardwareRetentionPlan(recommended),
		RecommendedLimits:    hardwareScalingLimits(cfg, recommended),
	}
	plan.ResourceSummary = hardwareResourceSummary(cfg)
	plan.GatingActions = hardwareScalingActions(cfg, recommended)
	if plan.CanRunSelected {
		plan.Summary = "Selected deployment profile fits the declared hardware scaling mode."
	} else {
		plan.Summary = "Selected deployment profile is above the declared hardware scaling mode."
	}
	plan.Reason = hardwareScalingReason(cfg, recommended, plan.HardwareKnown, plan.StorageKnown)
	return plan
}

func RecommendedHardwareScalingMode(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	memory := cfg.Deployment.Hardware.MemoryMB
	cores := cfg.Deployment.Hardware.CPUCores
	storage := cfg.Deployment.Hardware.StorageGB
	switch {
	case memory >= 8192 && cores >= 4 && storageMeets(storage, 64):
		return "enterprise"
	case memory >= 4096 && cores >= 2 && storageMeets(storage, 32):
		return "branch"
	default:
		return "lite"
	}
}

func hardwareScalingActions(cfg *Config, mode string) []HardwareScalingAction {
	if cfg == nil {
		return nil
	}
	actions := []HardwareScalingAction{}
	add := func(action HardwareScalingAction) {
		actions = append(actions, action)
	}
	if mode == "lite" {
		add(scalingAction("ai_mode", "AI Analysis", "warn", cfg.AILite.Enabled, []string{"ailite.enabled", "ailite.mode"}, EffectiveAIMode(cfg), "disabled", "AI analysis should stay off or very small on lite hardware.", "Disable AI analysis or keep AI Lite with a small recommendation limit."))
		add(scalingAction("telemetry", "Telemetry", "warn", cfg.Telemetry.Enabled, []string{"telemetry.enabled"}, boolText(cfg.Telemetry.Enabled), "false", "Lite mode should keep analytics and exporters minimal.", "Disable telemetry or keep polling/export intervals conservative."))
		add(scalingAction("runtime_shaping", "Runtime Shaping", "gate", cfg.Policy.RuntimeShapingEnabled, []string{"policy.runtime_shaping_enabled"}, boolText(cfg.Policy.RuntimeShapingEnabled), "false", "Runtime shaping is gated on lite hardware.", "Use branch hardware before enabling local shaping."))
		add(scalingAction("guest_self_registration", "Guest Self-Registration", "gate", cfg.Portal.GuestWorkflows.SelfRegistrationEnabled, []string{"portal.guest_workflows.self_registration_enabled"}, boolText(cfg.Portal.GuestWorkflows.SelfRegistrationEnabled), "false", "Guest self-registration is gated on lite hardware.", "Move to branch or enterprise hardware for guest workflow automation."))
		add(scalingAction("device_registration_inventory", "Device Registration Inventory", "gate", cfg.Onboarding.DeviceInventoryEnabled, []string{"onboarding.device_inventory_enabled"}, boolText(cfg.Onboarding.DeviceInventoryEnabled), "false", "Device inventory is gated on lite hardware.", "Use branch hardware before enabling inventory-driven onboarding."))
		add(scalingAction("onboarding_portal", "Onboarding Portal", "gate", cfg.Onboarding.PortalEnabled, []string{"onboarding.portal_enabled"}, boolText(cfg.Onboarding.PortalEnabled), "false", "BYOD onboarding is gated on lite hardware.", "Move to branch or enterprise hardware for onboarding flows."))
		add(scalingAction("certificate_enrollment", "Certificate Enrollment", "gate", cfg.Onboarding.CertificateEnrollmentEnabled, []string{"onboarding.certificate_enrollment_enabled"}, boolText(cfg.Onboarding.CertificateEnrollmentEnabled), "false", "Certificate enrollment is gated on lite hardware.", "Use enterprise hardware for certificate lifecycle operations."))
		add(scalingAction("eap_tls_onboarding", "EAP-TLS Onboarding", "gate", cfg.Onboarding.EAPTLSEnabled, []string{"onboarding.eap_tls_enabled"}, boolText(cfg.Onboarding.EAPTLSEnabled), "false", "EAP-TLS onboarding is gated on lite hardware.", "Use enterprise hardware before enabling certificate-heavy authentication."))
		add(scalingAction("passive_profiling", "Passive Profiling", "gate", cfg.Profiling.PassiveEnabled, []string{"profiling.passive_enabled"}, boolText(cfg.Profiling.PassiveEnabled), "false", "Passive profiling is gated on lite hardware.", "Use branch hardware for shallow profiling or enterprise hardware for posture workflows."))
		add(scalingAction("posture_checks", "Posture Checks", "gate", cfg.Profiling.PostureEnabled, []string{"profiling.posture_enabled"}, boolText(cfg.Profiling.PostureEnabled), "false", "Posture checks are gated on lite hardware.", "Use enterprise hardware with MDM or compliance inputs."))
		add(scalingAction("mdm_uem_integration", "MDM/UEM Integration", "gate", cfg.Profiling.MDMSyncEnabled, []string{"profiling.mdm_sync_enabled"}, boolText(cfg.Profiling.MDMSyncEnabled), "false", "Authoritative MDM sync is gated on lite hardware.", "Use enterprise hardware for MDM-backed posture."))
		add(scalingAction("siem_webhook_export", "SIEM Export", "gate", cfg.Integrations.SIEM.Enabled, []string{"integrations.siem.enabled"}, boolText(cfg.Integrations.SIEM.Enabled), "false", "SIEM export is gated on lite hardware.", "Use branch or enterprise hardware for durable export pipelines."))
		add(scalingAction("controller_automation", "Controller Automation", "gate", cfg.Integrations.Controller.Enabled, []string{"integrations.controller.enabled"}, boolText(cfg.Integrations.Controller.Enabled), "false", "Controller automation is gated on lite hardware.", "Use branch hardware for controller sync or enterprise for larger controller estates."))
		add(scalingAction("high_availability_failover", "High Availability / Failover", "gate", cfg.HighAvailability.Enabled, []string{"high_availability.enabled"}, boolText(cfg.HighAvailability.Enabled), "false", "HA failover is gated on lite hardware.", "Use enterprise hardware for active/standby orchestration."))
		add(scalingAction("admin_sso", "Admin SSO", "gate", cfg.Integrations.AdminSSO.Enabled, []string{"integrations.admin_sso.enabled"}, boolText(cfg.Integrations.AdminSSO.Enabled), "false", "Admin SSO is gated on lite hardware.", "Use branch or enterprise hardware for delegated admin identity."))
		add(scalingAction("delegated_admin_rbac", "Delegated Admin RBAC", "gate", cfg.Governance.DelegatedAdminEnabled, []string{"governance.delegated_admin_enabled"}, boolText(cfg.Governance.DelegatedAdminEnabled), "false", "Delegated admin RBAC is gated on lite hardware.", "Use branch or enterprise hardware for delegated administration."))
		add(scalingAction("multi_tenant_governance", "Multi-Tenant Governance", "gate", cfg.Governance.MultiTenantEnabled, []string{"governance.multi_tenant_enabled"}, boolText(cfg.Governance.MultiTenantEnabled), "false", "Multi-tenant governance is gated on lite hardware.", "Use enterprise hardware for multi-tenant control planes."))
		return actions
	}
	if mode == "branch" {
		add(scalingAction("ai_mode", "AI Analysis", "warn", cfg.AILite.Enabled && EffectiveAIMode(cfg) == "full", []string{"ailite.mode"}, EffectiveAIMode(cfg), "lite", "Full AI should be treated as enterprise scope.", "Use AI Lite on branch hardware unless an external AI endpoint is intentionally sized."))
		add(scalingAction("certificate_enrollment", "Certificate Enrollment", "gate", cfg.Onboarding.CertificateEnrollmentEnabled, []string{"onboarding.certificate_enrollment_enabled"}, boolText(cfg.Onboarding.CertificateEnrollmentEnabled), "false", "Certificate enrollment is gated to enterprise hardware.", "Use enterprise hardware for certificate lifecycle operations."))
		add(scalingAction("eap_tls_onboarding", "EAP-TLS Onboarding", "gate", cfg.Onboarding.EAPTLSEnabled, []string{"onboarding.eap_tls_enabled"}, boolText(cfg.Onboarding.EAPTLSEnabled), "false", "EAP-TLS onboarding is gated to enterprise hardware.", "Use enterprise hardware before enabling certificate-heavy authentication."))
		add(scalingAction("posture_checks", "Posture Checks", "gate", cfg.Profiling.PostureEnabled, []string{"profiling.posture_enabled"}, boolText(cfg.Profiling.PostureEnabled), "false", "Posture checks are gated to enterprise hardware.", "Use enterprise hardware with MDM or compliance inputs."))
		add(scalingAction("mdm_uem_integration", "MDM/UEM Integration", "gate", cfg.Profiling.MDMSyncEnabled, []string{"profiling.mdm_sync_enabled"}, boolText(cfg.Profiling.MDMSyncEnabled), "false", "Authoritative MDM sync is gated to enterprise hardware.", "Use enterprise hardware before treating MDM sync as a source of truth."))
		add(scalingAction("high_availability_failover", "High Availability / Failover", "gate", cfg.HighAvailability.Enabled, []string{"high_availability.enabled"}, boolText(cfg.HighAvailability.Enabled), "false", "HA failover is gated to enterprise hardware.", "Use enterprise hardware for active/standby orchestration."))
		add(scalingAction("multi_tenant_governance", "Multi-Tenant Governance", "gate", cfg.Governance.MultiTenantEnabled, []string{"governance.multi_tenant_enabled"}, boolText(cfg.Governance.MultiTenantEnabled), "false", "Multi-tenant governance is gated to enterprise hardware.", "Use enterprise hardware for tenant-scoped operations."))
		add(scalingAction("passive_profiling", "Passive Profiling", "warn", cfg.Profiling.PassiveEnabled && cfg.Profiling.RetentionHours > 24, []string{"profiling.retention_hours"}, intText(cfg.Profiling.RetentionHours), "24", "Branch profiling should keep retention moderate.", "Keep profiling retention at or below 24 hours on branch hardware."))
		return actions
	}
	add(scalingAction("enterprise_capacity", "Enterprise Capacity", "allow", true, nil, mode, "enterprise", "Enterprise hardware can run the full feature set when integrations are configured.", "Use per-feature validation to finish external dependencies."))
	return actions
}

func scalingAction(key, label, state string, active bool, paths []string, current, recommended, summary, recommendation string) HardwareScalingAction {
	return HardwareScalingAction{
		Key:            key,
		Label:          label,
		State:          state,
		Active:         active,
		ConfigPaths:    paths,
		Current:        current,
		Recommended:    recommended,
		Summary:        summary,
		Recommendation: recommendation,
	}
}

func hardwareRetentionPlan(mode string) HardwareRetentionPlan {
	switch mode {
	case "enterprise":
		return HardwareRetentionPlan{AnalyticsRetentionHours: 720, ProfilingRetentionHours: 168, LeaseHistoryPollSeconds: 60, Description: "Longer operational history, posture, and analytics retention are appropriate."}
	case "branch":
		return HardwareRetentionPlan{AnalyticsRetentionHours: 168, ProfilingRetentionHours: 24, LeaseHistoryPollSeconds: 300, Description: "Moderate local history for branch troubleshooting without heavy analytics pressure."}
	default:
		return HardwareRetentionPlan{AnalyticsRetentionHours: 24, ProfilingRetentionHours: 6, LeaseHistoryPollSeconds: 900, Description: "Short retention and shallow polling protect low-spec storage and CPU."}
	}
}

func hardwareScalingLimits(cfg *Config, mode string) HardwareScalingLimits {
	switch mode {
	case "enterprise":
		return HardwareScalingLimits{RadiusMaxSessions: 4096, RecommendationLimit: 250, ControllerSyncMode: "push-config", PreferredAPModel: preferredAPModel(cfg)}
	case "branch":
		return HardwareScalingLimits{RadiusMaxSessions: 1024, RecommendationLimit: 100, ControllerSyncMode: "monitor", PreferredAPModel: preferredAPModel(cfg)}
	default:
		return HardwareScalingLimits{RadiusMaxSessions: 256, RecommendationLimit: 25, ControllerSyncMode: "disabled", PreferredAPModel: "external-ap"}
	}
}

func hardwareScalingReason(cfg *Config, mode string, hardwareKnown, storageKnown bool) string {
	if !hardwareKnown {
		return "CPU or memory is not declared, so AegisNAS uses the conservative lite scaling mode until hardware is described."
	}
	if !storageKnown {
		return "Storage is not declared; CPU and memory select " + mode + " mode, but storage should be declared before relying on long retention."
	}
	return "CPU, memory, and storage select " + mode + " mode."
}

func hardwareResourceSummary(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	memory := intText(cfg.Deployment.Hardware.MemoryMB)
	if cfg.Deployment.Hardware.MemoryMB <= 0 {
		memory = "unknown"
	}
	cores := intText(cfg.Deployment.Hardware.CPUCores)
	if cfg.Deployment.Hardware.CPUCores <= 0 {
		cores = "unknown"
	}
	storage := intText(cfg.Deployment.Hardware.StorageGB)
	if cfg.Deployment.Hardware.StorageGB <= 0 {
		storage = "unknown"
	}
	return cores + " CPU cores, " + memory + " MB RAM, " + storage + " GB storage"
}

func preferredAPModel(cfg *Config) string {
	if cfg == nil || cfg.Deployment.Hardware.PreferExternalAP {
		return "external-ap"
	}
	if EffectiveDeploymentForm(cfg.Deployment.Form) == "virtual" && !cfg.Deployment.Hardware.WirelessPassthrough {
		return "external-ap"
	}
	return "local-or-external-ap"
}

func storageMeets(storageGB, minimumGB int) bool {
	return storageGB <= 0 || storageGB >= minimumGB
}

func recommendedStorageFloorGB(profile string) int {
	switch EffectiveDeploymentProfile(profile) {
	case "enterprise":
		return 64
	case "branch", "custom":
		return 32
	default:
		return 8
	}
}

func hardwareCPUAndMemoryKnown(cfg *Config) bool {
	return cfg != nil && cfg.Deployment.Hardware.MemoryMB > 0 && cfg.Deployment.Hardware.CPUCores > 0
}

func profileRank(profile string) int {
	switch EffectiveDeploymentProfile(profile) {
	case "enterprise":
		return 3
	case "branch", "custom":
		return 2
	default:
		return 1
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func intText(value int) string {
	return strconv.Itoa(value)
}

func deploymentAlwaysOnServices() []string {
	return []string{
		"aegis-admin-api",
		"aegis-gateway",
		"aegis-policy",
		"aegis-portal",
		"aegis-radius",
		"aegis-session",
	}
}

func deploymentOptionalServices(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	services := make([]string, 0, 4)
	if cfg.DHCP.Enabled {
		services = append(services, "dnsmasq")
	}
	if cfg.Radius.Enabled() {
		services = append(services, "freeradius")
	}
	if cfg.Telemetry.Enabled {
		services = append(services, "aegis-telemetry")
	}
	if cfg.AILite.Enabled {
		services = append(services, "aegis-ai-lite")
	}
	if cfg.Wireless.Enabled {
		services = append(services, "hostapd")
	}
	return services
}

func deploymentDisabledServices(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	services := make([]string, 0, 3)
	if !cfg.Telemetry.Enabled {
		services = append(services, "aegis-telemetry")
	}
	if !cfg.AILite.Enabled {
		services = append(services, "aegis-ai-lite")
	}
	if !cfg.Wireless.Enabled {
		services = append(services, "hostapd")
	}
	return services
}

func deploymentWarnings(cfg *Config, preset deploymentPreset, capabilities []FeatureCapability) []string {
	if cfg == nil {
		return []string{}
	}

	warnings := make([]string, 0)
	if memory := cfg.Deployment.Hardware.MemoryMB; memory > 0 && memory < preset.RecommendedMinMemoryMB {
		warnings = append(warnings, "Configured memory is below the recommended minimum for this deployment profile.")
	}
	if cores := cfg.Deployment.Hardware.CPUCores; cores > 0 && cores < preset.RecommendedMinCPUCores {
		warnings = append(warnings, "Configured CPU cores are below the recommended minimum for this deployment profile.")
	}
	if storage := cfg.Deployment.Hardware.StorageGB; storage > 0 && storage < recommendedStorageFloorGB(EffectiveDeploymentProfile(cfg.Deployment.Profile)) {
		warnings = append(warnings, "Configured storage is below the recommended minimum for this deployment profile.")
	}
	scaling := EvaluateHardwareScalingPlan(cfg)
	if !scaling.CanRunSelected {
		warnings = append(warnings, scaling.Summary)
	}
	capabilityIndex := make(map[string]FeatureCapability, len(capabilities))
	for _, capability := range capabilities {
		capabilityIndex[capability.Key] = capability
	}
	for _, key := range []string{"local_wireless", "runtime_shaping", "ai_mode", "telemetry", "upstream_status_probes", "guest_self_registration", "sponsor_approval", "guest_delivery", "device_registration_inventory", "onboarding_portal", "certificate_enrollment", "eap_tls_onboarding", "passive_profiling", "posture_checks", "mdm_uem_integration", "siem_webhook_export", "controller_automation", "high_availability_failover", "admin_sso", "delegated_admin_rbac", "multi_tenant_governance"} {
		capability, ok := capabilityIndex[key]
		if !ok || !capability.Active {
			continue
		}
		switch capability.State {
		case CapabilityWarned, CapabilityDegraded, CapabilityBlocked:
			warnings = append(warnings, capability.Summary)
		}
	}

	return dedupeWarnings(warnings)
}

func dedupeWarnings(warnings []string) []string {
	if len(warnings) == 0 {
		return warnings
	}
	seen := make(map[string]struct{}, len(warnings))
	out := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		if _, exists := seen[warning]; exists {
			continue
		}
		seen[warning] = struct{}{}
		out = append(out, warning)
	}
	return out
}
