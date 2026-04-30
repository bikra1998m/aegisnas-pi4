package config

import "strings"

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
			"prefer_external_ap":   cfg.Deployment.Hardware.PreferExternalAP,
			"wireless_passthrough": cfg.Deployment.Hardware.WirelessPassthrough,
		},
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
	capabilityIndex := make(map[string]FeatureCapability, len(capabilities))
	for _, capability := range capabilities {
		capabilityIndex[capability.Key] = capability
	}
	for _, key := range []string{"local_wireless", "runtime_shaping", "ai_mode", "telemetry", "upstream_status_probes", "guest_self_registration", "sponsor_approval", "guest_delivery", "device_registration_inventory", "onboarding_portal", "certificate_enrollment", "eap_tls_onboarding", "passive_profiling", "posture_checks"} {
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
