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

func DeploymentSummary(cfg *Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}

	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	form := EffectiveDeploymentForm(cfg.Deployment.Form)
	preset := deploymentPresetFor(profile, form)

	return map[string]any{
		"profile":                profile,
		"form":                   form,
		"label":                  preset.Label,
		"summary":                preset.Summary,
		"recommended_min_memory": preset.RecommendedMinMemoryMB,
		"recommended_min_cores":  preset.RecommendedMinCPUCores,
		"hardware": map[string]any{
			"memory_mb":          cfg.Deployment.Hardware.MemoryMB,
			"cpu_cores":          cfg.Deployment.Hardware.CPUCores,
			"prefer_external_ap": cfg.Deployment.Hardware.PreferExternalAP,
		},
		"recommended": map[string]any{
			"ai_lite_enabled":       preset.RecommendedAILite,
			"telemetry_enabled":     preset.RecommendedTelemetry,
			"runtime_shaping":       preset.RecommendedRuntimeShaping,
			"wireless_enabled":      preset.RecommendedWireless,
			"prefer_external_ap":    preset.RecommendedPreferExternalAP,
			"upstream_status_check": preset.RecommendedUpstreamStatusCheck,
			"radius_max_sessions":   preset.RecommendedRadiusMaxSessions,
			"recommendation_limit":  preset.RecommendedRecommendationLimit,
		},
		"effective": map[string]any{
			"ai_lite_enabled":       cfg.AILite.Enabled,
			"telemetry_enabled":     cfg.Telemetry.Enabled,
			"runtime_shaping":       cfg.Policy.RuntimeShapingEnabled,
			"wireless_enabled":      cfg.Wireless.Enabled,
			"prefer_external_ap":    cfg.Deployment.Hardware.PreferExternalAP,
			"upstream_status_check": cfg.Radius.Upstream.StatusCheck,
			"radius_max_sessions":   cfg.Radius.MaxSessions,
			"recommendation_limit":  cfg.AILite.RecommendationLimit,
		},
		"service_plan": map[string]any{
			"always_on":           deploymentAlwaysOnServices(),
			"optional":            deploymentOptionalServices(cfg),
			"disabled_by_profile": deploymentDisabledServices(cfg),
		},
		"warnings": deploymentWarnings(cfg, preset),
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

func deploymentWarnings(cfg *Config, preset deploymentPreset) []string {
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
	if EffectiveDeploymentForm(cfg.Deployment.Form) == "virtual" && cfg.Wireless.Enabled {
		warnings = append(warnings, "Virtual form is using local wireless. Use an external AP unless PCI or USB Wi-Fi passthrough is available.")
	}
	if cfg.Deployment.Hardware.MemoryMB > 0 && cfg.Deployment.Hardware.MemoryMB < 2048 {
		if cfg.AILite.Enabled {
			warnings = append(warnings, "AI Lite is enabled on a very low-memory target. Consider disabling it for constrained hardware.")
		}
		if cfg.Telemetry.Enabled {
			warnings = append(warnings, "Telemetry is enabled on a very low-memory target. Consider disabling it or reducing retention expectations.")
		}
		if cfg.Policy.RuntimeShapingEnabled {
			warnings = append(warnings, "Runtime shaping is enabled on a very low-memory target. Consider disabling it unless bandwidth policy is essential.")
		}
	}
	if EffectiveDeploymentProfile(cfg.Deployment.Profile) == "lite" && cfg.Radius.Upstream.StatusCheck == "status-server" {
		warnings = append(warnings, "Lite profile is still using active upstream Status-Server probes. Consider switching to status_check: none on constrained hardware.")
	}
	if cfg.Deployment.Hardware.PreferExternalAP && cfg.Wireless.Enabled {
		warnings = append(warnings, "External AP preference is enabled while local wireless is also enabled. Pick one radio model for predictable operations.")
	}
	return warnings
}
