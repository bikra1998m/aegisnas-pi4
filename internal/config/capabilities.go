package config

import (
	"fmt"
	"strings"
)

const (
	CapabilityEnabled   = "enabled"
	CapabilityAvailable = "available"
	CapabilityWarned    = "warned"
	CapabilityDegraded  = "degraded"
	CapabilityBlocked   = "blocked"
)

type FeatureCapability struct {
	Key            string   `json:"key"`
	Label          string   `json:"label"`
	State          string   `json:"state"`
	Active         bool     `json:"active"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

func ShapingInterface(cfg *Config) string {
	if cfg == nil || !cfg.Policy.RuntimeShapingEnabled {
		return ""
	}
	if name := strings.TrimSpace(cfg.LAN.Name); name != "" {
		return name
	}
	if cfg.Mode == "trunk" {
		return strings.TrimSpace(cfg.WAN.Name)
	}
	return ""
}

func RuntimeShapingEnabled(cfg *Config) bool {
	return cfg != nil && cfg.Policy.RuntimeShapingEnabled
}

func EvaluateFeatureCapabilities(cfg *Config) []FeatureCapability {
	if cfg == nil {
		return nil
	}

	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	form := EffectiveDeploymentForm(cfg.Deployment.Form)
	preset := deploymentPresetFor(profile, form)

	return []FeatureCapability{
		evaluateLocalWirelessCapability(cfg, preset),
		evaluateRuntimeShapingCapability(cfg, preset),
		evaluateAIModeCapability(cfg),
		evaluateTelemetryCapability(cfg),
		evaluateUpstreamStatusProbeCapability(cfg),
	}
}

func evaluateLocalWirelessCapability(cfg *Config, preset deploymentPreset) FeatureCapability {
	virtualNoPassthrough := EffectiveDeploymentForm(cfg.Deployment.Form) == "virtual" && !cfg.Deployment.Hardware.WirelessPassthrough
	capability := FeatureCapability{
		Key:    "local_wireless",
		Label:  "Local Wireless",
		Active: cfg.Wireless.Enabled,
	}

	switch {
	case cfg.Wireless.Enabled && virtualNoPassthrough:
		capability.State = CapabilityBlocked
		capability.Summary = "Local wireless is enabled on a virtual appliance without a passthrough radio."
		capability.Recommendation = "Disable wireless or set deployment.hardware.wireless_passthrough when a real USB or PCI Wi-Fi radio is attached."
		capability.Dependencies = []string{"deployment.hardware.wireless_passthrough", "wireless.interface"}
	case virtualNoPassthrough:
		capability.State = CapabilityBlocked
		capability.Summary = "Local wireless is unavailable on a plain virtual NIC."
		capability.Recommendation = "Use an external AP or mark deployment.hardware.wireless_passthrough when a real Wi-Fi radio is attached to the VM."
		capability.Dependencies = []string{"deployment.hardware.wireless_passthrough"}
	case cfg.Wireless.Enabled && cfg.Deployment.Hardware.PreferExternalAP:
		capability.State = CapabilityWarned
		capability.Summary = "Local wireless is active while external AP mode is preferred."
		capability.Recommendation = "Pick one radio model for production: external AP mode or local hostapd radio mode."
	case cfg.Wireless.Enabled && constrainedPlatform(cfg, preset):
		capability.State = CapabilityWarned
		capability.Summary = "Local wireless is active on hardware below the recommended floor for this deployment profile."
		capability.Recommendation = "Use a stronger appliance or keep local Wi-Fi limited to lighter SSID mixes."
	case cfg.Wireless.Enabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Local hostapd radio mode is active."
	case cfg.Deployment.Hardware.PreferExternalAP:
		capability.State = CapabilityAvailable
		capability.Summary = "External AP mode is preferred on this target."
		capability.Recommendation = "Enable local wireless only when the appliance has a real radio and you want the box to own SSID broadcast."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Local hostapd radio mode is supported but currently off."
	}

	return capability
}

func evaluateRuntimeShapingCapability(cfg *Config, preset deploymentPreset) FeatureCapability {
	interfaceName := ShapingInterface(cfg)
	capability := FeatureCapability{
		Key:    "runtime_shaping",
		Label:  "Runtime Shaping",
		Active: cfg.Policy.RuntimeShapingEnabled,
	}

	switch {
	case cfg.Policy.RuntimeShapingEnabled && interfaceName == "":
		capability.State = CapabilityBlocked
		capability.Summary = "Runtime shaping is enabled but no downstream shaping interface is configured."
		capability.Recommendation = "Set lan.name in two-NIC mode or ensure the WAN trunk interface is defined before enabling runtime shaping."
		capability.Dependencies = []string{"mode", "lan.name", "wan.name"}
	case interfaceName == "":
		capability.State = CapabilityBlocked
		capability.Summary = "No downstream interface is configured for runtime shaping."
		capability.Recommendation = "Configure a LAN or trunk interface before turning runtime shaping on."
		capability.Dependencies = []string{"mode", "lan.name", "wan.name"}
	case !cfg.Policy.RuntimeShapingEnabled:
		capability.State = CapabilityAvailable
		capability.Summary = fmt.Sprintf("Runtime shaping is supported on %s but currently disabled.", interfaceName)
	case EffectiveDeploymentProfile(cfg.Deployment.Profile) == "lite" || veryLowMemory(cfg) || lowCPU(cfg):
		capability.State = CapabilityWarned
		capability.Summary = fmt.Sprintf("Runtime shaping is active on %s, but this target is below the recommended floor for production shaping.", interfaceName)
		capability.Recommendation = "Use a branch or enterprise profile, or disable shaping until the appliance has more headroom."
	default:
		capability.State = CapabilityEnabled
		capability.Summary = fmt.Sprintf("Runtime shaping is active on downstream interface %s.", interfaceName)
	}

	return capability
}

func evaluateAIModeCapability(cfg *Config) FeatureCapability {
	mode := EffectiveAIMode(cfg)
	provider := EffectiveAIProvider(cfg)
	capability := FeatureCapability{
		Key:    "ai_mode",
		Label:  "AI Analysis",
		Active: cfg.AILite.Enabled,
	}

	switch {
	case !cfg.AILite.Enabled:
		capability.State = CapabilityAvailable
		capability.Summary = "AI analysis is currently disabled."
		if hasEnterpriseHeadroom(cfg) {
			capability.Recommendation = "This hardware can support full AI once endpoint and model are configured."
		}
	case mode == "full" && !fullAIConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Full AI mode requires both an endpoint and a model."
		capability.Recommendation = "Set ailite.endpoint and ailite.model before saving a production full-AI deployment."
		capability.Dependencies = []string{"ailite.endpoint", "ailite.model"}
	case mode == "full" && (cfg.Deployment.Hardware.MemoryMB < 8192 || cfg.Deployment.Hardware.CPUCores < 4 || EffectiveDeploymentProfile(cfg.Deployment.Profile) != "enterprise"):
		capability.State = CapabilityWarned
		capability.Summary = fmt.Sprintf("Full AI mode is active with provider %s, but the platform is below the recommended enterprise floor.", provider)
		capability.Recommendation = "Use the enterprise profile with at least 4 cores and 8 GB RAM, or switch back to AI Lite."
	case mode == "full":
		capability.State = CapabilityEnabled
		capability.Summary = fmt.Sprintf("Full AI mode is active with provider %s.", provider)
	case hasEnterpriseHeadroom(cfg):
		capability.State = CapabilityWarned
		capability.Summary = "AI Lite is active on hardware that can support full AI."
		capability.Recommendation = "Switch ailite.mode to full and configure an endpoint plus model to use the higher-capacity path."
	case veryLowMemory(cfg):
		capability.State = CapabilityWarned
		capability.Summary = "AI Lite is active on a very low-memory target."
		capability.Recommendation = "Disable AI analysis or increase memory before relying on it in production."
	default:
		capability.State = CapabilityEnabled
		capability.Summary = "AI Lite analysis is active."
	}

	return capability
}

func evaluateTelemetryCapability(cfg *Config) FeatureCapability {
	capability := FeatureCapability{
		Key:    "telemetry",
		Label:  "Telemetry",
		Active: cfg.Telemetry.Enabled,
	}

	switch {
	case !cfg.Telemetry.Enabled:
		capability.State = CapabilityAvailable
		capability.Summary = "Telemetry is currently disabled."
		if EffectiveDeploymentProfile(cfg.Deployment.Profile) == "enterprise" {
			capability.Recommendation = "Enable telemetry for production observability and longer-lived enterprise operations."
		}
	case veryLowMemory(cfg):
		capability.State = CapabilityWarned
		capability.Summary = "Telemetry is active on a very low-memory target."
		capability.Recommendation = "Disable telemetry or move to a stronger profile before treating this as a production observability baseline."
	case EffectiveDeploymentProfile(cfg.Deployment.Profile) == "lite":
		capability.State = CapabilityWarned
		capability.Summary = "Telemetry is active on the lite profile."
		capability.Recommendation = "Keep telemetry light on constrained targets or move to the branch profile for steadier production operation."
	default:
		capability.State = CapabilityEnabled
		capability.Summary = "Telemetry is active."
	}

	return capability
}

func evaluateUpstreamStatusProbeCapability(cfg *Config) FeatureCapability {
	capability := FeatureCapability{
		Key:    "upstream_status_probes",
		Label:  "Upstream AAA Probes",
		Active: cfg.Radius.Upstream.Enabled,
	}

	switch {
	case !cfg.Radius.Upstream.Enabled:
		capability.State = CapabilityAvailable
		capability.Summary = "Upstream AAA is disabled, so Status-Server probes are idle."
	case len(cfg.Radius.Upstream.Servers) == 0:
		capability.State = CapabilityBlocked
		capability.Summary = "Upstream AAA is enabled without any configured home servers."
		capability.Recommendation = "Add at least one upstream RADIUS server before enabling upstream AAA in production."
		capability.Dependencies = []string{"radius.upstream.servers"}
	case strings.EqualFold(strings.TrimSpace(cfg.Radius.Upstream.StatusCheck), "none"):
		if EffectiveDeploymentProfile(cfg.Deployment.Profile) == "lite" || veryLowMemory(cfg) {
			capability.State = CapabilityDegraded
			capability.Summary = "Upstream AAA is active without Status-Server probes to protect constrained hardware."
			capability.Recommendation = "This is acceptable on lite targets. Move to active probes when the appliance has more headroom."
		} else {
			capability.State = CapabilityWarned
			capability.Summary = "Upstream AAA is active but Status-Server probes are disabled."
			capability.Recommendation = "Use radius.upstream.status_check=status-server for stronger production liveness checks."
		}
	case EffectiveDeploymentProfile(cfg.Deployment.Profile) == "lite" && cfg.Radius.Upstream.StatusCheck == "status-server":
		capability.State = CapabilityWarned
		capability.Summary = "Status-Server probes are active on the lite profile."
		capability.Recommendation = "Switch radius.upstream.status_check to none on constrained hardware unless active probing is required."
	default:
		capability.State = CapabilityEnabled
		capability.Summary = "Upstream AAA Status-Server probes are active."
	}

	return capability
}

func fullAIConfigured(cfg *Config) bool {
	return strings.TrimSpace(cfg.AILite.Endpoint) != "" && strings.TrimSpace(cfg.AILite.Model) != ""
}

func constrainedPlatform(cfg *Config, preset deploymentPreset) bool {
	return memoryBelowPreset(cfg, preset) || cpuBelowPreset(cfg, preset)
}

func memoryBelowPreset(cfg *Config, preset deploymentPreset) bool {
	return cfg != nil && cfg.Deployment.Hardware.MemoryMB > 0 && cfg.Deployment.Hardware.MemoryMB < preset.RecommendedMinMemoryMB
}

func cpuBelowPreset(cfg *Config, preset deploymentPreset) bool {
	return cfg != nil && cfg.Deployment.Hardware.CPUCores > 0 && cfg.Deployment.Hardware.CPUCores < preset.RecommendedMinCPUCores
}

func veryLowMemory(cfg *Config) bool {
	return cfg != nil && cfg.Deployment.Hardware.MemoryMB > 0 && cfg.Deployment.Hardware.MemoryMB < 2048
}

func lowCPU(cfg *Config) bool {
	return cfg != nil && cfg.Deployment.Hardware.CPUCores > 0 && cfg.Deployment.Hardware.CPUCores < 2
}

func hasEnterpriseHeadroom(cfg *Config) bool {
	return cfg != nil && cfg.Deployment.Hardware.MemoryMB >= 8192 && cfg.Deployment.Hardware.CPUCores >= 4
}
