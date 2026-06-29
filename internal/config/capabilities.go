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

	capabilities := []FeatureCapability{
		evaluateLocalWirelessCapability(cfg, preset),
		evaluateRuntimeShapingCapability(cfg, preset),
		evaluateAIModeCapability(cfg),
		evaluateTelemetryCapability(cfg),
		evaluateUpstreamStatusProbeCapability(cfg),
		evaluateGuestSelfRegistrationCapability(cfg),
		evaluateSponsorApprovalCapability(cfg),
		evaluateGuestDeliveryCapability(cfg),
		evaluateDeviceInventoryCapability(cfg),
		evaluateOnboardingPortalCapability(cfg),
		evaluateCertificateEnrollmentCapability(cfg),
		evaluateEAPTLSOnboardingCapability(cfg),
		evaluatePassiveProfilingCapability(cfg),
		evaluatePostureCapability(cfg),
		evaluateMDMUEMCapability(cfg),
		evaluateSIEMExportCapability(cfg),
		evaluateControllerAutomationCapability(cfg),
		evaluateHighAvailabilityCapability(cfg),
		evaluateAdminSSOCapability(cfg),
		evaluateDelegatedAdminCapability(cfg),
		evaluateMultiTenantCapability(cfg),
	}
	return applyHardwareScalingGates(cfg, capabilities)
}

func applyHardwareScalingGates(cfg *Config, capabilities []FeatureCapability) []FeatureCapability {
	if cfg == nil || len(capabilities) == 0 {
		return capabilities
	}
	actions := EvaluateHardwareScalingPlan(cfg).GatingActions
	if len(actions) == 0 {
		return capabilities
	}
	actionByKey := map[string]HardwareScalingAction{}
	for _, action := range actions {
		if !action.Active {
			continue
		}
		actionByKey[action.Key] = action
	}
	for i := range capabilities {
		action, ok := actionByKey[capabilities[i].Key]
		if !ok || !capabilities[i].Active {
			continue
		}
		switch action.State {
		case "gate":
			capabilities[i].State = CapabilityBlocked
			capabilities[i].Summary = action.Summary
			capabilities[i].Recommendation = action.Recommendation
			capabilities[i].Dependencies = appendUniqueStrings(capabilities[i].Dependencies, action.ConfigPaths...)
		case "warn":
			if capabilities[i].State == CapabilityEnabled || capabilities[i].State == CapabilityAvailable {
				capabilities[i].State = CapabilityWarned
				capabilities[i].Summary = action.Summary
				capabilities[i].Recommendation = action.Recommendation
				capabilities[i].Dependencies = appendUniqueStrings(capabilities[i].Dependencies, action.ConfigPaths...)
			}
		}
	}
	return capabilities
}

func appendUniqueStrings(base []string, values ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(values))
	out := make([]string, 0, len(base)+len(values))
	for _, value := range base {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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

func evaluateGuestSelfRegistrationCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	active := cfg.Portal.GuestWorkflows.SelfRegistrationEnabled
	capability := FeatureCapability{
		Key:    "guest_self_registration",
		Label:  "Guest Self-Registration",
		Active: active,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Guest self-registration is blocked on the lite profile."
		capability.Recommendation = "Move to the branch or enterprise profile before enabling self-registration in production."
	case active && !cfg.Portal.Enabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Guest self-registration needs the captive portal to be enabled."
		capability.Dependencies = []string{"portal.enabled"}
	case active && !cfg.Portal.LocalFallback:
		capability.State = CapabilityBlocked
		capability.Summary = "Guest self-registration needs local fallback so the portal can mint local guest access."
		capability.Recommendation = "Turn on portal.local_fallback before enabling self-registration."
		capability.Dependencies = []string{"portal.local_fallback"}
	case active && strings.TrimSpace(cfg.Portal.Branding) == "":
		capability.State = CapabilityBlocked
		capability.Summary = "Guest self-registration needs portal branding before it is production-ready."
		capability.Dependencies = []string{"portal.branding"}
	case active && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Guest self-registration is active on the branch profile."
		capability.Recommendation = "This is fine for pilot production. Move to enterprise if the workflow will carry heavier guest volume."
	case active:
		capability.State = CapabilityEnabled
		capability.Summary = "Guest self-registration is active."
	case profile == "enterprise":
		capability.State = CapabilityAvailable
		capability.Summary = "Guest self-registration is supported and ready to be enabled."
		capability.Recommendation = "Turn it on after branding and transport choices are final."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Guest self-registration is supported but currently off."
	}

	return capability
}

func evaluateSponsorApprovalCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	active := cfg.Portal.GuestWorkflows.SponsorApprovalEnabled
	capability := FeatureCapability{
		Key:    "sponsor_approval",
		Label:  "Sponsor Approval",
		Active: active,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval is blocked on the lite profile."
		capability.Recommendation = "Use the branch or enterprise profile for guest approval workflows."
	case active && !cfg.Portal.GuestWorkflows.SelfRegistrationEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval depends on guest self-registration."
		capability.Dependencies = []string{"portal.guest_workflows.self_registration_enabled"}
	case active && strings.EqualFold(strings.TrimSpace(cfg.Portal.GuestWorkflows.ApprovalDelivery), "email") && !emailTransportConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval is set to email, but email delivery is not configured."
		capability.Dependencies = []string{"portal.guest_workflows.email_from", "portal.guest_workflows.smtp_server", "portal.guest_workflows.smtp_port"}
	case active && strings.EqualFold(strings.TrimSpace(cfg.Portal.GuestWorkflows.ApprovalDelivery), "sms") && !smsTransportConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval is set to SMS, but SMS delivery is not configured."
		capability.Dependencies = []string{"portal.guest_workflows.sms_provider", "portal.guest_workflows.sms_endpoint"}
	case active && strings.TrimSpace(cfg.Portal.GuestWorkflows.ApprovalDelivery) == "":
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval needs an approval delivery method."
		capability.Dependencies = []string{"portal.guest_workflows.approval_delivery"}
	case active && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Sponsor approval is active on the branch profile."
		capability.Recommendation = "Good for pilot deployments. Use enterprise when the guest workflow becomes a core service."
	case active:
		capability.State = CapabilityEnabled
		capability.Summary = "Sponsor approval is active."
	case !cfg.Portal.GuestWorkflows.SelfRegistrationEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Sponsor approval stays blocked until guest self-registration is enabled."
		capability.Dependencies = []string{"portal.guest_workflows.self_registration_enabled"}
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Sponsor approval is supported but currently off."
	}

	return capability
}

func evaluateGuestDeliveryCapability(cfg *Config) FeatureCapability {
	invite := strings.ToLower(strings.TrimSpace(cfg.Portal.GuestWorkflows.InviteDelivery))
	approval := strings.ToLower(strings.TrimSpace(cfg.Portal.GuestWorkflows.ApprovalDelivery))
	active := invite != "" && invite != "none"
	capability := FeatureCapability{
		Key:    "guest_delivery",
		Label:  "Guest Email/SMS Delivery",
		Active: active || cfg.Portal.GuestWorkflows.SponsorApprovalEnabled,
	}

	emailReady := emailTransportConfigured(cfg)
	smsReady := smsTransportConfigured(cfg)

	switch {
	case active && invite == "email" && !emailReady:
		capability.State = CapabilityBlocked
		capability.Summary = "Guest invite delivery is set to email, but email transport is not configured."
		capability.Dependencies = []string{"portal.guest_workflows.email_from", "portal.guest_workflows.smtp_server", "portal.guest_workflows.smtp_port"}
	case active && invite == "sms" && !smsReady:
		capability.State = CapabilityBlocked
		capability.Summary = "Guest invite delivery is set to SMS, but SMS transport is not configured."
		capability.Dependencies = []string{"portal.guest_workflows.sms_provider", "portal.guest_workflows.sms_endpoint"}
	case cfg.Portal.GuestWorkflows.SponsorApprovalEnabled && approval == "email" && emailReady:
		capability.State = CapabilityEnabled
		capability.Summary = "Email delivery is ready for sponsor approval and guest invite flows."
	case cfg.Portal.GuestWorkflows.SponsorApprovalEnabled && approval == "sms" && smsReady:
		capability.State = CapabilityEnabled
		capability.Summary = "SMS delivery is ready for sponsor approval and guest invite flows."
	case active && ((invite == "email" && emailReady) || (invite == "sms" && smsReady)):
		capability.State = CapabilityEnabled
		capability.Summary = fmt.Sprintf("Guest %s delivery is configured.", invite)
	case !emailReady && !smsReady:
		capability.State = CapabilityAvailable
		capability.Summary = "No guest delivery transport is configured yet."
		capability.Recommendation = "Configure SMTP or SMS before turning on invites or sponsor approval."
	case emailReady || smsReady:
		capability.State = CapabilityAvailable
		if emailReady && smsReady {
			capability.Summary = "Email and SMS delivery transports are configured."
		} else if emailReady {
			capability.Summary = "Email delivery transport is configured."
		} else {
			capability.Summary = "SMS delivery transport is configured."
		}
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Guest delivery transport can be configured for email or SMS."
	}

	return capability
}

func evaluateDeviceInventoryCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "device_registration_inventory",
		Label:  "Device Registration Inventory",
		Active: cfg.Onboarding.DeviceInventoryEnabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Device registration inventory is blocked on the lite profile."
		capability.Recommendation = "Use the branch or enterprise profile for managed onboarding inventory."
	case cfg.Onboarding.DeviceInventoryEnabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Device registration inventory is active on the branch profile."
		capability.Recommendation = "This is a good production baseline for smaller sites. Move to enterprise for heavier BYOD programs."
	case cfg.Onboarding.DeviceInventoryEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Device registration inventory is active."
	case profile == "enterprise":
		capability.State = CapabilityAvailable
		capability.Summary = "Device registration inventory is supported and ready to be enabled."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Device registration inventory is supported but currently off."
	}

	return capability
}

func evaluateOnboardingPortalCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "onboarding_portal",
		Label:  "Onboarding Portal",
		Active: cfg.Onboarding.PortalEnabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "The onboarding portal is blocked on the lite profile."
	case cfg.Onboarding.PortalEnabled && !cfg.Portal.Enabled:
		capability.State = CapabilityBlocked
		capability.Summary = "The onboarding portal needs the captive portal to be enabled."
		capability.Dependencies = []string{"portal.enabled"}
	case cfg.Onboarding.PortalEnabled && !identityWorkflowReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "The onboarding portal needs an identity path such as local fallback, LDAP, or portal RADIUS auth."
		capability.Dependencies = []string{"portal.local_fallback", "ldap.enabled", "portal.radius_auth"}
	case cfg.Onboarding.PortalEnabled && !cfg.Onboarding.DeviceInventoryEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "The onboarding portal needs device registration inventory."
		capability.Dependencies = []string{"onboarding.device_inventory_enabled"}
	case cfg.Onboarding.PortalEnabled && !certificateAuthorityDeclared(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "The onboarding portal needs a declared certificate authority mode."
		capability.Dependencies = []string{"onboarding.ca_mode"}
	case cfg.Onboarding.PortalEnabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "The onboarding portal is active on the branch profile."
		capability.Recommendation = "Good for pilot production. Move to enterprise when onboarding becomes a primary workflow."
	case cfg.Onboarding.PortalEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "The onboarding portal is active."
	case profile == "enterprise":
		capability.State = CapabilityAvailable
		capability.Summary = "The onboarding portal is supported and ready to be enabled."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "The onboarding portal is supported but currently off."
	}

	return capability
}

func evaluateCertificateEnrollmentCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "certificate_enrollment",
		Label:  "Certificate Enrollment",
		Active: cfg.Onboarding.CertificateEnrollmentEnabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "Certificate enrollment is reserved for the enterprise profile."
		capability.Recommendation = "Use enterprise for production certificate onboarding."
	case cfg.Onboarding.CertificateEnrollmentEnabled && !cfg.Onboarding.PortalEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Certificate enrollment requires the onboarding portal."
		capability.Dependencies = []string{"onboarding.portal_enabled"}
	case cfg.Onboarding.CertificateEnrollmentEnabled && !certificateAuthorityReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Certificate enrollment requires complete CA configuration."
		capability.Dependencies = []string{"onboarding.ca_mode", "onboarding.ca_cert_path", "onboarding.ca_key_path", "onboarding.ca_enrollment_url"}
	case cfg.Onboarding.CertificateEnrollmentEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Certificate enrollment is active."
	case certificateAuthorityDeclared(cfg):
		capability.State = CapabilityAvailable
		capability.Summary = "Certificate enrollment is supported and awaiting activation."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Certificate enrollment is supported but needs CA setup first."
	}

	return capability
}

func evaluateEAPTLSOnboardingCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "eap_tls_onboarding",
		Label:  "EAP-TLS Onboarding",
		Active: cfg.Onboarding.EAPTLSEnabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "EAP-TLS onboarding is reserved for the enterprise profile."
	case cfg.Onboarding.EAPTLSEnabled && !cfg.Onboarding.CertificateEnrollmentEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "EAP-TLS onboarding requires certificate enrollment."
		capability.Dependencies = []string{"onboarding.certificate_enrollment_enabled"}
	case cfg.Onboarding.EAPTLSEnabled && !certificateAuthorityReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "EAP-TLS onboarding requires complete CA configuration."
		capability.Dependencies = []string{"onboarding.ca_mode", "onboarding.ca_cert_path", "onboarding.ca_key_path", "onboarding.ca_enrollment_url"}
	case cfg.Onboarding.EAPTLSEnabled && strings.ToLower(strings.TrimSpace(cfg.Radius.EAP.DefaultType)) != "tls":
		capability.State = CapabilityBlocked
		capability.Summary = "EAP-TLS onboarding requires radius.eap.default_type to be tls."
		capability.Dependencies = []string{"radius.eap.default_type"}
	case cfg.Onboarding.EAPTLSEnabled && (veryLowMemory(cfg) || lowCPU(cfg)):
		capability.State = CapabilityBlocked
		capability.Summary = "EAP-TLS onboarding is active on hardware too constrained for certificate-heavy production auth."
	case cfg.Onboarding.EAPTLSEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "EAP-TLS onboarding is active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "EAP-TLS onboarding is supported and ready to be enabled."
	}

	return capability
}

func evaluatePassiveProfilingCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "passive_profiling",
		Label:  "Passive Profiling",
		Active: cfg.Profiling.PassiveEnabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Passive profiling is blocked on the lite profile."
	case cfg.Profiling.PassiveEnabled && !cfg.Profiling.MACInventoryEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Passive profiling requires MAC inventory."
		capability.Dependencies = []string{"profiling.mac_inventory_enabled"}
	case cfg.Profiling.PassiveEnabled && (veryLowMemory(cfg) || lowCPU(cfg)):
		capability.State = CapabilityDegraded
		capability.Summary = "Passive profiling is active, but the platform is constrained enough that collection should stay shallow."
		capability.Recommendation = "Increase hardware or keep poll intervals conservative before relying on this for production profiling."
	case cfg.Profiling.PassiveEnabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Passive profiling is active on the branch profile."
		capability.Recommendation = "Good for lighter production visibility. Enterprise is the preferred tier for richer profiling."
	case cfg.Profiling.PassiveEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Passive profiling is active."
	case profile == "enterprise":
		capability.State = CapabilityAvailable
		capability.Summary = "Passive profiling is supported and ready to be enabled."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Passive profiling is supported but currently off."
	}

	return capability
}

func evaluatePostureCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "posture_checks",
		Label:  "Posture Checks",
		Active: cfg.Profiling.PostureEnabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "Posture checks are reserved for the enterprise profile."
	case cfg.Profiling.PostureEnabled && !cfg.Profiling.MACInventoryEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Posture checks require MAC inventory."
		capability.Dependencies = []string{"profiling.mac_inventory_enabled"}
	case cfg.Profiling.PostureEnabled && !profilingIntegrationReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Posture checks require an MDM endpoint or compliance webhook."
		capability.Dependencies = []string{"profiling.mdm_provider", "profiling.mdm_endpoint", "profiling.compliance_webhook"}
	case cfg.Profiling.PostureEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Posture checks are active."
	case profilingIntegrationReady(cfg):
		capability.State = CapabilityAvailable
		capability.Summary = "Posture checks are supported and transport dependencies are ready."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Posture checks are supported but need compliance sources before activation."
	}

	return capability
}

func evaluateMDMUEMCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "mdm_uem_integration",
		Label:  "MDM/UEM Integration",
		Active: cfg.Profiling.MDMSyncEnabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "Authoritative MDM/UEM sync is reserved for the enterprise profile."
	case cfg.Profiling.MDMSyncEnabled && strings.TrimSpace(cfg.Profiling.MDMProvider) == "":
		capability.State = CapabilityBlocked
		capability.Summary = "MDM/UEM sync requires an MDM provider."
		capability.Dependencies = []string{"profiling.mdm_provider"}
	case cfg.Profiling.MDMSyncEnabled && strings.TrimSpace(cfg.Profiling.MDMEndpoint) == "":
		capability.State = CapabilityBlocked
		capability.Summary = "MDM/UEM sync requires an MDM endpoint."
		capability.Dependencies = []string{"profiling.mdm_endpoint"}
	case cfg.Profiling.MDMSyncEnabled && cfg.Profiling.MDMCacheHours == 0:
		capability.State = CapabilityBlocked
		capability.Summary = "MDM/UEM sync requires a positive cache window."
		capability.Dependencies = []string{"profiling.mdm_cache_hours"}
	case cfg.Profiling.MDMSyncEnabled && !hasEnterpriseHeadroom(cfg):
		capability.State = CapabilityWarned
		capability.Summary = "MDM/UEM sync is active, but the hardware is below the recommended enterprise floor."
		capability.Recommendation = "Use at least 4 cores and 8 GB RAM before treating MDM sync as a stable production source of truth."
	case cfg.Profiling.MDMSyncEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "MDM/UEM sync is active."
	case strings.TrimSpace(cfg.Profiling.MDMProvider) != "" || strings.TrimSpace(cfg.Profiling.MDMEndpoint) != "":
		capability.State = CapabilityAvailable
		capability.Summary = "MDM/UEM connection details are present and ready for activation."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "MDM/UEM sync is supported but currently off."
	}

	return capability
}

func evaluateSIEMExportCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "siem_webhook_export",
		Label:  "SIEM/Webhook Export",
		Active: cfg.Integrations.SIEM.Enabled,
	}

	switch {
	case cfg.Integrations.SIEM.Enabled && !siemConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "SIEM export needs provider, endpoint, API key env, and positive batch size."
		capability.Dependencies = []string{"integrations.siem.provider", "integrations.siem.endpoint", "integrations.siem.api_key_env", "integrations.siem.batch_size"}
	case cfg.Integrations.SIEM.Enabled && profile == "lite":
		capability.State = CapabilityWarned
		capability.Summary = "SIEM export is active on the lite profile."
		capability.Recommendation = "Keep export batching conservative on constrained targets or move to the branch profile."
	case cfg.Integrations.SIEM.Enabled:
		capability.State = CapabilityEnabled
		capability.Summary = "SIEM/webhook export is active."
	case strings.TrimSpace(cfg.Integrations.SIEM.Provider) != "" || strings.TrimSpace(cfg.Integrations.SIEM.Endpoint) != "":
		capability.State = CapabilityAvailable
		capability.Summary = "SIEM export details are configured and ready to be enabled."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "SIEM/webhook export is supported but currently off."
	}

	return capability
}

func evaluateControllerAutomationCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "controller_automation",
		Label:  "Controller Automation",
		Active: cfg.Integrations.Controller.Enabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Controller automation is blocked on the lite profile."
	case cfg.Integrations.Controller.Enabled && !controllerConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Controller automation requires platform, endpoint, API token env, and sync mode."
		capability.Dependencies = []string{"integrations.controller.platform", "integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.sync_mode"}
	case cfg.Integrations.Controller.Enabled && cfg.Wireless.Enabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Controller automation requires the external AP model, not local wireless ownership."
		capability.Dependencies = []string{"wireless.enabled", "deployment.hardware.prefer_external_ap"}
	case cfg.Integrations.Controller.Enabled && !cfg.Deployment.Hardware.PreferExternalAP:
		capability.State = CapabilityWarned
		capability.Summary = "Controller automation is active without the external AP preference hint."
		capability.Recommendation = "Set deployment.hardware.prefer_external_ap=true so operations and automation follow the same deployment model."
	case cfg.Integrations.Controller.Enabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Controller automation is active on the branch profile."
		capability.Recommendation = "Good for branch pilots. Enterprise is the preferred tier for larger controller-driven estates."
	case cfg.Integrations.Controller.Enabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Controller automation is active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Controller automation is supported but currently off."
	}

	return capability
}

func evaluateHighAvailabilityCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "high_availability_failover",
		Label:  "High Availability / Failover",
		Active: cfg.HighAvailability.Enabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "High availability is reserved for the enterprise profile."
	case cfg.HighAvailability.Enabled && !highAvailabilityConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "High availability requires role, peer API URL, virtual IP, and positive heartbeat timers."
		capability.Dependencies = []string{"high_availability.role", "high_availability.peer_api_url", "high_availability.virtual_ip", "high_availability.heartbeat_interval_seconds", "high_availability.failover_timeout_seconds"}
	case cfg.HighAvailability.Enabled && !hasEnterpriseHeadroom(cfg):
		capability.State = CapabilityWarned
		capability.Summary = "High availability is active, but the node is below the recommended enterprise hardware floor."
		capability.Recommendation = "Use at least 4 cores and 8 GB RAM before treating failover monitoring as a production control plane."
	case cfg.HighAvailability.Enabled && !cfg.HighAvailability.SplitBrainProtectionEnabled:
		capability.State = CapabilityWarned
		capability.Summary = "High availability is active without split-brain protection."
		capability.Recommendation = "Turn on high_availability.split_brain_protection_enabled so standby nodes require stale shared-state heartbeats before promoting."
	case cfg.HighAvailability.Enabled:
		capability.State = CapabilityEnabled
		capability.Summary = "High availability peer monitoring and split-brain protection are active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "High availability groundwork is supported but currently off."
	}

	return capability
}

func evaluateAdminSSOCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "admin_sso",
		Label:  "Admin SSO",
		Active: cfg.Integrations.AdminSSO.Enabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Admin SSO is blocked on the lite profile."
	case cfg.Integrations.AdminSSO.Enabled && !adminSSOConfigured(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Admin SSO needs provider, issuer URL, client ID, and redirect URL."
		capability.Dependencies = []string{"integrations.admin_sso.provider", "integrations.admin_sso.issuer_url", "integrations.admin_sso.client_id", "integrations.admin_sso.redirect_url"}
	case cfg.Integrations.AdminSSO.Enabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Admin SSO is active on the branch profile."
		capability.Recommendation = "This is fine for smaller admin teams. Enterprise is the preferred tier for central admin identity."
	case cfg.Integrations.AdminSSO.Enabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Admin SSO is active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Admin SSO is supported but currently off."
	}

	return capability
}

func evaluateDelegatedAdminCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "delegated_admin_rbac",
		Label:  "Delegated Admin / RBAC",
		Active: cfg.Governance.DelegatedAdminEnabled,
	}

	switch {
	case profile == "lite":
		capability.State = CapabilityBlocked
		capability.Summary = "Delegated admin and RBAC are blocked on the lite profile."
	case cfg.Governance.DelegatedAdminEnabled && !delegatedAdminIdentityReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "Delegated admin needs admin SSO or LDAP."
		capability.Dependencies = []string{"integrations.admin_sso.enabled", "ldap.enabled"}
	case cfg.Governance.DelegatedAdminEnabled && strings.EqualFold(strings.TrimSpace(cfg.Governance.RBACMode), "external-groups") && !adminGroupSourceReady(cfg):
		capability.State = CapabilityBlocked
		capability.Summary = "External group RBAC needs an admin SSO groups claim or LDAP group filter."
		capability.Dependencies = []string{"integrations.admin_sso.groups_claim", "ldap.group_filter"}
	case cfg.Governance.DelegatedAdminEnabled && profile == "branch":
		capability.State = CapabilityWarned
		capability.Summary = "Delegated admin is active on the branch profile."
		capability.Recommendation = "Good for smaller teams. Enterprise is the preferred tier for broader admin separation."
	case cfg.Governance.DelegatedAdminEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Delegated admin and RBAC are active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Delegated admin and RBAC are supported but currently off."
	}

	return capability
}

func evaluateMultiTenantCapability(cfg *Config) FeatureCapability {
	profile := EffectiveDeploymentProfile(cfg.Deployment.Profile)
	capability := FeatureCapability{
		Key:    "multi_tenant_governance",
		Label:  "Multi-Tenant Governance",
		Active: cfg.Governance.MultiTenantEnabled,
	}

	switch {
	case profile != "enterprise":
		capability.State = CapabilityBlocked
		capability.Summary = "Multi-tenant governance is reserved for the enterprise profile."
	case cfg.Governance.MultiTenantEnabled && !cfg.Governance.DelegatedAdminEnabled:
		capability.State = CapabilityBlocked
		capability.Summary = "Multi-tenant governance requires delegated admin to be enabled first."
		capability.Dependencies = []string{"governance.delegated_admin_enabled"}
	case cfg.Governance.MultiTenantEnabled && cfg.Integrations.AdminSSO.Enabled && strings.TrimSpace(cfg.Governance.TenantClaim) == "":
		capability.State = CapabilityBlocked
		capability.Summary = "Multi-tenant governance needs a tenant claim when admin SSO is active."
		capability.Dependencies = []string{"governance.tenant_claim"}
	case cfg.Governance.MultiTenantEnabled:
		capability.State = CapabilityEnabled
		capability.Summary = "Multi-tenant governance is active."
	default:
		capability.State = CapabilityAvailable
		capability.Summary = "Multi-tenant governance is supported but currently off."
	}

	return capability
}

func fullAIConfigured(cfg *Config) bool {
	return strings.TrimSpace(cfg.AILite.Endpoint) != "" && strings.TrimSpace(cfg.AILite.Model) != ""
}

func certificateAuthorityDeclared(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return strings.ToLower(strings.TrimSpace(cfg.Onboarding.CAMode)) != "" &&
		strings.ToLower(strings.TrimSpace(cfg.Onboarding.CAMode)) != "none"
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
	return cfg != nil && cfg.Deployment.Hardware.MemoryMB >= 8192 && cfg.Deployment.Hardware.CPUCores >= 4 && storageMeets(cfg.Deployment.Hardware.StorageGB, 64)
}
