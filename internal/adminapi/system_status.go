package adminapi

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/activedirectory"
	"github.com/yourorg/aegisnas-pi4/internal/certlifecycle"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	eappkg "github.com/yourorg/aegisnas-pi4/internal/eap"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/identity"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
	mabpkg "github.com/yourorg/aegisnas-pi4/internal/mab"
	mfapkg "github.com/yourorg/aegisnas-pi4/internal/mfa"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/supplicantprofile"
	"github.com/yourorg/aegisnas-pi4/internal/tacacs"
	webauthnpkg "github.com/yourorg/aegisnas-pi4/internal/webauthn"
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
	vendorObservabilitySummary, err := db.GetVendorObservabilitySummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vendorObservabilityRows, err := db.ListVendorObservability(8)
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
	runtimeFirewallStatus := map[string]any{
		"status":  "unknown",
		"message": "Runtime firewall status has not been evaluated.",
	}
	if firewallPlan, err := enforcement.PreviewRuntimeFirewall(); err == nil {
		firewallSummary, _ := db.GetRuntimeFirewallEventSummary()
		runtimeFirewallStatus = map[string]any{
			"schema_version":      enforcement.RuntimeFirewallSchemaVersion,
			"status":              firewallPlan.Status,
			"message":             firewallPlan.Message,
			"table_name":          firewallPlan.TableName,
			"ruleset_fingerprint": firewallPlan.RulesetFingerprint,
			"summary":             firewallPlan.Summary,
			"diagnostic_count":    len(firewallPlan.Diagnostics),
			"evidence_summary":    firewallSummary,
			"runtime_status":      runtimeMap["runtime_firewall"],
		}
	} else {
		runtimeFirewallStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["runtime_firewall"]}
	}
	runtimeQoSStatus := map[string]any{
		"status":  "unknown",
		"message": "Runtime QoS scheduler status has not been evaluated.",
	}
	if qosPlan, err := enforcement.PreviewRuntimeQoS(cfg); err == nil {
		qosSummary, _ := db.GetRuntimeQoSEventSummary()
		runtimeQoSStatus = map[string]any{
			"schema_version":   enforcement.RuntimeQoSSchemaVersion,
			"status":           qosPlan.Status,
			"message":          qosPlan.Message,
			"interface_name":   qosPlan.InterfaceName,
			"ifb_device":       qosPlan.IFBDevice,
			"plan_fingerprint": qosPlan.PlanFingerprint,
			"summary":          qosPlan.Summary,
			"diagnostic_count": len(qosPlan.Diagnostics),
			"evidence_summary": qosSummary,
			"runtime_status":   runtimeMap["runtime_qos_scheduler"],
		}
	} else {
		runtimeQoSStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["runtime_qos_scheduler"]}
	}
	vlanLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "Dynamic VLAN lifecycle status has not been evaluated.",
	}
	if vlanPlan, err := enforcement.PreviewVLANLifecycle(cfg); err == nil {
		vlanSummary, _ := db.GetVLANLifecycleEventSummary()
		vlanLifecycleStatus = map[string]any{
			"schema_version":           enforcement.VLANLifecycleSchemaVersion,
			"status":                   vlanPlan.Status,
			"message":                  vlanPlan.Message,
			"parent_interface":         vlanPlan.ParentInterface,
			"hostapd_vlan_file_path":   vlanPlan.HostapdVLANFilePath,
			"hostapd_vlan_file_sha256": vlanPlan.HostapdVLANFileSHA256,
			"plan_fingerprint":         vlanPlan.PlanFingerprint,
			"summary":                  vlanPlan.Summary,
			"diagnostic_count":         len(vlanPlan.Diagnostics),
			"evidence_summary":         vlanSummary,
			"runtime_status":           runtimeMap["vlan_lifecycle"],
		}
	} else {
		vlanLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["vlan_lifecycle"]}
	}
	hostapdVLANLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "hostapd dynamic VLAN lifecycle status has not been evaluated.",
	}
	if hostapdReport, err := enforcement.PreviewHostapdVLANLifecycle(cfg); err == nil {
		vlanSummary, _ := db.GetVLANLifecycleEventSummary()
		hostapdVLANLifecycleStatus = map[string]any{
			"schema_version":                  hostapdReport.SchemaVersion,
			"feature_id":                      hostapdReport.FeatureID,
			"status":                          hostapdReport.Status,
			"message":                         hostapdReport.Message,
			"ready_for_external_validation":   hostapdReport.ReadyForExternalValidation,
			"software_completion_percent":     hostapdReport.SoftwareCompletionPercent,
			"dynamic_ssid_count":              hostapdReport.Summary.DynamicSSIDCount,
			"fallback_ssid_count":             hostapdReport.Summary.FallbackSSIDCount,
			"fail_closed_ssid_count":          hostapdReport.Summary.FailClosedSSIDCount,
			"hostapd_vlan_entry_count":        hostapdReport.Summary.HostapdVLANEntryCount,
			"cleanup_command_count":           hostapdReport.Summary.CleanupCommandCount,
			"rollback_command_count":          hostapdReport.Summary.RollbackCommandCount,
			"hostapd_config_path":             hostapdReport.HostapdConfigPath,
			"hostapd_config_sha256":           hostapdReport.HostapdConfigSHA256,
			"hostapd_vlan_file_path":          hostapdReport.Plan.HostapdVLANFilePath,
			"hostapd_vlan_file_sha256":        hostapdReport.Plan.HostapdVLANFileSHA256,
			"plan_fingerprint":                hostapdReport.Plan.PlanFingerprint,
			"release_certification_checklist": hostapdReport.ReleaseCertificationChecklist,
			"evidence_summary":                vlanSummary,
			"runtime_status":                  runtimeMap["vlan_lifecycle"],
		}
	} else {
		hostapdVLANLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["vlan_lifecycle"]}
	}
	wirelessRoamingLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "802.11r/k/v roaming lifecycle status has not been evaluated.",
	}
	if roamingReport, err := enforcement.PreviewWirelessRoamingLifecycle(cfg); err == nil {
		roamingSummary, _ := db.GetWirelessRoamingLifecycleSummary()
		wirelessRoamingLifecycleStatus = map[string]any{
			"schema_version":                  roamingReport.SchemaVersion,
			"feature_id":                      roamingReport.FeatureID,
			"status":                          roamingReport.Status,
			"message":                         roamingReport.Message,
			"ready_for_external_validation":   roamingReport.ReadyForExternalValidation,
			"software_completion_percent":     roamingReport.SoftwareCompletionPercent,
			"roaming_enabled":                 roamingReport.Summary.RoamingEnabled,
			"roaming_ssid_count":              roamingReport.Summary.RoamingSSIDCount,
			"ft_ssid_count":                   roamingReport.Summary.FTSSIDCount,
			"k_ssid_count":                    roamingReport.Summary.KSSIDCount,
			"v_ssid_count":                    roamingReport.Summary.VSSIDCount,
			"profile_count":                   roamingReport.Summary.ProfileCount,
			"neighbor_count":                  roamingReport.Summary.NeighborCount,
			"key_ref_count":                   roamingReport.Summary.KeyRefCount,
			"staged_key_ref_count":            roamingReport.Summary.StagedKeyRefCount,
			"resolvable_key_ref_count":        roamingReport.Summary.ResolvableKeyRefCount,
			"diagnostic_count":                roamingReport.Summary.DiagnosticCount,
			"hostapd_config_path":             roamingReport.HostapdConfigPath,
			"hostapd_config_sha256":           roamingReport.HostapdConfigSHA256,
			"plan_fingerprint":                roamingReport.PlanFingerprint,
			"release_certification_checklist": roamingReport.ReleaseCertificationChecklist,
			"evidence_summary":                roamingSummary,
			"runtime_status":                  runtimeMap["wireless_roaming_lifecycle"],
		}
	} else {
		wirelessRoamingLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["wireless_roaming_lifecycle"]}
	}
	passpointLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "Passpoint and Hotspot 2.0 lifecycle status has not been evaluated.",
	}
	if passpointReport, err := enforcement.PreviewPasspointLifecycle(cfg); err == nil {
		passpointSummary, _ := db.GetPasspointLifecycleSummary()
		passpointLifecycleStatus = map[string]any{
			"schema_version":                  passpointReport.SchemaVersion,
			"feature_id":                      passpointReport.FeatureID,
			"status":                          passpointReport.Status,
			"message":                         passpointReport.Message,
			"ready_for_external_validation":   passpointReport.ReadyForExternalValidation,
			"software_completion_percent":     passpointReport.SoftwareCompletionPercent,
			"passpoint_enabled":               passpointReport.Summary.PasspointEnabled,
			"passpoint_ssid_count":            passpointReport.Summary.PasspointSSIDCount,
			"interworking_ssid_count":         passpointReport.Summary.InterworkingSSIDCount,
			"hs20_ssid_count":                 passpointReport.Summary.HS20SSIDCount,
			"osu_provider_count":              passpointReport.Summary.OSUProviderCount,
			"domain_name_count":               passpointReport.Summary.DomainNameCount,
			"roaming_consortium_count":        passpointReport.Summary.RoamingConsortiumCount,
			"nai_realm_count":                 passpointReport.Summary.NAIRealmCount,
			"cellular_network_count":          passpointReport.Summary.CellularNetworkCount,
			"connection_capability_count":     passpointReport.Summary.ConnectionCapabilityCount,
			"diagnostic_count":                passpointReport.Summary.DiagnosticCount,
			"hostapd_config_path":             passpointReport.HostapdConfigPath,
			"hostapd_config_sha256":           passpointReport.HostapdConfigSHA256,
			"plan_fingerprint":                passpointReport.PlanFingerprint,
			"release_certification_checklist": passpointReport.ReleaseCertificationChecklist,
			"evidence_summary":                passpointSummary,
			"runtime_status":                  runtimeMap["passpoint_lifecycle"],
		}
	} else {
		passpointLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["passpoint_lifecycle"]}
	}
	ppskLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "DPSK/PPSK lifecycle status has not been evaluated.",
	}
	if ppskReport, err := enforcement.PreviewPPSKLifecycle(cfg); err == nil {
		ppskSummary, _ := db.GetPPSKLifecycleSummary()
		ppskLifecycleStatus = map[string]any{
			"schema_version":                  ppskReport.SchemaVersion,
			"feature_id":                      ppskReport.FeatureID,
			"status":                          ppskReport.Status,
			"message":                         ppskReport.Message,
			"ready_for_external_validation":   ppskReport.ReadyForExternalValidation,
			"software_completion_percent":     ppskReport.SoftwareCompletionPercent,
			"ppsk_enabled":                    ppskReport.Summary.PPSKEnabled,
			"ppsk_ssid_count":                 ppskReport.Summary.PPSKSSIDCount,
			"profile_count":                   ppskReport.Summary.ProfileCount,
			"group_count":                     ppskReport.Summary.GroupCount,
			"credential_count":                ppskReport.Summary.CredentialCount,
			"active_credential_count":         ppskReport.Summary.ActiveCredentialCount,
			"staged_credential_count":         ppskReport.Summary.StagedCredentialCount,
			"revoked_credential_count":        ppskReport.Summary.RevokedCredentialCount,
			"expired_credential_count":        ppskReport.Summary.ExpiredCredentialCount,
			"controller_sync_count":           ppskReport.Summary.ControllerSyncCount,
			"diagnostic_count":                ppskReport.Summary.DiagnosticCount,
			"hostapd_config_path":             ppskReport.HostapdConfigPath,
			"hostapd_config_sha256":           ppskReport.HostapdConfigSHA256,
			"psk_file_path":                   ppskReport.PSKFilePath,
			"psk_file_sha256":                 ppskReport.PSKFileSHA256,
			"plan_fingerprint":                ppskReport.PlanFingerprint,
			"release_certification_checklist": ppskReport.ReleaseCertificationChecklist,
			"evidence_summary":                ppskSummary,
			"runtime_status":                  runtimeMap["ppsk_lifecycle"],
		}
	} else {
		ppskLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["ppsk_lifecycle"]}
	}
	controllerEstateLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "Controller estate lifecycle status has not been evaluated.",
	}
	if estateReport, err := integrations.PreviewControllerEstateLifecycle(cfg); err == nil {
		estateSummary, _ := db.GetControllerEstateLifecycleSummary()
		controllerEstateLifecycleStatus = map[string]any{
			"schema_version":                  estateReport.SchemaVersion,
			"feature_id":                      estateReport.FeatureID,
			"status":                          estateReport.Status,
			"message":                         estateReport.Message,
			"ready_for_external_validation":   estateReport.ReadyForExternalValidation,
			"software_completion_percent":     estateReport.SoftwareCompletionPercent,
			"configured_platform":             estateReport.Summary.ConfiguredPlatform,
			"configured_adapter":              estateReport.Summary.ConfiguredAdapter,
			"sync_mode":                       estateReport.Summary.SyncMode,
			"inventory_object_count":          estateReport.Summary.InventoryObjectCount,
			"template_count":                  estateReport.Summary.TemplateCount,
			"wlan_template_count":             estateReport.Summary.WLANTemplateCount,
			"managed_object_count":            estateReport.Summary.ManagedObjectCount,
			"delete_guard_count":              estateReport.Summary.DeleteGuardCount,
			"compliance_check_count":          estateReport.Summary.ComplianceCheckCount,
			"passed_check_count":              estateReport.Summary.PassedCheckCount,
			"warning_count":                   estateReport.Summary.WarningCount,
			"blocker_count":                   estateReport.Summary.BlockerCount,
			"drift_check_available":           estateReport.Summary.DriftCheckAvailable,
			"desired_state_hash":              estateReport.DesiredStateHash,
			"plan_fingerprint":                estateReport.PlanFingerprint,
			"release_certification_checklist": estateReport.ReleaseCertificationChecklist,
			"evidence_summary":                estateSummary,
			"runtime_status":                  runtimeMap[integrations.ControllerComponent()],
		}
	} else {
		controllerEstateLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[integrations.ControllerComponent()]}
	}
	rfPlanningLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "RF/RRM/mesh planning lifecycle status has not been evaluated.",
	}
	if rfReport, err := enforcement.PreviewRFPlanningLifecycle(cfg); err == nil {
		rfSummary, _ := db.GetRFPlanningLifecycleSummary()
		rfPlanningLifecycleStatus = map[string]any{
			"schema_version":                  rfReport.SchemaVersion,
			"feature_id":                      rfReport.FeatureID,
			"status":                          rfReport.Status,
			"message":                         rfReport.Message,
			"ready_for_external_validation":   rfReport.ReadyForExternalValidation,
			"software_completion_percent":     rfReport.SoftwareCompletionPercent,
			"rf_enabled":                      rfReport.Summary.RFEnabled,
			"mode":                            rfReport.Summary.Mode,
			"country_code":                    rfReport.Summary.CountryCode,
			"controller_platform":             rfReport.Summary.ControllerPlatform,
			"ap_count":                        rfReport.Summary.APCount,
			"radio_count":                     rfReport.Summary.RadioCount,
			"band_count":                      rfReport.Summary.BandCount,
			"channel_plan_count":              rfReport.Summary.ChannelPlanCount,
			"power_plan_count":                rfReport.Summary.PowerPlanCount,
			"mesh_link_count":                 rfReport.Summary.MeshLinkCount,
			"steering_policy_count":           rfReport.Summary.SteeringPolicyCount,
			"channel_conflict_count":          rfReport.Summary.ChannelConflictCount,
			"capacity_warning_count":          rfReport.Summary.CapacityWarningCount,
			"compliance_check_count":          rfReport.Summary.ComplianceCheckCount,
			"passed_check_count":              rfReport.Summary.PassedCheckCount,
			"warning_count":                   rfReport.Summary.WarningCount,
			"blocker_count":                   rfReport.Summary.BlockerCount,
			"plan_fingerprint":                rfReport.PlanFingerprint,
			"release_certification_checklist": rfReport.ReleaseCertificationChecklist,
			"evidence_summary":                rfSummary,
			"runtime_status":                  runtimeMap[enforcement.RFPlanningLifecycleComponent()],
		}
	} else {
		rfPlanningLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.RFPlanningLifecycleComponent()]}
	}
	wirelessSecurityLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "Wireless security lifecycle status has not been evaluated.",
	}
	if securityReport, err := enforcement.PreviewWirelessSecurityLifecycle(cfg); err == nil {
		securitySummary, _ := db.GetWirelessSecurityLifecycleSummary()
		wirelessSecurityLifecycleStatus = map[string]any{
			"schema_version":                  securityReport.SchemaVersion,
			"feature_id":                      securityReport.FeatureID,
			"status":                          securityReport.Status,
			"message":                         securityReport.Message,
			"ready_for_external_validation":   securityReport.ReadyForExternalValidation,
			"software_completion_percent":     securityReport.SoftwareCompletionPercent,
			"security_enabled":                securityReport.Summary.SecurityEnabled,
			"mode":                            securityReport.Summary.Mode,
			"controller_platform":             securityReport.Summary.ControllerPlatform,
			"sensor_count":                    securityReport.Summary.SensorCount,
			"rogue_policy_count":              securityReport.Summary.RoguePolicyCount,
			"wips_detection_count":            securityReport.Summary.WIPSDetectionCount,
			"spectrum_channel_count":          securityReport.Summary.SpectrumChannelCount,
			"location_zone_count":             securityReport.Summary.LocationZoneCount,
			"multicast_policy_count":          securityReport.Summary.MulticastPolicyCount,
			"containment_guard_count":         securityReport.Summary.ContainmentGuardCount,
			"privacy_check_count":             securityReport.Summary.PrivacyCheckCount,
			"compliance_check_count":          securityReport.Summary.ComplianceCheckCount,
			"passed_check_count":              securityReport.Summary.PassedCheckCount,
			"warning_count":                   securityReport.Summary.WarningCount,
			"blocker_count":                   securityReport.Summary.BlockerCount,
			"plan_fingerprint":                securityReport.PlanFingerprint,
			"release_certification_checklist": securityReport.ReleaseCertificationChecklist,
			"evidence_summary":                securitySummary,
			"runtime_status":                  runtimeMap[enforcement.WirelessSecurityLifecycleComponent()],
		}
	} else {
		wirelessSecurityLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.WirelessSecurityLifecycleComponent()]}
	}
	cwaPortalLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "CWA portal lifecycle status has not been evaluated.",
	}
	if cwaReport, err := enforcement.PreviewCWAPortalLifecycle(cfg); err == nil {
		cwaSummary, _ := db.GetCWAPortalLifecycleSummary()
		cwaPortalLifecycleStatus = map[string]any{
			"schema_version":                  cwaReport.SchemaVersion,
			"feature_id":                      cwaReport.FeatureID,
			"status":                          cwaReport.Status,
			"message":                         cwaReport.Message,
			"ready_for_external_validation":   cwaReport.ReadyForExternalValidation,
			"software_completion_percent":     cwaReport.SoftwareCompletionPercent,
			"cwa_enabled":                     cwaReport.Summary.CWAEnabled,
			"mode":                            cwaReport.Summary.Mode,
			"portal_base_url":                 cwaReport.Summary.PortalBaseURL,
			"captive_api_path":                cwaReport.Summary.CaptiveAPIPath,
			"controller_platform":             cwaReport.Summary.ControllerPlatform,
			"guest_ssid_count":                cwaReport.Summary.GuestSSIDCount,
			"walled_garden_count":             cwaReport.Summary.WalledGardenCount,
			"controller_policy_count":         cwaReport.Summary.ControllerPolicyCount,
			"redirect_rule_count":             cwaReport.Summary.RedirectRuleCount,
			"coa_action_count":                cwaReport.Summary.CoAActionCount,
			"compliance_check_count":          cwaReport.Summary.ComplianceCheckCount,
			"passed_check_count":              cwaReport.Summary.PassedCheckCount,
			"warning_count":                   cwaReport.Summary.WarningCount,
			"blocker_count":                   cwaReport.Summary.BlockerCount,
			"plan_fingerprint":                cwaReport.PlanFingerprint,
			"release_certification_checklist": cwaReport.ReleaseCertificationChecklist,
			"evidence_summary":                cwaSummary,
			"runtime_status":                  runtimeMap[enforcement.CWAPortalLifecycleComponent()],
		}
	} else {
		cwaPortalLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.CWAPortalLifecycleComponent()]}
	}
	pppoeAccessLifecycleStatus := map[string]any{
		"status":  "unknown",
		"message": "PPPoE access lifecycle status has not been evaluated.",
	}
	if pppoeReport, err := enforcement.PreviewPPPoEAccessLifecycle(cfg); err == nil {
		pppoeSummary, _ := db.GetPPPoEAccessLifecycleSummary()
		pppoeAccessLifecycleStatus = map[string]any{
			"schema_version":                  pppoeReport.SchemaVersion,
			"feature_id":                      pppoeReport.FeatureID,
			"status":                          pppoeReport.Status,
			"message":                         pppoeReport.Message,
			"ready_for_external_validation":   pppoeReport.ReadyForExternalValidation,
			"software_completion_percent":     pppoeReport.SoftwareCompletionPercent,
			"enabled":                         pppoeReport.Summary.Enabled,
			"mode":                            pppoeReport.Summary.Mode,
			"access_concentrator_name":        pppoeReport.Summary.AccessConcentratorName,
			"service_name":                    pppoeReport.Summary.ServiceName,
			"enabled_interface_count":         pppoeReport.Summary.EnabledInterfaceCount,
			"interface_count":                 pppoeReport.Summary.InterfaceCount,
			"enabled_profile_count":           pppoeReport.Summary.EnabledProfileCount,
			"profile_count":                   pppoeReport.Summary.ProfileCount,
			"packet_stage_count":              pppoeReport.Summary.PacketStageCount,
			"radius_attribute_count":          pppoeReport.Summary.RadiusAttributeCount,
			"enforcement_action_count":        pppoeReport.Summary.EnforcementActionCount,
			"compliance_check_count":          pppoeReport.Summary.ComplianceCheckCount,
			"passed_check_count":              pppoeReport.Summary.PassedCheckCount,
			"warning_count":                   pppoeReport.Summary.WarningCount,
			"blocker_count":                   pppoeReport.Summary.BlockerCount,
			"plan_fingerprint":                pppoeReport.PlanFingerprint,
			"release_certification_checklist": pppoeReport.ReleaseCertificationChecklist,
			"evidence_summary":                pppoeSummary,
			"runtime_status":                  runtimeMap[enforcement.PPPoEAccessLifecycleComponent()],
		}
	} else {
		pppoeAccessLifecycleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.PPPoEAccessLifecycleComponent()]}
	}
	broadbandSubscriberStateStatus := map[string]any{
		"status":  "unknown",
		"message": "Broadband subscriber state status has not been evaluated.",
	}
	if subscriberReport, err := enforcement.PreviewBroadbandSubscriberState(cfg); err == nil {
		subscriberSummary, _ := db.GetBroadbandSubscriberStateSummary()
		broadbandSubscriberStateStatus = map[string]any{
			"schema_version":                  subscriberReport.SchemaVersion,
			"feature_id":                      subscriberReport.FeatureID,
			"status":                          subscriberReport.Status,
			"message":                         subscriberReport.Message,
			"ready_for_external_validation":   subscriberReport.ReadyForExternalValidation,
			"software_completion_percent":     subscriberReport.SoftwareCompletionPercent,
			"enabled":                         subscriberReport.Summary.Enabled,
			"mode":                            subscriberReport.Summary.Mode,
			"default_access_method":           subscriberReport.Summary.DefaultAccessMethod,
			"enabled_product_count":           subscriberReport.Summary.EnabledProductCount,
			"product_count":                   subscriberReport.Summary.ProductCount,
			"enabled_service_policy_count":    subscriberReport.Summary.EnabledServicePolicyCount,
			"service_policy_count":            subscriberReport.Summary.ServicePolicyCount,
			"state_count":                     subscriberReport.Summary.StateCount,
			"transition_count":                subscriberReport.Summary.TransitionCount,
			"accounting_transition_count":     subscriberReport.Summary.AccountingTransitionCount,
			"recovery_transition_count":       subscriberReport.Summary.RecoveryTransitionCount,
			"compliance_check_count":          subscriberReport.Summary.ComplianceCheckCount,
			"passed_check_count":              subscriberReport.Summary.PassedCheckCount,
			"warning_count":                   subscriberReport.Summary.WarningCount,
			"blocker_count":                   subscriberReport.Summary.BlockerCount,
			"plan_fingerprint":                subscriberReport.PlanFingerprint,
			"release_certification_checklist": subscriberReport.ReleaseCertificationChecklist,
			"evidence_summary":                subscriberSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandSubscriberStateComponent()],
		}
	} else {
		broadbandSubscriberStateStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandSubscriberStateComponent()]}
	}
	broadbandCommercialCatalogStatus := map[string]any{
		"status":  "unknown",
		"message": "Broadband commercial catalog status has not been evaluated.",
	}
	if commercialReport, err := enforcement.PreviewBroadbandCommercialCatalog(cfg); err == nil {
		commercialSummary, _ := db.GetBroadbandCommercialCatalogSummary()
		broadbandCommercialCatalogStatus = map[string]any{
			"schema_version":                   commercialReport.SchemaVersion,
			"feature_id":                       commercialReport.FeatureID,
			"status":                           commercialReport.Status,
			"message":                          commercialReport.Message,
			"ready_for_external_validation":    commercialReport.ReadyForExternalValidation,
			"software_completion_percent":      commercialReport.SoftwareCompletionPercent,
			"enabled":                          commercialReport.Summary.Enabled,
			"mode":                             commercialReport.Summary.Mode,
			"account_count":                    commercialReport.Summary.AccountCount,
			"active_account_count":             commercialReport.Summary.ActiveAccountCount,
			"family_account_count":             commercialReport.Summary.FamilyAccountCount,
			"plan_count":                       commercialReport.Summary.PlanCount,
			"enabled_plan_count":               commercialReport.Summary.EnabledPlanCount,
			"bundle_count":                     commercialReport.Summary.BundleCount,
			"enabled_bundle_count":             commercialReport.Summary.EnabledBundleCount,
			"subscription_count":               commercialReport.Summary.SubscriptionCount,
			"active_subscription_count":        commercialReport.Summary.ActiveSubscriptionCount,
			"concurrency_policy_count":         commercialReport.Summary.ConcurrencyPolicyCount,
			"enabled_concurrency_policy_count": commercialReport.Summary.EnabledConcurrencyPolicyCount,
			"active_session_count":             commercialReport.Summary.ActiveSessionCount,
			"over_limit_count":                 commercialReport.Summary.OverLimitCount,
			"compliance_check_count":           commercialReport.Summary.ComplianceCheckCount,
			"passed_check_count":               commercialReport.Summary.PassedCheckCount,
			"warning_count":                    commercialReport.Summary.WarningCount,
			"blocker_count":                    commercialReport.Summary.BlockerCount,
			"plan_fingerprint":                 commercialReport.PlanFingerprint,
			"release_certification_checklist":  commercialReport.ReleaseCertificationChecklist,
			"evidence_summary":                 commercialSummary,
			"runtime_status":                   runtimeMap[enforcement.BroadbandCommercialCatalogComponent()],
		}
	} else {
		broadbandCommercialCatalogStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandCommercialCatalogComponent()]}
	}
	broadbandQuotaBalanceStatus := map[string]any{
		"status":  "unknown",
		"message": "Broadband quota and balance status has not been evaluated.",
	}
	if quotaReport, err := enforcement.PreviewBroadbandQuotaBalance(cfg); err == nil {
		quotaSummary, _ := db.GetBroadbandQuotaBalanceSummary()
		broadbandQuotaBalanceStatus = map[string]any{
			"schema_version":                  quotaReport.SchemaVersion,
			"feature_id":                      quotaReport.FeatureID,
			"status":                          quotaReport.Status,
			"message":                         quotaReport.Message,
			"ready_for_external_validation":   quotaReport.ReadyForExternalValidation,
			"software_completion_percent":     quotaReport.SoftwareCompletionPercent,
			"enabled":                         quotaReport.Summary.Enabled,
			"mode":                            quotaReport.Summary.Mode,
			"wallet_count":                    quotaReport.Summary.WalletCount,
			"active_wallet_count":             quotaReport.Summary.ActiveWalletCount,
			"prepaid_wallet_count":            quotaReport.Summary.PrepaidWalletCount,
			"postpaid_wallet_count":           quotaReport.Summary.PostpaidWalletCount,
			"exhausted_wallet_count":          quotaReport.Summary.ExhaustedWalletCount,
			"quota_profile_count":             quotaReport.Summary.QuotaProfileCount,
			"enabled_quota_profile_count":     quotaReport.Summary.EnabledQuotaProfileCount,
			"top_up_count":                    quotaReport.Summary.TopUpCount,
			"applied_top_up_count":            quotaReport.Summary.AppliedTopUpCount,
			"rating_rule_count":               quotaReport.Summary.RatingRuleCount,
			"enabled_rating_rule_count":       quotaReport.Summary.EnabledRatingRuleCount,
			"reset_policy_count":              quotaReport.Summary.ResetPolicyCount,
			"enabled_reset_policy_count":      quotaReport.Summary.EnabledResetPolicyCount,
			"total_balance_micros":            quotaReport.Summary.TotalBalanceMicros,
			"total_top_up_micros":             quotaReport.Summary.TotalTopUpMicros,
			"compliance_check_count":          quotaReport.Summary.ComplianceCheckCount,
			"passed_check_count":              quotaReport.Summary.PassedCheckCount,
			"warning_count":                   quotaReport.Summary.WarningCount,
			"blocker_count":                   quotaReport.Summary.BlockerCount,
			"plan_fingerprint":                quotaReport.PlanFingerprint,
			"release_certification_checklist": quotaReport.ReleaseCertificationChecklist,
			"evidence_summary":                quotaSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandQuotaBalanceComponent()],
		}
	} else {
		broadbandQuotaBalanceStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandQuotaBalanceComponent()]}
	}
	broadbandAddressLeaseStatus := map[string]any{
		"status":  "unknown",
		"message": "Broadband address lease status has not been evaluated.",
	}
	if leaseReport, err := enforcement.PreviewBroadbandAddressLeases(cfg); err == nil {
		leaseSummary, _ := db.GetBroadbandAddressLeaseSummary()
		broadbandAddressLeaseStatus = map[string]any{
			"schema_version":                  leaseReport.SchemaVersion,
			"feature_id":                      leaseReport.FeatureID,
			"status":                          leaseReport.Status,
			"message":                         leaseReport.Message,
			"ready_for_external_validation":   leaseReport.ReadyForExternalValidation,
			"software_completion_percent":     leaseReport.SoftwareCompletionPercent,
			"enabled":                         leaseReport.Summary.Enabled,
			"mode":                            leaseReport.Summary.Mode,
			"pool_count":                      leaseReport.Summary.PoolCount,
			"ipv4_pool_count":                 leaseReport.Summary.IPv4PoolCount,
			"ipv6_pool_count":                 leaseReport.Summary.IPv6PoolCount,
			"delegated_pool_count":            leaseReport.Summary.DelegatedPoolCount,
			"reservation_count":               leaseReport.Summary.ReservationCount,
			"lease_intent_count":              leaseReport.Summary.LeaseIntentCount,
			"active_lease_count":              leaseReport.Summary.ActiveLeaseCount,
			"reserved_lease_count":            leaseReport.Summary.ReservedLeaseCount,
			"conflict_count":                  leaseReport.Summary.ConflictCount,
			"compliance_check_count":          leaseReport.Summary.ComplianceCheckCount,
			"passed_check_count":              leaseReport.Summary.PassedCheckCount,
			"warning_count":                   leaseReport.Summary.WarningCount,
			"blocker_count":                   leaseReport.Summary.BlockerCount,
			"plan_fingerprint":                leaseReport.PlanFingerprint,
			"release_certification_checklist": leaseReport.ReleaseCertificationChecklist,
			"evidence_summary":                leaseSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandAddressLeaseComponent()],
		}
	} else {
		broadbandAddressLeaseStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandAddressLeaseComponent()]}
	}
	broadbandQoSServiceFlowStatus := map[string]any{
		"status":  "unknown",
		"message": "Broadband QoS service-flow status has not been evaluated.",
	}
	if qosReport, err := enforcement.PreviewBroadbandQoSServiceFlows(cfg); err == nil {
		qosSummary, _ := db.GetBroadbandQoSServiceFlowSummary()
		broadbandQoSServiceFlowStatus = map[string]any{
			"schema_version":                  qosReport.SchemaVersion,
			"feature_id":                      qosReport.FeatureID,
			"status":                          qosReport.Status,
			"message":                         qosReport.Message,
			"ready_for_external_validation":   qosReport.ReadyForExternalValidation,
			"software_completion_percent":     qosReport.SoftwareCompletionPercent,
			"enabled":                         qosReport.Summary.Enabled,
			"mode":                            qosReport.Summary.Mode,
			"profile_count":                   qosReport.Summary.ProfileCount,
			"enabled_profile_count":           qosReport.Summary.EnabledProfileCount,
			"service_flow_count":              qosReport.Summary.ServiceFlowCount,
			"enabled_service_flow_count":      qosReport.Summary.EnabledServiceFlowCount,
			"aggregate_policy_count":          qosReport.Summary.AggregatePolicyCount,
			"compiled_attribute_count":        qosReport.Summary.CompiledAttributeCount,
			"compiler_diagnostic_count":       qosReport.Summary.CompilerDiagnosticCount,
			"compliance_check_count":          qosReport.Summary.ComplianceCheckCount,
			"passed_check_count":              qosReport.Summary.PassedCheckCount,
			"warning_count":                   qosReport.Summary.WarningCount,
			"blocker_count":                   qosReport.Summary.BlockerCount,
			"plan_fingerprint":                qosReport.PlanFingerprint,
			"release_certification_checklist": qosReport.ReleaseCertificationChecklist,
			"evidence_summary":                qosSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandQoSServiceFlowComponent()],
		}
	} else {
		broadbandQoSServiceFlowStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandQoSServiceFlowComponent()]}
	}
	broadbandL2TPWholesaleStatus := map[string]any{
		"status":  "unknown",
		"message": "L2TP wholesale realm separation status has not been evaluated.",
	}
	if l2tpReport, err := enforcement.PreviewBroadbandL2TPWholesale(cfg); err == nil {
		l2tpSummary, _ := db.GetBroadbandL2TPWholesaleSummary()
		broadbandL2TPWholesaleStatus = map[string]any{
			"schema_version":                  l2tpReport.SchemaVersion,
			"feature_id":                      l2tpReport.FeatureID,
			"status":                          l2tpReport.Status,
			"message":                         l2tpReport.Message,
			"ready_for_external_validation":   l2tpReport.ReadyForExternalValidation,
			"software_completion_percent":     l2tpReport.SoftwareCompletionPercent,
			"enabled":                         l2tpReport.Summary.Enabled,
			"mode":                            l2tpReport.Summary.Mode,
			"realm_count":                     l2tpReport.Summary.RealmCount,
			"enabled_realm_count":             l2tpReport.Summary.EnabledRealmCount,
			"tunnel_profile_count":            l2tpReport.Summary.TunnelProfileCount,
			"enabled_tunnel_profile_count":    l2tpReport.Summary.EnabledTunnelProfileCount,
			"failover_policy_count":           l2tpReport.Summary.FailoverPolicyCount,
			"proxy_route_binding_count":       l2tpReport.Summary.ProxyRouteBindingCount,
			"accounting_route_binding_count":  l2tpReport.Summary.AccountingRouteBindingCount,
			"compiled_attribute_count":        l2tpReport.Summary.CompiledAttributeCount,
			"compliance_check_count":          l2tpReport.Summary.ComplianceCheckCount,
			"passed_check_count":              l2tpReport.Summary.PassedCheckCount,
			"warning_count":                   l2tpReport.Summary.WarningCount,
			"blocker_count":                   l2tpReport.Summary.BlockerCount,
			"plan_fingerprint":                l2tpReport.PlanFingerprint,
			"release_certification_checklist": l2tpReport.ReleaseCertificationChecklist,
			"evidence_summary":                l2tpSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandL2TPWholesaleComponent()],
		}
	} else {
		broadbandL2TPWholesaleStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandL2TPWholesaleComponent()]}
	}
	broadbandDHCPSecurityStatus := map[string]any{
		"status":  "unknown",
		"message": "DHCP relay, snooping, Option 82, and source guard status has not been evaluated.",
	}
	if dhcpReport, err := enforcement.PreviewBroadbandDHCPSecurity(cfg); err == nil {
		dhcpSummary, _ := db.GetBroadbandDHCPSecuritySummary()
		broadbandDHCPSecurityStatus = map[string]any{
			"schema_version":                  dhcpReport.SchemaVersion,
			"feature_id":                      dhcpReport.FeatureID,
			"status":                          dhcpReport.Status,
			"message":                         dhcpReport.Message,
			"ready_for_external_validation":   dhcpReport.ReadyForExternalValidation,
			"software_completion_percent":     dhcpReport.SoftwareCompletionPercent,
			"enabled":                         dhcpReport.Summary.Enabled,
			"mode":                            dhcpReport.Summary.Mode,
			"relay_agent_count":               dhcpReport.Summary.RelayAgentCount,
			"enabled_relay_agent_count":       dhcpReport.Summary.EnabledRelayAgentCount,
			"port_count":                      dhcpReport.Summary.PortCount,
			"enabled_port_count":              dhcpReport.Summary.EnabledPortCount,
			"trusted_port_count":              dhcpReport.Summary.TrustedPortCount,
			"option82_rule_count":             dhcpReport.Summary.Option82RuleCount,
			"source_guard_policy_count":       dhcpReport.Summary.SourceGuardPolicyCount,
			"radius_correlation_count":        dhcpReport.Summary.RADIUSCorrelationCount,
			"compiled_option_count":           dhcpReport.Summary.CompiledOptionCount,
			"compliance_check_count":          dhcpReport.Summary.ComplianceCheckCount,
			"passed_check_count":              dhcpReport.Summary.PassedCheckCount,
			"warning_count":                   dhcpReport.Summary.WarningCount,
			"blocker_count":                   dhcpReport.Summary.BlockerCount,
			"plan_fingerprint":                dhcpReport.PlanFingerprint,
			"release_certification_checklist": dhcpReport.ReleaseCertificationChecklist,
			"evidence_summary":                dhcpSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandDHCPSecurityComponent()],
		}
	} else {
		broadbandDHCPSecurityStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandDHCPSecurityComponent()]}
	}
	broadbandServiceActivationStatus := map[string]any{
		"status":  "unknown",
		"message": "BNG service activation status has not been evaluated.",
	}
	if activationReport, err := enforcement.PreviewBroadbandServiceActivation(cfg); err == nil {
		activationSummary, _ := db.GetBroadbandServiceActivationSummary()
		broadbandServiceActivationStatus = map[string]any{
			"schema_version":                  activationReport.SchemaVersion,
			"feature_id":                      activationReport.FeatureID,
			"status":                          activationReport.Status,
			"message":                         activationReport.Message,
			"ready_for_external_validation":   activationReport.ReadyForExternalValidation,
			"software_completion_percent":     activationReport.SoftwareCompletionPercent,
			"enabled":                         activationReport.Summary.Enabled,
			"mode":                            activationReport.Summary.Mode,
			"service_count":                   activationReport.Summary.ServiceCount,
			"enabled_service_count":           activationReport.Summary.EnabledServiceCount,
			"route_policy_count":              activationReport.Summary.RoutePolicyCount,
			"enabled_route_policy_count":      activationReport.Summary.EnabledRoutePolicyCount,
			"multicast_profile_count":         activationReport.Summary.MulticastProfileCount,
			"enabled_multicast_profile_count": activationReport.Summary.EnabledMulticastProfileCount,
			"activation_policy_count":         activationReport.Summary.ActivationPolicyCount,
			"radius_attribute_count":          activationReport.Summary.RadiusAttributeCount,
			"route_attribute_count":           activationReport.Summary.RouteAttributeCount,
			"multicast_attribute_count":       activationReport.Summary.MulticastAttributeCount,
			"compliance_check_count":          activationReport.Summary.ComplianceCheckCount,
			"passed_check_count":              activationReport.Summary.PassedCheckCount,
			"warning_count":                   activationReport.Summary.WarningCount,
			"blocker_count":                   activationReport.Summary.BlockerCount,
			"plan_fingerprint":                activationReport.PlanFingerprint,
			"release_certification_checklist": activationReport.ReleaseCertificationChecklist,
			"evidence_summary":                activationSummary,
			"runtime_status":                  runtimeMap[enforcement.BroadbandServiceActivationComponent()],
		}
	} else {
		broadbandServiceActivationStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandServiceActivationComponent()]}
	}
	broadbandGovernanceSelfServiceStatus := map[string]any{
		"status":  "unknown",
		"message": "Lawful governance and subscriber self-service status has not been evaluated.",
	}
	if governanceReport, err := enforcement.PreviewBroadbandGovernanceSelfService(cfg); err == nil {
		governanceSummary, _ := db.GetBroadbandGovernanceSelfServiceSummary()
		broadbandGovernanceSelfServiceStatus = map[string]any{
			"schema_version":                      governanceReport.SchemaVersion,
			"feature_id":                          governanceReport.FeatureID,
			"status":                              governanceReport.Status,
			"message":                             governanceReport.Message,
			"ready_for_external_validation":       governanceReport.ReadyForExternalValidation,
			"software_completion_percent":         governanceReport.SoftwareCompletionPercent,
			"enabled":                             governanceReport.Summary.Enabled,
			"mode":                                governanceReport.Summary.Mode,
			"case_count":                          governanceReport.Summary.CaseCount,
			"enabled_case_count":                  governanceReport.Summary.EnabledCaseCount,
			"approval_policy_count":               governanceReport.Summary.ApprovalPolicyCount,
			"enabled_approval_policy_count":       governanceReport.Summary.EnabledApprovalPolicyCount,
			"self_service_action_count":           governanceReport.Summary.SelfServiceActionCount,
			"enabled_self_service_count":          governanceReport.Summary.EnabledSelfServiceCount,
			"privacy_policy_count":                governanceReport.Summary.PrivacyPolicyCount,
			"enabled_privacy_policy_count":        governanceReport.Summary.EnabledPrivacyPolicyCount,
			"compiled_attribute_count":            governanceReport.Summary.CompiledAttributeCount,
			"compliance_check_count":              governanceReport.Summary.ComplianceCheckCount,
			"passed_check_count":                  governanceReport.Summary.PassedCheckCount,
			"warning_count":                       governanceReport.Summary.WarningCount,
			"blocker_count":                       governanceReport.Summary.BlockerCount,
			"plan_fingerprint":                    governanceReport.PlanFingerprint,
			"release_certification_checklist":     governanceReport.ReleaseCertificationChecklist,
			"release_certification_external_only": true,
			"evidence_summary":                    governanceSummary,
			"runtime_status":                      runtimeMap[enforcement.BroadbandGovernanceSelfServiceComponent()],
		}
	} else {
		broadbandGovernanceSelfServiceStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap[enforcement.BroadbandGovernanceSelfServiceComponent()]}
	}
	subscriberRouteExportStatus := map[string]any{
		"status":  "unknown",
		"message": "Dynamic subscriber route export status has not been evaluated.",
	}
	if routeExportPlan, err := enforcement.PreviewSubscriberRouteExport(cfg); err == nil {
		routeExportSummary, _ := db.GetSubscriberRouteExportSummary()
		subscriberRouteExportStatus = map[string]any{
			"schema_version":   enforcement.SubscriberRouteExportSchemaVersion,
			"status":           routeExportPlan.Status,
			"message":          routeExportPlan.Message,
			"driver":           routeExportPlan.Driver,
			"apply_enabled":    routeExportPlan.ApplyEnabled,
			"artifact_path":    routeExportPlan.ArtifactPath,
			"artifact_sha256":  routeExportPlan.ArtifactSHA256,
			"plan_fingerprint": routeExportPlan.PlanFingerprint,
			"summary":          routeExportPlan.Summary,
			"diagnostic_count": len(routeExportPlan.Diagnostics),
			"evidence_summary": routeExportSummary,
			"runtime_status":   runtimeMap["subscriber_route_export"],
		}
	} else {
		subscriberRouteExportStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["subscriber_route_export"]}
	}
	atomicEnforcementStatus := map[string]any{
		"status":  "unknown",
		"message": "Atomic enforcement transactions have not been evaluated.",
	}
	if atomicPlan, err := enforcement.BuildAtomicEnforcementPlan(r.Context(), cfg, enforcement.AtomicEnforcementRequest{}); err == nil {
		atomicSummary, _ := db.GetEnforcementTransactionSummary()
		atomicEnforcementStatus = map[string]any{
			"schema_version":   enforcement.AtomicEnforcementSchemaVersion,
			"status":           atomicPlan.Status,
			"message":          atomicPlan.Message,
			"plan_fingerprint": atomicPlan.PlanFingerprint,
			"summary":          atomicPlan.Summary,
			"target_count":     len(atomicPlan.Targets),
			"diagnostic_count": len(atomicPlan.Diagnostics),
			"capabilities":     atomicPlan.Capabilities,
			"evidence_summary": atomicSummary,
			"runtime_status":   runtimeMap["enforcement_transactions"],
		}
	} else {
		atomicEnforcementStatus = map[string]any{"status": "blocked", "message": err.Error(), "runtime_status": runtimeMap["enforcement_transactions"]}
	}

	healthyServices := 0
	for _, service := range services {
		if service.Status == "ok" {
			healthyServices++
		}
	}

	upstreamStatuses, probeErr := radius.ProbeUpstreamServers(r.Context(), cfg)
	packetHardening := radius.BuildPacketHardeningReport(cfg)
	dynamicNASClients := radius.BuildDynamicNASClientReport(cfg)
	radSecCredentials := radius.BuildRadSecCredentialReport(cfg)
	outboundDAC := radius.BuildOutboundDACReport(cfg)
	nasOwnership := radius.BuildNASCapabilityOwnershipReport(cfg)
	dacHandoff := outboundDAC.Handoff
	proxyRoutes := radius.BuildProxyRoutingReport(cfg)
	transportPolicy := radius.BuildTransportPolicyReport(cfg)
	proxyPolicy := radius.BuildProxyPolicyReport(cfg)
	accountingSpool := radius.BuildAccountingSpoolReport(cfg)
	accountingIngestSpool := radius.BuildAccountingIngestSpoolReport(cfg)
	accountingCharging := radius.BuildAccountingChargingReport(cfg)
	sqlAccounting := radius.BuildSQLAccountingReport(cfg)
	accountingOrdering := radius.BuildAccountingOrderingReport(cfg)
	accountingCounters := radius.BuildAccountingCountersReport(cfg)
	accountingIP := radius.BuildAccountingIPReport(cfg)
	accountingServices := radius.BuildAccountingServicesReport(cfg)
	fallbackPolicy := radius.BuildFallbackPolicyReport(cfg)
	rateCompiler := radius.BuildRateCompilerReport()
	rateCompilerSummary, rateCompilerErr := db.GetRateCompilerEventSummary()
	vlanPolicy := radius.BuildVLANPolicyReport(cfg)
	vlanPolicySummary, vlanPolicyErr := db.GetVLANPolicyEventSummary()
	routePolicy := radius.BuildRoutePolicyReport(cfg)
	routePolicySummary, routePolicyErr := db.GetRoutePolicyEventSummary()
	addressPolicy := radius.BuildAddressPolicyReport(cfg)
	addressPolicySummary, addressPolicyErr := db.GetAddressPolicyEventSummary()
	translationPolicy := radius.BuildTranslationPolicyReport(cfg)
	translationPolicySummary, translationPolicyErr := db.GetTranslationPolicyEventSummary()
	eapSummary, _ := db.SummarizeEAPMethodEvents(1000)
	eapFramework := eappkg.BuildFrameworkReport(cfg, eapRuntimeSummaryFromDB(eapSummary))
	teapSummary, _ := db.SummarizeTEAPChainEvents(1000)
	teapFramework := eappkg.BuildTEAPReport(cfg, teapRuntimeSummaryFromDB(teapSummary))
	machineUserSummary, _ := db.SummarizeMachineUserCorrelations(1000)
	machineUserFramework := eappkg.BuildMachineUserReport(cfg, machineUserRuntimeSummaryFromDB(machineUserSummary))
	fastPWDSummary, _ := db.SummarizeFASTPWDEvents(1000)
	fastPWDFramework := eappkg.BuildFASTPWDReport(cfg, fastPWDRuntimeSummaryFromDB(fastPWDSummary))
	simAKASummary, _ := db.SummarizeSIMAKAEvents(1000)
	simAKAFramework := eappkg.BuildSIMAKAReport(cfg, simAKARuntimeSummaryFromDB(simAKASummary))
	certificateLifecycleSummary, _ := db.SummarizeCertificateLifecycle(1000)
	certificateLifecycle := certlifecycle.BuildReport(cfg, certificateLifecycleRuntimeSummaryFromDB(certificateLifecycleSummary))
	supplicantLifecycleSummary, _ := db.SummarizeSupplicantLifecycle(1000)
	supplicantLifecycle := supplicantprofile.BuildReport(cfg, supplicantRuntimeSummaryFromDB(supplicantLifecycleSummary))
	policyEngine, _ := buildPolicyEngineReport(cfg, 5)
	policySets, _ := buildPolicySetGovernanceReport(cfg, 5)
	policyAnalyses, _ := db.SummarizePolicySimulationAnalyses()
	subscriberServiceChains, _ := buildSubscriberServiceChainsReport(cfg, 5)
	tacacsReport := tacacs.BuildReport(cfg, 5)
	tenantIsolation, _ := buildTenantIsolationReport(cfg, 5)
	vendorMappingCertificationStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0060 vendor mapping certification has not been evaluated.",
	}
	if certification, err := buildVendorMappingCertificationForConfig(cfg); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0060 software certification covers %d/%d partial mappings across %d vendors.",
			certification.Summary.CertifiedMappings,
			certification.Summary.BaselinePartialMappings,
			certification.Summary.VendorCount,
		)
		if err := productconfigs.ValidateVendorMappingCertificationReport(certification); err != nil {
			status = "blocked"
			message = "NAS-0060 vendor mapping certification is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetVendorMappingCertificationSummary()
		vendorMappingCertificationStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      certification.SchemaVersion,
			"source_sha256":                       certification.SourceSHA256,
			"baseline_partial_mappings":           certification.Summary.BaselinePartialMappings,
			"certified_mappings":                  certification.Summary.CertifiedMappings,
			"software_blocked_mappings":           certification.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          certification.Summary.ExternalRequiredMappings,
			"software_completion_percent":         certification.Summary.SoftwareCompletionPercent,
			"fingerprint":                         certification.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0060-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		vendorMappingCertificationStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	ciscoFamilyPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0061 Cisco family pack has not been evaluated.",
	}
	if ciscoPack, err := buildCiscoFamilyPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0061 software certification covers %d/%d Cisco-family rows across %d vendors.",
			ciscoPack.Summary.SoftwareCertifiedMappings,
			ciscoPack.Summary.AttributeCount,
			ciscoPack.Summary.VendorCount,
		)
		if err := productconfigs.ValidateCiscoFamilyPackReport(ciscoPack); err != nil {
			status = "blocked"
			message = "NAS-0061 Cisco family pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetCiscoFamilyPackSummary()
		ciscoFamilyPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      ciscoPack.SchemaVersion,
			"feature_id":                          ciscoPack.FeatureID,
			"source_sha256":                       ciscoPack.SourceSHA256,
			"attribute_count":                     ciscoPack.Summary.AttributeCount,
			"software_certified_mappings":         ciscoPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           ciscoPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          ciscoPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         ciscoPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  ciscoPack.Summary.GrammarRuleCount,
			"fingerprint":                         ciscoPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0061-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		ciscoFamilyPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	arubaFamilyPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0062 Aruba/HPE family pack has not been evaluated.",
	}
	if arubaPack, err := buildArubaFamilyPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0062 software certification covers %d/%d Aruba/HPE-family rows across %d vendors.",
			arubaPack.Summary.SoftwareCertifiedMappings,
			arubaPack.Summary.AttributeCount,
			arubaPack.Summary.VendorCount,
		)
		if err := productconfigs.ValidateArubaFamilyPackReport(arubaPack); err != nil {
			status = "blocked"
			message = "NAS-0062 Aruba/HPE family pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetArubaFamilyPackSummary()
		arubaFamilyPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      arubaPack.SchemaVersion,
			"feature_id":                          arubaPack.FeatureID,
			"source_sha256":                       arubaPack.SourceSHA256,
			"attribute_count":                     arubaPack.Summary.AttributeCount,
			"software_certified_mappings":         arubaPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           arubaPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          arubaPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         arubaPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  arubaPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         arubaPack.Summary.SensitiveRedactedMappings,
			"fingerprint":                         arubaPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0062-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		arubaFamilyPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	juniperExtremePackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0063 Juniper/ERX/Extreme/Mist pack has not been evaluated.",
	}
	if juniperExtremePack, err := buildJuniperExtremePackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0063 software certification covers %d/%d Juniper/ERX/Extreme rows across %d dictionary vendors and %d product scopes.",
			juniperExtremePack.Summary.SoftwareCertifiedMappings,
			juniperExtremePack.Summary.AttributeCount,
			juniperExtremePack.Summary.VendorCount,
			juniperExtremePack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateJuniperExtremePackReport(juniperExtremePack); err != nil {
			status = "blocked"
			message = "NAS-0063 Juniper/ERX/Extreme/Mist pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetJuniperExtremePackSummary()
		juniperExtremePackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      juniperExtremePack.SchemaVersion,
			"feature_id":                          juniperExtremePack.FeatureID,
			"source_sha256":                       juniperExtremePack.SourceSHA256,
			"attribute_count":                     juniperExtremePack.Summary.AttributeCount,
			"software_certified_mappings":         juniperExtremePack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           juniperExtremePack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          juniperExtremePack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         juniperExtremePack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  juniperExtremePack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         juniperExtremePack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 juniperExtremePack.Summary.ProductScopeCount,
			"fingerprint":                         juniperExtremePack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0063-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		juniperExtremePackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	ruckusICXPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0064 Ruckus/ICX pack has not been evaluated.",
	}
	if ruckusICXPack, err := buildRuckusICXPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0064 software certification covers %d/%d Ruckus/ICX rows across %d dictionary vendors and %d product scopes.",
			ruckusICXPack.Summary.SoftwareCertifiedMappings,
			ruckusICXPack.Summary.AttributeCount,
			ruckusICXPack.Summary.VendorCount,
			ruckusICXPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateRuckusICXPackReport(ruckusICXPack); err != nil {
			status = "blocked"
			message = "NAS-0064 Ruckus/ICX pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetRuckusICXPackSummary()
		ruckusICXPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      ruckusICXPack.SchemaVersion,
			"feature_id":                          ruckusICXPack.FeatureID,
			"source_sha256":                       ruckusICXPack.SourceSHA256,
			"attribute_count":                     ruckusICXPack.Summary.AttributeCount,
			"software_certified_mappings":         ruckusICXPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           ruckusICXPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          ruckusICXPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         ruckusICXPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  ruckusICXPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         ruckusICXPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 ruckusICXPack.Summary.ProductScopeCount,
			"fingerprint":                         ruckusICXPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0064-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		ruckusICXPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	fortinetPaloAltoPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0065 Fortinet/Palo Alto pack has not been evaluated.",
	}
	if fortinetPaloAltoPack, err := buildFortinetPaloAltoPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0065 software certification covers %d/%d Fortinet/Palo Alto rows across %d dictionary vendors and %d product scopes.",
			fortinetPaloAltoPack.Summary.SoftwareCertifiedMappings,
			fortinetPaloAltoPack.Summary.AttributeCount,
			fortinetPaloAltoPack.Summary.VendorCount,
			fortinetPaloAltoPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateFortinetPaloAltoPackReport(fortinetPaloAltoPack); err != nil {
			status = "blocked"
			message = "NAS-0065 Fortinet/Palo Alto pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetFortinetPaloAltoPackSummary()
		fortinetPaloAltoPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      fortinetPaloAltoPack.SchemaVersion,
			"feature_id":                          fortinetPaloAltoPack.FeatureID,
			"source_sha256":                       fortinetPaloAltoPack.SourceSHA256,
			"attribute_count":                     fortinetPaloAltoPack.Summary.AttributeCount,
			"software_certified_mappings":         fortinetPaloAltoPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           fortinetPaloAltoPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          fortinetPaloAltoPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         fortinetPaloAltoPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  fortinetPaloAltoPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         fortinetPaloAltoPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 fortinetPaloAltoPack.Summary.ProductScopeCount,
			"fingerprint":                         fortinetPaloAltoPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0065-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		fortinetPaloAltoPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	cloudControllerPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0066 Meraki/UniFi/OpenWiFi cloud pack has not been evaluated.",
	}
	if cloudControllerPack, err := buildCloudControllerPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0066 software certification covers %d/%d Meraki, UniFi/UBNT, and OpenWiFi rows across %d dictionary/runtime vendors and %d product scopes.",
			cloudControllerPack.Summary.SoftwareCertifiedMappings,
			cloudControllerPack.Summary.AttributeCount,
			cloudControllerPack.Summary.VendorCount,
			cloudControllerPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateCloudControllerPackReport(cloudControllerPack); err != nil {
			status = "blocked"
			message = "NAS-0066 Meraki/UniFi/OpenWiFi cloud pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetCloudControllerPackSummary()
		cloudControllerPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      cloudControllerPack.SchemaVersion,
			"feature_id":                          cloudControllerPack.FeatureID,
			"source_sha256":                       cloudControllerPack.SourceSHA256,
			"attribute_count":                     cloudControllerPack.Summary.AttributeCount,
			"software_certified_mappings":         cloudControllerPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           cloudControllerPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          cloudControllerPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         cloudControllerPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  cloudControllerPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         cloudControllerPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 cloudControllerPack.Summary.ProductScopeCount,
			"fingerprint":                         cloudControllerPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0066-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		cloudControllerPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	accessVendorPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0067 Cambium/TP-Link/D-Link access pack has not been evaluated.",
	}
	if accessVendorPack, err := buildAccessVendorPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0067 software certification covers %d/%d Cambium, TP-Link, and D-Link rows across %d dictionary vendors and %d product scopes.",
			accessVendorPack.Summary.SoftwareCertifiedMappings,
			accessVendorPack.Summary.AttributeCount,
			accessVendorPack.Summary.VendorCount,
			accessVendorPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateAccessVendorPackReport(accessVendorPack); err != nil {
			status = "blocked"
			message = "NAS-0067 Cambium/TP-Link/D-Link access pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetAccessVendorPackSummary()
		accessVendorPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      accessVendorPack.SchemaVersion,
			"feature_id":                          accessVendorPack.FeatureID,
			"source_sha256":                       accessVendorPack.SourceSHA256,
			"attribute_count":                     accessVendorPack.Summary.AttributeCount,
			"software_certified_mappings":         accessVendorPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           accessVendorPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          accessVendorPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         accessVendorPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  accessVendorPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         accessVendorPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 accessVendorPack.Summary.ProductScopeCount,
			"fingerprint":                         accessVendorPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0067-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		accessVendorPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	broadbandVendorPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0068 Huawei/H3C/ZTE broadband pack has not been evaluated.",
	}
	if broadbandVendorPack, err := buildBroadbandVendorPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0068 software certification covers %d/%d Huawei, H3C, and ZTE rows across %d dictionary vendors and %d product scopes.",
			broadbandVendorPack.Summary.SoftwareCertifiedMappings,
			broadbandVendorPack.Summary.AttributeCount,
			broadbandVendorPack.Summary.VendorCount,
			broadbandVendorPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateBroadbandVendorPackReport(broadbandVendorPack); err != nil {
			status = "blocked"
			message = "NAS-0068 Huawei/H3C/ZTE broadband pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetBroadbandVendorPackSummary()
		broadbandVendorPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      broadbandVendorPack.SchemaVersion,
			"feature_id":                          broadbandVendorPack.FeatureID,
			"source_sha256":                       broadbandVendorPack.SourceSHA256,
			"attribute_count":                     broadbandVendorPack.Summary.AttributeCount,
			"software_certified_mappings":         broadbandVendorPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           broadbandVendorPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          broadbandVendorPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         broadbandVendorPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  broadbandVendorPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         broadbandVendorPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 broadbandVendorPack.Summary.ProductScopeCount,
			"fingerprint":                         broadbandVendorPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0068-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		broadbandVendorPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	nokiaALUPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0069 Nokia/Alcatel-Lucent service-router pack has not been evaluated.",
	}
	if nokiaALUPack, err := buildNokiaALUPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0069 software certification covers %d/%d Nokia, Alcatel, Alcatel-ESAM, Alcatel-Lucent SR OS, and ALU-AAA rows across %d dictionary vendors and %d product scopes.",
			nokiaALUPack.Summary.SoftwareCertifiedMappings,
			nokiaALUPack.Summary.AttributeCount,
			nokiaALUPack.Summary.VendorCount,
			nokiaALUPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateNokiaALUPackReport(nokiaALUPack); err != nil {
			status = "blocked"
			message = "NAS-0069 Nokia/ALU pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetNokiaALUPackSummary()
		nokiaALUPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      nokiaALUPack.SchemaVersion,
			"feature_id":                          nokiaALUPack.FeatureID,
			"source_sha256":                       nokiaALUPack.SourceSHA256,
			"attribute_count":                     nokiaALUPack.Summary.AttributeCount,
			"software_certified_mappings":         nokiaALUPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           nokiaALUPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          nokiaALUPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         nokiaALUPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  nokiaALUPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         nokiaALUPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 nokiaALUPack.Summary.ProductScopeCount,
			"fingerprint":                         nokiaALUPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0069-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		nokiaALUPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	mikroTikPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0070 MikroTik RouterOS pack has not been evaluated.",
	}
	if mikroTikPack, err := buildMikroTikPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0070 software certification covers %d/%d MikroTik RouterOS rows across %d dictionary vendor and %d product scopes.",
			mikroTikPack.Summary.SoftwareCertifiedMappings,
			mikroTikPack.Summary.AttributeCount,
			mikroTikPack.Summary.VendorCount,
			mikroTikPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateMikroTikPackReport(mikroTikPack); err != nil {
			status = "blocked"
			message = "NAS-0070 MikroTik pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetMikroTikPackSummary()
		mikroTikPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      mikroTikPack.SchemaVersion,
			"feature_id":                          mikroTikPack.FeatureID,
			"source_sha256":                       mikroTikPack.SourceSHA256,
			"attribute_count":                     mikroTikPack.Summary.AttributeCount,
			"software_certified_mappings":         mikroTikPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           mikroTikPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          mikroTikPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         mikroTikPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  mikroTikPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         mikroTikPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 mikroTikPack.Summary.ProductScopeCount,
			"fingerprint":                         mikroTikPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0070-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		mikroTikPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	switchingVendorPackStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0071 enterprise switching vendor pack has not been evaluated.",
	}
	if switchingVendorPack, err := buildSwitchingVendorPackForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0071 software certification covers %d/%d enterprise switching rows across %d dictionary vendors and %d product scopes.",
			switchingVendorPack.Summary.SoftwareCertifiedMappings,
			switchingVendorPack.Summary.AttributeCount,
			switchingVendorPack.Summary.VendorCount,
			switchingVendorPack.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateSwitchingVendorPackReport(switchingVendorPack); err != nil {
			status = "blocked"
			message = "NAS-0071 enterprise switching vendor pack is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetSwitchingVendorPackSummary()
		switchingVendorPackStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      switchingVendorPack.SchemaVersion,
			"feature_id":                          switchingVendorPack.FeatureID,
			"source_sha256":                       switchingVendorPack.SourceSHA256,
			"attribute_count":                     switchingVendorPack.Summary.AttributeCount,
			"software_certified_mappings":         switchingVendorPack.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           switchingVendorPack.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          switchingVendorPack.Summary.ExternalRequiredMappings,
			"software_completion_percent":         switchingVendorPack.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  switchingVendorPack.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         switchingVendorPack.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 switchingVendorPack.Summary.ProductScopeCount,
			"fingerprint":                         switchingVendorPack.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0071-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		switchingVendorPackStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	longTailNamespaceStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0072 long-tail namespace program has not been evaluated.",
	}
	if longTailNamespace, err := buildLongTailNamespaceForRequest(); err == nil {
		status := "ready"
		message := fmt.Sprintf("NAS-0072 software certification covers %d/%d long-tail namespace rows across %d dictionary vendors and %d product scopes.",
			longTailNamespace.Summary.SoftwareCertifiedMappings,
			longTailNamespace.Summary.AttributeCount,
			longTailNamespace.Summary.VendorCount,
			longTailNamespace.Summary.ProductScopeCount,
		)
		if err := productconfigs.ValidateLongTailNamespaceReport(longTailNamespace); err != nil {
			status = "blocked"
			message = "NAS-0072 long-tail namespace program is incomplete: " + err.Error()
		}
		historySummary, historyErr := db.GetLongTailNamespaceSummary()
		longTailNamespaceStatus = map[string]any{
			"status":                              status,
			"message":                             message,
			"schema_version":                      longTailNamespace.SchemaVersion,
			"feature_id":                          longTailNamespace.FeatureID,
			"source_sha256":                       longTailNamespace.SourceSHA256,
			"attribute_count":                     longTailNamespace.Summary.AttributeCount,
			"software_certified_mappings":         longTailNamespace.Summary.SoftwareCertifiedMappings,
			"software_blocked_mappings":           longTailNamespace.Summary.SoftwareBlockedMappings,
			"external_required_mappings":          longTailNamespace.Summary.ExternalRequiredMappings,
			"software_completion_percent":         longTailNamespace.Summary.SoftwareCompletionPercent,
			"grammar_rule_count":                  longTailNamespace.Summary.GrammarRuleCount,
			"sensitive_redacted_mappings":         longTailNamespace.Summary.SensitiveRedactedMappings,
			"product_scope_count":                 longTailNamespace.Summary.ProductScopeCount,
			"vendor_count":                        longTailNamespace.Summary.VendorCount,
			"fingerprint":                         longTailNamespace.Summary.Fingerprint,
			"release_certification_checklist":     "docs/nas-0072-release-certification-checklist.md",
			"release_certification_external_only": true,
			"evidence_summary":                    historySummary,
			"evidence_error":                      rateCompilerErrorString(historyErr),
		}
	} else {
		longTailNamespaceStatus = map[string]any{"status": "blocked", "message": err.Error()}
	}
	externalVendorIntakeStatus := map[string]any{
		"status":  "unknown",
		"message": "NAS-0073 out-of-corpus vendor intake has not been evaluated.",
	}
	externalVendorIntake := productconfigs.BuildExternalVendorIntakeGovernanceReport()
	status := "ready"
	message := fmt.Sprintf("NAS-0073 software intake accepts authoritative external dictionaries with %d supported wire types, %d required provenance fields, and %d maximum attributes per intake.",
		len(externalVendorIntake.SupportedWireTypes),
		len(externalVendorIntake.RequiredProvenanceFields),
		externalVendorIntake.MaxAttributes,
	)
	if err := productconfigs.ValidateExternalVendorIntakeGovernanceReport(externalVendorIntake); err != nil {
		status = "blocked"
		message = "NAS-0073 out-of-corpus vendor intake is incomplete: " + err.Error()
	}
	historySummary, historyErr := db.GetExternalVendorIntakeSummary()
	externalVendorIntakeStatus = map[string]any{
		"status":                              status,
		"message":                             message,
		"schema_version":                      externalVendorIntake.SchemaVersion,
		"feature_id":                          externalVendorIntake.FeatureID,
		"source_sha256":                       externalVendorIntake.SourceSHA256,
		"max_dictionary_bytes":                externalVendorIntake.MaxDictionaryBytes,
		"max_attributes":                      externalVendorIntake.MaxAttributes,
		"allowed_license_count":               len(externalVendorIntake.AllowedLicenses),
		"required_provenance_field_count":     len(externalVendorIntake.RequiredProvenanceFields),
		"supported_wire_type_count":           len(externalVendorIntake.SupportedWireTypes),
		"release_certification_checklist":     "docs/nas-0073-release-certification-checklist.md",
		"release_certification_external_only": true,
		"evidence_summary":                    historySummary,
		"evidence_error":                      rateCompilerErrorString(historyErr),
	}

	radiusStatus := map[string]any{
		"upstream_enabled":        cfg.Radius.Upstream.Enabled,
		"realm":                   cfg.Radius.Upstream.Realm,
		"pool_strategy":           cfg.Radius.Upstream.PoolStrategy,
		"configured_servers":      cfg.Radius.Upstream.Servers,
		"server_statuses":         upstreamStatuses,
		"proxy_routes":            proxyRoutes,
		"transport_policy":        transportPolicy,
		"proxy_policy":            proxyPolicy,
		"accounting_spool":        accountingSpool,
		"accounting_ingest_spool": accountingIngestSpool,
		"accounting_charging":     accountingCharging,
		"sql_accounting":          sqlAccounting,
		"accounting_ordering":     accountingOrdering,
		"accounting_counters":     accountingCounters,
		"accounting_ip":           accountingIP,
		"accounting_services":     accountingServices,
		"fallback_policy":         fallbackPolicy,
		"rate_compiler": map[string]any{
			"status":           firstNonEmptyAdminString(rateCompiler.Status, "ready"),
			"message":          "Vendor rate compiler is ready for unit-safe RADIUS reply and CoA previews.",
			"compiler_version": rateCompiler.CompilerVersion,
			"capability_count": len(rateCompiler.Capabilities),
			"evidence_summary": rateCompilerSummary,
			"evidence_error":   rateCompilerErrorString(rateCompilerErr),
		},
		"vlan_policy": map[string]any{
			"status":           vlanPolicyStatus(vlanPolicy),
			"message":          vlanPolicyMessage(vlanPolicy),
			"compiler_version": vlanPolicy.CompilerVersion,
			"enabled":          vlanPolicy.Enabled,
			"policy_count":     vlanPolicy.Summary.PolicyCount,
			"pool_count":       vlanPolicy.Summary.PoolCount,
			"pool_vlan_count":  vlanPolicy.Summary.PoolVLANCount,
			"voice_policies":   vlanPolicy.Summary.VoicePolicyCount,
			"qinq_policies":    vlanPolicy.Summary.QinQPolicyCount,
			"fallback_count":   vlanPolicy.Summary.FallbackCount,
			"auth_fail_count":  vlanPolicy.Summary.AuthFailCount,
			"evidence_summary": vlanPolicySummary,
			"evidence_error":   rateCompilerErrorString(vlanPolicyErr),
		},
		"route_policy": map[string]any{
			"status":           routePolicyStatus(routePolicy),
			"message":          routePolicyMessage(routePolicy, routePolicySummary),
			"compiler_version": routePolicy.CompilerVersion,
			"enabled":          routePolicy.Enabled,
			"policy_count":     routePolicy.Summary.PolicyCount,
			"vrf_count":        routePolicy.Summary.VRFCount,
			"ipv4_route_count": routePolicy.Summary.IPv4RouteCount,
			"ipv6_route_count": routePolicy.Summary.IPv6RouteCount,
			"active_routes":    routePolicySummary.ActiveRoutes,
			"withdrawn_routes": routePolicySummary.WithdrawnRoutes,
			"evidence_summary": routePolicySummary,
			"evidence_error":   rateCompilerErrorString(routePolicyErr),
		},
		"subscriber_route_export":           subscriberRouteExportStatus,
		"pppoe_access_lifecycle":            pppoeAccessLifecycleStatus,
		"broadband_subscriber_state":        broadbandSubscriberStateStatus,
		"broadband_commercial_catalog":      broadbandCommercialCatalogStatus,
		"broadband_quota_balance":           broadbandQuotaBalanceStatus,
		"broadband_address_leases":          broadbandAddressLeaseStatus,
		"broadband_dhcp_security":           broadbandDHCPSecurityStatus,
		"broadband_service_activation":      broadbandServiceActivationStatus,
		"broadband_governance_self_service": broadbandGovernanceSelfServiceStatus,
		"vendor_mapping_certification":      vendorMappingCertificationStatus,
		"cisco_family_pack":                 ciscoFamilyPackStatus,
		"aruba_family_pack":                 arubaFamilyPackStatus,
		"juniper_extreme_pack":              juniperExtremePackStatus,
		"ruckus_icx_pack":                   ruckusICXPackStatus,
		"fortinet_paloalto_pack":            fortinetPaloAltoPackStatus,
		"cloud_controller_pack":             cloudControllerPackStatus,
		"access_vendor_pack":                accessVendorPackStatus,
		"broadband_vendor_pack":             broadbandVendorPackStatus,
		"nokia_alu_pack":                    nokiaALUPackStatus,
		"mikrotik_pack":                     mikroTikPackStatus,
		"switching_vendor_pack":             switchingVendorPackStatus,
		"long_tail_namespace_program":       longTailNamespaceStatus,
		"external_vendor_intake":            externalVendorIntakeStatus,
		"address_policy": map[string]any{
			"status":                 addressPolicyStatus(addressPolicy),
			"message":                addressPolicyMessage(addressPolicy, addressPolicySummary),
			"compiler_version":       addressPolicy.CompilerVersion,
			"enabled":                addressPolicy.Enabled,
			"policy_count":           addressPolicy.Summary.PolicyCount,
			"pool_count":             addressPolicy.Summary.PoolCount,
			"ipv4_pool_count":        addressPolicy.Summary.IPv4PoolCount,
			"ipv6_pool_count":        addressPolicy.Summary.IPv6PoolCount,
			"delegated_policy_count": addressPolicy.Summary.DelegatedPolicyCount,
			"ra_policy_count":        addressPolicy.Summary.RAPolicyCount,
			"active_assignments":     addressPolicySummary.ActiveAssignments,
			"withdrawn_assignments":  addressPolicySummary.WithdrawnAssignments,
			"delegated_prefixes":     addressPolicySummary.DelegatedPrefixes,
			"ra_prefixes":            addressPolicySummary.RAPrefixes,
			"evidence_summary":       addressPolicySummary,
			"evidence_error":         rateCompilerErrorString(addressPolicyErr),
		},
		"translation_policy": map[string]any{
			"status":                translationPolicyStatus(translationPolicy),
			"message":               translationPolicyMessage(translationPolicy, translationPolicySummary),
			"compiler_version":      translationPolicy.CompilerVersion,
			"enabled":               translationPolicy.Enabled,
			"policy_count":          translationPolicy.Summary.PolicyCount,
			"pool_count":            translationPolicy.Summary.PoolCount,
			"public_ipv4_pools":     translationPolicy.Summary.PublicIPv4Pools,
			"cgnat_policies":        translationPolicy.Summary.CGNATPolicies,
			"nat64_policies":        translationPolicy.Summary.NAT64Policies,
			"port_block_policies":   translationPolicy.Summary.PortBlockPolicies,
			"active_mappings":       translationPolicySummary.ActiveMappings,
			"withdrawn_mappings":    translationPolicySummary.WithdrawnMappings,
			"active_port_blocks":    translationPolicySummary.ActivePortBlocks,
			"active_nat64_mappings": translationPolicySummary.ActiveNAT64Mappings,
			"active_cgnat_mappings": translationPolicySummary.ActiveCGNATMappings,
			"evidence_summary":      translationPolicySummary,
			"evidence_error":        rateCompilerErrorString(translationPolicyErr),
		},
		"eap_framework":              eapFramework,
		"eap_teap":                   teapFramework,
		"eap_machine_user":           machineUserFramework,
		"eap_fast_pwd":               fastPWDFramework,
		"eap_sim_aka":                simAKAFramework,
		"certificate_lifecycle":      certificateLifecycle,
		"supplicant_lifecycle":       supplicantLifecycle,
		"policy_engine":              policyEngine,
		"policy_sets":                policySets,
		"policy_simulation_analyses": policyAnalyses,
		"subscriber_service_chains":  subscriberServiceChains,
		"tacacs":                     tacacsReport,
		"tenant_isolation":           tenantIsolation,
		"enabled_radius_clients":     enabledRadiusClients,
		"broker_auth":                runtimeMap["radius_broker_auth"],
		"broker_accounting":          runtimeMap["radius_broker_accounting"],
		"dynamic_authorization":      cfg.Radius.DynamicAuth,
		"dac_client":                 outboundDAC,
		"nas_ownership":              nasOwnership,
		"dac_handoff":                dacHandoff,
		"dynamic_nas_clients":        dynamicNASClients,
		"radsec_credentials":         radSecCredentials,
		"packet_hardening":           packetHardening,
		"request_timeout_seconds":    cfg.Radius.RequestTimeoutSeconds,
		"vendor_observability": map[string]any{
			"summary": vendorObservabilitySummary,
			"vendors": vendorObservabilityRows,
			"status":  vendorObservabilityStatus(vendorObservabilitySummary),
			"message": vendorObservabilityMessage(vendorObservabilitySummary),
		},
	}
	if probeErr != nil {
		radiusStatus["probe_error"] = probeErr.Error()
	}
	if !cfg.Radius.Upstream.Enabled {
		radiusStatus["broker_auth"] = map[string]any{"status": "disabled", "message": "Upstream AAA is disabled"}
		radiusStatus["broker_accounting"] = map[string]any{"status": "disabled", "message": "Upstream AAA is disabled"}
	}

	wirelessStatus := map[string]any{
		"enabled":                cfg.Wireless.Enabled,
		"interface":              cfg.Wireless.Interface,
		"country_code":           cfg.Wireless.CountryCode,
		"channel":                cfg.Wireless.Channel,
		"hostapd_config_path":    cfg.Wireless.HostapdConfigPath,
		"hostapd_vlan_file_path": cfg.Wireless.HostapdVLANFilePath,
		"hostapd_vlan_lifecycle": hostapdVLANLifecycleStatus,
		"roaming_lifecycle":      wirelessRoamingLifecycleStatus,
		"passpoint_lifecycle":    passpointLifecycleStatus,
		"ppsk_lifecycle":         ppskLifecycleStatus,
		"rf_planning_lifecycle":  rfPlanningLifecycleStatus,
		"security_lifecycle":     wirelessSecurityLifecycleStatus,
		"cwa_portal_lifecycle":   cwaPortalLifecycleStatus,
		"ssid_count":             len(cfg.Wireless.SSIDs),
		"auth_modes":             ssidAuthModes(cfg.Wireless.SSIDs),
	}

	enforcementStatus := map[string]any{
		"shaping_enabled":                   enforcement.RuntimeShapingEnabled(cfg) && enforcement.ShapingInterface(cfg) != "",
		"shaping_interface":                 enforcement.ShapingInterface(cfg),
		"vlan_lifecycle_enabled":            enforcement.RuntimeVLANLifecycleEnabled(cfg) && enforcement.VLANLifecycleInterface(cfg) != "",
		"vlan_lifecycle_interface":          enforcement.VLANLifecycleInterface(cfg),
		"shaped_sessions":                   shapedSessions,
		"shaper":                            runtimeMap["runtime_shaper"],
		"qos_scheduler":                     runtimeQoSStatus,
		"vlan_lifecycle":                    vlanLifecycleStatus,
		"subscriber_route_export":           subscriberRouteExportStatus,
		"broadband_commercial_catalog":      broadbandCommercialCatalogStatus,
		"broadband_quota_balance":           broadbandQuotaBalanceStatus,
		"broadband_address_leases":          broadbandAddressLeaseStatus,
		"broadband_qos_service_flows":       broadbandQoSServiceFlowStatus,
		"broadband_l2tp_wholesale":          broadbandL2TPWholesaleStatus,
		"broadband_dhcp_security":           broadbandDHCPSecurityStatus,
		"broadband_service_activation":      broadbandServiceActivationStatus,
		"broadband_governance_self_service": broadbandGovernanceSelfServiceStatus,
		"local_firewall":                    runtimeFirewallStatus,
		"atomic_transactions":               atomicEnforcementStatus,
	}
	if !enforcement.RuntimeShapingEnabled(cfg) {
		enforcementStatus["shaper"] = map[string]any{"status": "disabled", "message": "Runtime shaping is disabled by deployment or policy config"}
	} else if enforcement.ShapingInterface(cfg) == "" {
		enforcementStatus["shaper"] = map[string]any{"status": "disabled", "message": "No downstream interface is configured for runtime shaping"}
	}

	controllerState := buildControllerAdapterConfiguredState(cfg)
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
			"enabled":            cfg.Integrations.Controller.Enabled,
			"platform":           cfg.Integrations.Controller.Platform,
			"endpoint":           cfg.Integrations.Controller.Endpoint,
			"sync_mode":          cfg.Integrations.Controller.SyncMode,
			"site":               cfg.Integrations.Controller.Site,
			"adapter":            controllerState.Adapter,
			"ready":              controllerState.Ready,
			"site_required":      controllerState.SiteRequired,
			"readiness_warnings": controllerState.ReadinessWarnings,
			"selected_adapter":   controllerState.Selected,
			"sync":               runtimeMap["controller_automation"],
			"estate_lifecycle":   controllerEstateLifecycleStatus,
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
			"enabled":            false,
			"platform":           cfg.Integrations.Controller.Platform,
			"endpoint":           cfg.Integrations.Controller.Endpoint,
			"sync_mode":          cfg.Integrations.Controller.SyncMode,
			"site":               cfg.Integrations.Controller.Site,
			"adapter":            controllerState.Adapter,
			"ready":              controllerState.Ready,
			"site_required":      controllerState.SiteRequired,
			"readiness_warnings": controllerState.ReadinessWarnings,
			"selected_adapter":   controllerState.Selected,
			"sync":               map[string]any{"status": "disabled", "message": "Controller automation is disabled in config"},
			"estate_lifecycle":   controllerEstateLifecycleStatus,
		}
	} else if !cfg.Telemetry.Enabled {
		integrationsStatus["controller"] = map[string]any{
			"enabled":            true,
			"platform":           cfg.Integrations.Controller.Platform,
			"endpoint":           cfg.Integrations.Controller.Endpoint,
			"sync_mode":          cfg.Integrations.Controller.SyncMode,
			"site":               cfg.Integrations.Controller.Site,
			"adapter":            controllerState.Adapter,
			"ready":              controllerState.Ready,
			"site_required":      controllerState.SiteRequired,
			"readiness_warnings": controllerState.ReadinessWarnings,
			"selected_adapter":   controllerState.Selected,
			"sync":               map[string]any{"status": "degraded", "message": "Telemetry service is disabled, so controller automation is not running."},
			"estate_lifecycle":   controllerEstateLifecycleStatus,
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
		"voucher_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.VoucherAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[voucherAnalyticsExportsComponent],
		},
		"voucher_aging_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.VoucherAgingAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherAgingAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAgingAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAgingAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[voucherAgingAnalyticsExportsComponent],
		},
		"voucher_redemption_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.VoucherRedemptionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherRedemptionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherRedemptionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[voucherRedemptionAnalyticsExportsComponent],
		},
		"voucher_expiry_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.VoucherExpiryAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherExpiryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherExpiryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[voucherExpiryAnalyticsExportsComponent],
		},
		"guest_lifecycle_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestLifecycleExports.Enabled,
			"directory":        cfg.Telemetry.GuestLifecycleExports.Directory,
			"format":           cfg.Telemetry.GuestLifecycleExports.Format,
			"interval_minutes": cfg.Telemetry.GuestLifecycleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestLifecycleExports.RetentionCount,
			"runtime":          runtimeMap[guestLifecycleExportsComponent],
		},
		"guest_invite_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestInviteAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestInviteAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestInviteAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestInviteAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[guestInviteAnalyticsExportsComponent],
		},
		"guest_conversion_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestConversionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestConversionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestConversionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestConversionAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[guestConversionAnalyticsExportsComponent],
		},
		"guest_rejection_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestRejectionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestRejectionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestRejectionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestRejectionAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[guestRejectionAnalyticsExportsComponent],
		},
		"guest_delivery_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestDeliveryAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestDeliveryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[guestDeliveryAnalyticsExportsComponent],
		},
		"guest_delivery_failures_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestDeliveryFailuresExports.Enabled,
			"directory":        cfg.Telemetry.GuestDeliveryFailuresExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryFailuresExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryFailuresExports.RetentionCount,
			"runtime":          runtimeMap[guestDeliveryFailuresExportsComponent],
		},
		"guest_sponsor_analytics_exports": map[string]any{
			"enabled":          cfg.Telemetry.GuestSponsorAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestSponsorAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestSponsorAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestSponsorAnalyticsExports.RetentionCount,
			"runtime":          runtimeMap[guestSponsorAnalyticsExportsComponent],
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
		telemetryStatus["voucher_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.VoucherAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled voucher analytics exports are not running."},
		}
		telemetryStatus["voucher_aging_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.VoucherAgingAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherAgingAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAgingAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAgingAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled voucher aging analytics exports are not running."},
		}
		telemetryStatus["voucher_redemption_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.VoucherRedemptionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherRedemptionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherRedemptionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled voucher redemption analytics exports are not running."},
		}
		telemetryStatus["voucher_expiry_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.VoucherExpiryAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.VoucherExpiryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherExpiryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled voucher expiry analytics exports are not running."},
		}
		telemetryStatus["guest_lifecycle_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestLifecycleExports.Enabled,
			"directory":        cfg.Telemetry.GuestLifecycleExports.Directory,
			"format":           cfg.Telemetry.GuestLifecycleExports.Format,
			"interval_minutes": cfg.Telemetry.GuestLifecycleExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestLifecycleExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest lifecycle exports are not running."},
		}
		telemetryStatus["guest_invite_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestInviteAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestInviteAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestInviteAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestInviteAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest invite analytics exports are not running."},
		}
		telemetryStatus["guest_conversion_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestConversionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestConversionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestConversionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestConversionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest conversion analytics exports are not running."},
		}
		telemetryStatus["guest_rejection_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestRejectionAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestRejectionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestRejectionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestRejectionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest rejection analytics exports are not running."},
		}
		telemetryStatus["guest_delivery_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestDeliveryAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestDeliveryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest delivery analytics exports are not running."},
		}
		telemetryStatus["guest_delivery_failures_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestDeliveryFailuresExports.Enabled,
			"directory":        cfg.Telemetry.GuestDeliveryFailuresExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryFailuresExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryFailuresExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest delivery failure exports are not running."},
		}
		telemetryStatus["guest_sponsor_analytics_exports"] = map[string]any{
			"enabled":          cfg.Telemetry.GuestSponsorAnalyticsExports.Enabled,
			"directory":        cfg.Telemetry.GuestSponsorAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestSponsorAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestSponsorAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Telemetry is disabled, so scheduled guest sponsor analytics exports are not running."},
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
	if cfg.Telemetry.Enabled && !cfg.Telemetry.VoucherAnalyticsExports.Enabled {
		telemetryStatus["voucher_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.VoucherAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled voucher analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.VoucherAgingAnalyticsExports.Enabled {
		telemetryStatus["voucher_aging_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.VoucherAgingAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherAgingAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherAgingAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled voucher aging analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.VoucherRedemptionAnalyticsExports.Enabled {
		telemetryStatus["voucher_redemption_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.VoucherRedemptionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherRedemptionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled voucher redemption analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.VoucherExpiryAnalyticsExports.Enabled {
		telemetryStatus["voucher_expiry_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.VoucherExpiryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.VoucherExpiryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled voucher expiry analytics exports are disabled in config."},
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
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestInviteAnalyticsExports.Enabled {
		telemetryStatus["guest_invite_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestInviteAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestInviteAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestInviteAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest invite analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestConversionAnalyticsExports.Enabled {
		telemetryStatus["guest_conversion_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestConversionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestConversionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestConversionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest conversion analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestRejectionAnalyticsExports.Enabled {
		telemetryStatus["guest_rejection_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestRejectionAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestRejectionAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestRejectionAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest rejection analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestDeliveryAnalyticsExports.Enabled {
		telemetryStatus["guest_delivery_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestDeliveryAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest delivery analytics exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestDeliveryFailuresExports.Enabled {
		telemetryStatus["guest_delivery_failures_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestDeliveryFailuresExports.Directory,
			"format":           cfg.Telemetry.GuestDeliveryFailuresExports.Format,
			"interval_minutes": cfg.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestDeliveryFailuresExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest delivery failure exports are disabled in config."},
		}
	}
	if cfg.Telemetry.Enabled && !cfg.Telemetry.GuestSponsorAnalyticsExports.Enabled {
		telemetryStatus["guest_sponsor_analytics_exports"] = map[string]any{
			"enabled":          false,
			"directory":        cfg.Telemetry.GuestSponsorAnalyticsExports.Directory,
			"format":           cfg.Telemetry.GuestSponsorAnalyticsExports.Format,
			"interval_minutes": cfg.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes,
			"retention_count":  cfg.Telemetry.GuestSponsorAnalyticsExports.RetentionCount,
			"runtime":          map[string]any{"status": "disabled", "message": "Scheduled guest sponsor analytics exports are disabled in config."},
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
	productionReadiness := buildProductionReadinessReport(cfg)
	identityFailover := identity.BuildFailoverReport(cfg)
	activeDirectory := activedirectory.BuildReport(cfg)
	mfaReport := mfapkg.BuildReport(cfg)
	webAuthnReport := webauthnpkg.BuildReport(cfg)
	mabReport := mabpkg.BuildReport(cfg)

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
		"services":             services,
		"deployment":           config.DeploymentSummary(cfg),
		"database":             db.BuildStatusReport(cfg),
		"production_readiness": productionReadinessSummaryFromReport(productionReadiness),
		"identity":             map[string]any{"failover": identityFailover, "active_directory": activeDirectory, "mfa": mfaReport, "webauthn": webAuthnReport, "mab": mabReport},
		"radius":               radiusStatus,
		"wireless":             wirelessStatus,
		"enforcement":          enforcementStatus,
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
			"apply_stats":                 applyStats,
			"lease_trends":                leaseTrends,
			"recovery":                    recoveryState,
			"controller_sync":             runtimeMap["controller_automation"],
			"controller_estate_lifecycle": controllerEstateLifecycleStatus,
			"vendor_observability": map[string]any{
				"summary": vendorObservabilitySummary,
				"vendors": vendorObservabilityRows,
				"status":  vendorObservabilityStatus(vendorObservabilitySummary),
				"message": vendorObservabilityMessage(vendorObservabilitySummary),
			},
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

func rateCompilerErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func vlanPolicyStatus(report radius.VLANPolicyReport) string {
	switch {
	case !report.Enabled:
		return "disabled"
	case report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0:
		return "ready"
	case report.Summary.VoicePolicyCount > 0 || report.Summary.QinQPolicyCount > 0 || report.Summary.PoolCount > 0:
		return "ok"
	default:
		return "ready"
	}
}

func vlanPolicyMessage(report radius.VLANPolicyReport) string {
	if !report.Enabled {
		return "Tagged VLAN policy compiler is disabled in config."
	}
	if report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0 {
		return "Tagged VLAN policy compiler is ready; no role policy or pool is configured yet."
	}
	return fmt.Sprintf("Tagged VLAN policy compiler has %d role policy(s), %d pool(s), %d voice policy(s), and %d QinQ policy(s).",
		report.Summary.PolicyCount,
		report.Summary.PoolCount,
		report.Summary.VoicePolicyCount,
		report.Summary.QinQPolicyCount)
}

func routePolicyStatus(report radius.RoutePolicyReport) string {
	switch {
	case !report.Enabled:
		return "disabled"
	case report.Summary.PolicyCount == 0 && report.Summary.IPv4RouteCount == 0 && report.Summary.IPv6RouteCount == 0:
		return "ready"
	case report.Summary.IPv4RouteCount > 0 || report.Summary.IPv6RouteCount > 0:
		return "ok"
	default:
		return "ready"
	}
}

func routePolicyMessage(report radius.RoutePolicyReport, summary db.RoutePolicyEventSummary) string {
	if !report.Enabled {
		return "Route policy compiler is disabled in config."
	}
	if report.Summary.PolicyCount == 0 {
		return "Route policy compiler is ready; no role route policy is configured yet."
	}
	return fmt.Sprintf("Route policy compiler has %d role policy(s), %d VRF(s), %d IPv4 route(s), %d IPv6 route(s), and %d active ownership row(s).",
		report.Summary.PolicyCount,
		report.Summary.VRFCount,
		report.Summary.IPv4RouteCount,
		report.Summary.IPv6RouteCount,
		summary.ActiveRoutes)
}

func addressPolicyStatus(report radius.AddressPolicyReport) string {
	switch {
	case !report.Enabled:
		return "disabled"
	case report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0:
		return "ready"
	case report.Summary.DelegatedPolicyCount > 0 || report.Summary.RAPolicyCount > 0 || report.Summary.PoolCount > 0:
		return "ok"
	default:
		return "ready"
	}
}

func addressPolicyMessage(report radius.AddressPolicyReport, summary db.AddressPolicyEventSummary) string {
	if !report.Enabled {
		return "Address policy compiler is disabled in config."
	}
	if report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0 {
		return "Address policy compiler is ready; no IPv4/IPv6 pool, DHCPv6, RA, or delegated-prefix policy is configured yet."
	}
	return fmt.Sprintf("Address policy compiler has %d role policy(s), %d pool(s), %d delegated-prefix policy(s), %d RA policy(s), and %d active ownership row(s).",
		report.Summary.PolicyCount,
		report.Summary.PoolCount,
		report.Summary.DelegatedPolicyCount,
		report.Summary.RAPolicyCount,
		summary.ActiveAssignments)
}

func translationPolicyStatus(report radius.TranslationPolicyReport) string {
	switch {
	case !report.Enabled:
		return "disabled"
	case report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0:
		return "ready"
	case report.Summary.CGNATPolicies > 0 || report.Summary.NAT64Policies > 0 || report.Summary.PortBlockPolicies > 0 || report.Summary.PublicIPv4Pools > 0:
		return "ok"
	default:
		return "ready"
	}
}

func translationPolicyMessage(report radius.TranslationPolicyReport, summary db.TranslationPolicyEventSummary) string {
	if !report.Enabled {
		return "Translation policy compiler is disabled in config."
	}
	if report.Summary.PolicyCount == 0 && report.Summary.PoolCount == 0 {
		return "Translation policy compiler is ready; no CGNAT, NAT64, public address pool, or deterministic port-block policy is configured yet."
	}
	return fmt.Sprintf("Translation policy compiler has %d role policy(s), %d pool(s), %d CGNAT policy(s), %d NAT64 policy(s), %d deterministic port-block policy(s), and %d active ownership row(s).",
		report.Summary.PolicyCount,
		report.Summary.PoolCount,
		report.Summary.CGNATPolicies,
		report.Summary.NAT64Policies,
		report.Summary.PortBlockPolicies,
		summary.ActiveMappings)
}
