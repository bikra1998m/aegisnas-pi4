package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

const (
	HostapdVLANLifecycleSchemaVersion = 1
	HostapdVLANLifecycleFeatureID     = "NAS-0074"
)

type HostapdVLANLifecycleReport struct {
	SchemaVersion                 int                         `json:"schema_version"`
	FeatureID                     string                      `json:"feature_id"`
	Status                        string                      `json:"status"`
	Message                       string                      `json:"message"`
	GeneratedAt                   string                      `json:"generated_at"`
	SoftwareCompletionPercent     float64                     `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                        `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                      `json:"release_certification_checklist"`
	ReleaseScope                  string                      `json:"release_scope"`
	Summary                       HostapdVLANLifecycleSummary `json:"summary"`
	Plan                          VLANLifecyclePlan           `json:"plan"`
	HostapdConfigPath             string                      `json:"hostapd_config_path"`
	HostapdConfigSHA256           string                      `json:"hostapd_config_sha256,omitempty"`
	HostapdConfigPreview          string                      `json:"hostapd_config_preview,omitempty"`
	RFCs                          []string                    `json:"rfcs"`
	Attributes                    []string                    `json:"attributes"`
	Requirements                  []string                    `json:"requirements"`
	Blockers                      []string                    `json:"blockers,omitempty"`
	Warnings                      []string                    `json:"warnings,omitempty"`
	Notes                         []string                    `json:"notes,omitempty"`
}

type HostapdVLANLifecycleSummary struct {
	WirelessEnabled          bool `json:"wireless_enabled"`
	DynamicSSIDCount         int  `json:"dynamic_ssid_count"`
	FallbackSSIDCount        int  `json:"fallback_ssid_count"`
	FailClosedSSIDCount      int  `json:"fail_closed_ssid_count"`
	VLANCount                int  `json:"vlan_count"`
	BridgeCount              int  `json:"bridge_count"`
	SubinterfaceCount        int  `json:"subinterface_count"`
	HostapdVLANEntryCount    int  `json:"hostapd_vlan_entry_count"`
	CommandCount             int  `json:"command_count"`
	CleanupCommandCount      int  `json:"cleanup_command_count"`
	RollbackCommandCount     int  `json:"rollback_command_count"`
	DiagnosticCount          int  `json:"diagnostic_count"`
	ExternalRequirementCount int  `json:"external_requirement_count"`
}

func PreviewHostapdVLANLifecycle(cfg *config.Config) (HostapdVLANLifecycleReport, error) {
	if cfg == nil {
		return HostapdVLANLifecycleReport{}, fmt.Errorf("config is required")
	}
	configuredDynamicSSIDs, configuredFallbackSSIDs, configuredFailClosedSSIDs := summarizeConfiguredHostapdDynamicSSIDs(cfg)
	plan, err := PreviewVLANLifecycle(cfg)
	if err != nil {
		return HostapdVLANLifecycleReport{}, err
	}
	if cfg.Wireless.Enabled && configuredDynamicSSIDs > 0 && !RuntimeVLANLifecycleEnabled(cfg) {
		plan.Status = "blocked"
		plan.Message = "hostapd dynamic VLAN requires the dynamic VLAN lifecycle to be enabled"
		plan.Diagnostics = append(plan.Diagnostics, VLANLifecycleDiagnostic{
			Severity: "error",
			Code:     "hostapd_vlan_lifecycle_disabled",
			Message:  "wireless dynamic VLAN SSIDs require policy.runtime_vlan_lifecycle_enabled before local hostapd rollout",
			Field:    "policy.runtime_vlan_lifecycle_enabled",
		})
		finalizeVLANLifecyclePlan(&plan)
	}
	hostapdConfig := ""
	hostapdConfigSHA := ""
	if cfg.Wireless.Enabled && configuredDynamicSSIDs > 0 {
		hostapdConfig, err = wireless.GenerateHostapdConfig(cfg)
		if err != nil {
			plan.Status = "blocked"
			plan.Diagnostics = append(plan.Diagnostics, VLANLifecycleDiagnostic{Severity: "error", Code: "hostapd_config_render_failed", Message: err.Error(), Field: "wireless"})
			finalizeVLANLifecyclePlan(&plan)
		} else {
			sum := sha256.Sum256([]byte(hostapdConfig))
			hostapdConfigSHA = "sha256:" + hex.EncodeToString(sum[:])
		}
	}
	report := HostapdVLANLifecycleReport{
		SchemaVersion:                 HostapdVLANLifecycleSchemaVersion,
		FeatureID:                     HostapdVLANLifecycleFeatureID,
		Status:                        hostapdVLANLifecycleReportStatus(cfg, plan, configuredDynamicSSIDs),
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     hostapdVLANLifecycleCompletion(cfg, plan, configuredDynamicSSIDs),
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0074-release-certification-checklist.md",
		ReleaseScope:                  "Local-radio, hostapd, Linux bridge/VLAN, FreeRADIUS, roaming, HA, performance, soak, security, production deployment, and customer proof are release certification activities.",
		Summary: HostapdVLANLifecycleSummary{
			WirelessEnabled:          cfg.Wireless.Enabled,
			DynamicSSIDCount:         maxInt(plan.Summary.HostapdDynamicSSIDCount, configuredDynamicSSIDs),
			FallbackSSIDCount:        maxInt(plan.Summary.HostapdFallbackSSIDCount, configuredFallbackSSIDs),
			FailClosedSSIDCount:      maxInt(plan.Summary.HostapdFailClosedSSIDCount, configuredFailClosedSSIDs),
			VLANCount:                plan.Summary.VLANCount,
			BridgeCount:              plan.Summary.BridgeCount,
			SubinterfaceCount:        plan.Summary.SubinterfaceCount,
			HostapdVLANEntryCount:    plan.Summary.HostapdVLANEntryCount,
			CommandCount:             plan.Summary.CommandCount,
			CleanupCommandCount:      plan.Summary.CleanupCommandCount,
			RollbackCommandCount:     plan.Summary.RollbackCommandCount,
			DiagnosticCount:          len(plan.Diagnostics),
			ExternalRequirementCount: 8,
		},
		Plan:                 plan,
		HostapdConfigPath:    strings.TrimSpace(cfg.Wireless.HostapdConfigPath),
		HostapdConfigSHA256:  hostapdConfigSHA,
		HostapdConfigPreview: redactHostapdConfigPreview(hostapdConfig),
		RFCs:                 []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176", "IEEE 802.1Q", "IEEE 802.11"},
		Attributes:           []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "Egress-VLANID", "AegisNAS-VLAN"},
		Requirements: []string{
			"hostapd enterprise SSIDs render dynamic_vlan and vlan_file consistently",
			"dynamic SSIDs without fallback VLAN use fail-closed dynamic_vlan=2",
			"dynamic SSIDs with fallback VLAN use optional dynamic_vlan=1",
			"managed VLAN file contains every local VLAN intent accepted by the appliance",
			"bridge and subinterface names are kernel-safe and deterministic",
			"cleanup commands remove obsolete managed VLAN links from the previous snapshot",
			"rollback commands restore the previous snapshot if apply fails",
			"hostapd lifecycle reports redact shared secrets and personal passphrases",
		},
		Notes: []string{
			"NAS-0074 completes the software lifecycle for local hostapd dynamic VLANs; vendor controller roaming and physical AP validation remain external release evidence.",
			"The older NAS-0053 VLAN lifecycle endpoints remain backward compatible and share the same snapshot ledger.",
		},
	}
	for _, diagnostic := range plan.Diagnostics {
		switch diagnostic.Severity {
		case "error":
			report.Blockers = append(report.Blockers, diagnostic.Message)
		case "warning":
			report.Warnings = append(report.Warnings, diagnostic.Message)
		}
	}
	if report.Status == "skipped" {
		report.Message = "NAS-0074 software is ready; local hostapd dynamic VLAN is not active in this configuration."
	} else if report.Status == "blocked" {
		report.ReadyForExternalValidation = false
		report.SoftwareCompletionPercent = 0
		report.Message = "NAS-0074 hostapd dynamic VLAN lifecycle is blocked by the current configuration."
	} else {
		report.Message = fmt.Sprintf("NAS-0074 plans %d dynamic SSID(s), %d VLAN file entries, %d bridge(s), %d cleanup command(s), and %d rollback command(s).",
			report.Summary.DynamicSSIDCount,
			report.Summary.HostapdVLANEntryCount,
			report.Summary.BridgeCount,
			report.Summary.CleanupCommandCount,
			report.Summary.RollbackCommandCount,
		)
	}
	return report, nil
}

func redactHostapdConfigPreview(text string) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	secretKeys := map[string]struct{}{
		"auth_server_shared_secret": {},
		"acct_server_shared_secret": {},
		"wpa_passphrase":            {},
		"sae_password":              {},
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		key, _, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		if _, secret := secretKeys[strings.ToLower(strings.TrimSpace(key))]; secret {
			lines[i] = strings.TrimSpace(key) + "=<redacted>"
		}
	}
	return strings.Join(lines, "\n")
}

func summarizeConfiguredHostapdDynamicSSIDs(cfg *config.Config) (dynamic, fallback, failClosed int) {
	if cfg == nil || !cfg.Wireless.Enabled {
		return 0, 0, 0
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		if !ssid.DynamicVLAN {
			continue
		}
		dynamic++
		if ssid.VLAN > 0 {
			fallback++
		} else {
			failClosed++
		}
	}
	return dynamic, fallback, failClosed
}

func PreviewAndRecordHostapdVLANLifecycle(cfg *config.Config, actor string) (HostapdVLANLifecycleReport, string, error) {
	report, err := PreviewHostapdVLANLifecycle(cfg)
	if err != nil {
		return HostapdVLANLifecycleReport{}, "", err
	}
	eventID, err := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(report.Plan, "preview", vlanPlanStatusToEventStatus(report.Plan.Status), "", "", actor, map[string]any{
		"feature_id":                    HostapdVLANLifecycleFeatureID,
		"hostapd_status":                report.Status,
		"hostapd_dynamic_ssid_count":    report.Summary.DynamicSSIDCount,
		"hostapd_vlan_entry_count":      report.Summary.HostapdVLANEntryCount,
		"cleanup_command_count":         report.Summary.CleanupCommandCount,
		"rollback_command_count":        report.Summary.RollbackCommandCount,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}))
	if err != nil {
		return HostapdVLANLifecycleReport{}, "", err
	}
	return report, eventID, nil
}

func hostapdVLANLifecycleReportStatus(cfg *config.Config, plan VLANLifecyclePlan, configuredDynamicSSIDs int) string {
	if cfg == nil || !cfg.Wireless.Enabled || configuredDynamicSSIDs == 0 {
		return "skipped"
	}
	if plan.Status == "blocked" {
		return "blocked"
	}
	if plan.Status == "degraded" {
		return "degraded"
	}
	return "ready"
}

func hostapdVLANLifecycleCompletion(cfg *config.Config, plan VLANLifecyclePlan, configuredDynamicSSIDs int) float64 {
	if cfg == nil || !cfg.Wireless.Enabled || configuredDynamicSSIDs == 0 {
		return 100
	}
	if plan.Status == "blocked" {
		return 0
	}
	return 100
}
