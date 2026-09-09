package enforcement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

const (
	WirelessRoamingLifecycleSchemaVersion = 1
	WirelessRoamingLifecycleFeatureID     = "NAS-0075"
)

type WirelessRoamingLifecycleReport struct {
	SchemaVersion                 int                             `json:"schema_version"`
	FeatureID                     string                          `json:"feature_id"`
	Status                        string                          `json:"status"`
	Message                       string                          `json:"message"`
	GeneratedAt                   string                          `json:"generated_at"`
	SoftwareCompletionPercent     float64                         `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                            `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                          `json:"release_certification_checklist"`
	ReleaseScope                  string                          `json:"release_scope"`
	PlanFingerprint               string                          `json:"plan_fingerprint"`
	HostapdConfigPath             string                          `json:"hostapd_config_path,omitempty"`
	HostapdConfigSHA256           string                          `json:"hostapd_config_sha256,omitempty"`
	HostapdConfigPreview          string                          `json:"hostapd_config_preview,omitempty"`
	Summary                       WirelessRoamingLifecycleSummary `json:"summary"`
	SSIDs                         []WirelessRoamingSSIDReport     `json:"ssids"`
	Neighbors                     []WirelessRoamingNeighborReport `json:"neighbors"`
	RFCs                          []string                        `json:"rfcs"`
	Attributes                    []string                        `json:"attributes"`
	Vendors                       []string                        `json:"vendors"`
	Requirements                  []string                        `json:"requirements"`
	Blockers                      []string                        `json:"blockers,omitempty"`
	Warnings                      []string                        `json:"warnings,omitempty"`
	Notes                         []string                        `json:"notes,omitempty"`
}

type WirelessRoamingLifecycleSummary struct {
	WirelessEnabled          bool `json:"wireless_enabled"`
	RoamingEnabled           bool `json:"roaming_enabled"`
	SSIDCount                int  `json:"ssid_count"`
	RoamingSSIDCount         int  `json:"roaming_ssid_count"`
	FTSSIDCount              int  `json:"ft_ssid_count"`
	KSSIDCount               int  `json:"k_ssid_count"`
	VSSIDCount               int  `json:"v_ssid_count"`
	ProfileCount             int  `json:"profile_count"`
	NeighborCount            int  `json:"neighbor_count"`
	KeyRefCount              int  `json:"key_ref_count"`
	StagedKeyRefCount        int  `json:"staged_key_ref_count"`
	ResolvableKeyRefCount    int  `json:"resolvable_key_ref_count"`
	DiagnosticCount          int  `json:"diagnostic_count"`
	ExternalRequirementCount int  `json:"external_requirement_count"`
}

type WirelessRoamingSSIDReport struct {
	SSID                    string   `json:"ssid"`
	AuthMode                string   `json:"auth_mode"`
	ProfileName             string   `json:"profile_name"`
	Status                  string   `json:"status"`
	IEEE80211R              bool     `json:"ieee80211r"`
	IEEE80211K              bool     `json:"ieee80211k"`
	IEEE80211V              bool     `json:"ieee80211v"`
	MobilityDomain          string   `json:"mobility_domain,omitempty"`
	FTOverDS                bool     `json:"ft_over_ds"`
	PMFRequired             bool     `json:"pmf_required"`
	R0KeyLifetimeSeconds    int      `json:"r0_key_lifetime_seconds,omitempty"`
	ReassociationDeadline   int      `json:"reassociation_deadline,omitempty"`
	NASIdentifier           string   `json:"nas_identifier,omitempty"`
	R1KeyHolder             string   `json:"r1_key_holder,omitempty"`
	KeySeedRefSet           bool     `json:"key_seed_ref_set"`
	KeySeedRefFingerprint   string   `json:"key_seed_ref_fingerprint,omitempty"`
	NextKeySeedRefSet       bool     `json:"next_key_seed_ref_set"`
	NextKeySeedFingerprint  string   `json:"next_key_seed_ref_fingerprint,omitempty"`
	KeyRotationMode         string   `json:"key_rotation_mode,omitempty"`
	NextKeyNotBefore        string   `json:"next_key_not_before,omitempty"`
	NextKeyNotAfter         string   `json:"next_key_not_after,omitempty"`
	RRMNeighborReport       bool     `json:"rrm_neighbor_report"`
	RRMBeaconReport         bool     `json:"rrm_beacon_report"`
	BSSTransition           bool     `json:"bss_transition"`
	WNMSleepMode            bool     `json:"wnm_sleep_mode"`
	NeighborCount           int      `json:"neighbor_count"`
	NeighborBSSIDs          []string `json:"neighbor_bssids,omitempty"`
	RadiusCorrelationFields []string `json:"radius_correlation_fields"`
	Diagnostics             []string `json:"diagnostics,omitempty"`
}

type WirelessRoamingNeighborReport struct {
	Name                  string   `json:"name,omitempty"`
	BSSID                 string   `json:"bssid"`
	NASIdentifier         string   `json:"nas_identifier,omitempty"`
	R1KeyHolder           string   `json:"r1_key_holder,omitempty"`
	SSIDs                 []string `json:"ssids,omitempty"`
	Channel               int      `json:"channel,omitempty"`
	OpClass               int      `json:"op_class,omitempty"`
	Preference            int      `json:"preference,omitempty"`
	KeySeedRefSet         bool     `json:"key_seed_ref_set"`
	KeySeedRefFingerprint string   `json:"key_seed_ref_fingerprint,omitempty"`
	Description           string   `json:"description,omitempty"`
}

func PreviewWirelessRoamingLifecycle(cfg *config.Config) (WirelessRoamingLifecycleReport, error) {
	if cfg == nil {
		return WirelessRoamingLifecycleReport{}, fmt.Errorf("config is required")
	}
	report := WirelessRoamingLifecycleReport{
		SchemaVersion:                 WirelessRoamingLifecycleSchemaVersion,
		FeatureID:                     WirelessRoamingLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0075-release-certification-checklist.md",
		ReleaseScope:                  "Real client roaming, controller/AP firmware validation, packet captures, HA failover, scale, soak, security audit, production deployment, and customer proof are release certification activities.",
		HostapdConfigPath:             strings.TrimSpace(cfg.Wireless.HostapdConfigPath),
		RFCs:                          []string{"IEEE 802.11r", "IEEE 802.11k", "IEEE 802.11v", "IEEE 802.11w", "IEEE 802.1X", "RFC 2865", "RFC 2866", "RFC 3748", "RFC 5176"},
		Attributes:                    []string{"EAP-Message", "Message-Authenticator", "Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "NAS-IP-Address", "Acct-Session-Id", "Acct-Multi-Session-Id", "Class", "Event-Timestamp", "Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"},
		Vendors:                       []string{"Cisco", "Aruba", "Ruckus", "Extreme", "Meraki", "UniFi", "Juniper Mist", "Fortinet", "OpenWiFi", "hostapd"},
		Requirements: []string{
			"802.11r FT key management is rendered only for WPA2/WPA3 personal or enterprise SSIDs",
			"802.11k RRM neighbor and beacon report flags are rendered for active roaming SSIDs",
			"802.11v BSS transition management is rendered for active roaming SSIDs",
			"PMF can be required for roaming SSIDs and is always preserved for WPA3",
			"mobility domain, NAS identifier, R1 key holder, and neighbor metadata are validated before render",
			"inter-AP FT keys are derived from secret references and never stored in API, DB, logs, support bundle, or UI payloads",
			"RADIUS/EAP/Accounting/CoA fields needed for roam correlation are declared in the report",
			"roaming lifecycle preview/apply/status/history is auditable and backward compatible",
		},
		Notes: []string{
			"NAS-0075 completes software handling for local hostapd roaming intent and key lifecycle evidence.",
			"Controller-native roaming orchestration and physical AP/client roaming evidence remain release certification work.",
		},
	}
	summary := WirelessRoamingLifecycleSummary{
		WirelessEnabled:          cfg.Wireless.Enabled,
		RoamingEnabled:           cfg.Wireless.Roaming.Enabled,
		SSIDCount:                len(cfg.Wireless.SSIDs),
		ProfileCount:             len(cfg.Wireless.Roaming.Profiles),
		NeighborCount:            len(cfg.Wireless.Roaming.NeighborAPs),
		ExternalRequirementCount: 8,
	}
	report.Neighbors = buildWirelessRoamingNeighborReports(cfg.Wireless.Roaming.NeighborAPs)
	summary.KeyRefCount += countWirelessRoamingKeyRefs(cfg.Wireless.Roaming.KeySeedRef, cfg.Wireless.Roaming.NeighborAPs, cfg.Wireless.Roaming.Profiles)
	if strings.TrimSpace(cfg.Wireless.Roaming.NextKeySeedRef) != "" {
		summary.StagedKeyRefCount++
	}

	if !cfg.Wireless.Enabled || !cfg.Wireless.Roaming.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0075 software is ready; wireless roaming is not active in this configuration."
		report.Summary = summary
		report.PlanFingerprint = wirelessRoamingFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Status = "blocked"
		report.Blockers = append(report.Blockers, err.Error())
		report.Summary = summary
		report.Summary.DiagnosticCount = len(report.Blockers)
		report.SoftwareCompletionPercent = 0
		report.ReadyForExternalValidation = false
		report.Message = "NAS-0075 roaming lifecycle is blocked by invalid configuration."
		report.PlanFingerprint = wirelessRoamingFingerprint(report)
		return report, nil
	}

	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	seenKeyRefs := map[string]struct{}{}
	for _, ssid := range cfg.Wireless.SSIDs {
		effective, active := config.EffectiveSSIDRoamingProfile(cfg.Wireless, ssid)
		if !active {
			continue
		}
		ssidReport := buildWirelessRoamingSSIDReport(ssid, effective)
		if effective.KeySeedRef != "" {
			seenKeyRefs[effective.KeySeedRef] = struct{}{}
			if _, err := resolver.Resolve(context.Background(), effective.KeySeedRef); err != nil {
				ssidReport.Status = "blocked"
				ssidReport.Diagnostics = append(ssidReport.Diagnostics, "key_seed_ref does not resolve: "+err.Error())
				report.Blockers = append(report.Blockers, fmt.Sprintf("%s key_seed_ref does not resolve: %s", ssid.Name, err.Error()))
			} else {
				summary.ResolvableKeyRefCount++
			}
		}
		for _, neighbor := range effective.NeighborAPs {
			ref := strings.TrimSpace(neighbor.KeySeedRef)
			if ref == "" {
				continue
			}
			if _, exists := seenKeyRefs[ref]; exists {
				continue
			}
			seenKeyRefs[ref] = struct{}{}
			if _, err := resolver.Resolve(context.Background(), ref); err != nil {
				ssidReport.Status = "blocked"
				ssidReport.Diagnostics = append(ssidReport.Diagnostics, "neighbor key_seed_ref does not resolve: "+err.Error())
				report.Blockers = append(report.Blockers, fmt.Sprintf("%s neighbor key_seed_ref does not resolve: %s", ssid.Name, err.Error()))
			} else {
				summary.ResolvableKeyRefCount++
			}
		}
		if effective.NextKeySeedRef != "" {
			seenKeyRefs[effective.NextKeySeedRef] = struct{}{}
			if _, err := resolver.Resolve(context.Background(), effective.NextKeySeedRef); err != nil {
				ssidReport.Status = "blocked"
				ssidReport.Diagnostics = append(ssidReport.Diagnostics, "next_key_seed_ref does not resolve: "+err.Error())
				report.Blockers = append(report.Blockers, fmt.Sprintf("%s next_key_seed_ref does not resolve: %s", ssid.Name, err.Error()))
			} else {
				summary.ResolvableKeyRefCount++
			}
		}
		if effective.IEEE80211R && len(effective.NeighborAPs) > 0 && !wirelessRoamingNeighborsHaveKeyRefs(effective) {
			ssidReport.Status = "blocked"
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "802.11r neighbor key lifecycle requires key_seed_ref")
			report.Blockers = append(report.Blockers, fmt.Sprintf("%s 802.11r neighbor key lifecycle requires key_seed_ref", ssid.Name))
		}
		if effective.IEEE80211R && !effective.PMFRequired && strings.Contains(strings.ToLower(ssid.AuthMode), "enterprise") {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s uses FT enterprise roaming without PMF-required policy", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "FT enterprise roaming should require PMF before production sign-off")
		}
		if effective.KeyRotationMode == "staged" && effective.NextKeySeedRef == "" {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s stages roaming key rotation without next_key_seed_ref", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "staged key rotation has no next key reference")
		}
		summary.RoamingSSIDCount++
		if effective.IEEE80211R {
			summary.FTSSIDCount++
		}
		if effective.IEEE80211K {
			summary.KSSIDCount++
		}
		if effective.IEEE80211V {
			summary.VSSIDCount++
		}
		report.SSIDs = append(report.SSIDs, ssidReport)
	}
	if summary.RoamingSSIDCount == 0 {
		report.Blockers = append(report.Blockers, "wireless.roaming.enabled requires at least one WPA2/WPA3 SSID with active roaming profile")
	}
	hostapdConfig, err := wireless.GenerateHostapdConfig(cfg)
	if err != nil {
		report.Blockers = append(report.Blockers, "hostapd roaming config render failed: "+err.Error())
	} else {
		sum := sha256.Sum256([]byte(hostapdConfig))
		report.HostapdConfigSHA256 = "sha256:" + hex.EncodeToString(sum[:])
		report.HostapdConfigPreview = redactHostapdConfigPreview(hostapdConfig)
	}
	summary.DiagnosticCount = len(report.Blockers) + len(report.Warnings)
	summary.KeyRefCount = len(seenKeyRefs)
	report.Summary = summary
	report.Status = wirelessRoamingStatus(report)
	report.SoftwareCompletionPercent = wirelessRoamingCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = wirelessRoamingMessage(report)
	report.PlanFingerprint = wirelessRoamingFingerprint(report)
	return report, nil
}

func PreviewAndRecordWirelessRoamingLifecycle(cfg *config.Config, actor string) (WirelessRoamingLifecycleReport, string, error) {
	report, err := PreviewWirelessRoamingLifecycle(cfg)
	if err != nil {
		return WirelessRoamingLifecycleReport{}, "", err
	}
	eventID, err := recordWirelessRoamingLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyWirelessRoamingLifecycle(cfg *config.Config, actor string) (WirelessRoamingLifecycleReport, string, error) {
	report, err := PreviewWirelessRoamingLifecycle(cfg)
	if err != nil {
		return WirelessRoamingLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordWirelessRoamingLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		return report, eventID, fmt.Errorf("wireless roaming lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		if _, err := wireless.WriteConfig(cfg); err != nil {
			report.Status = "failed"
			report.Message = "NAS-0075 hostapd roaming config apply failed: " + err.Error()
			report.Blockers = append(report.Blockers, err.Error())
			report.SoftwareCompletionPercent = 0
			report.ReadyForExternalValidation = false
			eventID, recordErr := recordWirelessRoamingLifecycleEvent(report, "apply", actor)
			if recordErr != nil {
				return report, eventID, recordErr
			}
			return report, eventID, err
		}
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0075 applied hostapd roaming configuration for %d roaming SSID(s).", report.Summary.RoamingSSIDCount)
	}
	eventID, err := recordWirelessRoamingLifecycleEvent(report, "apply", actor)
	return report, eventID, err
}

func recordWirelessRoamingLifecycleEvent(report WirelessRoamingLifecycleReport, operation, actor string) (string, error) {
	status := report.Status
	switch operation {
	case "preview":
		if status == "ready" || status == "degraded" {
			status = "previewed"
		}
	case "apply":
		if status == "ready" || status == "degraded" {
			status = "applied"
		}
	}
	return db.RecordWirelessRoamingLifecycleEvent(db.WirelessRoamingLifecycleEventInput{
		Operation:           operation,
		Status:              status,
		ConfigPath:          report.HostapdConfigPath,
		HostapdConfigSHA256: report.HostapdConfigSHA256,
		PlanFingerprint:     report.PlanFingerprint,
		SSIDCount:           report.Summary.SSIDCount,
		RoamingSSIDCount:    report.Summary.RoamingSSIDCount,
		FTSSIDCount:         report.Summary.FTSSIDCount,
		KSSIDCount:          report.Summary.KSSIDCount,
		VSSIDCount:          report.Summary.VSSIDCount,
		ProfileCount:        report.Summary.ProfileCount,
		NeighborCount:       report.Summary.NeighborCount,
		KeyRefCount:         report.Summary.KeyRefCount,
		StagedKeyRefCount:   report.Summary.StagedKeyRefCount,
		DiagnosticCount:     report.Summary.DiagnosticCount,
		SummaryJSON:         marshalJSON(report.Summary),
		ReportJSON:          marshalJSON(report),
		Actor:               actor,
	})
}

func buildWirelessRoamingSSIDReport(ssid config.SSIDConfig, effective config.EffectiveWirelessRoamingProfile) WirelessRoamingSSIDReport {
	report := WirelessRoamingSSIDReport{
		SSID:                    ssid.Name,
		AuthMode:                ssid.AuthMode,
		ProfileName:             effective.ProfileName,
		Status:                  "ready",
		IEEE80211R:              effective.IEEE80211R,
		IEEE80211K:              effective.IEEE80211K,
		IEEE80211V:              effective.IEEE80211V,
		MobilityDomain:          effective.MobilityDomain,
		FTOverDS:                effective.FTOverDS,
		PMFRequired:             effective.PMFRequired,
		R0KeyLifetimeSeconds:    effective.R0KeyLifetimeSeconds,
		ReassociationDeadline:   effective.ReassociationDeadline,
		NASIdentifier:           effective.NASIdentifier,
		R1KeyHolder:             effective.R1KeyHolder,
		KeySeedRefSet:           strings.TrimSpace(effective.KeySeedRef) != "",
		KeySeedRefFingerprint:   wirelessRoamingSecretFingerprint(effective.KeySeedRef),
		NextKeySeedRefSet:       strings.TrimSpace(effective.NextKeySeedRef) != "",
		NextKeySeedFingerprint:  wirelessRoamingSecretFingerprint(effective.NextKeySeedRef),
		KeyRotationMode:         effective.KeyRotationMode,
		NextKeyNotBefore:        effective.NextKeyNotBefore,
		NextKeyNotAfter:         effective.NextKeyNotAfter,
		RRMNeighborReport:       effective.RRMNeighborReport,
		RRMBeaconReport:         effective.RRMBeaconReport,
		BSSTransition:           effective.BSSTransition,
		WNMSleepMode:            effective.WNMSleepMode,
		NeighborCount:           len(effective.NeighborAPs),
		RadiusCorrelationFields: []string{"Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "Acct-Session-Id", "Acct-Multi-Session-Id", "Class", "Event-Timestamp"},
	}
	for _, neighbor := range effective.NeighborAPs {
		report.NeighborBSSIDs = append(report.NeighborBSSIDs, normalizeRoamingBSSID(neighbor.BSSID))
	}
	sort.Strings(report.NeighborBSSIDs)
	return report
}

func buildWirelessRoamingNeighborReports(neighbors []config.WirelessNeighborAPConfig) []WirelessRoamingNeighborReport {
	reports := make([]WirelessRoamingNeighborReport, 0, len(neighbors))
	for _, neighbor := range neighbors {
		ref := strings.TrimSpace(neighbor.KeySeedRef)
		reports = append(reports, WirelessRoamingNeighborReport{
			Name:                  strings.TrimSpace(neighbor.Name),
			BSSID:                 normalizeRoamingBSSID(neighbor.BSSID),
			NASIdentifier:         strings.TrimSpace(neighbor.NASIdentifier),
			R1KeyHolder:           strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(neighbor.R1KeyHolder), ":", ""), "-", "")),
			SSIDs:                 append([]string(nil), neighbor.SSIDs...),
			Channel:               neighbor.Channel,
			OpClass:               neighbor.OpClass,
			Preference:            neighbor.Preference,
			KeySeedRefSet:         ref != "",
			KeySeedRefFingerprint: wirelessRoamingSecretFingerprint(ref),
			Description:           strings.TrimSpace(neighbor.Description),
		})
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].BSSID == reports[j].BSSID {
			return reports[i].Name < reports[j].Name
		}
		return reports[i].BSSID < reports[j].BSSID
	})
	return reports
}

func countWirelessRoamingKeyRefs(global string, neighbors []config.WirelessNeighborAPConfig, profiles []config.WirelessRoamingProfileConfig) int {
	seen := map[string]struct{}{}
	add := func(ref string) {
		if ref = strings.TrimSpace(ref); ref != "" {
			seen[ref] = struct{}{}
		}
	}
	add(global)
	for _, neighbor := range neighbors {
		add(neighbor.KeySeedRef)
	}
	for _, profile := range profiles {
		add(profile.KeySeedRef)
	}
	return len(seen)
}

func wirelessRoamingNeighborsHaveKeyRefs(effective config.EffectiveWirelessRoamingProfile) bool {
	if strings.TrimSpace(effective.KeySeedRef) != "" {
		return true
	}
	if len(effective.NeighborAPs) == 0 {
		return true
	}
	for _, neighbor := range effective.NeighborAPs {
		if strings.TrimSpace(neighbor.KeySeedRef) == "" {
			return false
		}
	}
	return true
}

func wirelessRoamingSecretFingerprint(ref string) string {
	if strings.TrimSpace(ref) == "" {
		return ""
	}
	return secrets.Fingerprint(ref)
}

func normalizeRoamingBSSID(value string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) != 6 {
		return strings.ToLower(strings.TrimSpace(value))
	}
	parts := make([]string, 0, 6)
	for _, octet := range mac {
		parts = append(parts, fmt.Sprintf("%02x", octet))
	}
	return strings.Join(parts, ":")
}

func wirelessRoamingStatus(report WirelessRoamingLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.WirelessEnabled || !report.Summary.RoamingEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func wirelessRoamingCompletion(report WirelessRoamingLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func wirelessRoamingMessage(report WirelessRoamingLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0075 software is ready; wireless roaming is not active in this configuration."
	case "blocked":
		return "NAS-0075 roaming lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0075 plans %d roaming SSID(s) with warnings; review PMF/key rotation before release validation.", report.Summary.RoamingSSIDCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0075 plans %d roaming SSID(s), %d FT SSID(s), %d RRM SSID(s), %d BSS-transition SSID(s), and %d neighbor AP(s).",
			report.Summary.RoamingSSIDCount,
			report.Summary.FTSSIDCount,
			report.Summary.KSSIDCount,
			report.Summary.VSSIDCount,
			report.Summary.NeighborCount,
		)
	}
}

func wirelessRoamingFingerprint(report WirelessRoamingLifecycleReport) string {
	payload := struct {
		FeatureID           string
		HostapdConfigSHA256 string
		Summary             WirelessRoamingLifecycleSummary
		SSIDs               []WirelessRoamingSSIDReport
		Neighbors           []WirelessRoamingNeighborReport
	}{
		FeatureID:           report.FeatureID,
		HostapdConfigSHA256: report.HostapdConfigSHA256,
		Summary:             report.Summary,
		SSIDs:               report.SSIDs,
		Neighbors:           report.Neighbors,
	}
	return sha256JSON(payload)
}
