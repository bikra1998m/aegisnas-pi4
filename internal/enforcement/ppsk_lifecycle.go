package enforcement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

const (
	PPSKLifecycleSchemaVersion = 1
	PPSKLifecycleFeatureID     = "NAS-0077"
)

type PPSKLifecycleReport struct {
	SchemaVersion                 int                    `json:"schema_version"`
	FeatureID                     string                 `json:"feature_id"`
	Status                        string                 `json:"status"`
	Message                       string                 `json:"message"`
	GeneratedAt                   string                 `json:"generated_at"`
	SoftwareCompletionPercent     float64                `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                   `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                 `json:"release_certification_checklist"`
	ReleaseScope                  string                 `json:"release_scope"`
	PlanFingerprint               string                 `json:"plan_fingerprint"`
	HostapdConfigPath             string                 `json:"hostapd_config_path,omitempty"`
	PSKFilePath                   string                 `json:"psk_file_path,omitempty"`
	HostapdConfigSHA256           string                 `json:"hostapd_config_sha256,omitempty"`
	PSKFileSHA256                 string                 `json:"psk_file_sha256,omitempty"`
	HostapdConfigPreview          string                 `json:"hostapd_config_preview,omitempty"`
	PSKFilePreview                string                 `json:"psk_file_preview,omitempty"`
	Summary                       PPSKLifecycleSummary   `json:"summary"`
	SSIDs                         []PPSKSSIDReport       `json:"ssids"`
	Profiles                      []PPSKProfileReport    `json:"profiles"`
	Groups                        []PPSKGroupReport      `json:"groups"`
	Credentials                   []PPSKCredentialReport `json:"credentials"`
	RFCs                          []string               `json:"rfcs"`
	Attributes                    []string               `json:"attributes"`
	Vendors                       []string               `json:"vendors"`
	Requirements                  []string               `json:"requirements"`
	Blockers                      []string               `json:"blockers,omitempty"`
	Warnings                      []string               `json:"warnings,omitempty"`
	Notes                         []string               `json:"notes,omitempty"`
}

type PPSKLifecycleSummary struct {
	WirelessEnabled          bool `json:"wireless_enabled"`
	PPSKEnabled              bool `json:"ppsk_enabled"`
	SSIDCount                int  `json:"ssid_count"`
	PPSKSSIDCount            int  `json:"ppsk_ssid_count"`
	ProfileCount             int  `json:"profile_count"`
	GroupCount               int  `json:"group_count"`
	CredentialCount          int  `json:"credential_count"`
	ActiveCredentialCount    int  `json:"active_credential_count"`
	ResolvableSecretRefCount int  `json:"resolvable_secret_ref_count"`
	StagedCredentialCount    int  `json:"staged_credential_count"`
	RevokedCredentialCount   int  `json:"revoked_credential_count"`
	ExpiredCredentialCount   int  `json:"expired_credential_count"`
	ControllerSyncCount      int  `json:"controller_sync_count"`
	DiagnosticCount          int  `json:"diagnostic_count"`
	ExternalRequirementCount int  `json:"external_requirement_count"`
}

type PPSKSSIDReport struct {
	SSID             string   `json:"ssid"`
	AuthMode         string   `json:"auth_mode"`
	ProfileName      string   `json:"profile_name"`
	Status           string   `json:"status"`
	Mode             string   `json:"mode"`
	FailClosed       bool     `json:"fail_closed"`
	PSKFilePath      string   `json:"psk_file_path"`
	CredentialCount  int      `json:"credential_count"`
	GroupCount       int      `json:"group_count"`
	DefaultVLAN      int      `json:"default_vlan,omitempty"`
	Role             string   `json:"role,omitempty"`
	BandwidthProfile string   `json:"bandwidth_profile,omitempty"`
	ControllerSync   bool     `json:"controller_sync"`
	RadiusAttributes []string `json:"radius_attributes"`
	Diagnostics      []string `json:"diagnostics,omitempty"`
}

type PPSKProfileReport struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Description      string   `json:"description,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	FailClosed       bool     `json:"fail_closed"`
	GroupNames       []string `json:"groups,omitempty"`
	DefaultVLAN      int      `json:"default_vlan,omitempty"`
	Role             string   `json:"role,omitempty"`
	BandwidthProfile string   `json:"bandwidth_profile,omitempty"`
	MaxDevices       int      `json:"max_devices,omitempty"`
	ControllerSync   bool     `json:"controller_sync"`
}

type PPSKGroupReport struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	Description      string `json:"description,omitempty"`
	VLAN             int    `json:"vlan,omitempty"`
	Role             string `json:"role,omitempty"`
	BandwidthProfile string `json:"bandwidth_profile,omitempty"`
	MaxDevices       int    `json:"max_devices,omitempty"`
	SessionLimit     int    `json:"session_limit,omitempty"`
}

type PPSKCredentialReport struct {
	ID                    string   `json:"id,omitempty"`
	MAC                   string   `json:"mac,omitempty"`
	DeviceID              string   `json:"device_id,omitempty"`
	Owner                 string   `json:"owner,omitempty"`
	Profile               string   `json:"profile,omitempty"`
	Group                 string   `json:"group,omitempty"`
	Enabled               bool     `json:"enabled"`
	Revoked               bool     `json:"revoked"`
	Expired               bool     `json:"expired"`
	Status                string   `json:"status"`
	SecretRefSet          bool     `json:"secret_ref_set"`
	SecretRefFingerprint  string   `json:"secret_ref_fingerprint,omitempty"`
	NextSecretRefSet      bool     `json:"next_secret_ref_set"`
	NextSecretFingerprint string   `json:"next_secret_ref_fingerprint,omitempty"`
	NextNotBefore         string   `json:"next_not_before,omitempty"`
	NextNotAfter          string   `json:"next_not_after,omitempty"`
	VLAN                  int      `json:"vlan,omitempty"`
	Role                  string   `json:"role,omitempty"`
	BandwidthProfile      string   `json:"bandwidth_profile,omitempty"`
	ExpiresAt             string   `json:"expires_at,omitempty"`
	Diagnostics           []string `json:"diagnostics,omitempty"`
}

func PreviewPPSKLifecycle(cfg *config.Config) (PPSKLifecycleReport, error) {
	if cfg == nil {
		return PPSKLifecycleReport{}, fmt.Errorf("config is required")
	}
	report := PPSKLifecycleReport{
		SchemaVersion:                 PPSKLifecycleSchemaVersion,
		FeatureID:                     PPSKLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0077-release-certification-checklist.md",
		ReleaseScope:                  "Real Ruckus/Aruba/Cisco/UniFi/Cambium DPSK/PPSK controller synchronization, AP firmware behavior, packet captures, HA failover, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		HostapdConfigPath:             strings.TrimSpace(cfg.Wireless.HostapdConfigPath),
		PSKFilePath:                   wireless.HostapdPPSKFilePath(cfg),
		RFCs:                          []string{"IEEE 802.11", "IEEE 802.11i", "IEEE 802.1X", "RFC 2865", "RFC 2866", "RFC 5176"},
		Attributes:                    []string{"Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "NAS-IP-Address", "Class", "Filter-Id", "Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "Acct-Session-Id", "Acct-Multi-Session-Id", "Event-Timestamp"},
		Vendors:                       []string{"Ruckus", "Aruba", "Cisco", "UniFi", "Cambium", "hostapd"},
		Requirements: []string{
			"Per-device and group PSKs are modeled as secret references and never returned through API, UI, support bundles, or lifecycle history",
			"Local hostapd enforcement writes a managed wpa_psk_file only for WPA2 personal SSIDs with active MAC-bound credentials",
			"Rotation state records active and staged secret references with RFC3339 validity windows",
			"Revoked or expired credentials are excluded from local apply and counted in lifecycle evidence",
			"Profile, group, VLAN, role, and bandwidth intent is preserved for controller-native DPSK certification",
			"PPSK lifecycle preview/apply/status/history is auditable and backward compatible",
		},
		Notes: []string{
			"NAS-0077 completes software handling for local hostapd PPSK intent and controller-ready DPSK policy evidence.",
			"Controller-native DPSK object pushes remain release certification work until exact vendor firmware and API evidence is attached.",
		},
	}
	now := time.Now().UTC()
	summary := PPSKLifecycleSummary{
		WirelessEnabled:          cfg.Wireless.Enabled,
		PPSKEnabled:              cfg.Wireless.PPSK.Enabled,
		SSIDCount:                len(cfg.Wireless.SSIDs),
		ProfileCount:             len(cfg.Wireless.PPSK.Profiles),
		GroupCount:               len(cfg.Wireless.PPSK.Groups),
		CredentialCount:          len(cfg.Wireless.PPSK.Credentials),
		ExternalRequirementCount: 9,
	}
	report.Profiles = buildPPSKProfileReports(cfg.Wireless.PPSK.Profiles)
	report.Groups = buildPPSKGroupReports(cfg.Wireless.PPSK.Groups)
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	for _, credential := range cfg.Wireless.PPSK.Credentials {
		credReport := buildPPSKCredentialReport(credential, now)
		if credential.Revoked {
			summary.RevokedCredentialCount++
		}
		if credReport.Expired {
			summary.ExpiredCredentialCount++
		}
		if strings.TrimSpace(credential.NextSecretRef) != "" {
			summary.StagedCredentialCount++
		}
		if credential.Enabled && !credential.Revoked && !credReport.Expired {
			summary.ActiveCredentialCount++
			if _, err := resolver.Resolve(context.Background(), credential.SecretRef); err != nil {
				credReport.Status = "blocked"
				credReport.Diagnostics = append(credReport.Diagnostics, "secret_ref does not resolve: "+err.Error())
				report.Blockers = append(report.Blockers, fmt.Sprintf("PPSK credential %s secret_ref does not resolve: %s", ppskCredentialLabel(credential), err.Error()))
			} else {
				summary.ResolvableSecretRefCount++
			}
		}
		if strings.TrimSpace(credential.NextSecretRef) != "" {
			if _, err := resolver.Resolve(context.Background(), credential.NextSecretRef); err != nil {
				credReport.Status = "blocked"
				credReport.Diagnostics = append(credReport.Diagnostics, "next_secret_ref does not resolve: "+err.Error())
				report.Blockers = append(report.Blockers, fmt.Sprintf("PPSK credential %s next_secret_ref does not resolve: %s", ppskCredentialLabel(credential), err.Error()))
			}
		}
		report.Credentials = append(report.Credentials, credReport)
	}
	sort.Slice(report.Credentials, func(i, j int) bool {
		return ppskCredentialReportKey(report.Credentials[i]) < ppskCredentialReportKey(report.Credentials[j])
	})
	for _, profile := range cfg.Wireless.PPSK.Profiles {
		if profile.ControllerSync {
			summary.ControllerSyncCount++
		}
	}
	if !cfg.Wireless.Enabled || !cfg.Wireless.PPSK.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0077 software is ready; DPSK/PPSK is not active in this configuration."
		report.Summary = summary
		report.PlanFingerprint = ppskLifecycleFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Status = "blocked"
		report.Blockers = append(report.Blockers, err.Error())
		report.Summary = summary
		report.Summary.DiagnosticCount = len(report.Blockers)
		report.SoftwareCompletionPercent = 0
		report.ReadyForExternalValidation = false
		report.Message = "NAS-0077 DPSK/PPSK lifecycle is blocked by invalid configuration."
		report.PlanFingerprint = ppskLifecycleFingerprint(report)
		return report, nil
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		effective, active := config.EffectiveSSIDPPSKProfile(cfg.Wireless, ssid)
		if !active {
			continue
		}
		ssidReport := buildPPSKSSIDReport(ssid, effective)
		if !strings.EqualFold(ssid.AuthMode, "wpa2-personal") {
			ssidReport.Status = "blocked"
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "local hostapd PPSK currently supports WPA2 personal only")
			report.Blockers = append(report.Blockers, fmt.Sprintf("%s PPSK profile requires WPA2 personal auth", ssid.Name))
		}
		if effective.ControllerSync {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s requests controller-native DPSK sync; certify exact controller behavior before production claim", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "controller-native DPSK sync remains release certification work")
		}
		summary.PPSKSSIDCount++
		report.SSIDs = append(report.SSIDs, ssidReport)
	}
	if summary.PPSKSSIDCount == 0 {
		report.Blockers = append(report.Blockers, "wireless.ppsk.enabled requires at least one WPA2 personal SSID with active PPSK credentials")
	}
	hostapdConfig, err := wireless.GenerateHostapdConfig(cfg)
	if err != nil {
		report.Blockers = append(report.Blockers, "hostapd PPSK config render failed: "+err.Error())
	} else {
		sum := sha256.Sum256([]byte(hostapdConfig))
		report.HostapdConfigSHA256 = "sha256:" + hex.EncodeToString(sum[:])
		report.HostapdConfigPreview = redactHostapdConfigPreview(hostapdConfig)
	}
	pskFile, err := wireless.GeneratePPSKFile(cfg)
	if err != nil {
		report.Blockers = append(report.Blockers, "hostapd PPSK file render failed: "+err.Error())
	} else {
		sum := sha256.Sum256([]byte(pskFile))
		report.PSKFileSHA256 = "sha256:" + hex.EncodeToString(sum[:])
		report.PSKFilePreview = redactPPSKFilePreview(pskFile)
	}
	summary.DiagnosticCount = len(report.Blockers) + len(report.Warnings)
	report.Summary = summary
	report.Status = ppskLifecycleStatus(report)
	report.SoftwareCompletionPercent = ppskLifecycleCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = ppskLifecycleMessage(report)
	report.PlanFingerprint = ppskLifecycleFingerprint(report)
	return report, nil
}

func PreviewAndRecordPPSKLifecycle(cfg *config.Config, actor string) (PPSKLifecycleReport, string, error) {
	report, err := PreviewPPSKLifecycle(cfg)
	if err != nil {
		return PPSKLifecycleReport{}, "", err
	}
	eventID, err := recordPPSKLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyPPSKLifecycle(cfg *config.Config, actor string) (PPSKLifecycleReport, string, error) {
	report, err := PreviewPPSKLifecycle(cfg)
	if err != nil {
		return PPSKLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordPPSKLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		return report, eventID, fmt.Errorf("PPSK lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		if _, err := wireless.WritePPSKFile(cfg); err != nil {
			report.Status = "failed"
			report.Message = "NAS-0077 hostapd PPSK file apply failed: " + err.Error()
			report.Blockers = append(report.Blockers, err.Error())
			report.SoftwareCompletionPercent = 0
			report.ReadyForExternalValidation = false
			eventID, recordErr := recordPPSKLifecycleEvent(report, "apply", actor)
			if recordErr != nil {
				return report, eventID, recordErr
			}
			return report, eventID, err
		}
		if _, err := wireless.WriteConfig(cfg); err != nil {
			report.Status = "failed"
			report.Message = "NAS-0077 hostapd PPSK config apply failed: " + err.Error()
			report.Blockers = append(report.Blockers, err.Error())
			report.SoftwareCompletionPercent = 0
			report.ReadyForExternalValidation = false
			eventID, recordErr := recordPPSKLifecycleEvent(report, "apply", actor)
			if recordErr != nil {
				return report, eventID, recordErr
			}
			return report, eventID, err
		}
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0077 applied hostapd PPSK configuration for %d SSID(s) and %d active credential(s).", report.Summary.PPSKSSIDCount, report.Summary.ActiveCredentialCount)
	}
	eventID, err := recordPPSKLifecycleEvent(report, "apply", actor)
	return report, eventID, err
}

func recordPPSKLifecycleEvent(report PPSKLifecycleReport, operation, actor string) (string, error) {
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
	return db.RecordPPSKLifecycleEvent(db.PPSKLifecycleEventInput{
		Operation:              operation,
		Status:                 status,
		ConfigPath:             report.HostapdConfigPath,
		PSKFilePath:            report.PSKFilePath,
		HostapdConfigSHA256:    report.HostapdConfigSHA256,
		PSKFileSHA256:          report.PSKFileSHA256,
		PlanFingerprint:        report.PlanFingerprint,
		SSIDCount:              report.Summary.SSIDCount,
		PPSKSSIDCount:          report.Summary.PPSKSSIDCount,
		ProfileCount:           report.Summary.ProfileCount,
		GroupCount:             report.Summary.GroupCount,
		CredentialCount:        report.Summary.CredentialCount,
		ActiveCredentialCount:  report.Summary.ActiveCredentialCount,
		StagedCredentialCount:  report.Summary.StagedCredentialCount,
		RevokedCredentialCount: report.Summary.RevokedCredentialCount,
		ExpiredCredentialCount: report.Summary.ExpiredCredentialCount,
		ControllerSyncCount:    report.Summary.ControllerSyncCount,
		DiagnosticCount:        report.Summary.DiagnosticCount,
		SummaryJSON:            marshalJSON(report.Summary),
		ReportJSON:             marshalJSON(report),
		Actor:                  actor,
	})
}

func buildPPSKSSIDReport(ssid config.SSIDConfig, effective config.EffectiveWirelessPPSKProfile) PPSKSSIDReport {
	return PPSKSSIDReport{
		SSID:             ssid.Name,
		AuthMode:         ssid.AuthMode,
		ProfileName:      effective.ProfileName,
		Status:           "ready",
		Mode:             effective.Mode,
		FailClosed:       effective.FailClosed,
		PSKFilePath:      effective.PSKFilePath,
		CredentialCount:  len(effective.Credentials),
		GroupCount:       len(effective.Groups),
		DefaultVLAN:      effective.DefaultVLAN,
		Role:             effective.Role,
		BandwidthProfile: effective.BandwidthProfile,
		ControllerSync:   effective.ControllerSync,
		RadiusAttributes: []string{"Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "Class", "Filter-Id", "Tunnel-Private-Group-Id", "Acct-Session-Id"},
	}
}

func buildPPSKProfileReports(profiles []config.WirelessPPSKProfileConfig) []PPSKProfileReport {
	reports := make([]PPSKProfileReport, 0, len(profiles))
	for _, profile := range profiles {
		reports = append(reports, PPSKProfileReport{
			Name:             strings.TrimSpace(profile.Name),
			Enabled:          profile.Enabled,
			Description:      strings.TrimSpace(profile.Description),
			Mode:             strings.TrimSpace(profile.Mode),
			FailClosed:       profile.FailClosed,
			GroupNames:       append([]string(nil), profile.Groups...),
			DefaultVLAN:      profile.DefaultVLAN,
			Role:             strings.TrimSpace(profile.Role),
			BandwidthProfile: strings.TrimSpace(profile.BandwidthProfile),
			MaxDevices:       profile.MaxDevices,
			ControllerSync:   profile.ControllerSync,
		})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}

func buildPPSKGroupReports(groups []config.WirelessPPSKGroupConfig) []PPSKGroupReport {
	reports := make([]PPSKGroupReport, 0, len(groups))
	for _, group := range groups {
		reports = append(reports, PPSKGroupReport{
			Name:             strings.TrimSpace(group.Name),
			Enabled:          group.Enabled,
			Description:      strings.TrimSpace(group.Description),
			VLAN:             group.VLAN,
			Role:             strings.TrimSpace(group.Role),
			BandwidthProfile: strings.TrimSpace(group.BandwidthProfile),
			MaxDevices:       group.MaxDevices,
			SessionLimit:     group.SessionLimit,
		})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}

func buildPPSKCredentialReport(credential config.WirelessPPSKCredentialConfig, now time.Time) PPSKCredentialReport {
	report := PPSKCredentialReport{
		ID:                    strings.TrimSpace(credential.ID),
		MAC:                   strings.ToLower(strings.TrimSpace(credential.MAC)),
		DeviceID:              strings.TrimSpace(credential.DeviceID),
		Owner:                 strings.TrimSpace(credential.Owner),
		Profile:               strings.TrimSpace(credential.Profile),
		Group:                 strings.TrimSpace(credential.Group),
		Enabled:               credential.Enabled,
		Revoked:               credential.Revoked,
		SecretRefSet:          strings.TrimSpace(credential.SecretRef) != "",
		SecretRefFingerprint:  fingerprintSecretRef(credential.SecretRef),
		NextSecretRefSet:      strings.TrimSpace(credential.NextSecretRef) != "",
		NextSecretFingerprint: fingerprintSecretRef(credential.NextSecretRef),
		NextNotBefore:         strings.TrimSpace(credential.NextNotBefore),
		NextNotAfter:          strings.TrimSpace(credential.NextNotAfter),
		VLAN:                  credential.VLAN,
		Role:                  strings.TrimSpace(credential.Role),
		BandwidthProfile:      strings.TrimSpace(credential.BandwidthProfile),
		ExpiresAt:             strings.TrimSpace(credential.ExpiresAt),
		Status:                "ready",
	}
	if report.ExpiresAt != "" {
		if expiresAt, err := time.Parse(time.RFC3339, report.ExpiresAt); err == nil && !expiresAt.After(now) {
			report.Expired = true
			report.Status = "expired"
			report.Diagnostics = append(report.Diagnostics, "credential expiry is in the past")
		}
	}
	if credential.Revoked {
		report.Status = "revoked"
	}
	if !credential.Enabled {
		report.Status = "disabled"
	}
	return report
}

func ppskLifecycleStatus(report PPSKLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.WirelessEnabled || !report.Summary.PPSKEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func ppskLifecycleCompletion(report PPSKLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func ppskLifecycleMessage(report PPSKLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0077 software is ready; DPSK/PPSK is not active in this configuration."
	case "blocked":
		return "NAS-0077 DPSK/PPSK lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0077 plans %d PPSK SSID(s) with warnings; review controller sync and external certification scope.", report.Summary.PPSKSSIDCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0077 plans %d PPSK SSID(s), %d active credential(s), %d group(s), and %d staged credential(s).",
			report.Summary.PPSKSSIDCount,
			report.Summary.ActiveCredentialCount,
			report.Summary.GroupCount,
			report.Summary.StagedCredentialCount,
		)
	}
}

func ppskLifecycleFingerprint(report PPSKLifecycleReport) string {
	payload := struct {
		FeatureID           string
		HostapdConfigSHA256 string
		PSKFileSHA256       string
		Summary             PPSKLifecycleSummary
		SSIDs               []PPSKSSIDReport
		Profiles            []PPSKProfileReport
		Groups              []PPSKGroupReport
		Credentials         []PPSKCredentialReport
	}{
		FeatureID:           report.FeatureID,
		HostapdConfigSHA256: report.HostapdConfigSHA256,
		PSKFileSHA256:       report.PSKFileSHA256,
		Summary:             report.Summary,
		SSIDs:               report.SSIDs,
		Profiles:            report.Profiles,
		Groups:              report.Groups,
		Credentials:         report.Credentials,
	}
	return sha256JSON(payload)
}

func redactPPSKFilePreview(text string) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			lines[i] = fields[0] + " <redacted>"
		}
	}
	return strings.Join(lines, "\n")
}

func fingerprintSecretRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ref))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func ppskCredentialLabel(credential config.WirelessPPSKCredentialConfig) string {
	if strings.TrimSpace(credential.ID) != "" {
		return strings.TrimSpace(credential.ID)
	}
	return strings.TrimSpace(credential.MAC)
}

func ppskCredentialReportKey(report PPSKCredentialReport) string {
	return strings.Join([]string{report.Profile, report.Group, report.MAC, report.ID}, "\x00")
}
