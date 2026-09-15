package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

const (
	PasspointLifecycleSchemaVersion = 1
	PasspointLifecycleFeatureID     = "NAS-0076"
)

type PasspointLifecycleReport struct {
	SchemaVersion                 int                       `json:"schema_version"`
	FeatureID                     string                    `json:"feature_id"`
	Status                        string                    `json:"status"`
	Message                       string                    `json:"message"`
	GeneratedAt                   string                    `json:"generated_at"`
	SoftwareCompletionPercent     float64                   `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                      `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                    `json:"release_certification_checklist"`
	ReleaseScope                  string                    `json:"release_scope"`
	PlanFingerprint               string                    `json:"plan_fingerprint"`
	HostapdConfigPath             string                    `json:"hostapd_config_path,omitempty"`
	HostapdConfigSHA256           string                    `json:"hostapd_config_sha256,omitempty"`
	HostapdConfigPreview          string                    `json:"hostapd_config_preview,omitempty"`
	Summary                       PasspointLifecycleSummary `json:"summary"`
	SSIDs                         []PasspointSSIDReport     `json:"ssids"`
	Profiles                      []PasspointProfileReport  `json:"profiles"`
	RFCs                          []string                  `json:"rfcs"`
	Attributes                    []string                  `json:"attributes"`
	Vendors                       []string                  `json:"vendors"`
	Requirements                  []string                  `json:"requirements"`
	Blockers                      []string                  `json:"blockers,omitempty"`
	Warnings                      []string                  `json:"warnings,omitempty"`
	Notes                         []string                  `json:"notes,omitempty"`
}

type PasspointLifecycleSummary struct {
	WirelessEnabled           bool `json:"wireless_enabled"`
	PasspointEnabled          bool `json:"passpoint_enabled"`
	SSIDCount                 int  `json:"ssid_count"`
	PasspointSSIDCount        int  `json:"passpoint_ssid_count"`
	InterworkingSSIDCount     int  `json:"interworking_ssid_count"`
	HS20SSIDCount             int  `json:"hs20_ssid_count"`
	ProfileCount              int  `json:"profile_count"`
	OSUProviderCount          int  `json:"osu_provider_count"`
	DomainNameCount           int  `json:"domain_name_count"`
	RoamingConsortiumCount    int  `json:"roaming_consortium_count"`
	NAIRealmCount             int  `json:"nai_realm_count"`
	CellularNetworkCount      int  `json:"cellular_network_count"`
	ConnectionCapabilityCount int  `json:"connection_capability_count"`
	DiagnosticCount           int  `json:"diagnostic_count"`
	ExternalRequirementCount  int  `json:"external_requirement_count"`
}

type PasspointSSIDReport struct {
	SSID                      string                                          `json:"ssid"`
	AuthMode                  string                                          `json:"auth_mode"`
	ProfileName               string                                          `json:"profile_name"`
	Status                    string                                          `json:"status"`
	Mode                      string                                          `json:"mode"`
	FailClosed                bool                                            `json:"fail_closed"`
	Interworking              bool                                            `json:"interworking"`
	HS20                      bool                                            `json:"hs20"`
	AccessNetworkType         int                                             `json:"access_network_type"`
	Internet                  bool                                            `json:"internet"`
	ASRA                      bool                                            `json:"asra"`
	ESR                       bool                                            `json:"esr"`
	UESA                      bool                                            `json:"uesa"`
	VenueGroup                int                                             `json:"venue_group,omitempty"`
	VenueType                 int                                             `json:"venue_type,omitempty"`
	HESSID                    string                                          `json:"hessid,omitempty"`
	DisableDGAF               bool                                            `json:"disable_dgaf"`
	ProxyARP                  bool                                            `json:"proxy_arp"`
	DomainNames               []string                                        `json:"domain_names,omitempty"`
	RoamingConsortiumOIs      []string                                        `json:"roaming_consortium_ois,omitempty"`
	OperatorFriendlyNames     []config.WirelessLocalizedTextConfig            `json:"operator_friendly_names,omitempty"`
	VenueNames                []config.WirelessLocalizedTextConfig            `json:"venue_names,omitempty"`
	NAIRealms                 []PasspointNAIRealmReport                       `json:"nai_realms,omitempty"`
	CellularNetworks          []config.WirelessPasspointCellularNetworkConfig `json:"cellular_networks,omitempty"`
	WANMetricsEnabled         bool                                            `json:"wan_metrics_enabled"`
	ConnectionCapabilityCount int                                             `json:"connection_capability_count"`
	OSUEnabled                bool                                            `json:"osu_enabled"`
	OSUSSID                   string                                          `json:"osu_ssid,omitempty"`
	OSUServerURI              string                                          `json:"osu_server_uri,omitempty"`
	RadiusCorrelationFields   []string                                        `json:"radius_correlation_fields"`
	Diagnostics               []string                                        `json:"diagnostics,omitempty"`
}

type PasspointNAIRealmReport struct {
	Realm      string   `json:"realm"`
	Encoding   int      `json:"encoding"`
	EAPMethods []string `json:"eap_methods,omitempty"`
	AuthParams []string `json:"auth_params,omitempty"`
}

type PasspointProfileReport struct {
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	Description          string `json:"description,omitempty"`
	Interworking         bool   `json:"interworking"`
	HS20                 bool   `json:"hs20"`
	DomainNameCount      int    `json:"domain_name_count"`
	RoamingOICount       int    `json:"roaming_oi_count"`
	NAIRealmCount        int    `json:"nai_realm_count"`
	CellularNetworkCount int    `json:"cellular_network_count"`
	OSUEnabled           bool   `json:"osu_enabled"`
}

func PreviewPasspointLifecycle(cfg *config.Config) (PasspointLifecycleReport, error) {
	if cfg == nil {
		return PasspointLifecycleReport{}, fmt.Errorf("config is required")
	}
	report := PasspointLifecycleReport{
		SchemaVersion:                 PasspointLifecycleSchemaVersion,
		FeatureID:                     PasspointLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0076-release-certification-checklist.md",
		ReleaseScope:                  "Real AP/client Passpoint certification, carrier roaming agreement proof, packet captures, HA failover, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		HostapdConfigPath:             strings.TrimSpace(cfg.Wireless.HostapdConfigPath),
		RFCs:                          []string{"IEEE 802.11u", "IEEE 802.1X", "RFC 2865", "RFC 2866", "RFC 3748", "RFC 4186", "RFC 4187", "RFC 5448", "RFC 5176"},
		Attributes:                    []string{"EAP-Message", "Message-Authenticator", "Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "NAS-IP-Address", "Acct-Session-Id", "Acct-Multi-Session-Id", "Class", "Operator-Name", "Chargeable-User-Identity", "Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "WISPr-Location-ID", "WISPr-Location-Name"},
		Vendors:                       []string{"Cisco", "Aruba", "Ruckus", "Extreme", "Meraki", "UniFi", "Juniper Mist", "Fortinet", "Cambium", "Nomadix", "ChilliSpot", "WISPr", "OpenWiFi", "hostapd"},
		Requirements: []string{
			"ANQP Interworking data is rendered only after domain, realm, venue, OI, and PLMN validation",
			"Hotspot 2.0 Release 2 metadata covers operator names, DGAF policy, Proxy ARP, WAN metrics, connection capabilities, and OSU provider hints",
			"Passpoint profiles can be assigned per SSID or selected as a global default profile",
			"Enforce fail-closed mode requires domain_name, nai_realm, and HS2.0 operator_friendly_names before apply",
			"RADIUS/EAP/Accounting/CoA fields needed for roaming identity, CUI, VLAN, and session correlation are declared in the report",
			"Passpoint lifecycle preview/apply/status/history is auditable and backward compatible",
		},
		Notes: []string{
			"NAS-0076 completes software handling for local hostapd Passpoint and Hotspot 2.0 intent.",
			"Online signup server business process, roaming settlement, and real AP/client Wi-Fi Alliance certification remain external release validation work.",
		},
	}
	summary := PasspointLifecycleSummary{
		WirelessEnabled:          cfg.Wireless.Enabled,
		PasspointEnabled:         cfg.Wireless.Passpoint.Enabled,
		SSIDCount:                len(cfg.Wireless.SSIDs),
		ProfileCount:             len(cfg.Wireless.Passpoint.Profiles),
		ExternalRequirementCount: 9,
	}
	report.Profiles = buildPasspointProfileReports(cfg.Wireless.Passpoint.Profiles)

	if !cfg.Wireless.Enabled || !cfg.Wireless.Passpoint.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0076 software is ready; Passpoint and Hotspot 2.0 are not active in this configuration."
		report.Summary = summary
		report.PlanFingerprint = passpointLifecycleFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Status = "blocked"
		report.Blockers = append(report.Blockers, err.Error())
		report.Summary = summary
		report.Summary.DiagnosticCount = len(report.Blockers)
		report.SoftwareCompletionPercent = 0
		report.ReadyForExternalValidation = false
		report.Message = "NAS-0076 Passpoint lifecycle is blocked by invalid configuration."
		report.PlanFingerprint = passpointLifecycleFingerprint(report)
		return report, nil
	}

	for _, ssid := range cfg.Wireless.SSIDs {
		effective, active := config.EffectiveSSIDPasspointProfile(cfg.Wireless, ssid)
		if !active {
			continue
		}
		ssidReport := buildPasspointSSIDReport(ssid, effective)
		if (ssid.AuthMode == "open" || ssid.AuthMode == "captive-portal") && !effective.OSU.Enabled {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s uses Passpoint discovery on open/captive SSID without OSU metadata", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "open or captive-portal Passpoint SSIDs should publish OSU metadata before external validation")
		}
		if strings.Contains(strings.ToLower(ssid.AuthMode), "enterprise") && len(effective.NAIRealms) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s uses enterprise Passpoint without NAI realm discovery", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "enterprise Passpoint clients need at least one NAI realm for automatic provider selection")
		}
		if effective.HS20 && len(effective.OperatorFriendlyNames) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s enables HS2.0 without operator friendly name", ssid.Name))
			ssidReport.Diagnostics = append(ssidReport.Diagnostics, "HS2.0 clients should receive at least one operator friendly name")
		}
		summary.PasspointSSIDCount++
		if effective.Interworking {
			summary.InterworkingSSIDCount++
		}
		if effective.HS20 {
			summary.HS20SSIDCount++
		}
		if effective.OSU.Enabled {
			summary.OSUProviderCount++
		}
		summary.DomainNameCount += len(effective.DomainNames)
		summary.RoamingConsortiumCount += len(effective.RoamingConsortiumOIs)
		summary.NAIRealmCount += len(effective.NAIRealms)
		summary.CellularNetworkCount += len(effective.CellularNetworks)
		summary.ConnectionCapabilityCount += len(effective.ConnectionCapabilities)
		report.SSIDs = append(report.SSIDs, ssidReport)
	}
	if summary.PasspointSSIDCount == 0 {
		report.Blockers = append(report.Blockers, "wireless.passpoint.enabled requires at least one SSID with active Passpoint profile")
	}
	hostapdConfig, err := wireless.GenerateHostapdConfig(cfg)
	if err != nil {
		report.Blockers = append(report.Blockers, "hostapd Passpoint config render failed: "+err.Error())
	} else {
		sum := sha256.Sum256([]byte(hostapdConfig))
		report.HostapdConfigSHA256 = "sha256:" + hex.EncodeToString(sum[:])
		report.HostapdConfigPreview = redactHostapdConfigPreview(hostapdConfig)
	}
	summary.DiagnosticCount = len(report.Blockers) + len(report.Warnings)
	report.Summary = summary
	report.Status = passpointLifecycleStatus(report)
	report.SoftwareCompletionPercent = passpointLifecycleCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = passpointLifecycleMessage(report)
	report.PlanFingerprint = passpointLifecycleFingerprint(report)
	return report, nil
}

func PreviewAndRecordPasspointLifecycle(cfg *config.Config, actor string) (PasspointLifecycleReport, string, error) {
	report, err := PreviewPasspointLifecycle(cfg)
	if err != nil {
		return PasspointLifecycleReport{}, "", err
	}
	eventID, err := recordPasspointLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyPasspointLifecycle(cfg *config.Config, actor string) (PasspointLifecycleReport, string, error) {
	report, err := PreviewPasspointLifecycle(cfg)
	if err != nil {
		return PasspointLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordPasspointLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		return report, eventID, fmt.Errorf("Passpoint lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		if _, err := wireless.WriteConfig(cfg); err != nil {
			report.Status = "failed"
			report.Message = "NAS-0076 hostapd Passpoint config apply failed: " + err.Error()
			report.Blockers = append(report.Blockers, err.Error())
			report.SoftwareCompletionPercent = 0
			report.ReadyForExternalValidation = false
			eventID, recordErr := recordPasspointLifecycleEvent(report, "apply", actor)
			if recordErr != nil {
				return report, eventID, recordErr
			}
			return report, eventID, err
		}
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0076 applied hostapd Passpoint and Hotspot 2.0 configuration for %d SSID(s).", report.Summary.PasspointSSIDCount)
	}
	eventID, err := recordPasspointLifecycleEvent(report, "apply", actor)
	return report, eventID, err
}

func recordPasspointLifecycleEvent(report PasspointLifecycleReport, operation, actor string) (string, error) {
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
	return db.RecordPasspointLifecycleEvent(db.PasspointLifecycleEventInput{
		Operation:                 operation,
		Status:                    status,
		ConfigPath:                report.HostapdConfigPath,
		HostapdConfigSHA256:       report.HostapdConfigSHA256,
		PlanFingerprint:           report.PlanFingerprint,
		SSIDCount:                 report.Summary.SSIDCount,
		PasspointSSIDCount:        report.Summary.PasspointSSIDCount,
		InterworkingSSIDCount:     report.Summary.InterworkingSSIDCount,
		HS20SSIDCount:             report.Summary.HS20SSIDCount,
		OSUProviderCount:          report.Summary.OSUProviderCount,
		DomainNameCount:           report.Summary.DomainNameCount,
		RoamingConsortiumCount:    report.Summary.RoamingConsortiumCount,
		NAIRealmCount:             report.Summary.NAIRealmCount,
		CellularNetworkCount:      report.Summary.CellularNetworkCount,
		ConnectionCapabilityCount: report.Summary.ConnectionCapabilityCount,
		DiagnosticCount:           report.Summary.DiagnosticCount,
		SummaryJSON:               marshalJSON(report.Summary),
		ReportJSON:                marshalJSON(report),
		Actor:                     actor,
	})
}

func buildPasspointSSIDReport(ssid config.SSIDConfig, effective config.EffectiveWirelessPasspointProfile) PasspointSSIDReport {
	report := PasspointSSIDReport{
		SSID:                      ssid.Name,
		AuthMode:                  ssid.AuthMode,
		ProfileName:               effective.ProfileName,
		Status:                    "ready",
		Mode:                      effective.Mode,
		FailClosed:                effective.FailClosed,
		Interworking:              effective.Interworking,
		HS20:                      effective.HS20,
		AccessNetworkType:         effective.AccessNetworkType,
		Internet:                  effective.Internet,
		ASRA:                      effective.ASRA,
		ESR:                       effective.ESR,
		UESA:                      effective.UESA,
		VenueGroup:                effective.VenueGroup,
		VenueType:                 effective.VenueType,
		HESSID:                    effective.HESSID,
		DisableDGAF:               effective.DisableDGAF,
		ProxyARP:                  effective.ProxyARP,
		DomainNames:               append([]string(nil), effective.DomainNames...),
		RoamingConsortiumOIs:      append([]string(nil), effective.RoamingConsortiumOIs...),
		OperatorFriendlyNames:     append([]config.WirelessLocalizedTextConfig(nil), effective.OperatorFriendlyNames...),
		VenueNames:                append([]config.WirelessLocalizedTextConfig(nil), effective.VenueNames...),
		CellularNetworks:          append([]config.WirelessPasspointCellularNetworkConfig(nil), effective.CellularNetworks...),
		WANMetricsEnabled:         effective.WANMetrics.Enabled,
		ConnectionCapabilityCount: len(effective.ConnectionCapabilities),
		OSUEnabled:                effective.OSU.Enabled,
		OSUSSID:                   effective.OSU.SSID,
		OSUServerURI:              effective.OSU.ServerURI,
		RadiusCorrelationFields:   []string{"Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "Operator-Name", "Chargeable-User-Identity", "Class", "Acct-Session-Id", "Acct-Multi-Session-Id", "Event-Timestamp"},
	}
	for _, realm := range effective.NAIRealms {
		report.NAIRealms = append(report.NAIRealms, PasspointNAIRealmReport{
			Realm:      realm.Realm,
			Encoding:   realm.Encoding,
			EAPMethods: append([]string(nil), realm.EAPMethods...),
			AuthParams: append([]string(nil), realm.AuthParams...),
		})
	}
	sort.Strings(report.DomainNames)
	sort.Strings(report.RoamingConsortiumOIs)
	sort.Slice(report.NAIRealms, func(i, j int) bool { return report.NAIRealms[i].Realm < report.NAIRealms[j].Realm })
	sort.Slice(report.CellularNetworks, func(i, j int) bool {
		left := report.CellularNetworks[i].MCC + report.CellularNetworks[i].MNC
		right := report.CellularNetworks[j].MCC + report.CellularNetworks[j].MNC
		return left < right
	})
	return report
}

func buildPasspointProfileReports(profiles []config.WirelessPasspointProfileConfig) []PasspointProfileReport {
	reports := make([]PasspointProfileReport, 0, len(profiles))
	for _, profile := range profiles {
		reports = append(reports, PasspointProfileReport{
			Name:                 strings.TrimSpace(profile.Name),
			Enabled:              profile.Enabled,
			Description:          strings.TrimSpace(profile.Description),
			Interworking:         profile.Interworking,
			HS20:                 profile.HS20,
			DomainNameCount:      len(profile.DomainNames),
			RoamingOICount:       len(profile.RoamingConsortiumOIs),
			NAIRealmCount:        len(profile.NAIRealms),
			CellularNetworkCount: len(profile.CellularNetworks),
			OSUEnabled:           profile.OSU.Enabled,
		})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}

func passpointLifecycleStatus(report PasspointLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.WirelessEnabled || !report.Summary.PasspointEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func passpointLifecycleCompletion(report PasspointLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func passpointLifecycleMessage(report PasspointLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0076 software is ready; Passpoint and Hotspot 2.0 are not active in this configuration."
	case "blocked":
		return "NAS-0076 Passpoint lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0076 plans %d Passpoint SSID(s) with warnings; review OSU, realm, and operator metadata before release validation.", report.Summary.PasspointSSIDCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0076 plans %d Passpoint SSID(s), %d HS2.0 SSID(s), %d OSU provider(s), %d NAI realm(s), and %d roaming consortium OI(s).",
			report.Summary.PasspointSSIDCount,
			report.Summary.HS20SSIDCount,
			report.Summary.OSUProviderCount,
			report.Summary.NAIRealmCount,
			report.Summary.RoamingConsortiumCount,
		)
	}
}

func passpointLifecycleFingerprint(report PasspointLifecycleReport) string {
	payload := struct {
		FeatureID           string
		HostapdConfigSHA256 string
		Summary             PasspointLifecycleSummary
		SSIDs               []PasspointSSIDReport
		Profiles            []PasspointProfileReport
	}{
		FeatureID:           report.FeatureID,
		HostapdConfigSHA256: report.HostapdConfigSHA256,
		Summary:             report.Summary,
		SSIDs:               report.SSIDs,
		Profiles:            report.Profiles,
	}
	return sha256JSON(payload)
}
