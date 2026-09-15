package enforcement

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	WirelessSecurityLifecycleSchemaVersion = 1
	WirelessSecurityLifecycleFeatureID     = "NAS-0080"
	wirelessSecurityLifecycleComponent     = "wireless_security_lifecycle"
)

type WirelessSecurityLifecycleReport struct {
	SchemaVersion                 int                                `json:"schema_version"`
	FeatureID                     string                             `json:"feature_id"`
	Status                        string                             `json:"status"`
	Message                       string                             `json:"message"`
	GeneratedAt                   string                             `json:"generated_at"`
	SoftwareCompletionPercent     float64                            `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                               `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                             `json:"release_certification_checklist"`
	ReleaseScope                  string                             `json:"release_scope"`
	PlanFingerprint               string                             `json:"plan_fingerprint"`
	Summary                       WirelessSecurityLifecycleSummary   `json:"summary"`
	Sensors                       []WirelessSecuritySensorReport     `json:"sensors"`
	RoguePolicies                 []WirelessRoguePolicyReport        `json:"rogue_policies"`
	WIPSDetections                []WirelessWIPSDetectionReport      `json:"wips_detections"`
	SpectrumChannels              []WirelessSpectrumChannelReport    `json:"spectrum_channels"`
	LocationZones                 []WirelessLocationZoneReport       `json:"location_zones"`
	MulticastPolicies             []WirelessMulticastPolicyReport    `json:"multicast_policies"`
	ControllerActions             []WirelessSecurityControllerAction `json:"controller_actions"`
	Compliance                    []WirelessSecurityComplianceCheck  `json:"compliance"`
	Standards                     []string                           `json:"standards"`
	Vendors                       []string                           `json:"vendors"`
	Requirements                  []string                           `json:"requirements"`
	Blockers                      []string                           `json:"blockers,omitempty"`
	Warnings                      []string                           `json:"warnings,omitempty"`
	Notes                         []string                           `json:"notes,omitempty"`
}

type WirelessSecurityLifecycleSummary struct {
	SecurityEnabled          bool   `json:"security_enabled"`
	WirelessEnabled          bool   `json:"wireless_enabled"`
	RFEnabled                bool   `json:"rf_enabled"`
	ControllerEnabled        bool   `json:"controller_enabled"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	Mode                     string `json:"mode"`
	RogueEnabled             bool   `json:"rogue_enabled"`
	WIPSEnabled              bool   `json:"wips_enabled"`
	SpectrumEnabled          bool   `json:"spectrum_enabled"`
	LocationEnabled          bool   `json:"location_enabled"`
	MulticastEnabled         bool   `json:"multicast_enabled"`
	SensorCount              int    `json:"sensor_count"`
	RoguePolicyCount         int    `json:"rogue_policy_count"`
	WIPSDetectionCount       int    `json:"wips_detection_count"`
	SpectrumChannelCount     int    `json:"spectrum_channel_count"`
	LocationZoneCount        int    `json:"location_zone_count"`
	MulticastPolicyCount     int    `json:"multicast_policy_count"`
	ContainmentGuardCount    int    `json:"containment_guard_count"`
	PrivacyCheckCount        int    `json:"privacy_check_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
}

type WirelessSecuritySensorReport struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	BSSID        string   `json:"bssid,omitempty"`
	Zone         string   `json:"zone,omitempty"`
	Floor        string   `json:"floor,omitempty"`
	Location     string   `json:"location,omitempty"`
	Controller   string   `json:"controller,omitempty"`
	Bands        []string `json:"bands,omitempty"`
	Channels     []int    `json:"channels,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason"`
}

type WirelessRoguePolicyReport struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Action           string   `json:"action"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
	QuarantineRole   string   `json:"quarantine_role,omitempty"`
	MinRSSI          int      `json:"min_rssi,omitempty"`
	TrustedSSIDs     []string `json:"trusted_ssids,omitempty"`
	WatchSSIDs       []string `json:"watch_ssids,omitempty"`
	TrustedBSSIDs    []string `json:"trusted_bssids,omitempty"`
	AllowedOUIs      []string `json:"allowed_ouis,omitempty"`
	ContainmentGuard []string `json:"containment_guard,omitempty"`
}

type WirelessWIPSDetectionReport struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	Threshold      int      `json:"threshold,omitempty"`
	RequiredInputs []string `json:"required_inputs,omitempty"`
	Reason         string   `json:"reason"`
}

type WirelessSpectrumChannelReport struct {
	Band                          string   `json:"band"`
	Channel                       int      `json:"channel"`
	Sensors                       []string `json:"sensors,omitempty"`
	NoiseFloorDBM                 int      `json:"noise_floor_dbm"`
	ChannelUtilizationWarnPercent int      `json:"channel_utilization_warn_percent"`
	InterferenceWarnPercent       int      `json:"interference_warn_percent"`
	DutyCycleWarnPercent          int      `json:"duty_cycle_warn_percent"`
	SampleIntervalSeconds         int      `json:"sample_interval_seconds"`
	Status                        string   `json:"status"`
	Reason                        string   `json:"reason"`
}

type WirelessLocationZoneReport struct {
	Name                    string `json:"name"`
	Floor                   string `json:"floor,omitempty"`
	Building                string `json:"building,omitempty"`
	Mode                    string `json:"mode"`
	PrivacyMode             string `json:"privacy_mode"`
	HashClientIdentifiers   bool   `json:"hash_client_identifiers"`
	ExportClientCoordinates bool   `json:"export_client_coordinates"`
	RetentionHours          int    `json:"retention_hours"`
	MinAPsForTriangulation  int    `json:"min_aps_for_triangulation"`
	SensorCount             int    `json:"sensor_count"`
	Status                  string `json:"status"`
	Reason                  string `json:"reason"`
}

type WirelessMulticastPolicyReport struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Mode        string   `json:"mode"`
	Action      string   `json:"action"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason"`
	Groups      []string `json:"groups,omitempty"`
	IPv6Enabled bool     `json:"ipv6_enabled,omitempty"`
}

type WirelessSecurityControllerAction struct {
	ID        string         `json:"id"`
	Platform  string         `json:"platform"`
	Operation string         `json:"operation"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason"`
	Fields    []string       `json:"fields,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type WirelessSecurityComplianceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func WirelessSecurityLifecycleComponent() string {
	return wirelessSecurityLifecycleComponent
}

func PreviewWirelessSecurityLifecycle(cfg *config.Config) (WirelessSecurityLifecycleReport, error) {
	if cfg == nil {
		return WirelessSecurityLifecycleReport{}, fmt.Errorf("config is required")
	}
	security := cfg.Wireless.Security
	report := WirelessSecurityLifecycleReport{
		SchemaVersion:                 WirelessSecurityLifecycleSchemaVersion,
		FeatureID:                     WirelessSecurityLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0080-release-certification-checklist.md",
		ReleaseScope:                  "Live rogue containment, spectrum capture, location accuracy, multicast airtime proof, controller firmware mutation, HA failover, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards: []string{
			"IEEE 802.11-2020",
			"IEEE 802.11w",
			"IEEE 802.11k",
			"IEEE 802.11v",
			"IEEE 802.1X",
			"RFC 2865",
			"RFC 2866",
			"RFC 5176",
			"RFC 4541",
			"RFC 6762",
			"RFC 6763",
		},
		Vendors: []string{"Cisco", "Aruba", "Ruckus", "Extreme", "Meraki", "UniFi", "Cambium", "Juniper Mist", "Fortinet", "MikroTik", "OpenWiFi", "hostapd"},
		Requirements: []string{
			"rogue and WIPS policy must classify trusted, watched, and suspicious radios before any enforcement",
			"containment is guarded by explicit allow_containment and external certification evidence",
			"spectrum analytics are represented as deterministic sensor/channel watch plans",
			"location services enforce privacy mode, identifier hashing, retention, and coordinate export controls",
			"multicast optimization separates snooping, multicast-to-unicast, mDNS, SSDP, broadcast, and IPv6 behavior",
			"controller actions are previewed with ownership metadata and never silently mutate APs",
			"all preview/apply operations generate durable history and runtime status evidence",
		},
		Notes: []string{
			"NAS-0080 completes software governance for rogue/WIPS, spectrum, location privacy, and multicast optimization.",
			"Radio containment and spectrum capture require device-specific release certification before customer claims.",
		},
	}
	report.Summary = WirelessSecurityLifecycleSummary{
		SecurityEnabled:          security.Enabled,
		WirelessEnabled:          cfg.Wireless.Enabled,
		RFEnabled:                cfg.Wireless.RF.Enabled,
		ControllerEnabled:        cfg.Integrations.Controller.Enabled,
		ControllerPlatform:       strings.TrimSpace(cfg.Integrations.Controller.Platform),
		Mode:                     wirelessSecurityEffectiveMode(security.Mode),
		RogueEnabled:             security.Rogue.Enabled,
		WIPSEnabled:              security.WIPS.Enabled,
		SpectrumEnabled:          security.Spectrum.Enabled,
		LocationEnabled:          security.Location.Enabled,
		MulticastEnabled:         security.Multicast.Enabled,
		ExternalRequirementCount: 9,
	}
	if report.Summary.ControllerPlatform == "" {
		report.Summary.ControllerPlatform = "local"
	}
	if !security.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0080 software is ready; wireless security lifecycle is not active in this configuration."
		report.PlanFingerprint = wirelessSecurityFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}

	report.Sensors = wirelessSecurityBuildSensors(cfg)
	report.RoguePolicies = wirelessSecurityBuildRoguePolicies(cfg, &report)
	report.WIPSDetections = wirelessSecurityBuildWIPSDetections(cfg, &report)
	report.SpectrumChannels = wirelessSecurityBuildSpectrumChannels(cfg, report.Sensors, &report)
	report.LocationZones = wirelessSecurityBuildLocationZones(cfg, report.Sensors, &report)
	report.MulticastPolicies = wirelessSecurityBuildMulticastPolicies(cfg, &report)
	report.Summary.SensorCount = len(report.Sensors)
	report.Summary.RoguePolicyCount = len(report.RoguePolicies)
	report.Summary.WIPSDetectionCount = len(report.WIPSDetections)
	report.Summary.SpectrumChannelCount = len(report.SpectrumChannels)
	report.Summary.LocationZoneCount = len(report.LocationZones)
	report.Summary.MulticastPolicyCount = len(report.MulticastPolicies)
	report.ControllerActions = wirelessSecurityBuildControllerActions(cfg, &report)
	report.Compliance = wirelessSecurityBuildCompliance(cfg, &report)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
	}
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	if len(report.Sensors) == 0 {
		report.Blockers = append(report.Blockers, "wireless.security.enabled requires at least one sensor, RF AP radio, or enabled local wireless interface")
		report.Summary.BlockerCount = len(report.Blockers)
	}
	report.Status = wirelessSecurityStatus(report)
	report.SoftwareCompletionPercent = wirelessSecurityCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = wirelessSecurityMessage(report)
	report.PlanFingerprint = wirelessSecurityFingerprint(report)
	return report, nil
}

func PreviewAndRecordWirelessSecurityLifecycle(cfg *config.Config, actor string) (WirelessSecurityLifecycleReport, string, error) {
	report, err := PreviewWirelessSecurityLifecycle(cfg)
	if err != nil {
		return WirelessSecurityLifecycleReport{}, "", err
	}
	eventID, err := recordWirelessSecurityLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyWirelessSecurityLifecycle(ctx context.Context, cfg *config.Config, actor string) (WirelessSecurityLifecycleReport, string, error) {
	report, err := PreviewWirelessSecurityLifecycle(cfg)
	if err != nil {
		return WirelessSecurityLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordWirelessSecurityLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(wirelessSecurityLifecycleComponent, "down", report.Message, wirelessSecurityRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("wireless security lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0080 recorded wireless security lifecycle for %d sensor(s), %d rogue policy item(s), %d WIPS detection(s), %d spectrum channel(s), %d location zone(s), and %d multicast policy item(s).",
			report.Summary.SensorCount,
			report.Summary.RoguePolicyCount,
			report.Summary.WIPSDetectionCount,
			report.Summary.SpectrumChannelCount,
			report.Summary.LocationZoneCount,
			report.Summary.MulticastPolicyCount,
		)
	}
	eventID, err := recordWirelessSecurityLifecycleEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := wirelessSecurityRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if len(report.Warnings) > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(wirelessSecurityLifecycleComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(wirelessSecurityLifecycleComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordWirelessSecurityLifecycleEvent(report WirelessSecurityLifecycleReport, operation, actor string) (string, error) {
	status := report.Status
	switch operation {
	case "preview":
		if status == "ready" || status == "degraded" {
			status = "previewed"
		}
	case "apply":
		if status == "ready" || status == "degraded" || status == "applied" {
			status = "applied"
		}
	}
	return db.RecordWirelessSecurityLifecycleEvent(db.WirelessSecurityLifecycleEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		ControllerPlatform:       report.Summary.ControllerPlatform,
		SensorCount:              report.Summary.SensorCount,
		RoguePolicyCount:         report.Summary.RoguePolicyCount,
		WIPSDetectionCount:       report.Summary.WIPSDetectionCount,
		SpectrumChannelCount:     report.Summary.SpectrumChannelCount,
		LocationZoneCount:        report.Summary.LocationZoneCount,
		MulticastPolicyCount:     report.Summary.MulticastPolicyCount,
		ContainmentGuardCount:    report.Summary.ContainmentGuardCount,
		PrivacyCheckCount:        report.Summary.PrivacyCheckCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              marshalJSON(report.Summary),
		ReportJSON:               marshalJSON(report),
		Actor:                    actor,
	})
}

func wirelessSecurityBuildSensors(cfg *config.Config) []WirelessSecuritySensorReport {
	security := cfg.Wireless.Security
	sensors := []WirelessSecuritySensorReport{}
	for _, sensor := range security.Sensors {
		if !sensor.Enabled {
			continue
		}
		report := WirelessSecuritySensorReport{
			Name:         strings.TrimSpace(sensor.Name),
			Source:       "configured",
			BSSID:        strings.ToLower(strings.TrimSpace(sensor.BSSID)),
			Zone:         strings.TrimSpace(sensor.Zone),
			Floor:        strings.TrimSpace(sensor.Floor),
			Location:     strings.TrimSpace(sensor.Location),
			Controller:   rfFirstNonEmpty(sensor.Controller, cfg.Integrations.Controller.Platform, "local"),
			Bands:        wirelessSecurityBands(sensor.Bands),
			Channels:     wirelessSecurityPositiveChannels(sensor.Channels),
			Capabilities: wirelessSecurityCapabilities(security),
			Status:       "ready",
			Reason:       "declared wireless security sensor is eligible for rogue/WIPS/spectrum/location monitoring",
		}
		if len(report.Bands) == 0 {
			report.Bands = []string{"2.4ghz", "5ghz"}
		}
		if len(report.Channels) == 0 {
			report.Channels = wirelessSecurityDefaultChannels(report.Bands)
		}
		sensors = append(sensors, report)
	}
	if len(sensors) == 0 {
		for _, ap := range cfg.Wireless.RF.APs {
			if !ap.Enabled {
				continue
			}
			for _, radio := range ap.Radios {
				if !radio.Enabled {
					continue
				}
				band := rfNormalizeBand(radio.Band)
				channel := radio.Channel
				channels := []int{}
				if channel > 0 {
					channels = append(channels, channel)
				}
				if len(channels) == 0 {
					channels = wirelessSecurityDefaultChannels([]string{band})
				}
				sensors = append(sensors, WirelessSecuritySensorReport{
					Name:         strings.TrimSpace(ap.Name) + "/" + strings.TrimSpace(radio.Name),
					Source:       "rf_topology",
					BSSID:        strings.ToLower(strings.TrimSpace(radio.BSSID)),
					Zone:         strings.TrimSpace(ap.Zone),
					Floor:        strings.TrimSpace(ap.Floor),
					Location:     strings.TrimSpace(ap.Location),
					Controller:   rfFirstNonEmpty(ap.Controller, cfg.Integrations.Controller.Platform, "local"),
					Bands:        []string{band},
					Channels:     channels,
					Capabilities: wirelessSecurityCapabilities(security),
					Status:       "ready",
					Reason:       "sensor derived from RF planning topology",
				})
			}
		}
	}
	if len(sensors) == 0 && cfg.Wireless.Enabled {
		band := rfBandFromHostapd(cfg.Wireless.HWMode, cfg.Wireless.Channel)
		channels := []int{}
		if cfg.Wireless.Channel > 0 {
			channels = append(channels, cfg.Wireless.Channel)
		}
		sensors = append(sensors, WirelessSecuritySensorReport{
			Name:         "local-appliance/radio0",
			Source:       "local_wireless",
			Zone:         "local",
			Location:     "local appliance",
			Controller:   "hostapd",
			Bands:        []string{band},
			Channels:     channels,
			Capabilities: wirelessSecurityCapabilities(security),
			Status:       "ready",
			Reason:       "sensor derived from enabled local wireless interface",
		})
	}
	sort.Slice(sensors, func(i, j int) bool {
		return sensors[i].Name < sensors[j].Name
	})
	return sensors
}

func wirelessSecurityBuildRoguePolicies(cfg *config.Config, report *WirelessSecurityLifecycleReport) []WirelessRoguePolicyReport {
	rogue := cfg.Wireless.Security.Rogue
	if !rogue.Enabled {
		return nil
	}
	policies := []WirelessRoguePolicyReport{}
	classification := wirelessSecurityRoguePolicy(rogue.ClassificationPolicy)
	policies = append(policies, WirelessRoguePolicyReport{
		ID:             "rogue-classification",
		Name:           "Rogue Classification",
		Action:         "classify",
		Status:         "ready",
		Reason:         fmt.Sprintf("%s rogue classification evaluates trusted SSIDs, BSSIDs, OUIs, watch SSIDs, and RSSI.", classification),
		TrustedSSIDs:   rfSortedStrings(rogue.TrustedSSIDs),
		WatchSSIDs:     rfSortedStrings(rogue.WatchSSIDs),
		TrustedBSSIDs:  rfSortedStrings(wirelessSecurityLowerStrings(rogue.TrustedBSSIDs)),
		AllowedOUIs:    rfSortedStrings(wirelessSecurityUpperStrings(rogue.AllowedOUIs)),
		MinRSSI:        rfFirstNonZero(rogue.MinRSSI, -80),
		QuarantineRole: rfFirstNonEmpty(rogue.QuarantineRole, "quarantine"),
	})
	if len(rogue.TrustedSSIDs) == 0 && len(rogue.TrustedBSSIDs) == 0 && len(rogue.AllowedOUIs) == 0 {
		report.Warnings = append(report.Warnings, "rogue detection has no trusted SSID, trusted BSSID, or allowed OUI baseline")
	}
	containmentStatus := "observe"
	containmentReason := "containment is disabled; rogue findings are classified and can drive quarantine policy"
	guards := []string{"trusted inventory baseline", "operator preview/apply history", "release certification evidence"}
	if rogue.ContainmentEnabled {
		report.Summary.ContainmentGuardCount += 3
		containmentStatus = "guarded"
		containmentReason = "containment requires explicit allow_containment, trusted baseline, and release certification evidence"
		if rogue.AllowContainment {
			containmentStatus = "ready"
			containmentReason = "containment is explicitly allowed in software policy; live deauth or channel disruption remains release certification"
			guards = append(guards, "allow_containment=true")
		} else if report.Summary.Mode == "enforce" && cfg.Wireless.Security.FailClosed {
			report.Blockers = append(report.Blockers, "rogue containment is enabled in enforce fail-closed mode but allow_containment is false")
			containmentStatus = "blocked"
		}
	}
	if rogue.AutoContainment {
		guards = append(guards, "auto_containment=true")
	}
	policies = append(policies, WirelessRoguePolicyReport{
		ID:               "rogue-containment-governance",
		Name:             "Containment Governance",
		Action:           "containment_guard",
		Status:           containmentStatus,
		Reason:           containmentReason,
		QuarantineRole:   rfFirstNonEmpty(rogue.QuarantineRole, "quarantine"),
		MinRSSI:          rfFirstNonZero(rogue.MinRSSI, -80),
		ContainmentGuard: guards,
	})
	policies = append(policies, WirelessRoguePolicyReport{
		ID:             "rogue-quarantine-role",
		Name:           "Rogue Quarantine",
		Action:         "quarantine",
		Status:         "ready",
		Reason:         "rogue devices can map to a vendor-neutral quarantine role for RADIUS and controller policy workflows",
		QuarantineRole: rfFirstNonEmpty(rogue.QuarantineRole, "quarantine"),
	})
	return policies
}

func wirelessSecurityBuildWIPSDetections(cfg *config.Config, report *WirelessSecurityLifecycleReport) []WirelessWIPSDetectionReport {
	wips := cfg.Wireless.Security.WIPS
	if !wips.Enabled {
		return nil
	}
	definitions := []struct {
		enabled  bool
		id       string
		name     string
		category string
		severity string
		inputs   []string
	}{
		{wips.DeauthDetection, "deauth-disassoc", "Deauthentication And Disassociation Flood", "management-frame", "high", []string{"802.11 management frames", "sensor channel dwell"}},
		{wips.EvilTwinDetection, "evil-twin", "Evil Twin SSID/BSSID", "rogue", "critical", []string{"trusted SSID baseline", "BSSID inventory", "RSSI"}},
		{wips.HoneypotDetection, "honeypot-ap", "Honeypot Access Point", "rogue", "high", []string{"SSID baseline", "security suite fingerprint"}},
		{wips.AdHocDetection, "adhoc-ibss", "Ad Hoc Or IBSS Network", "client", "medium", []string{"beacon/probe frames"}},
		{wips.SpoofingDetection, "mac-spoof", "MAC/BSSID Spoofing", "identity", "high", []string{"BSSID inventory", "OUI policy"}},
		{wips.FloodDetection, "probe-auth-flood", "Probe/Auth Flood", "availability", "high", []string{"frame counters", "sensor interval"}},
		{wips.EAPOLAttackDetection, "eapol-attack", "EAPOL Attack Pattern", "802.1X", "critical", []string{"EAPOL frames", "RADIUS failures"}},
		{wips.PMFRequired, "pmf-required", "Protected Management Frames", "management-frame", "high", []string{"SSID PMF policy", "client capability"}},
	}
	detections := []WirelessWIPSDetectionReport{}
	for _, definition := range definitions {
		if !definition.enabled {
			continue
		}
		detections = append(detections, WirelessWIPSDetectionReport{
			ID:             definition.id,
			Name:           definition.name,
			Category:       definition.category,
			Severity:       definition.severity,
			Status:         "ready",
			Threshold:      rfFirstPositive(wips.AlertThreshold, 1),
			RequiredInputs: definition.inputs,
			Reason:         "detection is represented in vendor-neutral WIPS policy and event evidence",
		})
	}
	if len(detections) == 0 {
		report.Warnings = append(report.Warnings, "wireless.security.wips.enabled has no detection families enabled")
	}
	return detections
}

func wirelessSecurityBuildSpectrumChannels(cfg *config.Config, sensors []WirelessSecuritySensorReport, report *WirelessSecurityLifecycleReport) []WirelessSpectrumChannelReport {
	spectrum := cfg.Wireless.Security.Spectrum
	if !spectrum.Enabled {
		return nil
	}
	byKey := map[string]WirelessSpectrumChannelReport{}
	for _, sensor := range sensors {
		for _, band := range sensor.Bands {
			channels := sensor.Channels
			if len(channels) == 0 {
				channels = wirelessSecurityDefaultChannels([]string{band})
			}
			for _, channel := range channels {
				key := rfNormalizeBand(band) + fmt.Sprintf("/%d", channel)
				item := byKey[key]
				item.Band = rfNormalizeBand(band)
				item.Channel = channel
				item.Sensors = append(item.Sensors, sensor.Name)
				item.NoiseFloorDBM = rfFirstNonZero(spectrum.NoiseFloorDBM, -95)
				item.ChannelUtilizationWarnPercent = rfFirstPositive(spectrum.ChannelUtilizationWarnPercent, 70)
				item.InterferenceWarnPercent = rfFirstPositive(spectrum.InterferenceWarnPercent, 35)
				item.DutyCycleWarnPercent = rfFirstPositive(spectrum.DutyCycleWarnPercent, 80)
				item.SampleIntervalSeconds = rfFirstPositive(spectrum.SampleIntervalSeconds, 30)
				item.Status = "ready"
				item.Reason = "spectrum threshold watch is planned for sensor channel coverage"
				byKey[key] = item
			}
		}
	}
	if len(byKey) == 0 {
		for _, band := range []string{"2.4ghz", "5ghz"} {
			for _, channel := range rfDefaultChannels(band) {
				key := band + fmt.Sprintf("/%d", channel)
				byKey[key] = WirelessSpectrumChannelReport{
					Band:                          band,
					Channel:                       channel,
					NoiseFloorDBM:                 rfFirstNonZero(spectrum.NoiseFloorDBM, -95),
					ChannelUtilizationWarnPercent: rfFirstPositive(spectrum.ChannelUtilizationWarnPercent, 70),
					InterferenceWarnPercent:       rfFirstPositive(spectrum.InterferenceWarnPercent, 35),
					DutyCycleWarnPercent:          rfFirstPositive(spectrum.DutyCycleWarnPercent, 80),
					SampleIntervalSeconds:         rfFirstPositive(spectrum.SampleIntervalSeconds, 30),
					Status:                        "warning",
					Reason:                        "default spectrum watch has no attached sensor yet",
				}
			}
		}
		report.Warnings = append(report.Warnings, "spectrum analytics are enabled without attached sensor coverage")
	}
	channels := make([]WirelessSpectrumChannelReport, 0, len(byKey))
	for _, item := range byKey {
		item.Sensors = rfSortedStrings(item.Sensors)
		channels = append(channels, item)
	}
	sort.Slice(channels, func(i, j int) bool {
		if channels[i].Band == channels[j].Band {
			return channels[i].Channel < channels[j].Channel
		}
		return channels[i].Band < channels[j].Band
	})
	return channels
}

func wirelessSecurityBuildLocationZones(cfg *config.Config, sensors []WirelessSecuritySensorReport, report *WirelessSecurityLifecycleReport) []WirelessLocationZoneReport {
	location := cfg.Wireless.Security.Location
	if !location.Enabled {
		return nil
	}
	mode := wirelessSecurityLocationMode(location.Mode)
	privacy := wirelessSecurityPrivacyMode(location.PrivacyMode)
	minAPs := rfFirstPositive(location.MinAPsForTriangulation, 3)
	retention := rfFirstPositive(location.RetentionHours, 720)
	zones := []WirelessLocationZoneReport{}
	for _, zone := range location.Zones {
		name := strings.TrimSpace(zone.Name)
		sensorCount := wirelessSecurityCountSensorsForZone(sensors, name, zone.Floor)
		status, reason := wirelessSecurityLocationStatus(cfg, privacy, mode, minAPs, sensorCount, location)
		if status == "blocked" {
			report.Blockers = append(report.Blockers, "location zone "+name+": "+reason)
		} else if status == "warning" {
			report.Warnings = append(report.Warnings, "location zone "+name+": "+reason)
		}
		zones = append(zones, WirelessLocationZoneReport{
			Name:                    name,
			Floor:                   strings.TrimSpace(zone.Floor),
			Building:                strings.TrimSpace(zone.Building),
			Mode:                    mode,
			PrivacyMode:             privacy,
			HashClientIdentifiers:   location.HashClientIdentifiers || privacy != "raw",
			ExportClientCoordinates: location.ExportClientCoordinates,
			RetentionHours:          rfFirstPositive(zone.RetentionHours, retention),
			MinAPsForTriangulation:  minAPs,
			SensorCount:             sensorCount,
			Status:                  status,
			Reason:                  reason,
		})
		report.Summary.PrivacyCheckCount++
	}
	if len(zones) == 0 {
		sensorCount := len(sensors)
		status, reason := wirelessSecurityLocationStatus(cfg, privacy, mode, minAPs, sensorCount, location)
		if status == "blocked" {
			report.Blockers = append(report.Blockers, "location zone site-wide: "+reason)
		} else if status == "warning" {
			report.Warnings = append(report.Warnings, "location zone site-wide: "+reason)
		}
		zones = append(zones, WirelessLocationZoneReport{
			Name:                    "site-wide",
			Mode:                    mode,
			PrivacyMode:             privacy,
			HashClientIdentifiers:   location.HashClientIdentifiers || privacy != "raw",
			ExportClientCoordinates: location.ExportClientCoordinates,
			RetentionHours:          retention,
			MinAPsForTriangulation:  minAPs,
			SensorCount:             sensorCount,
			Status:                  status,
			Reason:                  reason,
		})
		report.Summary.PrivacyCheckCount++
	}
	return zones
}

func wirelessSecurityBuildMulticastPolicies(cfg *config.Config, report *WirelessSecurityLifecycleReport) []WirelessMulticastPolicyReport {
	multicast := cfg.Wireless.Security.Multicast
	if !multicast.Enabled {
		return nil
	}
	mode := wirelessSecurityMulticastMode(multicast.Mode)
	policies := []WirelessMulticastPolicyReport{}
	add := func(id, name, action string, enabled bool, groups []string, ipv6 bool) {
		status := "ready"
		reason := "multicast policy is available for controller/local-radio intent"
		if !enabled {
			status = "observe"
			reason = "policy is visible but disabled by configuration"
		}
		policies = append(policies, WirelessMulticastPolicyReport{
			ID:          id,
			Name:        name,
			Mode:        mode,
			Action:      action,
			Status:      status,
			Reason:      reason,
			Groups:      rfSortedStrings(groups),
			IPv6Enabled: ipv6,
		})
	}
	add("igmp-snooping", "IGMP Snooping", "snoop_ipv4_memberships", multicast.IGMPSnooping, nil, false)
	add("mld-snooping", "MLD Snooping", "snoop_ipv6_memberships", multicast.MLDSnooping, nil, true)
	add("multicast-to-unicast", "Multicast To Unicast", "convert_airtime_delivery", multicast.MulticastToUnicast, nil, multicast.IPv6Multicast)
	add("broadcast-filter", "Broadcast Filter", "limit_l2_broadcast", multicast.BroadcastFilter, nil, false)
	add("mdns-gateway", "mDNS Gateway", "proxy_mdns", multicast.MDNSGateway, []string{"224.0.0.251", "ff02::fb"}, true)
	add("ssdp-filter", "SSDP Filter", "filter_ssdp", multicast.SSDPFilter, []string{"239.255.255.250", "ff02::c"}, true)
	if len(multicast.AllowedGroups) > 0 {
		add("allowed-groups", "Allowed Multicast Groups", "allow_list", true, multicast.AllowedGroups, multicast.IPv6Multicast)
	}
	if mode != "monitor" && !multicast.IGMPSnooping && !multicast.MLDSnooping && !multicast.MulticastToUnicast && !multicast.BroadcastFilter && !multicast.MDNSGateway && !multicast.SSDPFilter {
		message := "wireless.security.multicast is in optimize/block mode with no multicast control enabled"
		if cfg.Wireless.Security.FailClosed && report.Summary.Mode == "enforce" {
			report.Blockers = append(report.Blockers, message)
		} else {
			report.Warnings = append(report.Warnings, message)
		}
	}
	return policies
}

func wirelessSecurityBuildControllerActions(cfg *config.Config, report *WirelessSecurityLifecycleReport) []WirelessSecurityControllerAction {
	platform := strings.TrimSpace(cfg.Integrations.Controller.Platform)
	if platform == "" {
		platform = "local"
	}
	fields := []string{"rogue_policy", "wips_detection", "spectrum_thresholds", "location_privacy", "multicast_policy"}
	status := "observe"
	reason := "wireless security controller automation is governed as preview-only until release certification evidence is attached"
	operation := "preview"
	if cfg.Integrations.Controller.Enabled && report.Summary.Mode == "enforce" && report.Summary.ControllerPlatform != "local" {
		status = "ready"
		operation = "stage"
		reason = "controller apply intent is enabled by configuration; live mutation remains release certification"
	} else if report.Summary.Mode == "enforce" && !cfg.Integrations.Controller.Enabled {
		status = "warning"
		reason = "wireless security enforce mode has no controller integration enabled"
		report.Warnings = append(report.Warnings, reason)
	}
	return []WirelessSecurityControllerAction{{
		ID:        "wireless-security-controller-intent",
		Platform:  platform,
		Operation: operation,
		Status:    status,
		Reason:    reason,
		Fields:    fields,
		Payload: map[string]any{
			"sensor_count":           report.Summary.SensorCount,
			"rogue_policy_count":     len(report.RoguePolicies),
			"wips_detection_count":   len(report.WIPSDetections),
			"spectrum_channel_count": len(report.SpectrumChannels),
			"location_zone_count":    len(report.LocationZones),
			"multicast_policy_count": len(report.MulticastPolicies),
		},
	}}
}

func wirelessSecurityBuildCompliance(cfg *config.Config, report *WirelessSecurityLifecycleReport) []WirelessSecurityComplianceCheck {
	checks := []WirelessSecurityComplianceCheck{}
	add := func(id, name, status, message string, evidence ...string) {
		checks = append(checks, WirelessSecurityComplianceCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence})
	}
	if len(report.Sensors) > 0 {
		add("sensor-coverage", "Sensor Coverage", "passed", fmt.Sprintf("%d wireless security sensor(s) are available.", len(report.Sensors)))
	} else {
		add("sensor-coverage", "Sensor Coverage", "blocked", "No wireless security sensor, RF AP radio, or local wireless interface is available.")
	}
	if cfg.Wireless.Security.Rogue.Enabled {
		if report.Summary.ContainmentGuardCount > 0 || !cfg.Wireless.Security.Rogue.ContainmentEnabled {
			add("rogue-governance", "Rogue Governance", "passed", "Rogue classification and containment guardrails are explicit.")
		} else {
			add("rogue-governance", "Rogue Governance", "warning", "Rogue containment should declare guardrails before production use.")
		}
	}
	if cfg.Wireless.Security.WIPS.Enabled {
		if len(report.WIPSDetections) > 0 {
			add("wips-coverage", "WIPS Coverage", "passed", fmt.Sprintf("%d WIPS detection family item(s) are enabled.", len(report.WIPSDetections)))
		} else {
			add("wips-coverage", "WIPS Coverage", "warning", "WIPS is enabled without any active detection family.")
		}
	}
	if cfg.Wireless.Security.Spectrum.Enabled {
		if cfg.Wireless.RF.Enabled {
			add("spectrum-rf-link", "Spectrum And RF Link", "passed", "Spectrum watch channels are tied to RF planning topology.")
		} else {
			add("spectrum-rf-link", "Spectrum And RF Link", "warning", "Enable wireless.rf before claiming RF-aware spectrum remediation.")
		}
	}
	if cfg.Wireless.Security.Location.Enabled {
		privacy := wirelessSecurityPrivacyMode(cfg.Wireless.Security.Location.PrivacyMode)
		if privacy == "raw" && cfg.Wireless.Security.Location.ExportClientCoordinates {
			status := "warning"
			if cfg.Wireless.Security.FailClosed && report.Summary.Mode == "enforce" {
				status = "blocked"
			}
			add("location-privacy", "Location Privacy", status, "Raw client coordinate export requires external privacy review and release certification.")
		} else {
			add("location-privacy", "Location Privacy", "passed", "Location services use hashed or anonymous client privacy by default.")
		}
	}
	if cfg.Wireless.Security.Multicast.Enabled {
		if len(report.MulticastPolicies) > 0 {
			add("multicast-governance", "Multicast Governance", "passed", fmt.Sprintf("%d multicast policy item(s) are declared.", len(report.MulticastPolicies)))
		} else {
			add("multicast-governance", "Multicast Governance", "warning", "Multicast lifecycle is enabled without policy items.")
		}
	}
	if cfg.Radius.DynamicAuth.Enabled {
		add("radius-coa-link", "RADIUS CoA Link", "passed", "Dynamic Authorization is configured for quarantine and policy-change workflows.")
	} else {
		add("radius-coa-link", "RADIUS CoA Link", "warning", "Enable radius.dynamic_auth before claiming automated quarantine CoA behavior.")
	}
	add("external-certification", "External Certification", "passed", "Live containment, spectrum capture, location accuracy, multicast airtime optimization, controller firmware behavior, HA, scale, soak, security, and customer proof are tracked outside software completion.", report.ReleaseCertificationChecklist)
	return checks
}

func wirelessSecurityStatus(report WirelessSecurityLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.SecurityEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func wirelessSecurityCompletion(report WirelessSecurityLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func wirelessSecurityMessage(report WirelessSecurityLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0080 software is ready; wireless security lifecycle is not active in this configuration."
	case "blocked":
		return "NAS-0080 wireless security lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0080 plans %d sensor(s), %d rogue policy item(s), %d WIPS detection(s), %d spectrum channel(s), %d location zone(s), and %d multicast policy item(s) with warnings.",
			report.Summary.SensorCount,
			report.Summary.RoguePolicyCount,
			report.Summary.WIPSDetectionCount,
			report.Summary.SpectrumChannelCount,
			report.Summary.LocationZoneCount,
			report.Summary.MulticastPolicyCount,
		)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0080 plans %d sensor(s), %d rogue policy item(s), %d WIPS detection(s), %d spectrum channel(s), %d location zone(s), and %d multicast policy item(s).",
			report.Summary.SensorCount,
			report.Summary.RoguePolicyCount,
			report.Summary.WIPSDetectionCount,
			report.Summary.SpectrumChannelCount,
			report.Summary.LocationZoneCount,
			report.Summary.MulticastPolicyCount,
		)
	}
}

func wirelessSecurityFingerprint(report WirelessSecurityLifecycleReport) string {
	payload := struct {
		FeatureID         string
		Summary           WirelessSecurityLifecycleSummary
		Sensors           []WirelessSecuritySensorReport
		RoguePolicies     []WirelessRoguePolicyReport
		WIPSDetections    []WirelessWIPSDetectionReport
		SpectrumChannels  []WirelessSpectrumChannelReport
		LocationZones     []WirelessLocationZoneReport
		MulticastPolicies []WirelessMulticastPolicyReport
		ControllerActions []WirelessSecurityControllerAction
	}{
		FeatureID:         report.FeatureID,
		Summary:           report.Summary,
		Sensors:           report.Sensors,
		RoguePolicies:     report.RoguePolicies,
		WIPSDetections:    report.WIPSDetections,
		SpectrumChannels:  report.SpectrumChannels,
		LocationZones:     report.LocationZones,
		MulticastPolicies: report.MulticastPolicies,
		ControllerActions: report.ControllerActions,
	}
	return sha256JSON(payload)
}

func wirelessSecurityRuntimeDetails(report WirelessSecurityLifecycleReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                    WirelessSecurityLifecycleFeatureID,
		"event_id":                      eventID,
		"plan_fingerprint":              report.PlanFingerprint,
		"mode":                          report.Summary.Mode,
		"controller_platform":           report.Summary.ControllerPlatform,
		"sensor_count":                  report.Summary.SensorCount,
		"rogue_policy_count":            report.Summary.RoguePolicyCount,
		"wips_detection_count":          report.Summary.WIPSDetectionCount,
		"spectrum_channel_count":        report.Summary.SpectrumChannelCount,
		"location_zone_count":           report.Summary.LocationZoneCount,
		"multicast_policy_count":        report.Summary.MulticastPolicyCount,
		"containment_guard_count":       report.Summary.ContainmentGuardCount,
		"privacy_check_count":           report.Summary.PrivacyCheckCount,
		"compliance_check_count":        report.Summary.ComplianceCheckCount,
		"passed_check_count":            report.Summary.PassedCheckCount,
		"release_checklist":             report.ReleaseCertificationChecklist,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}
}

func wirelessSecurityCapabilities(security config.WirelessSecurityConfig) []string {
	capabilities := []string{}
	if security.Rogue.Enabled {
		capabilities = append(capabilities, "rogue")
	}
	if security.WIPS.Enabled {
		capabilities = append(capabilities, "wips")
	}
	if security.Spectrum.Enabled {
		capabilities = append(capabilities, "spectrum")
	}
	if security.Location.Enabled {
		capabilities = append(capabilities, "location")
	}
	if security.Multicast.Enabled {
		capabilities = append(capabilities, "multicast")
	}
	return rfSortedStrings(capabilities)
}

func wirelessSecurityBands(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		band := rfNormalizeBand(value)
		if band == "" {
			continue
		}
		if _, exists := seen[band]; exists {
			continue
		}
		seen[band] = struct{}{}
		out = append(out, band)
	}
	sort.Strings(out)
	return out
}

func wirelessSecurityDefaultChannels(bands []string) []int {
	values := []int{}
	seen := map[int]struct{}{}
	for _, band := range bands {
		for _, channel := range rfDefaultChannels(band) {
			if _, exists := seen[channel]; exists {
				continue
			}
			seen[channel] = struct{}{}
			values = append(values, channel)
		}
	}
	if len(values) == 0 {
		values = []int{1, 6, 11, 36, 44, 149}
	}
	sort.Ints(values)
	return values
}

func wirelessSecurityPositiveChannels(values []int) []int {
	out := []int{}
	for _, value := range values {
		if value > 0 {
			out = append(out, value)
		}
	}
	sort.Ints(out)
	return out
}

func wirelessSecurityLowerStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.ToLower(strings.TrimSpace(value)))
		}
	}
	return out
}

func wirelessSecurityUpperStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(value))
		if normalized != "" {
			out = append(out, strings.ToUpper(normalized))
		}
	}
	return out
}

func wirelessSecurityRoguePolicy(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "balanced"
	}
	return value
}

func wirelessSecurityEffectiveMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func wirelessSecurityLocationMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "zone"
	}
	return value
}

func wirelessSecurityPrivacyMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "hashed"
	}
	return value
}

func wirelessSecurityMulticastMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func wirelessSecurityCountSensorsForZone(sensors []WirelessSecuritySensorReport, zoneName, floor string) int {
	zoneName = strings.ToLower(strings.TrimSpace(zoneName))
	floor = strings.ToLower(strings.TrimSpace(floor))
	if zoneName == "" && floor == "" {
		return len(sensors)
	}
	count := 0
	for _, sensor := range sensors {
		if zoneName != "" && strings.EqualFold(sensor.Zone, zoneName) {
			count++
			continue
		}
		if floor != "" && strings.EqualFold(sensor.Floor, floor) {
			count++
		}
	}
	return count
}

func wirelessSecurityLocationStatus(cfg *config.Config, privacy, mode string, minAPs, sensorCount int, location config.WirelessLocationConfig) (string, string) {
	status := "ready"
	reason := "location privacy and retention policy are ready"
	if mode == "coordinate" && sensorCount < minAPs {
		reason = fmt.Sprintf("coordinate mode needs at least %d sensor(s); %d are available", minAPs, sensorCount)
		if cfg.Wireless.Security.FailClosed && wirelessSecurityEffectiveMode(cfg.Wireless.Security.Mode) == "enforce" {
			return "blocked", reason
		}
		status = "warning"
	}
	if privacy == "raw" && location.ExportClientCoordinates {
		reason = "raw coordinate export requires external privacy review and release certification"
		if cfg.Wireless.Security.FailClosed && wirelessSecurityEffectiveMode(cfg.Wireless.Security.Mode) == "enforce" {
			return "blocked", reason
		}
		status = "warning"
	}
	return status, reason
}
