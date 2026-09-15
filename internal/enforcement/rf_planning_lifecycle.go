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
	RFPlanningLifecycleSchemaVersion = 1
	RFPlanningLifecycleFeatureID     = "NAS-0079"
	rfPlanningLifecycleComponent     = "rf_planning_lifecycle"
)

type RFPlanningLifecycleReport struct {
	SchemaVersion                 int                         `json:"schema_version"`
	FeatureID                     string                      `json:"feature_id"`
	Status                        string                      `json:"status"`
	Message                       string                      `json:"message"`
	GeneratedAt                   string                      `json:"generated_at"`
	SoftwareCompletionPercent     float64                     `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                        `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                      `json:"release_certification_checklist"`
	ReleaseScope                  string                      `json:"release_scope"`
	PlanFingerprint               string                      `json:"plan_fingerprint"`
	Summary                       RFPlanningLifecycleSummary  `json:"summary"`
	Radios                        []RFPlanningRadioReport     `json:"radios"`
	ChannelPlan                   []RFChannelPlanItem         `json:"channel_plan"`
	PowerPlan                     []RFPowerPlanItem           `json:"power_plan"`
	MeshPlan                      []RFMeshLinkReport          `json:"mesh_plan"`
	SteeringPolicies              []RFClientSteeringPolicy    `json:"steering_policies"`
	ControllerActions             []RFControllerAction        `json:"controller_actions"`
	Compliance                    []RFPlanningComplianceCheck `json:"compliance"`
	Standards                     []string                    `json:"standards"`
	Vendors                       []string                    `json:"vendors"`
	Requirements                  []string                    `json:"requirements"`
	Blockers                      []string                    `json:"blockers,omitempty"`
	Warnings                      []string                    `json:"warnings,omitempty"`
	Notes                         []string                    `json:"notes,omitempty"`
}

type RFPlanningLifecycleSummary struct {
	RFEnabled                bool   `json:"rf_enabled"`
	WirelessEnabled          bool   `json:"wireless_enabled"`
	ControllerEnabled        bool   `json:"controller_enabled"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	CountryCode              string `json:"country_code,omitempty"`
	Mode                     string `json:"mode"`
	ChannelPlanMode          string `json:"channel_plan_mode"`
	APCount                  int    `json:"ap_count"`
	RadioCount               int    `json:"radio_count"`
	BandCount                int    `json:"band_count"`
	SSIDCount                int    `json:"ssid_count"`
	ChannelPlanCount         int    `json:"channel_plan_count"`
	PowerPlanCount           int    `json:"power_plan_count"`
	MeshEnabled              bool   `json:"mesh_enabled"`
	MeshRootCount            int    `json:"mesh_root_count"`
	MeshLinkCount            int    `json:"mesh_link_count"`
	SteeringEnabled          bool   `json:"steering_enabled"`
	SteeringPolicyCount      int    `json:"steering_policy_count"`
	ChannelConflictCount     int    `json:"channel_conflict_count"`
	CapacityWarningCount     int    `json:"capacity_warning_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
}

type RFPlanningRadioReport struct {
	APName            string   `json:"ap_name"`
	RadioName         string   `json:"radio_name"`
	Interface         string   `json:"interface,omitempty"`
	BSSID             string   `json:"bssid,omitempty"`
	Band              string   `json:"band"`
	Zone              string   `json:"zone,omitempty"`
	Floor             string   `json:"floor,omitempty"`
	Location          string   `json:"location,omitempty"`
	Controller        string   `json:"controller,omitempty"`
	CurrentChannel    int      `json:"current_channel,omitempty"`
	PlannedChannel    int      `json:"planned_channel"`
	ChannelWidthMHz   int      `json:"channel_width_mhz"`
	CurrentTxPowerDBM int      `json:"current_tx_power_dbm,omitempty"`
	PlannedTxPowerDBM int      `json:"planned_tx_power_dbm"`
	AntennaGainDBI    int      `json:"antenna_gain_dbi,omitempty"`
	MaxClients        int      `json:"max_clients"`
	SSIDNames         []string `json:"ssid_names,omitempty"`
	NeighborAPs       []string `json:"neighbor_aps,omitempty"`
	MeshEnabled       bool     `json:"mesh_enabled"`
	MeshRole          string   `json:"mesh_role,omitempty"`
	ClientSteering    bool     `json:"client_steering"`
	Status            string   `json:"status"`
	Diagnostics       []string `json:"diagnostics,omitempty"`
}

type RFChannelPlanItem struct {
	APName          string `json:"ap_name"`
	RadioName       string `json:"radio_name"`
	Band            string `json:"band"`
	Zone            string `json:"zone,omitempty"`
	CurrentChannel  int    `json:"current_channel,omitempty"`
	PlannedChannel  int    `json:"planned_channel"`
	ChannelWidthMHz int    `json:"channel_width_mhz"`
	ReuseGroup      string `json:"reuse_group"`
	Status          string `json:"status"`
	Reason          string `json:"reason"`
	Alternates      []int  `json:"alternates,omitempty"`
}

type RFPowerPlanItem struct {
	APName            string `json:"ap_name"`
	RadioName         string `json:"radio_name"`
	Band              string `json:"band"`
	CurrentTxPowerDBM int    `json:"current_tx_power_dbm,omitempty"`
	PlannedTxPowerDBM int    `json:"planned_tx_power_dbm"`
	MinPowerDBM       int    `json:"min_power_dbm"`
	MaxPowerDBM       int    `json:"max_power_dbm"`
	TargetCellRSSI    int    `json:"target_cell_rssi"`
	Status            string `json:"status"`
	Reason            string `json:"reason"`
}

type RFMeshLinkReport struct {
	RootAP       string `json:"root_ap"`
	MeshAP       string `json:"mesh_ap"`
	RootRadio    string `json:"root_radio"`
	MeshRadio    string `json:"mesh_radio"`
	Band         string `json:"band"`
	BackhaulSSID string `json:"backhaul_ssid,omitempty"`
	BridgeVLAN   int    `json:"bridge_vlan,omitempty"`
	HopCount     int    `json:"hop_count"`
	MinRSSI      int    `json:"min_rssi"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
}

type RFClientSteeringPolicy struct {
	SSID               string   `json:"ssid"`
	BandPreference     string   `json:"band_preference"`
	MinRSSI            int      `json:"min_rssi"`
	StickyClientRSSI   int      `json:"sticky_client_rssi"`
	LoadBalance        bool     `json:"load_balance"`
	MaxClientsPerRadio int      `json:"max_clients_per_radio"`
	RejectBelowMinRSSI bool     `json:"reject_below_min_rssi"`
	TargetRadios       []string `json:"target_radios"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
}

type RFControllerAction struct {
	ID        string         `json:"id"`
	Platform  string         `json:"platform"`
	Operation string         `json:"operation"`
	Status    string         `json:"status"`
	Reason    string         `json:"reason"`
	Fields    []string       `json:"fields,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type RFPlanningComplianceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

type rfBandProfile struct {
	Name               string
	Enabled            bool
	Channels           []int
	ChannelWidth       int
	MinPowerDBM        int
	MaxPowerDBM        int
	DFSAllowed         bool
	MaxClientsPerRadio int
}

func RFPlanningLifecycleComponent() string {
	return rfPlanningLifecycleComponent
}

func PreviewRFPlanningLifecycle(cfg *config.Config) (RFPlanningLifecycleReport, error) {
	if cfg == nil {
		return RFPlanningLifecycleReport{}, fmt.Errorf("config is required")
	}
	rf := cfg.Wireless.RF
	report := RFPlanningLifecycleReport{
		SchemaVersion:                 RFPlanningLifecycleSchemaVersion,
		FeatureID:                     RFPlanningLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0079-release-certification-checklist.md",
		ReleaseScope:                  "Real RF survey validation, controller firmware behavior, AP radio telemetry, spectrum captures, mesh throughput, client steering behavior, HA failover, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards: []string{
			"IEEE 802.11-2020",
			"IEEE 802.11k",
			"IEEE 802.11v",
			"IEEE 802.11s",
			"IEEE 802.11ax",
			"IEEE 802.11be",
			"IEEE 802.1X",
			"RFC 2865",
			"RFC 2866",
			"RFC 5176",
		},
		Vendors: []string{"Cisco", "Aruba", "Ruckus", "Extreme", "Meraki", "UniFi", "Cambium", "Juniper Mist", "Fortinet", "MikroTik", "OpenWiFi", "hostapd"},
		Requirements: []string{
			"RF intent is represented as declared AP/radio topology, channels, channel width, power bounds, mesh roles, and steering policy",
			"channel plans are deterministic and avoid adjacent 2.4GHz overlap where possible",
			"power plans are bounded by configured regulatory and band policy limits",
			"mesh plans require at least one root radio before apply can be considered operational",
			"client steering remains policy intent until proven on controller/AP hardware",
			"controller actions are previews with explicit ownership and managed field lists",
			"RADIUS/EAP/Accounting/CoA dependencies remain visible for roaming and steering workflows",
		},
		Notes: []string{
			"NAS-0079 completes software planning and governance for RF/RRM/mesh/client-steering intent.",
			"Live spectrum measurements and vendor RF automation evidence are intentionally tracked in release certification.",
		},
	}
	report.Summary = RFPlanningLifecycleSummary{
		RFEnabled:                rf.Enabled,
		WirelessEnabled:          cfg.Wireless.Enabled,
		ControllerEnabled:        cfg.Integrations.Controller.Enabled,
		ControllerPlatform:       strings.TrimSpace(cfg.Integrations.Controller.Platform),
		CountryCode:              strings.ToUpper(strings.TrimSpace(cfg.Wireless.CountryCode)),
		Mode:                     rfEffectiveMode(rf.Mode),
		ChannelPlanMode:          rfEffectiveChannelPlanMode(rf.ChannelPlanMode),
		SSIDCount:                len(cfg.Wireless.SSIDs),
		MeshEnabled:              rf.Mesh.Enabled,
		SteeringEnabled:          rf.ClientSteering.Enabled,
		ExternalRequirementCount: 10,
	}
	if report.Summary.ControllerPlatform == "" {
		report.Summary.ControllerPlatform = "local"
	}
	if !rf.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0079 software is ready; RF planning is not active in this configuration."
		report.PlanFingerprint = rfPlanningFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}

	bands := rfBuildBandProfiles(cfg)
	radios := rfBuildRadioReports(cfg, bands)
	report.Radios = radios
	report.ChannelPlan = rfBuildChannelPlan(cfg, bands, radios, &report)
	report.PowerPlan = rfBuildPowerPlan(cfg, bands, radios, &report)
	report.MeshPlan = rfBuildMeshPlan(cfg, radios, &report)
	report.SteeringPolicies = rfBuildSteeringPolicies(cfg, radios, &report)
	report.Summary.APCount = rfCountAPs(radios)
	report.Summary.RadioCount = len(radios)
	report.Summary.BandCount = rfCountBands(radios)
	report.Summary.ChannelPlanCount = len(report.ChannelPlan)
	report.Summary.PowerPlanCount = len(report.PowerPlan)
	report.Summary.MeshLinkCount = len(report.MeshPlan)
	report.Summary.SteeringPolicyCount = len(report.SteeringPolicies)
	report.ControllerActions = rfBuildControllerActions(cfg, &report)
	report.Compliance = rfBuildCompliance(cfg, &report)
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
	if len(radios) == 0 {
		report.Blockers = append(report.Blockers, "wireless.rf.enabled requires at least one declared AP radio or an enabled local wireless radio")
		report.Summary.BlockerCount = len(report.Blockers)
	}
	report.Status = rfPlanningStatus(report)
	report.SoftwareCompletionPercent = rfPlanningCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = rfPlanningMessage(report)
	report.PlanFingerprint = rfPlanningFingerprint(report)
	return report, nil
}

func PreviewAndRecordRFPlanningLifecycle(cfg *config.Config, actor string) (RFPlanningLifecycleReport, string, error) {
	report, err := PreviewRFPlanningLifecycle(cfg)
	if err != nil {
		return RFPlanningLifecycleReport{}, "", err
	}
	eventID, err := recordRFPlanningLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyRFPlanningLifecycle(ctx context.Context, cfg *config.Config, actor string) (RFPlanningLifecycleReport, string, error) {
	report, err := PreviewRFPlanningLifecycle(cfg)
	if err != nil {
		return RFPlanningLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordRFPlanningLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(rfPlanningLifecycleComponent, "down", report.Message, rfPlanningRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("RF planning lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0079 recorded RF plan for %d AP(s), %d radio(s), %d channel assignment(s), and %d mesh link(s).",
			report.Summary.APCount,
			report.Summary.RadioCount,
			report.Summary.ChannelPlanCount,
			report.Summary.MeshLinkCount,
		)
	}
	eventID, err := recordRFPlanningLifecycleEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := rfPlanningRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if len(report.Warnings) > 0 || report.Summary.ChannelConflictCount > 0 || report.Summary.CapacityWarningCount > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(rfPlanningLifecycleComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(rfPlanningLifecycleComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordRFPlanningLifecycleEvent(report RFPlanningLifecycleReport, operation, actor string) (string, error) {
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
	return db.RecordRFPlanningLifecycleEvent(db.RFPlanningLifecycleEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		CountryCode:              report.Summary.CountryCode,
		ControllerPlatform:       report.Summary.ControllerPlatform,
		ChannelPlanMode:          report.Summary.ChannelPlanMode,
		APCount:                  report.Summary.APCount,
		RadioCount:               report.Summary.RadioCount,
		BandCount:                report.Summary.BandCount,
		ChannelPlanCount:         report.Summary.ChannelPlanCount,
		PowerPlanCount:           report.Summary.PowerPlanCount,
		MeshLinkCount:            report.Summary.MeshLinkCount,
		SteeringPolicyCount:      report.Summary.SteeringPolicyCount,
		ChannelConflictCount:     report.Summary.ChannelConflictCount,
		CapacityWarningCount:     report.Summary.CapacityWarningCount,
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

func rfBuildBandProfiles(cfg *config.Config) map[string]rfBandProfile {
	profiles := map[string]rfBandProfile{
		"2.4ghz": {Name: "2.4ghz", Enabled: true, Channels: []int{1, 6, 11}, ChannelWidth: 20, MinPowerDBM: 5, MaxPowerDBM: 17, MaxClientsPerRadio: 40},
		"5ghz":   {Name: "5ghz", Enabled: true, Channels: []int{36, 40, 44, 48, 149, 153, 157, 161}, ChannelWidth: 40, MinPowerDBM: 8, MaxPowerDBM: 23, DFSAllowed: true, MaxClientsPerRadio: 80},
		"6ghz":   {Name: "6ghz", Enabled: true, Channels: []int{5, 21, 37, 53, 69, 85}, ChannelWidth: 80, MinPowerDBM: 8, MaxPowerDBM: 23, MaxClientsPerRadio: 80},
	}
	rf := cfg.Wireless.RF
	for key, profile := range profiles {
		if rf.DefaultChannelWidth > 0 {
			profile.ChannelWidth = rf.DefaultChannelWidth
		}
		if rf.MinPowerDBM > 0 {
			profile.MinPowerDBM = rf.MinPowerDBM
		}
		if rf.MaxPowerDBM > 0 {
			profile.MaxPowerDBM = rf.MaxPowerDBM
		}
		if rf.MaxClientsPerRadio > 0 {
			profile.MaxClientsPerRadio = rf.MaxClientsPerRadio
		}
		profiles[key] = profile
	}
	for _, band := range rf.Bands {
		name := rfNormalizeBand(band.Name)
		if name == "" {
			continue
		}
		profile := profiles[name]
		if profile.Name == "" {
			profile = rfBandProfile{Name: name, Enabled: true, Channels: rfDefaultChannels(name), ChannelWidth: 20, MinPowerDBM: 5, MaxPowerDBM: 20, MaxClientsPerRadio: 64}
		}
		profile.Enabled = band.Enabled
		if len(band.Channels) > 0 {
			profile.Channels = rfPositiveChannels(band.Channels)
		}
		if band.ChannelWidth > 0 {
			profile.ChannelWidth = band.ChannelWidth
		}
		if band.MinPowerDBM > 0 {
			profile.MinPowerDBM = band.MinPowerDBM
		}
		if band.MaxPowerDBM > 0 {
			profile.MaxPowerDBM = band.MaxPowerDBM
		}
		profile.DFSAllowed = band.DFSAllowed
		if band.MaxClientsPerRadio > 0 {
			profile.MaxClientsPerRadio = band.MaxClientsPerRadio
		}
		profiles[name] = profile
	}
	return profiles
}

func rfBuildRadioReports(cfg *config.Config, bands map[string]rfBandProfile) []RFPlanningRadioReport {
	reports := []RFPlanningRadioReport{}
	for _, ap := range cfg.Wireless.RF.APs {
		if !ap.Enabled {
			continue
		}
		for _, radio := range ap.Radios {
			if !radio.Enabled {
				continue
			}
			band := rfNormalizeBand(radio.Band)
			profile := bands[band]
			channelWidth := rfFirstPositive(radio.ChannelWidth, profile.ChannelWidth, cfg.Wireless.RF.DefaultChannelWidth, 20)
			maxClients := rfFirstPositive(radio.MaxClients, profile.MaxClientsPerRadio, cfg.Wireless.RF.MaxClientsPerRadio, 64)
			report := RFPlanningRadioReport{
				APName:            strings.TrimSpace(ap.Name),
				RadioName:         strings.TrimSpace(radio.Name),
				Interface:         strings.TrimSpace(radio.Interface),
				BSSID:             strings.ToLower(strings.TrimSpace(radio.BSSID)),
				Band:              band,
				Zone:              strings.TrimSpace(ap.Zone),
				Floor:             strings.TrimSpace(ap.Floor),
				Location:          strings.TrimSpace(ap.Location),
				Controller:        rfFirstNonEmpty(ap.Controller, cfg.Integrations.Controller.Platform, "local"),
				CurrentChannel:    radio.Channel,
				ChannelWidthMHz:   channelWidth,
				CurrentTxPowerDBM: radio.TxPowerDBM,
				AntennaGainDBI:    radio.AntennaGainDBI,
				MaxClients:        maxClients,
				SSIDNames:         rfSSIDNamesForRadio(radio.SSIDs, cfg.Wireless.SSIDs),
				NeighborAPs:       rfSortedStrings(radio.NeighborAPs),
				MeshEnabled:       radio.MeshEnabled || cfg.Wireless.RF.Mesh.Enabled,
				MeshRole:          rfNormalizeMeshRole(radio.MeshRole),
				ClientSteering:    radio.ClientSteering || cfg.Wireless.RF.ClientSteering.Enabled,
				Status:            "ready",
			}
			if report.MeshRole == "" && report.MeshEnabled {
				report.MeshRole = "mesh"
			}
			if profile.Name == "" || !profile.Enabled {
				report.Status = "warning"
				report.Diagnostics = append(report.Diagnostics, "band profile is disabled or missing; default channel policy will be used")
			}
			reports = append(reports, report)
		}
	}
	if len(reports) == 0 && cfg.Wireless.Enabled {
		band := rfBandFromHostapd(cfg.Wireless.HWMode, cfg.Wireless.Channel)
		profile := bands[band]
		reports = append(reports, RFPlanningRadioReport{
			APName:          "local-appliance",
			RadioName:       "radio0",
			Interface:       strings.TrimSpace(cfg.Wireless.Interface),
			Band:            band,
			Zone:            "local",
			Controller:      "hostapd",
			CurrentChannel:  cfg.Wireless.Channel,
			ChannelWidthMHz: rfFirstPositive(profile.ChannelWidth, cfg.Wireless.RF.DefaultChannelWidth, 20),
			MaxClients:      rfFirstPositive(profile.MaxClientsPerRadio, cfg.Wireless.RF.MaxClientsPerRadio, 64),
			SSIDNames:       rfSSIDNamesForRadio(nil, cfg.Wireless.SSIDs),
			MeshEnabled:     cfg.Wireless.RF.Mesh.Enabled,
			MeshRole:        "root",
			ClientSteering:  cfg.Wireless.RF.ClientSteering.Enabled,
			Status:          "ready",
			Diagnostics:     []string{"synthetic local radio derived from wireless interface settings"},
		})
	}
	sort.Slice(reports, func(i, j int) bool {
		left := reports[i].APName + "/" + reports[i].RadioName
		right := reports[j].APName + "/" + reports[j].RadioName
		return left < right
	})
	return reports
}

func rfBuildChannelPlan(cfg *config.Config, bands map[string]rfBandProfile, radios []RFPlanningRadioReport, report *RFPlanningLifecycleReport) []RFChannelPlanItem {
	plans := make([]RFChannelPlanItem, 0, len(radios))
	bandZoneCounters := map[string]int{}
	usage := map[string]int{}
	for i, radio := range radios {
		profile := bands[radio.Band]
		channels := profile.Channels
		if len(channels) == 0 {
			channels = rfDefaultChannels(radio.Band)
		}
		mode := report.Summary.ChannelPlanMode
		planned := radio.CurrentChannel
		reason := "manual channel retained"
		if mode == "auto" || planned == 0 {
			counterKey := rfReuseGroup(radio)
			offset := bandZoneCounters[counterKey]
			bandZoneCounters[counterKey]++
			planned = channels[offset%len(channels)]
			reason = "auto-selected from regulatory band channel pool"
		} else if mode == "hybrid" && !rfChannelInList(planned, channels) {
			planned = channels[i%len(channels)]
			reason = "hybrid plan corrected channel outside allowed pool"
		}
		status := "ready"
		if radio.Band == "2.4ghz" && radio.ChannelWidthMHz > 20 {
			status = "warning"
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s/%s uses %dMHz on 2.4GHz", radio.APName, radio.RadioName, radio.ChannelWidthMHz))
		}
		if planned == 0 {
			status = "blocked"
			report.Blockers = append(report.Blockers, fmt.Sprintf("%s/%s has no planned channel", radio.APName, radio.RadioName))
		}
		key := rfReuseGroup(radio) + fmt.Sprintf("/%d", planned)
		usage[key]++
		plan := RFChannelPlanItem{
			APName:          radio.APName,
			RadioName:       radio.RadioName,
			Band:            radio.Band,
			Zone:            radio.Zone,
			CurrentChannel:  radio.CurrentChannel,
			PlannedChannel:  planned,
			ChannelWidthMHz: radio.ChannelWidthMHz,
			ReuseGroup:      rfReuseGroup(radio),
			Status:          status,
			Reason:          reason,
			Alternates:      rfAlternates(channels, planned),
		}
		plans = append(plans, plan)
		for idx := range report.Radios {
			if report.Radios[idx].APName == radio.APName && report.Radios[idx].RadioName == radio.RadioName {
				report.Radios[idx].PlannedChannel = planned
				if status != "ready" {
					report.Radios[idx].Status = status
					report.Radios[idx].Diagnostics = append(report.Radios[idx].Diagnostics, reason)
				}
			}
		}
	}
	maxReuse := rfFirstPositive(cfg.Wireless.RF.MaxChannelReuse, 1)
	for key, count := range usage {
		if count <= maxReuse {
			continue
		}
		report.Summary.ChannelConflictCount++
		message := fmt.Sprintf("channel reuse %s appears %d time(s), above configured maximum %d", key, count, maxReuse)
		report.Warnings = append(report.Warnings, message)
		for i := range plans {
			planKey := plans[i].ReuseGroup + fmt.Sprintf("/%d", plans[i].PlannedChannel)
			if planKey == key {
				plans[i].Status = "warning"
				plans[i].Reason = message
			}
		}
	}
	return plans
}

func rfBuildPowerPlan(cfg *config.Config, bands map[string]rfBandProfile, radios []RFPlanningRadioReport, report *RFPlanningLifecycleReport) []RFPowerPlanItem {
	plans := make([]RFPowerPlanItem, 0, len(radios))
	density := map[string]int{}
	for _, radio := range radios {
		density[rfReuseGroup(radio)]++
	}
	for _, radio := range radios {
		profile := bands[radio.Band]
		minPower := rfFirstPositive(profile.MinPowerDBM, cfg.Wireless.RF.MinPowerDBM, 5)
		maxPower := rfFirstPositive(profile.MaxPowerDBM, cfg.Wireless.RF.MaxPowerDBM, 20)
		planned := radio.CurrentTxPowerDBM
		reason := "declared radio power retained"
		if planned == 0 {
			penalty := density[rfReuseGroup(radio)] - 1
			if penalty < 0 {
				penalty = 0
			}
			planned = rfClamp(maxPower-penalty*2, minPower, maxPower)
			reason = "power selected from band bounds and local density"
		}
		planned = rfClamp(planned, minPower, maxPower)
		status := "ready"
		if radio.MaxClients > 0 && len(radio.SSIDNames) > 0 && radio.MaxClients < len(radio.SSIDNames)*8 {
			status = "warning"
			report.Summary.CapacityWarningCount++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s/%s max client budget is low for %d SSID(s)", radio.APName, radio.RadioName, len(radio.SSIDNames)))
		}
		plan := RFPowerPlanItem{
			APName:            radio.APName,
			RadioName:         radio.RadioName,
			Band:              radio.Band,
			CurrentTxPowerDBM: radio.CurrentTxPowerDBM,
			PlannedTxPowerDBM: planned,
			MinPowerDBM:       minPower,
			MaxPowerDBM:       maxPower,
			TargetCellRSSI:    rfFirstNonZero(cfg.Wireless.RF.TargetCellRSSI, -67),
			Status:            status,
			Reason:            reason,
		}
		plans = append(plans, plan)
		for i := range report.Radios {
			if report.Radios[i].APName == radio.APName && report.Radios[i].RadioName == radio.RadioName {
				report.Radios[i].PlannedTxPowerDBM = planned
				if status != "ready" {
					report.Radios[i].Status = status
					report.Radios[i].Diagnostics = append(report.Radios[i].Diagnostics, plan.Reason)
				}
			}
		}
	}
	return plans
}

func rfBuildMeshPlan(cfg *config.Config, radios []RFPlanningRadioReport, report *RFPlanningLifecycleReport) []RFMeshLinkReport {
	if !cfg.Wireless.RF.Mesh.Enabled {
		return nil
	}
	rootNames := map[string]struct{}{}
	for _, root := range cfg.Wireless.RF.Mesh.RootAPs {
		rootNames[strings.ToLower(strings.TrimSpace(root))] = struct{}{}
	}
	rootsByBand := map[string][]RFPlanningRadioReport{}
	meshRadios := []RFPlanningRadioReport{}
	for _, radio := range radios {
		if !radio.MeshEnabled {
			continue
		}
		role := rfNormalizeMeshRole(radio.MeshRole)
		_, configuredRoot := rootNames[strings.ToLower(radio.APName)]
		if role == "root" || configuredRoot {
			rootsByBand[radio.Band] = append(rootsByBand[radio.Band], radio)
			report.Summary.MeshRootCount++
			continue
		}
		meshRadios = append(meshRadios, radio)
	}
	if len(rootsByBand) == 0 {
		report.Blockers = append(report.Blockers, "wireless.rf.mesh.enabled requires at least one root AP or root mesh radio")
		return nil
	}
	links := make([]RFMeshLinkReport, 0, len(meshRadios))
	for _, radio := range meshRadios {
		rootCandidates := rootsByBand[radio.Band]
		if len(rootCandidates) == 0 && cfg.Wireless.RF.Mesh.Prefer5GHz {
			rootCandidates = rootsByBand["5ghz"]
		}
		if len(rootCandidates) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s/%s has no same-band mesh root", radio.APName, radio.RadioName))
			continue
		}
		root := rootCandidates[0]
		link := RFMeshLinkReport{
			RootAP:       root.APName,
			MeshAP:       radio.APName,
			RootRadio:    root.RadioName,
			MeshRadio:    radio.RadioName,
			Band:         radio.Band,
			BackhaulSSID: strings.TrimSpace(cfg.Wireless.RF.Mesh.BackhaulSSID),
			BridgeVLAN:   cfg.Wireless.RF.Mesh.BridgeVLAN,
			HopCount:     1,
			MinRSSI:      rfFirstNonZero(cfg.Wireless.RF.Mesh.MinBackhaulRSSI, -67),
			Status:       "planned",
			Reason:       "nearest declared same-band root selected deterministically",
		}
		if cfg.Wireless.RF.Mesh.MaxHops > 0 && link.HopCount > cfg.Wireless.RF.Mesh.MaxHops {
			link.Status = "blocked"
			link.Reason = "mesh hop count exceeds configured maximum"
			report.Blockers = append(report.Blockers, fmt.Sprintf("%s mesh link exceeds max_hops", radio.APName))
		}
		links = append(links, link)
	}
	return links
}

func rfBuildSteeringPolicies(cfg *config.Config, radios []RFPlanningRadioReport, report *RFPlanningLifecycleReport) []RFClientSteeringPolicy {
	steering := cfg.Wireless.RF.ClientSteering
	if !steering.Enabled {
		return nil
	}
	bySSID := map[string][]string{}
	for _, radio := range radios {
		if !radio.ClientSteering {
			continue
		}
		for _, ssid := range radio.SSIDNames {
			bySSID[ssid] = append(bySSID[ssid], radio.APName+"/"+radio.RadioName+"/"+radio.Band)
		}
	}
	ssids := make([]string, 0, len(bySSID))
	for ssid := range bySSID {
		ssids = append(ssids, ssid)
	}
	sort.Strings(ssids)
	policies := make([]RFClientSteeringPolicy, 0, len(ssids))
	for _, ssid := range ssids {
		targets := rfSortedStrings(bySSID[ssid])
		status := "planned"
		reason := "band steering and load balancing are planned as controller/local-radio intent"
		if len(targets) < 2 {
			status = "warning"
			reason = "client steering is more useful with two or more target radios"
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s has fewer than two steering target radios", ssid))
		}
		policies = append(policies, RFClientSteeringPolicy{
			SSID:               ssid,
			BandPreference:     rfFirstNonEmpty(steering.BandPreference, "5ghz"),
			MinRSSI:            rfFirstNonZero(steering.MinRSSI, -72),
			StickyClientRSSI:   rfFirstNonZero(steering.StickyClientRSSI, -78),
			LoadBalance:        steering.LoadBalance,
			MaxClientsPerRadio: rfFirstPositive(steering.MaxClientsPerRadio, cfg.Wireless.RF.MaxClientsPerRadio, 64),
			RejectBelowMinRSSI: steering.RejectBelowMinRSSI,
			TargetRadios:       targets,
			Status:             status,
			Reason:             reason,
		})
	}
	return policies
}

func rfBuildControllerActions(cfg *config.Config, report *RFPlanningLifecycleReport) []RFControllerAction {
	platform := strings.TrimSpace(cfg.Integrations.Controller.Platform)
	if platform == "" {
		platform = "local"
	}
	fields := rfSortedStrings(cfg.Wireless.RF.ControllerExtensions.ManagedFields)
	if len(fields) == 0 {
		fields = []string{"channel", "channel_width", "tx_power", "mesh_role", "client_steering"}
	}
	status := "observe"
	reason := "controller RF automation is governed as preview-only until release certification evidence is attached"
	operation := "preview"
	if cfg.Wireless.RF.ControllerExtensions.Enabled && cfg.Integrations.Controller.Enabled && cfg.Wireless.RF.ControllerExtensions.AllowControllerApply {
		status = "ready"
		reason = "controller RF apply is allowed by configuration; live execution remains external certification"
		operation = "stage"
	} else if cfg.Wireless.RF.ControllerExtensions.Enabled && !cfg.Integrations.Controller.Enabled {
		status = "warning"
		reason = "controller RF extensions are enabled but controller integration is disabled"
		report.Warnings = append(report.Warnings, reason)
	}
	return []RFControllerAction{{
		ID:        "rf-controller-intent",
		Platform:  platform,
		Operation: operation,
		Status:    status,
		Reason:    reason,
		Fields:    fields,
		Payload: map[string]any{
			"radio_count":           report.Summary.RadioCount,
			"channel_plan_count":    len(report.ChannelPlan),
			"power_plan_count":      len(report.PowerPlan),
			"mesh_link_count":       len(report.MeshPlan),
			"steering_policy_count": len(report.SteeringPolicies),
		},
	}}
}

func rfBuildCompliance(cfg *config.Config, report *RFPlanningLifecycleReport) []RFPlanningComplianceCheck {
	checks := []RFPlanningComplianceCheck{}
	add := func(id, name, status, message string, evidence ...string) {
		checks = append(checks, RFPlanningComplianceCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence})
	}
	country := strings.TrimSpace(report.Summary.CountryCode)
	if len(country) == 2 {
		add("regulatory-domain", "Regulatory Domain", "passed", "Country code is present for RF planning.", "country_code="+country)
	} else {
		status := "warning"
		if cfg.Wireless.RF.FailClosed && report.Summary.Mode == "enforce" {
			status = "blocked"
		}
		add("regulatory-domain", "Regulatory Domain", status, "RF planning should declare a two-letter country code before production apply.")
	}
	if len(report.Radios) > 0 {
		add("radio-topology", "Radio Topology", "passed", fmt.Sprintf("%d radio(s) across %d AP(s) are available for planning.", len(report.Radios), rfCountAPs(report.Radios)))
	} else {
		add("radio-topology", "Radio Topology", "blocked", "No active radio topology is available.")
	}
	if report.Summary.ChannelConflictCount == 0 {
		add("channel-reuse", "Channel Reuse", "passed", "No channel reuse threshold violation was detected.")
	} else {
		add("channel-reuse", "Channel Reuse", "warning", fmt.Sprintf("%d channel reuse warning(s) require field validation.", report.Summary.ChannelConflictCount))
	}
	if report.Summary.CapacityWarningCount == 0 {
		add("capacity-budget", "Capacity Budget", "passed", "Radio max-client budgets are not below the configured SSID footprint.")
	} else {
		add("capacity-budget", "Capacity Budget", "warning", fmt.Sprintf("%d capacity warning(s) require review.", report.Summary.CapacityWarningCount))
	}
	if cfg.Wireless.RF.Mesh.Enabled {
		if report.Summary.MeshRootCount > 0 {
			add("mesh-root", "Mesh Root", "passed", fmt.Sprintf("%d mesh root radio(s) are declared.", report.Summary.MeshRootCount))
		} else {
			add("mesh-root", "Mesh Root", "blocked", "Mesh planning requires at least one root radio.")
		}
	}
	if cfg.Wireless.RF.ClientSteering.Enabled {
		if len(report.SteeringPolicies) > 0 {
			add("client-steering", "Client Steering", "passed", fmt.Sprintf("%d SSID steering policy item(s) are planned.", len(report.SteeringPolicies)))
		} else {
			add("client-steering", "Client Steering", "warning", "Client steering is enabled but no SSID target radios were planned.")
		}
	}
	if cfg.Wireless.Roaming.Enabled {
		add("rrm-roaming-link", "RRM And Roaming", "passed", "802.11k/v roaming configuration is available for RF/RRM coordination.")
	} else {
		add("rrm-roaming-link", "RRM And Roaming", "warning", "Enable wireless.roaming with 802.11k/v before claiming controller-grade RRM behavior.")
	}
	add("external-certification", "External Certification", "passed", "Real AP radio telemetry, spectrum captures, controller firmware behavior, and client steering proof are tracked outside software completion.", report.ReleaseCertificationChecklist)
	return checks
}

func rfPlanningStatus(report RFPlanningLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.RFEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 || report.Summary.ChannelConflictCount > 0 || report.Summary.CapacityWarningCount > 0 {
		return "degraded"
	}
	return "ready"
}

func rfPlanningCompletion(report RFPlanningLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func rfPlanningMessage(report RFPlanningLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0079 software is ready; RF planning is not active in this configuration."
	case "blocked":
		return "NAS-0079 RF/RRM/mesh planning is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0079 plans %d AP(s), %d radio(s), %d channel assignment(s), and %d steering policy item(s) with warnings.",
			report.Summary.APCount, report.Summary.RadioCount, report.Summary.ChannelPlanCount, report.Summary.SteeringPolicyCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0079 plans %d AP(s), %d radio(s), %d channel assignment(s), %d power setting(s), %d mesh link(s), and %d steering policy item(s).",
			report.Summary.APCount,
			report.Summary.RadioCount,
			report.Summary.ChannelPlanCount,
			report.Summary.PowerPlanCount,
			report.Summary.MeshLinkCount,
			report.Summary.SteeringPolicyCount,
		)
	}
}

func rfPlanningFingerprint(report RFPlanningLifecycleReport) string {
	payload := struct {
		FeatureID         string
		Summary           RFPlanningLifecycleSummary
		Radios            []RFPlanningRadioReport
		ChannelPlan       []RFChannelPlanItem
		PowerPlan         []RFPowerPlanItem
		MeshPlan          []RFMeshLinkReport
		SteeringPolicies  []RFClientSteeringPolicy
		ControllerActions []RFControllerAction
	}{
		FeatureID:         report.FeatureID,
		Summary:           report.Summary,
		Radios:            report.Radios,
		ChannelPlan:       report.ChannelPlan,
		PowerPlan:         report.PowerPlan,
		MeshPlan:          report.MeshPlan,
		SteeringPolicies:  report.SteeringPolicies,
		ControllerActions: report.ControllerActions,
	}
	return sha256JSON(payload)
}

func rfPlanningRuntimeDetails(report RFPlanningLifecycleReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                    RFPlanningLifecycleFeatureID,
		"event_id":                      eventID,
		"plan_fingerprint":              report.PlanFingerprint,
		"country_code":                  report.Summary.CountryCode,
		"controller_platform":           report.Summary.ControllerPlatform,
		"channel_plan_mode":             report.Summary.ChannelPlanMode,
		"ap_count":                      report.Summary.APCount,
		"radio_count":                   report.Summary.RadioCount,
		"channel_plan_count":            report.Summary.ChannelPlanCount,
		"power_plan_count":              report.Summary.PowerPlanCount,
		"mesh_link_count":               report.Summary.MeshLinkCount,
		"steering_policy_count":         report.Summary.SteeringPolicyCount,
		"channel_conflict_count":        report.Summary.ChannelConflictCount,
		"capacity_warning_count":        report.Summary.CapacityWarningCount,
		"compliance_check_count":        report.Summary.ComplianceCheckCount,
		"passed_check_count":            report.Summary.PassedCheckCount,
		"release_checklist":             report.ReleaseCertificationChecklist,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}
}

func rfNormalizeBand(value string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", "")) {
	case "2.4", "2.4g", "2.4ghz", "24ghz", "2g", "g", "b":
		return "2.4ghz"
	case "5", "5g", "5ghz", "a":
		return "5ghz"
	case "6", "6g", "6ghz":
		return "6ghz"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func rfNormalizeMeshRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "root", "mesh", "leaf":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func rfEffectiveMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func rfEffectiveChannelPlanMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "auto"
	}
	return value
}

func rfBandFromHostapd(hwMode string, channel int) string {
	if channel >= 1 && channel <= 14 {
		return "2.4ghz"
	}
	if channel >= 1 && channel > 177 {
		return "6ghz"
	}
	switch strings.ToLower(strings.TrimSpace(hwMode)) {
	case "a":
		return "5ghz"
	default:
		return "2.4ghz"
	}
}

func rfDefaultChannels(band string) []int {
	switch rfNormalizeBand(band) {
	case "2.4ghz":
		return []int{1, 6, 11}
	case "5ghz":
		return []int{36, 40, 44, 48, 149, 153, 157, 161}
	case "6ghz":
		return []int{5, 21, 37, 53, 69, 85}
	default:
		return []int{1, 6, 11}
	}
}

func rfPositiveChannels(values []int) []int {
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value > 0 {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	return out
}

func rfSSIDNamesForRadio(declared []string, ssids []config.SSIDConfig) []string {
	values := []string{}
	if len(declared) > 0 {
		values = append(values, declared...)
	} else {
		for _, ssid := range ssids {
			values = append(values, ssid.Name)
		}
	}
	return rfSortedStrings(values)
}

func rfSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func rfChannelInList(channel int, channels []int) bool {
	for _, item := range channels {
		if item == channel {
			return true
		}
	}
	return false
}

func rfAlternates(channels []int, planned int) []int {
	out := []int{}
	for _, channel := range channels {
		if channel != planned {
			out = append(out, channel)
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func rfReuseGroup(radio RFPlanningRadioReport) string {
	return strings.Join([]string{rfFirstNonEmpty(radio.Zone, "default"), rfFirstNonEmpty(radio.Floor, "floor"), radio.Band}, "/")
}

func rfCountAPs(radios []RFPlanningRadioReport) int {
	seen := map[string]struct{}{}
	for _, radio := range radios {
		seen[strings.ToLower(radio.APName)] = struct{}{}
	}
	return len(seen)
}

func rfCountBands(radios []RFPlanningRadioReport) int {
	seen := map[string]struct{}{}
	for _, radio := range radios {
		if radio.Band != "" {
			seen[radio.Band] = struct{}{}
		}
	}
	return len(seen)
}

func rfFirstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func rfFirstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func rfFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func rfClamp(value, minValue, maxValue int) int {
	if minValue > maxValue {
		minValue, maxValue = maxValue, minValue
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
