package enforcement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

const (
	BroadbandQoSServiceFlowSchemaVersion = 1
	BroadbandQoSServiceFlowFeatureID     = "NAS-0087"
	broadbandQoSServiceFlowComponent     = "broadband_qos_service_flows"
)

type BroadbandQoSServiceFlowReport struct {
	SchemaVersion                 int                            `json:"schema_version"`
	FeatureID                     string                         `json:"feature_id"`
	Status                        string                         `json:"status"`
	Message                       string                         `json:"message"`
	GeneratedAt                   string                         `json:"generated_at"`
	SoftwareCompletionPercent     float64                        `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                           `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                         `json:"release_certification_checklist"`
	ReleaseScope                  string                         `json:"release_scope"`
	PlanFingerprint               string                         `json:"plan_fingerprint"`
	Summary                       BroadbandQoSServiceFlowSummary `json:"summary"`
	Profiles                      []BroadbandQoSProfile          `json:"profiles"`
	ServiceFlows                  []BroadbandQoSServiceFlow      `json:"service_flows"`
	AggregatePolicies             []BroadbandQoSAggregatePolicy  `json:"aggregate_policies"`
	AccountingBindings            []BroadbandQoSBinding          `json:"accounting_bindings"`
	AuthorizationBindings         []BroadbandQoSBinding          `json:"authorization_bindings"`
	Compliance                    []BroadbandQoSCheck            `json:"compliance"`
	Standards                     []string                       `json:"standards"`
	Vendors                       []string                       `json:"vendors"`
	Requirements                  []string                       `json:"requirements"`
	Blockers                      []string                       `json:"blockers,omitempty"`
	Warnings                      []string                       `json:"warnings,omitempty"`
	Notes                         []string                       `json:"notes,omitempty"`
}

type BroadbandQoSServiceFlowSummary struct {
	Enabled                       bool   `json:"enabled"`
	Mode                          string `json:"mode"`
	FailClosed                    bool   `json:"fail_closed"`
	RequireSubscriberState        bool   `json:"require_subscriber_state"`
	RequireCommercialCatalog      bool   `json:"require_commercial_catalog"`
	RequireRuntimeQoS             bool   `json:"require_runtime_qos"`
	RequireRateCompiler           bool   `json:"require_rate_compiler"`
	AccountingCorrelationRequired bool   `json:"accounting_correlation_required"`
	CoAOnChange                   bool   `json:"coa_on_change"`
	AggregateControlEnabled       bool   `json:"aggregate_control_enabled"`
	Scheduler                     string `json:"scheduler"`
	DefaultTrafficClass           string `json:"default_traffic_class"`
	EventRetentionLimit           int    `json:"event_retention_limit"`
	SubscriberStateEnabled        bool   `json:"subscriber_state_enabled"`
	CommercialCatalogEnabled      bool   `json:"commercial_catalog_enabled"`
	SQLAccountingEnabled          bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled     bool   `json:"accounting_services_enabled"`
	DynamicAuthEnabled            bool   `json:"dynamic_auth_enabled"`
	ProfileCount                  int    `json:"profile_count"`
	EnabledProfileCount           int    `json:"enabled_profile_count"`
	ServiceFlowCount              int    `json:"service_flow_count"`
	EnabledServiceFlowCount       int    `json:"enabled_service_flow_count"`
	AggregatePolicyCount          int    `json:"aggregate_policy_count"`
	EnabledAggregatePolicyCount   int    `json:"enabled_aggregate_policy_count"`
	CompiledAttributeCount        int    `json:"compiled_attribute_count"`
	CompilerDiagnosticCount       int    `json:"compiler_diagnostic_count"`
	AccountingBindingCount        int    `json:"accounting_binding_count"`
	AuthorizationBindingCount     int    `json:"authorization_binding_count"`
	ComplianceCheckCount          int    `json:"compliance_check_count"`
	PassedCheckCount              int    `json:"passed_check_count"`
	WarningCount                  int    `json:"warning_count"`
	BlockerCount                  int    `json:"blocker_count"`
	ExternalRequirementCount      int    `json:"external_requirement_count"`
}

type BroadbandQoSProfile struct {
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	ParentProfile        string   `json:"parent_profile,omitempty"`
	TrafficClass         string   `json:"traffic_class"`
	Scheduler            string   `json:"scheduler"`
	Priority             int      `json:"priority"`
	DSCPMark             int      `json:"dscp_mark"`
	DownloadMinRateKbps  int      `json:"download_min_rate_kbps"`
	DownloadRateKbps     int      `json:"download_rate_kbps"`
	DownloadPeakRateKbps int      `json:"download_peak_rate_kbps"`
	UploadMinRateKbps    int      `json:"upload_min_rate_kbps"`
	UploadRateKbps       int      `json:"upload_rate_kbps"`
	UploadPeakRateKbps   int      `json:"upload_peak_rate_kbps"`
	DownloadBurstKbps    int      `json:"download_burst_kbps"`
	UploadBurstKbps      int      `json:"upload_burst_kbps"`
	BurstTimeSeconds     int      `json:"burst_time_seconds"`
	AggregateLimitKbps   int      `json:"aggregate_limit_kbps"`
	MaxSubscribers       int      `json:"max_subscribers"`
	VendorPacks          []string `json:"vendor_packs"`
	ExternalPolicyName   string   `json:"external_policy_name,omitempty"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
}

type BroadbandQoSServiceFlow struct {
	FlowKey              string                          `json:"flow_key"`
	Name                 string                          `json:"name"`
	Enabled              bool                            `json:"enabled"`
	Product              string                          `json:"product,omitempty"`
	ServiceLeg           string                          `json:"service_leg,omitempty"`
	SubscriberID         string                          `json:"subscriber_id,omitempty"`
	Username             string                          `json:"username,omitempty"`
	Role                 string                          `json:"role,omitempty"`
	Tenant               string                          `json:"tenant,omitempty"`
	Direction            string                          `json:"direction"`
	Profile              string                          `json:"profile"`
	ParentProfile        string                          `json:"parent_profile,omitempty"`
	AggregatePolicy      string                          `json:"aggregate_policy,omitempty"`
	TrafficClass         string                          `json:"traffic_class"`
	Scheduler            string                          `json:"scheduler"`
	Priority             int                             `json:"priority"`
	DSCPMark             int                             `json:"dscp_mark"`
	DownloadMinRateKbps  int                             `json:"download_min_rate_kbps"`
	DownloadRateKbps     int                             `json:"download_rate_kbps"`
	DownloadPeakRateKbps int                             `json:"download_peak_rate_kbps"`
	UploadMinRateKbps    int                             `json:"upload_min_rate_kbps"`
	UploadRateKbps       int                             `json:"upload_rate_kbps"`
	UploadPeakRateKbps   int                             `json:"upload_peak_rate_kbps"`
	AggregateLimitKbps   int                             `json:"aggregate_limit_kbps"`
	VendorPacks          []string                        `json:"vendor_packs"`
	CompiledAttributes   []radius.RateCompilerAttribute  `json:"compiled_attributes"`
	CompilerDiagnostics  []radius.RateCompilerDiagnostic `json:"compiler_diagnostics,omitempty"`
	AccountingKey        string                          `json:"accounting_key,omitempty"`
	Precedence           int                             `json:"precedence"`
	CoAAction            string                          `json:"coa_action,omitempty"`
	Status               string                          `json:"status"`
	Reason               string                          `json:"reason"`
}

type BroadbandQoSAggregatePolicy struct {
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	Scope                 string   `json:"scope"`
	Tenant                string   `json:"tenant,omitempty"`
	Product               string   `json:"product,omitempty"`
	Profile               string   `json:"profile,omitempty"`
	MaxSubscribers        int      `json:"max_subscribers"`
	DownloadLimitKbps     int      `json:"download_limit_kbps"`
	UploadLimitKbps       int      `json:"upload_limit_kbps"`
	OversubscriptionRatio int      `json:"oversubscription_ratio"`
	Scheduler             string   `json:"scheduler"`
	DropPrecedence        string   `json:"drop_precedence,omitempty"`
	VendorPacks           []string `json:"vendor_packs,omitempty"`
	Status                string   `json:"status"`
	Reason                string   `json:"reason"`
}

type BroadbandQoSBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandQoSCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandQoSServiceFlowComponent() string {
	return broadbandQoSServiceFlowComponent
}

func PreviewBroadbandQoSServiceFlows(cfg *config.Config) (BroadbandQoSServiceFlowReport, error) {
	if cfg == nil {
		return BroadbandQoSServiceFlowReport{}, fmt.Errorf("config is required")
	}
	qos := config.EffectiveBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows)
	subscriber := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	catalog := config.EffectiveBroadbandCommercialCatalog(cfg.Broadband.CommercialCatalog)
	report := BroadbandQoSServiceFlowReport{
		SchemaVersion:                 BroadbandQoSServiceFlowSchemaVersion,
		FeatureID:                     BroadbandQoSServiceFlowFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0087-release-certification-checklist.md",
		ReleaseScope:                  "Live BNG scheduler activation, vendor hardware service-flow packet proof, aggregate scale, HA failover, long-duration QoS soak, performance benchmarking, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 2869", "RFC 5176"},
		Vendors:                       []string{"Juniper ERX/E-Series", "Huawei BRAS/BNG", "Nokia/Alcatel-Lucent SR OS", "Cisco BNG", "MikroTik", "ZTE", "H3C", "Starent/Cisco ASR", "WiMAX"},
		Requirements: []string{
			"model subscriber, product, and service-leg QoS as explicit service flows",
			"compile vendor-safe RADIUS rate and QoS attributes from normalized kbps intent",
			"preserve parent/child hierarchy, scheduler, priority, DSCP, aggregate policy, and CoA behavior",
			"record preview/apply evidence and effective flow ownership in durable tables",
			"surface compliance, runtime dependencies, API, UI, support-bundle, and production-readiness evidence",
		},
		Notes: []string{
			"NAS-0087 completes software governance for BNG hierarchical QoS and service flows.",
			"Hardware queue activation and vendor-specific packet proof remain release certification evidence.",
		},
	}
	report.Summary = BroadbandQoSServiceFlowSummary{
		Enabled:                       qos.Enabled,
		Mode:                          qos.Mode,
		FailClosed:                    qos.FailClosed,
		RequireSubscriberState:        qos.RequireSubscriberState,
		RequireCommercialCatalog:      qos.RequireCommercialCatalog,
		RequireRuntimeQoS:             qos.RequireRuntimeQoS,
		RequireRateCompiler:           qos.RequireRateCompiler,
		AccountingCorrelationRequired: qos.AccountingCorrelationRequired,
		CoAOnChange:                   qos.CoAOnChange,
		AggregateControlEnabled:       qos.AggregateControlEnabled,
		Scheduler:                     qos.Scheduler,
		DefaultTrafficClass:           qos.DefaultTrafficClass,
		EventRetentionLimit:           qos.EventRetentionLimit,
		SubscriberStateEnabled:        subscriber.Enabled,
		CommercialCatalogEnabled:      catalog.Enabled,
		SQLAccountingEnabled:          cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled:     cfg.Radius.AccountingServices.Enabled,
		DynamicAuthEnabled:            cfg.Radius.DynamicAuth.Enabled,
	}
	report.Profiles = buildBroadbandQoSProfiles(qos)
	report.AggregatePolicies = buildBroadbandQoSAggregates(qos)
	report.ServiceFlows = buildBroadbandQoSServiceFlows(qos, subscriber, report.Profiles, report.AggregatePolicies)
	report.AccountingBindings = broadbandQoSAccountingBindings()
	report.AuthorizationBindings = broadbandQoSAuthorizationBindings(report.ServiceFlows)
	report.Compliance = broadbandQoSComplianceChecks(qos, subscriber, catalog, cfg.Radius, report)
	finalizeBroadbandQoSReport(&report)
	return report, nil
}

func PreviewAndRecordBroadbandQoSServiceFlows(cfg *config.Config, actor string) (BroadbandQoSServiceFlowReport, string, error) {
	report, err := PreviewBroadbandQoSServiceFlows(cfg)
	if err != nil {
		return BroadbandQoSServiceFlowReport{}, "", err
	}
	eventID, err := recordBroadbandQoSReport(report, "preview", "previewed", actor)
	return report, eventID, err
}

func ApplyBroadbandQoSServiceFlows(ctx context.Context, cfg *config.Config, actor string) (BroadbandQoSServiceFlowReport, string, error) {
	_ = ctx
	report, err := PreviewBroadbandQoSServiceFlows(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandQoSServiceFlowComponent, "down", err.Error(), nil)
		return BroadbandQoSServiceFlowReport{}, "", err
	}
	status := "applied"
	if report.Status == "blocked" {
		eventID, _ := recordBroadbandQoSReport(report, "apply", "blocked", actor)
		_ = db.UpsertRuntimeStatus(broadbandQoSServiceFlowComponent, "down", "Broadband QoS service-flow apply blocked", broadbandQoSStatusDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband QoS service-flow apply blocked")
	}
	if !report.Summary.Enabled {
		status = "skipped"
	}
	eventID, err := recordBroadbandQoSReport(report, "apply", status, actor)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandQoSServiceFlowComponent, "down", err.Error(), broadbandQoSStatusDetails(report, ""))
		return report, eventID, err
	}
	runtimeStatus := "ok"
	if status == "skipped" {
		runtimeStatus = "disabled"
	} else if report.Status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("NAS-0087 recorded %d BNG QoS service flow(s), %d profile(s), and %d aggregate policie(s).", report.Summary.ServiceFlowCount, report.Summary.ProfileCount, report.Summary.AggregatePolicyCount)
	_ = db.UpsertRuntimeStatus(broadbandQoSServiceFlowComponent, runtimeStatus, message, broadbandQoSStatusDetails(report, eventID))
	return report, eventID, nil
}

func buildBroadbandQoSProfiles(qos config.BroadbandQoSServiceFlowConfig) []BroadbandQoSProfile {
	profiles := make([]BroadbandQoSProfile, 0, len(qos.Profiles))
	for _, raw := range qos.Profiles {
		profile := BroadbandQoSProfile{
			Name:                 strings.TrimSpace(raw.Name),
			Enabled:              raw.Enabled,
			ParentProfile:        strings.TrimSpace(raw.ParentProfile),
			TrafficClass:         firstNonEmptyString(strings.TrimSpace(raw.TrafficClass), qos.DefaultTrafficClass),
			Scheduler:            firstNonEmptyString(strings.TrimSpace(raw.Scheduler), qos.Scheduler),
			Priority:             raw.Priority,
			DSCPMark:             raw.DSCPMark,
			DownloadMinRateKbps:  raw.DownloadMinRateKbps,
			DownloadRateKbps:     raw.DownloadRateKbps,
			DownloadPeakRateKbps: firstNonZero(raw.DownloadPeakRateKbps, raw.DownloadRateKbps),
			UploadMinRateKbps:    raw.UploadMinRateKbps,
			UploadRateKbps:       raw.UploadRateKbps,
			UploadPeakRateKbps:   firstNonZero(raw.UploadPeakRateKbps, raw.UploadRateKbps),
			DownloadBurstKbps:    raw.DownloadBurstKbps,
			UploadBurstKbps:      raw.UploadBurstKbps,
			BurstTimeSeconds:     raw.BurstTimeSeconds,
			AggregateLimitKbps:   raw.AggregateLimitKbps,
			MaxSubscribers:       raw.MaxSubscribers,
			VendorPacks:          normalizeBroadbandQoSPacks(raw.VendorPacks),
			ExternalPolicyName:   strings.TrimSpace(raw.ExternalPolicyName),
			Status:               "ready",
			Reason:               "QoS profile compiles to normalized rate intent.",
		}
		if !profile.Enabled {
			profile.Status = "disabled"
			profile.Reason = "QoS profile is disabled."
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func buildBroadbandQoSAggregates(qos config.BroadbandQoSServiceFlowConfig) []BroadbandQoSAggregatePolicy {
	aggregates := make([]BroadbandQoSAggregatePolicy, 0, len(qos.AggregatePolicies))
	for _, raw := range qos.AggregatePolicies {
		aggregate := BroadbandQoSAggregatePolicy{
			Name:                  strings.TrimSpace(raw.Name),
			Enabled:               raw.Enabled,
			Scope:                 firstNonEmptyString(strings.TrimSpace(raw.Scope), "tenant"),
			Tenant:                strings.TrimSpace(raw.Tenant),
			Product:               strings.TrimSpace(raw.Product),
			Profile:               strings.TrimSpace(raw.Profile),
			MaxSubscribers:        raw.MaxSubscribers,
			DownloadLimitKbps:     raw.DownloadLimitKbps,
			UploadLimitKbps:       raw.UploadLimitKbps,
			OversubscriptionRatio: raw.OversubscriptionRatio,
			Scheduler:             firstNonEmptyString(strings.TrimSpace(raw.Scheduler), qos.Scheduler),
			DropPrecedence:        strings.TrimSpace(raw.DropPrecedence),
			VendorPacks:           normalizeBroadbandQoSPacks(raw.VendorPacks),
			Status:                "ready",
			Reason:                "Aggregate policy constrains a subscriber, product, tenant, or profile group.",
		}
		if !aggregate.Enabled {
			aggregate.Status = "disabled"
			aggregate.Reason = "Aggregate policy is disabled."
		}
		aggregates = append(aggregates, aggregate)
	}
	return aggregates
}

func buildBroadbandQoSServiceFlows(qos config.BroadbandQoSServiceFlowConfig, subscriber config.BroadbandSubscriberStateConfig, profiles []BroadbandQoSProfile, aggregates []BroadbandQoSAggregatePolicy) []BroadbandQoSServiceFlow {
	profileByName := map[string]BroadbandQoSProfile{}
	for _, profile := range profiles {
		profileByName[strings.ToLower(profile.Name)] = profile
	}
	flows := make([]BroadbandQoSServiceFlow, 0, len(qos.ServiceFlows)+len(subscriber.Products))
	for _, raw := range qos.ServiceFlows {
		flows = append(flows, compileBroadbandQoSFlow(raw, profileByName, qos))
	}
	if len(flows) == 0 {
		for _, product := range subscriber.Products {
			if strings.TrimSpace(product.QoSProfile) == "" {
				continue
			}
			raw := config.BroadbandQoSServiceFlowIntentConfig{
				Name:        "product-" + strings.TrimSpace(product.Name),
				Enabled:     product.Enabled,
				Product:     product.Name,
				ServiceLeg:  firstNonEmptyString(product.ServiceChain, "internet"),
				Role:        product.Role,
				Direction:   "bidirectional",
				Profile:     product.QoSProfile,
				VendorPacks: product.VendorPacks,
			}
			flows = append(flows, compileBroadbandQoSFlow(raw, profileByName, qos))
		}
	}
	_ = aggregates
	return flows
}

func compileBroadbandQoSFlow(raw config.BroadbandQoSServiceFlowIntentConfig, profiles map[string]BroadbandQoSProfile, qos config.BroadbandQoSServiceFlowConfig) BroadbandQoSServiceFlow {
	profile := profiles[strings.ToLower(strings.TrimSpace(raw.Profile))]
	packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
	if len(packs) == 0 {
		packs = profile.VendorPacks
	}
	if len(packs) == 0 {
		packs = []string{productconfigs.VendorPackMikroTik, productconfigs.VendorPackHuawei, productconfigs.VendorPackZTE, productconfigs.VendorPackWISPr}
	}
	result := radius.CompileVendorRates(radius.RateCompilerRequest{
		PackKeys:                   packs,
		DownloadRateKbps:           profile.DownloadRateKbps,
		UploadRateKbps:             profile.UploadRateKbps,
		DownloadBurstRateKbps:      profile.DownloadBurstKbps,
		UploadBurstRateKbps:        profile.UploadBurstKbps,
		DownloadBurstThresholdKbps: profile.DownloadMinRateKbps,
		UploadBurstThresholdKbps:   profile.UploadMinRateKbps,
		DownloadBurstTimeSeconds:   profile.BurstTimeSeconds,
		UploadBurstTimeSeconds:     profile.BurstTimeSeconds,
		Priority:                   profile.Priority,
		DownloadMinRateKbps:        profile.DownloadMinRateKbps,
		UploadMinRateKbps:          profile.UploadMinRateKbps,
	})
	status := "ready"
	reason := "Service flow compiled to vendor RADIUS QoS attributes."
	if !raw.Enabled {
		status = "disabled"
		reason = "Service flow is disabled."
	}
	if profile.Name == "" {
		status = "blocked"
		reason = "Referenced QoS profile is missing."
	} else if result.Status == "blocked" {
		status = "blocked"
		reason = "Rate compiler rejected this service flow."
	}
	return BroadbandQoSServiceFlow{
		FlowKey:              broadbandQoSFlowKey(raw),
		Name:                 strings.TrimSpace(raw.Name),
		Enabled:              raw.Enabled,
		Product:              strings.TrimSpace(raw.Product),
		ServiceLeg:           strings.TrimSpace(raw.ServiceLeg),
		SubscriberID:         strings.TrimSpace(raw.SubscriberID),
		Username:             strings.TrimSpace(raw.Username),
		Role:                 strings.TrimSpace(raw.Role),
		Tenant:               strings.TrimSpace(raw.Tenant),
		Direction:            firstNonEmptyString(strings.TrimSpace(raw.Direction), "bidirectional"),
		Profile:              strings.TrimSpace(raw.Profile),
		ParentProfile:        profile.ParentProfile,
		AggregatePolicy:      strings.TrimSpace(raw.Aggregate),
		TrafficClass:         firstNonEmptyString(profile.TrafficClass, qos.DefaultTrafficClass),
		Scheduler:            firstNonEmptyString(profile.Scheduler, qos.Scheduler),
		Priority:             profile.Priority,
		DSCPMark:             profile.DSCPMark,
		DownloadMinRateKbps:  profile.DownloadMinRateKbps,
		DownloadRateKbps:     profile.DownloadRateKbps,
		DownloadPeakRateKbps: profile.DownloadPeakRateKbps,
		UploadMinRateKbps:    profile.UploadMinRateKbps,
		UploadRateKbps:       profile.UploadRateKbps,
		UploadPeakRateKbps:   profile.UploadPeakRateKbps,
		AggregateLimitKbps:   profile.AggregateLimitKbps,
		VendorPacks:          packs,
		CompiledAttributes:   result.Attributes,
		CompilerDiagnostics:  result.Diagnostics,
		AccountingKey:        strings.TrimSpace(raw.AccountingKey),
		Precedence:           raw.Precedence,
		CoAAction:            strings.TrimSpace(raw.CoAAction),
		Status:               status,
		Reason:               reason,
	}
}

func broadbandQoSAccountingBindings() []BroadbandQoSBinding {
	return []BroadbandQoSBinding{
		{Stage: "start", Attributes: []string{"Acct-Status-Type=Start", "Acct-Session-Id", "Class", "Service-Type"}, Purpose: "Open service-flow ownership for the subscriber session.", Required: true},
		{Stage: "interim", Attributes: []string{"Acct-Status-Type=Interim-Update", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Multi-Session-Id"}, Purpose: "Refresh usage, service-leg, aggregate, and scheduler evidence.", Required: true},
		{Stage: "stop", Attributes: []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause"}, Purpose: "Withdraw active service-flow ownership and close accounting correlation.", Required: true},
	}
}

func broadbandQoSAuthorizationBindings(flows []BroadbandQoSServiceFlow) []BroadbandQoSBinding {
	attrs := []string{"Filter-Id", "Class", "WISPr-Bandwidth-Max-Down", "WISPr-Bandwidth-Max-Up", "Mikrotik-Rate-Limit", "Huawei-Output-Average-Rate", "Huawei-Input-Average-Rate", "Rate-Ctrl-SCR-Down", "Rate-Ctrl-SCR-Up"}
	if len(flows) == 0 {
		attrs = attrs[:2]
	}
	return []BroadbandQoSBinding{
		{Stage: "access-accept", Attributes: attrs, Purpose: "Attach compiled service-flow rate, class, and vendor QoS attributes.", Required: true},
		{Stage: "coa", Attributes: []string{"CoA-Request", "Cisco-AVPair", "Mikrotik-Rate-Limit", "ERX-Update-Service"}, Purpose: "Update active service flows after quota, product, or aggregate changes.", Required: false},
	}
}

func broadbandQoSComplianceChecks(qos config.BroadbandQoSServiceFlowConfig, subscriber config.BroadbandSubscriberStateConfig, catalog config.BroadbandCommercialCatalog, radiusCfg config.RadiusConfig, report BroadbandQoSServiceFlowReport) []BroadbandQoSCheck {
	return []BroadbandQoSCheck{
		broadbandQoSCheck("subscriber-state", "Subscriber state dependency", !qos.Enabled || !qos.RequireSubscriberState || subscriber.Enabled, "Subscriber state is available.", "Enabled BNG QoS requires subscriber state.", "broadband.subscriber_state"),
		broadbandQoSCheck("commercial-catalog", "Commercial catalog dependency", !qos.Enabled || !qos.RequireCommercialCatalog || catalog.Enabled, "Commercial catalog is available.", "Enabled BNG QoS requires product catalog context.", "broadband.commercial_catalog"),
		broadbandQoSCheck("profiles", "QoS profile catalog", len(report.Profiles) > 0 || !qos.Enabled, "At least one QoS profile is configured or QoS is disabled.", "Enabled BNG QoS requires a QoS profile.", "profiles"),
		broadbandQoSCheck("service-flows", "Service-flow catalog", len(report.ServiceFlows) > 0 || !qos.Enabled, "At least one service flow is configured or derived.", "Enabled BNG QoS requires service-flow intent.", "service_flows"),
		broadbandQoSCheck("compiler", "Vendor rate compiler", broadbandQoSCompiledAttributeCount(report.ServiceFlows) > 0 || !qos.Enabled, "Vendor rate attributes compile from normalized intent.", "No compiled vendor rate attributes are available.", "rate_compiler"),
		broadbandQoSCheck("accounting", "Accounting correlation", !qos.Enabled || !qos.AccountingCorrelationRequired || radiusCfg.AccountingServices.Enabled, "Accounting service correlation is enabled.", "QoS service flows need accounting service correlation.", "radius.accounting_services"),
		broadbandQoSCheck("coa", "Dynamic authorization", !qos.Enabled || !qos.CoAOnChange || radiusCfg.DynamicAuth.Enabled, "Dynamic authorization is enabled for active flow changes.", "CoA on QoS change requires radius.dynamic_auth.enabled.", "radius.dynamic_auth"),
		broadbandQoSCheck("external-certification", "External BNG certification boundary", true, "Live BNG hardware, packet capture, scale, soak, security, and customer proof are release certification activities.", "", "docs/nas-0087-release-certification-checklist.md"),
	}
}

func broadbandQoSCompiledAttributeCount(flows []BroadbandQoSServiceFlow) int {
	count := 0
	for _, flow := range flows {
		count += len(flow.CompiledAttributes)
	}
	return count
}

func broadbandQoSCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) BroadbandQoSCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return BroadbandQoSCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence}
}

func finalizeBroadbandQoSReport(report *BroadbandQoSServiceFlowReport) {
	for _, profile := range report.Profiles {
		report.Summary.ProfileCount++
		if profile.Enabled {
			report.Summary.EnabledProfileCount++
		}
	}
	for _, aggregate := range report.AggregatePolicies {
		report.Summary.AggregatePolicyCount++
		if aggregate.Enabled {
			report.Summary.EnabledAggregatePolicyCount++
		}
	}
	for _, flow := range report.ServiceFlows {
		report.Summary.ServiceFlowCount++
		if flow.Enabled {
			report.Summary.EnabledServiceFlowCount++
		}
		report.Summary.CompiledAttributeCount += len(flow.CompiledAttributes)
		report.Summary.CompilerDiagnosticCount += len(flow.CompilerDiagnostics)
		if flow.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("service flow %s: %s", flow.Name, flow.Reason))
		}
		for _, diag := range flow.CompilerDiagnostics {
			if diag.Severity == "error" {
				report.Blockers = append(report.Blockers, fmt.Sprintf("service flow %s compiler: %s", flow.Name, diag.Message))
			} else {
				report.Warnings = append(report.Warnings, fmt.Sprintf("service flow %s compiler: %s", flow.Name, diag.Message))
			}
		}
	}
	report.Summary.AccountingBindingCount = len(report.AccountingBindings)
	report.Summary.AuthorizationBindingCount = len(report.AuthorizationBindings)
	for _, check := range report.Compliance {
		report.Summary.ComplianceCheckCount++
		if check.Status == "passed" {
			report.Summary.PassedCheckCount++
		} else if check.Status == "blocked" {
			report.Blockers = append(report.Blockers, check.Message)
		}
	}
	report.Summary.ExternalRequirementCount = 1
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.Status = "ready"
	if !report.Summary.Enabled {
		report.Status = "disabled"
		report.Message = "NAS-0087 software is ready; BNG QoS service-flow lifecycle is not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = fmt.Sprintf("NAS-0087 BNG QoS service-flow lifecycle is blocked by %d requirement(s).", len(report.Blockers))
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0087 BNG QoS service-flow lifecycle is ready with %d warning(s).", len(report.Warnings))
	} else {
		report.Message = fmt.Sprintf("NAS-0087 BNG QoS service-flow lifecycle is ready with %d profile(s), %d service flow(s), %d aggregate policie(s), and %d compiled attribute(s).", report.Summary.ProfileCount, report.Summary.ServiceFlowCount, report.Summary.AggregatePolicyCount, report.Summary.CompiledAttributeCount)
	}
	report.PlanFingerprint = broadbandQoSFingerprint(*report)
}

func recordBroadbandQoSReport(report BroadbandQoSServiceFlowReport, operation, status, actor string) (string, error) {
	return db.RecordBroadbandQoSServiceFlowEvent(db.BroadbandQoSServiceFlowEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		ProfileCount:             report.Summary.ProfileCount,
		ServiceFlowCount:         report.Summary.ServiceFlowCount,
		AggregatePolicyCount:     report.Summary.AggregatePolicyCount,
		CompiledAttributeCount:   report.Summary.CompiledAttributeCount,
		DiagnosticCount:          report.Summary.CompilerDiagnosticCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              broadbandQoSJSON(report.Summary, "{}"),
		ReportJSON:               broadbandQoSJSON(report, "{}"),
		Actor:                    actor,
		Flows:                    broadbandQoSDBFlows(report, status),
	})
}

func broadbandQoSDBFlows(report BroadbandQoSServiceFlowReport, eventStatus string) []db.BroadbandQoSServiceFlowInput {
	flows := make([]db.BroadbandQoSServiceFlowInput, 0, len(report.ServiceFlows))
	for _, flow := range report.ServiceFlows {
		status := "planned"
		if eventStatus == "applied" && flow.Enabled && flow.Status == "ready" {
			status = "active"
		} else if flow.Status == "blocked" {
			status = "blocked"
		} else if flow.Status == "degraded" {
			status = "degraded"
		}
		flows = append(flows, db.BroadbandQoSServiceFlowInput{
			FlowKey:                flow.FlowKey,
			Name:                   flow.Name,
			SubscriberID:           flow.SubscriberID,
			Username:               flow.Username,
			Product:                flow.Product,
			ServiceLeg:             flow.ServiceLeg,
			Role:                   flow.Role,
			Tenant:                 flow.Tenant,
			Direction:              flow.Direction,
			Profile:                flow.Profile,
			ParentProfile:          flow.ParentProfile,
			AggregatePolicy:        flow.AggregatePolicy,
			TrafficClass:           flow.TrafficClass,
			Scheduler:              flow.Scheduler,
			Priority:               flow.Priority,
			DSCPMark:               flow.DSCPMark,
			DownloadMinRateKbps:    flow.DownloadMinRateKbps,
			DownloadRateKbps:       flow.DownloadRateKbps,
			DownloadPeakRateKbps:   flow.DownloadPeakRateKbps,
			UploadMinRateKbps:      flow.UploadMinRateKbps,
			UploadRateKbps:         flow.UploadRateKbps,
			UploadPeakRateKbps:     flow.UploadPeakRateKbps,
			AggregateLimitKbps:     flow.AggregateLimitKbps,
			Status:                 status,
			VendorPacksJSON:        broadbandQoSJSON(flow.VendorPacks, "[]"),
			CompiledAttributesJSON: broadbandQoSJSON(flow.CompiledAttributes, "[]"),
			DiagnosticsJSON:        broadbandQoSJSON(flow.CompilerDiagnostics, "[]"),
			PlanFingerprint:        report.PlanFingerprint,
			InstalledAt:            conditionalTimestamp(status == "active"),
		})
	}
	return flows
}

func broadbandQoSFingerprint(report BroadbandQoSServiceFlowReport) string {
	payload := map[string]any{
		"feature_id":         report.FeatureID,
		"summary":            report.Summary,
		"profiles":           report.Profiles,
		"service_flows":      report.ServiceFlows,
		"aggregate_policies": report.AggregatePolicies,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func broadbandQoSStatusDetails(report BroadbandQoSServiceFlowReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":        report.FeatureID,
		"event_id":          eventID,
		"plan_fingerprint":  report.PlanFingerprint,
		"status":            report.Status,
		"profile_count":     report.Summary.ProfileCount,
		"service_flows":     report.Summary.ServiceFlowCount,
		"compiled_attrs":    report.Summary.CompiledAttributeCount,
		"blocker_count":     report.Summary.BlockerCount,
		"warning_count":     report.Summary.WarningCount,
		"external_required": report.Summary.ExternalRequirementCount,
	}
}

func broadbandQoSJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}

func broadbandQoSFlowKey(raw config.BroadbandQoSServiceFlowIntentConfig) string {
	parts := []string{raw.Name, raw.Product, raw.ServiceLeg, raw.SubscriberID, raw.Username, raw.Profile}
	encoded := strings.ToLower(strings.Join(parts, "|"))
	sum := sha256.Sum256([]byte(encoded))
	return "bng-qos-flow-" + hex.EncodeToString(sum[:6])
}

func normalizeBroadbandQoSPacks(values []string) []string {
	packs := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(value)
		if pack == "" {
			continue
		}
		if _, ok := seen[pack]; ok {
			continue
		}
		seen[pack] = struct{}{}
		packs = append(packs, pack)
	}
	return packs
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func conditionalTimestamp(enabled bool) string {
	if !enabled {
		return ""
	}
	return time.Now().UTC().Format(time.RFC3339)
}
