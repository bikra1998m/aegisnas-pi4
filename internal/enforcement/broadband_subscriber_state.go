package enforcement

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/broadband/subscriber"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	BroadbandSubscriberStateSchemaVersion = 1
	BroadbandSubscriberStateFeatureID     = "NAS-0083"
	broadbandSubscriberStateComponent     = "broadband_subscriber_state"
)

type BroadbandSubscriberStateReport struct {
	SchemaVersion                 int                                    `json:"schema_version"`
	FeatureID                     string                                 `json:"feature_id"`
	Status                        string                                 `json:"status"`
	Message                       string                                 `json:"message"`
	GeneratedAt                   string                                 `json:"generated_at"`
	SoftwareCompletionPercent     float64                                `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                                   `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                                 `json:"release_certification_checklist"`
	ReleaseScope                  string                                 `json:"release_scope"`
	PlanFingerprint               string                                 `json:"plan_fingerprint"`
	Summary                       BroadbandSubscriberStateSummary        `json:"summary"`
	States                        []BroadbandSubscriberStateNode         `json:"states"`
	Transitions                   []BroadbandSubscriberTransitionReport  `json:"transitions"`
	Products                      []BroadbandSubscriberProductReport     `json:"products"`
	ServicePolicies               []BroadbandSubscriberServicePolicy     `json:"service_policies"`
	FailurePolicies               []BroadbandSubscriberFailurePolicy     `json:"failure_policies"`
	AccountingCorrelation         []BroadbandSubscriberAccountingBinding `json:"accounting_correlation"`
	Compliance                    []BroadbandSubscriberComplianceCheck   `json:"compliance"`
	Standards                     []string                               `json:"standards"`
	Vendors                       []string                               `json:"vendors"`
	Requirements                  []string                               `json:"requirements"`
	Blockers                      []string                               `json:"blockers,omitempty"`
	Warnings                      []string                               `json:"warnings,omitempty"`
	Notes                         []string                               `json:"notes,omitempty"`
}

type BroadbandSubscriberStateSummary struct {
	Enabled                   bool   `json:"enabled"`
	Mode                      string `json:"mode"`
	FailClosed                bool   `json:"fail_closed"`
	DefaultAccessMethod       string `json:"default_access_method"`
	MaxSessions               int    `json:"max_sessions"`
	MaxSessionsPerSubscriber  int    `json:"max_sessions_per_subscriber"`
	MaxReconnects             int    `json:"max_reconnects"`
	ReconnectWindowSeconds    int    `json:"reconnect_window_seconds"`
	AccountingGraceSeconds    int    `json:"accounting_grace_seconds"`
	RecoveryScanSeconds       int    `json:"recovery_scan_seconds"`
	RequireAccountingStart    bool   `json:"require_accounting_start"`
	RequireAccountingStop     bool   `json:"require_accounting_stop"`
	RequireSessionOwnership   bool   `json:"require_session_ownership"`
	ServiceLegsEnabled        bool   `json:"service_legs_enabled"`
	PolicyTransitionsEnabled  bool   `json:"policy_transitions_enabled"`
	ReconnectRecoveryEnabled  bool   `json:"reconnect_recovery_enabled"`
	QuotaHooksEnabled         bool   `json:"quota_hooks_enabled"`
	ChargingHooksEnabled      bool   `json:"charging_hooks_enabled"`
	WholesaleEnabled          bool   `json:"wholesale_enabled"`
	DualStackRequired         bool   `json:"dual_stack_required"`
	RoutePolicyRequired       bool   `json:"route_policy_required"`
	QoSRequired               bool   `json:"qos_required"`
	NATRequired               bool   `json:"nat_required"`
	CoARequired               bool   `json:"coa_required"`
	SQLAccountingEnabled      bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled bool   `json:"accounting_services_enabled"`
	PPPoEEnabled              bool   `json:"pppoe_enabled"`
	DynamicAuthEnabled        bool   `json:"dynamic_auth_enabled"`
	AddressPolicyEnabled      bool   `json:"address_policy_enabled"`
	RoutePolicyEnabled        bool   `json:"route_policy_enabled"`
	TranslationPolicyEnabled  bool   `json:"translation_policy_enabled"`
	HighAvailabilityEnabled   bool   `json:"high_availability_enabled"`
	ProductCount              int    `json:"product_count"`
	EnabledProductCount       int    `json:"enabled_product_count"`
	ServicePolicyCount        int    `json:"service_policy_count"`
	EnabledServicePolicyCount int    `json:"enabled_service_policy_count"`
	FailurePolicyCount        int    `json:"failure_policy_count"`
	EnabledFailurePolicyCount int    `json:"enabled_failure_policy_count"`
	StateCount                int    `json:"state_count"`
	TransitionCount           int    `json:"transition_count"`
	RequiredTransitionCount   int    `json:"required_transition_count"`
	AccountingTransitionCount int    `json:"accounting_transition_count"`
	RecoveryTransitionCount   int    `json:"recovery_transition_count"`
	ComplianceCheckCount      int    `json:"compliance_check_count"`
	PassedCheckCount          int    `json:"passed_check_count"`
	WarningCount              int    `json:"warning_count"`
	BlockerCount              int    `json:"blocker_count"`
	ExternalRequirementCount  int    `json:"external_requirement_count"`
}

type BroadbandSubscriberStateNode struct {
	Name        string `json:"name"`
	Terminal    bool   `json:"terminal"`
	Recoverable bool   `json:"recoverable"`
	Purpose     string `json:"purpose"`
}

type BroadbandSubscriberTransitionReport struct {
	From        string   `json:"from"`
	Event       string   `json:"event"`
	To          string   `json:"to"`
	Required    bool     `json:"required"`
	Accounting  bool     `json:"accounting"`
	Recoverable bool     `json:"recoverable"`
	Actions     []string `json:"actions"`
	Description string   `json:"description"`
}

type BroadbandSubscriberProductReport struct {
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	Role                  string   `json:"role,omitempty"`
	ServiceChain          string   `json:"service_chain,omitempty"`
	AddressPool           string   `json:"address_pool,omitempty"`
	IPv6Pool              string   `json:"ipv6_pool,omitempty"`
	DelegatedIPv6Pool     string   `json:"delegated_ipv6_pool,omitempty"`
	RoutePolicy           string   `json:"route_policy,omitempty"`
	QoSProfile            string   `json:"qos_profile,omitempty"`
	TranslationPool       string   `json:"translation_pool,omitempty"`
	QuotaProfile          string   `json:"quota_profile,omitempty"`
	MaxSessions           int      `json:"max_sessions,omitempty"`
	SessionTimeoutSeconds int      `json:"session_timeout_seconds,omitempty"`
	IdleTimeoutSeconds    int      `json:"idle_timeout_seconds,omitempty"`
	VendorPacks           []string `json:"vendor_packs,omitempty"`
	Status                string   `json:"status"`
	Reason                string   `json:"reason"`
}

type BroadbandSubscriberServicePolicy struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Product         string   `json:"product,omitempty"`
	Leg             string   `json:"leg,omitempty"`
	Trigger         string   `json:"trigger,omitempty"`
	RequiredState   string   `json:"required_state,omitempty"`
	NextState       string   `json:"next_state,omitempty"`
	AccountingClass string   `json:"accounting_class,omitempty"`
	CoAAction       string   `json:"coa_action,omitempty"`
	RoutePolicy     string   `json:"route_policy,omitempty"`
	QoSProfile      string   `json:"qos_profile,omitempty"`
	TranslationPool string   `json:"translation_pool,omitempty"`
	VendorPacks     []string `json:"vendor_packs,omitempty"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
}

type BroadbandSubscriberFailurePolicy struct {
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	Failure              string `json:"failure,omitempty"`
	Action               string `json:"action,omitempty"`
	TargetState          string `json:"target_state,omitempty"`
	DisconnectRequired   bool   `json:"disconnect_required"`
	CoARequired          bool   `json:"coa_required"`
	RecoveryAfterSeconds int    `json:"recovery_after_seconds,omitempty"`
	Status               string `json:"status"`
	Reason               string `json:"reason"`
}

type BroadbandSubscriberAccountingBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandSubscriberComplianceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandSubscriberStateComponent() string {
	return broadbandSubscriberStateComponent
}

func PreviewBroadbandSubscriberState(cfg *config.Config) (BroadbandSubscriberStateReport, error) {
	if cfg == nil {
		return BroadbandSubscriberStateReport{}, fmt.Errorf("config is required")
	}
	state := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	pppoe := config.EffectiveBroadbandPPPoEConfig(cfg.Broadband.PPPoE)
	report := BroadbandSubscriberStateReport{
		SchemaVersion:                 BroadbandSubscriberStateSchemaVersion,
		FeatureID:                     BroadbandSubscriberStateFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0083-release-certification-checklist.md",
		ReleaseScope:                  "Live BRAS/BNG subscriber recovery, PPP/DHCP packet captures, commercial billing integration, wholesale handoff, HA failover, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 5176", "RFC 6888", "RFC 2516"},
		Vendors:                       []string{"Juniper ERX/E-Series", "Huawei BRAS/BNG", "H3C", "Nokia/Alcatel-Lucent SR OS", "ZTE", "Ericsson/Redback", "Calix", "Adtran", "MikroTik", "FreeRADIUS"},
		Requirements: []string{
			"subscriber sessions have deterministic state transitions from discovery through accounting stop",
			"accounting start/interim/stop records correlate Acct-Session-Id, NAS identity, access circuit, counters, product, and service legs",
			"reconnect recovery preserves ownership leases and rejects stale or conflicting live sessions",
			"policy transitions stage quota, route, QoS, NAT, service-chain, and CoA changes before commit",
			"preview/apply operations persist evidence and runtime status while external device certification remains explicit",
		},
		Notes: []string{
			"NAS-0083 completes software state governance for broadband subscribers and provides DB foundations for product, quota, address, QoS, and activation features.",
			"Live BNG packet and commercial billing certification remains release evidence per exact vendor, product, firmware, and customer scope.",
		},
	}
	report.Summary = BroadbandSubscriberStateSummary{
		Enabled:                   state.Enabled,
		Mode:                      state.Mode,
		FailClosed:                state.FailClosed,
		DefaultAccessMethod:       strings.ToLower(strings.TrimSpace(state.DefaultAccessMethod)),
		MaxSessions:               state.MaxSessions,
		MaxSessionsPerSubscriber:  state.MaxSessionsPerSubscriber,
		MaxReconnects:             state.MaxReconnects,
		ReconnectWindowSeconds:    state.ReconnectWindowSeconds,
		AccountingGraceSeconds:    state.AccountingGraceSeconds,
		RecoveryScanSeconds:       state.RecoveryScanSeconds,
		RequireAccountingStart:    state.RequireAccountingStart,
		RequireAccountingStop:     state.RequireAccountingStop,
		RequireSessionOwnership:   state.RequireSessionOwnership,
		ServiceLegsEnabled:        state.ServiceLegsEnabled,
		PolicyTransitionsEnabled:  state.PolicyTransitionsEnabled,
		ReconnectRecoveryEnabled:  state.ReconnectRecoveryEnabled,
		QuotaHooksEnabled:         state.QuotaHooksEnabled,
		ChargingHooksEnabled:      state.ChargingHooksEnabled,
		WholesaleEnabled:          state.WholesaleEnabled,
		DualStackRequired:         state.DualStackRequired,
		RoutePolicyRequired:       state.RoutePolicyRequired,
		QoSRequired:               state.QoSRequired,
		NATRequired:               state.NATRequired,
		CoARequired:               state.CoARequired,
		SQLAccountingEnabled:      cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled: cfg.Radius.AccountingServices.Enabled,
		PPPoEEnabled:              pppoe.Enabled,
		DynamicAuthEnabled:        cfg.Radius.DynamicAuth.Enabled,
		AddressPolicyEnabled:      cfg.Radius.AddressPolicy.Enabled,
		RoutePolicyEnabled:        cfg.Radius.RoutePolicy.Enabled,
		TranslationPolicyEnabled:  cfg.Radius.TranslationPolicy.Enabled,
		HighAvailabilityEnabled:   cfg.HighAvailability.Enabled,
		ExternalRequirementCount:  11,
	}
	report.States = buildBroadbandSubscriberStates()
	report.Transitions = buildBroadbandSubscriberTransitions()
	report.Products = buildBroadbandSubscriberProducts(state)
	report.ServicePolicies = buildBroadbandSubscriberServicePolicies(state)
	report.FailurePolicies = buildBroadbandSubscriberFailurePolicies(state)
	report.AccountingCorrelation = buildBroadbandSubscriberAccountingBindings(state)
	report.Summary.ProductCount = len(report.Products)
	report.Summary.ServicePolicyCount = len(report.ServicePolicies)
	report.Summary.FailurePolicyCount = len(report.FailurePolicies)
	report.Summary.StateCount = len(report.States)
	report.Summary.TransitionCount = len(report.Transitions)
	for _, product := range report.Products {
		if product.Enabled {
			report.Summary.EnabledProductCount++
		}
	}
	for _, policy := range report.ServicePolicies {
		if policy.Enabled {
			report.Summary.EnabledServicePolicyCount++
		}
	}
	for _, policy := range report.FailurePolicies {
		if policy.Enabled {
			report.Summary.EnabledFailurePolicyCount++
		}
	}
	for _, transition := range report.Transitions {
		if transition.Required {
			report.Summary.RequiredTransitionCount++
		}
		if transition.Accounting {
			report.Summary.AccountingTransitionCount++
		}
		if transition.Recoverable {
			report.Summary.RecoveryTransitionCount++
		}
	}
	if !state.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0083 software is ready; broadband subscriber state machine is not active in this configuration."
		report.Compliance = buildBroadbandSubscriberCompliance(cfg, state, report)
		report.Summary.ComplianceCheckCount = len(report.Compliance)
		report.Summary.PassedCheckCount = countBroadbandSubscriberCompliance(report.Compliance, "passed")
		report.PlanFingerprint = broadbandSubscriberStateFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}
	report.Compliance = buildBroadbandSubscriberCompliance(cfg, state, report)
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
	switch {
	case len(report.Blockers) > 0:
		report.Status = "blocked"
		report.ReadyForExternalValidation = false
		report.Message = fmt.Sprintf("NAS-0083 subscriber state machine is blocked by %d requirement(s).", len(report.Blockers))
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0083 subscriber state machine is ready with %d warning(s).", len(report.Warnings))
	default:
		report.Status = "ready"
		report.Message = fmt.Sprintf("NAS-0083 subscriber state machine is ready with %d state(s), %d transition(s), %d product(s), and %d service policie(s).",
			report.Summary.StateCount, report.Summary.TransitionCount, report.Summary.EnabledProductCount, report.Summary.EnabledServicePolicyCount)
	}
	report.PlanFingerprint = broadbandSubscriberStateFingerprint(report)
	return report, nil
}

func PreviewAndRecordBroadbandSubscriberState(cfg *config.Config, actor string) (BroadbandSubscriberStateReport, string, error) {
	report, err := PreviewBroadbandSubscriberState(cfg)
	if err != nil {
		return BroadbandSubscriberStateReport{}, "", err
	}
	eventID, err := recordBroadbandSubscriberStateEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyBroadbandSubscriberState(ctx context.Context, cfg *config.Config, actor string) (BroadbandSubscriberStateReport, string, error) {
	report, err := PreviewBroadbandSubscriberState(cfg)
	if err != nil {
		return BroadbandSubscriberStateReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordBroadbandSubscriberStateEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(broadbandSubscriberStateComponent, "down", report.Message, broadbandSubscriberStateRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband subscriber state apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0083 recorded subscriber state machine with %d transition(s), %d enabled product(s), and %d enabled service policie(s).",
			report.Summary.TransitionCount, report.Summary.EnabledProductCount, report.Summary.EnabledServicePolicyCount)
	}
	eventID, err := recordBroadbandSubscriberStateEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := broadbandSubscriberStateRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if report.Summary.WarningCount > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(broadbandSubscriberStateComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(broadbandSubscriberStateComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordBroadbandSubscriberStateEvent(report BroadbandSubscriberStateReport, operation, actor string) (string, error) {
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
	return db.RecordBroadbandSubscriberStateEvent(db.BroadbandSubscriberStateEventInput{
		Operation:                 operation,
		Status:                    status,
		PlanFingerprint:           report.PlanFingerprint,
		Mode:                      report.Summary.Mode,
		AccessMethod:              report.Summary.DefaultAccessMethod,
		ProductCount:              report.Summary.ProductCount,
		ServicePolicyCount:        report.Summary.ServicePolicyCount,
		FailurePolicyCount:        report.Summary.FailurePolicyCount,
		StateCount:                report.Summary.StateCount,
		TransitionCount:           report.Summary.TransitionCount,
		RequiredTransitionCount:   report.Summary.RequiredTransitionCount,
		AccountingTransitionCount: report.Summary.AccountingTransitionCount,
		RecoveryTransitionCount:   report.Summary.RecoveryTransitionCount,
		ComplianceCheckCount:      report.Summary.ComplianceCheckCount,
		PassedCheckCount:          report.Summary.PassedCheckCount,
		WarningCount:              report.Summary.WarningCount,
		BlockerCount:              report.Summary.BlockerCount,
		ExternalRequirementCount:  report.Summary.ExternalRequirementCount,
		SummaryJSON:               marshalJSON(report.Summary),
		ReportJSON:                marshalJSON(report),
		Actor:                     actor,
	})
}

func buildBroadbandSubscriberStates() []BroadbandSubscriberStateNode {
	return []BroadbandSubscriberStateNode{
		{"new", false, true, "Subscriber context has not received access evidence."},
		{"discovered", false, true, "Access circuit or PPPoE discovery is known."},
		{"authenticating", false, true, "RADIUS authentication is in progress."},
		{"authorized", false, true, "Product and role authorization has been selected."},
		{"address_assigned", false, true, "IPv4, IPv6, and delegated prefix state is bound."},
		{"service_active", false, true, "Service legs, routes, QoS, NAT, and wholesale policy are active."},
		{"accounting_started", false, true, "Accounting Start created durable session ownership."},
		{"interim_seen", false, true, "Accounting Interim refreshed counters and quota/charging hooks."},
		{"policy_update_pending", false, true, "A quota, service, route, QoS, NAT, or CoA delta is staged."},
		{"reconnecting", false, true, "Access flap recovery is preserving ownership within the reconnect window."},
		{"suspended", false, true, "Subscriber is administratively or quota suspended."},
		{"disconnecting", false, false, "Disconnect or forced teardown has been requested."},
		{"stopped", true, false, "Accounting Stop closed the session and resources are released."},
		{"recovered", false, true, "Recovery scanner reconciled a stale or reconnecting session."},
		{"failed", true, false, "Session failed closed before a safe active state."},
	}
}

func buildBroadbandSubscriberTransitions() []BroadbandSubscriberTransitionReport {
	transitions := subscriber.CanonicalTransitions()
	report := make([]BroadbandSubscriberTransitionReport, 0, len(transitions))
	for _, transition := range transitions {
		report = append(report, BroadbandSubscriberTransitionReport{
			From:        string(transition.From),
			Event:       string(transition.Event),
			To:          string(transition.To),
			Required:    transition.Required,
			Accounting:  transition.Accounting,
			Recoverable: transition.Recoverable,
			Actions:     append([]string{}, transition.Actions...),
			Description: transition.Description,
		})
	}
	return report
}

func buildBroadbandSubscriberProducts(state config.BroadbandSubscriberStateConfig) []BroadbandSubscriberProductReport {
	products := make([]BroadbandSubscriberProductReport, 0, len(state.Products))
	for _, product := range state.Products {
		status := "disabled"
		reason := "Product is configured but disabled."
		if product.Enabled {
			status = "ready"
			reason = "Product participates in subscriber authorization and service activation."
		}
		products = append(products, BroadbandSubscriberProductReport{
			Name:                  strings.TrimSpace(product.Name),
			Enabled:               product.Enabled,
			Role:                  strings.TrimSpace(product.Role),
			ServiceChain:          strings.TrimSpace(product.ServiceChain),
			AddressPool:           strings.TrimSpace(product.AddressPool),
			IPv6Pool:              strings.TrimSpace(product.IPv6Pool),
			DelegatedIPv6Pool:     strings.TrimSpace(product.DelegatedIPv6Pool),
			RoutePolicy:           strings.TrimSpace(product.RoutePolicy),
			QoSProfile:            strings.TrimSpace(product.QoSProfile),
			TranslationPool:       strings.TrimSpace(product.TranslationPool),
			QuotaProfile:          strings.TrimSpace(product.QuotaProfile),
			MaxSessions:           product.MaxSessions,
			SessionTimeoutSeconds: product.SessionTimeoutSeconds,
			IdleTimeoutSeconds:    product.IdleTimeoutSeconds,
			VendorPacks:           append([]string{}, product.VendorPacks...),
			Status:                status,
			Reason:                reason,
		})
	}
	return products
}

func buildBroadbandSubscriberServicePolicies(state config.BroadbandSubscriberStateConfig) []BroadbandSubscriberServicePolicy {
	policies := make([]BroadbandSubscriberServicePolicy, 0, len(state.ServicePolicies))
	for _, policy := range state.ServicePolicies {
		status := "disabled"
		reason := "Service policy is configured but disabled."
		if policy.Enabled {
			status = "ready"
			reason = "Service policy contributes a product/service-leg transition."
		}
		policies = append(policies, BroadbandSubscriberServicePolicy{
			Name:            strings.TrimSpace(policy.Name),
			Enabled:         policy.Enabled,
			Product:         strings.TrimSpace(policy.Product),
			Leg:             strings.TrimSpace(policy.Leg),
			Trigger:         strings.TrimSpace(policy.Trigger),
			RequiredState:   strings.TrimSpace(policy.RequiredState),
			NextState:       strings.TrimSpace(policy.NextState),
			AccountingClass: strings.TrimSpace(policy.AccountingClass),
			CoAAction:       strings.TrimSpace(policy.CoAAction),
			RoutePolicy:     strings.TrimSpace(policy.RoutePolicy),
			QoSProfile:      strings.TrimSpace(policy.QoSProfile),
			TranslationPool: strings.TrimSpace(policy.TranslationPool),
			VendorPacks:     append([]string{}, policy.VendorPacks...),
			Status:          status,
			Reason:          reason,
		})
	}
	return policies
}

func buildBroadbandSubscriberFailurePolicies(state config.BroadbandSubscriberStateConfig) []BroadbandSubscriberFailurePolicy {
	policies := make([]BroadbandSubscriberFailurePolicy, 0, len(state.FailurePolicies))
	for _, policy := range state.FailurePolicies {
		status := "disabled"
		reason := "Failure policy is configured but disabled."
		if policy.Enabled {
			status = "ready"
			reason = "Failure policy maps an operational failure to a deterministic recovery or fail-closed action."
		}
		policies = append(policies, BroadbandSubscriberFailurePolicy{
			Name:                 strings.TrimSpace(policy.Name),
			Enabled:              policy.Enabled,
			Failure:              strings.TrimSpace(policy.Failure),
			Action:               strings.TrimSpace(policy.Action),
			TargetState:          strings.TrimSpace(policy.TargetState),
			DisconnectRequired:   policy.DisconnectRequired,
			CoARequired:          policy.CoARequired,
			RecoveryAfterSeconds: policy.RecoveryAfterSeconds,
			Status:               status,
			Reason:               reason,
		})
	}
	return policies
}

func buildBroadbandSubscriberAccountingBindings(state config.BroadbandSubscriberStateConfig) []BroadbandSubscriberAccountingBinding {
	return []BroadbandSubscriberAccountingBinding{
		{"start", []string{"Acct-Status-Type=Start", "Acct-Session-Id", "User-Name", "NAS-Identifier", "NAS-Port-Id", "Calling-Station-Id", "Class"}, "Open durable session ownership and bind product/service-chain identity.", state.RequireAccountingStart},
		{"interim", []string{"Acct-Status-Type=Interim-Update", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Session-Time", "Framed-IP-Address", "Delegated-IPv6-Prefix"}, "Refresh counters, address state, quota, and charging evidence.", true},
		{"stop", []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause", "Acct-Input-Gigawords", "Acct-Output-Gigawords"}, "Close ledger, release leases/routes/service legs, and support lawful audit.", state.RequireAccountingStop},
		{"policy", []string{"Class", "Filter-Id", "Reply-Message", "Vendor service VSAs", "CoA/Disconnect evidence"}, "Correlate policy transitions with RADIUS authorization and dynamic authorization.", state.PolicyTransitionsEnabled},
	}
}

func buildBroadbandSubscriberCompliance(cfg *config.Config, state config.BroadbandSubscriberStateConfig, report BroadbandSubscriberStateReport) []BroadbandSubscriberComplianceCheck {
	checks := []BroadbandSubscriberComplianceCheck{
		broadbandSubscriberCheck("state-machine", "Canonical state machine", len(report.Transitions) >= 20, "State transition graph is available.", "State transition graph is incomplete.", "states", "transitions"),
		broadbandSubscriberCheck("products", "Product catalog seed", report.Summary.EnabledProductCount > 0 || !state.Enabled, "At least one enabled subscriber product is configured or feature is disabled.", "Enabled subscriber state machine requires an enabled product.", "broadband.subscriber_state.products"),
		broadbandSubscriberCheck("service-legs", "Service-leg orchestration", !state.ServiceLegsEnabled || report.Summary.EnabledServicePolicyCount > 0 || !state.Enabled, "Service-leg policy is configured or not required.", "Enabled service-leg orchestration requires an enabled service policy.", "broadband.subscriber_state.service_policies"),
		broadbandSubscriberCheck("pppoe", "PPPoE access dependency", !strings.EqualFold(state.DefaultAccessMethod, "pppoe") || config.EffectiveBroadbandPPPoEConfig(cfg.Broadband.PPPoE).Enabled || !state.Enabled, "PPPoE access lifecycle is enabled for PPPoE subscribers.", "PPPoE subscribers require broadband.pppoe.enabled.", "broadband.pppoe"),
		broadbandSubscriberCheck("sql-accounting", "SQL accounting dependency", cfg.Radius.SQLAccounting.Enabled || !state.RequireAccountingStart || !state.Enabled, "SQL accounting is available for subscriber ledgers.", "Subscriber accounting requires radius.sql_accounting.enabled.", "radius.sql_accounting"),
		broadbandSubscriberCheck("accounting-services", "Accounting correlation dependency", cfg.Radius.AccountingServices.Enabled || !state.Enabled, "Accounting service correlation is available.", "Subscriber service correlation requires radius.accounting_services.enabled.", "radius.accounting_services"),
		broadbandSubscriberCheck("session-ownership", "Session ownership dependency", !state.RequireSessionOwnership || config.EffectiveBroadbandPPPoEConfig(cfg.Broadband.PPPoE).SessionOwnershipRequired || !state.Enabled, "Session ownership leases are required by the access lifecycle.", "Subscriber reconnect recovery requires PPPoE session ownership.", "nas_session_ownership"),
		broadbandSubscriberCheck("address-policy", "Address lifecycle dependency", !state.DualStackRequired || cfg.Radius.AddressPolicy.Enabled || !state.Enabled, "Address policy is available for IPv4/IPv6 lease state.", "Dual-stack subscriber state requires radius.address_policy.enabled.", "radius.address_policy"),
		broadbandSubscriberCheck("route-policy", "Route lifecycle dependency", !state.RoutePolicyRequired || cfg.Radius.RoutePolicy.Enabled || !state.Enabled, "Route policy is available for service activation.", "Subscriber route lifecycle requires radius.route_policy.enabled.", "radius.route_policy"),
		broadbandSubscriberCheck("nat-policy", "NAT lifecycle dependency", !state.NATRequired || cfg.Radius.TranslationPolicy.Enabled || !state.Enabled, "Translation policy is available when NAT is required.", "Subscriber NAT lifecycle requires radius.translation_policy.enabled.", "radius.translation_policy"),
		broadbandSubscriberCheck("coa-policy", "Dynamic authorization dependency", !state.CoARequired || cfg.Radius.DynamicAuth.Enabled || !state.Enabled, "Dynamic authorization is available for live policy transitions.", "Subscriber CoA policy transitions require radius.dynamic_auth.enabled.", "radius.dynamic_auth"),
	}
	return checks
}

func broadbandSubscriberCheck(id, name string, passed bool, passedMessage, blockedMessage string, evidence ...string) BroadbandSubscriberComplianceCheck {
	if passed {
		return BroadbandSubscriberComplianceCheck{ID: id, Name: name, Status: "passed", Message: passedMessage, Evidence: evidence}
	}
	return BroadbandSubscriberComplianceCheck{ID: id, Name: name, Status: "blocked", Message: blockedMessage, Evidence: evidence}
}

func countBroadbandSubscriberCompliance(checks []BroadbandSubscriberComplianceCheck, status string) int {
	count := 0
	for _, check := range checks {
		if check.Status == status {
			count++
		}
	}
	return count
}

func broadbandSubscriberStateFingerprint(report BroadbandSubscriberStateReport) string {
	return sha256JSON(map[string]any{
		"feature_id":       report.FeatureID,
		"summary":          report.Summary,
		"states":           report.States,
		"transitions":      report.Transitions,
		"products":         report.Products,
		"service_policies": report.ServicePolicies,
		"failure_policies": report.FailurePolicies,
		"accounting":       report.AccountingCorrelation,
		"compliance":       report.Compliance,
	})
}

func broadbandSubscriberStateRuntimeDetails(report BroadbandSubscriberStateReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                    report.FeatureID,
		"event_id":                      eventID,
		"plan_fingerprint":              report.PlanFingerprint,
		"mode":                          report.Summary.Mode,
		"default_access_method":         report.Summary.DefaultAccessMethod,
		"product_count":                 report.Summary.ProductCount,
		"enabled_product_count":         report.Summary.EnabledProductCount,
		"service_policy_count":          report.Summary.ServicePolicyCount,
		"enabled_service_policy_count":  report.Summary.EnabledServicePolicyCount,
		"state_count":                   report.Summary.StateCount,
		"transition_count":              report.Summary.TransitionCount,
		"blocker_count":                 report.Summary.BlockerCount,
		"warning_count":                 report.Summary.WarningCount,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}
}
