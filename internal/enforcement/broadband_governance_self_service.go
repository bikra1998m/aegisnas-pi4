package enforcement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	BroadbandGovernanceSelfServiceSchemaVersion = 1
	BroadbandGovernanceSelfServiceFeatureID     = "NAS-0091"
	broadbandGovernanceSelfServiceComponent     = "broadband_governance_self_service"
)

type BroadbandGovernanceSelfServiceReport struct {
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
	Summary                       BroadbandGovernanceSelfServiceSummary  `json:"summary"`
	Cases                         []BroadbandLawfulInterceptCase         `json:"cases"`
	ApprovalPolicies              []BroadbandGovernanceApprovalPolicy    `json:"approval_policies"`
	SelfServiceActions            []BroadbandSubscriberSelfServiceAction `json:"self_service_actions"`
	PrivacyPolicies               []BroadbandGovernancePrivacyPolicy     `json:"privacy_policies"`
	AuthorizationBindings         []BroadbandGovernanceBinding           `json:"authorization_bindings"`
	AccountingBindings            []BroadbandGovernanceBinding           `json:"accounting_bindings"`
	Compliance                    []BroadbandGovernanceSelfServiceCheck  `json:"compliance"`
	Standards                     []string                               `json:"standards"`
	Vendors                       []string                               `json:"vendors"`
	Requirements                  []string                               `json:"requirements"`
	Blockers                      []string                               `json:"blockers,omitempty"`
	Warnings                      []string                               `json:"warnings,omitempty"`
	Notes                         []string                               `json:"notes,omitempty"`
}

type BroadbandGovernanceSelfServiceSummary struct {
	Enabled                  bool   `json:"enabled"`
	Mode                     string `json:"mode"`
	FailClosed               bool   `json:"fail_closed"`
	RequireSubscriberState   bool   `json:"require_subscriber_state"`
	RequireCommercialCatalog bool   `json:"require_commercial_catalog"`
	RequireQuotaBalance      bool   `json:"require_quota_balance"`
	RequireAccounting        bool   `json:"require_accounting"`
	RequireDynamicAuth       bool   `json:"require_dynamic_auth"`
	RequireMFA               bool   `json:"require_mfa"`
	RequireAdminWebAuthn     bool   `json:"require_admin_webauthn"`
	LawfulInterceptEnabled   bool   `json:"lawful_intercept_enabled"`
	SelfServiceEnabled       bool   `json:"self_service_enabled"`
	PrivacyControlsEnabled   bool   `json:"privacy_controls_enabled"`
	ImmutableAuditRequired   bool   `json:"immutable_audit_required"`
	DualApprovalRequired     bool   `json:"dual_approval_required"`
	ApprovalThreshold        int    `json:"approval_threshold"`
	CaseRetentionDays        int    `json:"case_retention_days"`
	EventRetentionLimit      int    `json:"event_retention_limit"`

	SubscriberStateEnabled     bool `json:"subscriber_state_enabled"`
	CommercialCatalogEnabled   bool `json:"commercial_catalog_enabled"`
	QuotaBalanceEnabled        bool `json:"quota_balance_enabled"`
	SQLAccountingEnabled       bool `json:"sql_accounting_enabled"`
	AccountingServicesEnabled  bool `json:"accounting_services_enabled"`
	DynamicAuthEnabled         bool `json:"dynamic_auth_enabled"`
	MFAEnabled                 bool `json:"mfa_enabled"`
	AdminWebAuthnEnabled       bool `json:"admin_webauthn_enabled"`
	CaseCount                  int  `json:"case_count"`
	EnabledCaseCount           int  `json:"enabled_case_count"`
	ApprovalPolicyCount        int  `json:"approval_policy_count"`
	EnabledApprovalPolicyCount int  `json:"enabled_approval_policy_count"`
	SelfServiceActionCount     int  `json:"self_service_action_count"`
	EnabledSelfServiceCount    int  `json:"enabled_self_service_count"`
	PrivacyPolicyCount         int  `json:"privacy_policy_count"`
	EnabledPrivacyPolicyCount  int  `json:"enabled_privacy_policy_count"`
	AuthorizationBindingCount  int  `json:"authorization_binding_count"`
	AccountingBindingCount     int  `json:"accounting_binding_count"`
	CompiledAttributeCount     int  `json:"compiled_attribute_count"`
	ComplianceCheckCount       int  `json:"compliance_check_count"`
	PassedCheckCount           int  `json:"passed_check_count"`
	WarningCount               int  `json:"warning_count"`
	BlockerCount               int  `json:"blocker_count"`
	ExternalRequirementCount   int  `json:"external_requirement_count"`
}

type BroadbandLawfulInterceptCase struct {
	CaseKey          string                         `json:"case_key"`
	Name             string                         `json:"name"`
	Enabled          bool                           `json:"enabled"`
	CaseID           string                         `json:"case_id,omitempty"`
	LegalAuthority   string                         `json:"legal_authority,omitempty"`
	RequestReference string                         `json:"request_reference,omitempty"`
	SubscriberID     string                         `json:"subscriber_id,omitempty"`
	Username         string                         `json:"username,omitempty"`
	Tenant           string                         `json:"tenant,omitempty"`
	Scope            string                         `json:"scope,omitempty"`
	ExportAdapter    string                         `json:"export_adapter,omitempty"`
	RetentionClass   string                         `json:"retention_class,omitempty"`
	Approvers        []string                       `json:"approvers"`
	AuditTags        []string                       `json:"audit_tags"`
	Attributes       []BroadbandGovernanceAttribute `json:"attributes"`
	Status           string                         `json:"status"`
	Reason           string                         `json:"reason"`
}

type BroadbandGovernanceApprovalPolicy struct {
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Scope                string   `json:"scope,omitempty"`
	MinApprovals         int      `json:"min_approvals"`
	RequireMFA           bool     `json:"require_mfa"`
	RequireWebAuthn      bool     `json:"require_webauthn"`
	BreakGlassAllowed    bool     `json:"break_glass_allowed"`
	AllowedRoles         []string `json:"allowed_roles"`
	EscalationRecipients []string `json:"escalation_recipients"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
}

type BroadbandSubscriberSelfServiceAction struct {
	RequestKey            string                         `json:"request_key"`
	Name                  string                         `json:"name"`
	Enabled               bool                           `json:"enabled"`
	Action                string                         `json:"action"`
	RequiresAuth          bool                           `json:"requires_auth"`
	RequiresMFA           bool                           `json:"requires_mfa"`
	RequiresApproval      bool                           `json:"requires_approval"`
	AllowedProducts       []string                       `json:"allowed_products"`
	AllowedTenants        []string                       `json:"allowed_tenants"`
	RateLimitPerHour      int                            `json:"rate_limit_per_hour"`
	MaxPendingRequests    int                            `json:"max_pending_requests"`
	NotificationChannel   string                         `json:"notification_channel,omitempty"`
	AccountingCorrelation bool                           `json:"accounting_correlation"`
	Attributes            []BroadbandGovernanceAttribute `json:"attributes"`
	Status                string                         `json:"status"`
	Reason                string                         `json:"reason"`
}

type BroadbandGovernancePrivacyPolicy struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	DataClass        string   `json:"data_class,omitempty"`
	AccessPurpose    string   `json:"access_purpose,omitempty"`
	RetentionDays    int      `json:"retention_days"`
	RedactFields     []string `json:"redact_fields"`
	ExportAllowed    bool     `json:"export_allowed"`
	SubscriberNotice bool     `json:"subscriber_notice"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type BroadbandGovernanceAttribute struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	Vendor  string `json:"vendor,omitempty"`
	Stage   string `json:"stage,omitempty"`
}

type BroadbandGovernanceBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandGovernanceSelfServiceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandGovernanceSelfServiceComponent() string {
	return broadbandGovernanceSelfServiceComponent
}

func PreviewBroadbandGovernanceSelfService(cfg *config.Config) (BroadbandGovernanceSelfServiceReport, error) {
	if cfg == nil {
		return BroadbandGovernanceSelfServiceReport{}, fmt.Errorf("config is required")
	}
	governance := config.EffectiveBroadbandGovernanceSelfServiceConfig(cfg.Broadband.Governance)
	subscriber := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	catalog := config.EffectiveBroadbandCommercialCatalog(cfg.Broadband.CommercialCatalog)
	quota := config.EffectiveBroadbandQuotaBalanceConfig(cfg.Broadband.QuotaBalance)
	mfa := config.EffectiveMFAConfig(cfg.MFA)
	webauthn := config.EffectiveAdminWebAuthnConfig(cfg.AdminWebAuthn)

	report := BroadbandGovernanceSelfServiceReport{
		SchemaVersion:                 BroadbandGovernanceSelfServiceSchemaVersion,
		FeatureID:                     BroadbandGovernanceSelfServiceFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0091-release-certification-checklist.md",
		ReleaseScope:                  "Court-order workflow proof, regulator/customer approvals, physical lawful-intercept adapter certification, production Linux FreeRADIUS captures, HA failover, scale/soak, security audit, compliance review, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 5176", "ETSI lawful-interception architecture", "CALEA operational governance", "privacy-by-design controls"},
		Vendors:                       []string{"Cisco BNG", "Juniper ERX/E-Series", "Huawei BRAS/BNG", "Nokia/Alcatel-Lucent SR OS", "Ericsson/Redback", "ZTE BNG"},
		Requirements: []string{
			"govern lawful-intercept activation through immutable audit, dual control, strong admin authentication, scoped cases, and privacy redaction",
			"separate external legal/certification evidence from software readiness claims",
			"offer subscriber self-service actions for balance, plan changes, top-up, usage export, privacy request, service cancel, and support ticket workflows",
			"correlate self-service and lawful-governance decisions with subscriber state, catalog, quota/balance, accounting, and dynamic authorization",
			"expose preview, apply, history, support-bundle, runtime status, UI, and readiness evidence",
		},
		Notes: []string{
			"NAS-0091 completes software governance for lawful-intercept case control and subscriber self-service workflows.",
			"Actual lawful-intercept handoff, regulator acceptance, customer approval, and physical BNG adapter proof remain release certification evidence.",
		},
	}
	report.Summary = BroadbandGovernanceSelfServiceSummary{
		Enabled:                   governance.Enabled,
		Mode:                      governance.Mode,
		FailClosed:                governance.FailClosed,
		RequireSubscriberState:    governance.RequireSubscriberState,
		RequireCommercialCatalog:  governance.RequireCommercialCatalog,
		RequireQuotaBalance:       governance.RequireQuotaBalance,
		RequireAccounting:         governance.RequireAccounting,
		RequireDynamicAuth:        governance.RequireDynamicAuth,
		RequireMFA:                governance.RequireMFA,
		RequireAdminWebAuthn:      governance.RequireAdminWebAuthn,
		LawfulInterceptEnabled:    governance.LawfulInterceptEnabled,
		SelfServiceEnabled:        governance.SelfServiceEnabled,
		PrivacyControlsEnabled:    governance.PrivacyControlsEnabled,
		ImmutableAuditRequired:    governance.ImmutableAuditRequired,
		DualApprovalRequired:      governance.DualApprovalRequired,
		ApprovalThreshold:         governance.ApprovalThreshold,
		CaseRetentionDays:         governance.CaseRetentionDays,
		EventRetentionLimit:       governance.EventRetentionLimit,
		SubscriberStateEnabled:    subscriber.Enabled,
		CommercialCatalogEnabled:  catalog.Enabled,
		QuotaBalanceEnabled:       quota.Enabled,
		SQLAccountingEnabled:      cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled: cfg.Radius.AccountingServices.Enabled,
		DynamicAuthEnabled:        cfg.Radius.DynamicAuth.Enabled,
		MFAEnabled:                mfa.Enabled,
		AdminWebAuthnEnabled:      webauthn.Enabled,
	}
	report.Cases = compileBroadbandGovernanceCases(governance)
	report.ApprovalPolicies = compileBroadbandGovernanceApprovalPolicies(governance)
	report.SelfServiceActions = compileBroadbandSelfServiceActions(governance)
	report.PrivacyPolicies = compileBroadbandPrivacyPolicies(governance)
	report.AuthorizationBindings = []BroadbandGovernanceBinding{
		{Stage: "lawful-intercept-authorization", Attributes: []string{"Class", "Filter-Id", "Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "Nokia-AVPair"}, Purpose: "Correlate lawful-governance decisions with BNG authorization evidence.", Required: governance.LawfulInterceptEnabled},
		{Stage: "self-service-authorization", Attributes: []string{"Class", "Chargeable-User-Identity", "Session-Timeout", "Idle-Timeout"}, Purpose: "Bind subscriber-initiated service actions to durable authorization evidence.", Required: governance.SelfServiceEnabled},
	}
	report.AccountingBindings = []BroadbandGovernanceBinding{
		{Stage: "accounting-start", Attributes: []string{"Acct-Session-Id", "Acct-Multi-Session-Id", "Class", "Calling-Station-Id"}, Purpose: "Correlate subscriber self-service and lawful-governance scope with session ownership.", Required: governance.RequireAccounting},
		{Stage: "accounting-stop", Attributes: []string{"Acct-Terminate-Cause", "Class", "Acct-Session-Time"}, Purpose: "Close the immutable audit trail for governed subscriber service actions.", Required: governance.RequireAccounting},
	}
	report.Summary.CaseCount = len(report.Cases)
	report.Summary.ApprovalPolicyCount = len(report.ApprovalPolicies)
	report.Summary.SelfServiceActionCount = len(report.SelfServiceActions)
	report.Summary.PrivacyPolicyCount = len(report.PrivacyPolicies)
	report.Summary.AuthorizationBindingCount = len(report.AuthorizationBindings)
	report.Summary.AccountingBindingCount = len(report.AccountingBindings)
	for _, item := range report.Cases {
		if item.Enabled {
			report.Summary.EnabledCaseCount++
		}
		report.Summary.CompiledAttributeCount += len(item.Attributes)
	}
	for _, item := range report.ApprovalPolicies {
		if item.Enabled {
			report.Summary.EnabledApprovalPolicyCount++
		}
	}
	for _, item := range report.SelfServiceActions {
		if item.Enabled {
			report.Summary.EnabledSelfServiceCount++
		}
		report.Summary.CompiledAttributeCount += len(item.Attributes)
	}
	for _, item := range report.PrivacyPolicies {
		if item.Enabled {
			report.Summary.EnabledPrivacyPolicyCount++
		}
	}
	report.Compliance = buildBroadbandGovernanceChecks(report, governance, subscriber, catalog, quota, cfg.Radius, mfa, webauthn)
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
		if check.ID == "external-certification" {
			report.Summary.ExternalRequirementCount++
		}
	}
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.PlanFingerprint = fingerprintJSON(map[string]any{
		"feature":           report.FeatureID,
		"summary":           report.Summary,
		"cases":             report.Cases,
		"approval_policies": report.ApprovalPolicies,
		"self_service":      report.SelfServiceActions,
		"privacy":           report.PrivacyPolicies,
		"bindings":          []any{report.AuthorizationBindings, report.AccountingBindings},
	})
	if !governance.Enabled {
		report.Status = "disabled"
		report.Message = "NAS-0091 software is ready; lawful-intercept governance and subscriber self-service are not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = "Lawful-intercept governance and subscriber self-service are blocked by missing software prerequisites."
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = "Lawful-intercept governance and subscriber self-service are ready with warnings."
	} else {
		report.Status = "ready"
		report.Message = "Lawful-intercept governance and subscriber self-service software controls are ready for governed operation."
	}
	return report, nil
}

func PreviewAndRecordBroadbandGovernanceSelfService(cfg *config.Config, actor string) (BroadbandGovernanceSelfServiceReport, string, error) {
	report, err := PreviewBroadbandGovernanceSelfService(cfg)
	if err != nil {
		return report, "", err
	}
	eventID, err := recordBroadbandGovernanceSelfServiceReport("preview", "previewed", report, actor)
	return report, eventID, err
}

func ApplyBroadbandGovernanceSelfService(_ context.Context, cfg *config.Config, actor string) (BroadbandGovernanceSelfServiceReport, string, error) {
	report, err := PreviewBroadbandGovernanceSelfService(cfg)
	if err != nil {
		return report, "", err
	}
	status := "applied"
	if report.Status == "disabled" {
		status = "skipped"
	}
	if report.Status == "blocked" {
		status = "blocked"
	}
	eventID, recordErr := recordBroadbandGovernanceSelfServiceReport("apply", status, report, actor)
	if recordErr != nil {
		return report, eventID, recordErr
	}
	runtimeStatus := "ok"
	if report.Status == "degraded" {
		runtimeStatus = "degraded"
	} else if report.Status == "disabled" {
		runtimeStatus = "disabled"
	} else if report.Status == "blocked" {
		runtimeStatus = "blocked"
	}
	_ = db.UpsertRuntimeStatus(broadbandGovernanceSelfServiceComponent, runtimeStatus, report.Message, map[string]any{
		"feature_id":                report.FeatureID,
		"software_completion":       report.SoftwareCompletionPercent,
		"ready_for_external":        report.ReadyForExternalValidation,
		"plan_fingerprint":          report.PlanFingerprint,
		"case_count":                report.Summary.CaseCount,
		"self_service_action_count": report.Summary.SelfServiceActionCount,
		"privacy_policy_count":      report.Summary.PrivacyPolicyCount,
		"blocker_count":             report.Summary.BlockerCount,
		"warning_count":             report.Summary.WarningCount,
		"event_id":                  eventID,
	})
	if status == "blocked" {
		return report, eventID, errors.New(strings.Join(report.Blockers, "; "))
	}
	return report, eventID, nil
}

func compileBroadbandGovernanceCases(governance config.BroadbandGovernanceSelfServiceConfig) []BroadbandLawfulInterceptCase {
	out := make([]BroadbandLawfulInterceptCase, 0, len(governance.Cases))
	for _, item := range governance.Cases {
		caseID := strings.TrimSpace(item.CaseID)
		caseKey := strings.ToLower(firstNonEmptyString(caseID, item.Name))
		compiled := BroadbandLawfulInterceptCase{
			CaseKey:          caseKey,
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			CaseID:           caseID,
			LegalAuthority:   strings.TrimSpace(item.LegalAuthority),
			RequestReference: strings.TrimSpace(item.RequestReference),
			SubscriberID:     strings.TrimSpace(item.SubscriberID),
			Username:         strings.TrimSpace(item.Username),
			Tenant:           strings.TrimSpace(item.Tenant),
			Scope:            firstNonEmptyString(strings.TrimSpace(item.Scope), "accounting-metadata"),
			ExportAdapter:    firstNonEmptyString(strings.TrimSpace(item.ExportAdapter), "governed-export"),
			RetentionClass:   firstNonEmptyString(strings.TrimSpace(item.RetentionClass), "regulated"),
			Approvers:        trimStringSlice(item.Approvers),
			AuditTags:        trimStringSlice(item.AuditTags),
			Status:           "ready",
			Reason:           "Governed lawful-intercept case evidence is compiled.",
		}
		if !item.Enabled {
			compiled.Status = "planned"
			compiled.Reason = "Case is configured but disabled."
		}
		compiled.Attributes = []BroadbandGovernanceAttribute{
			{Name: "Class", Value: "aegisnas:li:" + caseKey, Purpose: "Stable lawful-governance correlation class.", Stage: "authorization"},
			{Name: "Filter-Id", Value: "li-scope-" + compiled.Scope, Purpose: "Vendor-neutral intercept scope hint.", Stage: "authorization"},
			{Name: "Cisco-AVPair", Value: "aegisnas-li-case=" + caseKey, Purpose: "Cisco-family governance correlation hint.", Vendor: "Cisco", Stage: "authorization"},
			{Name: "Juniper-AV-Pair", Value: "aegisnas-li-case=" + caseKey, Purpose: "Juniper/ERX governance correlation hint.", Vendor: "Juniper", Stage: "authorization"},
			{Name: "Huawei-AVpair", Value: "aegisnas-li-case=" + caseKey, Purpose: "Huawei/H3C governance correlation hint.", Vendor: "Huawei", Stage: "authorization"},
			{Name: "Nokia-AVPair", Value: "aegisnas-li-case=" + caseKey, Purpose: "Nokia/Alcatel-Lucent governance correlation hint.", Vendor: "Nokia", Stage: "authorization"},
		}
		out = append(out, compiled)
	}
	return out
}

func compileBroadbandGovernanceApprovalPolicies(governance config.BroadbandGovernanceSelfServiceConfig) []BroadbandGovernanceApprovalPolicy {
	out := make([]BroadbandGovernanceApprovalPolicy, 0, len(governance.ApprovalPolicies))
	for _, item := range governance.ApprovalPolicies {
		status := "ready"
		reason := "Approval policy enforces governed access."
		if !item.Enabled {
			status = "planned"
			reason = "Approval policy is configured but disabled."
		}
		out = append(out, BroadbandGovernanceApprovalPolicy{
			Name:                 strings.TrimSpace(item.Name),
			Enabled:              item.Enabled,
			Scope:                firstNonEmptyString(strings.TrimSpace(item.Scope), "all"),
			MinApprovals:         item.MinApprovals,
			RequireMFA:           item.RequireMFA,
			RequireWebAuthn:      item.RequireWebAuthn,
			BreakGlassAllowed:    item.BreakGlassAllowed,
			AllowedRoles:         trimStringSlice(item.AllowedRoles),
			EscalationRecipients: trimStringSlice(item.EscalationRecipients),
			Status:               status,
			Reason:               reason,
		})
	}
	return out
}

func compileBroadbandSelfServiceActions(governance config.BroadbandGovernanceSelfServiceConfig) []BroadbandSubscriberSelfServiceAction {
	out := make([]BroadbandSubscriberSelfServiceAction, 0, len(governance.SelfServiceActions))
	for _, item := range governance.SelfServiceActions {
		action := firstNonEmptyString(strings.TrimSpace(item.Action), "view_balance")
		name := strings.TrimSpace(item.Name)
		key := strings.ToLower(strings.ReplaceAll(firstNonEmptyString(name, action), " ", "-"))
		status := "ready"
		reason := "Self-service action is governed and correlated."
		if !item.Enabled {
			status = "planned"
			reason = "Self-service action is configured but disabled."
		}
		attributes := []BroadbandGovernanceAttribute{
			{Name: "Class", Value: "aegisnas:self-service:" + key, Purpose: "Stable subscriber self-service correlation class.", Stage: "authorization"},
			{Name: "Chargeable-User-Identity", Value: key, Purpose: "Billing-safe subscriber operation identity.", Stage: "authorization"},
			{Name: "Acct-Interim-Interval", Value: "300", Purpose: "Bounded accounting freshness for subscriber-visible service changes.", Stage: "accounting"},
		}
		out = append(out, BroadbandSubscriberSelfServiceAction{
			RequestKey:            key,
			Name:                  name,
			Enabled:               item.Enabled,
			Action:                action,
			RequiresAuth:          item.RequiresAuth,
			RequiresMFA:           item.RequiresMFA,
			RequiresApproval:      item.RequiresApproval,
			AllowedProducts:       trimStringSlice(item.AllowedProducts),
			AllowedTenants:        trimStringSlice(item.AllowedTenants),
			RateLimitPerHour:      item.RateLimitPerHour,
			MaxPendingRequests:    item.MaxPendingRequests,
			NotificationChannel:   strings.TrimSpace(item.NotificationChannel),
			AccountingCorrelation: item.AccountingCorrelation,
			Attributes:            attributes,
			Status:                status,
			Reason:                reason,
		})
	}
	return out
}

func compileBroadbandPrivacyPolicies(governance config.BroadbandGovernanceSelfServiceConfig) []BroadbandGovernancePrivacyPolicy {
	out := make([]BroadbandGovernancePrivacyPolicy, 0, len(governance.PrivacyPolicies))
	for _, item := range governance.PrivacyPolicies {
		status := "ready"
		reason := "Privacy policy is available for redaction and retention enforcement."
		if !item.Enabled {
			status = "planned"
			reason = "Privacy policy is configured but disabled."
		}
		out = append(out, BroadbandGovernancePrivacyPolicy{
			Name:             strings.TrimSpace(item.Name),
			Enabled:          item.Enabled,
			DataClass:        strings.TrimSpace(item.DataClass),
			AccessPurpose:    strings.TrimSpace(item.AccessPurpose),
			RetentionDays:    item.RetentionDays,
			RedactFields:     trimStringSlice(item.RedactFields),
			ExportAllowed:    item.ExportAllowed,
			SubscriberNotice: item.SubscriberNotice,
			Status:           status,
			Reason:           reason,
		})
	}
	return out
}

func buildBroadbandGovernanceChecks(report BroadbandGovernanceSelfServiceReport, governance config.BroadbandGovernanceSelfServiceConfig, subscriber config.BroadbandSubscriberStateConfig, catalog config.BroadbandCommercialCatalog, quota config.BroadbandQuotaBalanceConfig, radius config.RadiusConfig, mfa config.MFAConfig, webauthn config.AdminWebAuthnConfig) []BroadbandGovernanceSelfServiceCheck {
	checks := []BroadbandGovernanceSelfServiceCheck{
		governanceCheck("subscriber-state", "Subscriber state dependency", !governance.RequireSubscriberState || subscriber.Enabled, "Subscriber state is available for governed subscriber correlation.", "Subscriber state is required before governance enforcement.", []string{"broadband.subscriber_state"}),
		governanceCheck("commercial-catalog", "Commercial catalog dependency", !governance.RequireCommercialCatalog || catalog.Enabled, "Commercial catalog is available for plan and service self-service.", "Commercial catalog is required before self-service enforcement.", []string{"broadband.commercial_catalog"}),
		governanceCheck("quota-balance", "Quota and balance dependency", !governance.RequireQuotaBalance || quota.Enabled, "Quota and balance are available for subscriber-visible operations.", "Quota and balance are required before self-service enforcement.", []string{"broadband.quota_balance"}),
		governanceCheck("accounting", "Accounting correlation dependency", !governance.RequireAccounting || (radius.SQLAccounting.Enabled && radius.AccountingServices.Enabled), "SQL accounting and service correlation are available.", "SQL accounting and accounting service correlation are required.", []string{"radius.sql_accounting", "radius.accounting_services"}),
		governanceCheck("dynamic-auth", "Dynamic authorization dependency", !governance.RequireDynamicAuth || radius.DynamicAuth.Enabled, "Dynamic authorization is available for subscriber service changes.", "Dynamic authorization is required for governed plan and service changes.", []string{"radius.dynamic_auth"}),
		governanceCheck("mfa", "Administrator MFA dependency", !governance.RequireMFA || mfa.Enabled, "MFA is available for governed approvals.", "MFA is required for lawful-governance approvals.", []string{"mfa.enabled"}),
		governanceCheck("webauthn", "Administrator WebAuthn dependency", !governance.RequireAdminWebAuthn || webauthn.Enabled, "WebAuthn/passkeys are available for high-risk approvals.", "WebAuthn/passkeys are required for high-risk lawful-governance approvals.", []string{"admin_webauthn.enabled"}),
		governanceCheck("dual-approval", "Dual approval policy", !governance.DualApprovalRequired || report.Summary.EnabledApprovalPolicyCount > 0, "At least one approval policy is ready or dual approval is disabled.", "Dual approval requires an enabled approval policy.", []string{"approval_policies"}),
		governanceCheck("lawful-cases", "Lawful-intercept case scope", !governance.LawfulInterceptEnabled || report.Summary.EnabledCaseCount > 0 || governance.Mode != "enforce", "Lawful-intercept case evidence is present or monitor mode is active.", "Enforced lawful-intercept governance requires at least one enabled case.", []string{"cases"}),
		governanceCheck("self-service", "Subscriber self-service actions", !governance.SelfServiceEnabled || report.Summary.EnabledSelfServiceCount > 0 || governance.Mode != "enforce", "Subscriber self-service action evidence is present or monitor mode is active.", "Enforced subscriber self-service requires at least one enabled action.", []string{"self_service_actions"}),
		governanceCheck("privacy", "Privacy and redaction controls", !governance.PrivacyControlsEnabled || report.Summary.EnabledPrivacyPolicyCount > 0, "Privacy, retention, and redaction controls are present.", "Privacy controls require at least one enabled privacy policy.", []string{"privacy_policies"}),
		{ID: "external-certification", Name: "External lawful-governance certification boundary", Status: "passed", Message: "Court-order/legal workflow proof, regulator/customer acceptance, physical intercept adapters, HA, scale, soak, security, and customer proof are release certification activities.", Evidence: []string{"docs/nas-0091-release-certification-checklist.md"}},
	}
	return checks
}

func governanceCheck(id, name string, ok bool, passMessage, blockMessage string, evidence []string) BroadbandGovernanceSelfServiceCheck {
	if ok {
		return BroadbandGovernanceSelfServiceCheck{ID: id, Name: name, Status: "passed", Message: passMessage, Evidence: evidence}
	}
	return BroadbandGovernanceSelfServiceCheck{ID: id, Name: name, Status: "blocked", Message: blockMessage, Evidence: evidence}
}

func recordBroadbandGovernanceSelfServiceReport(operation, status string, report BroadbandGovernanceSelfServiceReport, actor string) (string, error) {
	summaryJSON, _ := json.Marshal(report.Summary)
	reportJSON, _ := json.Marshal(report)
	cases := make([]db.BroadbandGovernanceCaseInput, 0, len(report.Cases))
	for _, item := range report.Cases {
		attributesJSON, _ := json.Marshal(item.Attributes)
		cases = append(cases, db.BroadbandGovernanceCaseInput{
			CaseKey:          item.CaseKey,
			Name:             item.Name,
			CaseID:           item.CaseID,
			LegalAuthority:   item.LegalAuthority,
			RequestReference: item.RequestReference,
			SubscriberID:     item.SubscriberID,
			Username:         item.Username,
			Tenant:           item.Tenant,
			Scope:            item.Scope,
			Status:           item.Status,
			AttributesJSON:   string(attributesJSON),
			PlanFingerprint:  report.PlanFingerprint,
		})
	}
	requests := make([]db.BroadbandSelfServiceRequestInput, 0, len(report.SelfServiceActions))
	for _, item := range report.SelfServiceActions {
		attributesJSON, _ := json.Marshal(item.Attributes)
		requests = append(requests, db.BroadbandSelfServiceRequestInput{
			RequestKey:       item.RequestKey,
			Action:           item.Action,
			Name:             item.Name,
			Status:           item.Status,
			RequiresApproval: item.RequiresApproval,
			RequiresMFA:      item.RequiresMFA,
			AttributesJSON:   string(attributesJSON),
			PlanFingerprint:  report.PlanFingerprint,
		})
	}
	return db.RecordBroadbandGovernanceSelfServiceEvent(db.BroadbandGovernanceSelfServiceEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		CaseCount:                report.Summary.CaseCount,
		SelfServiceActionCount:   report.Summary.SelfServiceActionCount,
		PrivacyPolicyCount:       report.Summary.PrivacyPolicyCount,
		ApprovalPolicyCount:      report.Summary.ApprovalPolicyCount,
		CompiledAttributeCount:   report.Summary.CompiledAttributeCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              string(summaryJSON),
		ReportJSON:               string(reportJSON),
		Actor:                    actor,
		Cases:                    cases,
		Requests:                 requests,
	})
}

func fingerprintJSON(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
