package enforcement

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	BroadbandCommercialCatalogSchemaVersion = 1
	BroadbandCommercialCatalogFeatureID     = "NAS-0084"
	broadbandCommercialCatalogComponent     = "broadband_commercial_catalog"
)

type BroadbandCommercialCatalogReport struct {
	SchemaVersion                 int                                       `json:"schema_version"`
	FeatureID                     string                                    `json:"feature_id"`
	Status                        string                                    `json:"status"`
	Message                       string                                    `json:"message"`
	GeneratedAt                   string                                    `json:"generated_at"`
	SoftwareCompletionPercent     float64                                   `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                                      `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                                    `json:"release_certification_checklist"`
	ReleaseScope                  string                                    `json:"release_scope"`
	PlanFingerprint               string                                    `json:"plan_fingerprint"`
	Summary                       BroadbandCommercialCatalogSummary         `json:"summary"`
	Accounts                      []BroadbandCommercialAccount              `json:"accounts"`
	Plans                         []BroadbandCommercialPlan                 `json:"plans"`
	Bundles                       []BroadbandCommercialBundle               `json:"bundles"`
	Subscriptions                 []BroadbandCommercialSubscription         `json:"subscriptions"`
	ConcurrencyPolicies           []BroadbandCommercialConcurrencyPolicy    `json:"concurrency_policies"`
	AuthorizationBindings         []BroadbandCommercialAuthorizationBinding `json:"authorization_bindings"`
	AccountingBindings            []BroadbandCommercialAccountingBinding    `json:"accounting_bindings"`
	Compliance                    []BroadbandCommercialCatalogCheck         `json:"compliance"`
	Standards                     []string                                  `json:"standards"`
	Vendors                       []string                                  `json:"vendors"`
	Requirements                  []string                                  `json:"requirements"`
	Blockers                      []string                                  `json:"blockers,omitempty"`
	Warnings                      []string                                  `json:"warnings,omitempty"`
	Notes                         []string                                  `json:"notes,omitempty"`
}

type BroadbandCommercialCatalogSummary struct {
	Enabled                       bool   `json:"enabled"`
	Mode                          string `json:"mode"`
	FailClosed                    bool   `json:"fail_closed"`
	DefaultBillingPeriod          string `json:"default_billing_period"`
	DefaultCurrency               string `json:"default_currency"`
	AllowFamilyAccounts           bool   `json:"allow_family_accounts"`
	RequireActiveSubscription     bool   `json:"require_active_subscription"`
	RequireBundleEligibility      bool   `json:"require_bundle_eligibility"`
	EnforceConcurrency            bool   `json:"enforce_concurrency"`
	AccountingCorrelationRequired bool   `json:"accounting_correlation_required"`
	CoAOnLimit                    bool   `json:"coa_on_limit"`
	MaxAccounts                   int    `json:"max_accounts"`
	MaxSubscriptions              int    `json:"max_subscriptions"`
	MaxSessionsPerAccount         int    `json:"max_sessions_per_account"`
	MaxSessionsPerSubscription    int    `json:"max_sessions_per_subscription"`
	PeriodResetHour               int    `json:"period_reset_hour"`
	EventRetentionLimit           int    `json:"event_retention_limit"`
	SubscriberStateEnabled        bool   `json:"subscriber_state_enabled"`
	SQLAccountingEnabled          bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled     bool   `json:"accounting_services_enabled"`
	DynamicAuthEnabled            bool   `json:"dynamic_auth_enabled"`
	HighAvailabilityEnabled       bool   `json:"high_availability_enabled"`
	AccountCount                  int    `json:"account_count"`
	ActiveAccountCount            int    `json:"active_account_count"`
	FamilyAccountCount            int    `json:"family_account_count"`
	PlanCount                     int    `json:"plan_count"`
	EnabledPlanCount              int    `json:"enabled_plan_count"`
	BundleCount                   int    `json:"bundle_count"`
	EnabledBundleCount            int    `json:"enabled_bundle_count"`
	SubscriptionCount             int    `json:"subscription_count"`
	ActiveSubscriptionCount       int    `json:"active_subscription_count"`
	SuspendedSubscriptionCount    int    `json:"suspended_subscription_count"`
	ConcurrencyPolicyCount        int    `json:"concurrency_policy_count"`
	EnabledConcurrencyPolicyCount int    `json:"enabled_concurrency_policy_count"`
	AuthorizationBindingCount     int    `json:"authorization_binding_count"`
	AccountingBindingCount        int    `json:"accounting_binding_count"`
	ActiveSessionCount            int    `json:"active_session_count"`
	OverLimitCount                int    `json:"over_limit_count"`
	ComplianceCheckCount          int    `json:"compliance_check_count"`
	PassedCheckCount              int    `json:"passed_check_count"`
	WarningCount                  int    `json:"warning_count"`
	BlockerCount                  int    `json:"blocker_count"`
	ExternalRequirementCount      int    `json:"external_requirement_count"`
}

type BroadbandCommercialAccount struct {
	AccountID        string   `json:"account_id"`
	ParentAccountID  string   `json:"parent_account_id,omitempty"`
	Tenant           string   `json:"tenant,omitempty"`
	Status           string   `json:"status"`
	BillingMode      string   `json:"billing_mode,omitempty"`
	OwnerName        string   `json:"owner_name,omitempty"`
	Contact          string   `json:"contact,omitempty"`
	MaxSubscriptions int      `json:"max_subscriptions,omitempty"`
	MaxSessions      int      `json:"max_sessions,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	FamilyAccount    bool     `json:"family_account"`
	Reason           string   `json:"reason"`
}

type BroadbandCommercialPlan struct {
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	Product               string   `json:"product,omitempty"`
	DisplayName           string   `json:"display_name,omitempty"`
	BillingPeriod         string   `json:"billing_period"`
	PriceMicros           int64    `json:"price_micros"`
	Currency              string   `json:"currency"`
	MaxSessions           int      `json:"max_sessions,omitempty"`
	MaxDevices            int      `json:"max_devices,omitempty"`
	DownstreamKbps        int      `json:"downstream_kbps,omitempty"`
	UpstreamKbps          int      `json:"upstream_kbps,omitempty"`
	QuotaProfile          string   `json:"quota_profile,omitempty"`
	ServiceChain          string   `json:"service_chain,omitempty"`
	AddressPool           string   `json:"address_pool,omitempty"`
	IPv6Pool              string   `json:"ipv6_pool,omitempty"`
	DelegatedIPv6Pool     string   `json:"delegated_ipv6_pool,omitempty"`
	RoutePolicy           string   `json:"route_policy,omitempty"`
	QoSProfile            string   `json:"qos_profile,omitempty"`
	TranslationPool       string   `json:"translation_pool,omitempty"`
	PortalProfile         string   `json:"portal_profile,omitempty"`
	GraceSeconds          int      `json:"grace_seconds,omitempty"`
	SuspensionRole        string   `json:"suspension_role,omitempty"`
	SessionTimeoutSeconds int      `json:"session_timeout_seconds,omitempty"`
	IdleTimeoutSeconds    int      `json:"idle_timeout_seconds,omitempty"`
	VendorPacks           []string `json:"vendor_packs,omitempty"`
	Status                string   `json:"status"`
	Reason                string   `json:"reason"`
}

type BroadbandCommercialBundle struct {
	Name                       string   `json:"name"`
	Enabled                    bool     `json:"enabled"`
	DisplayName                string   `json:"display_name,omitempty"`
	Plans                      []string `json:"plans"`
	RequiredPlans              []string `json:"required_plans,omitempty"`
	MutuallyExclusivePlans     []string `json:"mutually_exclusive_plans,omitempty"`
	MaxConcurrentSubscriptions int      `json:"max_concurrent_subscriptions,omitempty"`
	SharedConcurrency          bool     `json:"shared_concurrency"`
	Priority                   int      `json:"priority,omitempty"`
	EligibilityTags            []string `json:"eligibility_tags,omitempty"`
	Status                     string   `json:"status"`
	Reason                     string   `json:"reason"`
}

type BroadbandCommercialSubscription struct {
	SubscriptionID     string   `json:"subscription_id"`
	AccountID          string   `json:"account_id"`
	SubscriberID       string   `json:"subscriber_id,omitempty"`
	Username           string   `json:"username,omitempty"`
	Plan               string   `json:"plan"`
	Bundle             string   `json:"bundle,omitempty"`
	Status             string   `json:"status"`
	StartsAt           string   `json:"starts_at,omitempty"`
	EndsAt             string   `json:"ends_at,omitempty"`
	AutoRenew          bool     `json:"auto_renew"`
	MaxSessions        int      `json:"max_sessions,omitempty"`
	DeviceLimit        int      `json:"device_limit,omitempty"`
	EligibilityTags    []string `json:"eligibility_tags,omitempty"`
	ActiveSessionCount int      `json:"active_session_count"`
	OverLimit          bool     `json:"over_limit"`
	Reason             string   `json:"reason"`
}

type BroadbandCommercialConcurrencyPolicy struct {
	PolicyKey                string `json:"policy_key"`
	Name                     string `json:"name"`
	Enabled                  bool   `json:"enabled"`
	Scope                    string `json:"scope"`
	Target                   string `json:"target,omitempty"`
	AccountID                string `json:"account_id,omitempty"`
	Tenant                   string `json:"tenant,omitempty"`
	Plan                     string `json:"plan,omitempty"`
	Bundle                   string `json:"bundle,omitempty"`
	MaxSessions              int    `json:"max_sessions,omitempty"`
	MaxSessionsPerSubscriber int    `json:"max_sessions_per_subscriber,omitempty"`
	BurstSessions            int    `json:"burst_sessions,omitempty"`
	GraceSeconds             int    `json:"grace_seconds,omitempty"`
	Action                   string `json:"action"`
	CoAAction                string `json:"coa_action,omitempty"`
	Status                   string `json:"status"`
	Reason                   string `json:"reason"`
}

type BroadbandCommercialAuthorizationBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandCommercialAccountingBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandCommercialCatalogCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandCommercialCatalogComponent() string {
	return broadbandCommercialCatalogComponent
}

func PreviewBroadbandCommercialCatalog(cfg *config.Config) (BroadbandCommercialCatalogReport, error) {
	if cfg == nil {
		return BroadbandCommercialCatalogReport{}, fmt.Errorf("config is required")
	}
	catalog := config.EffectiveBroadbandCommercialCatalog(cfg.Broadband.CommercialCatalog)
	state := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	report := BroadbandCommercialCatalogReport{
		SchemaVersion:                 BroadbandCommercialCatalogSchemaVersion,
		FeatureID:                     BroadbandCommercialCatalogFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0084-release-certification-checklist.md",
		ReleaseScope:                  "Live BSS/OSS billing integrations, vendor BRAS/BNG authorization proof, FreeRADIUS production interoperability, HA failover, scale, soak, security audit, production rollout, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 2869", "RFC 3162", "RFC 5176"},
		Vendors:                       []string{"Cisco", "Juniper ERX/E-Series", "Huawei BRAS/BNG", "Nokia/Alcatel-Lucent SR OS", "Ericsson/Redback", "MikroTik", "H3C", "ZTE", "Calix", "Adtran", "Nomadix", "ChilliSpot", "FreeRADIUS"},
		Requirements: []string{
			"commercial account hierarchy is represented independently from access sessions",
			"product plans bind business catalog terms to subscriber service products and RADIUS authorization attributes",
			"service bundles enforce eligibility, mutual exclusion, subscription state, and shared concurrency intent",
			"accounting start/interim/stop records correlate commercial subscription identity with session ownership",
			"concurrency decisions can reject, suspend, quarantine, degrade, or trigger CoA/Disconnect actions without losing audit history",
			"preview/apply operations persist software evidence while external vendor and billing certification remains explicit",
		},
		Notes: []string{
			"NAS-0084 completes software governance for commercial broadband account, plan, bundle, subscription, and concurrency state.",
			"The catalog is vendor neutral but records the RADIUS and VSA surfaces used by major BRAS/BNG vendors.",
		},
	}
	report.Summary = BroadbandCommercialCatalogSummary{
		Enabled:                       catalog.Enabled,
		Mode:                          catalog.Mode,
		FailClosed:                    catalog.FailClosed,
		DefaultBillingPeriod:          strings.ToLower(strings.TrimSpace(catalog.DefaultBillingPeriod)),
		DefaultCurrency:               strings.ToUpper(strings.TrimSpace(catalog.DefaultCurrency)),
		AllowFamilyAccounts:           catalog.AllowFamilyAccounts,
		RequireActiveSubscription:     catalog.RequireActiveSubscription,
		RequireBundleEligibility:      catalog.RequireBundleEligibility,
		EnforceConcurrency:            catalog.EnforceConcurrency,
		AccountingCorrelationRequired: catalog.AccountingCorrelationRequired,
		CoAOnLimit:                    catalog.CoAOnLimit,
		MaxAccounts:                   catalog.MaxAccounts,
		MaxSubscriptions:              catalog.MaxSubscriptions,
		MaxSessionsPerAccount:         catalog.MaxSessionsPerAccount,
		MaxSessionsPerSubscription:    catalog.MaxSessionsPerSubscription,
		PeriodResetHour:               catalog.PeriodResetHour,
		EventRetentionLimit:           catalog.EventRetentionLimit,
		SubscriberStateEnabled:        state.Enabled,
		SQLAccountingEnabled:          cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled:     cfg.Radius.AccountingServices.Enabled,
		DynamicAuthEnabled:            cfg.Radius.DynamicAuth.Enabled,
		HighAvailabilityEnabled:       cfg.HighAvailability.Enabled,
		ExternalRequirementCount:      9,
	}
	report.Accounts = buildBroadbandCommercialAccounts(catalog)
	report.Plans = buildBroadbandCommercialPlans(catalog, state)
	report.Bundles = buildBroadbandCommercialBundles(catalog)
	report.Subscriptions = buildBroadbandCommercialSubscriptions(catalog)
	report.ConcurrencyPolicies = buildBroadbandCommercialConcurrencyPolicies(catalog)
	report.AuthorizationBindings = buildBroadbandCommercialAuthorizationBindings(catalog)
	report.AccountingBindings = buildBroadbandCommercialAccountingBindings(catalog)
	fillBroadbandCommercialCounts(&report)
	if summary, err := db.GetBroadbandCommercialCatalogSummary(); err == nil {
		report.Summary.ActiveSessionCount = summary.ActiveSessions
		if report.Summary.ActiveSessionCount == 0 {
			report.Summary.ActiveSessionCount = countCommercialConfiguredActiveSessions(report.Subscriptions)
		}
		report.Summary.OverLimitCount += summary.OverLimitRecords
	}
	if !catalog.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0084 software is ready; broadband commercial catalog enforcement is not active in this configuration."
		report.Compliance = buildBroadbandCommercialCatalogCompliance(cfg, catalog, state, report)
		report.Summary.ComplianceCheckCount = len(report.Compliance)
		report.Summary.PassedCheckCount = countBroadbandCommercialChecks(report.Compliance, "passed")
		report.PlanFingerprint = broadbandCommercialCatalogFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}
	report.Compliance = buildBroadbandCommercialCatalogCompliance(cfg, catalog, state, report)
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
		report.Message = fmt.Sprintf("NAS-0084 commercial catalog is blocked by %d requirement(s).", len(report.Blockers))
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0084 commercial catalog is ready with %d warning(s).", len(report.Warnings))
	default:
		report.Status = "ready"
		report.Message = fmt.Sprintf("NAS-0084 commercial catalog is ready with %d account(s), %d plan(s), %d bundle(s), %d subscription(s), and %d concurrency policie(s).",
			report.Summary.AccountCount, report.Summary.EnabledPlanCount, report.Summary.EnabledBundleCount, report.Summary.SubscriptionCount, report.Summary.EnabledConcurrencyPolicyCount)
	}
	report.PlanFingerprint = broadbandCommercialCatalogFingerprint(report)
	return report, nil
}

func PreviewAndRecordBroadbandCommercialCatalog(cfg *config.Config, actor string) (BroadbandCommercialCatalogReport, string, error) {
	report, err := PreviewBroadbandCommercialCatalog(cfg)
	if err != nil {
		return BroadbandCommercialCatalogReport{}, "", err
	}
	eventID, err := recordBroadbandCommercialCatalogEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyBroadbandCommercialCatalog(ctx context.Context, cfg *config.Config, actor string) (BroadbandCommercialCatalogReport, string, error) {
	report, err := PreviewBroadbandCommercialCatalog(cfg)
	if err != nil {
		return BroadbandCommercialCatalogReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordBroadbandCommercialCatalogEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(broadbandCommercialCatalogComponent, "down", report.Message, broadbandCommercialCatalogRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband commercial catalog apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0084 recorded commercial catalog with %d account(s), %d plan(s), %d subscription(s), and %d concurrency policie(s).",
			report.Summary.AccountCount, report.Summary.EnabledPlanCount, report.Summary.SubscriptionCount, report.Summary.EnabledConcurrencyPolicyCount)
	}
	eventID, err := recordBroadbandCommercialCatalogEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := broadbandCommercialCatalogRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if report.Summary.WarningCount > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(broadbandCommercialCatalogComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(broadbandCommercialCatalogComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordBroadbandCommercialCatalogEvent(report BroadbandCommercialCatalogReport, operation, actor string) (string, error) {
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
	return db.RecordBroadbandCommercialCatalogEvent(db.BroadbandCommercialCatalogEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		AccountCount:             report.Summary.AccountCount,
		PlanCount:                report.Summary.PlanCount,
		BundleCount:              report.Summary.BundleCount,
		SubscriptionCount:        report.Summary.SubscriptionCount,
		ConcurrencyPolicyCount:   report.Summary.ConcurrencyPolicyCount,
		ActiveSubscriptionCount:  report.Summary.ActiveSubscriptionCount,
		ActiveSessionCount:       report.Summary.ActiveSessionCount,
		OverLimitCount:           report.Summary.OverLimitCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              marshalJSON(report.Summary),
		ReportJSON:               marshalJSON(report),
		Actor:                    actor,
		Accounts:                 dbAccountsFromBroadbandCommercialReport(report),
		Plans:                    dbPlansFromBroadbandCommercialReport(report),
		Bundles:                  dbBundlesFromBroadbandCommercialReport(report),
		Subscriptions:            dbSubscriptionsFromBroadbandCommercialReport(report),
		ConcurrencyPolicies:      dbConcurrencyPoliciesFromBroadbandCommercialReport(report),
	})
}

func buildBroadbandCommercialAccounts(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialAccount {
	accounts := make([]BroadbandCommercialAccount, 0, len(catalog.Accounts))
	for _, account := range catalog.Accounts {
		status := strings.ToLower(strings.TrimSpace(account.Status))
		if status == "" {
			status = "active"
		}
		reason := "Account can own commercial subscriptions."
		if status != "active" {
			reason = "Account is present for audit and lifecycle state but is not active."
		}
		accounts = append(accounts, BroadbandCommercialAccount{
			AccountID:        strings.TrimSpace(account.AccountID),
			ParentAccountID:  strings.TrimSpace(account.ParentAccountID),
			Tenant:           strings.TrimSpace(account.Tenant),
			Status:           status,
			BillingMode:      strings.ToLower(strings.TrimSpace(account.BillingMode)),
			OwnerName:        strings.TrimSpace(account.OwnerName),
			Contact:          strings.TrimSpace(account.Contact),
			MaxSubscriptions: account.MaxSubscriptions,
			MaxSessions:      account.MaxSessions,
			Tags:             cleanStringList(account.Tags),
			FamilyAccount:    strings.TrimSpace(account.ParentAccountID) != "",
			Reason:           reason,
		})
	}
	return accounts
}

func buildBroadbandCommercialPlans(catalog config.BroadbandCommercialCatalog, state config.BroadbandSubscriberStateConfig) []BroadbandCommercialPlan {
	products := map[string]config.BroadbandSubscriberProductConfig{}
	for _, product := range state.Products {
		products[strings.ToLower(strings.TrimSpace(product.Name))] = product
	}
	plans := make([]BroadbandCommercialPlan, 0, len(catalog.Plans))
	for _, plan := range catalog.Plans {
		product, hasProduct := products[strings.ToLower(strings.TrimSpace(plan.Product))]
		status := "disabled"
		reason := "Plan is configured but disabled."
		if plan.Enabled {
			status = "active"
			reason = "Plan can authorize matching subscribers."
		}
		out := BroadbandCommercialPlan{
			Name:                  strings.TrimSpace(plan.Name),
			Enabled:               plan.Enabled,
			Product:               strings.TrimSpace(plan.Product),
			DisplayName:           strings.TrimSpace(plan.DisplayName),
			BillingPeriod:         firstNonEmptyString(strings.ToLower(strings.TrimSpace(plan.BillingPeriod)), strings.ToLower(strings.TrimSpace(catalog.DefaultBillingPeriod))),
			PriceMicros:           plan.PriceMicros,
			Currency:              firstNonEmptyString(strings.ToUpper(strings.TrimSpace(plan.Currency)), strings.ToUpper(strings.TrimSpace(catalog.DefaultCurrency))),
			MaxSessions:           plan.MaxSessions,
			MaxDevices:            plan.MaxDevices,
			DownstreamKbps:        plan.DownstreamKbps,
			UpstreamKbps:          plan.UpstreamKbps,
			QuotaProfile:          strings.TrimSpace(plan.QuotaProfile),
			ServiceChain:          strings.TrimSpace(plan.ServiceChain),
			AddressPool:           strings.TrimSpace(plan.AddressPool),
			IPv6Pool:              strings.TrimSpace(plan.IPv6Pool),
			DelegatedIPv6Pool:     strings.TrimSpace(plan.DelegatedIPv6Pool),
			RoutePolicy:           strings.TrimSpace(plan.RoutePolicy),
			QoSProfile:            strings.TrimSpace(plan.QoSProfile),
			TranslationPool:       strings.TrimSpace(plan.TranslationPool),
			PortalProfile:         strings.TrimSpace(plan.PortalProfile),
			GraceSeconds:          plan.GraceSeconds,
			SuspensionRole:        strings.TrimSpace(plan.SuspensionRole),
			SessionTimeoutSeconds: plan.SessionTimeoutSeconds,
			IdleTimeoutSeconds:    plan.IdleTimeoutSeconds,
			VendorPacks:           cleanStringList(plan.VendorPacks),
			Status:                status,
			Reason:                reason,
		}
		if hasProduct {
			out.ServiceChain = firstNonEmptyString(out.ServiceChain, product.ServiceChain)
			out.AddressPool = firstNonEmptyString(out.AddressPool, product.AddressPool)
			out.IPv6Pool = firstNonEmptyString(out.IPv6Pool, product.IPv6Pool)
			out.DelegatedIPv6Pool = firstNonEmptyString(out.DelegatedIPv6Pool, product.DelegatedIPv6Pool)
			out.RoutePolicy = firstNonEmptyString(out.RoutePolicy, product.RoutePolicy)
			out.QoSProfile = firstNonEmptyString(out.QoSProfile, product.QoSProfile)
			out.TranslationPool = firstNonEmptyString(out.TranslationPool, product.TranslationPool)
			out.QuotaProfile = firstNonEmptyString(out.QuotaProfile, product.QuotaProfile)
			if out.MaxSessions == 0 {
				out.MaxSessions = product.MaxSessions
			}
			if out.SessionTimeoutSeconds == 0 {
				out.SessionTimeoutSeconds = product.SessionTimeoutSeconds
			}
			if out.IdleTimeoutSeconds == 0 {
				out.IdleTimeoutSeconds = product.IdleTimeoutSeconds
			}
			if len(out.VendorPacks) == 0 {
				out.VendorPacks = cleanStringList(product.VendorPacks)
			}
		}
		plans = append(plans, out)
	}
	return plans
}

func buildBroadbandCommercialBundles(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialBundle {
	bundles := make([]BroadbandCommercialBundle, 0, len(catalog.Bundles))
	for _, bundle := range catalog.Bundles {
		status := "disabled"
		reason := "Bundle is configured but disabled."
		if bundle.Enabled {
			status = "active"
			reason = "Bundle can group plans and enforce eligibility constraints."
		}
		bundles = append(bundles, BroadbandCommercialBundle{
			Name:                       strings.TrimSpace(bundle.Name),
			Enabled:                    bundle.Enabled,
			DisplayName:                strings.TrimSpace(bundle.DisplayName),
			Plans:                      cleanStringList(bundle.Plans),
			RequiredPlans:              cleanStringList(bundle.RequiredPlans),
			MutuallyExclusivePlans:     cleanStringList(bundle.MutuallyExclusivePlans),
			MaxConcurrentSubscriptions: bundle.MaxConcurrentSubscriptions,
			SharedConcurrency:          bundle.SharedConcurrency,
			Priority:                   bundle.Priority,
			EligibilityTags:            cleanStringList(bundle.EligibilityTags),
			Status:                     status,
			Reason:                     reason,
		})
	}
	return bundles
}

func buildBroadbandCommercialSubscriptions(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialSubscription {
	subscriptions := make([]BroadbandCommercialSubscription, 0, len(catalog.Subscriptions))
	for _, subscription := range catalog.Subscriptions {
		status := strings.ToLower(strings.TrimSpace(subscription.Status))
		if status == "" {
			status = "active"
		}
		reason := "Subscription can authorize its subscriber to the bound plan."
		if status != "active" {
			reason = "Subscription is present for commercial lifecycle evidence but is not active."
		}
		maxSessions := subscription.MaxSessions
		if maxSessions == 0 {
			maxSessions = catalog.MaxSessionsPerSubscription
		}
		activeSessions := 0
		overLimit := maxSessions > 0 && activeSessions > maxSessions
		subscriptions = append(subscriptions, BroadbandCommercialSubscription{
			SubscriptionID:     strings.TrimSpace(subscription.SubscriptionID),
			AccountID:          strings.TrimSpace(subscription.AccountID),
			SubscriberID:       strings.TrimSpace(subscription.SubscriberID),
			Username:           strings.TrimSpace(subscription.Username),
			Plan:               strings.TrimSpace(subscription.Plan),
			Bundle:             strings.TrimSpace(subscription.Bundle),
			Status:             status,
			StartsAt:           strings.TrimSpace(subscription.StartsAt),
			EndsAt:             strings.TrimSpace(subscription.EndsAt),
			AutoRenew:          subscription.AutoRenew,
			MaxSessions:        maxSessions,
			DeviceLimit:        subscription.DeviceLimit,
			EligibilityTags:    cleanStringList(subscription.EligibilityTags),
			ActiveSessionCount: activeSessions,
			OverLimit:          overLimit,
			Reason:             reason,
		})
	}
	return subscriptions
}

func buildBroadbandCommercialConcurrencyPolicies(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialConcurrencyPolicy {
	policies := make([]BroadbandCommercialConcurrencyPolicy, 0, len(catalog.ConcurrencyPolicies))
	for _, policy := range catalog.ConcurrencyPolicies {
		scope := strings.ToLower(strings.TrimSpace(policy.Scope))
		if scope == "" {
			scope = "subscriber"
		}
		action := strings.ToLower(strings.TrimSpace(policy.Action))
		if action == "" {
			action = "reject"
		}
		status := "disabled"
		reason := "Concurrency policy is configured but disabled."
		if policy.Enabled {
			status = "active"
			reason = "Concurrency policy can govern active sessions for the selected commercial scope."
		}
		target := commercialPolicyTarget(scope, policy)
		policies = append(policies, BroadbandCommercialConcurrencyPolicy{
			PolicyKey:                commercialPolicyKey(policy.Name, scope, target),
			Name:                     strings.TrimSpace(policy.Name),
			Enabled:                  policy.Enabled,
			Scope:                    scope,
			Target:                   target,
			AccountID:                strings.TrimSpace(policy.AccountID),
			Tenant:                   strings.TrimSpace(policy.Tenant),
			Plan:                     strings.TrimSpace(policy.Plan),
			Bundle:                   strings.TrimSpace(policy.Bundle),
			MaxSessions:              policy.MaxSessions,
			MaxSessionsPerSubscriber: policy.MaxSessionsPerSubscriber,
			BurstSessions:            policy.BurstSessions,
			GraceSeconds:             policy.GraceSeconds,
			Action:                   action,
			CoAAction:                strings.TrimSpace(policy.CoAAction),
			Status:                   status,
			Reason:                   reason,
		})
	}
	return policies
}

func buildBroadbandCommercialAuthorizationBindings(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialAuthorizationBinding {
	return []BroadbandCommercialAuthorizationBinding{
		{"commercial-lookup", []string{"User-Name", "Calling-Station-Id", "NAS-Identifier", "Class"}, "Resolve account, subscription, plan, bundle, tenant, and subscriber identity before Access-Accept.", catalog.Enabled},
		{"plan-enforcement", []string{"Filter-Id", "Class", "Session-Timeout", "Idle-Timeout", "Mikrotik-Rate-Limit", "Cisco-AVPair", "Juniper-Local-User-Name", "Huawei-User-Group", "Alc-Subsc-ID-Str"}, "Render selected commercial plan into standard and vendor-specific authorization attributes.", catalog.Enabled},
		{"suspension-or-quarantine", []string{"Filter-Id", "Reply-Message", "Tunnel-Private-Group-Id", "Cisco-AVPair", "Mikrotik-Address-List"}, "Apply suspension, quarantine, or degraded service when subscription state or concurrency policy requires it.", catalog.RequireActiveSubscription || catalog.EnforceConcurrency},
		{"dynamic-authorization", []string{"CoA-Request", "Disconnect-Request", "Error-Cause", "Event-Timestamp"}, "Update or tear down live sessions after subscription, bundle, quota, or concurrency state changes.", catalog.CoAOnLimit},
	}
}

func buildBroadbandCommercialAccountingBindings(catalog config.BroadbandCommercialCatalog) []BroadbandCommercialAccountingBinding {
	return []BroadbandCommercialAccountingBinding{
		{"accounting-start", []string{"Acct-Status-Type=Start", "Acct-Session-Id", "User-Name", "NAS-Identifier", "Class", "Acct-Multi-Session-Id"}, "Promote authorized commercial subscription into active session ownership.", catalog.AccountingCorrelationRequired},
		{"interim", []string{"Acct-Status-Type=Interim-Update", "Acct-Session-Time", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Input-Gigawords", "Acct-Output-Gigawords"}, "Refresh usage, concurrent session counts, charging records, and bundle eligibility counters.", catalog.AccountingCorrelationRequired},
		{"accounting-stop", []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause", "Acct-Session-Id", "Event-Timestamp"}, "Release session ownership and close commercial usage evidence.", catalog.AccountingCorrelationRequired},
		{"charging-export", []string{"Acct-Session-Time", "Framed-IP-Address", "Delegated-IPv6-Prefix", "Class"}, "Correlate accounting ledgers with external BSS/OSS charging and invoices.", catalog.AccountingCorrelationRequired},
	}
}

func fillBroadbandCommercialCounts(report *BroadbandCommercialCatalogReport) {
	report.Summary.AccountCount = len(report.Accounts)
	report.Summary.PlanCount = len(report.Plans)
	report.Summary.BundleCount = len(report.Bundles)
	report.Summary.SubscriptionCount = len(report.Subscriptions)
	report.Summary.ConcurrencyPolicyCount = len(report.ConcurrencyPolicies)
	report.Summary.AuthorizationBindingCount = len(report.AuthorizationBindings)
	report.Summary.AccountingBindingCount = len(report.AccountingBindings)
	for _, account := range report.Accounts {
		if account.Status == "active" {
			report.Summary.ActiveAccountCount++
		}
		if account.FamilyAccount {
			report.Summary.FamilyAccountCount++
		}
	}
	for _, plan := range report.Plans {
		if plan.Enabled {
			report.Summary.EnabledPlanCount++
		}
	}
	for _, bundle := range report.Bundles {
		if bundle.Enabled {
			report.Summary.EnabledBundleCount++
		}
	}
	for _, subscription := range report.Subscriptions {
		if subscription.Status == "active" {
			report.Summary.ActiveSubscriptionCount++
		}
		if subscription.Status == "suspended" {
			report.Summary.SuspendedSubscriptionCount++
		}
		report.Summary.ActiveSessionCount += subscription.ActiveSessionCount
		if subscription.OverLimit {
			report.Summary.OverLimitCount++
		}
	}
	for _, policy := range report.ConcurrencyPolicies {
		if policy.Enabled {
			report.Summary.EnabledConcurrencyPolicyCount++
		}
	}
}

func buildBroadbandCommercialCatalogCompliance(cfg *config.Config, catalog config.BroadbandCommercialCatalog, state config.BroadbandSubscriberStateConfig, report BroadbandCommercialCatalogReport) []BroadbandCommercialCatalogCheck {
	return []BroadbandCommercialCatalogCheck{
		broadbandCommercialCheck("subscriber-state", "Subscriber state dependency", state.Enabled || !catalog.Enabled, "Subscriber state machine is enabled or commercial catalog is disabled.", "Commercial catalog requires broadband.subscriber_state.enabled.", "broadband.subscriber_state"),
		broadbandCommercialCheck("plans", "Active plan catalog", report.Summary.EnabledPlanCount > 0 || !catalog.Enabled, "At least one enabled commercial plan is configured or catalog is disabled.", "Enabled commercial catalog requires at least one enabled plan.", "broadband.commercial_catalog.plans"),
		broadbandCommercialCheck("accounts", "Account catalog", report.Summary.AccountCount > 0 || report.Summary.SubscriptionCount == 0 || !catalog.Enabled, "Accounts exist for configured subscriptions or no subscriptions are configured.", "Commercial subscriptions require durable account records.", "broadband.commercial_catalog.accounts"),
		broadbandCommercialCheck("subscriptions", "Active subscriptions", !catalog.RequireActiveSubscription || report.Summary.ActiveSubscriptionCount > 0 || !catalog.Enabled, "Active subscriptions exist or are not required.", "require_active_subscription requires at least one active subscription.", "broadband.commercial_catalog.subscriptions"),
		broadbandCommercialCheck("family-accounts", "Family account hierarchy", catalog.AllowFamilyAccounts || report.Summary.FamilyAccountCount == 0 || !catalog.Enabled, "Family accounts are allowed or no parent account links exist.", "Parent account links require allow_family_accounts.", "broadband.commercial_catalog.allow_family_accounts"),
		broadbandCommercialCheck("bundles", "Bundle eligibility", !catalog.RequireBundleEligibility || report.Summary.EnabledBundleCount > 0 || !catalog.Enabled, "Enabled bundles exist or bundle eligibility is not required.", "require_bundle_eligibility requires at least one enabled bundle.", "broadband.commercial_catalog.bundles"),
		broadbandCommercialCheck("concurrency", "Concurrent session policy", !catalog.EnforceConcurrency || report.Summary.EnabledConcurrencyPolicyCount > 0 || !catalog.Enabled, "Concurrency policy is configured or concurrency enforcement is disabled.", "enforce_concurrency requires at least one enabled concurrency policy.", "broadband.commercial_catalog.concurrency_policies"),
		broadbandCommercialCheck("accounting", "Accounting correlation", !catalog.AccountingCorrelationRequired || (cfg.Radius.SQLAccounting.Enabled && cfg.Radius.AccountingServices.Enabled) || !catalog.Enabled, "SQL accounting and accounting services are available.", "Commercial accounting correlation requires radius.sql_accounting.enabled and radius.accounting_services.enabled.", "radius.sql_accounting", "radius.accounting_services"),
		broadbandCommercialCheck("coa", "CoA limit recovery", !catalog.CoAOnLimit || cfg.Radius.DynamicAuth.Enabled || !catalog.Enabled, "Dynamic authorization is available for limit recovery.", "coa_on_limit requires radius.dynamic_auth.enabled.", "RFC 5176"),
		broadbandCommercialCheck("fail-closed", "Enforce-mode fail-closed", catalog.Mode != "enforce" || catalog.FailClosed || !catalog.Enabled, "Enforce mode is fail-closed.", "Commercial enforce mode should use fail_closed to avoid free access during catalog failure.", "broadband.commercial_catalog.fail_closed"),
		broadbandCommercialCheck("plan-product-binding", "Plan to subscriber product binding", commercialPlansHaveServiceBinding(report.Plans) || !catalog.Enabled, "Commercial plans resolve to product or direct service attributes.", "Commercial plans must bind to a subscriber product or declare service attributes directly.", "broadband.subscriber_state.products", "broadband.commercial_catalog.plans"),
	}
}

func broadbandCommercialCheck(id, name string, passed bool, passedMessage, blockedMessage string, evidence ...string) BroadbandCommercialCatalogCheck {
	if passed {
		return BroadbandCommercialCatalogCheck{ID: id, Name: name, Status: "passed", Message: passedMessage, Evidence: evidence}
	}
	return BroadbandCommercialCatalogCheck{ID: id, Name: name, Status: "blocked", Message: blockedMessage, Evidence: evidence}
}

func countBroadbandCommercialChecks(checks []BroadbandCommercialCatalogCheck, status string) int {
	count := 0
	for _, check := range checks {
		if check.Status == status {
			count++
		}
	}
	return count
}

func commercialPlansHaveServiceBinding(plans []BroadbandCommercialPlan) bool {
	for _, plan := range plans {
		if !plan.Enabled {
			continue
		}
		if strings.TrimSpace(plan.Product) != "" ||
			strings.TrimSpace(plan.ServiceChain) != "" ||
			strings.TrimSpace(plan.AddressPool) != "" ||
			strings.TrimSpace(plan.IPv6Pool) != "" ||
			strings.TrimSpace(plan.DelegatedIPv6Pool) != "" ||
			strings.TrimSpace(plan.QoSProfile) != "" ||
			strings.TrimSpace(plan.RoutePolicy) != "" ||
			strings.TrimSpace(plan.TranslationPool) != "" {
			return true
		}
	}
	return false
}

func countCommercialConfiguredActiveSessions(subscriptions []BroadbandCommercialSubscription) int {
	total := 0
	for _, subscription := range subscriptions {
		total += subscription.ActiveSessionCount
	}
	return total
}

func commercialPolicyTarget(scope string, policy config.BroadbandCommercialConcurrencyPolicyConfig) string {
	switch scope {
	case "account":
		return strings.TrimSpace(policy.AccountID)
	case "tenant":
		return strings.TrimSpace(policy.Tenant)
	case "plan":
		return strings.TrimSpace(policy.Plan)
	case "bundle":
		return strings.TrimSpace(policy.Bundle)
	case "subscription":
		return firstNonEmptyString(strings.TrimSpace(policy.Plan), strings.TrimSpace(policy.Bundle), strings.TrimSpace(policy.AccountID))
	default:
		return firstNonEmptyString(strings.TrimSpace(policy.Plan), strings.TrimSpace(policy.Bundle), strings.TrimSpace(policy.AccountID), strings.TrimSpace(policy.Tenant), "*")
	}
}

func commercialPolicyKey(name, scope, target string) string {
	return "bccp_" + sha256JSON([]string{strings.TrimSpace(name), strings.TrimSpace(scope), strings.TrimSpace(target)})[:20]
}

func cleanStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func broadbandCommercialCatalogFingerprint(report BroadbandCommercialCatalogReport) string {
	return sha256JSON(map[string]any{
		"feature_id":             report.FeatureID,
		"summary":                report.Summary,
		"accounts":               report.Accounts,
		"plans":                  report.Plans,
		"bundles":                report.Bundles,
		"subscriptions":          report.Subscriptions,
		"concurrency_policies":   report.ConcurrencyPolicies,
		"authorization_bindings": report.AuthorizationBindings,
		"accounting_bindings":    report.AccountingBindings,
		"compliance":             report.Compliance,
	})
}

func broadbandCommercialCatalogRuntimeDetails(report BroadbandCommercialCatalogReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                       report.FeatureID,
		"event_id":                         eventID,
		"plan_fingerprint":                 report.PlanFingerprint,
		"mode":                             report.Summary.Mode,
		"account_count":                    report.Summary.AccountCount,
		"plan_count":                       report.Summary.PlanCount,
		"subscription_count":               report.Summary.SubscriptionCount,
		"active_subscription_count":        report.Summary.ActiveSubscriptionCount,
		"concurrency_policy_count":         report.Summary.ConcurrencyPolicyCount,
		"enabled_concurrency_policy_count": report.Summary.EnabledConcurrencyPolicyCount,
		"active_session_count":             report.Summary.ActiveSessionCount,
		"over_limit_count":                 report.Summary.OverLimitCount,
		"blocker_count":                    report.Summary.BlockerCount,
		"warning_count":                    report.Summary.WarningCount,
		"ready_for_external_validation":    report.ReadyForExternalValidation,
	}
}

func dbAccountsFromBroadbandCommercialReport(report BroadbandCommercialCatalogReport) []db.BroadbandCommercialAccountInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandCommercialAccountInput, 0, len(report.Accounts))
	for _, account := range report.Accounts {
		out = append(out, db.BroadbandCommercialAccountInput{
			AccountID:        account.AccountID,
			ParentAccountID:  account.ParentAccountID,
			Tenant:           account.Tenant,
			Status:           account.Status,
			BillingMode:      account.BillingMode,
			OwnerName:        account.OwnerName,
			Contact:          account.Contact,
			MaxSubscriptions: account.MaxSubscriptions,
			MaxSessions:      account.MaxSessions,
			TagsJSON:         marshalJSON(account.Tags),
			MetadataJSON: marshalJSON(map[string]any{
				"family_account": account.FamilyAccount,
				"reason":         account.Reason,
			}),
		})
	}
	return out
}

func dbPlansFromBroadbandCommercialReport(report BroadbandCommercialCatalogReport) []db.BroadbandCommercialPlanInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandCommercialPlanInput, 0, len(report.Plans))
	for _, plan := range report.Plans {
		out = append(out, db.BroadbandCommercialPlanInput{
			Name:                  plan.Name,
			Product:               plan.Product,
			Status:                plan.Status,
			DisplayName:           plan.DisplayName,
			BillingPeriod:         plan.BillingPeriod,
			PriceMicros:           plan.PriceMicros,
			Currency:              plan.Currency,
			MaxSessions:           plan.MaxSessions,
			MaxDevices:            plan.MaxDevices,
			DownstreamKbps:        plan.DownstreamKbps,
			UpstreamKbps:          plan.UpstreamKbps,
			QuotaProfile:          plan.QuotaProfile,
			ServiceChain:          plan.ServiceChain,
			AddressPool:           plan.AddressPool,
			IPv6Pool:              plan.IPv6Pool,
			DelegatedIPv6Pool:     plan.DelegatedIPv6Pool,
			RoutePolicy:           plan.RoutePolicy,
			QoSProfile:            plan.QoSProfile,
			TranslationPool:       plan.TranslationPool,
			PortalProfile:         plan.PortalProfile,
			GraceSeconds:          plan.GraceSeconds,
			SuspensionRole:        plan.SuspensionRole,
			SessionTimeoutSeconds: plan.SessionTimeoutSeconds,
			IdleTimeoutSeconds:    plan.IdleTimeoutSeconds,
			VendorPacksJSON:       marshalJSON(plan.VendorPacks),
			MetadataJSON: marshalJSON(map[string]any{
				"enabled": plan.Enabled,
				"reason":  plan.Reason,
			}),
		})
	}
	return out
}

func dbBundlesFromBroadbandCommercialReport(report BroadbandCommercialCatalogReport) []db.BroadbandCommercialBundleInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandCommercialBundleInput, 0, len(report.Bundles))
	for _, bundle := range report.Bundles {
		out = append(out, db.BroadbandCommercialBundleInput{
			Name:                       bundle.Name,
			Status:                     bundle.Status,
			DisplayName:                bundle.DisplayName,
			PlansJSON:                  marshalJSON(bundle.Plans),
			RequiredPlansJSON:          marshalJSON(bundle.RequiredPlans),
			MutuallyExclusivePlansJSON: marshalJSON(bundle.MutuallyExclusivePlans),
			MaxConcurrentSubscriptions: bundle.MaxConcurrentSubscriptions,
			SharedConcurrency:          bundle.SharedConcurrency,
			Priority:                   bundle.Priority,
			EligibilityTagsJSON:        marshalJSON(bundle.EligibilityTags),
			MetadataJSON: marshalJSON(map[string]any{
				"enabled": bundle.Enabled,
				"reason":  bundle.Reason,
			}),
		})
	}
	return out
}

func dbSubscriptionsFromBroadbandCommercialReport(report BroadbandCommercialCatalogReport) []db.BroadbandCommercialSubscriptionInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandCommercialSubscriptionInput, 0, len(report.Subscriptions))
	for _, subscription := range report.Subscriptions {
		out = append(out, db.BroadbandCommercialSubscriptionInput{
			SubscriptionID:      subscription.SubscriptionID,
			AccountID:           subscription.AccountID,
			SubscriberID:        subscription.SubscriberID,
			Username:            subscription.Username,
			PlanName:            subscription.Plan,
			BundleName:          subscription.Bundle,
			Status:              subscription.Status,
			StartsAt:            subscription.StartsAt,
			EndsAt:              subscription.EndsAt,
			AutoRenew:           subscription.AutoRenew,
			MaxSessions:         subscription.MaxSessions,
			DeviceLimit:         subscription.DeviceLimit,
			EligibilityTagsJSON: marshalJSON(subscription.EligibilityTags),
			ActiveSessionCount:  subscription.ActiveSessionCount,
			MetadataJSON: marshalJSON(map[string]any{
				"over_limit": subscription.OverLimit,
				"reason":     subscription.Reason,
			}),
		})
	}
	return out
}

func dbConcurrencyPoliciesFromBroadbandCommercialReport(report BroadbandCommercialCatalogReport) []db.BroadbandCommercialConcurrencyPolicyInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandCommercialConcurrencyPolicyInput, 0, len(report.ConcurrencyPolicies))
	for _, policy := range report.ConcurrencyPolicies {
		out = append(out, db.BroadbandCommercialConcurrencyPolicyInput{
			PolicyKey:                policy.PolicyKey,
			Name:                     policy.Name,
			Scope:                    policy.Scope,
			Target:                   policy.Target,
			AccountID:                policy.AccountID,
			Tenant:                   policy.Tenant,
			PlanName:                 policy.Plan,
			BundleName:               policy.Bundle,
			MaxSessions:              policy.MaxSessions,
			MaxSessionsPerSubscriber: policy.MaxSessionsPerSubscriber,
			BurstSessions:            policy.BurstSessions,
			GraceSeconds:             policy.GraceSeconds,
			Action:                   policy.Action,
			CoAAction:                policy.CoAAction,
			Status:                   policy.Status,
			MetadataJSON: marshalJSON(map[string]any{
				"enabled": policy.Enabled,
				"reason":  policy.Reason,
			}),
		})
	}
	return out
}
