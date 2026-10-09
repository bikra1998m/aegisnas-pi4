package config

import (
	"errors"
	"fmt"
	"strings"
)

type BroadbandGovernanceSelfServiceConfig struct {
	Enabled                  bool                                      `mapstructure:"enabled"`
	Mode                     string                                    `mapstructure:"mode"`
	FailClosed               bool                                      `mapstructure:"fail_closed"`
	RequireSubscriberState   bool                                      `mapstructure:"require_subscriber_state"`
	RequireCommercialCatalog bool                                      `mapstructure:"require_commercial_catalog"`
	RequireQuotaBalance      bool                                      `mapstructure:"require_quota_balance"`
	RequireAccounting        bool                                      `mapstructure:"require_accounting"`
	RequireDynamicAuth       bool                                      `mapstructure:"require_dynamic_auth"`
	RequireMFA               bool                                      `mapstructure:"require_mfa"`
	RequireAdminWebAuthn     bool                                      `mapstructure:"require_admin_webauthn"`
	LawfulInterceptEnabled   bool                                      `mapstructure:"lawful_intercept_enabled"`
	SelfServiceEnabled       bool                                      `mapstructure:"self_service_enabled"`
	PrivacyControlsEnabled   bool                                      `mapstructure:"privacy_controls_enabled"`
	ImmutableAuditRequired   bool                                      `mapstructure:"immutable_audit_required"`
	DualApprovalRequired     bool                                      `mapstructure:"dual_approval_required"`
	ApprovalThreshold        int                                       `mapstructure:"approval_threshold"`
	CaseRetentionDays        int                                       `mapstructure:"case_retention_days"`
	EventRetentionLimit      int                                       `mapstructure:"event_retention_limit"`
	Cases                    []BroadbandLawfulInterceptCaseConfig      `mapstructure:"cases"`
	ApprovalPolicies         []BroadbandGovernanceApprovalPolicyConfig `mapstructure:"approval_policies"`
	SelfServiceActions       []BroadbandSelfServiceActionConfig        `mapstructure:"self_service_actions"`
	PrivacyPolicies          []BroadbandPrivacyPolicyConfig            `mapstructure:"privacy_policies"`
}

type BroadbandLawfulInterceptCaseConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	CaseID           string   `mapstructure:"case_id"`
	LegalAuthority   string   `mapstructure:"legal_authority"`
	RequestReference string   `mapstructure:"request_reference"`
	SubscriberID     string   `mapstructure:"subscriber_id"`
	Username         string   `mapstructure:"username"`
	Tenant           string   `mapstructure:"tenant"`
	Scope            string   `mapstructure:"scope"`
	ExportAdapter    string   `mapstructure:"export_adapter"`
	RetentionClass   string   `mapstructure:"retention_class"`
	Approvers        []string `mapstructure:"approvers"`
	AuditTags        []string `mapstructure:"audit_tags"`
}

type BroadbandGovernanceApprovalPolicyConfig struct {
	Name                 string   `mapstructure:"name"`
	Enabled              bool     `mapstructure:"enabled"`
	Scope                string   `mapstructure:"scope"`
	MinApprovals         int      `mapstructure:"min_approvals"`
	RequireMFA           bool     `mapstructure:"require_mfa"`
	RequireWebAuthn      bool     `mapstructure:"require_webauthn"`
	BreakGlassAllowed    bool     `mapstructure:"break_glass_allowed"`
	AllowedRoles         []string `mapstructure:"allowed_roles"`
	EscalationRecipients []string `mapstructure:"escalation_recipients"`
}

type BroadbandSelfServiceActionConfig struct {
	Name                  string   `mapstructure:"name"`
	Enabled               bool     `mapstructure:"enabled"`
	Action                string   `mapstructure:"action"`
	RequiresAuth          bool     `mapstructure:"requires_auth"`
	RequiresMFA           bool     `mapstructure:"requires_mfa"`
	RequiresApproval      bool     `mapstructure:"requires_approval"`
	AllowedProducts       []string `mapstructure:"allowed_products"`
	AllowedTenants        []string `mapstructure:"allowed_tenants"`
	RateLimitPerHour      int      `mapstructure:"rate_limit_per_hour"`
	MaxPendingRequests    int      `mapstructure:"max_pending_requests"`
	NotificationChannel   string   `mapstructure:"notification_channel"`
	AccountingCorrelation bool     `mapstructure:"accounting_correlation"`
}

type BroadbandPrivacyPolicyConfig struct {
	Name             string   `mapstructure:"name"`
	Enabled          bool     `mapstructure:"enabled"`
	DataClass        string   `mapstructure:"data_class"`
	AccessPurpose    string   `mapstructure:"access_purpose"`
	RetentionDays    int      `mapstructure:"retention_days"`
	RedactFields     []string `mapstructure:"redact_fields"`
	ExportAllowed    bool     `mapstructure:"export_allowed"`
	SubscriberNotice bool     `mapstructure:"subscriber_notice"`
}

func EffectiveBroadbandGovernanceSelfServiceConfig(raw BroadbandGovernanceSelfServiceConfig) BroadbandGovernanceSelfServiceConfig {
	governance := raw
	governance.Mode = effectiveBroadbandGovernanceMode(governance.Mode)
	if governance.ApprovalThreshold == 0 {
		governance.ApprovalThreshold = 2
	}
	if governance.CaseRetentionDays == 0 {
		governance.CaseRetentionDays = 365
	}
	if governance.EventRetentionLimit == 0 {
		governance.EventRetentionLimit = 10000
	}
	if !raw.RequireSubscriberState && !raw.RequireCommercialCatalog && !raw.RequireQuotaBalance &&
		!raw.RequireAccounting && !raw.RequireDynamicAuth && !raw.RequireMFA && !raw.RequireAdminWebAuthn &&
		!raw.LawfulInterceptEnabled && !raw.SelfServiceEnabled && !raw.PrivacyControlsEnabled &&
		!raw.ImmutableAuditRequired && !raw.DualApprovalRequired {
		governance.RequireSubscriberState = true
		governance.RequireCommercialCatalog = true
		governance.RequireQuotaBalance = true
		governance.RequireAccounting = true
		governance.RequireDynamicAuth = true
		governance.RequireMFA = true
		governance.RequireAdminWebAuthn = true
		governance.LawfulInterceptEnabled = true
		governance.SelfServiceEnabled = true
		governance.PrivacyControlsEnabled = true
		governance.ImmutableAuditRequired = true
		governance.DualApprovalRequired = true
	}
	return governance
}

func effectiveBroadbandGovernanceMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "monitor", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "monitor"
	}
}

func validateBroadbandGovernanceSelfServiceConfig(raw BroadbandGovernanceSelfServiceConfig, subscriberRaw BroadbandSubscriberStateConfig, catalogRaw BroadbandCommercialCatalog, quotaRaw BroadbandQuotaBalanceConfig, radius RadiusConfig, mfa MFAConfig, webauthn AdminWebAuthnConfig, profile string) error {
	governance := EffectiveBroadbandGovernanceSelfServiceConfig(raw)
	if !governance.Enabled && len(governance.Cases) == 0 && len(governance.ApprovalPolicies) == 0 &&
		len(governance.SelfServiceActions) == 0 && len(governance.PrivacyPolicies) == 0 {
		return nil
	}
	if profile == "lite" && governance.Mode == "enforce" {
		return errors.New("broadband.governance_self_service cannot use enforce mode on lite deployment profile")
	}
	if governance.ApprovalThreshold < 0 || governance.ApprovalThreshold > 10 {
		return errors.New("broadband.governance_self_service.approval_threshold must be between 0 and 10")
	}
	if governance.CaseRetentionDays < 0 || governance.CaseRetentionDays > 3650 {
		return errors.New("broadband.governance_self_service.case_retention_days must be between 0 and 3650")
	}
	if governance.EventRetentionLimit < 0 || governance.EventRetentionLimit > 1000000 {
		return errors.New("broadband.governance_self_service.event_retention_limit must be between 0 and 1000000")
	}
	subscriber := EffectiveBroadbandSubscriberStateConfig(subscriberRaw)
	catalog := EffectiveBroadbandCommercialCatalog(catalogRaw)
	quota := EffectiveBroadbandQuotaBalanceConfig(quotaRaw)
	if governance.Enabled && governance.RequireSubscriberState && !subscriber.Enabled {
		return errors.New("broadband.governance_self_service requires broadband.subscriber_state.enabled")
	}
	if governance.Enabled && governance.RequireCommercialCatalog && !catalog.Enabled {
		return errors.New("broadband.governance_self_service requires broadband.commercial_catalog.enabled")
	}
	if governance.Enabled && governance.RequireQuotaBalance && !quota.Enabled {
		return errors.New("broadband.governance_self_service requires broadband.quota_balance.enabled")
	}
	if governance.Enabled && governance.RequireAccounting && (!radius.SQLAccounting.Enabled || !radius.AccountingServices.Enabled) {
		return errors.New("broadband.governance_self_service requires radius.sql_accounting and radius.accounting_services")
	}
	if governance.Enabled && governance.RequireDynamicAuth && !radius.DynamicAuth.Enabled {
		return errors.New("broadband.governance_self_service requires radius.dynamic_auth.enabled")
	}
	if governance.Enabled && governance.RequireMFA && !EffectiveMFAConfig(mfa).Enabled {
		return errors.New("broadband.governance_self_service requires mfa.enabled")
	}
	if governance.Enabled && governance.RequireAdminWebAuthn && !EffectiveAdminWebAuthnConfig(webauthn).Enabled {
		return errors.New("broadband.governance_self_service requires admin_webauthn.enabled")
	}
	enabledCases, err := validateBroadbandGovernanceCases(governance)
	if err != nil {
		return err
	}
	enabledApprovals, err := validateBroadbandGovernanceApprovalPolicies(governance)
	if err != nil {
		return err
	}
	enabledActions, err := validateBroadbandSelfServiceActions(governance, broadbandCommercialPlanNames(catalog))
	if err != nil {
		return err
	}
	enabledPrivacy, err := validateBroadbandPrivacyPolicies(governance)
	if err != nil {
		return err
	}
	if governance.Enabled && governance.Mode == "enforce" {
		if governance.LawfulInterceptEnabled && enabledCases == 0 {
			return errors.New("broadband.governance_self_service enforce mode requires at least one enabled lawful-intercept case or disable lawful_intercept_enabled")
		}
		if governance.DualApprovalRequired && enabledApprovals == 0 {
			return errors.New("broadband.governance_self_service dual approval requires at least one enabled approval policy")
		}
		if governance.SelfServiceEnabled && enabledActions == 0 {
			return errors.New("broadband.governance_self_service self_service_enabled requires at least one enabled self-service action")
		}
		if governance.PrivacyControlsEnabled && enabledPrivacy == 0 {
			return errors.New("broadband.governance_self_service privacy_controls_enabled requires at least one enabled privacy policy")
		}
	}
	return nil
}

func validateBroadbandGovernanceCases(governance BroadbandGovernanceSelfServiceConfig) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range governance.Cases {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].name is invalid", i)
		}
		key := strings.ToLower(firstNonEmptyString(item.CaseID, name))
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.governance_self_service.cases[%d] duplicates case %q", i, key)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"case_id", item.CaseID, 128},
			{"legal_authority", item.LegalAuthority, 253},
			{"request_reference", item.RequestReference, 253},
			{"subscriber_id", item.SubscriberID, 253},
			{"username", item.Username, 253},
			{"tenant", item.Tenant, 128},
			{"scope", item.Scope, 64},
			{"export_adapter", item.ExportAdapter, 128},
			{"retention_class", item.RetentionClass, 128},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].%s is invalid", i, field.name)
			}
		}
		if item.Enabled && strings.TrimSpace(item.CaseID) == "" {
			return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].case_id is required when enabled", i)
		}
		if item.Enabled && strings.TrimSpace(item.LegalAuthority) == "" {
			return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].legal_authority is required when enabled", i)
		}
		for j, approver := range item.Approvers {
			if strings.TrimSpace(approver) != "" && !validBroadbandPPPoEText(approver, 253) {
				return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].approvers[%d] is invalid", i, j)
			}
		}
		for j, tag := range item.AuditTags {
			if strings.TrimSpace(tag) != "" && !validBroadbandPPPoEText(tag, 128) {
				return 0, fmt.Errorf("broadband.governance_self_service.cases[%d].audit_tags[%d] is invalid", i, j)
			}
		}
	}
	return enabled, nil
}

func validateBroadbandGovernanceApprovalPolicies(governance BroadbandGovernanceSelfServiceConfig) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range governance.ApprovalPolicies {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].name %q duplicates an earlier policy", i, name)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.MinApprovals < 0 || item.MinApprovals > 10 {
			return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].min_approvals must be between 0 and 10", i)
		}
		if strings.TrimSpace(item.Scope) != "" && !validBroadbandPPPoEText(item.Scope, 64) {
			return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].scope is invalid", i)
		}
		for j, role := range item.AllowedRoles {
			if strings.TrimSpace(role) != "" && !validBroadbandPPPoEText(role, 128) {
				return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].allowed_roles[%d] is invalid", i, j)
			}
		}
		for j, recipient := range item.EscalationRecipients {
			if strings.TrimSpace(recipient) != "" && !validBroadbandPPPoEText(recipient, 253) {
				return 0, fmt.Errorf("broadband.governance_self_service.approval_policies[%d].escalation_recipients[%d] is invalid", i, j)
			}
		}
	}
	return enabled, nil
}

func validateBroadbandSelfServiceActions(governance BroadbandGovernanceSelfServiceConfig, planNames map[string]struct{}) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range governance.SelfServiceActions {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].name %q duplicates an earlier action", i, name)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		action := strings.ToLower(strings.TrimSpace(item.Action))
		switch action {
		case "", "view_balance", "plan_change", "top_up", "usage_export", "privacy_request", "support_ticket", "service_cancel":
		default:
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].action %q is invalid", i, item.Action)
		}
		if item.RateLimitPerHour < 0 || item.RateLimitPerHour > 10000 {
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].rate_limit_per_hour must be between 0 and 10000", i)
		}
		if item.MaxPendingRequests < 0 || item.MaxPendingRequests > 100000 {
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].max_pending_requests must be between 0 and 100000", i)
		}
		for j, product := range item.AllowedProducts {
			product = strings.TrimSpace(product)
			if product == "" {
				continue
			}
			if !validBroadbandPPPoEText(product, 128) {
				return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].allowed_products[%d] is invalid", i, j)
			}
			if len(planNames) > 0 {
				if _, ok := planNames[strings.ToLower(product)]; !ok {
					return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].allowed_products[%d] %q is not configured", i, j, product)
				}
			}
		}
		for j, tenant := range item.AllowedTenants {
			if strings.TrimSpace(tenant) != "" && !validBroadbandPPPoEText(tenant, 128) {
				return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].allowed_tenants[%d] is invalid", i, j)
			}
		}
		if strings.TrimSpace(item.NotificationChannel) != "" && !validBroadbandPPPoEText(item.NotificationChannel, 128) {
			return 0, fmt.Errorf("broadband.governance_self_service.self_service_actions[%d].notification_channel is invalid", i)
		}
	}
	return enabled, nil
}

func validateBroadbandPrivacyPolicies(governance BroadbandGovernanceSelfServiceConfig) (int, error) {
	seen := map[string]struct{}{}
	enabled := 0
	for i, item := range governance.PrivacyPolicies {
		name := strings.TrimSpace(item.Name)
		if !validBroadbandPPPoEText(name, 128) {
			return 0, fmt.Errorf("broadband.governance_self_service.privacy_policies[%d].name is invalid", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return 0, fmt.Errorf("broadband.governance_self_service.privacy_policies[%d].name %q duplicates an earlier policy", i, name)
		}
		seen[key] = struct{}{}
		if item.Enabled {
			enabled++
		}
		if item.RetentionDays < 0 || item.RetentionDays > 3650 {
			return 0, fmt.Errorf("broadband.governance_self_service.privacy_policies[%d].retention_days must be between 0 and 3650", i)
		}
		for _, field := range []struct {
			name  string
			value string
			limit int
		}{
			{"data_class", item.DataClass, 128},
			{"access_purpose", item.AccessPurpose, 253},
		} {
			if strings.TrimSpace(field.value) != "" && !validBroadbandPPPoEText(field.value, field.limit) {
				return 0, fmt.Errorf("broadband.governance_self_service.privacy_policies[%d].%s is invalid", i, field.name)
			}
		}
		for j, field := range item.RedactFields {
			if strings.TrimSpace(field) != "" && !validBroadbandPPPoEText(field, 128) {
				return 0, fmt.Errorf("broadband.governance_self_service.privacy_policies[%d].redact_fields[%d] is invalid", i, j)
			}
		}
	}
	return enabled, nil
}

func broadbandCommercialPlanNames(catalog BroadbandCommercialCatalog) map[string]struct{} {
	out := map[string]struct{}{}
	for _, plan := range catalog.Plans {
		if name := strings.TrimSpace(plan.Name); name != "" {
			out[strings.ToLower(name)] = struct{}{}
		}
	}
	return out
}
