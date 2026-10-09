package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateBroadbandGovernanceSelfServiceRequiresDependencies(t *testing.T) {
	cfg := &Config{}
	cfg.Deployment.Profile = "enterprise"
	cfg.Broadband.Governance.Enabled = true
	cfg.Broadband.Governance.Mode = "enforce"
	cfg.Broadband.Governance.Cases = []BroadbandLawfulInterceptCaseConfig{{
		Name:           "court-order-1",
		Enabled:        true,
		CaseID:         "LI-2026-001",
		LegalAuthority: "court-order",
		Scope:          "accounting-metadata",
	}}
	cfg.Broadband.Governance.ApprovalPolicies = []BroadbandGovernanceApprovalPolicyConfig{{
		Name:         "dual-control",
		Enabled:      true,
		MinApprovals: 2,
		RequireMFA:   true,
	}}
	cfg.Broadband.Governance.SelfServiceActions = []BroadbandSelfServiceActionConfig{{
		Name:             "balance",
		Enabled:          true,
		Action:           "view_balance",
		RequiresAuth:     true,
		RateLimitPerHour: 20,
	}}
	cfg.Broadband.Governance.PrivacyPolicies = []BroadbandPrivacyPolicyConfig{{
		Name:          "subscriber-privacy",
		Enabled:       true,
		DataClass:     "subscriber-metadata",
		AccessPurpose: "self-service",
		RetentionDays: 90,
		RedactFields:  []string{"legal_authority"},
	}}

	err := validateBroadbandGovernanceSelfServiceConfig(cfg.Broadband.Governance, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.QuotaBalance, cfg.Radius, cfg.MFA, cfg.AdminWebAuthn, cfg.Deployment.Profile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "broadband.subscriber_state.enabled")
}

func TestValidateBroadbandGovernanceSelfServiceAcceptsGovernedSoftwarePath(t *testing.T) {
	cfg := &Config{}
	cfg.Deployment.Profile = "enterprise"
	cfg.Radius = broadbandQuotaBalanceRadiusFixture()
	cfg.Radius.RequestTimeoutSeconds = 5
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.Secret = "testing-secret"
	cfg.MFA.Enabled = true
	cfg.AdminWebAuthn.Enabled = true
	cfg.AdminWebAuthn.RPID = "localhost"
	cfg.AdminWebAuthn.Origins = []string{"http://localhost"}
	cfg.Broadband.Subscriber = broadbandAddressLeaseSubscriberFixture()
	cfg.Broadband.CommercialCatalog = broadbandCommercialCatalogValidationFixture()
	cfg.Broadband.QuotaBalance = broadbandQuotaBalanceValidationFixture()
	cfg.Broadband.Governance = BroadbandGovernanceSelfServiceConfig{
		Enabled:                true,
		Mode:                   "enforce",
		LawfulInterceptEnabled: true,
		SelfServiceEnabled:     true,
		PrivacyControlsEnabled: true,
		DualApprovalRequired:   true,
		Cases: []BroadbandLawfulInterceptCaseConfig{{
			Name:           "court-order-1",
			Enabled:        true,
			CaseID:         "LI-2026-001",
			LegalAuthority: "court-order",
			SubscriberID:   "sub-1",
			Scope:          "accounting-metadata",
			Approvers:      []string{"ops_admin", "compliance"},
		}},
		ApprovalPolicies: []BroadbandGovernanceApprovalPolicyConfig{{
			Name:            "dual-control",
			Enabled:         true,
			Scope:           "lawful_intercept",
			MinApprovals:    2,
			RequireMFA:      true,
			RequireWebAuthn: true,
			AllowedRoles:    []string{"ops_admin", "super_admin"},
		}},
		SelfServiceActions: []BroadbandSelfServiceActionConfig{{
			Name:                  "plan-change",
			Enabled:               true,
			Action:                "plan_change",
			RequiresAuth:          true,
			RequiresMFA:           true,
			AllowedProducts:       []string{"fiber-100m"},
			RateLimitPerHour:      4,
			MaxPendingRequests:    2,
			AccountingCorrelation: true,
		}},
		PrivacyPolicies: []BroadbandPrivacyPolicyConfig{{
			Name:             "subscriber-privacy",
			Enabled:          true,
			DataClass:        "subscriber-metadata",
			AccessPurpose:    "self-service",
			RetentionDays:    90,
			RedactFields:     []string{"legal_authority", "request_reference"},
			ExportAllowed:    false,
			SubscriberNotice: true,
		}},
	}

	err := validateBroadbandGovernanceSelfServiceConfig(cfg.Broadband.Governance, cfg.Broadband.Subscriber, cfg.Broadband.CommercialCatalog, cfg.Broadband.QuotaBalance, cfg.Radius, cfg.MFA, cfg.AdminWebAuthn, cfg.Deployment.Profile)
	require.NoError(t, err)
}

func TestValidateBroadbandGovernanceSelfServiceRejectsInvalidAction(t *testing.T) {
	err := validateBroadbandGovernanceSelfServiceConfig(BroadbandGovernanceSelfServiceConfig{
		SelfServiceActions: []BroadbandSelfServiceActionConfig{{
			Name:   "bad-action",
			Action: strings.Repeat("x", 129),
		}},
	}, BroadbandSubscriberStateConfig{}, BroadbandCommercialCatalog{}, BroadbandQuotaBalanceConfig{}, RadiusConfig{}, MFAConfig{}, AdminWebAuthnConfig{}, "enterprise")
	require.Error(t, err)
	require.Contains(t, err.Error(), "action")
}
