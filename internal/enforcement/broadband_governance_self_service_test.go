package enforcement

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewBroadbandGovernanceSelfServiceBuildsGovernedPlan(t *testing.T) {
	cfg := loadBroadbandGovernanceSelfServiceTestConfig(t)

	report, err := PreviewBroadbandGovernanceSelfService(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandGovernanceSelfServiceFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.CaseCount)
	assert.Equal(t, 1, report.Summary.EnabledCaseCount)
	assert.Equal(t, 1, report.Summary.ApprovalPolicyCount)
	assert.Equal(t, 1, report.Summary.SelfServiceActionCount)
	assert.Equal(t, 1, report.Summary.PrivacyPolicyCount)
	assert.GreaterOrEqual(t, report.Summary.CompiledAttributeCount, 9)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	require.NotEmpty(t, report.Cases)
	assert.Contains(t, governanceAttributeNames(report.Cases[0].Attributes), "Class")
	assert.Contains(t, governanceAttributeNames(report.Cases[0].Attributes), "Cisco-AVPair")
	require.NotEmpty(t, report.SelfServiceActions)
	assert.Contains(t, governanceAttributeNames(report.SelfServiceActions[0].Attributes), "Chargeable-User-Identity")
}

func TestPreviewBroadbandGovernanceSelfServiceBlocksMissingMFA(t *testing.T) {
	cfg := loadBroadbandGovernanceSelfServiceTestConfig(t)
	cfg.MFA.Enabled = false

	report, err := PreviewBroadbandGovernanceSelfService(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "MFA")
}

func TestApplyBroadbandGovernanceSelfServiceRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandGovernanceSelfServiceTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandGovernanceSelfService(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandGovernanceSelfServiceEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].CaseCount)
	assert.Equal(t, 1, events[0].SelfServiceActionCount)

	cases, err := db.ListBroadbandGovernanceCases(10, "ready")
	require.NoError(t, err)
	require.Len(t, cases, 1)
	assert.Equal(t, "li-2026-001", cases[0].CaseKey)

	requests, err := db.ListBroadbandSelfServiceRequests(10, "ready")
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "plan-change", requests[0].RequestKey)

	runtime, err := db.GetRuntimeStatus(BroadbandGovernanceSelfServiceComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, strings.ToLower(runtime.Message), "lawful")
}

func loadBroadbandGovernanceSelfServiceTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := loadBroadbandServiceActivationTestConfig(t)
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.MFA.Enabled = true
	cfg.AdminWebAuthn.Enabled = true
	cfg.Broadband.QuotaBalance.Enabled = true
	cfg.Broadband.Governance = config.BroadbandGovernanceSelfServiceConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		RequireSubscriberState:   true,
		RequireCommercialCatalog: true,
		RequireQuotaBalance:      true,
		RequireAccounting:        true,
		RequireDynamicAuth:       true,
		RequireMFA:               true,
		RequireAdminWebAuthn:     true,
		LawfulInterceptEnabled:   true,
		SelfServiceEnabled:       true,
		PrivacyControlsEnabled:   true,
		ImmutableAuditRequired:   true,
		DualApprovalRequired:     true,
		ApprovalThreshold:        2,
		CaseRetentionDays:        365,
		EventRetentionLimit:      10000,
		Cases: []config.BroadbandLawfulInterceptCaseConfig{
			{Name: "court-order-1", Enabled: true, CaseID: "LI-2026-001", LegalAuthority: "court-order", RequestReference: "sealed-2026-001", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Tenant: "retail", Scope: "accounting-metadata", ExportAdapter: "governed-export", RetentionClass: "regulated", Approvers: []string{"ops_admin", "compliance"}, AuditTags: []string{"sealed"}},
		},
		ApprovalPolicies: []config.BroadbandGovernanceApprovalPolicyConfig{
			{Name: "dual-control", Enabled: true, Scope: "lawful_intercept", MinApprovals: 2, RequireMFA: true, RequireWebAuthn: true, AllowedRoles: []string{"ops_admin", "super_admin"}, EscalationRecipients: []string{"compliance@example.net"}},
		},
		SelfServiceActions: []config.BroadbandSelfServiceActionConfig{
			{Name: "plan-change", Enabled: true, Action: "plan_change", RequiresAuth: true, RequiresMFA: true, RequiresApproval: true, AllowedProducts: []string{"residential-fiber"}, AllowedTenants: []string{"retail"}, RateLimitPerHour: 4, MaxPendingRequests: 2, NotificationChannel: "email", AccountingCorrelation: true},
		},
		PrivacyPolicies: []config.BroadbandPrivacyPolicyConfig{
			{Name: "subscriber-privacy", Enabled: true, DataClass: "subscriber-metadata", AccessPurpose: "self-service", RetentionDays: 90, RedactFields: []string{"legal_authority", "request_reference"}, SubscriberNotice: true},
		},
	}
	return cfg
}

func governanceAttributeNames(attributes []BroadbandGovernanceAttribute) []string {
	names := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		names = append(names, attribute.Name)
	}
	return names
}
