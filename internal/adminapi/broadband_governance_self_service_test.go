package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBroadbandGovernanceSelfServiceAPIPreviewApplyStatusHistory(t *testing.T) {
	prepareBroadbandGovernanceSelfServiceAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandGovernanceSelfService(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-governance-self-service/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				CaseCount                int `json:"case_count"`
				ApprovalPolicyCount      int `json:"approval_policy_count"`
				SelfServiceActionCount   int `json:"self_service_action_count"`
				PrivacyPolicyCount       int `json:"privacy_policy_count"`
				CompiledAttributeCount   int `json:"compiled_attribute_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0091", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.CaseCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ApprovalPolicyCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.SelfServiceActionCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.PrivacyPolicyCount)
	assert.Greater(t, previewPayload.Report.Summary.CompiledAttributeCount, 0)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandGovernanceSelfService(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-governance-self-service/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"ready"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandGovernanceSelfService(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-governance-self-service", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"self_service_requests"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandGovernanceSelfServiceHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-governance-self-service/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0091"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)
}

func TestBroadbandGovernanceSelfServiceRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-governance-self-service"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-governance-self-service/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-governance-self-service/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-governance-self-service/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-governance-self-service/apply"))
}

func TestBroadbandGovernanceSelfServiceSupportBundleCaptures(t *testing.T) {
	var foundStatusCapture, foundHistoryCapture bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-governance-self-service.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-governance-self-service-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func prepareBroadbandGovernanceSelfServiceAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandServiceActivationAPITestRuntime(t)
	cfg := config.Get()
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.MFA.Enabled = true
	cfg.AdminWebAuthn.Enabled = true
	cfg.AdminWebAuthn.RPID = "localhost"
	cfg.AdminWebAuthn.Origins = []string{"http://localhost"}
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
			{Name: "court-order-1", Enabled: true, CaseID: "LI-2026-001", LegalAuthority: "court-order", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Tenant: "retail", Scope: "accounting-metadata", Approvers: []string{"ops_admin", "compliance"}},
		},
		ApprovalPolicies: []config.BroadbandGovernanceApprovalPolicyConfig{
			{Name: "dual-control", Enabled: true, Scope: "lawful_intercept", MinApprovals: 2, RequireMFA: true, RequireWebAuthn: true, AllowedRoles: []string{"ops_admin", "super_admin"}},
		},
		SelfServiceActions: []config.BroadbandSelfServiceActionConfig{
			{Name: "plan-change", Enabled: true, Action: "plan_change", RequiresAuth: true, RequiresMFA: true, RequiresApproval: true, AllowedProducts: []string{"residential-fiber"}, AllowedTenants: []string{"retail"}, RateLimitPerHour: 4, MaxPendingRequests: 2, NotificationChannel: "email", AccountingCorrelation: true},
		},
		PrivacyPolicies: []config.BroadbandPrivacyPolicyConfig{
			{Name: "subscriber-privacy", Enabled: true, DataClass: "subscriber-metadata", AccessPurpose: "self-service", RetentionDays: 90, RedactFields: []string{"legal_authority", "request_reference"}, SubscriberNotice: true},
		},
	}
}
