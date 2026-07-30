package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestTenantIsolationAPIProfileResourceEvaluateAndScope(t *testing.T) {
	prepareTenantIsolationAPITestConfig(t)

	createProfile := httptest.NewRecorder()
	HandleUpsertTenantProfile(createProfile, tenantIsolationRequest(http.MethodPost, "/api/v1/system/tenant-isolation/tenants", `{
		"tenant_key":"Tenant-A",
		"display_name":"Tenant A",
		"data_residency_region":"us-east",
		"quota":{"max_sessions":1000},
		"controller_scope":{"sites":["branch-1"]},
		"billing_account_ref":"acct-123"
	}`, adminRoleOpsAdmin, "tenant-a"))
	require.Equal(t, http.StatusOK, createProfile.Code, createProfile.Body.String())

	createResource := httptest.NewRecorder()
	HandleUpsertTenantResourceBinding(createResource, tenantIsolationRequest(http.MethodPost, "/api/v1/system/tenant-isolation/resources", `{
		"tenant":"tenant-a",
		"resource_type":"policy_set",
		"resource_id":"default:tenant-a",
		"owner_kind":"tenant",
		"status":"active",
		"evidence":{"source":"api-test"}
	}`, adminRoleOpsAdmin, "tenant-a"))
	require.Equal(t, http.StatusOK, createResource.Code, createResource.Body.String())

	evaluate := httptest.NewRecorder()
	HandleEvaluateTenantIsolation(evaluate, tenantIsolationRequest(http.MethodPost, "/api/v1/system/tenant-isolation/evaluate", `{
		"tenant":"tenant-a",
		"resource_type":"policy_set",
		"resource_id":"default:tenant-a",
		"action":"activate"
	}`, adminRoleOpsAdmin, "tenant-a"))
	require.Equal(t, http.StatusOK, evaluate.Code, evaluate.Body.String())
	var decision tenantIsolationDecision
	require.NoError(t, json.Unmarshal(evaluate.Body.Bytes(), &decision))
	assert.True(t, decision.Allowed)
	assert.Equal(t, "allow", decision.Decision)

	outOfScope := httptest.NewRecorder()
	HandleEvaluateTenantIsolation(outOfScope, tenantIsolationRequest(http.MethodPost, "/api/v1/system/tenant-isolation/evaluate", `{
		"tenant":"tenant-b",
		"resource_type":"policy_set",
		"resource_id":"default:tenant-b",
		"action":"activate"
	}`, adminRoleOpsAdmin, "tenant-a"))
	require.Equal(t, http.StatusForbidden, outOfScope.Code)

	reportRec := httptest.NewRecorder()
	HandleGetTenantIsolation(reportRec, tenantIsolationRequest(http.MethodGet, "/api/v1/system/tenant-isolation?limit=10", "", adminRoleReadOnly, "tenant-a"))
	require.Equal(t, http.StatusOK, reportRec.Code, reportRec.Body.String())
	var report tenantIsolationReport
	require.NoError(t, json.Unmarshal(reportRec.Body.Bytes(), &report))
	assert.Equal(t, "passed", report.Status)
	assert.Equal(t, 1, report.Summary.ActiveTenantCount)
	assert.Equal(t, 1, report.Summary.ResourceBindingCount)
	assert.Equal(t, 1, report.Summary.DeniedEventCount)
}

func TestPolicySetTenantScopeEnforcement(t *testing.T) {
	prepareTenantIsolationAPITestConfig(t)
	_, err := db.UpsertTenantProfile(db.TenantProfile{TenantKey: "tenant-a", DisplayName: "Tenant A"})
	require.NoError(t, err)
	_, err = db.UpsertTenantProfile(db.TenantProfile{TenantKey: "tenant-b", DisplayName: "Tenant B"})
	require.NoError(t, err)

	createTenantA := httptest.NewRecorder()
	HandleCreatePolicySetVersion(createTenantA, tenantIsolationRequest(http.MethodPost, "/api/v1/system/policy-sets/versions", `{
		"tenant":"tenant-a",
		"description":"tenant a policy",
		"content":{"key":"default","tenant":"tenant-a","name":"Tenant A","enabled":true,"rules":[{"name":"allow-a","priority":100,"enabled":true,"match_conditions":{"field":"tenant","op":"eq","value":"tenant-a"},"action":"allow"}]}
	}`, adminRoleSuperAdmin, "tenant-a"))
	require.Equal(t, http.StatusCreated, createTenantA.Code, createTenantA.Body.String())
	var tenantAVersion policySetVersionView
	require.NoError(t, json.Unmarshal(createTenantA.Body.Bytes(), &tenantAVersion))
	assert.Equal(t, "tenant-a", tenantAVersion.Tenant)

	createTenantBOutOfScope := httptest.NewRecorder()
	HandleCreatePolicySetVersion(createTenantBOutOfScope, tenantIsolationRequest(http.MethodPost, "/api/v1/system/policy-sets/versions", `{
		"tenant":"tenant-b",
		"description":"tenant b policy",
		"content":{"key":"default","tenant":"tenant-b","name":"Tenant B","enabled":true,"rules":[{"name":"allow-b","priority":100,"enabled":true,"match_conditions":{"field":"tenant","op":"eq","value":"tenant-b"},"action":"allow"}]}
	}`, adminRoleSuperAdmin, "tenant-a"))
	require.Equal(t, http.StatusForbidden, createTenantBOutOfScope.Code)

	tenantBVersion, err := db.CreatePolicySetVersion(context.Background(), db.CreatePolicySetVersionRequest{
		SetKey:           "default",
		Tenant:           "tenant-b",
		ContentJSON:      `{"schema_version":1,"key":"default","tenant":"tenant-b","name":"Tenant B","enabled":true,"rules":[{"name":"allow-b","priority":100,"enabled":true,"match_conditions":{"field":"tenant","op":"eq","value":"tenant-b"},"action":"allow"}]}`,
		ContentSHA256:    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		PolicySHA256:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		RuleCount:        1,
		MaxDepth:         1,
		ApprovalRequired: false,
		Status:           db.PolicySetStatusDraft,
		CreatedBy:        "maker",
	})
	require.NoError(t, err)

	listRec := httptest.NewRecorder()
	HandleListPolicySetVersions(listRec, tenantIsolationRequest(http.MethodGet, "/api/v1/system/policy-sets/versions", "", adminRoleReadOnly, "tenant-a"))
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var listed []policySetVersionView
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.Len(t, listed, 1)
	assert.Equal(t, tenantAVersion.ID, listed[0].ID)

	readTenantB := httptest.NewRecorder()
	readReq := tenantIsolationRequest(http.MethodGet, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(tenantBVersion.ID), "", adminRoleReadOnly, "tenant-a")
	readReq = withChiURLParam(readReq, "id", strconv.Itoa(tenantBVersion.ID))
	HandleGetPolicySetVersion(readTenantB, readReq)
	require.Equal(t, http.StatusForbidden, readTenantB.Code)
}

func TestProductionReadinessIncludesTenantIsolation(t *testing.T) {
	cfg := prepareTenantIsolationAPITestConfig(t)
	_, err := db.UpsertTenantProfile(db.TenantProfile{TenantKey: "tenant-a", DisplayName: "Tenant A"})
	require.NoError(t, err)

	report := buildProductionReadinessReport(cfg)
	var found bool
	for _, check := range report.Checks {
		if check.Key == "tenant_isolation" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/tenant-isolation")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeTenantIsolation(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/tenant-isolation")
	assert.Contains(t, paths, "/api/v1/system/tenant-isolation/evaluate")
	assert.Contains(t, paths, "/api/v1/system/tenant-isolation/tenants")
	assert.Contains(t, paths, "/api/v1/system/tenant-isolation/resources")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/tenant-isolation.json" {
			found = true
			assert.Equal(t, "/api/v1/system/tenant-isolation", capture.requestPath)
		}
	}
	assert.True(t, found)
}

func TestAuthorizeTenantIsolation(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/tenant-isolation"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/tenant-isolation/evaluate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/tenant-isolation/evaluate"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/tenant-isolation/tenants"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/tenant-isolation/tenants"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/tenant-isolation/resources"))
}

func prepareTenantIsolationAPITestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := preparePolicyEngineAPITestConfig(t)
	cfg.Deployment.Profile = "enterprise"
	cfg.Governance.DelegatedAdminEnabled = true
	cfg.Governance.MultiTenantEnabled = true
	cfg.Governance.TenantClaim = "tenant"
	cfg.Governance.IsolationMode = "enforce"
	cfg.Governance.FailClosed = true
	cfg.Governance.MaxTenants = 256
	cfg.Governance.TenantProfileRequired = true
	cfg.Governance.EnforcePolicySetOwnership = true
	cfg.Governance.EnforceResourceOwnership = true
	cfg.Governance.ResourceAuditEnabled = true
	cfg.Governance.ResourceRetentionLimit = 10000
	cfg.Governance.SharedResourceTypes = []string{"system_status", "production_readiness", "support_bundle"}
	return cfg
}

func tenantIsolationRequest(method, target, body, role string, tenants ...string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	ctx := context.WithValue(req.Context(), userContextKey, "tenant-api-test")
	ctx = withAdminIdentity(ctx, AdminIdentity{
		Subject:     "tenant-api-test",
		Role:        role,
		Tenants:     tenants,
		Permissions: permissionsForAdminRole(role),
	})
	return req.WithContext(ctx)
}
