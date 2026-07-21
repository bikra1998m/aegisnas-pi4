package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
)

func TestPolicySetVersionApprovalActivationSimulationAndRollback(t *testing.T) {
	preparePolicyEngineAPITestConfig(t)
	previousSync := syncRuntimeEnforcementForPolicySetFn
	syncRuntimeEnforcementForPolicySetFn = func(*config.Config) error { return nil }
	t.Cleanup(func() { syncRuntimeEnforcementForPolicySetFn = previousSync })

	_, err := db.DB.Exec(`DELETE FROM policy_rules`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO policy_rules (name, description, priority, enabled, match_conditions, action, vlan)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"employee-access", "typed employee rule", 100, true,
		`{"field":"groups","op":"contains","value":"employees"}`, "allow", 30)
	require.NoError(t, err)

	createRec := httptest.NewRecorder()
	HandleCreatePolicySetVersion(createRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions", "maker", `{"from_current":true,"description":"baseline","submit":true}`))
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())
	var created policySetVersionView
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	assert.Equal(t, db.PolicySetStatusPendingApproval, created.Status)
	assert.Equal(t, 1, created.RuleCount)

	approveRec := httptest.NewRecorder()
	HandleApprovePolicySetVersion(approveRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/approve", "maker", `{"comment":"self"}`))
	require.Equal(t, http.StatusBadRequest, approveRec.Code)
	assert.Contains(t, approveRec.Body.String(), "maker-checker")

	approveRec = httptest.NewRecorder()
	HandleApprovePolicySetVersion(approveRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/approve", "checker", `{"comment":"reviewed"}`))
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())
	var approved policySetVersionView
	require.NoError(t, json.Unmarshal(approveRec.Body.Bytes(), &approved))
	assert.Equal(t, db.PolicySetStatusApproved, approved.Status)
	assert.Equal(t, 1, approved.ApprovalCount)

	activateRec := httptest.NewRecorder()
	HandleActivatePolicySetVersion(activateRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/activate", "admin", `{"note":"activate baseline"}`))
	require.Equal(t, http.StatusOK, activateRec.Code, activateRec.Body.String())
	var activeName string
	require.NoError(t, db.DB.QueryRow(`SELECT name FROM policy_rules ORDER BY priority DESC LIMIT 1`).Scan(&activeName))
	assert.Equal(t, "default/employee-access", activeName)

	simRec := httptest.NewRecorder()
	HandleSimulatePolicySetVersion(simRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/simulate", "ops", `{"authenticated":true,"groups":["employees"]}`))
	require.Equal(t, http.StatusOK, simRec.Code, simRec.Body.String())
	var sim policy.EvaluationResult
	require.NoError(t, json.Unmarshal(simRec.Body.Bytes(), &sim))
	assert.True(t, sim.Decision.Allow)

	secondContent := `{"content":{"key":"default","name":"Default","enabled":true,"rules":[{"name":"employee-access","priority":100,"enabled":true,"match_conditions":{"field":"groups","op":"contains","value":"employees"},"action":"allow","vlan":30},{"name":"deny-risk","priority":200,"enabled":true,"match_conditions":{"field":"risk_score","op":"gte","value":90},"action":"deny"}]},"description":"add deny","submit":true}`
	secondRec := httptest.NewRecorder()
	HandleCreatePolicySetVersion(secondRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions", "maker-2", secondContent))
	require.Equal(t, http.StatusCreated, secondRec.Code, secondRec.Body.String())
	var second policySetVersionView
	require.NoError(t, json.Unmarshal(secondRec.Body.Bytes(), &second))
	approveSecondRec := httptest.NewRecorder()
	HandleApprovePolicySetVersion(approveSecondRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(second.ID)+"/approve", "checker-2", `{}`))
	require.Equal(t, http.StatusOK, approveSecondRec.Code, approveSecondRec.Body.String())

	compareReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/compare/"+strconv.Itoa(second.ID), nil)
	compareReq = compareReq.WithContext(policySetRequestContext(compareReq.Context(), "viewer"))
	compareReq = withChiURLParam(compareReq, "fromID", strconv.Itoa(created.ID))
	compareReq = withChiURLParam(compareReq, "toID", strconv.Itoa(second.ID))
	compareRec := httptest.NewRecorder()
	HandleComparePolicySetVersions(compareRec, compareReq)
	require.Equal(t, http.StatusOK, compareRec.Code, compareRec.Body.String())
	assert.Contains(t, compareRec.Body.String(), "deny-risk")

	analyzeRec := httptest.NewRecorder()
	HandleAnalyzePolicySetVersion(analyzeRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(second.ID)+"/analyze", "ops", `{"sample_source":"manual","requests":[{"authenticated":true,"groups":["employees"],"risk_score":95}],"include_trace":true}`))
	require.Equal(t, http.StatusOK, analyzeRec.Code, analyzeRec.Body.String())
	var analysis policy.PolicySimulationAnalysis
	require.NoError(t, json.Unmarshal(analyzeRec.Body.Bytes(), &analysis))
	assert.Equal(t, 1, analysis.SampleCount)
	assert.Equal(t, 1, analysis.AllowToDenyCount)
	assert.Equal(t, "critical", analysis.RiskLevel)

	analysisSummary, err := db.SummarizePolicySimulationAnalyses()
	require.NoError(t, err)
	assert.Equal(t, 1, analysisSummary.TotalAnalyses)
	assert.Equal(t, "critical", analysisSummary.LastRiskLevel)

	listAnalysesRec := httptest.NewRecorder()
	HandleListPolicySimulationAnalyses(listAnalysesRec, policySetRequest(http.MethodGet, "/api/v1/system/policy-sets/analyses", "viewer", ``))
	require.Equal(t, http.StatusOK, listAnalysesRec.Code, listAnalysesRec.Body.String())
	assert.Contains(t, listAnalysesRec.Body.String(), analysis.AnalysisID)

	activateSecondRec := httptest.NewRecorder()
	HandleActivatePolicySetVersion(activateSecondRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(second.ID)+"/activate", "admin", `{"note":"activate second"}`))
	require.Equal(t, http.StatusOK, activateSecondRec.Code, activateSecondRec.Body.String())

	rollbackRec := httptest.NewRecorder()
	HandleRollbackPolicySetVersion(rollbackRec, policySetRequest(http.MethodPost, "/api/v1/system/policy-sets/versions/"+strconv.Itoa(created.ID)+"/rollback", "admin", `{"note":"rollback baseline"}`))
	require.Equal(t, http.StatusOK, rollbackRec.Code, rollbackRec.Body.String())
	active, err := db.GetActivePolicySetVersion("default")
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, created.ID, active.ID)
}

func TestPolicySetAuthorization(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/policy-sets"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-sets/versions"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-sets/versions/1/simulate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-sets/versions/1/analyze"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/policy-sets/versions/1/approve"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleSuperAdmin}, "POST", "/api/v1/system/policy-sets/versions/1/approve"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/policy-sets/analyses"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/policy-sets/versions/1/compare/2"))
}

func policySetRequest(method, target, user, body string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req = req.WithContext(policySetRequestContext(req.Context(), user))
	if id := policySetIDFromTarget(target); id != "" {
		req = withChiURLParam(req, "id", id)
	}
	return req
}

func policySetRequestContext(ctx context.Context, user string) context.Context {
	ctx = context.WithValue(ctx, userContextKey, user)
	return withAdminIdentity(ctx, AdminIdentity{Subject: user, Role: adminRoleSuperAdmin})
}

func policySetIDFromTarget(target string) string {
	parts := strings.Split(target, "/")
	for i, part := range parts {
		if part == "versions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func withChiURLParam(req *http.Request, key, value string) *http.Request {
	routeCtx := chi.RouteContext(req.Context())
	if routeCtx == nil {
		routeCtx = chi.NewRouteContext()
	}
	routeCtx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}
