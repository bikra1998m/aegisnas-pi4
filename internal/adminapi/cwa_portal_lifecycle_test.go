package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestCWAPortalLifecycleAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareCWAPortalLifecycleAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewCWAPortalLifecycle(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/cwa-portal-lifecycle/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				GuestSSIDCount           int `json:"guest_ssid_count"`
				WalledGardenCount        int `json:"walled_garden_count"`
				ControllerPolicyCount    int `json:"controller_policy_count"`
				RedirectRuleCount        int `json:"redirect_rule_count"`
				CoAActionCount           int `json:"coa_action_count"`
				ComplianceCheckCount     int `json:"compliance_check_count"`
				PassedCheckCount         int `json:"passed_check_count"`
				BlockerCount             int `json:"blocker_count"`
				ExternalRequirementCount int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0081", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 1, previewPayload.Report.Summary.GuestSSIDCount)
	assert.Equal(t, 3, previewPayload.Report.Summary.WalledGardenCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ControllerPolicyCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.RedirectRuleCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.CoAActionCount)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyCWAPortalLifecycle(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/cwa-portal-lifecycle/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetCWAPortalLifecycle(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/cwa-portal-lifecycle", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"recent_events"`)

	historyRec := httptest.NewRecorder()
	HandleListCWAPortalLifecycleHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/cwa-portal-lifecycle/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0081"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "cwa_portal_lifecycle"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"cwa_portal_lifecycle"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/cwa-portal-lifecycle",
		"/api/v1/system/cwa-portal-lifecycle/preview",
		"/api/v1/system/cwa-portal-lifecycle/apply",
		"/api/v1/system/cwa-portal-lifecycle/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/cwa-portal-lifecycle.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/cwa-portal-lifecycle-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestCWAPortalLifecycleRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/cwa-portal-lifecycle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/cwa-portal-lifecycle/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/cwa-portal-lifecycle/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/cwa-portal-lifecycle/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/cwa-portal-lifecycle/apply"))
}

func prepareCWAPortalLifecycleAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: physical
database:
  path: ":memory:"
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
radius:
  secret: radius-secret
  dynamic_auth:
    enabled: true
portal:
  enabled: true
  port: 8081
  listen_ip: 192.168.50.1
  branding: AegisNAS Guest
  local_fallback: true
  cwa:
    enabled: true
    mode: monitor
    fail_closed: true
    rfc8910_api_enabled: true
    https_required: true
    portal_base_url: "https://portal.example.test"
    captive_api_path: "/captive-portal/api"
    venue_info_url: "https://portal.example.test/venue"
    controller_redirect_enabled: true
    per_session_walled_garden: true
    session_binding_required: true
    coa_after_authentication: true
    walled_garden:
      - name: sponsor-idp
        type: domain
        value: idp.example.test
        ports: [443]
    controller_policies:
      - name: guest-cwa
        enabled: true
        vendor: cisco
        platform: cisco
        ssid: Aegis Guest
        profile_name: guest-cwa
        redirect_acl: CWA_REDIRECT
        pre_auth_role: cwa-preauth
        post_auth_role: guest
        coa_action: reauth
        controller_sync: true
integrations:
  controller:
    enabled: true
    platform: cisco
    endpoint: "https://controller.example.test"
    api_username_env: AEGIS_CONTROLLER_USERNAME
    api_password_env: AEGIS_CONTROLLER_PASSWORD
    sync_mode: monitor
    site: HQ
    radius_profile: aegis-radius
wireless:
  enabled: false
  country_code: US
  ssids:
    - name: Aegis Guest
      auth_mode: captive-portal
      bridge: br-guest
      client_isolation: true
      portal_profile: guest
policy:
  default_role: guest
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
