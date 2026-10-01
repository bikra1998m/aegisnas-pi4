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

func TestBroadbandAddressLeasesAPIPreviewApplyStatusHistoryReadinessAndSupportBundle(t *testing.T) {
	prepareBroadbandAddressLeasesAPITestRuntime(t)

	previewRec := httptest.NewRecorder()
	HandlePreviewBroadbandAddressLeases(previewRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-address-leases/preview", nil))
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var previewPayload struct {
		EventID string `json:"event_id"`
		Report  struct {
			FeatureID       string `json:"feature_id"`
			Status          string `json:"status"`
			PlanFingerprint string `json:"plan_fingerprint"`
			Summary         struct {
				PoolCount                 int `json:"pool_count"`
				LeaseIntentCount          int `json:"lease_intent_count"`
				ReservationCount          int `json:"reservation_count"`
				IPv4LeaseIntentCount      int `json:"ipv4_lease_intent_count"`
				IPv6LeaseIntentCount      int `json:"ipv6_lease_intent_count"`
				DelegatedLeaseIntentCount int `json:"delegated_lease_intent_count"`
				ComplianceCheckCount      int `json:"compliance_check_count"`
				PassedCheckCount          int `json:"passed_check_count"`
				BlockerCount              int `json:"blocker_count"`
				ExternalRequirementCount  int `json:"external_requirement_count"`
			} `json:"summary"`
		} `json:"report"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &previewPayload))
	assert.NotEmpty(t, previewPayload.EventID)
	assert.Equal(t, "NAS-0086", previewPayload.Report.FeatureID)
	assert.Equal(t, "ready", previewPayload.Report.Status)
	assert.Equal(t, 3, previewPayload.Report.Summary.PoolCount)
	assert.Equal(t, 4, previewPayload.Report.Summary.LeaseIntentCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.ReservationCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.IPv4LeaseIntentCount)
	assert.Equal(t, 2, previewPayload.Report.Summary.IPv6LeaseIntentCount)
	assert.Equal(t, 1, previewPayload.Report.Summary.DelegatedLeaseIntentCount)
	assert.Equal(t, previewPayload.Report.Summary.ComplianceCheckCount, previewPayload.Report.Summary.PassedCheckCount)
	assert.Zero(t, previewPayload.Report.Summary.BlockerCount)
	assert.Greater(t, previewPayload.Report.Summary.ExternalRequirementCount, 0)
	assert.NotEmpty(t, previewPayload.Report.PlanFingerprint)

	applyRec := httptest.NewRecorder()
	HandleApplyBroadbandAddressLeases(applyRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/broadband-address-leases/apply", nil))
	require.Equal(t, http.StatusOK, applyRec.Code, applyRec.Body.String())
	assert.Contains(t, applyRec.Body.String(), `"status":"applied"`)

	statusRec := httptest.NewRecorder()
	HandleGetBroadbandAddressLeases(statusRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-address-leases", nil))
	require.Equal(t, http.StatusOK, statusRec.Code, statusRec.Body.String())
	assert.Contains(t, statusRec.Body.String(), `"ready_for_external_validation":true`)
	assert.Contains(t, statusRec.Body.String(), `"leases"`)

	historyRec := httptest.NewRecorder()
	HandleListBroadbandAddressLeaseHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/broadband-address-leases/history?limit=5", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"feature_id":"NAS-0086"`)
	assert.Contains(t, historyRec.Body.String(), `"preview_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"applied_count":1`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "broadband_address_leases"))

	systemRec := httptest.NewRecorder()
	HandleGetSystemStatus(systemRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	require.Equal(t, http.StatusOK, systemRec.Code, systemRec.Body.String())
	assert.Contains(t, systemRec.Body.String(), `"broadband_address_leases"`)

	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), config.Get())
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{
		"/api/v1/system/broadband-address-leases",
		"/api/v1/system/broadband-address-leases/preview",
		"/api/v1/system/broadband-address-leases/apply",
		"/api/v1/system/broadband-address-leases/history",
	} {
		_, ok := paths[path]
		assert.True(t, ok, "OpenAPI path %s should exist", path)
	}

	foundStatusCapture := false
	foundHistoryCapture := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/broadband-address-leases.json" {
			foundStatusCapture = true
		}
		if capture.archivePath == "api/broadband-address-leases-history.json" {
			foundHistoryCapture = true
		}
	}
	assert.True(t, foundStatusCapture)
	assert.True(t, foundHistoryCapture)
}

func TestBroadbandAddressLeasesRBAC(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-address-leases"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-address-leases/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/broadband-address-leases/history"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/broadband-address-leases/apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/broadband-address-leases/apply"))
}

func prepareBroadbandAddressLeasesAPITestRuntime(t *testing.T) {
	t.Helper()
	prepareBroadbandSubscriberStateAPITestRuntime(t)
	cfg := config.Get()
	cfg.Broadband.AddressLeases = config.BroadbandAddressLeaseConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		StickyIPv4:                    true,
		StickyIPv6:                    true,
		DualStackRequired:             true,
		DelegatedPrefixRequired:       true,
		ReservationRequired:           true,
		ConflictDetectionEnabled:      true,
		AccountingCorrelationRequired: true,
		CoAOnConflict:                 true,
		ReleaseOnAccountingStop:       true,
		RecoveryScanSeconds:           60,
		StaleAfterSeconds:             600,
		EventRetentionLimit:           10000,
		Pools: []config.BroadbandAddressLeasePoolConfig{
			{Name: "pppoe-v4", Family: "ipv4", CIDR: "100.64.0.0/24", Start: "100.64.0.10", End: "100.64.0.250", Gateway: "100.64.0.1", Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "mikrotik"}},
			{Name: "pppoe-v6", Family: "ipv6", CIDR: "2001:db8:100::/48", Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "huawei"}},
			{Name: "pppoe-pd", Family: "delegated-prefix", CIDR: "2001:db8:200::/40", DelegatedPrefixLength: 56, Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "alcatel-lucent-service-router"}},
		},
		Reservations: []config.BroadbandAddressLeaseReservationConfig{
			{Key: "lab-cpe-01", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Product: "residential-fiber", Role: "residential", Pool: "pppoe-v4", Family: "ipv4", AssignmentType: "address", Address: "100.64.0.20", Reason: "Lab reservation"},
		},
	}
}
