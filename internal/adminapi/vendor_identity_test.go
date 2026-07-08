package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/vendoridentity"
)

func TestVendorIdentityPreviewApplyStatusAndRollback(t *testing.T) {
	cfg := setupVendorIdentityTestRuntime(t)
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	restore := stubVendorIdentityDependencies(t, now, false)
	defer restore()

	previewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-identity/migrations/preview", bytes.NewBufferString(`{"pen":424242,"expected_organization":"AegisNAS Systems Ltd.","legacy_acceptance_hours":24}`))
	previewResponse := httptest.NewRecorder()
	HandlePreviewVendorIdentityMigration(previewResponse, previewRequest)
	require.Equal(t, http.StatusOK, previewResponse.Code, previewResponse.Body.String())
	var preview vendorIdentityPreviewResponse
	require.NoError(t, json.Unmarshal(previewResponse.Body.Bytes(), &preview))
	assert.NotEmpty(t, preview.MigrationID)
	assert.Len(t, preview.ConfirmationToken, vendorIdentityTokenSize*2)
	assert.Equal(t, 55555, preview.Current.PEN)
	assert.Equal(t, 424242, preview.Target.PEN)
	assert.Equal(t, []int{55555}, preview.Target.LegacyPENs)
	assert.Equal(t, now.Add(24*time.Hour).Format(time.RFC3339), preview.Target.LegacyAcceptUntil)

	applyBody, _ := json.Marshal(vendorIdentityApplyRequest{MigrationID: preview.MigrationID, ConfirmationToken: preview.ConfirmationToken})
	applyResponse := httptest.NewRecorder()
	HandleApplyVendorIdentityMigration(applyResponse, httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-identity/migrations/apply", bytes.NewReader(applyBody)))
	require.Equal(t, http.StatusOK, applyResponse.Code, applyResponse.Body.String())
	assert.Equal(t, 424242, config.Get().Radius.Vendor.ID)
	assert.Equal(t, "production", config.Get().Radius.Vendor.IdentityMode)
	assert.Equal(t, "AegisNAS Systems Ltd.", config.Get().Radius.Vendor.AssignedOrganization)

	statusResponse := httptest.NewRecorder()
	HandleGetVendorIdentity(statusResponse, httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-identity", nil))
	require.Equal(t, http.StatusOK, statusResponse.Code, statusResponse.Body.String())
	var status vendorIdentityStatusResponse
	require.NoError(t, json.Unmarshal(statusResponse.Body.Bytes(), &status))
	assert.True(t, status.Ready)
	assert.Equal(t, "production_verified", status.Status)
	assert.True(t, status.ConfigEvidenceValid)
	assert.True(t, status.LegacyWindowActive)
	assert.EqualValues(t, 1, status.Metrics.Applied)
	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "passed", productionReadinessCheckStatus(readiness.Checks, "vendor_identity"))

	router := chi.NewRouter()
	router.Post("/api/v1/system/vendor-identity/migrations/{id}/rollback", HandleRollbackVendorIdentityMigration)
	rollbackBody := fmt.Sprintf(`{"confirmation_text":"ROLLBACK %s"}`, preview.MigrationID)
	rollbackResponse := httptest.NewRecorder()
	router.ServeHTTP(rollbackResponse, httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-identity/migrations/"+preview.MigrationID+"/rollback", strings.NewReader(rollbackBody)))
	require.Equal(t, http.StatusOK, rollbackResponse.Code, rollbackResponse.Body.String())
	assert.Equal(t, 55555, config.Get().Radius.Vendor.ID)
	assert.Equal(t, "lab", config.Get().Radius.Vendor.IdentityMode)
	readiness = buildProductionReadinessReport(config.Get())
	assert.Equal(t, "blocked", productionReadinessCheckStatus(readiness.Checks, "vendor_identity"))

	migration, err := db.GetVendorIdentityMigration(db.DB, preview.MigrationID)
	require.NoError(t, err)
	assert.Equal(t, "rolled_back", migration.Status)
	require.FileExists(t, config.Path())
	data, err := os.ReadFile(config.Path())
	require.NoError(t, err)
	assert.Contains(t, string(data), "identity_mode: lab")
	assert.NotContains(t, string(data), "424242")
	_ = cfg
}

func TestVendorIdentityApplyFailureRestoresLabIdentity(t *testing.T) {
	setupVendorIdentityTestRuntime(t)
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	restore := stubVendorIdentityDependencies(t, now, true)
	defer restore()

	previewResponse := httptest.NewRecorder()
	HandlePreviewVendorIdentityMigration(previewResponse, httptest.NewRequest(http.MethodPost, "/preview", strings.NewReader(`{"pen":424242,"expected_organization":"AegisNAS Systems Ltd."}`)))
	require.Equal(t, http.StatusOK, previewResponse.Code, previewResponse.Body.String())
	var preview vendorIdentityPreviewResponse
	require.NoError(t, json.Unmarshal(previewResponse.Body.Bytes(), &preview))

	body, _ := json.Marshal(vendorIdentityApplyRequest{MigrationID: preview.MigrationID, ConfirmationToken: preview.ConfirmationToken})
	response := httptest.NewRecorder()
	HandleApplyVendorIdentityMigration(response, httptest.NewRequest(http.MethodPost, "/apply", bytes.NewReader(body)))
	require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
	assert.Equal(t, 55555, config.Get().Radius.Vendor.ID)
	assert.Equal(t, "lab", config.Get().Radius.Vendor.IdentityMode)
	migration, err := db.GetVendorIdentityMigration(db.DB, preview.MigrationID)
	require.NoError(t, err)
	assert.Equal(t, "failed", migration.Status)
	assert.Contains(t, migration.Failure, "simulated FreeRADIUS failure")
}

func TestVendorIdentityRejectsInvalidPENBeforeRegistryLookup(t *testing.T) {
	setupVendorIdentityTestRuntime(t)
	called := false
	previous := fetchVendorAssignmentFn
	fetchVendorAssignmentFn = func(context.Context, int, string) (vendoridentity.AssignmentEvidence, error) {
		called = true
		return vendoridentity.AssignmentEvidence{}, nil
	}
	defer func() { fetchVendorAssignmentFn = previous }()

	response := httptest.NewRecorder()
	HandlePreviewVendorIdentityMigration(response, httptest.NewRequest(http.MethodPost, "/preview", strings.NewReader(`{"pen":55555,"expected_organization":"AegisNAS"}`)))
	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.False(t, called)
}

func setupVendorIdentityTestRuntime(t *testing.T) *config.Config {
	t.Helper()
	handle, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.MigrateHandle(handle))
	previousDB := db.DB
	db.DB = handle
	t.Cleanup(func() {
		db.DB = previousDB
		_ = handle.Close()
	})

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
database:
  path: ':memory:'
logging:
  level: info
  output: stdout
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
radius:
  secret: test-secret
  vendor:
    enabled: true
    name: AegisNAS
    id: 55555
    identity_mode: lab
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	return cfg
}

func stubVendorIdentityDependencies(t *testing.T, now time.Time, failFirstApply bool) func() {
	t.Helper()
	previousFetch := fetchVendorAssignmentFn
	previousApply := applyVendorIdentityRadiusFn
	previousNow := vendorIdentityNow
	fetchVendorAssignmentFn = func(_ context.Context, pen int, organization string) (vendoridentity.AssignmentEvidence, error) {
		record := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s\n", pen, organization)))
		return vendoridentity.AssignmentEvidence{
			SchemaVersion: vendoridentity.EvidenceSchemaVersion, PEN: uint32(pen), Organization: organization,
			RegistryURL:         "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt",
			RegistryLastUpdated: "2026-07-06", FetchedAt: now,
			RegistrySHA256: strings.Repeat("a", 64), RecordSHA256: hex.EncodeToString(record[:]),
		}, nil
	}
	applyCalls := 0
	applyVendorIdentityRadiusFn = func(*config.Config) error {
		applyCalls++
		if failFirstApply && applyCalls == 1 {
			return fmt.Errorf("simulated FreeRADIUS failure")
		}
		return nil
	}
	vendorIdentityNow = func() time.Time { return now }
	return func() {
		fetchVendorAssignmentFn = previousFetch
		applyVendorIdentityRadiusFn = previousApply
		vendorIdentityNow = previousNow
	}
}
