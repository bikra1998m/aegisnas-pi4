package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetProductionReadinessReportsVendorBlockers(t *testing.T) {
	dbPath := prepareProductionReadinessDB(t)
	_, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled) VALUES (?, ?, ?, ?, ?)`,
		"mystery-ap", "192.0.2.10", "secret", "mystery-vendor", true)
	require.NoError(t, err)

	cfgPath := writeProductionReadinessConfig(t, dbPath, productconfigs.AegisNASPlaceholderVendorID)
	_, err = config.Load(cfgPath)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/production-readiness", nil)
	rec := httptest.NewRecorder()
	HandleGetProductionReadiness(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload productionReadinessReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "blocked", payload.Status)
	assert.False(t, payload.Ready)
	assert.True(t, payload.VendorIdentity.ConfiguredIDPlaceholder)
	assert.Equal(t, "blocked", productionReadinessCheckStatus(payload.Checks, "vendor_identity"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "attribute_registry"))
	assert.Equal(t, "passed", productionReadinessCheckStatus(payload.Checks, "dictionary_release_profile"))
	assert.Equal(t, "degraded", productionReadinessCheckStatus(payload.Checks, "compatibility_evidence"))
	assert.Equal(t, "blocked", productionReadinessCheckStatus(payload.Checks, "nas_profile_coverage"))
	assert.GreaterOrEqual(t, payload.BlockingCount, 2)
}

func prepareProductionReadinessDB(t *testing.T) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "production-readiness-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})
	return dbPath
}

func writeProductionReadinessConfig(t *testing.T, dbPath string, vendorID int) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "production-readiness-config-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())

	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: physical
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
ailite:
  enabled: false
radius:
  secret: secret
  vendor:
    enabled: true
    name: AegisNAS
    id: %d
    compatibility_packs: ["standard", "aegisnas", "aruba"]
`, strconv.Quote(dbPath), vendorID)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	t.Cleanup(func() { _ = os.Remove(cfgPath) })
	return cfgPath
}

func productionReadinessCheckStatus(checks []productionReadinessCheck, key string) string {
	for _, check := range checks {
		if check.Key == key {
			return check.Status
		}
	}
	return ""
}
