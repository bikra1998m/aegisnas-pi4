package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewControllerEstateLifecycleBuildsInventoryTemplatesAndHashes(t *testing.T) {
	t.Setenv("AEGIS_TEST_CONTROLLER_TOKEN", "controller-token")
	cfg := loadControllerEstateLifecycleTestConfig(t, `
integrations:
  controller:
    enabled: true
    platform: unifi
    endpoint: https://controller.example.test
    api_token_env: AEGIS_TEST_CONTROLLER_TOKEN
    radius_profile: corp-radius
    sync_mode: monitor
    site: default
wireless:
  enabled: false
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 20
      dynamic_vlan: true
      identity_source: active-directory
      bandwidth_profile: corp-standard
      roaming_profile: fast
    - name: Guest
      auth_mode: captive-portal
      vlan: 40
      portal_profile: guest
`)

	report, err := PreviewControllerEstateLifecycle(cfg)
	require.NoError(t, err)
	assert.Equal(t, "NAS-0078", report.FeatureID)
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, "unifi", report.Summary.ConfiguredPlatform)
	assert.Equal(t, "unifi-network", report.Summary.ConfiguredAdapter)
	assert.Equal(t, 10, report.Summary.AdapterCount)
	assert.Equal(t, 2, report.Summary.WLANTemplateCount)
	assert.GreaterOrEqual(t, report.Summary.InventoryObjectCount, 5)
	assert.NotEmpty(t, report.DesiredStateHash)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.True(t, report.Configured.TokenPresent)
	assert.Contains(t, report.Configured.TokenEnv, "AEGIS_TEST_CONTROLLER_TOKEN")
	assert.NotContains(t, string(mustMarshalControllerEstateTest(t, report)), "controller-token")
	require.Len(t, report.Templates, 2)
	assert.True(t, report.Templates[0].DeleteProtected)
	assert.NotEmpty(t, report.ObjectPlans)
	assert.NotEmpty(t, report.Compliance)
	assert.NotNil(t, report.PullPreview)
	assert.NotNil(t, report.PushPreview)
}

func TestPreviewControllerEstateLifecycleDisabledIsSoftwareComplete(t *testing.T) {
	cfg := loadControllerEstateLifecycleTestConfig(t, `
integrations:
  controller:
    enabled: false
wireless:
  enabled: false
`)

	report, err := PreviewControllerEstateLifecycle(cfg)
	require.NoError(t, err)
	assert.Equal(t, "skipped", report.Status)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.False(t, report.Summary.ControllerEnabled)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyControllerEstateLifecycleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	t.Setenv("AEGIS_TEST_CONTROLLER_TOKEN", "controller-token")
	cfg := loadControllerEstateLifecycleTestConfig(t, `
integrations:
  controller:
    enabled: true
    platform: generic
    endpoint: https://controller.example.test/aegisnas
    api_token_env: AEGIS_TEST_CONTROLLER_TOKEN
    sync_mode: monitor
wireless:
  enabled: false
  ssids:
    - name: Corp
      auth_mode: wpa2-enterprise
      vlan: 20
      identity_source: local
`)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyControllerEstateLifecycle(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	summary, err := db.GetControllerEstateLifecycleSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApplyEvents)
	assert.Equal(t, 1, summary.AppliedCount)
	assert.Equal(t, "generic-rest", summary.LastAdapter)
	assert.Equal(t, "generic", summary.LastPlatform)

	runtime, err := db.GetRuntimeStatus(ControllerComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0078")
}

func loadControllerEstateLifecycleTestConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
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
%s
`, extra)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.LoadCandidate(path)
	require.NoError(t, err)
	return cfg
}

func mustMarshalControllerEstateTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}
