package enforcement

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewCWAPortalLifecycleBuildsFullPlan(t *testing.T) {
	cfg := loadCWAPortalLifecycleTestConfig(t, "")

	report, err := PreviewCWAPortalLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, CWAPortalLifecycleFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status, "blockers: %v", report.Blockers)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "monitor", report.Summary.Mode)
	assert.Equal(t, 1, report.Summary.GuestSSIDCount)
	assert.Equal(t, 3, report.Summary.WalledGardenCount)
	assert.Equal(t, 1, report.Summary.ControllerPolicyCount)
	assert.Equal(t, 1, report.Summary.RedirectRuleCount)
	assert.Equal(t, 1, report.Summary.CoAActionCount)
	assert.Zero(t, report.Summary.BlockerCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Equal(t, "docs/nas-0081-release-certification-checklist.md", report.ReleaseCertificationChecklist)
	assert.Equal(t, "https://portal.example.test/captive-portal/api", report.RFC8910API.EndpointURL)
	assert.Contains(t, fmt.Sprint(report.Compliance), "RFC 8910 API")
}

func TestPreviewCWAPortalLifecycleBlocksUnsafeHTTPS(t *testing.T) {
	cfg := loadCWAPortalLifecycleTestConfig(t, `
    enabled: true
    mode: enforce
    fail_closed: true
    rfc8910_api_enabled: true
    https_required: true
    portal_base_url: "http://portal.example.test"
    captive_api_path: "/captive-portal/api"
    session_binding_required: true
    coa_after_authentication: true
`)

	report, err := PreviewCWAPortalLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(0), report.SoftwareCompletionPercent)
	assert.Contains(t, fmt.Sprint(report.Blockers), "portal.cwa.portal_base_url must use https")
}

func TestPreviewCWAPortalLifecycleSkippedWhenDisabled(t *testing.T) {
	cfg := loadCWAPortalLifecycleTestConfig(t, "disabled")

	report, err := PreviewCWAPortalLifecycle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.False(t, report.Summary.CWAEnabled)
	assert.Empty(t, report.GuestSSIDs)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyCWAPortalLifecycleRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadCWAPortalLifecycleTestConfig(t, "")
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyCWAPortalLifecycle(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListCWAPortalLifecycleEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, "ops@example.test", events[0].Actor)
	assert.Equal(t, 1, events[0].GuestSSIDCount)
	assert.Equal(t, 3, events[0].WalledGardenCount)

	runtime, err := db.GetRuntimeStatus(CWAPortalLifecycleComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0081")
}

func loadCWAPortalLifecycleTestConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cwaBlock := `
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
    event_retention_limit: 6000
    walled_garden:
      - name: sponsor-idp
        type: domain
        value: idp.example.test
        ports: [443]
        required: false
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
`
	if override == "disabled" {
		cwaBlock = strings.Replace(cwaBlock, "    enabled: true\n", "    enabled: false\n", 1)
	} else if strings.TrimSpace(override) != "" {
		cwaBlock = override
	}
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
` + cwaBlock + `
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
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	cfg, err := config.Load(path)
	require.NoError(t, err)
	return cfg
}
