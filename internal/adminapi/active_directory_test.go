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
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetActiveDirectory(t *testing.T) {
	prepareActiveDirectoryAPIConfig(t)
	require.NoError(t, db.RecordActiveDirectoryEvent(db.ActiveDirectoryEvent{
		ObservedAt:    "2026-07-01T10:00:00Z",
		Domain:        "corp.example.com",
		Realm:         "CORP.EXAMPLE.COM",
		SourceName:    "active-directory",
		UsernameHash:  db.HashIdentityUsername("alice@corp.example.com"),
		PrincipalHash: db.HashActiveDirectoryPrincipal("alice@CORP.EXAMPLE.COM"),
		AuthMethod:    "ldap_bind",
		Decision:      "accepted",
		Reason:        "credentials accepted",
		Role:          "employee",
		Groups:        []string{"AegisNAS-Employees"},
	}, nil, 6000))
	require.NoError(t, db.RecordActiveDirectoryHealthCheck(db.ActiveDirectoryHealthCheck{
		CheckedAt: "2026-07-01T10:00:05Z",
		Domain:    "corp.example.com",
		Realm:     "CORP.EXAMPLE.COM",
		Component: "configuration",
		Status:    "ok",
		Message:   "configuration executable",
	}, nil, 6000))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/active-directory?source=active-directory&decision=accepted&component=configuration&limit=10", nil)
	HandleGetActiveDirectory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	report := payload["report"].(map[string]any)
	assert.Equal(t, "ready", report["status"])
	assert.Equal(t, true, report["enabled"])
	events := payload["events"].([]any)
	require.Len(t, events, 1)
	health := payload["health"].([]any)
	require.Len(t, health, 1)
}

func TestProductionReadinessIncludesActiveDirectoryCheck(t *testing.T) {
	cfg := prepareActiveDirectoryAPIConfig(t)

	report := buildProductionReadinessReport(cfg)

	var found bool
	for _, check := range report.Checks {
		if check.Key == "active_directory_identity" {
			found = true
			assert.Equal(t, "passed", check.Status)
			assert.Contains(t, check.Dependencies, "/api/v1/system/active-directory")
		}
	}
	assert.True(t, found)
}

func TestOpenAPIAndSupportBundleIncludeActiveDirectory(t *testing.T) {
	spec := buildOpenAPISpec(httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil), nil)
	paths := spec["paths"].(map[string]any)
	assert.Contains(t, paths, "/api/v1/system/active-directory")
	assert.Contains(t, paths, "/api/v1/system/active-directory/check")

	var found bool
	for _, capture := range supportBundleAPICaptures() {
		if capture.archivePath == "api/active-directory.json" {
			found = true
			assert.Equal(t, "/api/v1/system/active-directory", capture.requestPath)
			assert.Equal(t, "Active Directory identity", capture.label)
		}
	}
	assert.True(t, found)
}

func prepareActiveDirectoryAPIConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "active-directory-api-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "active-directory-api-*.yaml")
	require.NoError(t, err)
	cfgPath := tmpcfg.Name()
	require.NoError(t, tmpcfg.Close())
	content := fmt.Sprintf(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: %s
policy:
  default_role: guest-basic
portal:
  enabled: true
  radius_auth: false
  local_fallback: true
identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order: [active-directory, local]
    max_failures: 3
    circuit_open_seconds: 300
    stale_cache_seconds: 3600
    cache_credentials: true
    split_result_policy: deny
    health_check_interval_seconds: 60
    audit_enabled: true
    retention_limit: 6000
active_directory:
  enabled: true
  mode: enforce
  fail_closed: true
  domain: corp.example.com
  realm: CORP.EXAMPLE.COM
  netbios_domain: CORP
  ldap_url: ldaps://dc1.corp.example.com:636
  base_dn: dc=corp,dc=example,dc=com
  user_filter: "(|(userPrincipalName=%%p)(sAMAccountName=%%u))"
  group_filter: "(member=%%D)"
  require_ldaps: true
  auth_method: ldap_bind
  default_role: guest-basic
  group_role_mappings:
    AegisNAS-Employees: employee
  request_timeout_seconds: 5
  group_cache_ttl_seconds: 3600
  health_check_interval_seconds: 60
  clock_skew_seconds: 300
  audit_enabled: true
  retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
	return cfg
}
