package adminapi

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestSyncAdminPrincipalFromClaimsDerivesRoleAndTenant(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "adminauth-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	cfg := &config.Config{}
	cfg.Governance.DelegatedAdminEnabled = true
	cfg.Governance.RBACMode = "external-groups"
	cfg.Governance.MultiTenantEnabled = true
	cfg.Governance.TenantClaim = "tenant"

	identity, err := syncAdminPrincipalFromClaims(cfg, "oidc", "oidc:alice@example.com", map[string]any{
		"name":   "Alice",
		"email":  "alice@example.com",
		"tenant": []any{"Tenant-A", "tenant-a", "tenant-b"},
	}, []string{"noc-team", "viewer"})
	require.NoError(t, err)
	assert.Equal(t, adminRoleOpsAdmin, identity.Role)
	assert.Equal(t, []string{"tenant-a", "tenant-b"}, identity.Tenants)

	items, err := listAdminPrincipals()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, adminRoleOpsAdmin, items[0].Role)
	assert.Equal(t, []string{"tenant-a", "tenant-b"}, items[0].Tenants)
}

func TestAuthorizeRequestByRole(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleGuestAdmin}, "POST", "/api/v1/guest-registrations/1/approve"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleGuestAdmin}, "DELETE", "/api/v1/sessions/123"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleGuestAdmin}, "PUT", "/api/v1/system/settings"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleGuestAdmin}, "POST", "/api/v1/system/network-apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/network-apply"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "GET", "/api/v1/system/network-preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/status"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dhcp-leases"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dhcp-lease-history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/dhcp-lease-history/export?format=csv"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upstream-aaa-history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upstream-aaa-history/export?format=json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upstream-aaa-exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upstream-aaa-exports/download?name=aegisnas-upstream-aaa-history-20260525-000000Z.json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/audit-history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/audit-history/export?format=json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/audit-exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/audit-exports/download?name=aegisnas-audit-history-20260521-000000Z.json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/integration-history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/integration-history/export?format=json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/integration-exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/integration-exports/download?name=aegisnas-integration-history-20260521-000000Z.json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-backups"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-apply-history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-apply-history/export?format=csv"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-observability"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/network-exports/download?name=aegisnas-network-apply-history-20260523-000000Z.json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/diagnostics-exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/diagnostics-exports/download?name=aegisnas-diagnostics-report-20260521-000000Z.json"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/diagnostics-report"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/diagnostics-report/export?format=json"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/support-bundle"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "GET", "/api/v1/system/support-bundle"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upgrade-readiness"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "GET", "/api/v1/system/upgrade-readiness"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/upgrade-rollback-package"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "GET", "/api/v1/system/upgrade-rollback-package"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/upgrade-rollback-package/inspect"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/upgrade-rollback-package/inspect"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/upgrade-rollback-package/restore"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/upgrade-rollback-package/restore"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/history"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/history/export?format=csv"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/exports"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/exports/download?name=aegisnas-ha-history-20260523-000000Z.json"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/replication-package"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "GET", "/api/v1/system/ha/replication-package"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/replication-shared"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/ha/replication-staged"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/ha/replication-stage-shared"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/ha/replication-stage-shared"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/ha/replication-activate"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/ha/replication-activate"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/network-recovery/confirm"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/network-recovery/confirm"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/network-rollback"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/alerts/1/acknowledge"))
}
