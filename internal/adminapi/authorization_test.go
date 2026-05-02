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
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/status"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/alerts/1/acknowledge"))
}
