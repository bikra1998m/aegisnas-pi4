package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateFallbackUsesIdentityFailoverAndAuditsLocalAccept(t *testing.T) {
	prepareIdentityFailoverAuthConfig(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-pass"), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO local_users (username, password_hash, role) VALUES (?, ?, ?)`, "alice@example.com", string(hash), "employee")
	require.NoError(t, err)

	result, err := authenticateFallback(context.Background(), "alice@example.com", "secret-pass")
	require.NoError(t, err)
	require.True(t, result.Accepted)
	assert.Equal(t, "employee", result.Role)
	assert.Equal(t, "local", result.IdentitySource)

	events, err := db.ListIdentitySourceEvents("local", "accepted", 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.NotContains(t, events[0].UsernameHash, "alice")
}

func TestValidateUserDetailedDistinguishesMissingAndBadPassword(t *testing.T) {
	prepareIdentityFailoverAuthConfig(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-pass"), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO local_users (username, password_hash, role) VALUES (?, ?, ?)`, "alice@example.com", string(hash), "employee")
	require.NoError(t, err)

	valid, role, found, err := ValidateUserDetailed("alice@example.com", "wrong-pass")
	require.NoError(t, err)
	assert.False(t, valid)
	assert.True(t, found)
	assert.Empty(t, role)

	valid, _, found, err = ValidateUserDetailed("missing@example.com", "secret-pass")
	require.NoError(t, err)
	assert.False(t, valid)
	assert.False(t, found)
}

func prepareIdentityFailoverAuthConfig(t *testing.T) {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "identity-failover-auth-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())

	tmpcfg, err := os.CreateTemp("", "identity-failover-auth-*.yaml")
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
portal:
  enabled: true
  radius_auth: false
  local_fallback: true
identity:
  failover:
    enabled: true
    mode: enforce
    fail_closed: true
    source_order: [local]
    max_failures: 3
    circuit_open_seconds: 300
    stale_cache_seconds: 3600
    split_result_policy: deny
    health_check_interval_seconds: 60
    audit_enabled: true
    retention_limit: 6000
radius:
  secret: secret
`, strconv.Quote(dbPath))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))
	_, err = config.Load(cfgPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
		_ = os.Remove(cfgPath)
	})
}
