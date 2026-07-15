package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestIdentitySourceEventsSummaryAndCircuitState(t *testing.T) {
	setupIdentitySourceFailoverDB(t)
	now := time.Now().UTC().Add(-10 * time.Second)

	for i := 0; i < 3; i++ {
		require.NoError(t, RecordIdentitySourceEvent(IdentitySourceEvent{
			ObservedAt:   now.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			SourceName:   "ldap-primary",
			SourceType:   "ldap",
			UsernameHash: HashIdentityUsername("alice@example.com"),
			Decision:     "failed",
			Reason:       "ldap dial timeout",
			CircuitState: "closed",
		}, map[string]any{"attempt": i + 1}, 10))
	}

	state, err := GetIdentitySourceCircuitState("ldap-primary", 3, 300, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, "open", state.State)
	assert.Equal(t, 3, state.FailureCount)
	assert.NotEmpty(t, state.ReopensAt)

	summary, err := GetIdentitySourceEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 3, summary.TotalRecords)
	assert.Equal(t, 3, summary.FailureCount)
	assert.Equal(t, "failed", summary.LastDecision)

	events, err := ListIdentitySourceEvents("ldap-primary", "failed", 10)
	require.NoError(t, err)
	require.Len(t, events, 3)
	assert.NotContains(t, events[0].UsernameHash, "alice")
}

func TestIdentitySourceCredentialCacheUsesBcryptAndExpires(t *testing.T) {
	setupIdentitySourceFailoverDB(t)
	originalCost := identitySourceCacheBcryptCost
	identitySourceCacheBcryptCost = bcrypt.MinCost
	t.Cleanup(func() {
		identitySourceCacheBcryptCost = originalCost
	})
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	require.NoError(t, UpsertIdentitySourceCache("ldap-primary", "alice@example.com", "secret-pass", "employee", "ldap", []string{"staff"}, 60, now))

	entry, ok, err := VerifyIdentitySourceCache("ldap-primary", "alice@example.com", "secret-pass", now.Add(30*time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "employee", entry.Role)
	assert.Equal(t, []string{"staff"}, entry.Groups)

	_, ok, err = VerifyIdentitySourceCache("ldap-primary", "alice@example.com", "wrong-pass", now.Add(30*time.Second))
	require.NoError(t, err)
	assert.False(t, ok)

	_, ok, err = VerifyIdentitySourceCache("ldap-primary", "alice@example.com", "secret-pass", now.Add(2*time.Minute))
	require.NoError(t, err)
	assert.False(t, ok)

	var storedHash string
	require.NoError(t, DB.QueryRow(`SELECT password_hash FROM identity_source_cache WHERE source_name = ?`, "ldap-primary").Scan(&storedHash))
	assert.NotEqual(t, "secret-pass", storedHash)
	assert.Contains(t, storedHash, "$2")
}

func setupIdentitySourceFailoverDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "identity-source-failover-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, Init(dbPath))
	require.NoError(t, Migrate())
}
