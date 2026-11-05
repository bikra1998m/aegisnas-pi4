package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthenticationChallengeExpiryAcrossBackends(t *testing.T) {
	require.NoError(t, initRuntimeTestDB(t, filepath.Join(t.TempDir(), "auth.db")))
	defer Close()
	require.NoError(t, Migrate())
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		name   string
		offset time.Duration
		status string
	}{
		{"expired", -time.Minute, "expired"}, {"boundary", 0, "expired"}, {"future", time.Minute, "pending"},
	} {
		t.Run(item.name, func(t *testing.T) {
			expiry := now.Add(item.offset).Format(time.RFC3339)
			require.NoError(t, InsertMFAChallenge(MFAChallenge{ID: "mfa-" + item.name, StateHash: "mfa-" + item.name, UsernameHash: "fixture", ExpiresAt: expiry}, nil))
			mfa, found, err := GetMFAChallengeByStateHash("mfa-"+item.name, now)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, item.status, mfa.Status)
			require.NoError(t, InsertAdminWebAuthnChallenge(AdminWebAuthnChallenge{ID: "webauthn-" + item.name, StateHash: "webauthn-" + item.name,
				Challenge: "isolated-challenge", ChallengeHash: "fixture", Ceremony: "authentication", UsernameHash: "fixture", Subject: "fixture", ExpiresAt: expiry}, nil))
			webauthn, found, err := GetAdminWebAuthnChallengeByStateHash("webauthn-"+item.name, now)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, item.status, webauthn.Status)
		})
	}
	_, err := ListAdminWebAuthnCredentials("", true, 10)
	require.NoError(t, err, "Boolean defaults in credential inventory must be portable")
}
