package mfa

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestVerifyTOTPRFC6238Vector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ok := VerifyTOTP(secret, "94287082", TOTPOptions{
		Algorithm:     "SHA1",
		Digits:        8,
		PeriodSeconds: 30,
		WindowSteps:   0,
		Now:           time.Unix(59, 0).UTC(),
	})
	assert.True(t, ok)
}

func TestEnrollVerifyAndRecoveryCode(t *testing.T) {
	cfg := setupMFATestDB(t)

	enrollment, err := EnrollTOTP(context.Background(), cfg, "alice@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Secret)
	require.NotEmpty(t, enrollment.OTPAuthURL)
	require.Len(t, enrollment.RecoveryCodes, 1)

	var storedCiphertext string
	require.NoError(t, db.DB.QueryRow(`SELECT secret_ciphertext FROM mfa_totp_secrets WHERE username_hash = ?`, enrollment.UsernameHash).Scan(&storedCiphertext))
	assert.NotContains(t, storedCiphertext, enrollment.Secret)

	code := GenerateTOTP(enrollment.Secret, TOTPOptions{
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
		Now:           time.Now().UTC(),
	})
	result, err := VerifyOTP(context.Background(), cfg, "alice@example.com", code, StepUpContext{Username: "alice@example.com", Source: "test"}, true)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "totp", result.Method)

	recovery := enrollment.RecoveryCodes[0]
	result, err = VerifyOTP(context.Background(), cfg, "alice@example.com", recovery, StepUpContext{Username: "alice@example.com", Source: "test"}, true)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "recovery", result.Method)

	result, err = VerifyOTP(context.Background(), cfg, "alice@example.com", recovery, StepUpContext{Username: "alice@example.com", Source: "test"}, true)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestChallengeFlow(t *testing.T) {
	cfg := setupMFATestDB(t)
	enrollment, err := EnrollTOTP(context.Background(), cfg, "admin@example.com")
	require.NoError(t, err)

	challenge, err := StartChallenge(cfg, StepUpContext{
		Username:       "admin@example.com",
		Role:           "admin",
		IdentitySource: "local",
		AuthMethod:     "portal-local",
		Source:         "portal",
	})
	require.NoError(t, err)
	require.True(t, IsLocalState(challenge.State))

	bad, err := VerifyChallenge(context.Background(), cfg, challenge.State, "admin@example.com", "000000")
	require.NoError(t, err)
	assert.False(t, bad.Allowed)

	code := GenerateTOTP(enrollment.Secret, TOTPOptions{
		Algorithm:     "SHA1",
		Digits:        6,
		PeriodSeconds: 30,
		Now:           time.Now().UTC(),
	})
	good, err := VerifyChallenge(context.Background(), cfg, challenge.State, "admin@example.com", code)
	require.NoError(t, err)
	assert.True(t, good.Allowed)
	assert.Equal(t, "admin", good.Role)
}

func TestBuildReport(t *testing.T) {
	cfg := setupMFATestDB(t)
	report := BuildReport(cfg)
	assert.Equal(t, SchemaVersion, report.SchemaVersion)
	assert.Equal(t, "degraded", report.Status)
	assert.True(t, report.Enabled)
	assert.True(t, report.Policy.SealingKeyRefSet)
}

func setupMFATestDB(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("AEGIS_MFA_SEALING_KEY", "0123456789abcdef0123456789abcdef")
	tmp, err := os.CreateTemp("", "mfa-test-*.db")
	require.NoError(t, err)
	path := tmp.Name()
	require.NoError(t, tmp.Close())
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	restoreHasher := db.SetMFARecoveryCodeHasherForTesting(testRecoveryHash, testRecoveryCompare)
	t.Cleanup(func() {
		restoreHasher()
		_ = db.Close()
		_ = os.Remove(path)
	})
	return &config.Config{
		Portal: config.PortalConfig{Enabled: true, LocalFallback: true},
		MFA: config.MFAConfig{
			Enabled:      true,
			Mode:         "enforce",
			FailClosed:   true,
			AuditEnabled: true,
			OTP: config.MFAOTPConfig{
				Enabled:           true,
				Issuer:            "AegisNAS",
				Algorithm:         "SHA1",
				Digits:            6,
				PeriodSeconds:     30,
				WindowSteps:       1,
				MaxAttempts:       3,
				SealingKeyRef:     "env:AEGIS_MFA_SEALING_KEY",
				StepUpRoles:       []string{"admin"},
				RequiredForAdmins: true,
			},
			RadiusChallenge: config.MFARadiusChallengeConfig{
				Enabled:    true,
				TTLSeconds: 300,
				MaxPending: 100,
				Prompt:     "Enter OTP",
				StateBytes: 32,
			},
			Recovery: config.MFARecoveryConfig{
				Enabled:   true,
				CodeCount: 1,
				CodeBytes: 8,
			},
			RetentionLimit: 6000,
		},
		Security: config.SecurityConfig{
			Secrets: config.SecretProviderConfig{
				Enabled:     true,
				Providers:   []string{"env", "file"},
				AllowInline: true,
			},
		},
	}
}

func testRecoveryHash(code string) (string, error) {
	return "test$" + code, nil
}

func testRecoveryCompare(hash, code string) bool {
	return hash == "test$"+code
}
