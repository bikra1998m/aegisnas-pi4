package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidationMFA(t *testing.T) {
	cfg := minimalMFAValidationConfig()
	cfg.MFA.Enabled = true
	cfg.MFA.Mode = "enforce"
	cfg.MFA.OTP.Enabled = true
	cfg.MFA.OTP.SealingKeyRef = "env:AEGIS_MFA_SEALING_KEY"
	require.NoError(t, validateMFA(cfg.MFA))

	cfg.MFA.OTP.Digits = 7
	assert.ErrorContains(t, validateMFA(cfg.MFA), "mfa.otp.digits")

	cfg = minimalMFAValidationConfig()
	cfg.MFA.Enabled = true
	cfg.MFA.OTP.SealingKeyRef = "vault:path"
	assert.ErrorContains(t, validateMFA(cfg.MFA), "unsupported secret provider")
}

func TestEffectiveMFAConfigDefaults(t *testing.T) {
	effective := EffectiveMFAConfig(MFAConfig{})
	assert.Equal(t, "monitor", effective.Mode)
	assert.Equal(t, "AegisNAS", effective.OTP.Issuer)
	assert.Equal(t, "env:AEGIS_MFA_SEALING_KEY", effective.OTP.SealingKeyRef)
	assert.Equal(t, 300, effective.RadiusChallenge.TTLSeconds)
	assert.Equal(t, 10, effective.Recovery.CodeCount)
}

func minimalMFAValidationConfig() *Config {
	return &Config{
		Mode: "two-nic",
		WAN:  InterfaceConfig{Name: "eth0"},
		LAN:  InterfaceConfig{Name: "eth1", Address: "192.168.1.1/24"},
		Database: DatabaseConfig{
			Backend: "sqlite",
			Path:    "/tmp/aegisnas-mfa-test.db",
		},
		Health:    HealthConfig{Port: 8080},
		AdminPort: 8083,
		Radius: RadiusConfig{
			Secret:   "secret",
			AuthPort: 1812,
			AcctPort: 1813,
		},
		Portal: PortalConfig{Enabled: true, LocalFallback: true},
		Identity: IdentityConfig{Failover: IdentityFailoverConfig{
			Enabled:                    true,
			Mode:                       "enforce",
			FailClosed:                 true,
			SourceOrder:                []string{"local"},
			MaxFailures:                3,
			CircuitOpenSeconds:         300,
			StaleCacheSeconds:          3600,
			SplitResultPolicy:          "deny",
			HealthCheckIntervalSeconds: 60,
			AuditEnabled:               true,
			RetentionLimit:             6000,
		}},
		MFA: MFAConfig{
			Enabled:      false,
			Mode:         "monitor",
			FailClosed:   true,
			AuditEnabled: true,
			OTP: MFAOTPConfig{
				Enabled:           true,
				Issuer:            "AegisNAS",
				Algorithm:         "SHA1",
				Digits:            6,
				PeriodSeconds:     30,
				WindowSteps:       1,
				MaxAttempts:       5,
				SealingKeyRef:     "env:AEGIS_MFA_SEALING_KEY",
				StepUpRoles:       []string{"admin"},
				RequiredForAdmins: true,
			},
			RadiusChallenge: MFARadiusChallengeConfig{
				Enabled:    true,
				TTLSeconds: 300,
				MaxPending: 100,
				Prompt:     "Enter OTP",
				StateBytes: 32,
			},
			Recovery: MFARecoveryConfig{
				Enabled:   true,
				CodeCount: 10,
				CodeBytes: 16,
			},
			RetentionLimit: 6000,
		},
		Security: SecurityConfig{Secrets: SecretProviderConfig{
			Enabled:     true,
			Providers:   []string{"env", "file"},
			AllowInline: true,
		}},
	}
}
