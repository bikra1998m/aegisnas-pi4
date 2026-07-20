package supplicantprofile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestSupplicantLifecycleEvaluateAcceptsSignedPinnedProfile(t *testing.T) {
	cfg := testSupplicantConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Protocol:                   "api",
		Platform:                   "windows",
		Username:                   "alice@example.com",
		DeviceID:                   "AA:BB:CC:DD:EE:FF",
		EAPMethod:                  "tls",
		TLSProtected:               true,
		PasswordVerifierCompatible: true,
		ProfileRequested:           true,
		ProfileSigned:              true,
		SigningKeyAvailable:        true,
		TrustAnchorPinned:          true,
		ServerNameMatched:          true,
		DeliveryTokenValid:         true,
		CertificateLifecycleReady:  true,
	})
	assert.Equal(t, "accepted", decision.Decision)
	assert.Equal(t, "profile_delivery_allowed", decision.Action)
	assert.NotEmpty(t, decision.UsernameHash)
	assert.NotContains(t, decision.UsernameHash, "alice")
}

func TestSupplicantLifecycleEvaluateRequiresPasswordChange(t *testing.T) {
	cfg := testSupplicantConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Platform:                   "windows",
		Username:                   "alice@example.com",
		EAPMethod:                  "peap",
		InnerMethod:                "mschapv2",
		IdentitySource:             "active-directory",
		PasswordExpired:            true,
		TLSProtected:               true,
		PasswordVerifierCompatible: true,
	})
	assert.Equal(t, "password_change_required", decision.Decision)
	assert.True(t, decision.PasswordChangeRequired)
}

func TestSupplicantLifecycleEvaluateRejectsVerifierMismatch(t *testing.T) {
	cfg := testSupplicantConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Platform:                   "windows",
		EAPMethod:                  "peap",
		InnerMethod:                "mschapv2",
		IdentitySource:             "unknown-source",
		TLSProtected:               true,
		PasswordVerifierCompatible: true,
	})
	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "identity source")
}

func TestSupplicantLifecycleBuildProfilePackageSignsContent(t *testing.T) {
	cfg := testSupplicantConfig()
	pkg, err := BuildProfilePackage(cfg, ProfileRequest{
		Platform:  "android",
		Username:  "alice@example.com",
		DeviceID:  "AA:BB:CC:DD:EE:FF",
		EAPMethod: "tls",
		Delivery:  "api",
	}, "profile-signing-secret")
	require.NoError(t, err)
	assert.Equal(t, "android", pkg.Manifest.Platform)
	assert.Equal(t, "application/json", pkg.ContentType)
	assert.NotEmpty(t, pkg.Signature)
	assert.NotEmpty(t, pkg.SigningKeyFingerprint)
	assert.Contains(t, pkg.Content, "AegisNAS-Enterprise")
	assert.NotContains(t, strings.ToLower(pkg.Content), "alice@example.com")
}

func TestSupplicantLifecycleBuildProfilePackageRejectsMissingSigningKey(t *testing.T) {
	cfg := testSupplicantConfig()
	_, err := BuildProfilePackage(cfg, ProfileRequest{Platform: "windows"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key")
}

func testSupplicantConfig() *config.Config {
	pin := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return &config.Config{
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
		Portal:     config.PortalConfig{Enabled: true},
		Radius: config.RadiusConfig{EAP: config.RadiusEAPConfig{Framework: config.RadiusEAPFramework{
			Enabled:        true,
			AllowedMethods: []string{"tls", "peap", "ttls"},
		}}},
		Onboarding: config.OnboardingConfig{
			PortalEnabled: true,
			CertificateLifecycle: config.CertificateLifecycleConfig{
				Enabled: true,
			},
			SupplicantLifecycle: config.SupplicantLifecycleConfig{
				Enabled:                      true,
				Mode:                         "enforce",
				FailClosed:                   true,
				SSID:                         "AegisNAS-Enterprise",
				Security:                     "wpa2-enterprise",
				DefaultPlatform:              "windows",
				AllowedPlatforms:             []string{"windows", "macos", "ios", "android", "linux"},
				DefaultEAPMethod:             "tls",
				AllowedEAPMethods:            []string{"tls", "peap", "ttls"},
				DefaultInnerMethod:           "mschapv2",
				AllowedInnerMethods:          []string{"mschapv2", "pap", "gtc", "tls"},
				AnonymousIdentity:            "anonymous@aegisnas.local",
				RequireAnonymousIdentity:     true,
				ServerNames:                  []string{"radius.example.com"},
				TrustAnchorPins:              []string{pin},
				RequireTrustAnchorPinning:    true,
				AllowPasswordChange:          true,
				PasswordChangeProviders:      []string{"active-directory"},
				RequireVerifierCompatibility: true,
				CompatibleVerifiers:          []string{"active-directory", "local"},
				ExpiryWarningDays:            14,
				RequireMFAForChange:          true,
				RequireTLSForDelivery:        true,
				RequireSignedProfiles:        true,
				ProfileSigningKeyRef:         "env:AEGIS_SUPPLICANT_PROFILE_SIGNING_KEY",
				ProfileValidityDays:          365,
				DeliveryTokenTTLSeconds:      900,
				AuditEnabled:                 true,
				EventRetentionLimit:          100,
				ProfileRetentionLimit:        100,
			},
		},
	}
}
