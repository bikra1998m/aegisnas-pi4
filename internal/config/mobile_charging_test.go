package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveMobileChargingConfigDefaults(t *testing.T) {
	cfg := EffectiveMobileChargingConfig(MobileChargingConfig{})

	assert.Equal(t, "monitor", cfg.Mode)
	assert.True(t, cfg.RequireDatabase)
	assert.True(t, cfg.RequireMobileSessions)
	assert.True(t, cfg.RequireAccountingCharging)
	assert.True(t, cfg.RequireOnlineCharging)
	assert.True(t, cfg.RequireOfflineCharging)
	assert.True(t, cfg.RequireMediation)
	assert.True(t, cfg.RedactSubscriberIDs)
	assert.True(t, cfg.HashSubscriberIDs)
	assert.True(t, cfg.QuotaCorrelation)
	assert.Equal(t, "USD", cfg.DefaultCurrency)
	assert.Equal(t, "ocs-online", cfg.DefaultOnlineStream)
	assert.Equal(t, "ofcs-offline", cfg.DefaultOfflineStream)
	assert.GreaterOrEqual(t, len(cfg.Streams), 3)
	assert.GreaterOrEqual(t, len(cfg.RatingGroups), 2)
	assert.GreaterOrEqual(t, len(cfg.QuotaPolicies), 2)
	assert.NotEmpty(t, cfg.CorrelationAttributes)
	assert.NotEmpty(t, cfg.ExternalMediationReferences)
}

func TestValidateMobileChargingConfigAcceptsEnterpriseEnforce(t *testing.T) {
	err := validateMobileChargingConfig(MobileChargingConfig{
		Enabled:                   true,
		Mode:                      "enforce",
		FailClosed:                true,
		RequireMobileSessions:     true,
		RequireAccountingCharging: true,
		RequireOnlineCharging:     true,
		RequireOfflineCharging:    true,
		RequireMediation:          true,
		QuotaCorrelation:          true,
		RedactSubscriberIDs:       true,
		HashSubscriberIDs:         true,
		DefaultCurrency:           "usd",
	}, MobileSessionConfig{
		Enabled: true,
		Mode:    "enforce",
	}, RadiusConfig{AccountingCharging: RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}}, "enterprise")

	require.NoError(t, err)
}

func TestValidateMobileChargingConfigBlocksMissingMobileSessions(t *testing.T) {
	err := validateMobileChargingConfig(MobileChargingConfig{
		Enabled:                   true,
		Mode:                      "enforce",
		RequireMobileSessions:     true,
		RequireAccountingCharging: true,
	}, MobileSessionConfig{}, RadiusConfig{AccountingCharging: RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}}, "enterprise")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "mobile.sessions.enabled")
}

func TestValidateMobileChargingConfigBlocksMissingAccountingCharging(t *testing.T) {
	err := validateMobileChargingConfig(MobileChargingConfig{
		Enabled:                   true,
		Mode:                      "enforce",
		RequireMobileSessions:     true,
		RequireAccountingCharging: true,
	}, MobileSessionConfig{Enabled: true}, RadiusConfig{}, "enterprise")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "radius.accounting_charging")
}

func TestValidateMobileChargingConfigRejectsUnknownQuotaPolicyReference(t *testing.T) {
	cfg := EffectiveMobileChargingConfig(MobileChargingConfig{Enabled: true, Mode: "enforce"})
	cfg.RatingGroups[0].QuotaPolicy = "missing-policy"
	err := validateMobileChargingConfig(cfg, MobileSessionConfig{Enabled: true}, RadiusConfig{AccountingCharging: RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}}, "enterprise")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown policy")
}

func TestValidateMobileChargingConfigBlocksLiteEnforce(t *testing.T) {
	err := validateMobileChargingConfig(MobileChargingConfig{
		Enabled: true,
		Mode:    "enforce",
	}, MobileSessionConfig{Enabled: true}, RadiusConfig{AccountingCharging: RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}}, "lite")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "lite")
}

func TestValidateMobileChargingConfigBlocksUnsafeSubscriberPrivacy(t *testing.T) {
	err := validateMobileChargingConfig(MobileChargingConfig{
		Enabled:             true,
		Mode:                "enforce",
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   false,
	}, MobileSessionConfig{Enabled: true}, RadiusConfig{AccountingCharging: RadiusAccountingChargingConfig{
		Enabled:       true,
		RatingEnabled: true,
		ExportEnabled: true,
	}}, "enterprise")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash_subscriber_ids")
}
