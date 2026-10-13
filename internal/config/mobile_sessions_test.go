package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveMobileSessionConfigDefaults(t *testing.T) {
	cfg := EffectiveMobileSessionConfig(MobileSessionConfig{})

	assert.Equal(t, "monitor", cfg.Mode)
	assert.Equal(t, "internet", cfg.DefaultAPN)
	assert.Equal(t, "ipv4v6", cfg.DefaultPDNType)
	assert.True(t, cfg.RequireDatabase)
	assert.True(t, cfg.RequireGroupedAVPs)
	assert.True(t, cfg.RequireAccounting)
	assert.True(t, cfg.RequireDynamicAuth)
	assert.True(t, cfg.RedactSubscriberIDs)
	assert.True(t, cfg.HashSubscriberIDs)
	assert.GreaterOrEqual(t, len(cfg.APNProfiles), 2)
	assert.GreaterOrEqual(t, len(cfg.BearerTemplates), 2)
	assert.GreaterOrEqual(t, len(cfg.RoamingPartners), 2)
}

func TestValidateMobileSessionConfigAcceptsEnterpriseEnforce(t *testing.T) {
	err := validateMobileSessionConfig(MobileSessionConfig{
		Enabled:             true,
		Mode:                "enforce",
		FailClosed:          true,
		RequireGroupedAVPs:  true,
		RedactSubscriberIDs: true,
		HashSubscriberIDs:   true,
		StateReconciliation: true,
		HandoverTracking:    true,
		RoamingTracking:     true,
	}, "enterprise")

	require.NoError(t, err)
}

func TestValidateMobileSessionConfigRejectsUnknownAPNReference(t *testing.T) {
	err := validateMobileSessionConfig(MobileSessionConfig{
		Enabled:         true,
		Mode:            "enforce",
		DefaultAPN:      "missing",
		APNProfiles:     defaultMobileAPNProfiles(),
		BearerTemplates: defaultMobileBearerTemplates(),
	}, "enterprise")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_apn")
}

func TestValidateMobileSessionConfigBlocksLiteEnforce(t *testing.T) {
	err := validateMobileSessionConfig(MobileSessionConfig{
		Enabled: true,
		Mode:    "enforce",
	}, "lite")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "lite")
}
