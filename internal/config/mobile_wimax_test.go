package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobileWiMAXValidation(t *testing.T) {
	cfg := testMobileWiMAXConfig()
	cfg.Mobile.WiMAX = EffectiveMobileWiMAXConfig(cfg.Mobile.WiMAX)
	require.NoError(t, validateMobileWiMAXConfig(cfg.Mobile.WiMAX, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Radius, "enterprise"))

	cfg.Mobile.WiMAX.ServiceFlows[0].SchedulingType = "unknown"
	require.ErrorContains(t, validateMobileWiMAXConfig(cfg.Mobile.WiMAX, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Radius, "enterprise"), "scheduling_type")

	cfg = testMobileWiMAXConfig()
	cfg.Mobile.WiMAX = EffectiveMobileWiMAXConfig(cfg.Mobile.WiMAX)
	cfg.Mobile.WiMAX.SubscriberProfiles[0].DefaultServiceFlow = "missing"
	require.ErrorContains(t, validateMobileWiMAXConfig(cfg.Mobile.WiMAX, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Radius, "enterprise"), "default_service_flow")

	cfg = testMobileWiMAXConfig()
	cfg.Mobile.WiMAX = EffectiveMobileWiMAXConfig(cfg.Mobile.WiMAX)
	cfg.Mobile.GroupedAVPs.Enabled = false
	require.ErrorContains(t, validateMobileWiMAXConfig(cfg.Mobile.WiMAX, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Radius, "enterprise"), "mobile.grouped_avps.enabled")

	cfg = testMobileWiMAXConfig()
	cfg.Mobile.WiMAX = EffectiveMobileWiMAXConfig(cfg.Mobile.WiMAX)
	require.ErrorContains(t, validateMobileWiMAXConfig(cfg.Mobile.WiMAX, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Radius, "lite"), "lite")
}

func TestEffectiveMobileWiMAXDefaults(t *testing.T) {
	cfg := EffectiveMobileWiMAXConfig(MobileWiMAXConfig{})

	assert.Equal(t, "monitor", cfg.Mode)
	assert.Equal(t, "wimax-retail", cfg.DefaultSubscriberProfile)
	assert.Equal(t, "internet-be", cfg.DefaultServiceFlow)
	assert.Equal(t, "asn-primary", cfg.DefaultASNProfile)
	assert.True(t, cfg.RequireDatabase)
	assert.True(t, cfg.RequireGroupedAVPs)
	assert.True(t, cfg.RequireCharging)
	assert.True(t, cfg.RequireDynamicAuth)
	assert.True(t, cfg.ServiceFlowAuthorization)
	assert.True(t, cfg.MobilityTracking)
	assert.True(t, cfg.AccountingCorrelation)
	assert.True(t, cfg.RedactSubscriberIDs)
	assert.True(t, cfg.HashSubscriberIDs)
	assert.GreaterOrEqual(t, len(cfg.SubscriberProfiles), 2)
	assert.GreaterOrEqual(t, len(cfg.ServiceFlows), 3)
	assert.GreaterOrEqual(t, len(cfg.ASNProfiles), 2)
	assert.GreaterOrEqual(t, len(cfg.MobilityPolicies), 2)
	assert.Contains(t, cfg.RadiusAttributes, "WiMAX-QoS-Descriptor")
}

func testMobileWiMAXConfig() *Config {
	return &Config{
		Deployment: DeploymentConfig{Profile: "enterprise"},
		Radius: RadiusConfig{
			DynamicAuth: DynamicAuthConfig{
				Enabled:         true,
				OutboundEnabled: true,
			},
			AccountingCharging: RadiusAccountingChargingConfig{
				Enabled:       true,
				RatingEnabled: true,
				ExportEnabled: true,
			},
		},
		Mobile: MobileConfig{
			GroupedAVPs: MobileGroupedAVPConfig{
				Enabled:         true,
				Mode:            "enforce",
				SafeRawEvidence: true,
				HashRawValues:   true,
			},
			Sessions: MobileSessionConfig{
				Enabled:             true,
				Mode:                "enforce",
				RedactSubscriberIDs: true,
				HashSubscriberIDs:   true,
			},
			Charging: MobileChargingConfig{
				Enabled:                   true,
				Mode:                      "enforce",
				RequireMobileSessions:     true,
				RequireAccountingCharging: true,
				RequireOnlineCharging:     true,
				RequireOfflineCharging:    true,
				QuotaCorrelation:          true,
				RedactSubscriberIDs:       true,
				HashSubscriberIDs:         true,
			},
			WiMAX: MobileWiMAXConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				RedactSubscriberIDs: true,
				HashSubscriberIDs:   true,
			},
		},
	}
}
