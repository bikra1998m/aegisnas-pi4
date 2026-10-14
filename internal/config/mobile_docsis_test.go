package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobileDOCSISValidation(t *testing.T) {
	cfg := testMobileDOCSISConfig()
	cfg.Mobile.DOCSIS = EffectiveMobileDOCSISConfig(cfg.Mobile.DOCSIS)
	require.NoError(t, validateMobileDOCSISConfig(cfg.Mobile.DOCSIS, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Broadband.QoSServiceFlows, cfg.Radius, "enterprise"))

	cfg.Mobile.DOCSIS.ServiceFlows[0].SchedulingType = "unknown"
	require.ErrorContains(t, validateMobileDOCSISConfig(cfg.Mobile.DOCSIS, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Broadband.QoSServiceFlows, cfg.Radius, "enterprise"), "scheduling_type")

	cfg = testMobileDOCSISConfig()
	cfg.Mobile.DOCSIS = EffectiveMobileDOCSISConfig(cfg.Mobile.DOCSIS)
	cfg.Mobile.DOCSIS.ModemProfiles[0].DefaultServiceFlow = "missing"
	require.ErrorContains(t, validateMobileDOCSISConfig(cfg.Mobile.DOCSIS, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Broadband.QoSServiceFlows, cfg.Radius, "enterprise"), "default_service_flow")

	cfg = testMobileDOCSISConfig()
	cfg.Mobile.DOCSIS = EffectiveMobileDOCSISConfig(cfg.Mobile.DOCSIS)
	cfg.Broadband.QoSServiceFlows.Enabled = false
	require.ErrorContains(t, validateMobileDOCSISConfig(cfg.Mobile.DOCSIS, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Broadband.QoSServiceFlows, cfg.Radius, "enterprise"), "broadband.qos_service_flows.enabled")

	cfg = testMobileDOCSISConfig()
	cfg.Mobile.DOCSIS = EffectiveMobileDOCSISConfig(cfg.Mobile.DOCSIS)
	require.ErrorContains(t, validateMobileDOCSISConfig(cfg.Mobile.DOCSIS, cfg.Mobile.GroupedAVPs, cfg.Mobile.Charging, cfg.Broadband.QoSServiceFlows, cfg.Radius, "lite"), "lite")
}

func TestEffectiveMobileDOCSISDefaults(t *testing.T) {
	cfg := EffectiveMobileDOCSISConfig(MobileDOCSISConfig{})

	assert.Equal(t, "monitor", cfg.Mode)
	assert.Equal(t, "docsis-retail", cfg.DefaultModemProfile)
	assert.Equal(t, "hsd-best-effort", cfg.DefaultServiceFlow)
	assert.Equal(t, "cmts-primary", cfg.DefaultCMTSProfile)
	assert.True(t, cfg.RequireDatabase)
	assert.True(t, cfg.RequireGroupedAVPs)
	assert.True(t, cfg.RequireCharging)
	assert.True(t, cfg.RequireQoSServiceFlows)
	assert.True(t, cfg.RequireDynamicAuth)
	assert.True(t, cfg.CableModemProvisioning)
	assert.True(t, cfg.ServiceFlowAuthorization)
	assert.True(t, cfg.IPDRAccounting)
	assert.True(t, cfg.PolicyChargingCorrelation)
	assert.True(t, cfg.RedactDeviceIDs)
	assert.True(t, cfg.HashDeviceIDs)
	assert.GreaterOrEqual(t, len(cfg.ModemProfiles), 2)
	assert.GreaterOrEqual(t, len(cfg.ServiceFlows), 3)
	assert.GreaterOrEqual(t, len(cfg.CMTSProfiles), 2)
	assert.GreaterOrEqual(t, len(cfg.ChargingPolicies), 2)
	assert.Contains(t, cfg.RadiusAttributes, "CableLabs-QoS-Descriptor")
}

func testMobileDOCSISConfig() *Config {
	cfg := testMobileWiMAXConfig()
	cfg.Broadband.QoSServiceFlows.Enabled = true
	cfg.Mobile.DOCSIS = MobileDOCSISConfig{
		Enabled:         true,
		Mode:            "enforce",
		FailClosed:      true,
		RedactDeviceIDs: true,
		HashDeviceIDs:   true,
	}
	return cfg
}
