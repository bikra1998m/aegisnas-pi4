package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMobilePolicyControlValidation(t *testing.T) {
	cfg := testMobilePolicyControlConfig()
	cfg.Mobile.PolicyControl = EffectiveMobilePolicyControlConfig(cfg.Mobile.PolicyControl)
	require.NoError(t, validateMobilePolicyControlConfig(cfg.Mobile.PolicyControl, cfg.Mobile.Sessions, cfg.Mobile.Charging, cfg.Radius, cfg.Policy, cfg.Broadband.QoSServiceFlows, "enterprise"))

	cfg.Mobile.PolicyControl.QoSClasses[0].Name = ""
	require.ErrorContains(t, validateMobilePolicyControlConfig(cfg.Mobile.PolicyControl, cfg.Mobile.Sessions, cfg.Mobile.Charging, cfg.Radius, cfg.Policy, cfg.Broadband.QoSServiceFlows, "enterprise"), "qos_classes[0].name")

	cfg = testMobilePolicyControlConfig()
	cfg.Mobile.PolicyControl = EffectiveMobilePolicyControlConfig(cfg.Mobile.PolicyControl)
	cfg.Mobile.PolicyControl.PolicyProfiles[0].QoSClass = "missing"
	require.ErrorContains(t, validateMobilePolicyControlConfig(cfg.Mobile.PolicyControl, cfg.Mobile.Sessions, cfg.Mobile.Charging, cfg.Radius, cfg.Policy, cfg.Broadband.QoSServiceFlows, "enterprise"), "qos_class")

	cfg = testMobilePolicyControlConfig()
	cfg.Mobile.PolicyControl = EffectiveMobilePolicyControlConfig(cfg.Mobile.PolicyControl)
	cfg.Policy.TypedEngineEnabled = false
	require.ErrorContains(t, validateMobilePolicyControlConfig(cfg.Mobile.PolicyControl, cfg.Mobile.Sessions, cfg.Mobile.Charging, cfg.Radius, cfg.Policy, cfg.Broadband.QoSServiceFlows, "enterprise"), "policy.typed_engine_enabled")

	cfg = testMobilePolicyControlConfig()
	cfg.Mobile.PolicyControl = EffectiveMobilePolicyControlConfig(cfg.Mobile.PolicyControl)
	require.ErrorContains(t, validateMobilePolicyControlConfig(cfg.Mobile.PolicyControl, cfg.Mobile.Sessions, cfg.Mobile.Charging, cfg.Radius, cfg.Policy, cfg.Broadband.QoSServiceFlows, "lite"), "lite")
}

func TestEffectiveMobilePolicyControlDefaults(t *testing.T) {
	cfg := EffectiveMobilePolicyControlConfig(MobilePolicyControlConfig{})

	assert.Equal(t, "monitor", cfg.Mode)
	assert.Equal(t, "home-default", cfg.DefaultPolicyProfile)
	assert.Equal(t, "default-5qi-9", cfg.DefaultQoSClass)
	assert.Equal(t, "home-plmn", cfg.DefaultRoamingPolicy)
	assert.True(t, cfg.RequireDatabase)
	assert.True(t, cfg.RequireMobileSessions)
	assert.True(t, cfg.RequirePolicyEngine)
	assert.True(t, cfg.RequireQoS)
	assert.True(t, cfg.RequireDynamicAuth)
	assert.True(t, cfg.RequireCharging)
	assert.True(t, cfg.RoamingControl)
	assert.True(t, cfg.EnforcementFeedback)
	assert.True(t, cfg.RedactSubscriberIDs)
	assert.True(t, cfg.HashSubscriberIDs)
	assert.GreaterOrEqual(t, len(cfg.PolicyProfiles), 3)
	assert.GreaterOrEqual(t, len(cfg.QoSClasses), 3)
	assert.GreaterOrEqual(t, len(cfg.RoamingPolicies), 2)
	assert.GreaterOrEqual(t, len(cfg.FeedbackRules), 2)
}

func testMobilePolicyControlConfig() *Config {
	return &Config{
		Deployment: DeploymentConfig{Profile: "enterprise"},
		Policy: PolicyConfig{
			TypedEngineEnabled:    true,
			RuntimeShapingEnabled: true,
		},
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
		Broadband: BroadbandConfig{
			QoSServiceFlows: BroadbandQoSServiceFlowConfig{Enabled: true},
		},
		Mobile: MobileConfig{
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
				QuotaCorrelation:          true,
				RedactSubscriberIDs:       true,
				HashSubscriberIDs:         true,
			},
			PolicyControl: MobilePolicyControlConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				RedactSubscriberIDs: true,
				HashSubscriberIDs:   true,
			},
		},
	}
}
