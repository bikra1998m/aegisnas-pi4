package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveMobileGroupedAVPConfigDefaults(t *testing.T) {
	effective := EffectiveMobileGroupedAVPConfig(MobileGroupedAVPConfig{})

	assert.Equal(t, "monitor", effective.Mode)
	assert.True(t, effective.RequireDatabase)
	assert.True(t, effective.RequireVSACodec)
	assert.True(t, effective.RequireAttributeRegistry)
	assert.True(t, effective.SafeRawEvidence)
	assert.True(t, effective.HashRawValues)
	assert.Equal(t, 4, effective.MaxDepth)
	assert.NotEmpty(t, effective.VendorScopes)
	assert.NotEmpty(t, effective.EvidencePolicies)
}

func TestValidateMobileGroupedAVPConfig(t *testing.T) {
	cfg := EffectiveMobileGroupedAVPConfig(MobileGroupedAVPConfig{Enabled: true, Mode: "enforce", FailClosed: true})
	require.NoError(t, validateMobileGroupedAVPConfig(cfg, "enterprise"))

	cfg.MaxDepth = 5
	require.ErrorContains(t, validateMobileGroupedAVPConfig(cfg, "enterprise"), "max_depth")

	cfg = EffectiveMobileGroupedAVPConfig(MobileGroupedAVPConfig{Enabled: true, Mode: "enforce"})
	require.ErrorContains(t, validateMobileGroupedAVPConfig(cfg, "lite"), "lite")

	cfg = EffectiveMobileGroupedAVPConfig(MobileGroupedAVPConfig{Enabled: true, Mode: "enforce"})
	cfg.EvidencePolicies[0].CaptureRaw = true
	cfg.EvidencePolicies[0].HashRawValues = false
	require.ErrorContains(t, validateMobileGroupedAVPConfig(cfg, "enterprise"), "hash_raw_values")
}
