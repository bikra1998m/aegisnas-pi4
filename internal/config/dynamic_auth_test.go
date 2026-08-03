package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoadAppliesOutboundDynamicAuthDefaults(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "dynamic-auth-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := `
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: /tmp/aegis.db
health:
  port: 8080
telemetry:
  prometheus_port: 9090
radius:
  secret: secret
  dynamic_auth:
    enabled: true
    port: 3799
`
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)
	effective := EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth)
	assert.True(t, effective.OutboundEnabled)
	assert.Equal(t, 3799, effective.OutboundDefaultPort)
	assert.Equal(t, 5, effective.OutboundTimeoutSeconds)
	assert.True(t, effective.OutboundRequireKnownClient)
	assert.Equal(t, 10000, effective.OutboundHistoryLimit)
	assert.Equal(t, 32, effective.OutboundMaxAttributes)
	assert.True(t, effective.OutboundAllowCoA)
	assert.True(t, effective.OutboundAllowDisconnect)
	assert.True(t, effective.OutboundRequireConfirmation)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidationOutboundDynamicAuthBounds(t *testing.T) {
	base := &Config{
		Mode: "two-nic",
		WAN:  InterfaceConfig{Name: "eth0"},
		LAN:  InterfaceConfig{Name: "eth1", Address: "192.168.1.1/24"},
		Database: DatabaseConfig{
			Path: "/tmp/aegis.db",
		},
		Health: HealthConfig{Port: 8080},
		Telemetry: TelemetryConfig{
			PrometheusPort: 9090,
		},
		Radius: RadiusConfig{
			Secret:                "secret",
			AuthPort:              1812,
			AcctPort:              1813,
			MaxSessions:           1024,
			RequestTimeoutSeconds: 5,
			DynamicAuth: DynamicAuthConfig{
				Enabled:                     true,
				Port:                        3799,
				OutboundEnabled:             true,
				OutboundDefaultPort:         3799,
				OutboundTimeoutSeconds:      5,
				OutboundRequireKnownClient:  true,
				OutboundHistoryLimit:        10000,
				OutboundMaxAttributes:       32,
				OutboundAllowCoA:            true,
				OutboundAllowDisconnect:     true,
				OutboundRequireConfirmation: true,
			},
		},
	}
	require.NoError(t, base.Validate())

	badTimeout := *base
	badTimeout.Radius.DynamicAuth.OutboundTimeoutSeconds = 0
	assert.NoError(t, badTimeout.Validate(), "zero timeout is defaulted")
	badTimeout.Radius.DynamicAuth.OutboundTimeoutSeconds = 61
	assert.ErrorContains(t, badTimeout.Validate(), "outbound_timeout_seconds")

	badLimit := *base
	badLimit.Radius.DynamicAuth.OutboundMaxAttributes = 65
	assert.ErrorContains(t, badLimit.Validate(), "outbound_max_attributes")

	badActions := *base
	badActions.Radius.DynamicAuth.OutboundAllowCoA = false
	badActions.Radius.DynamicAuth.OutboundAllowDisconnect = false
	assert.ErrorContains(t, badActions.Validate(), "outbound must allow")
}
