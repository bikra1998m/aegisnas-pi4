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
	assert.True(t, effective.OutboundQueueEnabled)
	assert.True(t, effective.OutboundReplayEnabled)
	assert.Equal(t, 10000, effective.OutboundMaxQueueRecords)
	assert.Equal(t, 6, effective.OutboundMaxAttempts)
	assert.Equal(t, 5, effective.OutboundInitialRetrySeconds)
	assert.Equal(t, 300, effective.OutboundMaxRetrySeconds)
	assert.Equal(t, 3600, effective.OutboundRecordTTLSeconds)
	assert.Equal(t, 15, effective.OutboundReplayIntervalSeconds)
	assert.Equal(t, 50, effective.OutboundBatchSize)
	assert.Equal(t, 60, effective.OutboundLockSeconds)
	assert.Equal(t, 86400, effective.OutboundACKRetentionSeconds)
	assert.Equal(t, 2592000, effective.OutboundDeadLetterRetentionSeconds)
	assert.Equal(t, 3600, effective.OutboundIdempotencyWindowSeconds)
	assert.True(t, effective.OutboundProxyEnabled)
	assert.True(t, effective.OutboundProxyAllowUDP)
	assert.True(t, effective.OutboundProxyAllowRadSec)
	assert.Equal(t, 8, effective.OutboundProxyMaxHops)
	assert.Equal(t, "aegisnas", effective.OutboundProxyLoopMarker)
	assert.True(t, effective.OutboundProxyAddLoopMarker)
	assert.True(t, effective.OutboundProxyRejectLoopMarker)
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
				Enabled:                            true,
				Port:                               3799,
				OutboundEnabled:                    true,
				OutboundDefaultPort:                3799,
				OutboundTimeoutSeconds:             5,
				OutboundRequireKnownClient:         true,
				OutboundHistoryLimit:               10000,
				OutboundMaxAttributes:              32,
				OutboundAllowCoA:                   true,
				OutboundAllowDisconnect:            true,
				OutboundRequireConfirmation:        true,
				OutboundQueueEnabled:               true,
				OutboundReplayEnabled:              true,
				OutboundMaxQueueRecords:            10000,
				OutboundMaxAttempts:                6,
				OutboundInitialRetrySeconds:        5,
				OutboundMaxRetrySeconds:            300,
				OutboundRecordTTLSeconds:           3600,
				OutboundReplayIntervalSeconds:      15,
				OutboundBatchSize:                  50,
				OutboundLockSeconds:                60,
				OutboundACKRetentionSeconds:        86400,
				OutboundDeadLetterRetentionSeconds: 2592000,
				OutboundIdempotencyWindowSeconds:   3600,
				OutboundProxyEnabled:               true,
				OutboundProxyAllowUDP:              true,
				OutboundProxyAllowRadSec:           true,
				OutboundProxyMaxHops:               8,
				OutboundProxyLoopMarker:            "aegisnas",
				OutboundProxyAddLoopMarker:         true,
				OutboundProxyRejectLoopMarker:      true,
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

	badQueue := *base
	badQueue.Radius.DynamicAuth.OutboundBatchSize = 10001
	assert.ErrorContains(t, badQueue.Validate(), "outbound_batch_size")

	badRetry := *base
	badRetry.Radius.DynamicAuth.OutboundMaxRetrySeconds = 4
	assert.ErrorContains(t, badRetry.Validate(), "outbound_max_retry_seconds")

	badIdempotency := *base
	badIdempotency.Radius.DynamicAuth.OutboundIdempotencyWindowSeconds = 7200
	assert.ErrorContains(t, badIdempotency.Validate(), "outbound_idempotency_window_seconds")

	badProxyTransport := *base
	badProxyTransport.Radius.DynamicAuth.OutboundProxyAllowUDP = false
	badProxyTransport.Radius.DynamicAuth.OutboundProxyAllowRadSec = false
	assert.ErrorContains(t, badProxyTransport.Validate(), "outbound proxy must allow")

	badProxyHops := *base
	badProxyHops.Radius.DynamicAuth.OutboundProxyMaxHops = 33
	assert.ErrorContains(t, badProxyHops.Validate(), "outbound_proxy_max_hops")

	badProxyMarker := *base
	badProxyMarker.Radius.DynamicAuth.OutboundProxyLoopMarker = "bad\nmarker"
	assert.ErrorContains(t, badProxyMarker.Validate(), "outbound_proxy_loop_marker")
}
