package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBuildProxyRoutingReportMultiRealm(t *testing.T) {
	cfg := proxyRoutingTestConfig()

	report := BuildProxyRoutingReport(cfg)

	require.Equal(t, "ready", report.Status)
	assert.True(t, report.Enabled)
	assert.Equal(t, ProxyRoutingSchemaVersion, report.SchemaVersion)
	assert.Equal(t, 2, report.Summary.RouteCount)
	assert.Equal(t, 2, report.Summary.ExplicitRouteCount)
	assert.Equal(t, 1, report.Summary.DefaultRouteCount)
	assert.Equal(t, "corp.example.com", report.Summary.DefaultRealm)
	assert.Len(t, report.Servers, 2)
	require.Len(t, report.Routes, 2)
	assert.Equal(t, "corp", report.Routes[0].Name)
	assert.True(t, report.Routes[0].Default)
	assert.Equal(t, []string{"corp.example.com", "employees.example.com"}, report.Routes[0].MatchRealms)
	assert.Equal(t, []string{"primary", "secondary"}, report.Routes[0].ServerNames)
}

func TestEffectiveProxyRoutesSynthesizesLegacyDefault(t *testing.T) {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Upstream.Routes = nil
	cfg.Radius.Upstream.Realm = "legacy.example.com"

	routes, err := EffectiveProxyRoutes(cfg)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "legacy-default", routes[0].Name)
	assert.Equal(t, "legacy.example.com", routes[0].Realm)
	assert.True(t, routes[0].Default)
	assert.Equal(t, "aegis_upstream_pool", routes[0].PoolName)
	assert.Equal(t, []string{"primary", "secondary"}, routes[0].ServerNames)
}

func TestBuildTransportPolicyReportFlagsMixedTransportRisk(t *testing.T) {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Upstream.Servers[1].Transport = "radsec"
	cfg.Radius.Upstream.TransportPolicy = config.RadiusTransportPolicyConfig{
		Enabled:                  true,
		Mode:                     "monitor",
		FailClosed:               true,
		DefaultRequiredTransport: "any",
		AllowMixedTransports:     false,
	}

	report := BuildTransportPolicyReport(cfg)

	require.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Summary.MixedTransportRoutes)
	assert.Equal(t, 1, report.Summary.ViolationCount)
	require.Len(t, report.Routes, 2)
	assert.True(t, report.Routes[0].DowngradeRisk)
	assert.Contains(t, report.Warnings[0], "mixes UDP and RadSec")
}

func TestBuildTransportPolicyReportEnforcesRadSecRoutes(t *testing.T) {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Upstream.TransportPolicy = config.RadiusTransportPolicyConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		DefaultRequiredTransport: "radsec",
	}

	report := BuildTransportPolicyReport(cfg)

	require.Equal(t, "blocked", report.Status)
	assert.Equal(t, 2, report.Summary.ViolationCount)
	assert.Contains(t, report.Routes[0].Message, "requires radsec")
}

func TestGeneratorBlocksTransportDowngradeInEnforceMode(t *testing.T) {
	cfg := proxyRoutingTestConfig()
	cfg.Radius.Upstream.Servers[1].Transport = "radsec"
	cfg.Radius.Upstream.TransportPolicy = config.RadiusTransportPolicyConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		DefaultRequiredTransport: "any",
		AllowMixedTransports:     false,
	}

	_, err := NewGenerator(cfg).Generate()

	assert.ErrorContains(t, err, "transport downgrade policy blocked")
}

func proxyRoutingTestConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			AuthPort: 1812,
			AcctPort: 1813,
			Upstream: config.RadiusUpstreamConfig{
				Enabled:           true,
				Realm:             "legacy.example.com",
				PoolStrategy:      "fail-over",
				StatusCheck:       "status-server",
				ResponseWindow:    20,
				ZombiePeriod:      40,
				ReviveInterval:    120,
				CheckInterval:     30,
				NumAnswersToAlive: 3,
				Servers: []config.RadiusHomeServer{
					{Name: "primary", Address: "10.0.0.10", Secret: "secret-one"},
					{Name: "secondary", Address: "10.0.0.11", Secret: "secret-two"},
				},
				Routes: []config.RadiusProxyRouteConfig{
					{
						Name:        "corp",
						Description: "Corporate 802.1X users",
						Enabled:     true,
						Realm:       "corp.example.com",
						MatchRealms: []string{"employees.example.com"},
						Default:     true,
						Servers:     []string{"primary", "secondary"},
					},
					{
						Name:         "guest",
						Enabled:      true,
						Realm:        "guest.example.com",
						PoolStrategy: "load-balance",
						StatusCheck:  "none",
						Servers:      []string{"secondary"},
					},
				},
			},
		},
	}
}
