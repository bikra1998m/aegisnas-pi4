package enforcement

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestSubscriberRouteExportPreviewApplyWithdrawRollback(t *testing.T) {
	prepareSubscriberRouteExportTestDB(t)
	artifactPath := filepath.Join(t.TempDir(), "subscriber-routes.frr")
	cfg := subscriberRouteExportTestConfig(artifactPath)

	_, err := db.RecordRoutePolicyEvent(db.RoutePolicyEventInput{
		Operation:       "compile",
		Status:          "compiled",
		Role:            "branch-vpn",
		SessionID:       "session-1",
		AcctSessionID:   "acct-1",
		VRF:             "corp",
		Owner:           "network-team",
		Revision:        "sha256:route",
		IPv4RouteCount:  1,
		IPv6RouteCount:  1,
		AttributeCount:  4,
		Fingerprint:     "sha256:compiled",
		RequestJSON:     "{}",
		ResponseJSON:    "{}",
		DiagnosticsJSON: "[]",
		Actor:           "ops",
		Ownership: []db.RoutePolicyOwnershipInput{
			{Family: "ipv4", Destination: "10.80.0.0/16", Gateway: "192.0.2.1", Metric: 10, Tag: "65000", Source: "role"},
			{Family: "ipv6", Destination: "2001:db8:80::/48", Gateway: "2001:db8::1", Metric: 20, Source: "role"},
		},
	})
	require.NoError(t, err)

	preview, err := PreviewSubscriberRouteExport(cfg)
	require.NoError(t, err)
	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, 2, preview.Summary.ExportedRoutes)
	assert.Contains(t, preview.ArtifactText, "ip route vrf corp 10.80.0.0/16 192.0.2.1 10 tag 65000")
	assert.Contains(t, preview.ArtifactText, "ipv6 route vrf corp 2001:db8:80::/48 2001:db8::1 20")
	assert.Contains(t, preview.ArtifactText, "router bgp 64512 vrf corp")
	assert.NotEmpty(t, preview.PlanFingerprint)

	firstApply, err := ApplySubscriberRouteExport(cfg, "ops", "apply")
	require.NoError(t, err)
	assert.Equal(t, "applied", firstApply.Status)
	require.NotEmpty(t, firstApply.SnapshotID)
	artifact, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	assert.Contains(t, string(artifact), "redistribute static route-map AEGISNAS-SUBSCRIBER-IPV4")

	affected, err := db.WithdrawRoutePolicyOwnershipForSession(context.Background(), "session-1", "", "acct-stop-1", "accounting-stop")
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected)

	secondApply, err := ApplySubscriberRouteExport(cfg, "ops", "apply")
	require.NoError(t, err)
	assert.Equal(t, "applied", secondApply.Status)
	assert.Equal(t, 0, secondApply.Plan.Summary.ExportedRoutes)
	assert.Equal(t, 2, secondApply.Plan.Summary.WithdrawRouteCount)

	rollback, err := RollbackSubscriberRouteExport(firstApply.SnapshotID, "ops")
	require.NoError(t, err)
	assert.Equal(t, "rolled_back", rollback.Status)
	assert.Equal(t, firstApply.SnapshotID, rollback.RestoredSnapshotID)
	artifact, err = os.ReadFile(artifactPath)
	require.NoError(t, err)
	assert.Contains(t, string(artifact), "ip route vrf corp 10.80.0.0/16 192.0.2.1 10 tag 65000")

	summary, err := db.GetSubscriberRouteExportSummary()
	require.NoError(t, err)
	assert.Equal(t, 3, summary.TotalEvents)
	assert.Equal(t, 2, summary.AppliedCount)
	assert.Equal(t, 1, summary.RolledBackCount)
}

func TestSubscriberRouteExportApplyGate(t *testing.T) {
	prepareSubscriberRouteExportTestDB(t)
	cfg := subscriberRouteExportTestConfig(filepath.Join(t.TempDir(), "subscriber-routes.frr"))
	cfg.Radius.RoutePolicy.DynamicRouting.ApplyEnabled = false

	result, err := ApplySubscriberRouteExport(cfg, "ops", "apply")
	require.NoError(t, err)
	assert.Equal(t, "skipped", result.Status)
	assert.Contains(t, result.Message, "apply is disabled")
}

func prepareSubscriberRouteExportTestDB(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}

func subscriberRouteExportTestConfig(artifactPath string) *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			RoutePolicy: config.RadiusRoutePolicyConfig{
				Enabled: true,
				DynamicRouting: config.RadiusDynamicRoutingConfig{
					Enabled:           true,
					ApplyEnabled:      true,
					Driver:            "file",
					ArtifactPath:      artifactPath,
					MaxExportedRoutes: 16,
					Dampening: config.RadiusRouteDampeningConfig{
						Enabled: false,
					},
					Protocols: []config.RadiusDynamicProtocolConfig{
						{
							Protocol:        "bgp",
							Enabled:         true,
							VRF:             "all",
							ASN:             64512,
							RouteMap:        "AEGISNAS-SUBSCRIBER",
							AddressFamilies: []string{"ipv4", "ipv6"},
							LocalPreference: 100,
						},
					},
				},
			},
		},
	}
}
