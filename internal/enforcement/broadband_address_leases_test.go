package enforcement

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestPreviewBroadbandAddressLeasesBuildsFullPlan(t *testing.T) {
	cfg := loadBroadbandAddressLeaseTestConfig(t)

	report, err := PreviewBroadbandAddressLeases(cfg)
	require.NoError(t, err)

	assert.Equal(t, BroadbandAddressLeaseFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status, "blockers: %v warnings: %v", report.Blockers, report.Warnings)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, float64(100), report.SoftwareCompletionPercent)
	assert.Equal(t, "enforce", report.Summary.Mode)
	assert.Equal(t, 3, report.Summary.PoolCount)
	assert.Equal(t, 1, report.Summary.IPv4PoolCount)
	assert.Equal(t, 1, report.Summary.IPv6PoolCount)
	assert.Equal(t, 1, report.Summary.DelegatedPoolCount)
	assert.Equal(t, 1, report.Summary.ReservationCount)
	assert.Equal(t, 4, report.Summary.LeaseIntentCount)
	assert.Equal(t, 2, report.Summary.IPv4LeaseIntentCount)
	assert.Equal(t, 2, report.Summary.IPv6LeaseIntentCount)
	assert.Equal(t, 1, report.Summary.DelegatedLeaseIntentCount)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.ReleaseCertificationChecklist, "nas-0086")
	assert.Contains(t, strings.Join(report.LeaseIntents[0].Attributes, " "), "Framed")
}

func TestPreviewBroadbandAddressLeasesBlocksUnsafeConfig(t *testing.T) {
	cfg := loadBroadbandAddressLeaseTestConfig(t)
	cfg.Radius.AddressPolicy.Enabled = false

	report, err := PreviewBroadbandAddressLeases(cfg)
	require.NoError(t, err)

	assert.Equal(t, "blocked", report.Status)
	assert.False(t, report.ReadyForExternalValidation)
	assert.Contains(t, strings.Join(report.Blockers, " "), "address_policy")
}

func TestPreviewBroadbandAddressLeasesSkippedWhenDisabled(t *testing.T) {
	cfg := loadBroadbandAddressLeaseTestConfig(t)
	cfg.Broadband.AddressLeases.Enabled = false

	report, err := PreviewBroadbandAddressLeases(cfg)
	require.NoError(t, err)

	assert.Equal(t, "skipped", report.Status)
	assert.True(t, report.ReadyForExternalValidation)
	assert.False(t, report.Summary.Enabled)
	assert.NotEmpty(t, report.LeaseIntents)
	assert.NotEmpty(t, report.PlanFingerprint)
}

func TestApplyBroadbandAddressLeasesRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandAddressLeaseTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandAddressLeases(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "applied", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandAddressLeaseEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "apply", events[0].Operation)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 4, events[0].LeaseIntentCount)

	leases, err := db.ListBroadbandAddressLeases(10, "")
	require.NoError(t, err)
	require.Len(t, leases, 4)
	assert.Equal(t, "reserved", leases[0].Status)

	runtime, err := db.GetRuntimeStatus(BroadbandAddressLeaseComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0086")
}

func loadBroadbandAddressLeaseTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := loadBroadbandSubscriberStateTestConfig(t, "")
	cfg.Broadband.AddressLeases = config.BroadbandAddressLeaseConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		StickyIPv4:                    true,
		StickyIPv6:                    true,
		DualStackRequired:             true,
		DelegatedPrefixRequired:       true,
		ReservationRequired:           true,
		ConflictDetectionEnabled:      true,
		AccountingCorrelationRequired: true,
		CoAOnConflict:                 true,
		ReleaseOnAccountingStop:       true,
		RecoveryScanSeconds:           60,
		StaleAfterSeconds:             600,
		EventRetentionLimit:           10000,
		Pools: []config.BroadbandAddressLeasePoolConfig{
			{Name: "pppoe-v4", Family: "ipv4", CIDR: "100.64.0.0/24", Start: "100.64.0.10", End: "100.64.0.250", Gateway: "100.64.0.1", Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "mikrotik"}},
			{Name: "pppoe-v6", Family: "ipv6", CIDR: "2001:db8:100::/48", Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "huawei"}},
			{Name: "pppoe-pd", Family: "delegated-prefix", CIDR: "2001:db8:200::/40", DelegatedPrefixLength: 56, Product: "residential-fiber", Role: "residential", Dynamic: true, Sticky: true, VendorPacks: []string{"standard", "aegisnas", "alcatel-lucent-service-router"}},
		},
		Reservations: []config.BroadbandAddressLeaseReservationConfig{
			{Key: "lab-cpe-01", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Product: "residential-fiber", Role: "residential", Pool: "pppoe-v4", Family: "ipv4", AssignmentType: "address", Address: "100.64.0.20", Reason: "Lab reservation"},
		},
	}
	return cfg
}
