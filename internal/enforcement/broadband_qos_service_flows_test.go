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

func TestPreviewBroadbandQoSServiceFlowsBuildsCompiledPlan(t *testing.T) {
	cfg := loadBroadbandQoSServiceFlowTestConfig(t)

	report, err := PreviewBroadbandQoSServiceFlows(cfg)
	require.NoError(t, err)
	assert.Equal(t, BroadbandQoSServiceFlowFeatureID, report.FeatureID)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 100.0, report.SoftwareCompletionPercent)
	assert.True(t, report.ReadyForExternalValidation)
	assert.Equal(t, 1, report.Summary.ProfileCount)
	assert.Equal(t, 1, report.Summary.ServiceFlowCount)
	assert.Equal(t, 1, report.Summary.AggregatePolicyCount)
	assert.GreaterOrEqual(t, report.Summary.CompiledAttributeCount, 3)
	assert.Equal(t, report.Summary.ComplianceCheckCount, report.Summary.PassedCheckCount)
	assert.Empty(t, report.Blockers)
	assert.NotEmpty(t, report.PlanFingerprint)
	assert.Contains(t, report.ServiceFlows[0].CompiledAttributes[0].Name, "Mikrotik")
}

func TestPreviewBroadbandQoSServiceFlowsBlocksMissingCoA(t *testing.T) {
	cfg := loadBroadbandQoSServiceFlowTestConfig(t)
	cfg.Radius.DynamicAuth.Enabled = false

	report, err := PreviewBroadbandQoSServiceFlows(cfg)
	require.NoError(t, err)
	assert.Equal(t, "blocked", report.Status)
	assert.Contains(t, strings.Join(report.Blockers, "\n"), "CoA")
}

func TestApplyBroadbandQoSServiceFlowsRecordsEvidenceAndRuntimeStatus(t *testing.T) {
	cfg := loadBroadbandQoSServiceFlowTestConfig(t)
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	report, eventID, err := ApplyBroadbandQoSServiceFlows(context.Background(), cfg, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ready", report.Status)
	assert.NotEmpty(t, eventID)

	events, err := db.ListBroadbandQoSServiceFlowEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "applied", events[0].Status)
	assert.Equal(t, 1, events[0].ServiceFlowCount)

	flows, err := db.ListBroadbandQoSServiceFlows(10, "active")
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, "fiber-internet", flows[0].Name)

	runtime, err := db.GetRuntimeStatus(BroadbandQoSServiceFlowComponent())
	require.NoError(t, err)
	require.NotNil(t, runtime)
	assert.Equal(t, "ok", runtime.Status)
	assert.Contains(t, runtime.Message, "NAS-0087")
}

func loadBroadbandQoSServiceFlowTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := loadBroadbandCommercialCatalogTestConfig(t)
	cfg.Radius.SQLAccounting.Enabled = true
	cfg.Radius.AccountingServices.Enabled = true
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Broadband.QoSServiceFlows = config.BroadbandQoSServiceFlowConfig{
		Enabled:                       true,
		Mode:                          "enforce",
		FailClosed:                    true,
		RequireSubscriberState:        true,
		RequireCommercialCatalog:      true,
		RequireRuntimeQoS:             true,
		RequireRateCompiler:           true,
		AccountingCorrelationRequired: true,
		CoAOnChange:                   true,
		AggregateControlEnabled:       true,
		Scheduler:                     "htb",
		DefaultTrafficClass:           "data",
		EventRetentionLimit:           10000,
		Profiles: []config.BroadbandQoSProfileConfig{
			{Name: "silver", Enabled: true, TrafficClass: "data", Scheduler: "htb", Priority: 4, DSCPMark: 10, DownloadMinRateKbps: 50000, DownloadRateKbps: 100000, DownloadPeakRateKbps: 120000, UploadMinRateKbps: 10000, UploadRateKbps: 20000, UploadPeakRateKbps: 25000, DownloadBurstKbps: 120000, UploadBurstKbps: 25000, BurstTimeSeconds: 10, AggregateLimitKbps: 1000000, MaxSubscribers: 128, VendorPacks: []string{"mikrotik", "huawei", "zte"}},
		},
		ServiceFlows: []config.BroadbandQoSServiceFlowIntentConfig{
			{Name: "fiber-internet", Enabled: true, Product: "fiber-100m", ServiceLeg: "internet", SubscriberID: "sub-lab-cpe-01", Username: "lab-cpe-01@example.net", Role: "subscriber", Tenant: "retail", Direction: "bidirectional", Profile: "silver", Aggregate: "tenant-retail", AccountingKey: "acct-class-internet", Precedence: 100, CoAAction: "rate-limit", VendorPacks: []string{"mikrotik", "huawei", "zte"}},
		},
		AggregatePolicies: []config.BroadbandQoSAggregatePolicyConfig{
			{Name: "tenant-retail", Enabled: true, Scope: "tenant", Tenant: "retail", Profile: "silver", MaxSubscribers: 1000, DownloadLimitKbps: 1000000, UploadLimitKbps: 250000, OversubscriptionRatio: 20, Scheduler: "htb", DropPrecedence: "low", VendorPacks: []string{"mikrotik", "huawei"}},
		},
	}
	return cfg
}
