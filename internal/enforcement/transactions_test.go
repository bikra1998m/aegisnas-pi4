package enforcement

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAtomicEnforcementApplyFailureCompensatesAppliedTargets(t *testing.T) {
	prepareAtomicEnforcementTestDB(t)
	restoreAtomicEnforcementParticipants(t)
	cfg := atomicEnforcementTestConfig()

	var calls []string
	atomicRuntimeQoSApplyFn = func(context.Context, *config.Config, string) (AtomicEnforcementStep, error) {
		calls = append(calls, "qos-apply")
		return AtomicEnforcementStep{
			Target:             "runtime_qos",
			Status:             "applied",
			DesiredFingerprint: "sha256:qos-desired",
			ActiveFingerprint:  "sha256:qos-active",
			PreviousSnapshotID: "qos-prev",
			SnapshotID:         "qos-new",
			RollbackSupported:  true,
			Message:            "qos applied",
		}, nil
	}
	atomicRuntimeFirewallApplyFn = func(context.Context, *config.Config, string) (AtomicEnforcementStep, error) {
		calls = append(calls, "firewall-apply")
		return AtomicEnforcementStep{
			Target: "runtime_firewall",
			Status: "failed",
			Error:  "nft apply failed",
		}, fmt.Errorf("nft apply failed")
	}
	atomicRuntimeQoSRollbackFn = func(_ context.Context, _ *config.Config, snapshotID, _ string) (AtomicEnforcementStep, error) {
		calls = append(calls, "qos-rollback:"+snapshotID)
		return AtomicEnforcementStep{
			Target:             "runtime_qos",
			Status:             "rolled_back",
			RestoredSnapshotID: snapshotID,
			RollbackSupported:  true,
			Message:            "qos rollback",
		}, nil
	}

	result, err := ApplyAtomicEnforcement(context.Background(), cfg, AtomicEnforcementRequest{Targets: []string{"runtime_firewall", "runtime_qos"}}, "ops")
	require.Error(t, err)
	assert.Equal(t, "compensated", result.Status)
	assert.Equal(t, []string{"qos-apply", "firewall-apply", "qos-rollback:qos-prev"}, calls)
	require.Len(t, result.Steps, 3)
	assert.Equal(t, "compensate", result.Steps[2].Operation)
	assert.Equal(t, "compensated", result.Steps[2].Status)

	summary, err := db.GetEnforcementTransactionSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalTransactions)
	assert.Equal(t, 1, summary.CompensatedCount)
	assert.Equal(t, 1, summary.CompensatedSteps)
	assert.Equal(t, 1, summary.FailedSteps)
}

func TestAtomicEnforcementDriftAndRollbackEvidence(t *testing.T) {
	prepareAtomicEnforcementTestDB(t)
	restoreAtomicEnforcementParticipants(t)
	cfg := atomicEnforcementTestConfig()

	var calls []string
	atomicRuntimeQoSApplyFn = func(context.Context, *config.Config, string) (AtomicEnforcementStep, error) {
		calls = append(calls, "qos-apply")
		return AtomicEnforcementStep{
			Target:             "runtime_qos",
			Status:             "applied",
			DesiredFingerprint: "sha256:qos-desired",
			ActiveFingerprint:  "sha256:qos-active",
			PreviousSnapshotID: "qos-prev",
			SnapshotID:         "qos-new",
			RollbackSupported:  true,
		}, nil
	}
	atomicRuntimeFirewallApplyFn = func(context.Context, *config.Config, string) (AtomicEnforcementStep, error) {
		calls = append(calls, "firewall-apply")
		return AtomicEnforcementStep{
			Target:             "runtime_firewall",
			Status:             "applied",
			DesiredFingerprint: "sha256:fw-desired",
			ActiveFingerprint:  "sha256:fw-active",
			PreviousSnapshotID: "fw-prev",
			SnapshotID:         "fw-new",
			RollbackSupported:  true,
		}, nil
	}
	atomicRuntimeFirewallRollbackFn = func(_ context.Context, _ *config.Config, snapshotID, _ string) (AtomicEnforcementStep, error) {
		calls = append(calls, "firewall-rollback:"+snapshotID)
		return AtomicEnforcementStep{Target: "runtime_firewall", Status: "rolled_back", RestoredSnapshotID: snapshotID, RollbackSupported: true}, nil
	}
	atomicRuntimeQoSRollbackFn = func(_ context.Context, _ *config.Config, snapshotID, _ string) (AtomicEnforcementStep, error) {
		calls = append(calls, "qos-rollback:"+snapshotID)
		return AtomicEnforcementStep{Target: "runtime_qos", Status: "rolled_back", RestoredSnapshotID: snapshotID, RollbackSupported: true}, nil
	}

	applyResult, err := ApplyAtomicEnforcement(context.Background(), cfg, AtomicEnforcementRequest{Targets: []string{"runtime_qos", "runtime_firewall"}, SkipDriftCheck: true}, "ops")
	require.NoError(t, err)
	assert.Equal(t, "applied", applyResult.Status)
	require.Len(t, applyResult.Steps, 2)

	now := time.Now().UTC()
	_, err = db.RecordRuntimeQoSSnapshot(db.RuntimeQoSSnapshotInput{
		Operation:       "apply",
		Status:          "applied",
		Active:          true,
		InterfaceName:   "eth1",
		IFBDevice:       "ifb-aegis0",
		PlanFingerprint: "sha256:old-qos",
		CommandText:     "tc qdisc replace dev eth1 root handle 1: htb",
		DiagnosticsJSON: "[]",
		SummaryJSON:     "{}",
		Actor:           "ops",
		AppliedAt:       &now,
	})
	require.NoError(t, err)
	_, err = db.RecordRuntimeFirewallSnapshot(db.RuntimeFirewallSnapshotInput{
		Operation:          "apply",
		Status:             "applied",
		Active:             true,
		RulesetFingerprint: "sha256:old-firewall",
		RulesetText:        "table inet aegis_runtime {}",
		DiagnosticsJSON:    "[]",
		Actor:              "ops",
		AppliedAt:          &now,
	})
	require.NoError(t, err)

	driftResult, err := DetectAtomicEnforcementDrift(context.Background(), cfg, AtomicEnforcementRequest{Targets: []string{"runtime_qos", "runtime_firewall"}}, "ops")
	require.NoError(t, err)
	assert.Equal(t, "drifted", driftResult.Status)
	assert.Equal(t, 2, len(driftResult.Drift))
	drifts, err := db.ListEnforcementDriftEvents(10)
	require.NoError(t, err)
	assert.Len(t, drifts, 2)

	rollbackResult, err := RollbackAtomicEnforcement(context.Background(), cfg, AtomicEnforcementRequest{}, "ops")
	require.NoError(t, err)
	assert.Equal(t, "rolled_back", rollbackResult.Status)
	assert.Equal(t, []string{
		"qos-apply",
		"firewall-apply",
		"firewall-rollback:fw-prev",
		"qos-rollback:qos-prev",
	}, calls)
}

func prepareAtomicEnforcementTestDB(t *testing.T) {
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

func atomicEnforcementTestConfig() *config.Config {
	return &config.Config{
		Mode: "two-nic",
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: true,
			EnforcementTransactions: config.EnforcementTransactionPolicyConfig{
				Enabled:                    true,
				FailClosed:                 true,
				Targets:                    []string{"runtime_qos", "runtime_firewall"},
				RequirePreviewBeforeApply:  true,
				AutoRollbackOnFailure:      true,
				DriftCheckAfterApply:       false,
				HistoryRetentionLimit:      5000,
				CompensationRetentionLimit: 1000,
			},
		},
	}
}

func restoreAtomicEnforcementParticipants(t *testing.T) {
	t.Helper()
	originalRuntimeFirewallApply := atomicRuntimeFirewallApplyFn
	originalRuntimeFirewallRollback := atomicRuntimeFirewallRollbackFn
	originalRuntimeQoSApply := atomicRuntimeQoSApplyFn
	originalRuntimeQoSRollback := atomicRuntimeQoSRollbackFn
	originalVLANApply := atomicVLANLifecycleApplyFn
	originalVLANRollback := atomicVLANLifecycleRollbackFn
	originalSubscriberRouteExportApply := atomicSubscriberRouteExportApplyFn
	originalSubscriberRouteExportRollback := atomicSubscriberRouteExportRollbackFn
	originalControllerApply := atomicControllerApplyFn
	t.Cleanup(func() {
		atomicRuntimeFirewallApplyFn = originalRuntimeFirewallApply
		atomicRuntimeFirewallRollbackFn = originalRuntimeFirewallRollback
		atomicRuntimeQoSApplyFn = originalRuntimeQoSApply
		atomicRuntimeQoSRollbackFn = originalRuntimeQoSRollback
		atomicVLANLifecycleApplyFn = originalVLANApply
		atomicVLANLifecycleRollbackFn = originalVLANRollback
		atomicSubscriberRouteExportApplyFn = originalSubscriberRouteExportApply
		atomicSubscriberRouteExportRollbackFn = originalSubscriberRouteExportRollback
		atomicControllerApplyFn = originalControllerApply
	})
}
