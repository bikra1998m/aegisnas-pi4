package ha

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"go.uber.org/zap"
)

type probeClient struct {
	do func(*http.Request) (*http.Response, error)
}

func (p probeClient) Do(req *http.Request) (*http.Response, error) {
	return p.do(req)
}

func TestStandbyWaitsBeforeTakingVIP(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	now := time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC)
	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()
	assert.False(t, ctrl.vipAssigned)
	assert.NotContains(t, strings.Join(ipCalls, "\n"), "addr replace")

	now = now.Add(10 * time.Second)
	ctrl.tick()
	assert.False(t, ctrl.vipAssigned)
	assert.NotContains(t, strings.Join(ipCalls, "\n"), "addr replace")

	now = now.Add(11 * time.Second)
	ctrl.tick()
	assert.True(t, ctrl.vipAssigned)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")

	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Equal(t, "standby-1", lease.HolderNode)
	assert.Equal(t, 50, lease.Priority)
}

func TestActivePreemptsLowerPriorityLeaseWhenEnabled(t *testing.T) {
	cfg := haTestConfig(t, "active")
	cfg.HighAvailability.Preempt = true
	now := time.Date(2026, 5, 6, 11, 0, 0, 0, time.UTC)
	require.NoError(t, saveLease(cfg, vipLease{
		HolderNode: "standby-1",
		HolderRole: "standby",
		VirtualIP:  cfg.HighAvailability.VirtualIP,
		Interface:  "ens37",
		Priority:   50,
		AcquiredAt: now.Add(-30 * time.Second).Format(time.RFC3339),
		RenewedAt:  now.Add(-5 * time.Second).Format(time.RFC3339),
		ExpiresAt:  now.Add(30 * time.Second).Format(time.RFC3339),
	}))

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody}, nil
	}}, zap.NewNop())
	ctrl.nodeName = "active-1"
	ctrl.now = func() time.Time { return now }
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()
	assert.True(t, ctrl.vipAssigned)
	require.Len(t, ipCalls, 1)

	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Equal(t, "active-1", lease.HolderNode)
	assert.Equal(t, 100, lease.Priority)
}

func TestActiveWaitsForPreemptHoldoffBeforeReclaimingVIP(t *testing.T) {
	cfg := haTestConfig(t, "active")
	cfg.HighAvailability.Preempt = true
	cfg.HighAvailability.PreemptHoldoffSeconds = 30
	now := time.Date(2026, 5, 6, 11, 30, 0, 0, time.UTC)
	require.NoError(t, saveLease(cfg, vipLease{
		HolderNode: "standby-1",
		HolderRole: "standby",
		VirtualIP:  cfg.HighAvailability.VirtualIP,
		Interface:  "ens37",
		Priority:   50,
		AcquiredAt: now.Add(-45 * time.Second).Format(time.RFC3339),
		RenewedAt:  now.Add(-5 * time.Second).Format(time.RFC3339),
		ExpiresAt:  now.Add(30 * time.Second).Format(time.RFC3339),
	}))

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody}, nil
	}}, zap.NewNop())
	ctrl.nodeName = "active-1"
	ctrl.now = func() time.Time { return now }
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()
	assert.False(t, ctrl.vipAssigned)
	assert.Contains(t, ipCalls, "addr del 192.168.50.2/24 dev ens37")
	assert.NotContains(t, strings.Join(ipCalls, "\n"), "addr replace 192.168.50.2/24 dev ens37")

	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Equal(t, "standby-1", lease.HolderNode)

	now = now.Add(31 * time.Second)
	ctrl.tick()
	assert.True(t, ctrl.vipAssigned)
	assert.Contains(t, ipCalls, "addr replace 192.168.50.2/24 dev ens37")

	lease, err = loadLease(cfg)
	require.NoError(t, err)
	assert.Equal(t, "active-1", lease.HolderNode)
	assert.Equal(t, 100, lease.Priority)
}

func TestActiveWaitsWhenPreemptDisabled(t *testing.T) {
	cfg := haTestConfig(t, "active")
	cfg.HighAvailability.Preempt = false
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	require.NoError(t, saveLease(cfg, vipLease{
		HolderNode: "standby-1",
		HolderRole: "standby",
		VirtualIP:  cfg.HighAvailability.VirtualIP,
		Interface:  "ens37",
		Priority:   50,
		AcquiredAt: now.Add(-30 * time.Second).Format(time.RFC3339),
		RenewedAt:  now.Add(-5 * time.Second).Format(time.RFC3339),
		ExpiresAt:  now.Add(30 * time.Second).Format(time.RFC3339),
	}))

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody}, nil
	}}, zap.NewNop())
	ctrl.nodeName = "active-1"
	ctrl.now = func() time.Time { return now }
	ctrl.ipRunner = func(args ...string) (string, error) {
		if strings.HasPrefix(strings.Join(args, " "), "addr del") {
			return "Cannot assign requested address", errors.New("exit status 2")
		}
		t.Fatalf("unexpected ip call: %v", args)
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()
	assert.False(t, ctrl.vipAssigned)

	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Equal(t, "standby-1", lease.HolderNode)
}

func TestStandbySchedulesActivationBeforeVIPTakeover(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.AutoActivateOnFailover = true
	now := time.Date(2026, 5, 6, 13, 0, 0, 0, time.UTC)

	originalLoadShared := controllerLoadSharedReplicationStatusFn
	originalFindStage := controllerFindStagedReplicationPackageByFingerprintFn
	originalActivate := controllerActivateStagedReplicationPackageFn
	originalSchedule := controllerScheduleActivationRestartFn
	defer func() {
		controllerLoadSharedReplicationStatusFn = originalLoadShared
		controllerFindStagedReplicationPackageByFingerprintFn = originalFindStage
		controllerActivateStagedReplicationPackageFn = originalActivate
		controllerScheduleActivationRestartFn = originalSchedule
	}()

	controllerLoadSharedReplicationStatusFn = func(cfg *config.Config) (SharedReplicationStatus, error) {
		return SharedReplicationStatus{
			Present:            true,
			SourceNode:         "active-1",
			SourceRole:         "active",
			PublishedAt:        now.Add(-30 * time.Second).Format(time.RFC3339),
			SchemaVersion:      8,
			PackageChecksum:    "archive-checksum",
			ContentFingerprint: "content-fingerprint",
		}, nil
	}
	controllerFindStagedReplicationPackageByFingerprintFn = func(cfg *config.Config, fingerprint string) (StagedReplicationPackage, bool, error) {
		return StagedReplicationPackage{
			ID:                 "stage-001",
			Ready:              true,
			ContentFingerprint: fingerprint,
			ImportedSource:     "shared-auto",
		}, true, nil
	}
	activated := []string{}
	controllerActivateStagedReplicationPackageFn = func(cfg *config.Config, id, activatedBy string) (ActivationResult, error) {
		activated = append(activated, id)
		return ActivationResult{
			ID:              id,
			RestartServices: []string{"aegis-gateway", "aegis-admin-api"},
			BackupPath:      "/var/lib/aegisnas/ha/replication/backups/rollback.tar.gz",
		}, nil
	}
	scheduled := []string{}
	controllerScheduleActivationRestartFn = func(cfg *config.Config, result ActivationResult, actor string) error {
		scheduled = append([]string(nil), result.RestartServices...)
		return nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		t.Fatalf("VIP should not be assigned before activation restart handoff, got %v", args)
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, []string{"stage-001"}, activated)
	assert.Equal(t, []string{"aegis-gateway", "aegis-admin-api"}, scheduled)
}

func TestStandbyUsesActivatedStageBeforeVIPTakeover(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.AutoActivateOnFailover = true
	now := time.Date(2026, 5, 6, 14, 0, 0, 0, time.UTC)

	originalLoadShared := controllerLoadSharedReplicationStatusFn
	originalFindStage := controllerFindStagedReplicationPackageByFingerprintFn
	originalActivate := controllerActivateStagedReplicationPackageFn
	defer func() {
		controllerLoadSharedReplicationStatusFn = originalLoadShared
		controllerFindStagedReplicationPackageByFingerprintFn = originalFindStage
		controllerActivateStagedReplicationPackageFn = originalActivate
	}()

	controllerLoadSharedReplicationStatusFn = func(cfg *config.Config) (SharedReplicationStatus, error) {
		return SharedReplicationStatus{
			Present:            true,
			SourceNode:         "active-1",
			SourceRole:         "active",
			PublishedAt:        now.Add(-30 * time.Second).Format(time.RFC3339),
			SchemaVersion:      8,
			PackageChecksum:    "archive-checksum",
			ContentFingerprint: "content-fingerprint",
		}, nil
	}
	controllerFindStagedReplicationPackageByFingerprintFn = func(cfg *config.Config, fingerprint string) (StagedReplicationPackage, bool, error) {
		return StagedReplicationPackage{
			ID:                 "stage-002",
			Ready:              true,
			ActivatedAt:        now.Add(-10 * time.Second).Format(time.RFC3339),
			ContentFingerprint: fingerprint,
			ImportedSource:     "shared-auto",
		}, true, nil
	}
	controllerActivateStagedReplicationPackageFn = func(cfg *config.Config, id, activatedBy string) (ActivationResult, error) {
		t.Fatalf("already activated stage should not be activated again")
		return ActivationResult{}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyDoesNotPromoteWhenPeerSharedHeartbeatIsFresh(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	now := time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-5 * time.Second).Format(time.RFC3339),
	}))

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.NotContains(t, strings.Join(ipCalls, "\n"), "addr replace")
	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Empty(t, lease.HolderNode)
}

func TestStandbyPromotesWhenPeerSharedHeartbeatIsStale(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	now := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessBlocksPromotionWhenHeartbeatIsStale(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	now := time.Date(2026, 5, 7, 10, 30, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		return witnessDecision{
			AllowPromotion: false,
			Summary:        "Witness still sees the active node.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-1",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.NotContains(t, strings.Join(ipCalls, "\n"), "addr replace")
	lease, err := loadLease(cfg)
	require.NoError(t, err)
	assert.Empty(t, lease.HolderNode)
}

func TestStandbyWitnessAllowsPromotionWhenHeartbeatIsStale(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	now := time.Date(2026, 5, 7, 11, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness confirms standby promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-1",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessBlocksPromotionWhenResponseIsStale(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	cfg.HighAvailability.WitnessMaxAgeSeconds = 30
	now := time.Date(2026, 5, 7, 11, 15, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness confirms standby promotion is safe.",
			ObservedAt:     now.Add(-45 * time.Second).Format(time.RFC3339),
			WitnessNode:    "witness-1",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessBlocksPromotionWhenTierFreshnessIsExceeded(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessMaxAgeSeconds = 60
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinApprovalsByTier = map[string]int{
		"critical": 1,
		"advisory": 1,
	}
	cfg.HighAvailability.WitnessMaxAgeByTier = map[string]int{
		"critical": 10,
		"advisory": 30,
	}
	now := time.Date(2026, 5, 7, 11, 20, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Add(-20 * time.Second).Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Add(-5 * time.Second).Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessTierFreshnessOverrideAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = "https://witness-a.example.test/ha"
	cfg.HighAvailability.WitnessQuorum = 1
	cfg.HighAvailability.WitnessMaxAgeSeconds = 10
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMaxAgeByTier = map[string]int{
		"advisory": 30,
	}
	now := time.Date(2026, 5, 7, 11, 22, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Add(-20 * time.Second).Format(time.RFC3339),
			WitnessNode:    "witness-a",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierRequiredNodeBlocksPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredNodeByTier = map[string]string{
		"critical": "witness-a",
	}
	now := time.Date(2026, 5, 7, 11, 24, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "wrong-node",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessTierRequiredNodeAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredNodeByTier = map[string]string{
		"critical": "witness-a",
	}
	now := time.Date(2026, 5, 7, 11, 25, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierReplayBlocksPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessReplayRequiredTiers = []string{"critical"}
	now := time.Date(2026, 5, 7, 11, 27, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness allows promotion but omitted the replay challenge.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
				ReplayStatus:   "missing",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
			ReplayStatus:   "verified",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessTierReplayAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessReplayRequiredTiers = []string{"critical"}
	now := time.Date(2026, 5, 7, 11, 28, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion and replay verification.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
				ReplayStatus:   "verified",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
			ReplayStatus:   "verified",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierSignatureBlocksPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessSignatureRequiredTiers = []string{"critical"}
	now := time.Date(2026, 5, 7, 11, 29, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion:    true,
				Summary:           "Critical witness omitted its signature.",
				ObservedAt:        now.Format(time.RFC3339),
				WitnessNode:       "witness-a",
				SignatureStatus:   "missing",
				SignatureRequired: true,
			}, nil
		}
		return witnessDecision{
			AllowPromotion:    true,
			Summary:           "Advisory witness confirms promotion is safe.",
			ObservedAt:        now.Format(time.RFC3339),
			WitnessNode:       "witness-b",
			SignatureStatus:   "verified",
			SignatureRequired: false,
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessTierSignatureAllowsUnsignedAdvisoryWitness(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessSignatureRequiredTiers = []string{"critical"}
	now := time.Date(2026, 5, 7, 11, 30, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion:    true,
				Summary:           "Critical witness provides a valid signature.",
				ObservedAt:        now.Format(time.RFC3339),
				WitnessNode:       "witness-a",
				SignatureStatus:   "verified",
				SignatureRequired: true,
			}, nil
		}
		return witnessDecision{
			AllowPromotion:    true,
			Summary:           "Advisory witness is unsigned but acceptable.",
			ObservedAt:        now.Format(time.RFC3339),
			WitnessNode:       "witness-b",
			SignatureStatus:   "unsigned",
			SignatureRequired: false,
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessBlocksPromotionWhenNodeDoesNotMatchPolicy(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	cfg.HighAvailability.WitnessRequiredNode = "witness-1"
	now := time.Date(2026, 5, 7, 11, 30, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness confirms standby promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-2",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessQuorumAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	now := time.Date(2026, 5, 7, 11, 45, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessQuorumBlocksPromotionWhenQuorumNotMet(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: false,
			Summary:        "Witness still sees the active node.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-2",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessWeightThresholdBlocksPromotionWhenWeightIsTooLow(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 3,
		"https://witness-b.example.test/ha": 1,
		"https://witness-c.example.test/ha": 1,
	}
	cfg.HighAvailability.WitnessWeightThreshold = 4
	now := time.Date(2026, 5, 7, 12, 15, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-b.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
}

func TestStandbyWitnessDiversityBlocksPromotionWhenDistinctGroupsAreTooLow(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-a",
		"https://witness-c.example.test/ha": "dc-b",
	}
	cfg.HighAvailability.WitnessMinDistinctGroups = 2
	now := time.Date(2026, 5, 7, 12, 30, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "diversity_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessDiversityAllowsPromotionAcrossDistinctGroups(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-a",
		"https://witness-c.example.test/ha": "dc-b",
	}
	cfg.HighAvailability.WitnessMinDistinctGroups = 2
	now := time.Date(2026, 5, 7, 12, 45, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessSourcesBlockPromotionWhenRequiredSourceIsMissing(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessRequiredSources = []string{"local", "external"}
	now := time.Date(2026, 5, 7, 13, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-b.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "source_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessSourcesAllowPromotionWhenRequiredSourcesArePresent(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessRequiredSources = []string{"local", "external"}
	now := time.Date(2026, 5, 7, 13, 15, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierSourcesBlockPromotionWhenTierSourceIsMissing(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredSourcesByTier = map[string][]string{
		"critical": {"local"},
	}
	now := time.Date(2026, 5, 7, 13, 20, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-b.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Advisory witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Critical witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "tier_source_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierSourcesAllowPromotionWhenTierSourceIsPresent(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredSourcesByTier = map[string][]string{
		"critical": {"local"},
	}
	now := time.Date(2026, 5, 7, 13, 25, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierGroupsBlockPromotionWhenTierGroupIsMissing(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredGroupsByTier = map[string][]string{
		"critical": {"dc-a"},
	}
	now := time.Date(2026, 5, 7, 13, 27, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-b.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Advisory witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Critical witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "tier_group_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierGroupsAllowPromotionWhenTierGroupIsPresent(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessRequiredGroupsByTier = map[string][]string{
		"critical": {"dc-a"},
	}
	now := time.Date(2026, 5, 7, 13, 29, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierDistinctGroupsBlockPromotionWhenTierDiversityIsMissing(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local-a",
		"https://witness-b.example.test/ha": "local-b",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local-a":  "critical",
		"local-b":  "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinDistinctGroupsByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 13, 31, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Critical witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "tier_diversity_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierDistinctGroupsAllowPromotionWhenTierDiversityIsMet(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local-a",
		"https://witness-b.example.test/ha": "local-b",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local-a":  "critical",
		"local-b":  "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinDistinctGroupsByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 13, 33, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierDistinctSourcesBlockPromotionWhenTierSourceDiversityIsMissing(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local-a",
		"https://witness-b.example.test/ha": "local-b",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local-a":  "critical",
		"local-b":  "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinDistinctSourcesByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 13, 35, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-c.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Critical witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	fencing := ctrl.evaluateFencing(now, false, true, map[string]any{})
	assert.Equal(t, "tier_source_diversity_unmet", fencing.WitnessStatus)
	assert.False(t, fencing.AllowPromotion)

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierDistinctSourcesAllowPromotionWhenTierSourceDiversityIsMet(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local-a",
		"https://witness-b.example.test/ha": "local-b",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local-a":  "critical",
		"local-b":  "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinDistinctSourcesByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 13, 37, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessPolicyAnyAllowsPromotionWhenSourceRulePasses(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessPolicyMode = "any"
	cfg.HighAvailability.WitnessMinDistinctGroups = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-a",
		"https://witness-c.example.test/ha": "dc-b",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessRequiredSources = []string{"local", "external"}
	now := time.Date(2026, 5, 7, 13, 30, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessPolicySourceOnlyBlocksPromotionWhenOnlyGroupRulePasses(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
		"https://witness-c.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessPolicyMode = "source_only"
	cfg.HighAvailability.WitnessMinDistinctGroups = 2
	cfg.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
		"https://witness-c.example.test/ha": "dc-c",
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "local",
		"https://witness-c.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessRequiredSources = []string{"local", "external"}
	now := time.Date(2026, 5, 7, 13, 45, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		switch witnessURL {
		case "https://witness-a.example.test/ha", "https://witness-b.example.test/ha":
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		default:
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Witness still sees the active node.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-2",
			}, nil
		}
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessBlockingTierDeniesPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 1
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessBlockingTiers = []string{"critical"}
	now := time.Date(2026, 5, 7, 13, 45, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Local critical witness still sees an active owner.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "External advisory witness allows promotion.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierMinimumBlocksPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 1
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinApprovalsByTier = map[string]int{
		"critical": 1,
	}
	now := time.Date(2026, 5, 7, 13, 52, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: false,
				Summary:        "Critical witness did not approve promotion.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness allows promotion.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessFailureToleranceAllowsPromotionWithOneProbeFailure(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessFailureTolerance = 1
	now := time.Date(2026, 5, 7, 14, 0, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		}
		return witnessDecision{}, errors.New("witness unavailable")
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierMinimumAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinApprovalsByTier = map[string]int{
		"critical": 1,
		"advisory": 1,
	}
	now := time.Date(2026, 5, 7, 14, 10, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierWeightBlocksPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 1,
		"https://witness-b.example.test/ha": 1,
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinWeightByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 14, 12, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) { return "", nil }
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.False(t, ctrl.vipAssigned)
	assert.Equal(t, "witness_blocked", ctrl.lastFencingStatus)
}

func TestStandbyWitnessTierWeightAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 2,
		"https://witness-b.example.test/ha": 1,
	}
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessMinWeightByTier = map[string]int{
		"critical": 2,
	}
	now := time.Date(2026, 5, 7, 14, 13, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{
			AllowPromotion: true,
			Summary:        "Advisory witness confirms promotion is safe.",
			ObservedAt:     now.Format(time.RFC3339),
			WitnessNode:    "witness-b",
		}, nil
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessTierFailureToleranceAllowsPromotion(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 2
	cfg.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	cfg.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	cfg.HighAvailability.WitnessFailureToleranceByTier = map[string]int{
		"advisory": 1,
	}
	now := time.Date(2026, 5, 7, 14, 7, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Critical witness confirms promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-a",
			}, nil
		}
		return witnessDecision{}, errors.New("advisory witness unavailable")
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestStandbyWitnessFailureWeightToleranceAllowsPromotionWhenThresholdRelaxes(t *testing.T) {
	cfg := haTestConfig(t, "standby")
	cfg.HighAvailability.SplitBrainProtectionEnabled = true
	cfg.HighAvailability.WitnessAPIURL = ""
	cfg.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	cfg.HighAvailability.WitnessQuorum = 1
	cfg.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 2,
		"https://witness-b.example.test/ha": 1,
	}
	cfg.HighAvailability.WitnessWeightThreshold = 3
	cfg.HighAvailability.WitnessFailureWeightTolerance = 1
	now := time.Date(2026, 5, 7, 14, 15, 0, 0, time.UTC)

	peerCfg := *cfg
	peerCfg.HighAvailability.Role = "active"
	require.NoError(t, saveSharedHeartbeat(&peerCfg, sharedHeartbeat{
		NodeName:       "active-1",
		ConfiguredRole: "active",
		EffectiveRole:  "active",
		VirtualIP:      cfg.HighAvailability.VirtualIP,
		VIPAssigned:    true,
		PublishedAt:    now.Add(-31 * time.Second).Format(time.RFC3339),
	}))

	originalWitness := controllerProbeWitnessDecisionFn
	defer func() { controllerProbeWitnessDecisionFn = originalWitness }()
	controllerProbeWitnessDecisionFn = func(cfg *config.Config, client httpDoer, witnessURL string) (witnessDecision, error) {
		if witnessURL == "https://witness-a.example.test/ha" {
			return witnessDecision{
				AllowPromotion: true,
				Summary:        "Witness confirms standby promotion is safe.",
				ObservedAt:     now.Format(time.RFC3339),
				WitnessNode:    "witness-1",
			}, nil
		}
		return witnessDecision{}, errors.New("witness unavailable")
	}

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("peer down")
	}}, zap.NewNop())
	ctrl.nodeName = "standby-1"
	ctrl.now = func() time.Time { return now }
	ctrl.failureSince = now.Add(-30 * time.Second)
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) { return "", nil }

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
}

func TestVIPAnnouncementUsesReplyAndRequestModes(t *testing.T) {
	cfg := haTestConfig(t, "active")
	now := time.Date(2026, 5, 8, 9, 0, 0, 0, time.UTC)

	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody}, nil
	}}, zap.NewNop())
	ctrl.nodeName = "active-1"
	ctrl.now = func() time.Time { return now }

	var calls []string
	ctrl.arpingRunner = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		return "", nil
	}

	details := map[string]any{}
	err := ctrl.refreshVIPAnnouncement(vipTarget{Interface: "ens37", Address: "192.168.50.2/24"}, details)
	require.NoError(t, err)
	require.Len(t, calls, 2)
	assert.Contains(t, calls[0], "-A")
	assert.Contains(t, calls[1], "-U")
	assert.Equal(t, "sent", ctrl.lastAnnouncementMode)
	assert.Equal(t, "sent", details["vip_announcement_status"])
}

func TestVIPAnnouncementFailureDoesNotBlockAssignment(t *testing.T) {
	cfg := haTestConfig(t, "active")
	now := time.Date(2026, 5, 8, 10, 0, 0, 0, time.UTC)

	var ipCalls []string
	ctrl := newController(cfg, probeClient{do: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody}, nil
	}}, zap.NewNop())
	ctrl.nodeName = "active-1"
	ctrl.now = func() time.Time { return now }
	ctrl.ipRunner = func(args ...string) (string, error) {
		ipCalls = append(ipCalls, strings.Join(args, " "))
		return "", nil
	}
	ctrl.arpingRunner = func(args ...string) (string, error) {
		return "arping missing", errors.New("exit status 127")
	}

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Equal(t, "failed", ctrl.lastAnnouncementMode)
	assert.Contains(t, ctrl.lastAnnouncementErr, "arping missing")
}

func haTestConfig(t *testing.T, role string) *config.Config {
	t.Helper()
	root := t.TempDir()
	return &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "ens33", DHCP: true},
		LAN:  config.InterfaceConfig{Name: "ens37", DHCP: false, Address: "192.168.50.1/24"},
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                  true,
			Role:                     role,
			PeerAPIURL:               "https://peer.example.test:8083",
			VirtualIP:                "192.168.50.2",
			HeartbeatIntervalSeconds: 5,
			FailoverTimeoutSeconds:   20,
			SharedStateDir:           filepath.Join(root, "ha"),
		},
	}
}
