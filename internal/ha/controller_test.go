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

	ctrl.tick()
	assert.True(t, ctrl.vipAssigned)
	require.Len(t, ipCalls, 1)

	lease, err := loadLease(cfg)
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

	ctrl.tick()

	assert.True(t, ctrl.vipAssigned)
	require.NotEmpty(t, ipCalls)
	assert.Contains(t, ipCalls[len(ipCalls)-1], "addr replace 192.168.50.2/24 dev ens37")
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
