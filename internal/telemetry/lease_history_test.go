package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"go.uber.org/zap"
)

func TestLeaseHistoryPollIntervalDefaultsAndOverrides(t *testing.T) {
	assert.Equal(t, 5*time.Minute, LeaseHistoryPollInterval(nil))

	cfg := &config.Config{}
	assert.Equal(t, 5*time.Minute, LeaseHistoryPollInterval(cfg))

	cfg.Telemetry.LeaseHistoryPollSeconds = 45
	assert.Equal(t, 45*time.Second, LeaseHistoryPollInterval(cfg))
}

func TestStartDHCPLeaseHistoryCollectorStoresObservations(t *testing.T) {
	originalParse := parseLeasesFileFn
	originalStore := storeLeaseHistoryFn
	originalNow := nowFn
	defer func() {
		parseLeasesFileFn = originalParse
		storeLeaseHistoryFn = originalStore
		nowFn = originalNow
	}()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	cfg.Telemetry.LeaseHistoryPollSeconds = 1
	cfg.DHCP.Enabled = true
	cfg.DHCP.StaticLeases = []config.DHCPStaticLeaseConfig{{MAC: "aa-bb-cc-dd-ee-ff", IP: "192.168.50.10", Enabled: true}}

	nowFn = func() time.Time {
		return time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	}

	parseCalls := 0
	parseLeasesFileFn = func(path string, now time.Time, reservations map[string]struct{}) ([]dnsmasq.Lease, error) {
		parseCalls++
		if parseCalls > 1 {
			return []dnsmasq.Lease{}, nil
		}
		require.Contains(t, reservations, "mac:aa:bb:cc:dd:ee:ff")
		return []dnsmasq.Lease{
			{
				MAC:              "aa:bb:cc:dd:ee:ff",
				IP:               "192.168.50.10",
				Hostname:         "lab-client",
				Reservation:      true,
				ExpiresAt:        "2026-05-05T13:00:00Z",
				RemainingSeconds: 3600,
			},
		}, nil
	}

	stored := []db.DHCPLeaseObservation{}
	storeLeaseHistoryFn = func(observedAt time.Time, leases []db.DHCPLeaseObservation) error {
		stored = append(stored, leases...)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartDHCPLeaseHistoryCollector(ctx, cfg, zap.NewNop())
		close(done)
	}()

	require.Eventually(t, func() bool { return len(stored) == 1 }, 2*time.Second, 25*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not stop after context cancellation")
	}

	require.Len(t, stored, 1)
	assert.Equal(t, "lab-client", stored[0].Hostname)
	assert.True(t, stored[0].Reservation)
}
