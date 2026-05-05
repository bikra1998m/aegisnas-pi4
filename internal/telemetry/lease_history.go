package telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"go.uber.org/zap"
)

const (
	defaultLeaseHistoryPollInterval = 5 * time.Minute
	dnsmasqLeasePath                = "/var/lib/misc/dnsmasq.leases"
)

var (
	parseLeasesFileFn   = dnsmasq.ParseLeasesFile
	storeLeaseHistoryFn = db.StoreDHCPLeaseObservations
	nowFn               = time.Now
)

func LeaseHistoryPollInterval(cfg *config.Config) time.Duration {
	if cfg == nil {
		return defaultLeaseHistoryPollInterval
	}
	if cfg.Telemetry.LeaseHistoryPollSeconds <= 0 {
		return defaultLeaseHistoryPollInterval
	}
	return time.Duration(cfg.Telemetry.LeaseHistoryPollSeconds) * time.Second
}

func StartDHCPLeaseHistoryCollector(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if cfg == nil || !cfg.Telemetry.Enabled || !cfg.DHCP.Enabled {
		return
	}
	interval := LeaseHistoryPollInterval(cfg)
	runLeaseHistoryCollection(cfg, logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runLeaseHistoryCollection(cfg, logger)
		}
	}
}

func runLeaseHistoryCollection(cfg *config.Config, logger *zap.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	currentTime := nowFn()
	leases, err := parseLeasesFileFn(dnsmasqLeasePath, currentTime, leaseReservations(cfg))
	if err != nil {
		logger.Warn("failed to collect dhcp lease history", zap.Error(err))
		return
	}
	if len(leases) == 0 {
		logger.Debug("dhcp lease history collector found no leases")
		return
	}
	if err := storeLeaseHistoryFn(currentTime.UTC(), leaseObservationsFromCurrent(leases)); err != nil {
		logger.Warn("failed to store dhcp lease history", zap.Error(err))
		return
	}
	logger.Debug("dhcp lease history collector stored lease observations", zap.Int("count", len(leases)))
}

func leaseReservations(cfg *config.Config) map[string]struct{} {
	values := make(map[string]struct{}, len(cfg.DHCP.StaticLeases)*2)
	for _, lease := range cfg.DHCP.StaticLeases {
		if !lease.Enabled {
			continue
		}
		values[fmt.Sprintf("mac:%s", normalizeReservationMAC(lease.MAC))] = struct{}{}
		values[fmt.Sprintf("ip:%s", strings.TrimSpace(lease.IP))] = struct{}{}
	}
	return values
}

func leaseObservationsFromCurrent(leases []dnsmasq.Lease) []db.DHCPLeaseObservation {
	out := make([]db.DHCPLeaseObservation, 0, len(leases))
	for _, lease := range leases {
		out = append(out, db.DHCPLeaseObservation{
			MAC:              lease.MAC,
			IP:               lease.IP,
			Hostname:         lease.Hostname,
			ClientID:         lease.ClientID,
			Reservation:      lease.Reservation,
			Expired:          lease.Expired,
			ExpiresAt:        lease.ExpiresAt,
			RemainingSeconds: lease.RemainingSeconds,
		})
	}
	return out
}

func normalizeReservationMAC(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
}
