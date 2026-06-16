package telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"go.uber.org/zap"
)

const (
	defaultLeaseHistoryPollInterval = 5 * time.Minute
	dnsmasqLeasePath                = "/var/lib/misc/dnsmasq.leases"
)

var (
	parseLeasesFileFn   = dnsmasq.ParseLeasesFile
	storeLeaseHistoryFn = db.StoreDHCPLeaseObservations
	profileLeasesFn     = profileLeaseObservations
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
	observations := leaseObservationsFromCurrent(leases)
	if err := storeLeaseHistoryFn(currentTime.UTC(), observations); err != nil {
		logger.Warn("failed to store dhcp lease history", zap.Error(err))
		return
	}
	if stats, err := profileLeasesFn(cfg, observations); err != nil {
		logger.Warn("failed to update passive device profiles from dhcp leases", zap.Error(err))
		_ = db.UpsertRuntimeStatus("device_inventory", "degraded", "Passive DHCP profiling failed.", map[string]any{
			"source": "dhcp-lease",
			"error":  err.Error(),
		})
	} else if stats != nil && stats.TotalRecords > 0 {
		status := "ok"
		message := fmt.Sprintf("Passive DHCP profiling updated %d device record(s).", stats.TotalRecords)
		if stats.HighRiskRecords > 0 {
			status = "degraded"
			message = fmt.Sprintf("Passive DHCP profiling found %d high-risk device record(s).", stats.HighRiskRecords)
		}
		_ = db.UpsertRuntimeStatus("device_inventory", status, message, map[string]any{
			"source":                    stats.Source,
			"total_records":             stats.TotalRecords,
			"active_records":            stats.ActiveRecords,
			"expired_records":           stats.ExpiredRecords,
			"reservation_records":       stats.ReservationRecords,
			"hostname_records":          stats.HostnameRecords,
			"client_id_records":         stats.ClientIDRecords,
			"locally_administered_macs": stats.LocallyAdministeredMACs,
			"high_risk_records":         stats.HighRiskRecords,
			"auto_quarantined_sessions": stats.AutoQuarantinedSessions,
		})
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

func profileLeaseObservations(cfg *config.Config, observations []db.DHCPLeaseObservation) (*onboarding.LeaseProfileStats, error) {
	if cfg == nil || len(observations) == 0 {
		return nil, nil
	}
	if !cfg.Onboarding.DeviceInventoryEnabled && !cfg.Profiling.MACInventoryEnabled && !cfg.Profiling.PassiveEnabled {
		return nil, nil
	}
	profiles := make([]onboarding.DHCPLeaseProfile, 0, len(observations))
	for _, observation := range observations {
		profiles = append(profiles, onboarding.DHCPLeaseProfile{
			MAC:              observation.MAC,
			IP:               observation.IP,
			Hostname:         observation.Hostname,
			ClientID:         observation.ClientID,
			Reservation:      observation.Reservation,
			Expired:          observation.Expired,
			ExpiresAt:        observation.ExpiresAt,
			RemainingSeconds: observation.RemainingSeconds,
		})
	}
	return onboarding.New(cfg, nil).ObserveDHCPLeaseProfiles(profiles)
}

func normalizeReservationMAC(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
}
