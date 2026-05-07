package ha

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const RuntimeComponent = "high_availability"

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func StartMonitor(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	go StartController(ctx, cfg, nil, logger)
	StartContinuousReplication(ctx, cfg, logger)
}

func ProbeStatus(cfg *config.Config, client httpDoer) (string, string, map[string]any) {
	details := map[string]any{}
	if cfg == nil {
		return "disabled", "Configuration is unavailable.", details
	}

	details["role"] = strings.TrimSpace(cfg.HighAvailability.Role)
	details["peer_api_url"] = strings.TrimSpace(cfg.HighAvailability.PeerAPIURL)
	details["virtual_ip"] = strings.TrimSpace(cfg.HighAvailability.VirtualIP)
	details["preempt"] = cfg.HighAvailability.Preempt
	details["heartbeat_interval_seconds"] = cfg.HighAvailability.HeartbeatIntervalSeconds
	details["failover_timeout_seconds"] = cfg.HighAvailability.FailoverTimeoutSeconds
	details["shared_state_dir"] = strings.TrimSpace(cfg.HighAvailability.SharedStateDir)

	if !cfg.HighAvailability.Enabled {
		return "disabled", "High availability is disabled in config.", details
	}

	if !highAvailabilityConfigured(cfg) {
		return "degraded", "High availability is enabled, but peer monitoring settings are incomplete.", details
	}

	healthURL := strings.TrimRight(cfg.HighAvailability.PeerAPIURL, "/") + "/health"
	details["peer_health_url"] = healthURL

	if client == nil {
		client = &http.Client{Timeout: 1500 * time.Millisecond}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, healthURL, nil)
	if err != nil {
		details["peer_reachable"] = false
		details["last_error"] = err.Error()
		return "degraded", "Peer health URL could not be constructed.", details
	}

	resp, err := client.Do(req)
	if err != nil {
		details["peer_reachable"] = false
		details["last_error"] = err.Error()
		return "degraded", "Peer health probe failed.", details
	}
	defer resp.Body.Close()

	details["peer_status_code"] = resp.StatusCode
	details["peer_reachable"] = resp.StatusCode >= 200 && resp.StatusCode < 300

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "degraded", fmt.Sprintf("Peer health probe returned %s.", resp.Status), details
	}

	return "ok", "Peer health probe is healthy.", details
}

func publishStatus(cfg *config.Config, client httpDoer, logger *zap.Logger) {
	status, message, details := ProbeStatus(cfg, client)
	if err := db.UpsertRuntimeStatus(RuntimeComponent, status, message, details); err != nil && logger != nil {
		logger.Warn("failed to update high availability runtime status", zap.Error(err))
	}
}

func highAvailabilityConfigured(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return strings.TrimSpace(cfg.HighAvailability.Role) != "" &&
		strings.TrimSpace(cfg.HighAvailability.PeerAPIURL) != "" &&
		strings.TrimSpace(cfg.HighAvailability.VirtualIP) != "" &&
		cfg.HighAvailability.HeartbeatIntervalSeconds > 0 &&
		cfg.HighAvailability.FailoverTimeoutSeconds > 0
}
