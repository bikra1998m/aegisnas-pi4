package telemetry

import (
	"context"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
)

// StartUpstreamAAACollector records transport health independently of admin UI
// refreshes so the history is useful during unattended failures.
func StartUpstreamAAACollector(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if cfg == nil || !cfg.Radius.Upstream.Enabled || len(cfg.Radius.Upstream.Servers) == 0 {
		return
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	intervalSeconds := cfg.Radius.RadSec.ProbeIntervalSeconds
	if intervalSeconds <= 0 {
		intervalSeconds = cfg.Radius.Upstream.CheckInterval
	}
	if intervalSeconds <= 0 {
		intervalSeconds = 30
	}

	collect := func() {
		statuses, err := radius.ProbeUpstreamServers(ctx, cfg)
		if err != nil {
			logger.Warn("upstream AAA collection failed", zap.Error(err))
			return
		}
		for _, status := range statuses {
			if status.Status == "down" || status.Status == "degraded" {
				logger.Warn("upstream AAA health changed",
					zap.String("server", status.Name), zap.String("transport", status.Transport),
					zap.String("status", status.Status), zap.String("message", status.Message))
			}
		}
	}

	collect()
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}
