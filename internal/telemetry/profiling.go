package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"go.uber.org/zap"
)

func StartProfilingRuntime(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if ctx == nil || cfg == nil {
		return
	}
	interval := time.Duration(max(cfg.Profiling.PollIntervalSeconds, 30)) * time.Second
	service := onboarding.New(cfg, logger)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	run := func() {
		if !cfg.Profiling.PassiveEnabled && !cfg.Profiling.PostureEnabled && !cfg.Profiling.MDMSyncEnabled {
			_ = db.UpsertRuntimeStatus("device_inventory", "disabled", "Profiling runtime is disabled in config.", nil)
			return
		}
		_ = db.UpsertRuntimeStatus("device_inventory", "ok", "Device inventory runtime is active.", map[string]any{
			"passive_enabled": cfg.Profiling.PassiveEnabled,
			"posture_enabled": cfg.Profiling.PostureEnabled,
		})
		if cfg.Profiling.MDMSyncEnabled {
			if err := service.SyncFromMDM(ctx); err != nil {
				_ = db.UpsertRuntimeStatus("mdm_sync", "degraded", fmt.Sprintf("MDM sync failed: %v", err), nil)
				logger.Warn("mdm sync failed", zap.Error(err))
			} else {
				_ = db.UpsertRuntimeStatus("mdm_sync", "ok", "MDM sync completed successfully.", map[string]any{"provider": cfg.Profiling.MDMProvider})
			}
		}
		if cfg.Profiling.PostureEnabled && cfg.Profiling.ComplianceWebhook != "" {
			if err := service.SyncFromComplianceWebhook(ctx); err != nil {
				_ = db.UpsertRuntimeStatus("posture_checks", "degraded", fmt.Sprintf("Compliance webhook failed: %v", err), nil)
				logger.Warn("compliance webhook failed", zap.Error(err))
			} else {
				_ = db.UpsertRuntimeStatus("posture_checks", "ok", "Compliance webhook evaluation completed.", nil)
			}
		} else if cfg.Profiling.PostureEnabled {
			_ = db.UpsertRuntimeStatus("posture_checks", "ok", "Posture checks are active with MDM-backed compliance.", nil)
		}
	}

	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
