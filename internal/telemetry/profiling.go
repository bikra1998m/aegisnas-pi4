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

type profilingRuntimeService interface {
	SyncFromMDM(ctx context.Context) (*onboarding.ComplianceSyncStats, error)
	SyncFromComplianceWebhook(ctx context.Context) (*onboarding.ComplianceSyncStats, error)
}

var newProfilingRuntimeService = func(cfg *config.Config, logger *zap.Logger) profilingRuntimeService {
	return onboarding.New(cfg, logger)
}

func StartProfilingRuntime(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if ctx == nil || cfg == nil {
		return
	}
	interval := time.Duration(max(cfg.Profiling.PollIntervalSeconds, 30)) * time.Second
	service := newProfilingRuntimeService(cfg, logger)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	runProfilingRuntimeCycle(ctx, cfg, logger, service)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runProfilingRuntimeCycle(ctx, cfg, logger, service)
		}
	}
}

func runProfilingRuntimeCycle(ctx context.Context, cfg *config.Config, logger *zap.Logger, service profilingRuntimeService) {
	if cfg == nil {
		return
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if !cfg.Profiling.PassiveEnabled && !cfg.Profiling.PostureEnabled && !cfg.Profiling.MDMSyncEnabled {
		_ = db.UpsertRuntimeStatus("device_inventory", "disabled", "Profiling runtime is disabled in config.", nil)
		return
	}
	_ = db.UpsertRuntimeStatus("device_inventory", "ok", "Device inventory runtime is active.", map[string]any{
		"passive_enabled": cfg.Profiling.PassiveEnabled,
		"posture_enabled": cfg.Profiling.PostureEnabled,
	})
	if cfg.Profiling.MDMSyncEnabled {
		if stats, err := service.SyncFromMDM(ctx); err != nil {
			_ = db.RecordIntegrationHistory("mdm_sync", "degraded", fmt.Sprintf("MDM sync failed: %v", err), map[string]any{
				"provider": cfg.Profiling.MDMProvider,
				"source":   "mdm",
				"error":    err.Error(),
			})
			_ = db.UpsertRuntimeStatus("mdm_sync", "degraded", fmt.Sprintf("MDM sync failed: %v", err), nil)
			logger.Warn("mdm sync failed", zap.Error(err))
		} else {
			mdmDetails := map[string]any{
				"provider":              stats.Provider,
				"source":                stats.Source,
				"total_records":         stats.TotalRecords,
				"managed_records":       stats.ManagedRecords,
				"compliant_records":     stats.CompliantRecords,
				"non_compliant_records": stats.NonCompliantRecords,
				"unknown_records":       stats.UnknownRecords,
				"remediation_records":   stats.RemediationRecords,
			}
			_ = db.RecordIntegrationHistory("mdm_sync", "ok", "MDM sync completed successfully.", mdmDetails)
			_ = db.UpsertRuntimeStatus("mdm_sync", "ok", "MDM sync completed successfully.", mdmDetails)
		}
	}
	if cfg.Profiling.PostureEnabled && cfg.Profiling.ComplianceWebhook != "" {
		if stats, err := service.SyncFromComplianceWebhook(ctx); err != nil {
			_ = db.RecordIntegrationHistory("posture_checks", "degraded", fmt.Sprintf("Compliance webhook failed: %v", err), map[string]any{
				"provider": cfg.Profiling.MDMProvider,
				"source":   "compliance-webhook",
				"error":    err.Error(),
			})
			_ = db.UpsertRuntimeStatus("posture_checks", "degraded", fmt.Sprintf("Compliance webhook failed: %v", err), nil)
			logger.Warn("compliance webhook failed", zap.Error(err))
		} else {
			postureDetails := map[string]any{
				"provider":              stats.Provider,
				"source":                stats.Source,
				"total_records":         stats.TotalRecords,
				"managed_records":       stats.ManagedRecords,
				"compliant_records":     stats.CompliantRecords,
				"non_compliant_records": stats.NonCompliantRecords,
				"unknown_records":       stats.UnknownRecords,
				"remediation_records":   stats.RemediationRecords,
			}
			_ = db.RecordIntegrationHistory("posture_checks", "ok", "Compliance webhook evaluation completed.", postureDetails)
			_ = db.UpsertRuntimeStatus("posture_checks", "ok", "Compliance webhook evaluation completed.", postureDetails)
		}
	} else if cfg.Profiling.PostureEnabled {
		postureDetails := map[string]any{
			"provider": cfg.Profiling.MDMProvider,
			"source":   "mdm-sync",
		}
		_ = db.RecordIntegrationHistory("posture_checks", "ok", "Posture checks are active with MDM-backed compliance.", postureDetails)
		_ = db.UpsertRuntimeStatus("posture_checks", "ok", "Posture checks are active with MDM-backed compliance.", postureDetails)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
