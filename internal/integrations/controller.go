package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const controllerComponent = "controller_automation"

func ControllerComponent() string {
	return controllerComponent
}

func StartControllerAutomation(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg == nil || !cfg.Integrations.Controller.Enabled {
		_ = db.UpsertRuntimeStatus(controllerComponent, "disabled", "Controller automation is disabled in config.", nil)
		return
	}

	syncOnce := func() {
		startedAt := time.Now().UTC()
		lastStatus, _ := db.GetRuntimeStatus(controllerComponent)
		syncCount, successCount, failureCount := controllerStatusCounters(lastStatus)
		if err := pushControllerState(ctx, cfg); err != nil {
			syncCount++
			failureCount++
			logger.Warn("controller automation sync failed", zap.Error(err))
			_ = db.UpsertRuntimeStatus(controllerComponent, "degraded", err.Error(), map[string]any{
				"platform":         cfg.Integrations.Controller.Platform,
				"endpoint":         cfg.Integrations.Controller.Endpoint,
				"sync_mode":        cfg.Integrations.Controller.SyncMode,
				"site":             cfg.Integrations.Controller.Site,
				"last_sync_at":     startedAt.Format(time.RFC3339),
				"last_duration_ms": time.Since(startedAt).Milliseconds(),
				"sync_count":       syncCount,
				"success_count":    successCount,
				"failure_count":    failureCount,
				"last_error":       err.Error(),
			})
			return
		}
		syncCount++
		successCount++
		_ = db.UpsertRuntimeStatus(controllerComponent, "ok", "Controller automation sync completed.", map[string]any{
			"platform":         cfg.Integrations.Controller.Platform,
			"endpoint":         cfg.Integrations.Controller.Endpoint,
			"sync_mode":        cfg.Integrations.Controller.SyncMode,
			"site":             cfg.Integrations.Controller.Site,
			"last_sync_at":     time.Now().UTC().Format(time.RFC3339),
			"last_duration_ms": time.Since(startedAt).Milliseconds(),
			"sync_count":       syncCount,
			"success_count":    successCount,
			"failure_count":    failureCount,
			"last_error":       "",
		})
	}

	syncOnce()
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}

func pushControllerState(ctx context.Context, cfg *config.Config) error {
	token := controllerToken(cfg)
	if token == "" {
		return fmt.Errorf("controller API token env %q is empty", strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv))
	}
	payload, err := json.Marshal(buildControllerPayload(cfg))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Integrations.Controller.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AegisNAS-Controller-Platform", strings.TrimSpace(cfg.Integrations.Controller.Platform))
	req.Header.Set("X-AegisNAS-Sync-Mode", strings.TrimSpace(cfg.Integrations.Controller.SyncMode))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("controller endpoint returned %s", resp.Status)
	}
	return nil
}

func buildControllerPayload(cfg *config.Config) map[string]any {
	ssids := make([]map[string]any, 0, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		ssids = append(ssids, map[string]any{
			"name":              ssid.Name,
			"auth_mode":         ssid.AuthMode,
			"vlan":              ssid.VLAN,
			"portal_profile":    ssid.PortalProfile,
			"identity_source":   ssid.IdentitySource,
			"bandwidth_profile": ssid.BandwidthProfile,
		})
	}
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"deployment": map[string]any{
			"profile": cfg.Deployment.Profile,
			"form":    cfg.Deployment.Form,
			"mode":    cfg.Mode,
		},
		"controller": map[string]any{
			"platform":  cfg.Integrations.Controller.Platform,
			"sync_mode": cfg.Integrations.Controller.SyncMode,
			"site":      cfg.Integrations.Controller.Site,
		},
		"portal": map[string]any{
			"enabled":         cfg.Portal.Enabled,
			"listen_ip":       cfg.Portal.ListenIP,
			"port":            cfg.Portal.Port,
			"branding":        cfg.Portal.Branding,
			"guest_workflows": cfg.Portal.GuestWorkflows,
		},
		"radius": map[string]any{
			"auth_port":       cfg.Radius.AuthPort,
			"acct_port":       cfg.Radius.AcctPort,
			"dynamic_auth":    cfg.Radius.DynamicAuth,
			"request_timeout": cfg.Radius.RequestTimeoutSeconds,
		},
		"wireless_profiles": ssids,
	}
}

func controllerToken(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(os.Getenv(strings.TrimSpace(cfg.Integrations.Controller.APITokenEnv)))
}

func controllerStatusCounters(status *db.RuntimeStatus) (int64, int64, int64) {
	if status == nil || status.Details == nil {
		return 0, 0, 0
	}
	return int64ControllerDetail(status.Details, "sync_count"),
		int64ControllerDetail(status.Details, "success_count"),
		int64ControllerDetail(status.Details, "failure_count")
}

func int64ControllerDetail(details map[string]any, key string) int64 {
	if details == nil {
		return 0
	}
	switch value := details[key].(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	case json.Number:
		number, _ := value.Int64()
		return number
	default:
		return 0
	}
}
