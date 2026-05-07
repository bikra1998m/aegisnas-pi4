package ha

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

var (
	restartClockFn   = time.Now
	restartCommandFn = runRestartHandoffCommand
)

func ScheduleServiceRestart(services []string) error {
	items := normalizeRestartServices(services)
	if len(items) == 0 {
		return nil
	}
	return restartCommandFn(items)
}

func ScheduleActivationRestart(cfg *config.Config, result ActivationResult, actor string) error {
	summary := "Service restart handoff queued for the activated standby package."
	if err := ScheduleServiceRestart(result.RestartServices); err != nil {
		summary = "Standby replication data was activated, but automatic restart handoff failed. Restart appliance services manually."
		_ = db.RecordHAHistory("replication_restart", "failed", summary, standbyRole(cfg), strings.TrimSpace(actor), map[string]any{
			"stage_id":         result.ID,
			"restart_services": result.RestartServices,
			"error":            err.Error(),
		})
		_ = db.UpsertRuntimeStatus(ReplicationRuntimeComponent, "degraded", summary, map[string]any{
			"staged_id":           result.ID,
			"restart_services":    result.RestartServices,
			"restart_scheduled":   false,
			"restart_warning":     err.Error(),
			"restart_backup_path": result.BackupPath,
		})
		return err
	}

	_ = db.RecordHAHistory("replication_restart", "scheduled", summary, standbyRole(cfg), strings.TrimSpace(actor), map[string]any{
		"stage_id":         result.ID,
		"restart_services": result.RestartServices,
	})
	_ = db.UpsertRuntimeStatus(ReplicationRuntimeComponent, "pending", summary, map[string]any{
		"staged_id":           result.ID,
		"restart_services":    result.RestartServices,
		"restart_scheduled":   true,
		"restart_backup_path": result.BackupPath,
	})
	return nil
}

func buildRestartHandoffScript(services []string) string {
	args := make([]string, 0, len(services)+2)
	args = append(args, "systemctl", "restart")
	args = append(args, services...)
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return "sleep 2; exec " + strings.Join(quoted, " ")
}

func normalizeRestartServices(services []string) []string {
	items := make([]string, 0, len(services))
	for _, service := range services {
		service = strings.TrimSpace(service)
		if service == "" || slices.Contains(items, service) {
			continue
		}
		items = append(items, service)
	}
	return items
}

func runRestartHandoffCommand(services []string) error {
	unitName := fmt.Sprintf("aegis-ha-activate-%d", restartClockFn().UTC().UnixNano())
	script := buildRestartHandoffScript(services)
	cmd := exec.Command("systemd-run",
		"--unit", unitName,
		"--collect",
		"--property=Type=oneshot",
		"/bin/sh", "-lc", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, trimmed)
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func standbyRole(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.HighAvailability.Role)
}
