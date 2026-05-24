package adminapi

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	upgradepkg "github.com/yourorg/aegisnas-pi4/internal/upgrade"
	"go.uber.org/zap"
)

const (
	upgradeReadinessExportsComponent = "upgrade_readiness_exports"
	upgradeReadinessExportPrefix     = "aegisnas-upgrade-readiness-"
)

type UpgradeReadinessExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	upgradeReadinessExportNow               = time.Now
	upgradeReadinessExportAssessFn          = assessUpgradeReadinessFn
	upgradeReadinessExportGetRuntimeStatus  = db.GetRuntimeStatus
	upgradeReadinessExportUpsertRuntime     = db.UpsertRuntimeStatus
	upgradeReadinessExportPollInterval      = 30 * time.Second
	upgradeReadinessExportSchedulerMu       sync.Mutex
	upgradeReadinessExportSchedulerStopChan chan struct{}
	upgradeReadinessExportLogger            = zap.NewNop()
)

func StartUpgradeReadinessExportScheduler(_ *config.Config, logger *zap.Logger) error {
	upgradeReadinessExportSchedulerMu.Lock()
	if upgradeReadinessExportSchedulerStopChan != nil {
		close(upgradeReadinessExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	upgradeReadinessExportSchedulerStopChan = stop
	if logger != nil {
		upgradeReadinessExportLogger = logger
	}
	upgradeReadinessExportSchedulerMu.Unlock()

	go upgradeReadinessExportLoop(stop)
	return nil
}

func upgradeReadinessExportLoop(stop <-chan struct{}) {
	runUpgradeReadinessExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(upgradeReadinessExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runUpgradeReadinessExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListUpgradeReadinessExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listUpgradeReadinessExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := upgradeReadinessExportGetRuntimeStatus(upgradeReadinessExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadUpgradeReadinessExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.UpgradeReadinessExports.Directory)
	if targetDir == "" {
		http.Error(w, "upgrade readiness export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "upgrade readiness export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, upgradeReadinessExportPrefix) {
		http.Error(w, "invalid upgrade readiness export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "upgrade readiness export not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	contentType := "application/octet-stream"
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		contentType = "application/json"
	case ".csv":
		contentType = "text/csv"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	audit(r, "download_scheduled_upgrade_readiness_export", name, "downloaded")
}

func runUpgradeReadinessExportCycle(ctx context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.UpgradeReadinessExports
	now := upgradeReadinessExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeUpgradeReadinessExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled upgrade readiness exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeUpgradeReadinessExportRuntimeStatus("disabled", "Scheduled upgrade readiness exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := upgradeReadinessExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeUpgradeReadinessExportRuntimeStatus("ok", "Scheduled upgrade readiness export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	report, err := upgradeReadinessExportAssessFn(cfg, config.Path())
	if err != nil {
		_ = writeUpgradeReadinessExportRuntimeStatus("degraded", "Scheduled upgrade readiness export failed while assessing readiness.", exportCfg, nil, now, time.Time{}, err.Error())
		upgradeReadinessExportLogger.Warn("scheduled upgrade readiness export assessment failed", zap.Error(err))
		return
	}

	artifacts, err := writeUpgradeReadinessExportArtifacts(exportCfg, report, now)
	if err != nil {
		_ = writeUpgradeReadinessExportRuntimeStatus("degraded", "Scheduled upgrade readiness export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		upgradeReadinessExportLogger.Warn("scheduled upgrade readiness export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneUpgradeReadinessExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		upgradeReadinessExportLogger.Warn("scheduled upgrade readiness export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled upgrade readiness export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeUpgradeReadinessExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func upgradeReadinessExportLastRun() (time.Time, error) {
	status, err := upgradeReadinessExportGetRuntimeStatus(upgradeReadinessExportsComponent)
	if err != nil || status == nil || status.Details == nil {
		return time.Time{}, err
	}
	raw, ok := status.Details["last_export_at"]
	if !ok {
		return time.Time{}, nil
	}
	text := strings.TrimSpace(fmt.Sprint(raw))
	if text == "" {
		return time.Time{}, nil
	}
	parsed, parseErr := time.Parse(time.RFC3339, text)
	if parseErr != nil {
		return time.Time{}, nil
	}
	return parsed, nil
}

func writeUpgradeReadinessExportArtifacts(exportCfg config.DiagnosticsExportConfig, report upgradepkg.ReadinessReport, now time.Time) ([]UpgradeReadinessExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create upgrade readiness export directory: %w", err)
	}

	baseName := upgradeReadinessExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]UpgradeReadinessExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(report)
			if err != nil {
				return nil, fmt.Errorf("encode upgrade readiness export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := upgradeReadinessCSV(report)
			if err != nil {
				return nil, fmt.Errorf("encode upgrade readiness export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write upgrade readiness export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat upgrade readiness export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, UpgradeReadinessExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listUpgradeReadinessExportArtifacts(cfg *config.Config) ([]UpgradeReadinessExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.UpgradeReadinessExports.Directory)
	if targetDir == "" {
		return []UpgradeReadinessExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []UpgradeReadinessExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read upgrade readiness export directory: %w", err)
	}

	artifacts := make([]UpgradeReadinessExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, upgradeReadinessExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect upgrade readiness export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, UpgradeReadinessExportArtifact{
			Name:      name,
			Path:      filepath.Join(targetDir, name),
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
	}

	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].CreatedAt == artifacts[j].CreatedAt {
			return artifacts[i].Name > artifacts[j].Name
		}
		return artifacts[i].CreatedAt > artifacts[j].CreatedAt
	})
	return artifacts, nil
}

func pruneUpgradeReadinessExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listUpgradeReadinessExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{UpgradeReadinessExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]UpgradeReadinessExportArtifact{}
	for _, artifact := range artifacts {
		byFormat[artifact.Format] = append(byFormat[artifact.Format], artifact)
	}
	for _, format := range []string{"json", "csv"} {
		items := byFormat[format]
		if len(items) <= exportCfg.RetentionCount {
			continue
		}
		for _, item := range items[exportCfg.RetentionCount:] {
			if err := os.Remove(item.Path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove upgrade readiness export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeUpgradeReadinessExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []UpgradeReadinessExportArtifact, now, nextDue time.Time, warning string) error {
	details := map[string]any{
		"enabled":          exportCfg.Enabled,
		"directory":        strings.TrimSpace(exportCfg.Directory),
		"format":           scheduledExportEffectiveFormat(exportCfg.Format),
		"interval_minutes": exportCfg.IntervalMinutes,
		"retention_count":  exportCfg.RetentionCount,
	}
	if !now.IsZero() {
		details["observed_at"] = now.Format(time.RFC3339)
	}
	if !nextDue.IsZero() {
		details["next_due_at"] = nextDue.Format(time.RFC3339)
	}
	if len(artifacts) > 0 {
		paths := make([]string, 0, len(artifacts))
		names := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			paths = append(paths, artifact.Path)
			names = append(names, artifact.Name)
		}
		details["last_export_at"] = artifacts[0].CreatedAt
		details["last_export_paths"] = paths
		details["last_export_names"] = names
		details["artifact_count"] = len(artifacts)
	}
	if warning != "" {
		details["warning"] = warning
	}
	return upgradeReadinessExportUpsertRuntime(upgradeReadinessExportsComponent, status, message, details)
}

func upgradeReadinessCSV(report upgradepkg.ReadinessReport) ([]byte, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"section", "key", "value"}); err != nil {
		return nil, err
	}

	rows := [][]string{
		{"summary", "generated_at", report.GeneratedAt},
		{"summary", "config_path", report.ConfigPath},
		{"summary", "database_path", report.DatabasePath},
		{"summary", "database_exists", fmt.Sprint(report.DatabaseExists)},
		{"summary", "database_size_bytes", fmt.Sprint(report.DatabaseSizeBytes)},
		{"summary", "current_schema_version", fmt.Sprint(report.CurrentSchemaVersion)},
		{"summary", "target_schema_version", fmt.Sprint(report.TargetSchemaVersion)},
		{"summary", "config_valid", fmt.Sprint(report.ConfigValid)},
		{"summary", "config_validation_error", report.ConfigValidationError},
		{"summary", "deployment_profile", report.DeploymentProfile},
		{"summary", "deployment_form", report.DeploymentForm},
		{"rehearsal", "ran", fmt.Sprint(report.Rehearsal.Ran)},
		{"rehearsal", "succeeded", fmt.Sprint(report.Rehearsal.Succeeded)},
		{"rehearsal", "started_schema_version", fmt.Sprint(report.Rehearsal.StartedSchemaVersion)},
		{"rehearsal", "result_schema_version", fmt.Sprint(report.Rehearsal.ResultSchemaVersion)},
		{"rehearsal", "duration_milliseconds", fmt.Sprint(report.Rehearsal.DurationMilliseconds)},
		{"rehearsal", "error", report.Rehearsal.Error},
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	for index, recommendation := range report.Recommendations {
		if err := writer.Write([]string{"recommendation", fmt.Sprint(index + 1), recommendation}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}
