package adminapi

import (
	"context"
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
	"go.uber.org/zap"
)

const (
	integrationExportsComponent = "integration_exports"
	integrationExportPrefix     = "aegisnas-integration-history-"
)

type IntegrationExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	integrationExportNow               = time.Now
	integrationExportListHistoryFn     = db.ListIntegrationHistory
	integrationExportGetRuntimeStatus  = db.GetRuntimeStatus
	integrationExportUpsertRuntime     = db.UpsertRuntimeStatus
	integrationExportPollInterval      = 30 * time.Second
	integrationExportSchedulerMu       sync.Mutex
	integrationExportSchedulerStopChan chan struct{}
	integrationExportLogger            = zap.NewNop()
)

func StartIntegrationExportScheduler(_ *config.Config, logger *zap.Logger) error {
	integrationExportSchedulerMu.Lock()
	if integrationExportSchedulerStopChan != nil {
		close(integrationExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	integrationExportSchedulerStopChan = stop
	if logger != nil {
		integrationExportLogger = logger
	}
	integrationExportSchedulerMu.Unlock()

	go integrationExportLoop(stop)
	return nil
}

func integrationExportLoop(stop <-chan struct{}) {
	runIntegrationExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(integrationExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runIntegrationExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListIntegrationExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listIntegrationExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := integrationExportGetRuntimeStatus(integrationExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadIntegrationExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.IntegrationExports.Directory)
	if targetDir == "" {
		http.Error(w, "integration export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "integration export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, integrationExportPrefix) {
		http.Error(w, "invalid integration export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "integration export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_integration_export", name, "downloaded")
}

func runIntegrationExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.IntegrationExports
	now := integrationExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeIntegrationExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled integration exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeIntegrationExportRuntimeStatus("disabled", "Scheduled integration exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := integrationExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeIntegrationExportRuntimeStatus("ok", "Scheduled integration export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	history, err := integrationExportListHistoryFn("", 2000)
	if err != nil {
		_ = writeIntegrationExportRuntimeStatus("degraded", "Scheduled integration export failed while loading integration history.", exportCfg, nil, now, time.Time{}, err.Error())
		integrationExportLogger.Warn("scheduled integration export load failed", zap.Error(err))
		return
	}

	artifacts, err := writeIntegrationExportArtifacts(exportCfg, history, now)
	if err != nil {
		_ = writeIntegrationExportRuntimeStatus("degraded", "Scheduled integration export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		integrationExportLogger.Warn("scheduled integration export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneIntegrationExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		integrationExportLogger.Warn("scheduled integration export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled integration export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeIntegrationExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func integrationExportLastRun() (time.Time, error) {
	status, err := integrationExportGetRuntimeStatus(integrationExportsComponent)
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

func writeIntegrationExportArtifacts(exportCfg config.DiagnosticsExportConfig, history []db.IntegrationHistoryRecord, now time.Time) ([]IntegrationExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create integration export directory: %w", err)
	}

	baseName := integrationExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]IntegrationExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := integrationHistoryJSONPayload("", history)
			if err != nil {
				return nil, fmt.Errorf("encode integration export json: %w", err)
			}
			payload = data
		case "csv":
			data, err := integrationHistoryCSV(history)
			if err != nil {
				return nil, fmt.Errorf("encode integration export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write integration export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat integration export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, IntegrationExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listIntegrationExportArtifacts(cfg *config.Config) ([]IntegrationExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.IntegrationExports.Directory)
	if targetDir == "" {
		return []IntegrationExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []IntegrationExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read integration export directory: %w", err)
	}

	artifacts := make([]IntegrationExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, integrationExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect integration export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, IntegrationExportArtifact{
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

func pruneIntegrationExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listIntegrationExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{IntegrationExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]IntegrationExportArtifact{}
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
				return fmt.Errorf("remove integration export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeIntegrationExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []IntegrationExportArtifact, now, nextDue time.Time, warning string) error {
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
	return integrationExportUpsertRuntime(integrationExportsComponent, status, message, details)
}
