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
	upstreamAAAExportsComponent = "upstream_aaa_exports"
	upstreamAAAExportPrefix     = "aegisnas-upstream-aaa-history-"
)

type UpstreamAAAExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	upstreamAAAExportNow               = time.Now
	upstreamAAAExportListHistoryFn     = db.ListUpstreamAAAHistory
	upstreamAAAExportGetRuntimeStatus  = db.GetRuntimeStatus
	upstreamAAAExportUpsertRuntime     = db.UpsertRuntimeStatus
	upstreamAAAExportPollInterval      = 30 * time.Second
	upstreamAAAExportSchedulerMu       sync.Mutex
	upstreamAAAExportSchedulerStopChan chan struct{}
	upstreamAAAExportLogger            = zap.NewNop()
)

func StartUpstreamAAAExportScheduler(_ *config.Config, logger *zap.Logger) error {
	upstreamAAAExportSchedulerMu.Lock()
	if upstreamAAAExportSchedulerStopChan != nil {
		close(upstreamAAAExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	upstreamAAAExportSchedulerStopChan = stop
	if logger != nil {
		upstreamAAAExportLogger = logger
	}
	upstreamAAAExportSchedulerMu.Unlock()

	go upstreamAAAExportLoop(stop)
	return nil
}

func upstreamAAAExportLoop(stop <-chan struct{}) {
	runUpstreamAAAExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(upstreamAAAExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runUpstreamAAAExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListUpstreamAAAExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listUpstreamAAAExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := upstreamAAAExportGetRuntimeStatus(upstreamAAAExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadUpstreamAAAExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.UpstreamAAAExports.Directory)
	if targetDir == "" {
		http.Error(w, "upstream aaa export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "upstream aaa export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, upstreamAAAExportPrefix) {
		http.Error(w, "invalid upstream aaa export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "upstream aaa export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_upstream_aaa_export", name, "downloaded")
}

func runUpstreamAAAExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.UpstreamAAAExports
	now := upstreamAAAExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeUpstreamAAAExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled upstream AAA exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeUpstreamAAAExportRuntimeStatus("disabled", "Scheduled upstream AAA exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := upstreamAAAExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeUpstreamAAAExportRuntimeStatus("ok", "Scheduled upstream AAA export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	history, err := upstreamAAAExportListHistoryFn("", "", 5000)
	if err != nil {
		_ = writeUpstreamAAAExportRuntimeStatus("degraded", "Scheduled upstream AAA export failed while loading upstream AAA history.", exportCfg, nil, now, time.Time{}, err.Error())
		upstreamAAAExportLogger.Warn("scheduled upstream aaa export load failed", zap.Error(err))
		return
	}

	artifacts, err := writeUpstreamAAAExportArtifacts(exportCfg, history, now)
	if err != nil {
		_ = writeUpstreamAAAExportRuntimeStatus("degraded", "Scheduled upstream AAA export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		upstreamAAAExportLogger.Warn("scheduled upstream aaa export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneUpstreamAAAExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		upstreamAAAExportLogger.Warn("scheduled upstream aaa export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled upstream AAA export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeUpstreamAAAExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func upstreamAAAExportLastRun() (time.Time, error) {
	status, err := upstreamAAAExportGetRuntimeStatus(upstreamAAAExportsComponent)
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

func writeUpstreamAAAExportArtifacts(exportCfg config.DiagnosticsExportConfig, history []db.UpstreamAAAHistoryRecord, now time.Time) ([]UpstreamAAAExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create upstream aaa export directory: %w", err)
	}

	baseName := upstreamAAAExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]UpstreamAAAExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := upstreamAAAHistoryJSONPayload("", "", history)
			if err != nil {
				return nil, fmt.Errorf("encode upstream aaa export json: %w", err)
			}
			payload = data
		case "csv":
			data, err := upstreamAAAHistoryCSV(history)
			if err != nil {
				return nil, fmt.Errorf("encode upstream aaa export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write upstream aaa export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat upstream aaa export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, UpstreamAAAExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listUpstreamAAAExportArtifacts(cfg *config.Config) ([]UpstreamAAAExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.UpstreamAAAExports.Directory)
	if targetDir == "" {
		return []UpstreamAAAExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []UpstreamAAAExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read upstream aaa export directory: %w", err)
	}

	artifacts := make([]UpstreamAAAExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, upstreamAAAExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect upstream aaa export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, UpstreamAAAExportArtifact{
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

func pruneUpstreamAAAExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listUpstreamAAAExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{UpstreamAAAExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]UpstreamAAAExportArtifact{}
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
				return fmt.Errorf("remove upstream aaa export artifact %s (%s): %w", item.Name, format, err)
			}
		}
	}
	return nil
}

func writeUpstreamAAAExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []UpstreamAAAExportArtifact, now, nextDue time.Time, warning string) error {
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
	return upstreamAAAExportUpsertRuntime(upstreamAAAExportsComponent, status, message, details)
}
