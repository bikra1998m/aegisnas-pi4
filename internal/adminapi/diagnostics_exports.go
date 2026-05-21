package adminapi

import (
	"context"
	"encoding/json"
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
	diagnosticsExportsComponent = "diagnostics_exports"
	diagnosticsExportPrefix     = "aegisnas-diagnostics-report-"
)

type DiagnosticsExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	diagnosticsExportNow               = time.Now
	diagnosticsExportBuildReportFn     = buildDiagnosticsReport
	diagnosticsExportCSVFn             = diagnosticsReportCSV
	diagnosticsExportPollInterval      = 30 * time.Second
	diagnosticsExportGetRuntimeStatus  = db.GetRuntimeStatus
	diagnosticsExportUpsertRuntime     = db.UpsertRuntimeStatus
	diagnosticsExportSchedulerMu       sync.Mutex
	diagnosticsExportSchedulerStopChan chan struct{}
	diagnosticsExportLogger            = zap.NewNop()
)

func StartDiagnosticsExportScheduler(_ *config.Config, logger *zap.Logger) error {
	diagnosticsExportSchedulerMu.Lock()
	if diagnosticsExportSchedulerStopChan != nil {
		close(diagnosticsExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	diagnosticsExportSchedulerStopChan = stop
	if logger != nil {
		diagnosticsExportLogger = logger
	}
	diagnosticsExportSchedulerMu.Unlock()

	go diagnosticsExportLoop(stop)
	return nil
}

func diagnosticsExportLoop(stop <-chan struct{}) {
	runDiagnosticsExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(diagnosticsExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runDiagnosticsExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListDiagnosticsExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listDiagnosticsExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := diagnosticsExportGetRuntimeStatus(diagnosticsExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadDiagnosticsExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.DiagnosticsExports.Directory)
	if targetDir == "" {
		http.Error(w, "diagnostics export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "diagnostics export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, diagnosticsExportPrefix) {
		http.Error(w, "invalid diagnostics export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "diagnostics export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_diagnostics_export", name, "downloaded")
}

func runDiagnosticsExportCycle(ctx context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.DiagnosticsExports
	now := diagnosticsExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeDiagnosticsExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled diagnostics exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeDiagnosticsExportRuntimeStatus("disabled", "Scheduled diagnostics exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := diagnosticsExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeDiagnosticsExportRuntimeStatus("ok", "Scheduled diagnostics export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	report, err := diagnosticsExportBuildReportFn(ctx)
	if err != nil {
		_ = writeDiagnosticsExportRuntimeStatus("degraded", "Scheduled diagnostics export failed while building the report.", exportCfg, nil, now, time.Time{}, err.Error())
		diagnosticsExportLogger.Warn("scheduled diagnostics export build failed", zap.Error(err))
		return
	}

	artifacts, err := writeDiagnosticsExportArtifacts(exportCfg, report, now)
	if err != nil {
		_ = writeDiagnosticsExportRuntimeStatus("degraded", "Scheduled diagnostics export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		diagnosticsExportLogger.Warn("scheduled diagnostics export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneDiagnosticsExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		diagnosticsExportLogger.Warn("scheduled diagnostics export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled diagnostics export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeDiagnosticsExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func diagnosticsExportLastRun() (time.Time, error) {
	status, err := diagnosticsExportGetRuntimeStatus(diagnosticsExportsComponent)
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

func writeDiagnosticsExportArtifacts(exportCfg config.DiagnosticsExportConfig, report DiagnosticsReport, now time.Time) ([]DiagnosticsExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create diagnostics export directory: %w", err)
	}

	baseName := diagnosticsExportPrefix + now.Format("20060102-150405Z")
	formats := diagnosticsExportFormats(exportCfg.Format)
	artifacts := make([]DiagnosticsExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(report)
			if err != nil {
				return nil, fmt.Errorf("encode diagnostics export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := diagnosticsExportCSVFn(report)
			if err != nil {
				return nil, fmt.Errorf("encode diagnostics export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write diagnostics export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat diagnostics export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, DiagnosticsExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listDiagnosticsExportArtifacts(cfg *config.Config) ([]DiagnosticsExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.DiagnosticsExports.Directory)
	if targetDir == "" {
		return []DiagnosticsExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []DiagnosticsExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read diagnostics export directory: %w", err)
	}

	artifacts := make([]DiagnosticsExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, diagnosticsExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect diagnostics export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, DiagnosticsExportArtifact{
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

func pruneDiagnosticsExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listDiagnosticsExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{DiagnosticsExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]DiagnosticsExportArtifact{}
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
				return fmt.Errorf("remove diagnostics export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeDiagnosticsExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []DiagnosticsExportArtifact, now, nextDue time.Time, warning string) error {
	details := map[string]any{
		"enabled":          exportCfg.Enabled,
		"directory":        strings.TrimSpace(exportCfg.Directory),
		"format":           diagnosticsEffectiveFormat(exportCfg.Format),
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
	return diagnosticsExportUpsertRuntime(diagnosticsExportsComponent, status, message, details)
}

func diagnosticsExportFormats(raw string) []string {
	switch diagnosticsEffectiveFormat(raw) {
	case "csv":
		return []string{"csv"}
	case "both":
		return []string{"json", "csv"}
	default:
		return []string{"json"}
	}
}

func diagnosticsEffectiveFormat(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "csv":
		return "csv"
	case "both":
		return "both"
	default:
		return "json"
	}
}

func jsonMarshalIndented(payload any) ([]byte, error) {
	return json.MarshalIndent(payload, "", "  ")
}
