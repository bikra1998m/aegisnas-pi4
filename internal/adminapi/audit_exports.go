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
	auditExportsComponent = "audit_exports"
	auditExportPrefix     = "aegisnas-audit-history-"
)

type AuditExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	auditExportNow               = time.Now
	auditExportListHistoryFn     = db.ListAuditHistory
	auditExportGetRuntimeStatus  = db.GetRuntimeStatus
	auditExportUpsertRuntime     = db.UpsertRuntimeStatus
	auditExportPollInterval      = 30 * time.Second
	auditExportSchedulerMu       sync.Mutex
	auditExportSchedulerStopChan chan struct{}
	auditExportLogger            = zap.NewNop()
)

func StartAuditExportScheduler(_ *config.Config, logger *zap.Logger) error {
	auditExportSchedulerMu.Lock()
	if auditExportSchedulerStopChan != nil {
		close(auditExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	auditExportSchedulerStopChan = stop
	if logger != nil {
		auditExportLogger = logger
	}
	auditExportSchedulerMu.Unlock()

	go auditExportLoop(stop)
	return nil
}

func auditExportLoop(stop <-chan struct{}) {
	runAuditExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(auditExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runAuditExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListAuditExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listAuditExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := auditExportGetRuntimeStatus(auditExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadAuditExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.AuditExports.Directory)
	if targetDir == "" {
		http.Error(w, "audit export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "audit export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, auditExportPrefix) {
		http.Error(w, "invalid audit export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "audit export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_audit_export", name, "downloaded")
}

func runAuditExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.AuditExports
	now := auditExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeAuditExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled audit exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeAuditExportRuntimeStatus("disabled", "Scheduled audit exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := auditExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeAuditExportRuntimeStatus("ok", "Scheduled audit export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	history, err := auditExportListHistoryFn("", "", 5000)
	if err != nil {
		_ = writeAuditExportRuntimeStatus("degraded", "Scheduled audit export failed while loading audit history.", exportCfg, nil, now, time.Time{}, err.Error())
		auditExportLogger.Warn("scheduled audit export load failed", zap.Error(err))
		return
	}

	artifacts, err := writeAuditExportArtifacts(exportCfg, history, now)
	if err != nil {
		_ = writeAuditExportRuntimeStatus("degraded", "Scheduled audit export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		auditExportLogger.Warn("scheduled audit export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneAuditExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		auditExportLogger.Warn("scheduled audit export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled audit export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeAuditExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func auditExportLastRun() (time.Time, error) {
	status, err := auditExportGetRuntimeStatus(auditExportsComponent)
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

func writeAuditExportArtifacts(exportCfg config.DiagnosticsExportConfig, history []db.AuditHistoryRecord, now time.Time) ([]AuditExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create audit export directory: %w", err)
	}

	baseName := auditExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]AuditExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := auditHistoryJSONPayload("", "", history)
			if err != nil {
				return nil, fmt.Errorf("encode audit export json: %w", err)
			}
			payload = data
		case "csv":
			data, err := auditHistoryCSV(history)
			if err != nil {
				return nil, fmt.Errorf("encode audit export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write audit export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat audit export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, AuditExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listAuditExportArtifacts(cfg *config.Config) ([]AuditExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.AuditExports.Directory)
	if targetDir == "" {
		return []AuditExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read audit export directory: %w", err)
	}

	artifacts := make([]AuditExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, auditExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect audit export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, AuditExportArtifact{
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

func pruneAuditExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listAuditExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{AuditExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]AuditExportArtifact{}
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
				return fmt.Errorf("remove audit export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeAuditExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []AuditExportArtifact, now, nextDue time.Time, warning string) error {
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
	return auditExportUpsertRuntime(auditExportsComponent, status, message, details)
}
