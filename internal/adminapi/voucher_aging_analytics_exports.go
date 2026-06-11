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
	voucherAgingAnalyticsExportsComponent = "voucher_aging_analytics_exports"
	voucherAgingAnalyticsExportPrefix     = "aegisnas-voucher-aging-analytics-"
)

type VoucherAgingAnalyticsExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	voucherAgingAnalyticsExportNow               = time.Now
	voucherAgingAnalyticsExportGetSummary        = db.GetVoucherAgingAnalytics
	voucherAgingAnalyticsExportGetRuntimeStatus  = db.GetRuntimeStatus
	voucherAgingAnalyticsExportUpsertRuntime     = db.UpsertRuntimeStatus
	voucherAgingAnalyticsExportPollInterval      = 30 * time.Second
	voucherAgingAnalyticsExportSchedulerMu       sync.Mutex
	voucherAgingAnalyticsExportSchedulerStopChan chan struct{}
	voucherAgingAnalyticsExportLogger            = zap.NewNop()
)

func StartVoucherAgingAnalyticsExportScheduler(_ *config.Config, logger *zap.Logger) error {
	voucherAgingAnalyticsExportSchedulerMu.Lock()
	if voucherAgingAnalyticsExportSchedulerStopChan != nil {
		close(voucherAgingAnalyticsExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	voucherAgingAnalyticsExportSchedulerStopChan = stop
	if logger != nil {
		voucherAgingAnalyticsExportLogger = logger
	}
	voucherAgingAnalyticsExportSchedulerMu.Unlock()

	go voucherAgingAnalyticsExportLoop(stop)
	return nil
}

func voucherAgingAnalyticsExportLoop(stop <-chan struct{}) {
	runVoucherAgingAnalyticsExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(voucherAgingAnalyticsExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runVoucherAgingAnalyticsExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListVoucherAgingAnalyticsExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listVoucherAgingAnalyticsExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := voucherAgingAnalyticsExportGetRuntimeStatus(voucherAgingAnalyticsExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadVoucherAgingAnalyticsExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.VoucherAgingAnalyticsExports.Directory)
	if targetDir == "" {
		http.Error(w, "voucher aging analytics export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "voucher aging analytics export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, voucherAgingAnalyticsExportPrefix) {
		http.Error(w, "invalid voucher aging analytics export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "voucher aging analytics export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_voucher_aging_analytics_export", name, "downloaded")
}

func runVoucherAgingAnalyticsExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.VoucherAgingAnalyticsExports
	now := voucherAgingAnalyticsExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeVoucherAgingAnalyticsExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled voucher aging analytics exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeVoucherAgingAnalyticsExportRuntimeStatus("disabled", "Scheduled voucher aging analytics exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := voucherAgingAnalyticsExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeVoucherAgingAnalyticsExportRuntimeStatus("ok", "Scheduled voucher aging analytics export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	query := db.VoucherAgingQuery{
		Window:      time.Duration(defaultVoucherAnalyticsWindowHours) * time.Hour,
		BucketCount: defaultVoucherAnalyticsBucketCount,
	}
	summary, err := voucherAgingAnalyticsExportGetSummary(query)
	if err != nil {
		_ = writeVoucherAgingAnalyticsExportRuntimeStatus("degraded", "Scheduled voucher aging analytics export failed while loading analytics.", exportCfg, nil, now, time.Time{}, err.Error())
		voucherAgingAnalyticsExportLogger.Warn("scheduled voucher aging analytics export summary load failed", zap.Error(err))
		return
	}

	artifacts, err := writeVoucherAgingAnalyticsExportArtifacts(exportCfg, summary, now)
	if err != nil {
		_ = writeVoucherAgingAnalyticsExportRuntimeStatus("degraded", "Scheduled voucher aging analytics export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		voucherAgingAnalyticsExportLogger.Warn("scheduled voucher aging analytics export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneVoucherAgingAnalyticsExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		voucherAgingAnalyticsExportLogger.Warn("scheduled voucher aging analytics export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled voucher aging analytics export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeVoucherAgingAnalyticsExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func voucherAgingAnalyticsExportLastRun() (time.Time, error) {
	status, err := voucherAgingAnalyticsExportGetRuntimeStatus(voucherAgingAnalyticsExportsComponent)
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

func writeVoucherAgingAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig, summary db.VoucherAgingSummary, now time.Time) ([]VoucherAgingAnalyticsExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create voucher aging analytics export directory: %w", err)
	}

	baseName := voucherAgingAnalyticsExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]VoucherAgingAnalyticsExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(voucherAgingAnalyticsPayload(summary))
			if err != nil {
				return nil, fmt.Errorf("encode voucher aging analytics export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := voucherAgingAnalyticsCSV(summary)
			if err != nil {
				return nil, fmt.Errorf("encode voucher aging analytics export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write voucher aging analytics export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat voucher aging analytics export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, VoucherAgingAnalyticsExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listVoucherAgingAnalyticsExportArtifacts(cfg *config.Config) ([]VoucherAgingAnalyticsExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.VoucherAgingAnalyticsExports.Directory)
	if targetDir == "" {
		return []VoucherAgingAnalyticsExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []VoucherAgingAnalyticsExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read voucher aging analytics export directory: %w", err)
	}

	artifacts := make([]VoucherAgingAnalyticsExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, voucherAgingAnalyticsExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect voucher aging analytics export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, VoucherAgingAnalyticsExportArtifact{
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

func pruneVoucherAgingAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listVoucherAgingAnalyticsExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{VoucherAgingAnalyticsExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]VoucherAgingAnalyticsExportArtifact{}
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
				return fmt.Errorf("remove voucher aging analytics export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeVoucherAgingAnalyticsExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []VoucherAgingAnalyticsExportArtifact, now, nextDue time.Time, warning string) error {
	details := map[string]any{
		"enabled":          exportCfg.Enabled,
		"directory":        strings.TrimSpace(exportCfg.Directory),
		"format":           scheduledExportEffectiveFormat(exportCfg.Format),
		"interval_minutes": exportCfg.IntervalMinutes,
		"retention_count":  exportCfg.RetentionCount,
		"window_hours":     defaultVoucherAnalyticsWindowHours,
		"bucket_count":     defaultVoucherAnalyticsBucketCount,
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
	return voucherAgingAnalyticsExportUpsertRuntime(voucherAgingAnalyticsExportsComponent, status, message, details)
}
