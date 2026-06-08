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
	voucherRedemptionAnalyticsExportsComponent = "voucher_redemption_analytics_exports"
	voucherRedemptionAnalyticsExportPrefix     = "aegisnas-voucher-redemption-analytics-"
)

type VoucherRedemptionAnalyticsExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	voucherRedemptionAnalyticsExportNow               = time.Now
	voucherRedemptionAnalyticsExportGetSummary        = db.GetVoucherRedemptionAnalytics
	voucherRedemptionAnalyticsExportGetRuntimeStatus  = db.GetRuntimeStatus
	voucherRedemptionAnalyticsExportUpsertRuntime     = db.UpsertRuntimeStatus
	voucherRedemptionAnalyticsExportPollInterval      = 30 * time.Second
	voucherRedemptionAnalyticsExportSchedulerMu       sync.Mutex
	voucherRedemptionAnalyticsExportSchedulerStopChan chan struct{}
	voucherRedemptionAnalyticsExportLogger            = zap.NewNop()
)

func StartVoucherRedemptionAnalyticsExportScheduler(_ *config.Config, logger *zap.Logger) error {
	voucherRedemptionAnalyticsExportSchedulerMu.Lock()
	if voucherRedemptionAnalyticsExportSchedulerStopChan != nil {
		close(voucherRedemptionAnalyticsExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	voucherRedemptionAnalyticsExportSchedulerStopChan = stop
	if logger != nil {
		voucherRedemptionAnalyticsExportLogger = logger
	}
	voucherRedemptionAnalyticsExportSchedulerMu.Unlock()

	go voucherRedemptionAnalyticsExportLoop(stop)
	return nil
}

func voucherRedemptionAnalyticsExportLoop(stop <-chan struct{}) {
	runVoucherRedemptionAnalyticsExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(voucherRedemptionAnalyticsExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runVoucherRedemptionAnalyticsExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListVoucherRedemptionAnalyticsExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listVoucherRedemptionAnalyticsExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := voucherRedemptionAnalyticsExportGetRuntimeStatus(voucherRedemptionAnalyticsExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadVoucherRedemptionAnalyticsExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.VoucherRedemptionAnalyticsExports.Directory)
	if targetDir == "" {
		http.Error(w, "voucher redemption analytics export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "voucher redemption analytics export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, voucherRedemptionAnalyticsExportPrefix) {
		http.Error(w, "invalid voucher redemption analytics export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "voucher redemption analytics export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_voucher_redemption_analytics_export", name, "downloaded")
}

func runVoucherRedemptionAnalyticsExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.VoucherRedemptionAnalyticsExports
	now := voucherRedemptionAnalyticsExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled voucher redemption analytics exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("disabled", "Scheduled voucher redemption analytics exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := voucherRedemptionAnalyticsExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("ok", "Scheduled voucher redemption analytics export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	query := db.VoucherRedemptionQuery{
		Window:      time.Duration(defaultVoucherAnalyticsWindowHours) * time.Hour,
		BucketCount: defaultVoucherAnalyticsBucketCount,
	}
	summary, err := voucherRedemptionAnalyticsExportGetSummary(query)
	if err != nil {
		_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("degraded", "Scheduled voucher redemption analytics export failed while loading analytics.", exportCfg, nil, now, time.Time{}, err.Error())
		voucherRedemptionAnalyticsExportLogger.Warn("scheduled voucher redemption analytics export summary load failed", zap.Error(err))
		return
	}

	artifacts, err := writeVoucherRedemptionAnalyticsExportArtifacts(exportCfg, summary, now)
	if err != nil {
		_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("degraded", "Scheduled voucher redemption analytics export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		voucherRedemptionAnalyticsExportLogger.Warn("scheduled voucher redemption analytics export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneVoucherRedemptionAnalyticsExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		voucherRedemptionAnalyticsExportLogger.Warn("scheduled voucher redemption analytics export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled voucher redemption analytics export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeVoucherRedemptionAnalyticsExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func voucherRedemptionAnalyticsExportLastRun() (time.Time, error) {
	status, err := voucherRedemptionAnalyticsExportGetRuntimeStatus(voucherRedemptionAnalyticsExportsComponent)
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

func writeVoucherRedemptionAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig, summary db.VoucherRedemptionSummary, now time.Time) ([]VoucherRedemptionAnalyticsExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create voucher redemption analytics export directory: %w", err)
	}

	baseName := voucherRedemptionAnalyticsExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]VoucherRedemptionAnalyticsExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(voucherRedemptionAnalyticsPayload(summary))
			if err != nil {
				return nil, fmt.Errorf("encode voucher redemption analytics export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := voucherRedemptionAnalyticsCSV(summary)
			if err != nil {
				return nil, fmt.Errorf("encode voucher redemption analytics export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write voucher redemption analytics export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat voucher redemption analytics export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, VoucherRedemptionAnalyticsExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listVoucherRedemptionAnalyticsExportArtifacts(cfg *config.Config) ([]VoucherRedemptionAnalyticsExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.VoucherRedemptionAnalyticsExports.Directory)
	if targetDir == "" {
		return []VoucherRedemptionAnalyticsExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []VoucherRedemptionAnalyticsExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read voucher redemption analytics export directory: %w", err)
	}

	artifacts := make([]VoucherRedemptionAnalyticsExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, voucherRedemptionAnalyticsExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect voucher redemption analytics export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, VoucherRedemptionAnalyticsExportArtifact{
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

func pruneVoucherRedemptionAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listVoucherRedemptionAnalyticsExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{VoucherRedemptionAnalyticsExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]VoucherRedemptionAnalyticsExportArtifact{}
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
				return fmt.Errorf("remove voucher redemption analytics export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeVoucherRedemptionAnalyticsExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []VoucherRedemptionAnalyticsExportArtifact, now, nextDue time.Time, warning string) error {
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
	return voucherRedemptionAnalyticsExportUpsertRuntime(voucherRedemptionAnalyticsExportsComponent, status, message, details)
}
