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
	guestDeliveryFailuresExportsComponent = "guest_delivery_failures_exports"
	guestDeliveryFailuresExportPrefix     = "aegisnas-guest-delivery-failures-"
)

type GuestDeliveryFailuresExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	guestDeliveryFailuresExportNow               = time.Now
	guestDeliveryFailuresExportGetSummary        = db.GetGuestDeliveryFailureAnalytics
	guestDeliveryFailuresExportGetRuntimeStatus  = db.GetRuntimeStatus
	guestDeliveryFailuresExportUpsertRuntime     = db.UpsertRuntimeStatus
	guestDeliveryFailuresExportPollInterval      = 30 * time.Second
	guestDeliveryFailuresExportSchedulerMu       sync.Mutex
	guestDeliveryFailuresExportSchedulerStopChan chan struct{}
	guestDeliveryFailuresExportLogger            = zap.NewNop()
)

func StartGuestDeliveryFailuresExportScheduler(_ *config.Config, logger *zap.Logger) error {
	guestDeliveryFailuresExportSchedulerMu.Lock()
	if guestDeliveryFailuresExportSchedulerStopChan != nil {
		close(guestDeliveryFailuresExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	guestDeliveryFailuresExportSchedulerStopChan = stop
	if logger != nil {
		guestDeliveryFailuresExportLogger = logger
	}
	guestDeliveryFailuresExportSchedulerMu.Unlock()

	go guestDeliveryFailuresExportLoop(stop)
	return nil
}

func guestDeliveryFailuresExportLoop(stop <-chan struct{}) {
	runGuestDeliveryFailuresExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(guestDeliveryFailuresExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runGuestDeliveryFailuresExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListGuestDeliveryFailuresExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listGuestDeliveryFailuresExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := guestDeliveryFailuresExportGetRuntimeStatus(guestDeliveryFailuresExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadGuestDeliveryFailuresExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.GuestDeliveryFailuresExports.Directory)
	if targetDir == "" {
		http.Error(w, "guest delivery failures export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "guest delivery failures export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, guestDeliveryFailuresExportPrefix) {
		http.Error(w, "invalid guest delivery failures export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "guest delivery failures export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_guest_delivery_failures_export", name, "downloaded")
}

func runGuestDeliveryFailuresExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.GuestDeliveryFailuresExports
	now := guestDeliveryFailuresExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeGuestDeliveryFailuresExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled guest delivery failures exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeGuestDeliveryFailuresExportRuntimeStatus("disabled", "Scheduled guest delivery failures exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := guestDeliveryFailuresExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeGuestDeliveryFailuresExportRuntimeStatus("ok", "Scheduled guest delivery failures export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	query := db.GuestLifecycleQuery{
		Window:      time.Duration(defaultGuestLifecycleWindowHours) * time.Hour,
		BucketCount: defaultGuestLifecycleBucketCount,
		Limit:       defaultGuestLifecycleLimit,
	}
	summary, err := guestDeliveryFailuresExportGetSummary(query)
	if err != nil {
		_ = writeGuestDeliveryFailuresExportRuntimeStatus("degraded", "Scheduled guest delivery failures export failed while loading analytics.", exportCfg, nil, now, time.Time{}, err.Error())
		guestDeliveryFailuresExportLogger.Warn("scheduled guest delivery failures export summary load failed", zap.Error(err))
		return
	}

	artifacts, err := writeGuestDeliveryFailuresExportArtifacts(exportCfg, query, summary, now)
	if err != nil {
		_ = writeGuestDeliveryFailuresExportRuntimeStatus("degraded", "Scheduled guest delivery failures export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		guestDeliveryFailuresExportLogger.Warn("scheduled guest delivery failures export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneGuestDeliveryFailuresExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		guestDeliveryFailuresExportLogger.Warn("scheduled guest delivery failures export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled guest delivery failures export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeGuestDeliveryFailuresExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func guestDeliveryFailuresExportLastRun() (time.Time, error) {
	status, err := guestDeliveryFailuresExportGetRuntimeStatus(guestDeliveryFailuresExportsComponent)
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

func writeGuestDeliveryFailuresExportArtifacts(exportCfg config.DiagnosticsExportConfig, query db.GuestLifecycleQuery, summary db.GuestDeliveryFailureAnalyticsSummary, now time.Time) ([]GuestDeliveryFailuresExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create guest delivery failures export directory: %w", err)
	}

	baseName := guestDeliveryFailuresExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]GuestDeliveryFailuresExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(guestDeliveryFailuresPayload(query, summary))
			if err != nil {
				return nil, fmt.Errorf("encode guest delivery failures export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := guestDeliveryFailuresCSV(summary)
			if err != nil {
				return nil, fmt.Errorf("encode guest delivery failures export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write guest delivery failures export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat guest delivery failures export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, GuestDeliveryFailuresExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listGuestDeliveryFailuresExportArtifacts(cfg *config.Config) ([]GuestDeliveryFailuresExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.GuestDeliveryFailuresExports.Directory)
	if targetDir == "" {
		return []GuestDeliveryFailuresExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []GuestDeliveryFailuresExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read guest delivery failures export directory: %w", err)
	}

	artifacts := make([]GuestDeliveryFailuresExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, guestDeliveryFailuresExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect guest delivery failures export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, GuestDeliveryFailuresExportArtifact{
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

func pruneGuestDeliveryFailuresExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listGuestDeliveryFailuresExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{GuestDeliveryFailuresExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]GuestDeliveryFailuresExportArtifact{}
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
				return fmt.Errorf("remove guest delivery failures export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeGuestDeliveryFailuresExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []GuestDeliveryFailuresExportArtifact, now, nextDue time.Time, warning string) error {
	details := map[string]any{
		"enabled":          exportCfg.Enabled,
		"directory":        strings.TrimSpace(exportCfg.Directory),
		"format":           scheduledExportEffectiveFormat(exportCfg.Format),
		"interval_minutes": exportCfg.IntervalMinutes,
		"retention_count":  exportCfg.RetentionCount,
		"window_hours":     defaultGuestLifecycleWindowHours,
		"bucket_count":     defaultGuestLifecycleBucketCount,
		"limit":            defaultGuestLifecycleLimit,
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
	return guestDeliveryFailuresExportUpsertRuntime(guestDeliveryFailuresExportsComponent, status, message, details)
}
