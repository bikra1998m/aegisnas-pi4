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
	guestInviteAnalyticsExportsComponent = "guest_invite_analytics_exports"
	guestInviteAnalyticsExportPrefix     = "aegisnas-guest-invite-analytics-"
)

type GuestInviteAnalyticsExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	guestInviteAnalyticsExportNow               = time.Now
	guestInviteAnalyticsExportGetSummary        = db.GetGuestInviteAnalytics
	guestInviteAnalyticsExportGetRuntimeStatus  = db.GetRuntimeStatus
	guestInviteAnalyticsExportUpsertRuntime     = db.UpsertRuntimeStatus
	guestInviteAnalyticsExportPollInterval      = 30 * time.Second
	guestInviteAnalyticsExportSchedulerMu       sync.Mutex
	guestInviteAnalyticsExportSchedulerStopChan chan struct{}
	guestInviteAnalyticsExportLogger            = zap.NewNop()
)

func StartGuestInviteAnalyticsExportScheduler(_ *config.Config, logger *zap.Logger) error {
	guestInviteAnalyticsExportSchedulerMu.Lock()
	if guestInviteAnalyticsExportSchedulerStopChan != nil {
		close(guestInviteAnalyticsExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	guestInviteAnalyticsExportSchedulerStopChan = stop
	if logger != nil {
		guestInviteAnalyticsExportLogger = logger
	}
	guestInviteAnalyticsExportSchedulerMu.Unlock()

	go guestInviteAnalyticsExportLoop(stop)
	return nil
}

func guestInviteAnalyticsExportLoop(stop <-chan struct{}) {
	runGuestInviteAnalyticsExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(guestInviteAnalyticsExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runGuestInviteAnalyticsExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListGuestInviteAnalyticsExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listGuestInviteAnalyticsExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := guestInviteAnalyticsExportGetRuntimeStatus(guestInviteAnalyticsExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadGuestInviteAnalyticsExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.GuestInviteAnalyticsExports.Directory)
	if targetDir == "" {
		http.Error(w, "guest invite analytics export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "guest invite analytics export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !strings.HasPrefix(name, guestInviteAnalyticsExportPrefix) {
		http.Error(w, "invalid guest invite analytics export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "guest invite analytics export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_guest_invite_analytics_export", name, "downloaded")
}

func runGuestInviteAnalyticsExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.GuestInviteAnalyticsExports
	now := guestInviteAnalyticsExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeGuestInviteAnalyticsExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled guest invite analytics exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeGuestInviteAnalyticsExportRuntimeStatus("disabled", "Scheduled guest invite analytics exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := guestInviteAnalyticsExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeGuestInviteAnalyticsExportRuntimeStatus("ok", "Scheduled guest invite analytics export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	query := db.GuestLifecycleQuery{
		Window:      time.Duration(defaultGuestLifecycleWindowHours) * time.Hour,
		BucketCount: defaultGuestLifecycleBucketCount,
		Limit:       defaultGuestLifecycleLimit,
	}
	summary, err := guestInviteAnalyticsExportGetSummary(query)
	if err != nil {
		_ = writeGuestInviteAnalyticsExportRuntimeStatus("degraded", "Scheduled guest invite analytics export failed while loading analytics.", exportCfg, nil, now, time.Time{}, err.Error())
		guestInviteAnalyticsExportLogger.Warn("scheduled guest invite analytics export summary load failed", zap.Error(err))
		return
	}

	artifacts, err := writeGuestInviteAnalyticsExportArtifacts(exportCfg, query, summary, now)
	if err != nil {
		_ = writeGuestInviteAnalyticsExportRuntimeStatus("degraded", "Scheduled guest invite analytics export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		guestInviteAnalyticsExportLogger.Warn("scheduled guest invite analytics export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneGuestInviteAnalyticsExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		guestInviteAnalyticsExportLogger.Warn("scheduled guest invite analytics export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled guest invite analytics export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeGuestInviteAnalyticsExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func guestInviteAnalyticsExportLastRun() (time.Time, error) {
	status, err := guestInviteAnalyticsExportGetRuntimeStatus(guestInviteAnalyticsExportsComponent)
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

func writeGuestInviteAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig, query db.GuestLifecycleQuery, summary db.GuestInviteAnalyticsSummary, now time.Time) ([]GuestInviteAnalyticsExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create guest invite analytics export directory: %w", err)
	}

	baseName := guestInviteAnalyticsExportPrefix + now.Format("20060102-150405Z")
	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]GuestInviteAnalyticsExportArtifact, 0, len(formats))
	for _, format := range formats {
		filename := baseName + "." + format
		targetPath := filepath.Join(targetDir, filename)

		var payload []byte
		switch format {
		case "json":
			data, err := jsonMarshalIndented(guestInviteAnalyticsPayload(query, summary))
			if err != nil {
				return nil, fmt.Errorf("encode guest invite analytics export json: %w", err)
			}
			payload = append(data, '\n')
		case "csv":
			data, err := guestInviteAnalyticsCSV(summary)
			if err != nil {
				return nil, fmt.Errorf("encode guest invite analytics export csv: %w", err)
			}
			payload = data
		default:
			continue
		}

		if err := os.WriteFile(targetPath, payload, 0640); err != nil {
			return nil, fmt.Errorf("write guest invite analytics export artifact %s: %w", filename, err)
		}
		info, err := os.Stat(targetPath)
		if err != nil {
			return nil, fmt.Errorf("stat guest invite analytics export artifact %s: %w", filename, err)
		}
		artifacts = append(artifacts, GuestInviteAnalyticsExportArtifact{
			Name:      filename,
			Path:      targetPath,
			Format:    format,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		})
	}
	return artifacts, nil
}

func listGuestInviteAnalyticsExportArtifacts(cfg *config.Config) ([]GuestInviteAnalyticsExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.GuestInviteAnalyticsExports.Directory)
	if targetDir == "" {
		return []GuestInviteAnalyticsExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []GuestInviteAnalyticsExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read guest invite analytics export directory: %w", err)
	}

	artifacts := make([]GuestInviteAnalyticsExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, guestInviteAnalyticsExportPrefix) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect guest invite analytics export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, GuestInviteAnalyticsExportArtifact{
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

func pruneGuestInviteAnalyticsExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listGuestInviteAnalyticsExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{GuestInviteAnalyticsExports: exportCfg}})
	if err != nil {
		return err
	}

	byFormat := map[string][]GuestInviteAnalyticsExportArtifact{}
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
				return fmt.Errorf("remove guest invite analytics export artifact %s: %w", item.Name, err)
			}
		}
	}
	return nil
}

func writeGuestInviteAnalyticsExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []GuestInviteAnalyticsExportArtifact, now, nextDue time.Time, warning string) error {
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
	return guestInviteAnalyticsExportUpsertRuntime(guestInviteAnalyticsExportsComponent, status, message, details)
}
