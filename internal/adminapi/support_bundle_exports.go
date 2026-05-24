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
	supportBundleExportsComponent = "support_bundle_exports"
	supportBundleExportPrefix     = "aegisnas-support-bundle-"
)

type SupportBundleExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	supportBundleExportNow               = time.Now
	supportBundleExportBuildFn           = buildSupportBundle
	supportBundleExportGetRuntimeStatus  = db.GetRuntimeStatus
	supportBundleExportUpsertRuntime     = db.UpsertRuntimeStatus
	supportBundleExportPollInterval      = 30 * time.Second
	supportBundleExportSchedulerMu       sync.Mutex
	supportBundleExportSchedulerStopChan chan struct{}
	supportBundleExportLogger            = zap.NewNop()
)

func StartSupportBundleExportScheduler(_ *config.Config, logger *zap.Logger) error {
	supportBundleExportSchedulerMu.Lock()
	if supportBundleExportSchedulerStopChan != nil {
		close(supportBundleExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	supportBundleExportSchedulerStopChan = stop
	if logger != nil {
		supportBundleExportLogger = logger
	}
	supportBundleExportSchedulerMu.Unlock()

	go supportBundleExportLoop(stop)
	return nil
}

func supportBundleExportLoop(stop <-chan struct{}) {
	runSupportBundleExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(supportBundleExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runSupportBundleExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListSupportBundleExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listSupportBundleExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := supportBundleExportGetRuntimeStatus(supportBundleExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadSupportBundleExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	targetDir := strings.TrimSpace(cfg.Telemetry.SupportBundleExports.Directory)
	if targetDir == "" {
		http.Error(w, "support bundle export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "support bundle export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !isSupportBundleExportName(name) {
		http.Error(w, "invalid support bundle export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "support bundle export not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	audit(r, "download_scheduled_support_bundle_export", name, "downloaded")
}

func runSupportBundleExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.SupportBundleExports
	now := supportBundleExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeSupportBundleExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled support bundle exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeSupportBundleExportRuntimeStatus("disabled", "Scheduled support bundle exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := supportBundleExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeSupportBundleExportRuntimeStatus("ok", "Scheduled support bundle export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	payload, filename, err := supportBundleExportBuildFn(cfg)
	if err != nil {
		_ = writeSupportBundleExportRuntimeStatus("degraded", "Scheduled support bundle export failed while building the bundle.", exportCfg, nil, now, time.Time{}, err.Error())
		supportBundleExportLogger.Warn("scheduled support bundle export build failed", zap.Error(err))
		return
	}

	artifacts, err := writeSupportBundleExportArtifacts(exportCfg, payload, filename, now)
	if err != nil {
		_ = writeSupportBundleExportRuntimeStatus("degraded", "Scheduled support bundle export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		supportBundleExportLogger.Warn("scheduled support bundle export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneSupportBundleExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		supportBundleExportLogger.Warn("scheduled support bundle export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled support bundle export wrote %d artifact(s).", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeSupportBundleExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func supportBundleExportLastRun() (time.Time, error) {
	status, err := supportBundleExportGetRuntimeStatus(supportBundleExportsComponent)
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

func writeSupportBundleExportArtifacts(exportCfg config.SupportBundleExportConfig, payload []byte, filename string, now time.Time) ([]SupportBundleExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create support bundle export directory: %w", err)
	}

	filename = supportBundleExportFilename(filename, now)
	targetPath := filepath.Join(targetDir, filename)
	if err := os.WriteFile(targetPath, payload, 0640); err != nil {
		return nil, fmt.Errorf("write support bundle export artifact %s: %w", filename, err)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("stat support bundle export artifact %s: %w", filename, err)
	}
	return []SupportBundleExportArtifact{
		{
			Name:      filename,
			Path:      targetPath,
			SizeBytes: info.Size(),
			CreatedAt: now.Format(time.RFC3339),
		},
	}, nil
}

func listSupportBundleExportArtifacts(cfg *config.Config) ([]SupportBundleExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.SupportBundleExports.Directory)
	if targetDir == "" {
		return []SupportBundleExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SupportBundleExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read support bundle export directory: %w", err)
	}

	artifacts := make([]SupportBundleExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isSupportBundleExportName(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect support bundle export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, SupportBundleExportArtifact{
			Name:      name,
			Path:      filepath.Join(targetDir, name),
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

func pruneSupportBundleExportArtifacts(exportCfg config.SupportBundleExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listSupportBundleExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{SupportBundleExports: exportCfg}})
	if err != nil {
		return err
	}
	if len(artifacts) <= exportCfg.RetentionCount {
		return nil
	}
	for _, item := range artifacts[exportCfg.RetentionCount:] {
		if err := os.Remove(item.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove support bundle export artifact %s: %w", item.Name, err)
		}
	}
	return nil
}

func writeSupportBundleExportRuntimeStatus(status, message string, exportCfg config.SupportBundleExportConfig, artifacts []SupportBundleExportArtifact, now, nextDue time.Time, warning string) error {
	details := map[string]any{
		"enabled":          exportCfg.Enabled,
		"directory":        strings.TrimSpace(exportCfg.Directory),
		"archive_type":     "zip",
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
	return supportBundleExportUpsertRuntime(supportBundleExportsComponent, status, message, details)
}

func isSupportBundleExportName(name string) bool {
	return strings.HasPrefix(name, supportBundleExportPrefix) && strings.EqualFold(filepath.Ext(name), ".zip")
}

func supportBundleExportFilename(name string, now time.Time) string {
	name = filepath.Base(strings.TrimSpace(name))
	if isSupportBundleExportName(name) {
		return name
	}
	return supportBundleExportPrefix + now.Format(supportBundleTimeStamp) + ".zip"
}
