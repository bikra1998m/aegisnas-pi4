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
	networkExportsComponent      = "network_exports"
	networkApplyExportPrefix     = "aegisnas-network-apply-history-"
	dhcpLeaseHistoryExportPrefix = "aegisnas-dhcp-lease-history-"
)

type NetworkExportArtifact struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	CreatedAt string `json:"created_at"`
}

var (
	networkExportNow               = time.Now
	networkExportListApplyHistory  = db.ListNetworkApplyHistory
	networkExportListLeaseHistory  = db.ListDHCPLeaseHistory
	networkExportGetRuntimeStatus  = db.GetRuntimeStatus
	networkExportUpsertRuntime     = db.UpsertRuntimeStatus
	networkExportPollInterval      = 30 * time.Second
	networkExportSchedulerMu       sync.Mutex
	networkExportSchedulerStopChan chan struct{}
	networkExportLogger            = zap.NewNop()
)

func StartNetworkExportScheduler(_ *config.Config, logger *zap.Logger) error {
	networkExportSchedulerMu.Lock()
	if networkExportSchedulerStopChan != nil {
		close(networkExportSchedulerStopChan)
	}
	stop := make(chan struct{})
	networkExportSchedulerStopChan = stop
	if logger != nil {
		networkExportLogger = logger
	}
	networkExportSchedulerMu.Unlock()

	go networkExportLoop(stop)
	return nil
}

func networkExportLoop(stop <-chan struct{}) {
	runNetworkExportCycle(context.Background(), config.Get())

	ticker := time.NewTicker(networkExportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runNetworkExportCycle(context.Background(), config.Get())
		}
	}
}

func HandleListNetworkExports(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	exports, err := listNetworkExportArtifacts(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runtimeStatus, err := networkExportGetRuntimeStatus(networkExportsComponent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": runtimeStatus,
		"exports": exports,
	})
}

func HandleDownloadNetworkExport(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.NetworkExports.Directory)
	if targetDir == "" {
		http.Error(w, "network export directory is not configured", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "network export name is required", http.StatusBadRequest)
		return
	}
	if filepath.Base(name) != name || !isNetworkExportName(name) {
		http.Error(w, "invalid network export name", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(targetDir, name)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "network export not found", http.StatusNotFound)
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
	audit(r, "download_scheduled_network_export", name, "downloaded")
}

func runNetworkExportCycle(_ context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	exportCfg := cfg.Telemetry.NetworkExports
	now := networkExportNow().UTC()

	if !cfg.Telemetry.Enabled {
		_ = writeNetworkExportRuntimeStatus("disabled", "Telemetry is disabled, so scheduled network exports are not running.", exportCfg, nil, now, time.Time{}, "")
		return
	}
	if !exportCfg.Enabled {
		_ = writeNetworkExportRuntimeStatus("disabled", "Scheduled network exports are disabled in config.", exportCfg, nil, now, time.Time{}, "")
		return
	}

	lastExportAt, _ := networkExportLastRun()
	interval := time.Duration(exportCfg.IntervalMinutes) * time.Minute
	nextDue := now
	if !lastExportAt.IsZero() && interval > 0 {
		nextDue = lastExportAt.Add(interval)
	}
	if !lastExportAt.IsZero() && interval > 0 && now.Before(nextDue) {
		_ = writeNetworkExportRuntimeStatus("ok", "Scheduled network export is waiting for the next interval.", exportCfg, nil, now, nextDue, "")
		return
	}

	applyHistory, err := networkExportListApplyHistory(1000)
	if err != nil {
		_ = writeNetworkExportRuntimeStatus("degraded", "Scheduled network export failed while loading network apply history.", exportCfg, nil, now, time.Time{}, err.Error())
		networkExportLogger.Warn("scheduled network export apply history load failed", zap.Error(err))
		return
	}
	leaseHistory, err := networkExportListLeaseHistory(2000)
	if err != nil {
		_ = writeNetworkExportRuntimeStatus("degraded", "Scheduled network export failed while loading DHCP lease history.", exportCfg, nil, now, time.Time{}, err.Error())
		networkExportLogger.Warn("scheduled network export lease history load failed", zap.Error(err))
		return
	}

	artifacts, err := writeNetworkExportArtifacts(exportCfg, applyHistory, leaseHistory, now)
	if err != nil {
		_ = writeNetworkExportRuntimeStatus("degraded", "Scheduled network export failed while writing artifacts.", exportCfg, nil, now, time.Time{}, err.Error())
		networkExportLogger.Warn("scheduled network export write failed", zap.Error(err))
		return
	}

	cleanupWarning := ""
	if err := pruneNetworkExportArtifacts(exportCfg); err != nil {
		cleanupWarning = err.Error()
		networkExportLogger.Warn("scheduled network export cleanup failed", zap.Error(err))
	}

	nextDue = now.Add(interval)
	message := fmt.Sprintf("Scheduled network export wrote %d artifact(s) for apply and DHCP lease history.", len(artifacts))
	if cleanupWarning != "" {
		message += " Retention cleanup needs attention."
	}
	_ = writeNetworkExportRuntimeStatus("ok", message, exportCfg, artifacts, now, nextDue, cleanupWarning)
}

func networkExportLastRun() (time.Time, error) {
	status, err := networkExportGetRuntimeStatus(networkExportsComponent)
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

func writeNetworkExportArtifacts(exportCfg config.DiagnosticsExportConfig, applyHistory []db.NetworkApplyHistoryRecord, leaseHistory []db.DHCPLeaseHistoryRecord, now time.Time) ([]NetworkExportArtifact, error) {
	targetDir := strings.TrimSpace(exportCfg.Directory)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("create network export directory: %w", err)
	}

	formats := scheduledExportFormats(exportCfg.Format)
	artifacts := make([]NetworkExportArtifact, 0, len(formats)*2)
	for _, format := range formats {
		specs := []struct {
			kind    string
			prefix  string
			buildFn func() ([]byte, error)
		}{
			{
				kind:   "network_apply_history",
				prefix: networkApplyExportPrefix,
				buildFn: func() ([]byte, error) {
					if format == "json" {
						return networkApplyHistoryJSONPayload(applyHistory)
					}
					return networkApplyHistoryCSV(applyHistory)
				},
			},
			{
				kind:   "dhcp_lease_history",
				prefix: dhcpLeaseHistoryExportPrefix,
				buildFn: func() ([]byte, error) {
					if format == "json" {
						return dhcpLeaseHistoryJSONPayload(leaseHistory)
					}
					return dhcpLeaseHistoryCSV(leaseHistory)
				},
			},
		}
		for _, spec := range specs {
			filename := spec.prefix + now.Format("20060102-150405Z") + "." + format
			targetPath := filepath.Join(targetDir, filename)
			payload, err := spec.buildFn()
			if err != nil {
				return nil, fmt.Errorf("encode %s export %s: %w", spec.kind, format, err)
			}
			if err := os.WriteFile(targetPath, payload, 0640); err != nil {
				return nil, fmt.Errorf("write network export artifact %s: %w", filename, err)
			}
			info, err := os.Stat(targetPath)
			if err != nil {
				return nil, fmt.Errorf("stat network export artifact %s: %w", filename, err)
			}
			artifacts = append(artifacts, NetworkExportArtifact{
				Name:      filename,
				Path:      targetPath,
				Kind:      spec.kind,
				Format:    format,
				SizeBytes: info.Size(),
				CreatedAt: now.Format(time.RFC3339),
			})
		}
	}
	return artifacts, nil
}

func listNetworkExportArtifacts(cfg *config.Config) ([]NetworkExportArtifact, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	targetDir := strings.TrimSpace(cfg.Telemetry.NetworkExports.Directory)
	if targetDir == "" {
		return []NetworkExportArtifact{}, nil
	}
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []NetworkExportArtifact{}, nil
		}
		return nil, fmt.Errorf("read network export directory: %w", err)
	}

	artifacts := make([]NetworkExportArtifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isNetworkExportName(name) {
			continue
		}
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
		if format != "json" && format != "csv" {
			continue
		}
		kind := networkExportKindFromName(name)
		if kind == "" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect network export artifact %s: %w", name, err)
		}
		artifacts = append(artifacts, NetworkExportArtifact{
			Name:      name,
			Path:      filepath.Join(targetDir, name),
			Kind:      kind,
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

func pruneNetworkExportArtifacts(exportCfg config.DiagnosticsExportConfig) error {
	if exportCfg.RetentionCount <= 0 {
		return nil
	}
	artifacts, err := listNetworkExportArtifacts(&config.Config{Telemetry: config.TelemetryConfig{NetworkExports: exportCfg}})
	if err != nil {
		return err
	}

	byKindAndFormat := map[string][]NetworkExportArtifact{}
	for _, artifact := range artifacts {
		key := artifact.Kind + ":" + artifact.Format
		byKindAndFormat[key] = append(byKindAndFormat[key], artifact)
	}
	for key, items := range byKindAndFormat {
		if len(items) <= exportCfg.RetentionCount {
			continue
		}
		for _, item := range items[exportCfg.RetentionCount:] {
			if err := os.Remove(item.Path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove network export artifact %s (%s): %w", item.Name, key, err)
			}
		}
	}
	return nil
}

func writeNetworkExportRuntimeStatus(status, message string, exportCfg config.DiagnosticsExportConfig, artifacts []NetworkExportArtifact, now, nextDue time.Time, warning string) error {
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
		kinds := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			paths = append(paths, artifact.Path)
			names = append(names, artifact.Name)
			kinds = append(kinds, artifact.Kind)
		}
		details["last_export_at"] = artifacts[0].CreatedAt
		details["last_export_paths"] = paths
		details["last_export_names"] = names
		details["last_export_kinds"] = kinds
		details["artifact_count"] = len(artifacts)
	}
	if warning != "" {
		details["warning"] = warning
	}
	return networkExportUpsertRuntime(networkExportsComponent, status, message, details)
}

func isNetworkExportName(name string) bool {
	return strings.HasPrefix(name, networkApplyExportPrefix) || strings.HasPrefix(name, dhcpLeaseHistoryExportPrefix)
}

func networkExportKindFromName(name string) string {
	switch {
	case strings.HasPrefix(name, networkApplyExportPrefix):
		return "network_apply_history"
	case strings.HasPrefix(name, dhcpLeaseHistoryExportPrefix):
		return "dhcp_lease_history"
	default:
		return ""
	}
}
