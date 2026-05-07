package adminapi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/ha"
)

var (
	createReplicationPackageFn      = ha.CreateReplicationPackage
	importReplicationPackageFn      = ha.ImportReplicationPackage
	listStagedReplicationPackagesFn = ha.ListStagedReplicationPackages
	activateStagedReplicationFn     = ha.ActivateStagedReplicationPackage
	loadSharedReplicationStatusFn   = ha.LoadSharedReplicationStatus
	stageLatestSharedReplicationFn  = ha.StageLatestSharedReplicationPackage
	scheduleReplicationRestartFn    = scheduleReplicationRestart
	replicationRestartCommandFn     = runRestartHandoffCommand
	replicationClockFn              = time.Now
)

func HandleDownloadHAReplicationPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	packageBytes, manifest, err := createReplicationPackageFn(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filename := fmt.Sprintf("aegisnas-ha-replication-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("X-Aegis-Source-Node", manifest.SourceNode)
	w.Header().Set("X-Aegis-Source-Role", manifest.SourceRole)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packageBytes)
}

func HandleListHAReplicationPackages(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	packages, err := listStagedReplicationPackagesFn(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"packages":     packages,
		"count":        len(packages),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func HandleGetSharedHAReplicationStatus(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	shared, err := loadSharedReplicationStatusFn(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"shared":       shared,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func HandleImportHAReplicationPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	packageBytes, err := readReplicationPackageUpload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stage, err := importReplicationPackageFn(cfg, packageBytes, userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "import_ha_replication_package", stage.ID, "staged")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "staged",
		"package": stage,
	})
}

func HandleStageLatestSharedHAReplicationPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	stage, err := stageLatestSharedReplicationFn(cfg, userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "stage_shared_ha_replication_package", stage.ID, "staged")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "staged",
		"package": stage,
		"message": "Latest shared HA replication package is staged on this node.",
	})
}

func HandleActivateHAReplicationPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var payload struct {
		ID string `json:"id"`
	}
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	result, err := activateStagedReplicationFn(cfg, payload.ID, userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	restartWarning := ""
	if err := scheduleReplicationRestartFn(result.RestartServices); err != nil {
		restartWarning = err.Error()
		result.RestartScheduled = false
		summary := "Standby replication data was activated, but automatic restart handoff failed. Restart appliance services manually."
		_ = db.RecordHAHistory("replication_restart", "failed", summary, strings.TrimSpace(cfg.HighAvailability.Role), userFromRequest(r), map[string]any{
			"stage_id":         result.ID,
			"restart_services": result.RestartServices,
			"error":            restartWarning,
		})
		_ = db.UpsertRuntimeStatus(ha.ReplicationRuntimeComponent, "degraded", summary, map[string]any{
			"staged_id":           result.ID,
			"restart_services":    result.RestartServices,
			"restart_scheduled":   false,
			"restart_warning":     restartWarning,
			"restart_backup_path": result.BackupPath,
		})
	} else {
		_ = db.RecordHAHistory("replication_restart", "scheduled", "Service restart handoff queued for the activated standby package.", strings.TrimSpace(cfg.HighAvailability.Role), userFromRequest(r), map[string]any{
			"stage_id":         result.ID,
			"restart_services": result.RestartServices,
		})
	}
	audit(r, "activate_ha_replication_package", result.ID, "activated")
	message := "Standby replication data was activated. Appliance services are restarting to pick up the imported config and database."
	if restartWarning != "" {
		message = "Standby replication data was activated, but automatic restart handoff failed. Restart the listed services manually."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "activated",
		"result":          result,
		"message":         message,
		"restart_warning": restartWarning,
	})
}

func readReplicationPackageUpload(r *http.Request) ([]byte, error) {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("parse upload: %w", err)
		}
		file, _, err := r.FormFile("package")
		if err != nil {
			return nil, errors.New("replication upload must include a file field named package")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 64<<20))
		if err != nil {
			return nil, fmt.Errorf("read upload: %w", err)
		}
		return data, nil
	}
	if r.Body == nil {
		return nil, errors.New("replication upload body is empty")
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read upload: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("replication upload body is empty")
	}
	return data, nil
}

func scheduleReplicationRestart(services []string) error {
	items := normalizeRestartServices(services)
	if len(items) == 0 {
		return nil
	}
	return replicationRestartCommandFn(items)
}

func runRestartHandoffCommand(services []string) error {
	unitName := fmt.Sprintf("aegis-ha-activate-%d", replicationClockFn().UTC().UnixNano())
	script := buildReplicationRestartScript(services)
	cmd := exec.Command("systemd-run",
		"--unit", unitName,
		"--collect",
		"--property=Type=oneshot",
		"/bin/sh", "-lc", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, trimmed)
	}
	return nil
}

func buildReplicationRestartScript(services []string) string {
	args := make([]string, 0, len(services)+2)
	args = append(args, "systemctl", "restart")
	args = append(args, services...)
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return "sleep 2; exec " + strings.Join(quoted, " ")
}

func normalizeRestartServices(services []string) []string {
	items := make([]string, 0, len(services))
	for _, service := range services {
		service = strings.TrimSpace(service)
		if service == "" || slices.Contains(items, service) {
			continue
		}
		items = append(items, service)
	}
	return items
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
