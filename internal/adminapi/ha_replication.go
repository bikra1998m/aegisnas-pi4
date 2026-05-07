package adminapi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/ha"
)

var (
	createReplicationPackageFn      = ha.CreateReplicationPackage
	importReplicationPackageFn      = ha.ImportReplicationPackage
	listStagedReplicationPackagesFn = ha.ListStagedReplicationPackages
	activateStagedReplicationFn     = ha.ActivateStagedReplicationPackage
	loadSharedReplicationStatusFn   = ha.LoadSharedReplicationStatus
	stageLatestSharedReplicationFn  = ha.StageLatestSharedReplicationPackage
	scheduleActivationRestartFn     = ha.ScheduleActivationRestart
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
	if err := scheduleActivationRestartFn(cfg, result, userFromRequest(r)); err != nil {
		restartWarning = err.Error()
		result.RestartScheduled = false
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
