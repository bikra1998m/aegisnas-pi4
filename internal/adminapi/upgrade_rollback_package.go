package adminapi

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

var createUpgradeRollbackPackageFn = upgrade.CreateRollbackPackage
var inspectUpgradeRollbackPackageFn = upgrade.InspectRollbackPackageBytes
var restoreUpgradeRollbackPackageFn = upgrade.RestoreRollbackPackage

func HandleDownloadUpgradeRollbackPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	payload, filename, manifest, err := createUpgradeRollbackPackageFn(cfg, config.Path())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-AegisNAS-Schema-Version", fmt.Sprintf("%d", manifest.CurrentSchemaVersion))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	audit(r, "download_upgrade_rollback_package", filename, "downloaded")
}

func HandleInspectUpgradeRollbackPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	packageBytes, filename, err := readUpgradeRollbackPackageUpload(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	inspection, err := inspectUpgradeRollbackPackageFn(packageBytes, cfg, config.Path())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"filename":   filename,
		"inspection": inspection,
	})
}

func HandleRestoreUpgradeRollbackPackage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	packageBytes, filename, err := readUpgradeRollbackPackageUpload(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	confirmationText := strings.TrimSpace(r.FormValue("confirmation_text"))
	result, err := restoreUpgradeRollbackPackageFn(cfg, config.Path(), packageBytes, confirmationText)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit(r, "restore_upgrade_rollback_package", filename, "restored")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "restored",
		"filename":             filename,
		"restart_required":     result.RestartRequired,
		"safety_package_path":  result.SafetyPackagePath,
		"database_backup_path": result.DatabaseBackupPath,
		"inspection":           result.Inspection,
	})
}

func readUpgradeRollbackPackageUpload(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		return nil, "", fmt.Errorf("invalid rollback package upload: %w", err)
	}
	file, header, err := r.FormFile("package")
	if err != nil {
		return nil, "", fmt.Errorf("rollback package file is required")
	}
	defer file.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, file, 512<<20))
	if err != nil {
		return nil, "", fmt.Errorf("rollback package upload is too large or unreadable")
	}
	return body, header.Filename, nil
}
