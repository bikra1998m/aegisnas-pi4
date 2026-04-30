package adminapi

import (
	"encoding/json"
	"net/http"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

func HandleGetSystemSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, config.SettingsSnapshot())
}

func HandleUpdateSystemSettings(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	next, err := config.SaveSettingsMap(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit(r, "update_system_settings", config.Path(), "saved")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "saved",
		"restart_required": true,
		"config_path":      config.Path(),
		"settings":         config.SettingsSnapshot(),
		"wireless_enabled": next.Wireless.Enabled,
	})
}

func HandleEvaluateSystemSettings(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	next, err := config.EvaluateSettingsMap(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validationErr := next.Validate()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "evaluated",
		"valid":            validationErr == nil,
		"validation_error": errorString(validationErr),
		"deployment":       config.DeploymentSummary(next),
	})
}

func HandlePreviewHostapdConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	text, err := wireless.GenerateHostapdConfig(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     cfg.Wireless.Enabled,
		"path":        cfg.Wireless.HostapdConfigPath,
		"config":      text,
		"radio":       cfg.Wireless.Interface,
		"ssid_count":  len(cfg.Wireless.SSIDs),
		"restart_tip": "Write the file and restart hostapd on the appliance after saving, or use the publish action from the UI.",
	})
}

func HandleWriteHostapdConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	target, err := wireless.WriteConfig(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	audit(r, "write_hostapd_config", target, "written")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "written",
		"path":             target,
		"restart_required": true,
	})
}

func HandlePublishHostapdConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	target, err := wireless.WriteConfig(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := wireless.RestartHostapd(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "publish_hostapd_config", target, "restarted")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "published",
		"path":   target,
	})
}

func HandleApplyRadiusConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	if err := radius.ApplyConfig(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "apply_radius_config", radius.ConfigDir(), "applied")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "applied",
		"config_dir": radius.ConfigDir(),
	})
}

func HandleExportSystemSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-system-settings.json"`)
	writeJSON(w, http.StatusOK, config.SettingsSnapshot())
}

func HandleImportSystemSettings(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid settings JSON", http.StatusBadRequest)
		return
	}
	if _, err := config.SaveSettingsMap(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "import_system_settings", config.Path(), "saved")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "imported",
		"restart_required": true,
		"config_path":      config.Path(),
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
