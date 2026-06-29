package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

const controllerPushConfirmation = "PUSH CONTROLLER POLICY"

type controllerOperationRequest struct {
	Operation    string `json:"operation"`
	Confirmation string `json:"confirmation"`
}

func HandlePreviewControllerSync(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration is not loaded", http.StatusServiceUnavailable)
		return
	}
	operation := strings.TrimSpace(r.URL.Query().Get("operation"))
	if operation == "" {
		operation = defaultControllerOperation(cfg)
	}
	preview, err := integrations.BuildControllerSyncPreview(cfg, operation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"preview":           preview,
		"configured":        buildControllerAdapterConfiguredState(cfg),
		"push_confirmation": controllerPushConfirmation,
	})
}

func HandleRunControllerSync(w http.ResponseWriter, r *http.Request) {
	var request controllerOperationRequest
	if err := decodeBody(r, &request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration is not loaded", http.StatusServiceUnavailable)
		return
	}
	if !cfg.Integrations.Controller.Enabled {
		http.Error(w, "controller automation is disabled", http.StatusConflict)
		return
	}
	configured := buildControllerAdapterConfiguredState(cfg)
	if !configured.Ready {
		writeJSON(w, http.StatusConflict, map[string]any{
			"status": "blocked", "message": "controller integration is not ready", "warnings": configured.ReadinessWarnings,
		})
		return
	}
	operation := strings.TrimSpace(request.Operation)
	if operation == "" {
		operation = defaultControllerOperation(cfg)
	}
	preview, err := integrations.BuildControllerSyncPreview(cfg, operation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if preview.Operation == "push" && strings.TrimSpace(request.Confirmation) != controllerPushConfirmation {
		http.Error(w, "confirmation must equal "+controllerPushConfirmation, http.StatusBadRequest)
		return
	}

	startedAt := time.Now().UTC()
	result, executeErr := integrations.ExecuteControllerOperation(r.Context(), cfg, preview.Operation)
	status, message := controllerOperationOutcome(preview.Operation, result, executeErr)
	details := controllerOperationDetails(r, startedAt, result)
	_ = db.RecordIntegrationHistory(integrations.ControllerComponent(), status, message, details)
	_ = updateControllerOperationRuntime(status, message, details)
	audit(r, "controller_"+preview.Operation, message, status)

	response := map[string]any{"status": status, "message": message, "result": result}
	if executeErr != nil {
		response["error"] = executeErr.Error()
		writeJSON(w, http.StatusBadGateway, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func defaultControllerOperation(cfg *config.Config) string {
	if cfg != nil {
		mode := strings.ToLower(strings.TrimSpace(cfg.Integrations.Controller.SyncMode))
		if mode == "monitor" || mode == "pull-config" {
			return "pull"
		}
	}
	return "push"
}

func controllerOperationOutcome(operation string, result *integrations.ControllerOperationResult, err error) (string, string) {
	if err != nil {
		return "degraded", "Controller " + operation + " failed: " + err.Error()
	}
	if result != nil && (result.FailedCount > 0 || result.DriftDetected) {
		if result.DriftDetected {
			return "degraded", "Controller " + operation + " completed with detected policy drift."
		}
		return "degraded", "Controller " + operation + " completed with failed items."
	}
	return "ok", "Controller " + operation + " completed successfully."
}

func controllerOperationDetails(r *http.Request, startedAt time.Time, result *integrations.ControllerOperationResult) map[string]any {
	details := map[string]any{
		"manual": true, "actor": userFromRequest(r), "started_at": startedAt.Format(time.RFC3339),
		"duration_ms": time.Since(startedAt).Milliseconds(),
	}
	if result == nil {
		return details
	}
	details["operation"] = result.Operation
	details["adapter"] = result.Adapter
	details["request_url"] = result.TargetURL
	details["auth_scheme"] = result.AuthScheme
	details["response_status"] = result.ResponseStatus
	details["desired_state_hash"] = result.DesiredStateHash
	details["observed_state_hash"] = result.ObservedStateHash
	details["drift_detected"] = result.DriftDetected
	details["drift_count"] = result.DriftCount
	details["applied_count"] = result.AppliedCount
	details["failed_count"] = result.FailedCount
	details["controller_health"] = result.ControllerHealth
	details["compatibility_score"] = result.CompatibilityScore
	for key, value := range result.Details {
		details[key] = value
	}
	return details
}

func updateControllerOperationRuntime(status, message string, details map[string]any) error {
	previous, _ := db.GetRuntimeStatus(integrations.ControllerComponent())
	if previous != nil {
		for key, value := range previous.Details {
			if _, exists := details[key]; !exists {
				details[key] = value
			}
		}
	}
	details["sync_count"] = runtimeCounter(details, "sync_count") + 1
	if status == "ok" {
		details["success_count"] = runtimeCounter(details, "success_count") + 1
	} else {
		details["failure_count"] = runtimeCounter(details, "failure_count") + 1
	}
	details["last_manual_at"] = time.Now().UTC().Format(time.RFC3339)
	return db.UpsertRuntimeStatus(integrations.ControllerComponent(), status, message, details)
}

func runtimeCounter(details map[string]any, key string) int64 {
	switch value := details[key].(type) {
	case int:
		return int64(value)
	case int64:
		return value
	case float64:
		return int64(value)
	default:
		return 0
	}
}
