package ha

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const (
	PostFailoverRecoveryComponent       = "ha_post_failover_recovery"
	defaultPostFailoverValidationWindow = 45 * time.Second
	defaultPostFailoverRetryInterval    = 2 * time.Second
)

type PostFailoverRecoveryState struct {
	Pending              bool     `json:"pending"`
	StageID              string   `json:"stage_id,omitempty"`
	BackupPath           string   `json:"backup_path,omitempty"`
	RestartServices      []string `json:"restart_services,omitempty"`
	RequestedBy          string   `json:"requested_by,omitempty"`
	RequestedAt          string   `json:"requested_at,omitempty"`
	ValidatedAt          string   `json:"validated_at,omitempty"`
	RolledBackAt         string   `json:"rolled_back_at,omitempty"`
	LastValidationStatus string   `json:"last_validation_status,omitempty"`
	LastValidationError  string   `json:"last_validation_error,omitempty"`
	Status               string   `json:"status,omitempty"`
	Message              string   `json:"message,omitempty"`
}

type PostFailoverValidationReport struct {
	Healthy         bool                `json:"healthy"`
	Summary         string              `json:"summary"`
	Checks          []PostFailoverCheck `json:"checks,omitempty"`
	UnhealthyChecks []PostFailoverCheck `json:"unhealthy_checks,omitempty"`
	ObservedAt      string              `json:"observed_at,omitempty"`
	Meta            map[string]any      `json:"meta,omitempty"`
}

type PostFailoverCheck struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

var (
	postFailoverNowFn                   = time.Now
	postFailoverValidationWindow        = defaultPostFailoverValidationWindow
	postFailoverRetryInterval           = defaultPostFailoverRetryInterval
	postFailoverGetRuntimeStatusFn      = db.GetRuntimeStatus
	postFailoverUpsertRuntimeStatusFn   = db.UpsertRuntimeStatus
	postFailoverRecordHAHistoryFn       = db.RecordHAHistory
	postFailoverRestoreBackupFn         = RestoreReplicationBackup
	postFailoverScheduleRestartFn       = ScheduleServiceRestart
	postFailoverValidateServicesFn      = validatePostFailoverServices
	postFailoverSystemdStatusFn         = postFailoverSystemdServiceStatus
	postFailoverHTTPHealthFn            = postFailoverHTTPHealthCheck
	postFailoverServiceValidationClient = &http.Client{Timeout: 1500 * time.Millisecond}
)

func BeginPostFailoverHealthRecovery(cfg *config.Config, result ActivationResult, actor string) error {
	if cfg == nil {
		return errors.New("post-failover recovery requires config")
	}
	state := PostFailoverRecoveryState{
		Pending:         true,
		StageID:         strings.TrimSpace(result.ID),
		BackupPath:      strings.TrimSpace(result.BackupPath),
		RestartServices: normalizeRestartServices(result.RestartServices),
		RequestedBy:     strings.TrimSpace(actor),
		RequestedAt:     postFailoverNowFn().UTC().Format(time.RFC3339),
		Status:          "pending",
		Message:         "Standby failover activation is restarting core services. Appliance health will be verified before the promoted node keeps serving traffic.",
	}
	if state.RequestedBy == "" {
		state.RequestedBy = "system"
	}
	if strings.TrimSpace(state.BackupPath) == "" {
		return errors.New("post-failover recovery requires an activation backup path")
	}
	if err := persistPostFailoverRecoveryState(state); err != nil {
		return err
	}
	_ = postFailoverRecordHAHistoryFn("post_failover_validation", "pending", state.Message, standbyRole(cfg), state.RequestedBy, map[string]any{
		"stage_id":         state.StageID,
		"backup_path":      state.BackupPath,
		"restart_services": state.RestartServices,
	})
	return nil
}

func ClearPostFailoverHealthRecovery(message string, details map[string]any) error {
	state := PostFailoverRecoveryState{
		Pending: false,
		Status:  "ok",
		Message: strings.TrimSpace(message),
	}
	if state.Message == "" {
		state.Message = "Post-failover recovery state cleared."
	}
	if len(details) > 0 {
		if status := strings.TrimSpace(fmt.Sprint(details["status"])); status != "" {
			state.Status = status
		}
	}
	if err := persistPostFailoverRecoveryState(state); err != nil {
		return err
	}
	if len(details) > 0 {
		_ = postFailoverRecordHAHistoryFn("post_failover_validation", "cleared", state.Message, "", "", details)
	}
	return nil
}

func ResumePendingPostFailoverRecovery(ctx context.Context, cfg *config.Config, logger *zap.Logger) (bool, error) {
	if cfg == nil || !cfg.HighAvailability.Enabled {
		return false, nil
	}
	state, err := currentPostFailoverRecoveryState()
	if err != nil {
		return false, err
	}
	if state == nil || !state.Pending {
		return false, nil
	}

	restartScheduled, err := runPendingPostFailoverRecovery(ctx, cfg, *state, logger)
	return restartScheduled, err
}

func currentPostFailoverRecoveryState() (*PostFailoverRecoveryState, error) {
	status, err := postFailoverGetRuntimeStatusFn(PostFailoverRecoveryComponent)
	if err != nil || status == nil {
		return nil, err
	}
	state := runtimeStatusToPostFailoverRecoveryState(*status)
	return &state, nil
}

func runPendingPostFailoverRecovery(ctx context.Context, cfg *config.Config, state PostFailoverRecoveryState, logger *zap.Logger) (bool, error) {
	role := standbyRole(cfg)
	if strings.TrimSpace(role) == "" {
		role = "standby"
	}
	state.Status = "pending"
	state.Message = "Validating promoted standby health after failover restart."
	if err := persistPostFailoverRecoveryState(state); err != nil {
		return false, err
	}

	report, err := waitForPostFailoverHealth(ctx, cfg, state.RestartServices)
	if err == nil && report.Healthy {
		now := postFailoverNowFn().UTC().Format(time.RFC3339)
		state.Pending = false
		state.Status = "ok"
		state.Message = "Promoted standby passed post-failover health validation."
		state.ValidatedAt = now
		state.LastValidationStatus = "validated"
		state.LastValidationError = ""
		if err := persistPostFailoverRecoveryState(state); err != nil {
			return false, err
		}
		_ = postFailoverRecordHAHistoryFn("post_failover_validation", "validated", state.Message, role, "", map[string]any{
			"stage_id":         state.StageID,
			"backup_path":      state.BackupPath,
			"restart_services": state.RestartServices,
			"report":           report,
		})
		return false, nil
	}

	validationError := ""
	if err != nil {
		validationError = err.Error()
	}
	if validationError == "" && !report.Healthy {
		validationError = report.Summary
	}

	result, restoreErr := postFailoverRestoreBackupFn(cfg, state.BackupPath, "ha-post-failover-rollback")
	if restoreErr != nil {
		state.Pending = false
		state.Status = "degraded"
		state.Message = "Promoted standby failed health validation, and the standby rollback bundle could not be restored automatically."
		state.LastValidationStatus = "rollback_failed"
		state.LastValidationError = strings.TrimSpace(joinMessages(validationError, restoreErr.Error()))
		if err := persistPostFailoverRecoveryState(state); err != nil {
			return false, err
		}
		_ = postFailoverRecordHAHistoryFn("post_failover_validation", "rollback_failed", state.Message, role, "", map[string]any{
			"stage_id":         state.StageID,
			"backup_path":      state.BackupPath,
			"restart_services": state.RestartServices,
			"validation_error": validationError,
			"rollback_error":   restoreErr.Error(),
			"report":           report,
		})
		return false, restoreErr
	}

	if restartErr := postFailoverScheduleRestartFn(result.RestartServices); restartErr != nil {
		state.Pending = false
		state.Status = "degraded"
		state.Message = "Standby rollback bundle was restored after failed failover validation, but the restart handoff did not succeed."
		state.LastValidationStatus = "rollback_restart_failed"
		state.LastValidationError = strings.TrimSpace(joinMessages(validationError, restartErr.Error()))
		if err := persistPostFailoverRecoveryState(state); err != nil {
			return false, err
		}
		_ = postFailoverRecordHAHistoryFn("post_failover_validation", "rollback_restart_failed", state.Message, role, "", map[string]any{
			"stage_id":                state.StageID,
			"backup_path":             state.BackupPath,
			"restart_services":        result.RestartServices,
			"validation_error":        validationError,
			"rollback_restart_error":  restartErr.Error(),
			"rollback_activation_id":  result.ID,
			"rollback_activation_msg": result.Summary,
			"report":                  report,
		})
		return false, restartErr
	}

	now := postFailoverNowFn().UTC().Format(time.RFC3339)
	state.Pending = false
	state.Status = "degraded"
	state.Message = "Promoted standby failed health validation. The last known-good standby bundle was restored and services are restarting."
	state.RolledBackAt = now
	state.LastValidationStatus = "rolled_back"
	state.LastValidationError = validationError
	if err := persistPostFailoverRecoveryState(state); err != nil {
		return false, err
	}
	_ = postFailoverRecordHAHistoryFn("post_failover_validation", "rolled_back", state.Message, role, "", map[string]any{
		"stage_id":                state.StageID,
		"backup_path":             state.BackupPath,
		"restart_services":        result.RestartServices,
		"validation_error":        validationError,
		"rollback_activation_id":  result.ID,
		"rollback_activation_msg": result.Summary,
		"report":                  report,
	})
	if logger != nil {
		logger.Warn("post-failover health validation failed; restored standby rollback bundle",
			zap.String("stage_id", state.StageID),
			zap.String("backup_path", state.BackupPath),
			zap.String("validation_error", validationError))
	}
	return true, nil
}

func waitForPostFailoverHealth(ctx context.Context, cfg *config.Config, services []string) (PostFailoverValidationReport, error) {
	deadline := postFailoverNowFn().Add(postFailoverValidationWindow)
	for {
		report := postFailoverValidateServicesFn(cfg, services)
		if report.Healthy {
			return report, nil
		}
		if ctx != nil {
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			default:
			}
		}
		if !postFailoverNowFn().Before(deadline) {
			if strings.TrimSpace(report.Summary) == "" {
				report.Summary = "Core standby services did not become healthy before the post-failover deadline."
			}
			return report, errors.New(report.Summary)
		}
		time.Sleep(postFailoverRetryInterval)
	}
}

func validatePostFailoverServices(cfg *config.Config, services []string) PostFailoverValidationReport {
	report := PostFailoverValidationReport{
		Healthy:    true,
		ObservedAt: postFailoverNowFn().UTC().Format(time.RFC3339),
		Meta:       map[string]any{},
	}
	items := normalizeRestartServices(services)
	if len(items) == 0 {
		items = []string{"aegis-gateway", "aegis-admin-api", "aegis-portal", "aegis-session", "aegis-policy", "aegis-radius"}
	}
	for _, service := range items {
		check := postFailoverSystemdStatusFn(service)
		report.Checks = append(report.Checks, check)
		if check.Status != "ok" {
			report.Healthy = false
			report.UnhealthyChecks = append(report.UnhealthyChecks, check)
			continue
		}
		if url, ok := postFailoverHealthURL(cfg, service); ok {
			healthCheck := postFailoverHTTPHealthFn(service, url)
			report.Checks = append(report.Checks, healthCheck)
			if healthCheck.Status != "ok" {
				report.Healthy = false
				report.UnhealthyChecks = append(report.UnhealthyChecks, healthCheck)
			}
		}
	}
	if report.Healthy {
		report.Summary = fmt.Sprintf("Validated %d core post-failover service checks.", len(report.Checks))
		return report
	}
	issues := make([]string, 0, len(report.UnhealthyChecks))
	for _, check := range report.UnhealthyChecks {
		if check.Message != "" {
			issues = append(issues, fmt.Sprintf("%s (%s)", check.Name, check.Message))
		} else {
			issues = append(issues, check.Name)
		}
	}
	report.Summary = "Core standby services are not healthy after failover restart: " + strings.Join(issues, "; ")
	return report
}

func postFailoverSystemdServiceStatus(service string) PostFailoverCheck {
	output, err := exec.Command("systemctl", "is-active", service).CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		if trimmed == "" {
			trimmed = err.Error()
		}
		return PostFailoverCheck{Name: service, Kind: "systemd", Status: "down", Message: trimmed}
	}
	if trimmed != "active" {
		return PostFailoverCheck{Name: service, Kind: "systemd", Status: "degraded", Message: trimmed}
	}
	return PostFailoverCheck{Name: service, Kind: "systemd", Status: "ok", Message: trimmed}
}

func postFailoverHTTPHealthCheck(service, url string) PostFailoverCheck {
	resp, err := postFailoverServiceValidationClient.Get(url)
	if err != nil {
		return PostFailoverCheck{Name: service, Kind: "http", Status: "down", Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PostFailoverCheck{Name: service, Kind: "http", Status: "degraded", Message: resp.Status}
	}
	return PostFailoverCheck{Name: service, Kind: "http", Status: "ok", Message: resp.Status}
}

func postFailoverHealthURL(cfg *config.Config, service string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	switch service {
	case "aegis-gateway":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port), true
	case "aegis-admin-api":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.AdminPort), true
	case "aegis-portal":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Portal.Port), true
	case "aegis-policy":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port+2), true
	case "aegis-ai-lite":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port+4), true
	case "aegis-radius":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port+5), true
	case "aegis-telemetry":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port+6), true
	case "aegis-session":
		return fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Health.Port+7), true
	default:
		return "", false
	}
}

func persistPostFailoverRecoveryState(state PostFailoverRecoveryState) error {
	details := map[string]any{
		"pending":                state.Pending,
		"stage_id":               state.StageID,
		"backup_path":            state.BackupPath,
		"restart_services":       state.RestartServices,
		"requested_by":           state.RequestedBy,
		"requested_at":           state.RequestedAt,
		"validated_at":           state.ValidatedAt,
		"rolled_back_at":         state.RolledBackAt,
		"last_validation_status": state.LastValidationStatus,
		"last_validation_error":  state.LastValidationError,
	}
	return postFailoverUpsertRuntimeStatusFn(PostFailoverRecoveryComponent, state.Status, state.Message, details)
}

func runtimeStatusToPostFailoverRecoveryState(status db.RuntimeStatus) PostFailoverRecoveryState {
	state := PostFailoverRecoveryState{
		Status:  strings.TrimSpace(status.Status),
		Message: strings.TrimSpace(status.Message),
	}
	if status.Details == nil {
		return state
	}
	state.Pending = boolDetailValue(status.Details, "pending")
	state.StageID = stringDetailValue(status.Details, "stage_id")
	state.BackupPath = stringDetailValue(status.Details, "backup_path")
	state.RequestedBy = stringDetailValue(status.Details, "requested_by")
	state.RequestedAt = stringDetailValue(status.Details, "requested_at")
	state.ValidatedAt = stringDetailValue(status.Details, "validated_at")
	state.RolledBackAt = stringDetailValue(status.Details, "rolled_back_at")
	state.LastValidationStatus = stringDetailValue(status.Details, "last_validation_status")
	state.LastValidationError = stringDetailValue(status.Details, "last_validation_error")
	if raw, ok := status.Details["restart_services"].([]any); ok {
		for _, item := range raw {
			service := strings.TrimSpace(fmt.Sprint(item))
			if service != "" {
				state.RestartServices = append(state.RestartServices, service)
			}
		}
	}
	return state
}

func joinMessages(parts ...string) string {
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			items = append(items, part)
		}
	}
	return strings.Join(items, "; ")
}

func stringDetailValue(details map[string]any, key string) string {
	value, ok := details[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func boolDetailValue(details map[string]any, key string) bool {
	value, ok := details[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return strings.EqualFold(strings.TrimSpace(fmt.Sprint(value)), "true")
	}
}
