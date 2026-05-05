package adminapi

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/network"
	"go.uber.org/zap"
)

const (
	networkRecoveryComponent          = "edge_network_recovery"
	defaultNetworkRecoveryGracePeriod = 90 * time.Second
)

type NetworkRecoveryState struct {
	Pending            bool   `json:"pending"`
	BackupID           string `json:"backup_id,omitempty"`
	Deadline           string `json:"deadline,omitempty"`
	RemainingSeconds   int    `json:"remaining_seconds,omitempty"`
	GracePeriodSeconds int    `json:"grace_period_seconds,omitempty"`
	RiskSummary        string `json:"risk_summary,omitempty"`
	ValidationSummary  string `json:"validation_summary,omitempty"`
	Status             string `json:"status,omitempty"`
	Message            string `json:"message,omitempty"`
	RequestedBy        string `json:"requested_by,omitempty"`
	ConfirmedBy        string `json:"confirmed_by,omitempty"`
	ConfirmedAt        string `json:"confirmed_at,omitempty"`
	RolledBackAt       string `json:"rolled_back_at,omitempty"`
}

var (
	networkRecoveryNowFn        = time.Now
	networkRecoveryGracePeriod  = defaultNetworkRecoveryGracePeriod
	loadRecoverySnapshotFn      = network.LoadSnapshot
	recordNetworkApplyHistoryFn = db.RecordNetworkApplyHistory
	upsertRuntimeStatusFn       = db.UpsertRuntimeStatus
	getRuntimeStatusFn          = db.GetRuntimeStatus
	networkRecoveryMu           sync.Mutex
	networkRecoveryTimer        *time.Timer
	networkRecoveryCfg          *config.Config
	networkRecoveryLogger       = zap.NewNop()
)

func StartNetworkRecoveryMonitor(cfg *config.Config, logger *zap.Logger) error {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	networkRecoveryCfg = cfg
	if logger != nil {
		networkRecoveryLogger = logger
	}
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}

	state, err := currentNetworkRecoveryStateLocked()
	if err != nil || state == nil || !state.Pending {
		return err
	}
	return schedulePendingNetworkRecoveryLocked(*state)
}

func CurrentNetworkRecoveryState() (*NetworkRecoveryState, error) {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()
	return currentNetworkRecoveryStateLocked()
}

func ConfirmPendingNetworkRecovery(backupID, actor string) (*NetworkRecoveryState, error) {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	state, err := currentNetworkRecoveryStateLocked()
	if err != nil {
		return nil, err
	}
	if state == nil || !state.Pending {
		return nil, errors.New("no pending management-loss auto-revert is active")
	}
	if expected := strings.TrimSpace(backupID); expected != "" && state.BackupID != expected {
		return nil, fmt.Errorf("pending auto-revert is attached to snapshot %s, not %s", state.BackupID, expected)
	}
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}

	now := networkRecoveryNowFn().UTC()
	state.Pending = false
	state.RemainingSeconds = 0
	state.Status = "ok"
	state.Message = "Admin reachability was confirmed before the rollback deadline."
	state.ConfirmedBy = strings.TrimSpace(actor)
	state.ConfirmedAt = now.Format(time.RFC3339)

	if err := persistNetworkRecoveryStateLocked(*state); err != nil {
		return nil, err
	}
	_ = recordNetworkApplyHistoryFn("apply", "confirmed", state.Message, state.BackupID, "", actor, map[string]any{
		"backup_id":    state.BackupID,
		"confirmed_at": state.ConfirmedAt,
	})
	return state, nil
}

func ClearPendingNetworkRecovery(message string, details map[string]any) error {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	state, err := currentNetworkRecoveryStateLocked()
	if err != nil {
		return err
	}
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}
	if state == nil {
		return nil
	}
	state.Pending = false
	state.RemainingSeconds = 0
	state.Status = "ok"
	if strings.TrimSpace(message) != "" {
		state.Message = strings.TrimSpace(message)
	}
	return persistNetworkRecoveryStateLocked(*state)
}

func StartPendingNetworkRecovery(cfg *config.Config, backupID string, risk network.ApplyRiskAssessment, validation network.ValidationReport, actor string) (*NetworkRecoveryState, error) {
	if cfg == nil {
		return nil, errors.New("configuration not loaded")
	}

	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	networkRecoveryCfg = cfg
	deadline := networkRecoveryNowFn().Add(networkRecoveryGracePeriod).UTC()
	state := NetworkRecoveryState{
		Pending:            true,
		BackupID:           strings.TrimSpace(backupID),
		Deadline:           deadline.Format(time.RFC3339),
		RemainingSeconds:   secondsUntil(deadline),
		GracePeriodSeconds: int(networkRecoveryGracePeriod.Seconds()),
		RiskSummary:        strings.TrimSpace(risk.Summary),
		ValidationSummary:  strings.TrimSpace(validation.Summary()),
		Status:             "pending",
		Message:            "Risky edge-network changes are live. Confirm management reachability before the rollback deadline or the appliance will restore the previous snapshot automatically.",
		RequestedBy:        strings.TrimSpace(actor),
	}
	if err := persistNetworkRecoveryStateLocked(state); err != nil {
		return nil, err
	}
	if err := schedulePendingNetworkRecoveryLocked(state); err != nil {
		return nil, err
	}
	_ = recordNetworkApplyHistoryFn("apply", "pending_confirmation", state.Message, state.BackupID, "", actor, map[string]any{
		"backup_id":          state.BackupID,
		"deadline":           state.Deadline,
		"grace_period_secs":  state.GracePeriodSeconds,
		"risk_summary":       state.RiskSummary,
		"validation_summary": state.ValidationSummary,
	})
	return &state, nil
}

func currentNetworkRecoveryStateLocked() (*NetworkRecoveryState, error) {
	status, err := getRuntimeStatusFn(networkRecoveryComponent)
	if err != nil || status == nil {
		return nil, err
	}
	state := runtimeStatusToNetworkRecoveryState(*status)
	return &state, nil
}

func schedulePendingNetworkRecoveryLocked(state NetworkRecoveryState) error {
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}

	deadline, err := time.Parse(time.RFC3339, strings.TrimSpace(state.Deadline))
	if err != nil {
		return fmt.Errorf("parse network recovery deadline: %w", err)
	}
	wait := deadline.Sub(networkRecoveryNowFn())
	if wait <= 0 {
		go func(backupID string) {
			if err := expirePendingNetworkRecovery(backupID); err != nil {
				networkRecoveryLogger.Warn("failed to restore pending network recovery immediately after startup", zap.Error(err))
			}
		}(state.BackupID)
		return nil
	}

	backupID := state.BackupID
	networkRecoveryTimer = time.AfterFunc(wait, func() {
		if err := expirePendingNetworkRecovery(backupID); err != nil {
			networkRecoveryLogger.Warn("failed to auto-rollback risky network change", zap.Error(err), zap.String("backup_id", backupID))
		}
	})
	return nil
}

func expirePendingNetworkRecovery(expectedBackupID string) error {
	networkRecoveryMu.Lock()
	cfg := networkRecoveryCfg
	state, err := currentNetworkRecoveryStateLocked()
	if err != nil {
		networkRecoveryMu.Unlock()
		return err
	}
	if state == nil || !state.Pending || state.BackupID != strings.TrimSpace(expectedBackupID) {
		networkRecoveryMu.Unlock()
		return nil
	}
	if cfg == nil {
		networkRecoveryMu.Unlock()
		return errors.New("network recovery config is not initialized")
	}
	if networkRecoveryTimer != nil {
		networkRecoveryTimer.Stop()
		networkRecoveryTimer = nil
	}
	networkRecoveryMu.Unlock()

	snapshot, err := loadRecoverySnapshotFn(cfg, expectedBackupID)
	if err != nil {
		return failPendingNetworkRecovery(expectedBackupID, fmt.Sprintf("The rollback snapshot %s could not be loaded.", expectedBackupID), err)
	}
	if err := restoreNetworkSnapshotFn(cfg, snapshot); err != nil {
		return failPendingNetworkRecovery(expectedBackupID, fmt.Sprintf("Automatic rollback to snapshot %s failed.", expectedBackupID), err)
	}

	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	updated, err := currentNetworkRecoveryStateLocked()
	if err != nil {
		return err
	}
	if updated == nil {
		updated = &NetworkRecoveryState{BackupID: expectedBackupID}
	}
	updated.Pending = false
	updated.RemainingSeconds = 0
	updated.Status = "degraded"
	updated.Message = fmt.Sprintf("Risky edge-network changes were rolled back automatically after the confirmation window expired. Snapshot %s was restored.", expectedBackupID)
	updated.RolledBackAt = networkRecoveryNowFn().UTC().Format(time.RFC3339)
	if err := persistNetworkRecoveryStateLocked(*updated); err != nil {
		return err
	}
	_ = recordNetworkApplyHistoryFn("apply", "auto_rolled_back", updated.Message, expectedBackupID, expectedBackupID, "system:auto-revert", map[string]any{
		"backup_id":      expectedBackupID,
		"rolled_back_at": updated.RolledBackAt,
	})
	return nil
}

func failPendingNetworkRecovery(backupID, message string, cause error) error {
	networkRecoveryMu.Lock()
	defer networkRecoveryMu.Unlock()

	state, err := currentNetworkRecoveryStateLocked()
	if err != nil {
		return err
	}
	if state == nil {
		state = &NetworkRecoveryState{BackupID: backupID}
	}
	state.Pending = false
	state.RemainingSeconds = 0
	state.Status = "degraded"
	state.Message = fmt.Sprintf("%s %v", strings.TrimSpace(message), cause)
	if err := persistNetworkRecoveryStateLocked(*state); err != nil {
		return err
	}
	_ = recordNetworkApplyHistoryFn("apply", "auto_rollback_failed", state.Message, backupID, "", "system:auto-revert", map[string]any{
		"backup_id": backupID,
		"error":     cause.Error(),
	})
	return cause
}

func persistNetworkRecoveryStateLocked(state NetworkRecoveryState) error {
	details := map[string]any{
		"pending":              state.Pending,
		"backup_id":            state.BackupID,
		"deadline":             state.Deadline,
		"grace_period_seconds": state.GracePeriodSeconds,
		"risk_summary":         state.RiskSummary,
		"validation_summary":   state.ValidationSummary,
		"requested_by":         state.RequestedBy,
		"confirmed_by":         state.ConfirmedBy,
		"confirmed_at":         state.ConfirmedAt,
		"rolled_back_at":       state.RolledBackAt,
	}
	return upsertRuntimeStatusFn(networkRecoveryComponent, state.Status, state.Message, details)
}

func runtimeStatusToNetworkRecoveryState(status db.RuntimeStatus) NetworkRecoveryState {
	state := NetworkRecoveryState{
		Status:  strings.TrimSpace(status.Status),
		Message: strings.TrimSpace(status.Message),
	}
	if status.Details == nil {
		return state
	}
	state.Pending = boolDetail(status.Details, "pending")
	state.BackupID = stringDetail(status.Details, "backup_id")
	state.Deadline = stringDetail(status.Details, "deadline")
	state.GracePeriodSeconds = intDetail(status.Details, "grace_period_seconds")
	state.RiskSummary = stringDetail(status.Details, "risk_summary")
	state.ValidationSummary = stringDetail(status.Details, "validation_summary")
	state.RequestedBy = stringDetail(status.Details, "requested_by")
	state.ConfirmedBy = stringDetail(status.Details, "confirmed_by")
	state.ConfirmedAt = stringDetail(status.Details, "confirmed_at")
	state.RolledBackAt = stringDetail(status.Details, "rolled_back_at")
	if state.Pending && state.Deadline != "" {
		if deadline, err := time.Parse(time.RFC3339, state.Deadline); err == nil {
			state.RemainingSeconds = secondsUntil(deadline)
		}
	}
	return state
}

func secondsUntil(deadline time.Time) int {
	remaining := int(deadline.Sub(networkRecoveryNowFn()).Seconds())
	if remaining < 0 {
		return 0
	}
	return remaining
}

func stringDetail(details map[string]any, key string) string {
	value, ok := details[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func intDetail(details map[string]any, key string) int {
	value, ok := details[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" {
			return 0
		}
		parsed, _ := time.ParseDuration(text + "s")
		if parsed > 0 {
			return int(parsed.Seconds())
		}
		return 0
	}
}

func boolDetail(details map[string]any, key string) bool {
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
