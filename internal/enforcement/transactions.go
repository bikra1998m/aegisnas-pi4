package enforcement

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

const (
	AtomicEnforcementSchemaVersion = 1
	atomicEnforcementComponent     = "enforcement_transactions"
)

var atomicEnforcementMu sync.Mutex

var (
	atomicRuntimeFirewallApplyFn = func(ctx context.Context, cfg *config.Config, actor string) (AtomicEnforcementStep, error) {
		result, err := ApplyRuntimeFirewall(actor, "apply")
		step := AtomicEnforcementStep{
			Target:             "runtime_firewall",
			Operation:          "apply",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.RulesetFingerprint,
			DesiredFingerprint: result.Plan.RulesetFingerprint,
			RollbackSupported:  result.PreviousSnapshotID != "",
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicRuntimeFirewallRollbackFn = func(ctx context.Context, cfg *config.Config, snapshotID, actor string) (AtomicEnforcementStep, error) {
		result, err := RollbackRuntimeFirewall(snapshotID, actor)
		step := AtomicEnforcementStep{
			Target:             "runtime_firewall",
			Operation:          "rollback",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			RestoredSnapshotID: result.RestoredSnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.RulesetFingerprint,
			DesiredFingerprint: result.Plan.RulesetFingerprint,
			RollbackSupported:  true,
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicRuntimeQoSApplyFn = func(ctx context.Context, cfg *config.Config, actor string) (AtomicEnforcementStep, error) {
		result, err := ApplyRuntimeQoS(cfg, actor, "apply")
		step := AtomicEnforcementStep{
			Target:             "runtime_qos",
			Operation:          "apply",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.PlanFingerprint,
			DesiredFingerprint: result.Plan.PlanFingerprint,
			RollbackSupported:  result.PreviousSnapshotID != "",
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicRuntimeQoSRollbackFn = func(ctx context.Context, cfg *config.Config, snapshotID, actor string) (AtomicEnforcementStep, error) {
		result, err := RollbackRuntimeQoS(snapshotID, actor)
		step := AtomicEnforcementStep{
			Target:             "runtime_qos",
			Operation:          "rollback",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			RestoredSnapshotID: result.RestoredSnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.PlanFingerprint,
			DesiredFingerprint: result.Plan.PlanFingerprint,
			RollbackSupported:  true,
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicVLANLifecycleApplyFn = func(ctx context.Context, cfg *config.Config, actor string) (AtomicEnforcementStep, error) {
		result, err := ApplyVLANLifecycle(cfg, actor, "apply")
		step := AtomicEnforcementStep{
			Target:             "vlan_lifecycle",
			Operation:          "apply",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.PlanFingerprint,
			DesiredFingerprint: result.Plan.PlanFingerprint,
			RollbackSupported:  result.PreviousSnapshotID != "",
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicVLANLifecycleRollbackFn = func(ctx context.Context, cfg *config.Config, snapshotID, actor string) (AtomicEnforcementStep, error) {
		result, err := RollbackVLANLifecycle(snapshotID, actor)
		step := AtomicEnforcementStep{
			Target:             "vlan_lifecycle",
			Operation:          "rollback",
			Status:             result.Status,
			SnapshotID:         result.SnapshotID,
			RestoredSnapshotID: result.RestoredSnapshotID,
			PreviousSnapshotID: result.PreviousSnapshotID,
			ActiveFingerprint:  result.Plan.PlanFingerprint,
			DesiredFingerprint: result.Plan.PlanFingerprint,
			RollbackSupported:  true,
			Message:            result.Message,
			Details: map[string]any{
				"event_id": result.EventID,
				"summary":  result.Plan.Summary,
			},
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		}
		return step, err
	}
	atomicControllerApplyFn = func(ctx context.Context, cfg *config.Config, actor string) (AtomicEnforcementStep, error) {
		result, err := integrations.ExecuteControllerOperation(ctx, cfg, "push")
		step := AtomicEnforcementStep{
			Target:             "controller_sync",
			Operation:          "apply",
			Status:             "applied",
			DesiredFingerprint: "",
			RollbackSupported:  false,
			Message:            "Controller policy synchronization applied.",
			Details: map[string]any{
				"actor": actor,
			},
		}
		if result != nil {
			step.DesiredFingerprint = strings.TrimSpace(result.DesiredStateHash)
			step.ActiveFingerprint = strings.TrimSpace(firstNonEmptyAtomicString(result.ObservedStateHash, result.DesiredStateHash))
			if result.DriftDetected {
				step.Status = "degraded"
				step.DriftStatus = "drifted"
				step.Message = fmt.Sprintf("Controller policy sync completed with %d drift item(s).", result.DriftCount)
			}
			if result.FailedCount > 0 {
				step.Status = "failed"
				step.Message = fmt.Sprintf("Controller policy sync reported %d failed item(s).", result.FailedCount)
			}
			step.Details["result"] = result
		}
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
			if step.Message == "" {
				step.Message = err.Error()
			}
		}
		return step, err
	}
)

type AtomicEnforcementRequest struct {
	Targets        []string `json:"targets,omitempty"`
	TransactionID  string   `json:"transaction_id,omitempty"`
	Confirmation   string   `json:"confirmation,omitempty"`
	SkipDriftCheck bool     `json:"skip_drift_check,omitempty"`
}

type AtomicEnforcementDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Target   string `json:"target,omitempty"`
	Message  string `json:"message"`
}

type AtomicEnforcementTargetPlan struct {
	Target              string         `json:"target"`
	Label               string         `json:"label"`
	Domain              string         `json:"domain"`
	Enabled             bool           `json:"enabled"`
	Status              string         `json:"status"`
	Message             string         `json:"message"`
	DesiredFingerprint  string         `json:"desired_fingerprint,omitempty"`
	ActiveFingerprint   string         `json:"active_fingerprint,omitempty"`
	ActiveSnapshotID    string         `json:"active_snapshot_id,omitempty"`
	PreviousSnapshotID  string         `json:"previous_snapshot_id,omitempty"`
	RollbackSupported   bool           `json:"rollback_supported"`
	ApplyRequired       bool           `json:"apply_required"`
	DriftStatus         string         `json:"drift_status"`
	DriftMessage        string         `json:"drift_message,omitempty"`
	Local               bool           `json:"local"`
	Controller          bool           `json:"controller"`
	Dependencies        []string       `json:"dependencies,omitempty"`
	Diagnostics         []string       `json:"diagnostics,omitempty"`
	Details             map[string]any `json:"details,omitempty"`
	ExternalValidation  []string       `json:"external_validation,omitempty"`
	CompensationSupport string         `json:"compensation_support"`
}

type AtomicEnforcementSummary struct {
	TargetCount       int `json:"target_count"`
	EnabledTargets    int `json:"enabled_targets"`
	LocalTargets      int `json:"local_targets"`
	ControllerTargets int `json:"controller_targets"`
	ReadyTargets      int `json:"ready_targets"`
	DegradedTargets   int `json:"degraded_targets"`
	BlockedTargets    int `json:"blocked_targets"`
	SkippedTargets    int `json:"skipped_targets"`
	ApplyRequired     int `json:"apply_required"`
	RollbackAvailable int `json:"rollback_available"`
	DriftedTargets    int `json:"drifted_targets"`
	UnknownDrift      int `json:"unknown_drift"`
}

type AtomicEnforcementPlan struct {
	SchemaVersion   int                           `json:"schema_version"`
	Status          string                        `json:"status"`
	Message         string                        `json:"message"`
	GeneratedAt     string                        `json:"generated_at"`
	Summary         AtomicEnforcementSummary      `json:"summary"`
	Targets         []AtomicEnforcementTargetPlan `json:"targets"`
	Diagnostics     []AtomicEnforcementDiagnostic `json:"diagnostics,omitempty"`
	PlanFingerprint string                        `json:"plan_fingerprint"`
	RFCs            []string                      `json:"rfcs"`
	Capabilities    []string                      `json:"capabilities"`
}

type AtomicEnforcementStep struct {
	StepOrder          int            `json:"step_order"`
	Target             string         `json:"target"`
	Operation          string         `json:"operation"`
	Status             string         `json:"status"`
	DesiredFingerprint string         `json:"desired_fingerprint,omitempty"`
	ActiveFingerprint  string         `json:"active_fingerprint,omitempty"`
	ActiveSnapshotID   string         `json:"active_snapshot_id,omitempty"`
	PreviousSnapshotID string         `json:"previous_snapshot_id,omitempty"`
	SnapshotID         string         `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string         `json:"restored_snapshot_id,omitempty"`
	RollbackSupported  bool           `json:"rollback_supported"`
	DriftStatus        string         `json:"drift_status,omitempty"`
	Message            string         `json:"message,omitempty"`
	Error              string         `json:"error,omitempty"`
	Details            map[string]any `json:"details,omitempty"`
	StartedAt          string         `json:"started_at,omitempty"`
	CompletedAt        string         `json:"completed_at,omitempty"`
}

type AtomicEnforcementDriftFinding struct {
	Target             string         `json:"target"`
	Status             string         `json:"status"`
	DesiredFingerprint string         `json:"desired_fingerprint,omitempty"`
	ActiveFingerprint  string         `json:"active_fingerprint,omitempty"`
	ActiveSnapshotID   string         `json:"active_snapshot_id,omitempty"`
	Message            string         `json:"message"`
	Details            map[string]any `json:"details,omitempty"`
}

type AtomicEnforcementResult struct {
	TransactionID string                          `json:"transaction_id"`
	Operation     string                          `json:"operation"`
	Status        string                          `json:"status"`
	Message       string                          `json:"message"`
	Plan          AtomicEnforcementPlan           `json:"plan"`
	Steps         []AtomicEnforcementStep         `json:"steps,omitempty"`
	Drift         []AtomicEnforcementDriftFinding `json:"drift,omitempty"`
	StartedAt     string                          `json:"started_at"`
	CompletedAt   string                          `json:"completed_at"`
}

type atomicParticipant struct {
	target   string
	apply    func(context.Context, *config.Config, string) (AtomicEnforcementStep, error)
	rollback func(context.Context, *config.Config, string, string) (AtomicEnforcementStep, error)
}

func BuildAtomicEnforcementPlan(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest) (AtomicEnforcementPlan, error) {
	if cfg == nil {
		return AtomicEnforcementPlan{}, fmt.Errorf("config is required")
	}
	targets := atomicTargetOrder(cfg, req.Targets)
	plan := AtomicEnforcementPlan{
		SchemaVersion: AtomicEnforcementSchemaVersion,
		Status:        "ready",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176"},
		Capabilities: []string{
			"single-operation-ledger",
			"preflight-preview",
			"reverse-order-compensation",
			"drift-detection",
			"rollback-evidence",
			"controller-sync-participant",
			"HA-safe-history",
		},
	}
	if !cfg.Policy.EnforcementTransactions.Enabled {
		plan.Status = "skipped"
		plan.Message = "Atomic enforcement transactions are disabled by policy config."
		for _, target := range targets {
			plan.Targets = append(plan.Targets, skippedAtomicTarget(target, "Atomic enforcement transactions are disabled."))
		}
		finalizeAtomicEnforcementPlan(&plan)
		return plan, nil
	}
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return AtomicEnforcementPlan{}, ctx.Err()
		default:
		}
		targetPlan, err := previewAtomicTarget(ctx, cfg, target)
		if err != nil {
			targetPlan = blockedAtomicTarget(target, err.Error())
			plan.Diagnostics = append(plan.Diagnostics, AtomicEnforcementDiagnostic{Severity: "error", Code: "target_preview_failed", Target: target, Message: err.Error()})
		}
		plan.Targets = append(plan.Targets, targetPlan)
	}
	finalizeAtomicEnforcementPlan(&plan)
	return plan, nil
}

func PreviewAtomicEnforcement(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest, actor string) (AtomicEnforcementResult, error) {
	started := time.Now().UTC()
	plan, err := BuildAtomicEnforcementPlan(ctx, cfg, req)
	if err != nil {
		return AtomicEnforcementResult{}, err
	}
	completed := time.Now().UTC()
	result := AtomicEnforcementResult{
		TransactionID: newAtomicEnforcementID("enf-preview"),
		Operation:     "preview",
		Status:        "previewed",
		Message:       plan.Message,
		Plan:          plan,
		StartedAt:     started.Format(time.RFC3339),
		CompletedAt:   completed.Format(time.RFC3339),
	}
	if plan.Status == "blocked" {
		result.Status = "blocked"
	}
	for i, target := range plan.Targets {
		result.Steps = append(result.Steps, AtomicEnforcementStep{
			StepOrder:          i + 1,
			Target:             target.Target,
			Operation:          "preview",
			Status:             targetPlanStepStatus(target),
			DesiredFingerprint: target.DesiredFingerprint,
			ActiveFingerprint:  target.ActiveFingerprint,
			ActiveSnapshotID:   target.ActiveSnapshotID,
			PreviousSnapshotID: target.PreviousSnapshotID,
			RollbackSupported:  target.RollbackSupported,
			DriftStatus:        target.DriftStatus,
			Message:            target.Message,
			Details:            target.Details,
			StartedAt:          started.Format(time.RFC3339),
			CompletedAt:        completed.Format(time.RFC3339),
		})
	}
	if err := recordAtomicEnforcementResult(req, result, actor); err != nil {
		return AtomicEnforcementResult{}, err
	}
	return result, nil
}

func ApplyAtomicEnforcement(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest, actor string) (AtomicEnforcementResult, error) {
	atomicEnforcementMu.Lock()
	defer atomicEnforcementMu.Unlock()

	started := time.Now().UTC()
	transactionID := newAtomicEnforcementID("enf-apply")
	plan, err := BuildAtomicEnforcementPlan(ctx, cfg, req)
	if err != nil {
		return AtomicEnforcementResult{}, err
	}
	result := AtomicEnforcementResult{
		TransactionID: transactionID,
		Operation:     "apply",
		Status:        "applied",
		Message:       plan.Message,
		Plan:          plan,
		StartedAt:     started.Format(time.RFC3339),
	}
	if plan.Status == "skipped" {
		result.Status = "skipped"
		result.Message = plan.Message
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if recordErr := recordAtomicEnforcementResult(req, result, actor); recordErr != nil {
			return AtomicEnforcementResult{}, recordErr
		}
		return result, nil
	}
	if plan.Status == "blocked" && cfg.Policy.EnforcementTransactions.FailClosed {
		result.Status = "blocked"
		result.Message = "Atomic enforcement apply blocked by preflight diagnostics."
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if recordErr := recordAtomicEnforcementResult(req, result, actor); recordErr != nil {
			return AtomicEnforcementResult{}, recordErr
		}
		_ = db.UpsertRuntimeStatus(atomicEnforcementComponent, "down", result.Message, atomicRuntimeStatusDetails(result))
		return result, fmt.Errorf("%s", result.Message)
	}

	participants := atomicParticipantMap()
	applied := []AtomicEnforcementStep{}
	var firstErr error
	for i, target := range plan.Targets {
		stepStarted := time.Now().UTC()
		if shouldSkipAtomicTargetApply(target) {
			result.Steps = append(result.Steps, AtomicEnforcementStep{
				StepOrder:          i + 1,
				Target:             target.Target,
				Operation:          "apply",
				Status:             "skipped",
				DesiredFingerprint: target.DesiredFingerprint,
				ActiveFingerprint:  target.ActiveFingerprint,
				ActiveSnapshotID:   target.ActiveSnapshotID,
				PreviousSnapshotID: target.PreviousSnapshotID,
				RollbackSupported:  target.RollbackSupported,
				DriftStatus:        target.DriftStatus,
				Message:            target.Message,
				StartedAt:          stepStarted.Format(time.RFC3339),
				CompletedAt:        time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		participant, ok := participants[target.Target]
		if !ok || participant.apply == nil {
			firstErr = fmt.Errorf("target %s has no apply participant", target.Target)
			result.Steps = append(result.Steps, failedAtomicStep(i+1, target, firstErr, stepStarted))
			break
		}
		step, err := participant.apply(ctx, cfg, actor)
		step.StepOrder = i + 1
		step.Target = target.Target
		step.Operation = "apply"
		step.StartedAt = stepStarted.Format(time.RFC3339)
		step.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		step.DesiredFingerprint = firstNonEmptyAtomicString(step.DesiredFingerprint, target.DesiredFingerprint)
		step.ActiveFingerprint = firstNonEmptyAtomicString(step.ActiveFingerprint, target.ActiveFingerprint)
		if step.Message == "" {
			step.Message = target.Message
		}
		result.Steps = append(result.Steps, step)
		if err != nil || step.Status == "failed" {
			if err == nil {
				err = fmt.Errorf("%s apply failed", target.Target)
			}
			firstErr = err
			break
		}
		if step.Status == "applied" || step.Status == "degraded" || step.Status == "rolled_back" {
			applied = append(applied, step)
		}
	}

	if firstErr != nil {
		result.Status = "failed"
		result.Message = firstErr.Error()
		if cfg.Policy.EnforcementTransactions.AutoRollbackOnFailure {
			compensations := compensateAtomicEnforcement(ctx, cfg, participants, applied, actor)
			result.Steps = append(result.Steps, compensations...)
			if atomicCompensationFailed(compensations) {
				result.Status = "failed"
				result.Message = firstErr.Error() + "; compensation failed"
			} else if len(compensations) > 0 {
				result.Status = "compensated"
				result.Message = firstErr.Error() + "; applied targets were rolled back"
			}
		}
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if recordErr := recordAtomicEnforcementResult(req, result, actor); recordErr != nil {
			return AtomicEnforcementResult{}, recordErr
		}
		_ = db.UpsertRuntimeStatus(atomicEnforcementComponent, "down", result.Message, atomicRuntimeStatusDetails(result))
		return result, firstErr
	}

	if cfg.Policy.EnforcementTransactions.DriftCheckAfterApply && !req.SkipDriftCheck {
		drift, driftErr := observeAtomicEnforcementDrift(ctx, cfg, req, actor, transactionID, true)
		if driftErr != nil {
			result.Status = "degraded"
			result.Message = "Atomic enforcement applied, but drift verification failed: " + driftErr.Error()
		}
		result.Drift = drift
		if atomicDriftCount(drift) > 0 {
			result.Status = "drifted"
			result.Message = fmt.Sprintf("Atomic enforcement applied with %d drifted target(s).", atomicDriftCount(drift))
			if cfg.Policy.EnforcementTransactions.AutoRollbackOnDrift {
				compensations := compensateAtomicEnforcement(ctx, cfg, participants, applied, actor)
				result.Steps = append(result.Steps, compensations...)
				if !atomicCompensationFailed(compensations) && len(compensations) > 0 {
					result.Status = "compensated"
					result.Message = "Atomic enforcement drift was detected after apply; applied targets were rolled back."
				}
			}
		}
	}
	if result.Message == "" || result.Message == plan.Message {
		result.Message = fmt.Sprintf("Atomic enforcement applied %d target(s).", atomicAppliedStepCount(result.Steps))
	}
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if err := recordAtomicEnforcementResult(req, result, actor); err != nil {
		return AtomicEnforcementResult{}, err
	}
	runtimeStatus := "ok"
	if result.Status == "degraded" || result.Status == "drifted" {
		runtimeStatus = "degraded"
	}
	_ = db.UpsertRuntimeStatus(atomicEnforcementComponent, runtimeStatus, result.Message, atomicRuntimeStatusDetails(result))
	return result, nil
}

func DetectAtomicEnforcementDrift(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest, actor string) (AtomicEnforcementResult, error) {
	started := time.Now().UTC()
	transactionID := newAtomicEnforcementID("enf-drift")
	plan, err := BuildAtomicEnforcementPlan(ctx, cfg, req)
	if err != nil {
		return AtomicEnforcementResult{}, err
	}
	drift, err := observeAtomicEnforcementDrift(ctx, cfg, req, actor, transactionID, true)
	status := "in_sync"
	message := "Atomic enforcement targets are in sync."
	if count := atomicDriftCount(drift); count > 0 {
		status = "drifted"
		message = fmt.Sprintf("Atomic enforcement detected %d drifted target(s).", count)
	} else if err != nil {
		status = "degraded"
		message = err.Error()
	}
	result := AtomicEnforcementResult{
		TransactionID: transactionID,
		Operation:     "drift",
		Status:        status,
		Message:       message,
		Plan:          plan,
		Drift:         drift,
		StartedAt:     started.Format(time.RFC3339),
		CompletedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	for i, finding := range drift {
		result.Steps = append(result.Steps, AtomicEnforcementStep{
			StepOrder:          i + 1,
			Target:             finding.Target,
			Operation:          "drift",
			Status:             finding.Status,
			DesiredFingerprint: finding.DesiredFingerprint,
			ActiveFingerprint:  finding.ActiveFingerprint,
			ActiveSnapshotID:   finding.ActiveSnapshotID,
			DriftStatus:        finding.Status,
			Message:            finding.Message,
			Details:            finding.Details,
			StartedAt:          started.Format(time.RFC3339),
			CompletedAt:        time.Now().UTC().Format(time.RFC3339),
		})
	}
	if recordErr := recordAtomicEnforcementResult(req, result, actor); recordErr != nil {
		return AtomicEnforcementResult{}, recordErr
	}
	runtimeStatus := "ok"
	if status == "drifted" || status == "degraded" {
		runtimeStatus = "degraded"
	}
	_ = db.UpsertRuntimeStatus(atomicEnforcementComponent, runtimeStatus, message, atomicRuntimeStatusDetails(result))
	return result, err
}

func RollbackAtomicEnforcement(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest, actor string) (AtomicEnforcementResult, error) {
	atomicEnforcementMu.Lock()
	defer atomicEnforcementMu.Unlock()

	started := time.Now().UTC()
	var (
		source db.EnforcementTransactionRecord
		steps  []db.EnforcementTransactionStepRecord
		found  bool
		err    error
	)
	if strings.TrimSpace(req.TransactionID) != "" {
		source, steps, found, err = db.GetEnforcementTransaction(req.TransactionID)
	} else {
		source, steps, found, err = db.GetLatestEnforcementRollbackCandidate()
	}
	if err != nil {
		return AtomicEnforcementResult{}, err
	}
	if !found {
		return AtomicEnforcementResult{}, fmt.Errorf("no atomic enforcement transaction is available for rollback")
	}
	plan, err := BuildAtomicEnforcementPlan(ctx, cfg, req)
	if err != nil {
		return AtomicEnforcementResult{}, err
	}
	participants := atomicParticipantMap()
	result := AtomicEnforcementResult{
		TransactionID: newAtomicEnforcementID("enf-rollback"),
		Operation:     "rollback",
		Status:        "rolled_back",
		Message:       fmt.Sprintf("Atomic enforcement rolled back transaction %s.", source.TransactionID),
		Plan:          plan,
		StartedAt:     started.Format(time.RFC3339),
	}
	rollbackInputs := rollbackableAtomicSteps(steps)
	for i, stepRecord := range rollbackInputs {
		stepStarted := time.Now().UTC()
		participant, ok := participants[stepRecord.Target]
		if !ok || participant.rollback == nil || strings.TrimSpace(stepRecord.PreviousSnapshotID) == "" {
			result.Steps = append(result.Steps, AtomicEnforcementStep{
				StepOrder:          i + 1,
				Target:             stepRecord.Target,
				Operation:          "rollback",
				Status:             "skipped",
				DesiredFingerprint: stepRecord.DesiredFingerprint,
				ActiveFingerprint:  stepRecord.ActiveFingerprint,
				PreviousSnapshotID: stepRecord.PreviousSnapshotID,
				SnapshotID:         stepRecord.SnapshotID,
				RollbackSupported:  false,
				Message:            "No previous target snapshot is available for rollback.",
				StartedAt:          stepStarted.Format(time.RFC3339),
				CompletedAt:        time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		step, rollbackErr := participant.rollback(ctx, cfg, stepRecord.PreviousSnapshotID, actor)
		step.StepOrder = i + 1
		step.Target = stepRecord.Target
		step.Operation = "rollback"
		step.StartedAt = stepStarted.Format(time.RFC3339)
		step.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		step.DesiredFingerprint = firstNonEmptyAtomicString(step.DesiredFingerprint, stepRecord.DesiredFingerprint)
		if rollbackErr != nil {
			step.Status = "failed"
			step.Error = rollbackErr.Error()
			result.Status = "failed"
			result.Message = "Atomic enforcement rollback failed: " + rollbackErr.Error()
			result.Steps = append(result.Steps, step)
			break
		}
		result.Steps = append(result.Steps, step)
	}
	if len(rollbackInputs) == 0 {
		result.Status = "skipped"
		result.Message = fmt.Sprintf("Transaction %s has no rollback-capable applied steps.", source.TransactionID)
	}
	result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	recordReq := req
	recordReq.TransactionID = source.TransactionID
	if recordErr := recordAtomicEnforcementResult(recordReq, result, actor); recordErr != nil {
		return AtomicEnforcementResult{}, recordErr
	}
	status := "ok"
	if result.Status == "failed" {
		status = "down"
	}
	_ = db.UpsertRuntimeStatus(atomicEnforcementComponent, status, result.Message, atomicRuntimeStatusDetails(result))
	if result.Status == "failed" {
		return result, fmt.Errorf("%s", result.Message)
	}
	return result, nil
}

func previewAtomicTarget(ctx context.Context, cfg *config.Config, target string) (AtomicEnforcementTargetPlan, error) {
	switch normalizeAtomicTarget(target) {
	case "runtime_firewall":
		return previewAtomicRuntimeFirewall()
	case "runtime_qos":
		return previewAtomicRuntimeQoS(cfg)
	case "vlan_lifecycle":
		return previewAtomicVLANLifecycle(cfg)
	case "controller_sync":
		return previewAtomicController(ctx, cfg)
	default:
		return blockedAtomicTarget(target, "unsupported enforcement target"), fmt.Errorf("unsupported enforcement target %q", target)
	}
}

func previewAtomicRuntimeFirewall() (AtomicEnforcementTargetPlan, error) {
	plan, err := PreviewRuntimeFirewall()
	if err != nil {
		return AtomicEnforcementTargetPlan{}, err
	}
	target := AtomicEnforcementTargetPlan{
		Target:              "runtime_firewall",
		Label:               "Runtime Firewall",
		Domain:              "nftables",
		Enabled:             true,
		Status:              normalizeAtomicPlanStatus(plan.Status),
		Message:             plan.Message,
		DesiredFingerprint:  plan.RulesetFingerprint,
		Local:               true,
		Dependencies:        []string{"nft", "sessions", "acl_policies"},
		ExternalValidation:  []string{"nft list ruleset packet capture", "session ACL smoke test"},
		CompensationSupport: "snapshot-rollback",
		Details: map[string]any{
			"summary":    plan.Summary,
			"diagnostic": len(plan.Diagnostics),
		},
	}
	if active, found, err := db.GetActiveRuntimeFirewallSnapshot(); err == nil && found {
		target.ActiveSnapshotID = active.SnapshotID
		target.ActiveFingerprint = active.RulesetFingerprint
		target.PreviousSnapshotID = active.PreviousSnapshotID
		target.RollbackSupported = active.PreviousSnapshotID != ""
	} else if err != nil {
		return target, err
	}
	attachAtomicDriftState(&target)
	return target, nil
}

func previewAtomicRuntimeQoS(cfg *config.Config) (AtomicEnforcementTargetPlan, error) {
	plan, err := PreviewRuntimeQoS(cfg)
	if err != nil {
		return AtomicEnforcementTargetPlan{}, err
	}
	target := AtomicEnforcementTargetPlan{
		Target:              "runtime_qos",
		Label:               "Runtime QoS",
		Domain:              "tc/ifb",
		Enabled:             plan.Status != "skipped",
		Status:              normalizeAtomicPlanStatus(plan.Status),
		Message:             plan.Message,
		DesiredFingerprint:  plan.PlanFingerprint,
		Local:               true,
		Dependencies:        []string{"tc", "ifb", "bandwidth_profiles", "sessions"},
		ExternalValidation:  []string{"tc class/filter inspection", "dual-stack shaping smoke test"},
		CompensationSupport: "snapshot-rollback",
		Details: map[string]any{
			"summary":        plan.Summary,
			"interface_name": plan.InterfaceName,
			"ifb_device":     plan.IFBDevice,
		},
	}
	if active, found, err := db.GetActiveRuntimeQoSSnapshot(); err == nil && found {
		target.ActiveSnapshotID = active.SnapshotID
		target.ActiveFingerprint = active.PlanFingerprint
		target.PreviousSnapshotID = active.PreviousSnapshotID
		target.RollbackSupported = active.PreviousSnapshotID != ""
	} else if err != nil {
		return target, err
	}
	attachAtomicDriftState(&target)
	return target, nil
}

func previewAtomicVLANLifecycle(cfg *config.Config) (AtomicEnforcementTargetPlan, error) {
	plan, err := PreviewVLANLifecycle(cfg)
	if err != nil {
		return AtomicEnforcementTargetPlan{}, err
	}
	target := AtomicEnforcementTargetPlan{
		Target:              "vlan_lifecycle",
		Label:               "VLAN Lifecycle",
		Domain:              "ip/hostapd",
		Enabled:             plan.Status != "skipped",
		Status:              normalizeAtomicPlanStatus(plan.Status),
		Message:             plan.Message,
		DesiredFingerprint:  plan.PlanFingerprint,
		Local:               true,
		Dependencies:        []string{"iproute2", "hostapd", "vlan policy"},
		ExternalValidation:  []string{"ip link bridge/subinterface check", "hostapd dynamic VLAN smoke test"},
		CompensationSupport: "snapshot-rollback",
		Details: map[string]any{
			"summary":                  plan.Summary,
			"parent_interface":         plan.ParentInterface,
			"hostapd_vlan_file_path":   plan.HostapdVLANFilePath,
			"hostapd_vlan_file_sha256": plan.HostapdVLANFileSHA256,
		},
	}
	if active, found, err := db.GetActiveVLANLifecycleSnapshot(); err == nil && found {
		target.ActiveSnapshotID = active.SnapshotID
		target.ActiveFingerprint = active.PlanFingerprint
		target.PreviousSnapshotID = active.PreviousSnapshotID
		target.RollbackSupported = active.PreviousSnapshotID != ""
	} else if err != nil {
		return target, err
	}
	attachAtomicDriftState(&target)
	return target, nil
}

func previewAtomicController(ctx context.Context, cfg *config.Config) (AtomicEnforcementTargetPlan, error) {
	target := AtomicEnforcementTargetPlan{
		Target:              "controller_sync",
		Label:               "Controller Sync",
		Domain:              "controller-api",
		Controller:          true,
		Dependencies:        []string{"integrations.controller"},
		ExternalValidation:  []string{"controller API smoke test", "device firmware drift validation"},
		CompensationSupport: "local-compensation; controller rollback requires external controller evidence",
	}
	if cfg == nil || !cfg.Integrations.Controller.Enabled {
		target.Enabled = false
		target.Status = "skipped"
		target.Message = "Controller sync is disabled."
		target.DriftStatus = "skipped"
		return target, nil
	}
	preview, err := integrations.BuildControllerSyncPreview(cfg, "push")
	if err != nil {
		target.Enabled = true
		target.Status = "blocked"
		target.Message = err.Error()
		target.DriftStatus = "blocked"
		return target, err
	}
	target.Enabled = true
	target.Status = "ready"
	target.Message = "Controller sync preview is ready."
	target.DesiredFingerprint = strings.TrimSpace(preview.DesiredStateHash)
	target.Details = map[string]any{
		"adapter":     preview.Adapter,
		"method":      preview.Method,
		"target_url":  preview.TargetURL,
		"auth_scheme": preview.AuthScheme,
	}
	if runtimeStatus, err := db.GetRuntimeStatus(integrations.ControllerComponent()); err == nil && runtimeStatus != nil {
		target.ActiveSnapshotID = runtimeStatus.UpdatedAt
		target.ActiveFingerprint = firstNonEmptyFromMap(runtimeStatus.Details, "desired_state_hash", "observed_state_hash")
		target.Details["runtime_status"] = runtimeStatus.Status
		target.Details["runtime_message"] = runtimeStatus.Message
	} else if err != nil {
		return target, err
	}
	attachAtomicDriftState(&target)
	_ = ctx
	return target, nil
}

func observeAtomicEnforcementDrift(ctx context.Context, cfg *config.Config, req AtomicEnforcementRequest, actor, transactionID string, record bool) ([]AtomicEnforcementDriftFinding, error) {
	plan, err := BuildAtomicEnforcementPlan(ctx, cfg, req)
	if err != nil {
		return nil, err
	}
	findings := make([]AtomicEnforcementDriftFinding, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		status := target.DriftStatus
		if status == "" {
			status = "unknown"
		}
		message := target.DriftMessage
		if message == "" {
			message = target.Message
		}
		finding := AtomicEnforcementDriftFinding{
			Target:             target.Target,
			Status:             status,
			DesiredFingerprint: target.DesiredFingerprint,
			ActiveFingerprint:  target.ActiveFingerprint,
			ActiveSnapshotID:   target.ActiveSnapshotID,
			Message:            message,
			Details: map[string]any{
				"apply_required":       target.ApplyRequired,
				"rollback_supported":   target.RollbackSupported,
				"compensation_support": target.CompensationSupport,
			},
		}
		findings = append(findings, finding)
		if record {
			if _, err := db.RecordEnforcementDriftEvent(db.EnforcementDriftEventInput{
				TransactionID:      transactionID,
				Target:             finding.Target,
				Status:             finding.Status,
				DesiredFingerprint: finding.DesiredFingerprint,
				ActiveFingerprint:  finding.ActiveFingerprint,
				ActiveSnapshotID:   finding.ActiveSnapshotID,
				Message:            finding.Message,
				DetailsJSON:        atomicJSON(finding.Details, "{}"),
				Actor:              actor,
			}); err != nil {
				return findings, err
			}
		}
	}
	return findings, nil
}

func compensateAtomicEnforcement(ctx context.Context, cfg *config.Config, participants map[string]atomicParticipant, applied []AtomicEnforcementStep, actor string) []AtomicEnforcementStep {
	compensations := []AtomicEnforcementStep{}
	for i := len(applied) - 1; i >= 0; i-- {
		original := applied[i]
		stepStarted := time.Now().UTC()
		order := len(compensations) + 1
		participant, ok := participants[original.Target]
		if !ok || participant.rollback == nil || strings.TrimSpace(original.PreviousSnapshotID) == "" {
			compensations = append(compensations, AtomicEnforcementStep{
				StepOrder:          order,
				Target:             original.Target,
				Operation:          "compensate",
				Status:             "skipped",
				DesiredFingerprint: original.DesiredFingerprint,
				ActiveFingerprint:  original.ActiveFingerprint,
				SnapshotID:         original.SnapshotID,
				PreviousSnapshotID: original.PreviousSnapshotID,
				RollbackSupported:  false,
				Message:            "No previous snapshot is available for compensation.",
				StartedAt:          stepStarted.Format(time.RFC3339),
				CompletedAt:        time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		step, err := participant.rollback(ctx, cfg, original.PreviousSnapshotID, actor)
		step.StepOrder = order
		step.Target = original.Target
		step.Operation = "compensate"
		step.StartedAt = stepStarted.Format(time.RFC3339)
		step.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		step.DesiredFingerprint = firstNonEmptyAtomicString(step.DesiredFingerprint, original.DesiredFingerprint)
		if err != nil {
			step.Status = "failed"
			step.Error = err.Error()
		} else if step.Status == "rolled_back" || step.Status == "applied" {
			step.Status = "compensated"
		}
		compensations = append(compensations, step)
	}
	return compensations
}

func recordAtomicEnforcementResult(req AtomicEnforcementRequest, result AtomicEnforcementResult, actor string) error {
	steps := make([]db.EnforcementTransactionStepInput, 0, len(result.Steps))
	for _, step := range result.Steps {
		steps = append(steps, db.EnforcementTransactionStepInput{
			TransactionID:      result.TransactionID,
			StepOrder:          step.StepOrder,
			Target:             step.Target,
			Operation:          step.Operation,
			Status:             step.Status,
			DesiredFingerprint: step.DesiredFingerprint,
			ActiveFingerprint:  step.ActiveFingerprint,
			ActiveSnapshotID:   step.ActiveSnapshotID,
			PreviousSnapshotID: step.PreviousSnapshotID,
			SnapshotID:         step.SnapshotID,
			RestoredSnapshotID: step.RestoredSnapshotID,
			RollbackSupported:  step.RollbackSupported,
			DriftStatus:        step.DriftStatus,
			Message:            step.Message,
			Error:              step.Error,
			DetailsJSON:        atomicJSON(step.Details, "{}"),
			StartedAt:          parseAtomicTime(step.StartedAt),
			CompletedAt:        parseAtomicTime(step.CompletedAt),
		})
	}
	completedAt := parseAtomicTime(result.CompletedAt)
	startedAt := parseAtomicTime(result.StartedAt)
	_, err := db.RecordEnforcementTransaction(db.EnforcementTransactionInput{
		TransactionID:         result.TransactionID,
		Operation:             result.Operation,
		Status:                result.Status,
		Actor:                 actor,
		TargetCount:           result.Plan.Summary.TargetCount,
		AppliedCount:          atomicAppliedStepCount(result.Steps),
		SkippedCount:          atomicStepStatusCount(result.Steps, "skipped"),
		FailedCount:           atomicStepStatusCount(result.Steps, "failed"),
		RollbackCount:         atomicStepOperationCount(result.Steps, "rollback"),
		CompensationCount:     atomicStepOperationCount(result.Steps, "compensate"),
		DriftCount:            atomicDriftCount(result.Drift),
		PlanFingerprint:       result.Plan.PlanFingerprint,
		PreviousTransactionID: strings.TrimSpace(req.TransactionID),
		Summary:               result.Message,
		RequestJSON:           atomicJSON(req, "{}"),
		PlanJSON:              atomicJSON(result.Plan, "{}"),
		ResultJSON:            atomicJSON(result, "{}"),
		DiagnosticsJSON:       atomicJSON(result.Plan.Diagnostics, "[]"),
		StartedAt:             startedAt,
		CompletedAt:           completedAt,
		Steps:                 steps,
	})
	if err != nil {
		return err
	}
	if cfg := config.Get(); cfg != nil {
		_ = db.TrimEnforcementTransactionHistory(cfg.Policy.EnforcementTransactions.HistoryRetentionLimit, cfg.Policy.EnforcementTransactions.CompensationRetentionLimit)
	}
	return nil
}

func finalizeAtomicEnforcementPlan(plan *AtomicEnforcementPlan) {
	plan.Summary.TargetCount = len(plan.Targets)
	blocked := 0
	degraded := 0
	ready := 0
	skipped := 0
	for _, target := range plan.Targets {
		if target.Enabled {
			plan.Summary.EnabledTargets++
		}
		if target.Local {
			plan.Summary.LocalTargets++
		}
		if target.Controller {
			plan.Summary.ControllerTargets++
		}
		if target.ApplyRequired {
			plan.Summary.ApplyRequired++
		}
		if target.RollbackSupported {
			plan.Summary.RollbackAvailable++
		}
		switch target.Status {
		case "blocked":
			blocked++
		case "degraded":
			degraded++
		case "skipped":
			skipped++
		default:
			ready++
		}
		switch target.DriftStatus {
		case "drifted":
			plan.Summary.DriftedTargets++
		case "unknown":
			plan.Summary.UnknownDrift++
		}
	}
	plan.Summary.BlockedTargets = blocked
	plan.Summary.DegradedTargets = degraded
	plan.Summary.ReadyTargets = ready
	plan.Summary.SkippedTargets = skipped
	switch {
	case len(plan.Targets) == 0:
		plan.Status = "blocked"
		plan.Message = "No enforcement transaction targets are configured."
	case skipped == len(plan.Targets):
		plan.Status = "skipped"
		plan.Message = "All enforcement transaction targets are skipped."
	case blocked > 0:
		plan.Status = "blocked"
		plan.Message = fmt.Sprintf("Atomic enforcement preflight found %d blocked target(s).", blocked)
	case degraded > 0 || plan.Summary.DriftedTargets > 0 || plan.Summary.UnknownDrift > 0:
		plan.Status = "degraded"
		plan.Message = fmt.Sprintf("Atomic enforcement preflight is degraded: %d target(s) need apply and %d target(s) have drift.", plan.Summary.ApplyRequired, plan.Summary.DriftedTargets)
	default:
		plan.Status = "ready"
		plan.Message = fmt.Sprintf("Atomic enforcement preflight is ready for %d target(s).", len(plan.Targets)-skipped)
	}
	sort.SliceStable(plan.Targets, func(i, j int) bool {
		return atomicTargetRank(plan.Targets[i].Target) < atomicTargetRank(plan.Targets[j].Target)
	})
	payload, _ := json.Marshal(struct {
		Targets []AtomicEnforcementTargetPlan `json:"targets"`
		RFCs    []string                      `json:"rfcs"`
	}{Targets: plan.Targets, RFCs: plan.RFCs})
	sum := sha256.Sum256(payload)
	plan.PlanFingerprint = hex.EncodeToString(sum[:])
}

func attachAtomicDriftState(target *AtomicEnforcementTargetPlan) {
	target.Status = normalizeAtomicPlanStatus(target.Status)
	if !target.Enabled || target.Status == "skipped" {
		target.DriftStatus = "skipped"
		target.ApplyRequired = false
		return
	}
	if target.Status == "blocked" {
		target.DriftStatus = "blocked"
		target.ApplyRequired = false
		return
	}
	desired := strings.TrimSpace(target.DesiredFingerprint)
	active := strings.TrimSpace(target.ActiveFingerprint)
	switch {
	case desired == "":
		target.DriftStatus = "unknown"
		target.DriftMessage = "No desired fingerprint is available."
	case active == "":
		target.DriftStatus = "unknown"
		target.DriftMessage = "No active snapshot fingerprint is available."
		target.ApplyRequired = true
	case strings.EqualFold(desired, active):
		target.DriftStatus = "in_sync"
		target.ApplyRequired = false
	default:
		target.DriftStatus = "drifted"
		target.DriftMessage = "Active target fingerprint differs from the desired plan."
		target.ApplyRequired = true
	}
}

func atomicTargetOrder(cfg *config.Config, requested []string) []string {
	values := requested
	if len(values) == 0 && cfg != nil {
		values = cfg.Policy.EnforcementTransactions.Targets
	}
	if len(values) == 0 {
		values = []string{"vlan_lifecycle", "runtime_qos", "runtime_firewall", "controller_sync"}
	}
	seen := map[string]struct{}{}
	targets := make([]string, 0, len(values))
	for _, value := range values {
		target := normalizeAtomicTarget(value)
		if target == "" {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	sort.SliceStable(targets, func(i, j int) bool { return atomicTargetRank(targets[i]) < atomicTargetRank(targets[j]) })
	return targets
}

func atomicParticipantMap() map[string]atomicParticipant {
	return map[string]atomicParticipant{
		"vlan_lifecycle":   {target: "vlan_lifecycle", apply: atomicVLANLifecycleApplyFn, rollback: atomicVLANLifecycleRollbackFn},
		"runtime_qos":      {target: "runtime_qos", apply: atomicRuntimeQoSApplyFn, rollback: atomicRuntimeQoSRollbackFn},
		"runtime_firewall": {target: "runtime_firewall", apply: atomicRuntimeFirewallApplyFn, rollback: atomicRuntimeFirewallRollbackFn},
		"controller_sync":  {target: "controller_sync", apply: atomicControllerApplyFn},
	}
}

func normalizeAtomicTarget(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "runtime-firewall", "runtime_firewall", "firewall":
		return "runtime_firewall"
	case "runtime-qos", "runtime_qos", "qos", "qos_scheduler":
		return "runtime_qos"
	case "vlan-lifecycle", "vlan_lifecycle", "vlan":
		return "vlan_lifecycle"
	case "controller-sync", "controller_sync", "controller":
		return "controller_sync"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func atomicTargetRank(target string) int {
	switch normalizeAtomicTarget(target) {
	case "vlan_lifecycle":
		return 10
	case "runtime_qos":
		return 20
	case "runtime_firewall":
		return 30
	case "controller_sync":
		return 40
	default:
		return 100
	}
}

func skippedAtomicTarget(target, message string) AtomicEnforcementTargetPlan {
	target = normalizeAtomicTarget(target)
	return AtomicEnforcementTargetPlan{
		Target:              target,
		Label:               atomicTargetLabel(target),
		Domain:              atomicTargetDomain(target),
		Status:              "skipped",
		Message:             strings.TrimSpace(message),
		DriftStatus:         "skipped",
		CompensationSupport: "not-needed",
	}
}

func blockedAtomicTarget(target, message string) AtomicEnforcementTargetPlan {
	target = normalizeAtomicTarget(target)
	return AtomicEnforcementTargetPlan{
		Target:              target,
		Label:               atomicTargetLabel(target),
		Domain:              atomicTargetDomain(target),
		Enabled:             true,
		Status:              "blocked",
		Message:             strings.TrimSpace(message),
		DriftStatus:         "blocked",
		CompensationSupport: "blocked-before-apply",
	}
}

func failedAtomicStep(order int, target AtomicEnforcementTargetPlan, err error, started time.Time) AtomicEnforcementStep {
	return AtomicEnforcementStep{
		StepOrder:          order,
		Target:             target.Target,
		Operation:          "apply",
		Status:             "failed",
		DesiredFingerprint: target.DesiredFingerprint,
		ActiveFingerprint:  target.ActiveFingerprint,
		ActiveSnapshotID:   target.ActiveSnapshotID,
		PreviousSnapshotID: target.PreviousSnapshotID,
		RollbackSupported:  target.RollbackSupported,
		Error:              err.Error(),
		Message:            err.Error(),
		StartedAt:          started.Format(time.RFC3339),
		CompletedAt:        time.Now().UTC().Format(time.RFC3339),
	}
}

func shouldSkipAtomicTargetApply(target AtomicEnforcementTargetPlan) bool {
	return !target.Enabled || target.Status == "skipped"
}

func targetPlanStepStatus(target AtomicEnforcementTargetPlan) string {
	switch target.Status {
	case "blocked", "degraded", "skipped":
		return target.Status
	default:
		return "previewed"
	}
}

func normalizeAtomicPlanStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ready":
		return "ready"
	case "degraded":
		return "degraded"
	case "blocked":
		return "blocked"
	case "skipped", "disabled":
		return "skipped"
	default:
		return "degraded"
	}
}

func rollbackableAtomicSteps(steps []db.EnforcementTransactionStepRecord) []db.EnforcementTransactionStepRecord {
	var out []db.EnforcementTransactionStepRecord
	for _, step := range steps {
		if step.Operation != "apply" {
			continue
		}
		if step.Status != "applied" && step.Status != "degraded" && step.Status != "drifted" {
			continue
		}
		out = append(out, step)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StepOrder > out[j].StepOrder })
	return out
}

func atomicTargetLabel(target string) string {
	switch normalizeAtomicTarget(target) {
	case "runtime_firewall":
		return "Runtime Firewall"
	case "runtime_qos":
		return "Runtime QoS"
	case "vlan_lifecycle":
		return "VLAN Lifecycle"
	case "controller_sync":
		return "Controller Sync"
	default:
		return strings.TrimSpace(target)
	}
}

func atomicTargetDomain(target string) string {
	switch normalizeAtomicTarget(target) {
	case "runtime_firewall":
		return "nftables"
	case "runtime_qos":
		return "tc/ifb"
	case "vlan_lifecycle":
		return "ip/hostapd"
	case "controller_sync":
		return "controller-api"
	default:
		return "unknown"
	}
}

func atomicAppliedStepCount(steps []AtomicEnforcementStep) int {
	count := 0
	for _, step := range steps {
		if step.Operation == "apply" && (step.Status == "applied" || step.Status == "degraded" || step.Status == "rolled_back") {
			count++
		}
	}
	return count
}

func atomicStepStatusCount(steps []AtomicEnforcementStep, status string) int {
	count := 0
	for _, step := range steps {
		if step.Status == status {
			count++
		}
	}
	return count
}

func atomicStepOperationCount(steps []AtomicEnforcementStep, operation string) int {
	count := 0
	for _, step := range steps {
		if step.Operation == operation {
			count++
		}
	}
	return count
}

func atomicDriftCount(findings []AtomicEnforcementDriftFinding) int {
	count := 0
	for _, finding := range findings {
		if finding.Status == "drifted" {
			count++
		}
	}
	return count
}

func atomicCompensationFailed(steps []AtomicEnforcementStep) bool {
	for _, step := range steps {
		if step.Status == "failed" {
			return true
		}
	}
	return false
}

func atomicRuntimeStatusDetails(result AtomicEnforcementResult) map[string]any {
	return map[string]any{
		"transaction_id":   result.TransactionID,
		"operation":        result.Operation,
		"status":           result.Status,
		"plan_fingerprint": result.Plan.PlanFingerprint,
		"target_count":     result.Plan.Summary.TargetCount,
		"applied_count":    atomicAppliedStepCount(result.Steps),
		"failed_count":     atomicStepStatusCount(result.Steps, "failed"),
		"drift_count":      atomicDriftCount(result.Drift),
		"completed_at":     result.CompletedAt,
	}
}

func newAtomicEnforcementID(prefix string) string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%x", prefix, time.Now().UTC().UnixNano(), nonce)))
	return prefix + "-" + hex.EncodeToString(sum[:12])
}

func firstNonEmptyAtomicString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonEmptyFromMap(values map[string]any, keys ...string) string {
	if len(values) == 0 {
		return ""
	}
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
				return text
			}
		}
	}
	return ""
}

func atomicJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || !json.Valid(encoded) {
		return fallback
	}
	return string(encoded)
}

func parseAtomicTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return &parsed
}
