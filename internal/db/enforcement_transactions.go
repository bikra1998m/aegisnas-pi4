package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type EnforcementTransactionInput struct {
	TransactionID         string
	Operation             string
	Status                string
	Actor                 string
	TargetCount           int
	AppliedCount          int
	SkippedCount          int
	FailedCount           int
	RollbackCount         int
	CompensationCount     int
	DriftCount            int
	PlanFingerprint       string
	PreviousTransactionID string
	RollbackTransactionID string
	Summary               string
	RequestJSON           string
	PlanJSON              string
	ResultJSON            string
	DiagnosticsJSON       string
	StartedAt             *time.Time
	CompletedAt           *time.Time
	Steps                 []EnforcementTransactionStepInput
}

type EnforcementTransactionStepInput struct {
	TransactionID      string
	StepOrder          int
	Target             string
	Operation          string
	Status             string
	DesiredFingerprint string
	ActiveFingerprint  string
	ActiveSnapshotID   string
	PreviousSnapshotID string
	SnapshotID         string
	RestoredSnapshotID string
	RollbackSupported  bool
	DriftStatus        string
	Message            string
	Error              string
	DetailsJSON        string
	StartedAt          *time.Time
	CompletedAt        *time.Time
}

type EnforcementDriftEventInput struct {
	DriftID            string
	TransactionID      string
	Target             string
	Status             string
	DesiredFingerprint string
	ActiveFingerprint  string
	ActiveSnapshotID   string
	Message            string
	DetailsJSON        string
	Actor              string
	ObservedAt         *time.Time
}

type EnforcementTransactionRecord struct {
	ID                    int             `json:"id"`
	TransactionID         string          `json:"transaction_id"`
	Operation             string          `json:"operation"`
	Status                string          `json:"status"`
	Actor                 string          `json:"actor,omitempty"`
	TargetCount           int             `json:"target_count"`
	AppliedCount          int             `json:"applied_count"`
	SkippedCount          int             `json:"skipped_count"`
	FailedCount           int             `json:"failed_count"`
	RollbackCount         int             `json:"rollback_count"`
	CompensationCount     int             `json:"compensation_count"`
	DriftCount            int             `json:"drift_count"`
	PlanFingerprint       string          `json:"plan_fingerprint,omitempty"`
	PreviousTransactionID string          `json:"previous_transaction_id,omitempty"`
	RollbackTransactionID string          `json:"rollback_transaction_id,omitempty"`
	Summary               string          `json:"summary,omitempty"`
	RequestJSON           json.RawMessage `json:"request_json,omitempty"`
	PlanJSON              json.RawMessage `json:"plan_json,omitempty"`
	ResultJSON            json.RawMessage `json:"result_json,omitempty"`
	DiagnosticsJSON       json.RawMessage `json:"diagnostics_json,omitempty"`
	StartedAt             string          `json:"started_at"`
	CompletedAt           string          `json:"completed_at,omitempty"`
}

type EnforcementTransactionStepRecord struct {
	ID                 int             `json:"id"`
	TransactionID      string          `json:"transaction_id"`
	StepOrder          int             `json:"step_order"`
	Target             string          `json:"target"`
	Operation          string          `json:"operation"`
	Status             string          `json:"status"`
	DesiredFingerprint string          `json:"desired_fingerprint,omitempty"`
	ActiveFingerprint  string          `json:"active_fingerprint,omitempty"`
	ActiveSnapshotID   string          `json:"active_snapshot_id,omitempty"`
	PreviousSnapshotID string          `json:"previous_snapshot_id,omitempty"`
	SnapshotID         string          `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string          `json:"restored_snapshot_id,omitempty"`
	RollbackSupported  bool            `json:"rollback_supported"`
	DriftStatus        string          `json:"drift_status,omitempty"`
	Message            string          `json:"message,omitempty"`
	Error              string          `json:"error,omitempty"`
	DetailsJSON        json.RawMessage `json:"details_json,omitempty"`
	StartedAt          string          `json:"started_at,omitempty"`
	CompletedAt        string          `json:"completed_at,omitempty"`
}

type EnforcementDriftEventRecord struct {
	ID                 int             `json:"id"`
	DriftID            string          `json:"drift_id"`
	TransactionID      string          `json:"transaction_id,omitempty"`
	Target             string          `json:"target"`
	Status             string          `json:"status"`
	DesiredFingerprint string          `json:"desired_fingerprint,omitempty"`
	ActiveFingerprint  string          `json:"active_fingerprint,omitempty"`
	ActiveSnapshotID   string          `json:"active_snapshot_id,omitempty"`
	Message            string          `json:"message,omitempty"`
	DetailsJSON        json.RawMessage `json:"details_json,omitempty"`
	Actor              string          `json:"actor,omitempty"`
	ObservedAt         string          `json:"observed_at"`
}

type EnforcementTransactionSummary struct {
	TotalTransactions    int    `json:"total_transactions"`
	PreviewTransactions  int    `json:"preview_transactions"`
	ApplyTransactions    int    `json:"apply_transactions"`
	DriftTransactions    int    `json:"drift_transactions"`
	RollbackTransactions int    `json:"rollback_transactions"`
	AppliedCount         int    `json:"applied_count"`
	DegradedCount        int    `json:"degraded_count"`
	BlockedCount         int    `json:"blocked_count"`
	FailedCount          int    `json:"failed_count"`
	CompensatedCount     int    `json:"compensated_count"`
	RolledBackCount      int    `json:"rolled_back_count"`
	DriftedCount         int    `json:"drifted_count"`
	InSyncCount          int    `json:"in_sync_count"`
	LastTransactionID    string `json:"last_transaction_id,omitempty"`
	LastStatus           string `json:"last_status,omitempty"`
	LastOperation        string `json:"last_operation,omitempty"`
	LastTransactionAt    string `json:"last_transaction_at,omitempty"`
	LastPlanFingerprint  string `json:"last_plan_fingerprint,omitempty"`
	LastDriftCount       int    `json:"last_drift_count"`
	TotalSteps           int    `json:"total_steps"`
	FailedSteps          int    `json:"failed_steps"`
	CompensatedSteps     int    `json:"compensated_steps"`
	DriftEvents          int    `json:"drift_events"`
	OpenDriftEvents      int    `json:"open_drift_events"`
}

func RecordEnforcementTransaction(input EnforcementTransactionInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeEnforcementTransactionOperation(input.Operation)
	input.Status = normalizeEnforcementTransactionStatus(input.Status)
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("enforcement transaction operation and status are required")
	}
	input.TransactionID = strings.TrimSpace(input.TransactionID)
	if input.TransactionID == "" {
		input.TransactionID = newRuntimeQoSID("enf-tx", input.Operation, input.Status, input.PlanFingerprint)
	}
	input.RequestJSON = defaultJSON(input.RequestJSON, "{}")
	input.PlanJSON = defaultJSON(input.PlanJSON, "{}")
	input.ResultJSON = defaultJSON(input.ResultJSON, "{}")
	input.DiagnosticsJSON = defaultJSON(input.DiagnosticsJSON, "[]")
	startedAt := time.Now().UTC()
	if input.StartedAt != nil {
		startedAt = input.StartedAt.UTC()
	}

	tx, err := DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin enforcement transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO enforcement_transactions (
			transaction_id, operation, status, actor, target_count, applied_count,
			skipped_count, failed_count, rollback_count, compensation_count, drift_count,
			plan_fingerprint, previous_transaction_id, rollback_transaction_id, summary,
			request_json, plan_json, result_json, diagnostics_json, started_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.TransactionID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.Actor)),
		nonNegativeInt(input.TargetCount),
		nonNegativeInt(input.AppliedCount),
		nonNegativeInt(input.SkippedCount),
		nonNegativeInt(input.FailedCount),
		nonNegativeInt(input.RollbackCount),
		nonNegativeInt(input.CompensationCount),
		nonNegativeInt(input.DriftCount),
		nullString(strings.TrimSpace(input.PlanFingerprint)),
		nullString(strings.TrimSpace(input.PreviousTransactionID)),
		nullString(strings.TrimSpace(input.RollbackTransactionID)),
		nullString(strings.TrimSpace(input.Summary)),
		input.RequestJSON,
		input.PlanJSON,
		input.ResultJSON,
		input.DiagnosticsJSON,
		startedAt,
		timeOrNil(input.CompletedAt),
	)
	if err != nil {
		return "", fmt.Errorf("record enforcement transaction: %w", err)
	}
	for _, step := range input.Steps {
		if step.TransactionID == "" {
			step.TransactionID = input.TransactionID
		}
		if err := insertEnforcementTransactionStep(tx, step); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit enforcement transaction: %w", err)
	}
	return input.TransactionID, nil
}

func RecordEnforcementDriftEvent(input EnforcementDriftEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Target = normalizeEnforcementTarget(input.Target)
	input.Status = normalizeEnforcementDriftStatus(input.Status)
	if input.Target == "" || input.Status == "" {
		return "", fmt.Errorf("enforcement drift target and status are required")
	}
	input.DriftID = strings.TrimSpace(input.DriftID)
	if input.DriftID == "" {
		input.DriftID = newRuntimeQoSID("enf-drift", input.Target, input.Status, input.DesiredFingerprint+input.ActiveFingerprint)
	}
	input.DetailsJSON = defaultJSON(input.DetailsJSON, "{}")
	observedAt := time.Now().UTC()
	if input.ObservedAt != nil {
		observedAt = input.ObservedAt.UTC()
	}
	_, err := DB.Exec(`INSERT INTO enforcement_drift_events (
			drift_id, transaction_id, target, status, desired_fingerprint, active_fingerprint,
			active_snapshot_id, message, details_json, actor, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.DriftID,
		nullString(strings.TrimSpace(input.TransactionID)),
		input.Target,
		input.Status,
		nullString(strings.TrimSpace(input.DesiredFingerprint)),
		nullString(strings.TrimSpace(input.ActiveFingerprint)),
		nullString(strings.TrimSpace(input.ActiveSnapshotID)),
		nullString(strings.TrimSpace(input.Message)),
		input.DetailsJSON,
		nullString(strings.TrimSpace(input.Actor)),
		observedAt,
	)
	if err != nil {
		return "", fmt.Errorf("record enforcement drift event: %w", err)
	}
	return input.DriftID, nil
}

func TrimEnforcementTransactionHistory(transactionLimit, driftLimit int) error {
	if DB == nil {
		return nil
	}
	if transactionLimit > 0 {
		if transactionLimit < 100 {
			transactionLimit = 100
		}
		_, err := DB.Exec(`DELETE FROM enforcement_transaction_steps
			WHERE transaction_id NOT IN (
				SELECT transaction_id FROM enforcement_transactions
				ORDER BY datetime(started_at) DESC, id DESC
				LIMIT ?
			)`, transactionLimit)
		if err != nil {
			return fmt.Errorf("trim enforcement transaction steps: %w", err)
		}
		_, err = DB.Exec(`DELETE FROM enforcement_transactions
			WHERE transaction_id NOT IN (
				SELECT transaction_id FROM enforcement_transactions
				ORDER BY datetime(started_at) DESC, id DESC
				LIMIT ?
			)`, transactionLimit)
		if err != nil {
			return fmt.Errorf("trim enforcement transactions: %w", err)
		}
	}
	if driftLimit > 0 {
		if driftLimit < 100 {
			driftLimit = 100
		}
		_, err := DB.Exec(`DELETE FROM enforcement_drift_events
			WHERE drift_id NOT IN (
				SELECT drift_id FROM enforcement_drift_events
				ORDER BY datetime(observed_at) DESC, id DESC
				LIMIT ?
			)`, driftLimit)
		if err != nil {
			return fmt.Errorf("trim enforcement drift events: %w", err)
		}
	}
	return nil
}

func ListEnforcementTransactions(limit int) ([]EnforcementTransactionRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, transaction_id, operation, status, COALESCE(actor, ''),
			target_count, applied_count, skipped_count, failed_count, rollback_count,
			compensation_count, drift_count, COALESCE(plan_fingerprint, ''),
			COALESCE(previous_transaction_id, ''), COALESCE(rollback_transaction_id, ''),
			COALESCE(summary, ''), request_json, plan_json, result_json, diagnostics_json,
			COALESCE(CAST(started_at AS TEXT), ''), COALESCE(CAST(completed_at AS TEXT), '')
		FROM enforcement_transactions
		ORDER BY datetime(started_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list enforcement transactions: %w", err)
	}
	defer rows.Close()

	var records []EnforcementTransactionRecord
	for rows.Next() {
		record, err := scanEnforcementTransaction(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func GetEnforcementTransaction(transactionID string) (EnforcementTransactionRecord, []EnforcementTransactionStepRecord, bool, error) {
	if DB == nil || strings.TrimSpace(transactionID) == "" {
		return EnforcementTransactionRecord{}, nil, false, nil
	}
	row := DB.QueryRow(`SELECT id, transaction_id, operation, status, COALESCE(actor, ''),
			target_count, applied_count, skipped_count, failed_count, rollback_count,
			compensation_count, drift_count, COALESCE(plan_fingerprint, ''),
			COALESCE(previous_transaction_id, ''), COALESCE(rollback_transaction_id, ''),
			COALESCE(summary, ''), request_json, plan_json, result_json, diagnostics_json,
			COALESCE(CAST(started_at AS TEXT), ''), COALESCE(CAST(completed_at AS TEXT), '')
		FROM enforcement_transactions
		WHERE transaction_id = ?
		LIMIT 1`, strings.TrimSpace(transactionID))
	record, err := scanEnforcementTransaction(row)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return EnforcementTransactionRecord{}, nil, false, nil
		}
		return EnforcementTransactionRecord{}, nil, false, err
	}
	steps, err := ListEnforcementTransactionSteps(record.TransactionID)
	if err != nil {
		return EnforcementTransactionRecord{}, nil, false, err
	}
	return record, steps, true, nil
}

func GetLatestEnforcementRollbackCandidate() (EnforcementTransactionRecord, []EnforcementTransactionStepRecord, bool, error) {
	if DB == nil {
		return EnforcementTransactionRecord{}, nil, false, nil
	}
	rows, err := DB.Query(`SELECT id, transaction_id, operation, status, COALESCE(actor, ''),
			target_count, applied_count, skipped_count, failed_count, rollback_count,
			compensation_count, drift_count, COALESCE(plan_fingerprint, ''),
			COALESCE(previous_transaction_id, ''), COALESCE(rollback_transaction_id, ''),
			COALESCE(summary, ''), request_json, plan_json, result_json, diagnostics_json,
			COALESCE(CAST(started_at AS TEXT), ''), COALESCE(CAST(completed_at AS TEXT), '')
		FROM enforcement_transactions
		WHERE operation = 'apply' AND status IN ('applied', 'degraded', 'drifted')
		ORDER BY datetime(started_at) DESC, id DESC
		LIMIT 1`)
	if err != nil {
		if tableMissing(err) {
			return EnforcementTransactionRecord{}, nil, false, nil
		}
		return EnforcementTransactionRecord{}, nil, false, fmt.Errorf("get enforcement rollback candidate: %w", err)
	}
	if !rows.Next() {
		if err := rows.Close(); err != nil {
			return EnforcementTransactionRecord{}, nil, false, fmt.Errorf("close enforcement rollback candidate rows: %w", err)
		}
		return EnforcementTransactionRecord{}, nil, false, rows.Err()
	}
	record, err := scanEnforcementTransaction(rows)
	if err != nil {
		_ = rows.Close()
		return EnforcementTransactionRecord{}, nil, false, err
	}
	if err := rows.Close(); err != nil {
		return EnforcementTransactionRecord{}, nil, false, fmt.Errorf("close enforcement rollback candidate rows: %w", err)
	}
	steps, err := ListEnforcementTransactionSteps(record.TransactionID)
	if err != nil {
		return EnforcementTransactionRecord{}, nil, false, err
	}
	return record, steps, true, nil
}

func ListEnforcementTransactionSteps(transactionID string) ([]EnforcementTransactionStepRecord, error) {
	if DB == nil || strings.TrimSpace(transactionID) == "" {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT id, transaction_id, step_order, target, operation, status,
			COALESCE(desired_fingerprint, ''), COALESCE(active_fingerprint, ''),
			COALESCE(active_snapshot_id, ''), COALESCE(previous_snapshot_id, ''),
			COALESCE(snapshot_id, ''), COALESCE(restored_snapshot_id, ''),
			rollback_supported, COALESCE(drift_status, ''), COALESCE(message, ''),
			COALESCE(error, ''), details_json, COALESCE(CAST(started_at AS TEXT), ''),
			COALESCE(CAST(completed_at AS TEXT), '')
		FROM enforcement_transaction_steps
		WHERE transaction_id = ?
		ORDER BY step_order, id`, strings.TrimSpace(transactionID))
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list enforcement transaction steps: %w", err)
	}
	defer rows.Close()
	var steps []EnforcementTransactionStepRecord
	for rows.Next() {
		var step EnforcementTransactionStepRecord
		var rollbackSupported int
		var details string
		if err := rows.Scan(
			&step.ID,
			&step.TransactionID,
			&step.StepOrder,
			&step.Target,
			&step.Operation,
			&step.Status,
			&step.DesiredFingerprint,
			&step.ActiveFingerprint,
			&step.ActiveSnapshotID,
			&step.PreviousSnapshotID,
			&step.SnapshotID,
			&step.RestoredSnapshotID,
			&rollbackSupported,
			&step.DriftStatus,
			&step.Message,
			&step.Error,
			&details,
			&step.StartedAt,
			&step.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan enforcement transaction step: %w", err)
		}
		step.RollbackSupported = rollbackSupported == 1
		step.DetailsJSON = rawJSON(details, "{}")
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

func ListEnforcementDriftEvents(limit int) ([]EnforcementDriftEventRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(`SELECT id, drift_id, COALESCE(transaction_id, ''), target, status,
			COALESCE(desired_fingerprint, ''), COALESCE(active_fingerprint, ''),
			COALESCE(active_snapshot_id, ''), COALESCE(message, ''), details_json,
			COALESCE(actor, ''), COALESCE(CAST(observed_at AS TEXT), '')
		FROM enforcement_drift_events
		ORDER BY datetime(observed_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list enforcement drift events: %w", err)
	}
	defer rows.Close()

	var events []EnforcementDriftEventRecord
	for rows.Next() {
		var event EnforcementDriftEventRecord
		var details string
		if err := rows.Scan(
			&event.ID,
			&event.DriftID,
			&event.TransactionID,
			&event.Target,
			&event.Status,
			&event.DesiredFingerprint,
			&event.ActiveFingerprint,
			&event.ActiveSnapshotID,
			&event.Message,
			&details,
			&event.Actor,
			&event.ObservedAt,
		); err != nil {
			return nil, fmt.Errorf("scan enforcement drift event: %w", err)
		}
		event.DetailsJSON = rawJSON(details, "{}")
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetEnforcementTransactionSummary() (EnforcementTransactionSummary, error) {
	var summary EnforcementTransactionSummary
	transactions, err := ListEnforcementTransactions(1000)
	if err != nil {
		return summary, err
	}
	for _, tx := range transactions {
		summary.TotalTransactions++
		switch tx.Operation {
		case "preview":
			summary.PreviewTransactions++
		case "apply":
			summary.ApplyTransactions++
		case "drift":
			summary.DriftTransactions++
		case "rollback":
			summary.RollbackTransactions++
		}
		switch tx.Status {
		case "applied":
			summary.AppliedCount++
		case "degraded":
			summary.DegradedCount++
		case "blocked":
			summary.BlockedCount++
		case "failed":
			summary.FailedCount++
		case "compensated":
			summary.CompensatedCount++
		case "rolled_back":
			summary.RolledBackCount++
		case "drifted":
			summary.DriftedCount++
		case "in_sync":
			summary.InSyncCount++
		}
		if summary.LastTransactionAt == "" || tx.StartedAt > summary.LastTransactionAt {
			summary.LastTransactionAt = tx.StartedAt
			summary.LastTransactionID = tx.TransactionID
			summary.LastStatus = tx.Status
			summary.LastOperation = tx.Operation
			summary.LastPlanFingerprint = tx.PlanFingerprint
			summary.LastDriftCount = tx.DriftCount
		}
		steps, stepErr := ListEnforcementTransactionSteps(tx.TransactionID)
		if stepErr != nil {
			return summary, stepErr
		}
		summary.TotalSteps += len(steps)
		for _, step := range steps {
			if step.Status == "failed" {
				summary.FailedSteps++
			}
			if step.Status == "compensated" || step.Status == "rolled_back" {
				summary.CompensatedSteps++
			}
		}
	}
	drifts, err := ListEnforcementDriftEvents(1000)
	if err != nil {
		return summary, err
	}
	summary.DriftEvents = len(drifts)
	for _, drift := range drifts {
		if drift.Status == "drifted" {
			summary.OpenDriftEvents++
		}
	}
	return summary, nil
}

func insertEnforcementTransactionStep(tx *sql.Tx, input EnforcementTransactionStepInput) error {
	input.Target = normalizeEnforcementTarget(input.Target)
	input.Operation = normalizeEnforcementStepOperation(input.Operation)
	if input.Operation == "" {
		input.Operation = "apply"
	}
	input.Status = normalizeEnforcementStepStatus(input.Status)
	if input.Target == "" || input.Status == "" {
		return fmt.Errorf("enforcement transaction step target and status are required")
	}
	input.DetailsJSON = defaultJSON(input.DetailsJSON, "{}")
	_, err := tx.Exec(`INSERT INTO enforcement_transaction_steps (
			transaction_id, step_order, target, operation, status, desired_fingerprint,
			active_fingerprint, active_snapshot_id, previous_snapshot_id, snapshot_id,
			restored_snapshot_id, rollback_supported, drift_status, message, error,
			details_json, started_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(input.TransactionID),
		nonNegativeInt(input.StepOrder),
		input.Target,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.DesiredFingerprint)),
		nullString(strings.TrimSpace(input.ActiveFingerprint)),
		nullString(strings.TrimSpace(input.ActiveSnapshotID)),
		nullString(strings.TrimSpace(input.PreviousSnapshotID)),
		nullString(strings.TrimSpace(input.SnapshotID)),
		nullString(strings.TrimSpace(input.RestoredSnapshotID)),
		boolToSQLite(input.RollbackSupported),
		nullString(strings.TrimSpace(input.DriftStatus)),
		nullString(strings.TrimSpace(input.Message)),
		nullString(strings.TrimSpace(input.Error)),
		input.DetailsJSON,
		timeOrNil(input.StartedAt),
		timeOrNil(input.CompletedAt),
	)
	if err != nil {
		return fmt.Errorf("record enforcement transaction step: %w", err)
	}
	return nil
}

type enforcementTransactionScanner interface {
	Scan(dest ...any) error
}

func scanEnforcementTransaction(row enforcementTransactionScanner) (EnforcementTransactionRecord, error) {
	var record EnforcementTransactionRecord
	var requestJSON, planJSON, resultJSON, diagnosticsJSON string
	if err := row.Scan(
		&record.ID,
		&record.TransactionID,
		&record.Operation,
		&record.Status,
		&record.Actor,
		&record.TargetCount,
		&record.AppliedCount,
		&record.SkippedCount,
		&record.FailedCount,
		&record.RollbackCount,
		&record.CompensationCount,
		&record.DriftCount,
		&record.PlanFingerprint,
		&record.PreviousTransactionID,
		&record.RollbackTransactionID,
		&record.Summary,
		&requestJSON,
		&planJSON,
		&resultJSON,
		&diagnosticsJSON,
		&record.StartedAt,
		&record.CompletedAt,
	); err != nil {
		return EnforcementTransactionRecord{}, fmt.Errorf("scan enforcement transaction: %w", err)
	}
	record.RequestJSON = rawJSON(requestJSON, "{}")
	record.PlanJSON = rawJSON(planJSON, "{}")
	record.ResultJSON = rawJSON(resultJSON, "{}")
	record.DiagnosticsJSON = rawJSON(diagnosticsJSON, "[]")
	return record, nil
}

func normalizeEnforcementTransactionOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "drift", "rollback":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeEnforcementTransactionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "degraded", "blocked", "failed", "compensated", "rolled_back", "drifted", "in_sync", "skipped":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func normalizeEnforcementStepStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pending", "previewed", "applied", "degraded", "blocked", "failed", "rolled_back", "compensated", "skipped", "drifted", "in_sync", "unknown":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func normalizeEnforcementStepOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "drift", "rollback", "compensate":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeEnforcementDriftStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "in_sync", "drifted", "unknown", "skipped", "blocked":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func normalizeEnforcementTarget(value string) string {
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

func defaultJSON(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || !json.Valid([]byte(value)) {
		return fallback
	}
	return value
}

func rawJSON(value, fallback string) json.RawMessage {
	value = defaultJSON(value, fallback)
	return json.RawMessage(value)
}
