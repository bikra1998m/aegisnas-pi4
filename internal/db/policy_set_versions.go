package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	PolicySetStatusDraft           = "draft"
	PolicySetStatusPendingApproval = "pending_approval"
	PolicySetStatusApproved        = "approved"
	PolicySetStatusActive          = "active"
	PolicySetStatusSuperseded      = "superseded"
	PolicySetStatusRejected        = "rejected"
)

type PolicySetVersion struct {
	ID                  int    `json:"id"`
	SetKey              string `json:"set_key"`
	Tenant              string `json:"tenant,omitempty"`
	Version             int    `json:"version"`
	Status              string `json:"status"`
	Description         string `json:"description,omitempty"`
	ParentVersionID     int    `json:"parent_version_id,omitempty"`
	RollbackOfVersionID int    `json:"rollback_of_version_id,omitempty"`
	ContentJSON         string `json:"content_json"`
	ContentSHA256       string `json:"content_sha256"`
	PolicySHA256        string `json:"policy_sha256"`
	RuleCount           int    `json:"rule_count"`
	ChildSetCount       int    `json:"child_set_count"`
	MaxDepth            int    `json:"max_depth"`
	ApprovalRequired    bool   `json:"approval_required"`
	MinApprovals        int    `json:"min_approvals"`
	CreatedBy           string `json:"created_by,omitempty"`
	CreatedAt           string `json:"created_at"`
	SubmittedBy         string `json:"submitted_by,omitempty"`
	SubmittedAt         string `json:"submitted_at,omitempty"`
	ActivatedBy         string `json:"activated_by,omitempty"`
	ActivatedAt         string `json:"activated_at,omitempty"`
	SupersededAt        string `json:"superseded_at,omitempty"`
	RejectedBy          string `json:"rejected_by,omitempty"`
	RejectedAt          string `json:"rejected_at,omitempty"`
	RejectionReason     string `json:"rejection_reason,omitempty"`
	ActivationNote      string `json:"activation_note,omitempty"`
	ApprovalCount       int    `json:"approval_count,omitempty"`
}

type PolicySetApproval struct {
	ID         int    `json:"id"`
	VersionID  int    `json:"version_id"`
	ApprovedBy string `json:"approved_by"`
	Comment    string `json:"comment,omitempty"`
	ApprovedAt string `json:"approved_at"`
}

type PolicySetActivationEvent struct {
	ID                int    `json:"id"`
	VersionID         int    `json:"version_id"`
	PreviousVersionID int    `json:"previous_version_id,omitempty"`
	Tenant            string `json:"tenant,omitempty"`
	EventType         string `json:"event_type"`
	Status            string `json:"status"`
	Actor             string `json:"actor,omitempty"`
	Summary           string `json:"summary,omitempty"`
	DetailsJSON       string `json:"details_json"`
	CreatedAt         string `json:"created_at"`
}

type PolicySetSimulation struct {
	ID               int    `json:"id"`
	VersionID        int    `json:"version_id"`
	Tenant           string `json:"tenant,omitempty"`
	EvaluationID     string `json:"evaluation_id"`
	PolicySHA256     string `json:"policy_sha256"`
	RequestHash      string `json:"request_hash"`
	Decision         string `json:"decision"`
	Allowed          bool   `json:"allowed"`
	Quarantine       bool   `json:"quarantine"`
	ConflictCount    int    `json:"conflict_count"`
	MatchedRuleCount int    `json:"matched_rule_count"`
	TraceNodeCount   int    `json:"trace_node_count"`
	Actor            string `json:"actor,omitempty"`
	ResultJSON       string `json:"result_json"`
	CreatedAt        string `json:"created_at"`
}

type PolicySetVersionSummary struct {
	TotalVersions        int    `json:"total_versions"`
	DraftCount           int    `json:"draft_count"`
	PendingApprovalCount int    `json:"pending_approval_count"`
	ApprovedCount        int    `json:"approved_count"`
	ActiveCount          int    `json:"active_count"`
	RejectedCount        int    `json:"rejected_count"`
	SimulationCount      int    `json:"simulation_count"`
	LastVersion          int    `json:"last_version"`
	ActiveVersionID      int    `json:"active_version_id,omitempty"`
	ActiveVersion        int    `json:"active_version,omitempty"`
	ActivePolicySHA256   string `json:"active_policy_sha256,omitempty"`
	LastActivationAt     string `json:"last_activation_at,omitempty"`
}

type CreatePolicySetVersionRequest struct {
	SetKey              string
	Tenant              string
	Description         string
	ParentVersionID     int
	RollbackOfVersionID int
	ContentJSON         string
	ContentSHA256       string
	PolicySHA256        string
	RuleCount           int
	ChildSetCount       int
	MaxDepth            int
	ApprovalRequired    bool
	MinApprovals        int
	CreatedBy           string
	Status              string
}

func CreatePolicySetVersion(ctx context.Context, req CreatePolicySetVersionRequest) (PolicySetVersion, error) {
	if DB == nil {
		return PolicySetVersion{}, fmt.Errorf("database is not initialized")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return PolicySetVersion{}, err
	}
	defer tx.Rollback()
	version, err := createPolicySetVersionTx(tx, req)
	if err != nil {
		return PolicySetVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return PolicySetVersion{}, err
	}
	return version, nil
}

func ListPolicySetVersions(limit int) ([]PolicySetVersion, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT v.id, v.set_key, COALESCE(v.tenant, ''), v.version, v.status, COALESCE(v.description, ''),
		COALESCE(v.parent_version_id, 0), COALESCE(v.rollback_of_version_id, 0), v.content_json,
		v.content_sha256, v.policy_sha256, v.rule_count, v.child_set_count, v.max_depth,
		v.approval_required, v.min_approvals, COALESCE(v.created_by, ''), v.created_at,
		COALESCE(v.submitted_by, ''), COALESCE(v.submitted_at, ''), COALESCE(v.activated_by, ''),
		COALESCE(v.activated_at, ''), COALESCE(v.superseded_at, ''), COALESCE(v.rejected_by, ''),
		COALESCE(v.rejected_at, ''), COALESCE(v.rejection_reason, ''), COALESCE(v.activation_note, ''),
		(SELECT COUNT(*) FROM policy_set_approvals a WHERE a.version_id = v.id)
		FROM policy_set_versions v ORDER BY COALESCE(v.tenant, ''), v.set_key, v.version DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicySetVersion
	for rows.Next() {
		item, err := scanPolicySetVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func ListPolicySetVersionsForTenants(limit int, tenants []string) ([]PolicySetVersion, error) {
	if DB == nil {
		return nil, nil
	}
	tenants = normalizeTenantScopes(tenants)
	if len(tenants) == 0 {
		return ListPolicySetVersions(limit)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	placeholders := make([]string, len(tenants))
	args := make([]any, 0, len(tenants)+1)
	for i, tenant := range tenants {
		placeholders[i] = "?"
		args = append(args, tenant)
	}
	args = append(args, limit)
	rows, err := DB.Query(`SELECT v.id, v.set_key, COALESCE(v.tenant, ''), v.version, v.status, COALESCE(v.description, ''),
		COALESCE(v.parent_version_id, 0), COALESCE(v.rollback_of_version_id, 0), v.content_json,
		v.content_sha256, v.policy_sha256, v.rule_count, v.child_set_count, v.max_depth,
		v.approval_required, v.min_approvals, COALESCE(v.created_by, ''), v.created_at,
		COALESCE(v.submitted_by, ''), COALESCE(v.submitted_at, ''), COALESCE(v.activated_by, ''),
		COALESCE(v.activated_at, ''), COALESCE(v.superseded_at, ''), COALESCE(v.rejected_by, ''),
		COALESCE(v.rejected_at, ''), COALESCE(v.rejection_reason, ''), COALESCE(v.activation_note, ''),
		(SELECT COUNT(*) FROM policy_set_approvals a WHERE a.version_id = v.id)
		FROM policy_set_versions v
		WHERE COALESCE(v.tenant, '') IN (`+strings.Join(placeholders, ",")+`)
		ORDER BY COALESCE(v.tenant, ''), v.set_key, v.version DESC LIMIT ?`, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicySetVersion
	for rows.Next() {
		item, err := scanPolicySetVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetPolicySetVersion(id int) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, nil
	}
	return getPolicySetVersionQuery(DB, id)
}

func GetActivePolicySetVersion(setKey string) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, nil
	}
	setKey = normalizePolicySetKey(setKey)
	return getPolicySetVersionByStatusTenantQuery(DB, setKey, "", PolicySetStatusActive)
}

func GetActivePolicySetVersionForTenant(setKey, tenant string) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, nil
	}
	return getPolicySetVersionByStatusTenantQuery(DB, normalizePolicySetKey(setKey), NormalizeTenantKey(tenant), PolicySetStatusActive)
}

func ListPolicySetApprovals(versionID int) ([]PolicySetApproval, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT id, version_id, approved_by, COALESCE(comment, ''), approved_at
		FROM policy_set_approvals WHERE version_id = ? ORDER BY approved_at`, versionID)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicySetApproval
	for rows.Next() {
		var item PolicySetApproval
		if err := rows.Scan(&item.ID, &item.VersionID, &item.ApprovedBy, &item.Comment, &item.ApprovedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func ListPolicySetActivationEvents(limit int) ([]PolicySetActivationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, version_id, COALESCE(previous_version_id, 0), COALESCE(tenant, ''), event_type, status,
		COALESCE(actor, ''), COALESCE(summary, ''), details_json, created_at
		FROM policy_set_activation_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicySetActivationEvent
	for rows.Next() {
		var item PolicySetActivationEvent
		if err := rows.Scan(&item.ID, &item.VersionID, &item.PreviousVersionID, &item.Tenant, &item.EventType, &item.Status, &item.Actor, &item.Summary, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func SubmitPolicySetVersion(ctx context.Context, id int, actor string) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database is not initialized")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	version, err := getPolicySetVersionTx(tx, id)
	if err != nil {
		return nil, err
	}
	switch version.Status {
	case PolicySetStatusDraft:
	default:
		return nil, fmt.Errorf("policy set version %d is %s and cannot be submitted", id, version.Status)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`UPDATE policy_set_versions
		SET status = ?, submitted_by = ?, submitted_at = ?
		WHERE id = ?`, PolicySetStatusPendingApproval, nullIfEmpty(actor), now, id); err != nil {
		return nil, err
	}
	if err := insertPolicySetActivationEventTx(tx, id, 0, "submitted", "pending_approval", actor, "Policy set version submitted for approval.", nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetPolicySetVersion(id)
}

func ApprovePolicySetVersion(ctx context.Context, id int, actor, comment string, minApprovals int, makerChecker bool) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database is not initialized")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	version, err := getPolicySetVersionTx(tx, id)
	if err != nil {
		return nil, err
	}
	if version.Status != PolicySetStatusPendingApproval && version.Status != PolicySetStatusApproved {
		return nil, fmt.Errorf("policy set version %d is %s and cannot be approved", id, version.Status)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil, fmt.Errorf("approval actor is required")
	}
	if makerChecker && strings.EqualFold(strings.TrimSpace(version.CreatedBy), actor) {
		return nil, fmt.Errorf("policy set version creator cannot approve when maker-checker is enabled")
	}
	if _, err := tx.Exec(`INSERT INTO policy_set_approvals (version_id, approved_by, comment, approved_at)
		VALUES (?, ?, ?, ?) ON CONFLICT(version_id, approved_by) DO UPDATE SET
		comment = excluded.comment, approved_at = excluded.approved_at`,
		id, actor, nullIfEmpty(comment), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	count, err := policySetApprovalCountTx(tx, id)
	if err != nil {
		return nil, err
	}
	if minApprovals < 0 {
		minApprovals = 0
	}
	status := PolicySetStatusPendingApproval
	if count >= minApprovals {
		status = PolicySetStatusApproved
	}
	if _, err := tx.Exec(`UPDATE policy_set_versions SET status = ? WHERE id = ?`, status, id); err != nil {
		return nil, err
	}
	if err := insertPolicySetActivationEventTx(tx, id, 0, "approved", status, actor, fmt.Sprintf("Policy set version has %d approval(s).", count), map[string]any{"approval_count": count, "min_approvals": minApprovals}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetPolicySetVersion(id)
}

func RejectPolicySetVersion(ctx context.Context, id int, actor, reason string) (*PolicySetVersion, error) {
	if DB == nil {
		return nil, fmt.Errorf("database is not initialized")
	}
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	version, err := getPolicySetVersionTx(tx, id)
	if err != nil {
		return nil, err
	}
	if version.Status == PolicySetStatusActive || version.Status == PolicySetStatusSuperseded {
		return nil, fmt.Errorf("policy set version %d is %s and cannot be rejected", id, version.Status)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`UPDATE policy_set_versions
		SET status = ?, rejected_by = ?, rejected_at = ?, rejection_reason = ?
		WHERE id = ?`, PolicySetStatusRejected, nullIfEmpty(actor), now, nullIfEmpty(reason), id); err != nil {
		return nil, err
	}
	if err := insertPolicySetActivationEventTx(tx, id, 0, "rejected", "rejected", actor, defaultPolicySetSummary(reason, "Policy set version rejected."), nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return GetPolicySetVersion(id)
}

func RecordPolicySetSimulation(record PolicySetSimulation) error {
	if DB == nil {
		return nil
	}
	record.Tenant = NormalizeTenantKey(record.Tenant)
	record.Decision = strings.ToLower(strings.TrimSpace(record.Decision))
	switch record.Decision {
	case "allow", "deny", "quarantine":
	default:
		return fmt.Errorf("policy set simulation decision %q is invalid", record.Decision)
	}
	if record.VersionID <= 0 || strings.TrimSpace(record.EvaluationID) == "" || strings.TrimSpace(record.PolicySHA256) == "" || strings.TrimSpace(record.RequestHash) == "" {
		return fmt.Errorf("version_id, evaluation_id, policy_sha256, and request_hash are required")
	}
	if strings.TrimSpace(record.ResultJSON) == "" || !json.Valid([]byte(record.ResultJSON)) {
		record.ResultJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO policy_set_simulations (
		version_id, tenant, evaluation_id, policy_sha256, request_hash, decision, allowed, quarantine,
		conflict_count, matched_rule_count, trace_node_count, actor, result_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.VersionID, nullIfEmpty(record.Tenant), record.EvaluationID, record.PolicySHA256, record.RequestHash, record.Decision, record.Allowed, record.Quarantine,
		record.ConflictCount, record.MatchedRuleCount, record.TraceNodeCount, nullIfEmpty(record.Actor), record.ResultJSON)
	return err
}

func SummarizePolicySetVersions() (PolicySetVersionSummary, error) {
	var summary PolicySetVersionSummary
	if DB == nil {
		return summary, nil
	}
	rows, err := DB.Query(`SELECT status, COUNT(*), COALESCE(MAX(version), 0) FROM policy_set_versions GROUP BY status`)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, err
	}
	for rows.Next() {
		var status string
		var count, lastVersion int
		if err := rows.Scan(&status, &count, &lastVersion); err != nil {
			rows.Close()
			return summary, err
		}
		summary.TotalVersions += count
		if lastVersion > summary.LastVersion {
			summary.LastVersion = lastVersion
		}
		switch status {
		case PolicySetStatusDraft:
			summary.DraftCount = count
		case PolicySetStatusPendingApproval:
			summary.PendingApprovalCount = count
		case PolicySetStatusApproved:
			summary.ApprovedCount = count
		case PolicySetStatusActive:
			summary.ActiveCount = count
		case PolicySetStatusRejected:
			summary.RejectedCount = count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return summary, err
	}
	rows.Close()

	if active, err := GetActivePolicySetVersion("default"); err != nil {
		return summary, err
	} else if active != nil {
		summary.ActiveVersionID = active.ID
		summary.ActiveVersion = active.Version
		summary.ActivePolicySHA256 = active.PolicySHA256
		summary.LastActivationAt = active.ActivatedAt
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM policy_set_simulations`).Scan(&summary.SimulationCount); err != nil && !tableMissing(err) {
		return summary, err
	}
	return summary, nil
}

func createPolicySetVersionTx(tx *sql.Tx, req CreatePolicySetVersionRequest) (PolicySetVersion, error) {
	req.SetKey = normalizePolicySetKey(req.SetKey)
	req.Tenant = NormalizeTenantKey(req.Tenant)
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if req.Status == "" {
		req.Status = PolicySetStatusDraft
	}
	switch req.Status {
	case PolicySetStatusDraft, PolicySetStatusPendingApproval, PolicySetStatusApproved:
	default:
		return PolicySetVersion{}, fmt.Errorf("initial policy set version status %q is invalid", req.Status)
	}
	if err := validatePolicyVersionMaterial(req.ContentJSON, req.ContentSHA256, req.PolicySHA256); err != nil {
		return PolicySetVersion{}, err
	}
	minApprovals := req.MinApprovals
	if minApprovals < 0 {
		minApprovals = 0
	}
	var nextVersion int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) + 1 FROM policy_set_versions WHERE set_key = ? AND COALESCE(tenant, '') = ?`, req.SetKey, req.Tenant).Scan(&nextVersion); err != nil {
		return PolicySetVersion{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	args := []any{
		req.SetKey, req.Tenant, nextVersion, req.Status, nullIfEmpty(req.Description), intOrNull(req.ParentVersionID), intOrNull(req.RollbackOfVersionID),
		req.ContentJSON, req.ContentSHA256, req.PolicySHA256, req.RuleCount, req.ChildSetCount, req.MaxDepth,
		req.ApprovalRequired, minApprovals, nullIfEmpty(req.CreatedBy), createdAt,
	}
	insertSQL := `INSERT INTO policy_set_versions (
		set_key, tenant, version, status, description, parent_version_id, rollback_of_version_id,
		content_json, content_sha256, policy_sha256, rule_count, child_set_count, max_depth,
		approval_required, min_approvals, created_by, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var id int
	if DialectForHandle(DB) == DialectPostgreSQL {
		if err := tx.QueryRow(insertSQL+" RETURNING id", args...).Scan(&id); err != nil {
			return PolicySetVersion{}, err
		}
	} else {
		res, err := tx.Exec(insertSQL, args...)
		if err != nil {
			return PolicySetVersion{}, err
		}
		id64, err := res.LastInsertId()
		if err != nil {
			return PolicySetVersion{}, err
		}
		id = int(id64)
	}
	if err := insertPolicySetActivationEventTx(tx, id, 0, "created", req.Status, req.CreatedBy, "Policy set version created.", map[string]any{"content_sha256": req.ContentSHA256, "policy_sha256": req.PolicySHA256}); err != nil {
		return PolicySetVersion{}, err
	}
	return getPolicySetVersionTx(tx, id)
}

func MarkPolicySetVersionActiveTx(tx *sql.Tx, versionID int, actor, note string) (previousID int, err error) {
	version, err := getPolicySetVersionTx(tx, versionID)
	if err != nil {
		return 0, err
	}
	if version.Status != PolicySetStatusApproved && version.Status != PolicySetStatusActive && version.Status != PolicySetStatusSuperseded {
		return 0, fmt.Errorf("policy set version %d is %s and cannot be activated", versionID, version.Status)
	}
	active, err := getPolicySetVersionByStatusTenantTx(tx, version.SetKey, version.Tenant, PolicySetStatusActive)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if active != nil && active.ID != versionID {
		previousID = active.ID
		if _, err := tx.Exec(`UPDATE policy_set_versions SET status = ?, superseded_at = ? WHERE id = ?`, PolicySetStatusSuperseded, now, active.ID); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`UPDATE policy_set_versions
		SET status = ?, activated_by = ?, activated_at = ?, activation_note = ?, superseded_at = NULL
		WHERE id = ?`, PolicySetStatusActive, nullIfEmpty(actor), now, nullIfEmpty(note), versionID); err != nil {
		return 0, err
	}
	if err := insertPolicySetActivationEventTx(tx, versionID, previousID, "activated", "active", actor, defaultPolicySetSummary(note, "Policy set version activated."), map[string]any{"previous_version_id": previousID, "tenant": version.Tenant}); err != nil {
		return 0, err
	}
	return previousID, nil
}

func InsertPolicySetActivationEventTx(tx *sql.Tx, versionID, previousVersionID int, eventType, status, actor, summary string, details any) error {
	return insertPolicySetActivationEventTx(tx, versionID, previousVersionID, eventType, status, actor, summary, details)
}

func GetPolicySetVersionTx(tx *sql.Tx, id int) (*PolicySetVersion, error) {
	version, err := getPolicySetVersionTx(tx, id)
	if err != nil {
		return nil, err
	}
	return &version, nil
}

func policySetApprovalCountTx(tx *sql.Tx, versionID int) (int, error) {
	var count int
	err := tx.QueryRow(`SELECT COUNT(*) FROM policy_set_approvals WHERE version_id = ?`, versionID).Scan(&count)
	return count, err
}

func getPolicySetVersionTx(tx *sql.Tx, id int) (PolicySetVersion, error) {
	version, err := getPolicySetVersionQuery(tx, id)
	if err != nil {
		return PolicySetVersion{}, err
	}
	if version == nil {
		return PolicySetVersion{}, sql.ErrNoRows
	}
	return *version, nil
}

func getPolicySetVersionQuery(q interface {
	QueryRow(query string, args ...any) *sql.Row
}, id int) (*PolicySetVersion, error) {
	row := q.QueryRow(`SELECT v.id, v.set_key, COALESCE(v.tenant, ''), v.version, v.status, COALESCE(v.description, ''),
		COALESCE(v.parent_version_id, 0), COALESCE(v.rollback_of_version_id, 0), v.content_json,
		v.content_sha256, v.policy_sha256, v.rule_count, v.child_set_count, v.max_depth,
		v.approval_required, v.min_approvals, COALESCE(v.created_by, ''), v.created_at,
		COALESCE(v.submitted_by, ''), COALESCE(v.submitted_at, ''), COALESCE(v.activated_by, ''),
		COALESCE(v.activated_at, ''), COALESCE(v.superseded_at, ''), COALESCE(v.rejected_by, ''),
		COALESCE(v.rejected_at, ''), COALESCE(v.rejection_reason, ''), COALESCE(v.activation_note, ''),
		(SELECT COUNT(*) FROM policy_set_approvals a WHERE a.version_id = v.id)
		FROM policy_set_versions v WHERE v.id = ?`, id)
	item, err := scanPolicySetVersion(row)
	if err != nil {
		if tableMissing(err) || err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func getPolicySetVersionByStatusQuery(q interface {
	QueryRow(query string, args ...any) *sql.Row
}, setKey, status string) (*PolicySetVersion, error) {
	return getPolicySetVersionByStatusTenantQuery(q, setKey, "", status)
}

func getPolicySetVersionByStatusTenantQuery(q interface {
	QueryRow(query string, args ...any) *sql.Row
}, setKey, tenant, status string) (*PolicySetVersion, error) {
	row := q.QueryRow(`SELECT v.id, v.set_key, COALESCE(v.tenant, ''), v.version, v.status, COALESCE(v.description, ''),
		COALESCE(v.parent_version_id, 0), COALESCE(v.rollback_of_version_id, 0), v.content_json,
		v.content_sha256, v.policy_sha256, v.rule_count, v.child_set_count, v.max_depth,
		v.approval_required, v.min_approvals, COALESCE(v.created_by, ''), v.created_at,
		COALESCE(v.submitted_by, ''), COALESCE(v.submitted_at, ''), COALESCE(v.activated_by, ''),
		COALESCE(v.activated_at, ''), COALESCE(v.superseded_at, ''), COALESCE(v.rejected_by, ''),
		COALESCE(v.rejected_at, ''), COALESCE(v.rejection_reason, ''), COALESCE(v.activation_note, ''),
		(SELECT COUNT(*) FROM policy_set_approvals a WHERE a.version_id = v.id)
		FROM policy_set_versions v WHERE v.set_key = ? AND COALESCE(v.tenant, '') = ? AND v.status = ? ORDER BY v.version DESC LIMIT 1`, normalizePolicySetKey(setKey), NormalizeTenantKey(tenant), status)
	item, err := scanPolicySetVersion(row)
	if err != nil {
		if tableMissing(err) || err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func getPolicySetVersionByStatusTx(tx *sql.Tx, setKey, status string) (*PolicySetVersion, error) {
	return getPolicySetVersionByStatusQuery(tx, setKey, status)
}

func getPolicySetVersionByStatusTenantTx(tx *sql.Tx, setKey, tenant, status string) (*PolicySetVersion, error) {
	return getPolicySetVersionByStatusTenantQuery(tx, setKey, tenant, status)
}

func scanPolicySetVersion(row interface {
	Scan(dest ...any) error
}) (PolicySetVersion, error) {
	var item PolicySetVersion
	err := row.Scan(&item.ID, &item.SetKey, &item.Tenant, &item.Version, &item.Status, &item.Description,
		&item.ParentVersionID, &item.RollbackOfVersionID, &item.ContentJSON,
		&item.ContentSHA256, &item.PolicySHA256, &item.RuleCount, &item.ChildSetCount, &item.MaxDepth,
		&item.ApprovalRequired, &item.MinApprovals, &item.CreatedBy, &item.CreatedAt,
		&item.SubmittedBy, &item.SubmittedAt, &item.ActivatedBy, &item.ActivatedAt,
		&item.SupersededAt, &item.RejectedBy, &item.RejectedAt, &item.RejectionReason, &item.ActivationNote,
		&item.ApprovalCount)
	return item, err
}

func insertPolicySetActivationEventTx(tx *sql.Tx, versionID, previousVersionID int, eventType, status, actor, summary string, details any) error {
	detailsJSON, err := json.Marshal(map[string]any{})
	if details != nil {
		detailsJSON, err = json.Marshal(details)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO policy_set_activation_events (
		version_id, previous_version_id, tenant, event_type, status, actor, summary, details_json
	) VALUES (?, ?, (SELECT tenant FROM policy_set_versions WHERE id = ?), ?, ?, ?, ?, ?)`,
		versionID, intOrNull(previousVersionID), versionID, strings.TrimSpace(eventType), strings.TrimSpace(status),
		nullIfEmpty(actor), nullIfEmpty(summary), string(detailsJSON))
	return err
}

func validatePolicyVersionMaterial(contentJSON, contentSHA, policySHA string) error {
	if strings.TrimSpace(contentJSON) == "" || !json.Valid([]byte(contentJSON)) {
		return fmt.Errorf("content_json must be valid JSON")
	}
	if len(strings.TrimSpace(contentSHA)) != 64 {
		return fmt.Errorf("content_sha256 must be a 64-character hex digest")
	}
	if len(strings.TrimSpace(policySHA)) != 64 {
		return fmt.Errorf("policy_sha256 must be a 64-character hex digest")
	}
	return nil
}

func normalizePolicySetKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "default"
	}
	return value
}

func normalizeTenantScopes(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = NormalizeTenantKey(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func intOrNull(value int) sql.NullInt64 {
	if value <= 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(value), Valid: true}
}

func tableMissing(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func defaultPolicySetSummary(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
