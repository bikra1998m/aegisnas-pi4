package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type PolicyEngineEvaluation struct {
	ID                 int    `json:"id"`
	EvaluationID       string `json:"evaluation_id"`
	EvaluatedAt        string `json:"evaluated_at"`
	PolicySetHash      string `json:"policy_set_hash"`
	RequestHash        string `json:"request_hash"`
	UsernameHash       string `json:"username_hash,omitempty"`
	CallingStationHash string `json:"calling_station_hash,omitempty"`
	Tenant             string `json:"tenant,omitempty"`
	Decision           string `json:"decision"`
	Allowed            bool   `json:"allowed"`
	Quarantine         bool   `json:"quarantine"`
	MatchedRulesJSON   string `json:"matched_rules_json"`
	ConflictsJSON      string `json:"conflicts_json"`
	TraceJSON          string `json:"trace_json"`
	RequestSummaryJSON string `json:"request_summary_json"`
	RequestReplayJSON  string `json:"request_replay_json"`
	LegacyRuleCount    int    `json:"legacy_rule_count"`
	TypedRuleCount     int    `json:"typed_rule_count"`
	InvalidRuleCount   int    `json:"invalid_rule_count"`
	LatencyMS          int64  `json:"latency_ms"`
	CreatedAt          string `json:"created_at"`
}

type PolicyEngineEvaluationSummary struct {
	TotalRecords         int    `json:"total_records"`
	AllowedCount         int    `json:"allowed_count"`
	DeniedCount          int    `json:"denied_count"`
	QuarantineCount      int    `json:"quarantine_count"`
	TypedRuleCount       int    `json:"typed_rule_count"`
	LegacyRuleCount      int    `json:"legacy_rule_count"`
	InvalidRuleCount     int    `json:"invalid_rule_count"`
	LastEvaluatedAt      string `json:"last_evaluated_at,omitempty"`
	LastDecision         string `json:"last_decision,omitempty"`
	LastPolicySetHash    string `json:"last_policy_set_hash,omitempty"`
	LastEvaluationID     string `json:"last_evaluation_id,omitempty"`
	LastConflictCount    int    `json:"last_conflict_count"`
	LastMatchedRuleCount int    `json:"last_matched_rule_count"`
}

func RecordPolicyEngineEvaluation(record PolicyEngineEvaluation, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	record.EvaluationID = strings.TrimSpace(record.EvaluationID)
	record.PolicySetHash = strings.TrimSpace(record.PolicySetHash)
	record.RequestHash = strings.TrimSpace(record.RequestHash)
	record.Decision = strings.ToLower(strings.TrimSpace(record.Decision))
	if record.EvaluationID == "" || record.PolicySetHash == "" || record.RequestHash == "" {
		return fmt.Errorf("evaluation_id, policy_set_hash, and request_hash are required")
	}
	switch record.Decision {
	case "allow", "deny", "quarantine":
	default:
		return fmt.Errorf("policy decision %q is invalid", record.Decision)
	}
	if strings.TrimSpace(record.EvaluatedAt) == "" {
		record.EvaluatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	record.UsernameHash = HashEAPIdentity(record.UsernameHash)
	record.CallingStationHash = HashEAPIdentity(record.CallingStationHash)
	record.Tenant = strings.TrimSpace(record.Tenant)
	record.MatchedRulesJSON = defaultJSONObjectArray(record.MatchedRulesJSON)
	record.ConflictsJSON = defaultJSONObjectArray(record.ConflictsJSON)
	record.TraceJSON = defaultJSONObjectArray(record.TraceJSON)
	record.RequestSummaryJSON = defaultJSONObject(record.RequestSummaryJSON)
	record.RequestReplayJSON = defaultJSONObject(record.RequestReplayJSON)

	_, err := DB.Exec(`INSERT INTO policy_engine_evaluations (
		evaluation_id, evaluated_at, policy_set_hash, request_hash, username_hash, calling_station_hash,
		tenant, decision, allowed, quarantine, matched_rules_json, conflicts_json, trace_json,
		request_summary_json, request_replay_json, legacy_rule_count, typed_rule_count, invalid_rule_count, latency_ms
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(evaluation_id) DO UPDATE SET
		evaluated_at = excluded.evaluated_at,
		policy_set_hash = excluded.policy_set_hash,
		request_hash = excluded.request_hash,
		username_hash = excluded.username_hash,
		calling_station_hash = excluded.calling_station_hash,
		tenant = excluded.tenant,
		decision = excluded.decision,
		allowed = excluded.allowed,
		quarantine = excluded.quarantine,
		matched_rules_json = excluded.matched_rules_json,
		conflicts_json = excluded.conflicts_json,
		trace_json = excluded.trace_json,
		request_summary_json = excluded.request_summary_json,
		request_replay_json = excluded.request_replay_json,
		legacy_rule_count = excluded.legacy_rule_count,
		typed_rule_count = excluded.typed_rule_count,
		invalid_rule_count = excluded.invalid_rule_count,
		latency_ms = excluded.latency_ms`,
		record.EvaluationID, record.EvaluatedAt, record.PolicySetHash, record.RequestHash, nullIfEmpty(record.UsernameHash),
		nullIfEmpty(record.CallingStationHash), nullIfEmpty(record.Tenant), record.Decision, record.Allowed, record.Quarantine,
		record.MatchedRulesJSON, record.ConflictsJSON, record.TraceJSON, record.RequestSummaryJSON,
		record.RequestReplayJSON,
		record.LegacyRuleCount, record.TypedRuleCount, record.InvalidRuleCount, record.LatencyMS)
	if err != nil {
		return err
	}
	return prunePolicyEngineEvaluations(retentionLimit)
}

func ListPolicyEngineEvaluations(limit int) ([]PolicyEngineEvaluation, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, evaluation_id, evaluated_at, policy_set_hash, request_hash,
		COALESCE(username_hash, ''), COALESCE(calling_station_hash, ''), COALESCE(tenant, ''),
		decision, allowed, quarantine, matched_rules_json, conflicts_json, trace_json, request_summary_json,
		COALESCE(request_replay_json, '{}'), legacy_rule_count, typed_rule_count, invalid_rule_count, latency_ms, created_at
		FROM policy_engine_evaluations ORDER BY evaluated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicyEngineEvaluation
	for rows.Next() {
		record, err := scanPolicyEngineEvaluation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func SummarizePolicyEngine(retentionLimit int) (PolicyEngineEvaluationSummary, error) {
	var summary PolicyEngineEvaluationSummary
	if DB == nil {
		return summary, nil
	}
	limit := retentionLimit
	if limit <= 0 || limit > 1000000 {
		limit = 10000
	}
	rows, err := DB.Query(`SELECT decision, allowed, quarantine, legacy_rule_count, typed_rule_count, invalid_rule_count,
		evaluated_at, policy_set_hash, evaluation_id, matched_rules_json, conflicts_json
		FROM policy_engine_evaluations ORDER BY evaluated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return summary, nil
		}
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var decision, evaluatedAt, policyHash, evaluationID, matchedJSON, conflictsJSON string
		var allowed, quarantine bool
		var legacyCount, typedCount, invalidCount int
		if err := rows.Scan(&decision, &allowed, &quarantine, &legacyCount, &typedCount, &invalidCount, &evaluatedAt, &policyHash, &evaluationID, &matchedJSON, &conflictsJSON); err != nil {
			return summary, err
		}
		summary.TotalRecords++
		if summary.LastEvaluatedAt == "" {
			summary.LastEvaluatedAt = evaluatedAt
			summary.LastDecision = decision
			summary.LastPolicySetHash = policyHash
			summary.LastEvaluationID = evaluationID
			summary.LastMatchedRuleCount = jsonArrayLength(matchedJSON)
			summary.LastConflictCount = jsonArrayLength(conflictsJSON)
		}
		if allowed {
			summary.AllowedCount++
		}
		if quarantine {
			summary.QuarantineCount++
		}
		if decision == "deny" {
			summary.DeniedCount++
		}
		if typedCount > summary.TypedRuleCount {
			summary.TypedRuleCount = typedCount
		}
		if legacyCount > summary.LegacyRuleCount {
			summary.LegacyRuleCount = legacyCount
		}
		if invalidCount > summary.InvalidRuleCount {
			summary.InvalidRuleCount = invalidCount
		}
	}
	return summary, rows.Err()
}

func prunePolicyEngineEvaluations(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM policy_engine_evaluations
		WHERE id NOT IN (
			SELECT id FROM policy_engine_evaluations ORDER BY evaluated_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	return err
}

func scanPolicyEngineEvaluation(rows interface {
	Scan(dest ...any) error
}) (PolicyEngineEvaluation, error) {
	var record PolicyEngineEvaluation
	err := rows.Scan(&record.ID, &record.EvaluationID, &record.EvaluatedAt, &record.PolicySetHash, &record.RequestHash,
		&record.UsernameHash, &record.CallingStationHash, &record.Tenant, &record.Decision, &record.Allowed, &record.Quarantine,
		&record.MatchedRulesJSON, &record.ConflictsJSON, &record.TraceJSON, &record.RequestSummaryJSON,
		&record.RequestReplayJSON,
		&record.LegacyRuleCount, &record.TypedRuleCount, &record.InvalidRuleCount, &record.LatencyMS, &record.CreatedAt)
	return record, err
}

func defaultJSONObjectArray(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "[]"
	}
	var value []any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return "[]"
	}
	return raw
}

func defaultJSONObject(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}"
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return "{}"
	}
	return raw
}

func jsonArrayLength(raw string) int {
	var items []any
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return 0
	}
	return len(items)
}

func nullIfEmpty(value string) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
