package db

import (
	"fmt"
	"strings"
)

type PolicySimulationAnalysisRecord struct {
	ID                          int    `json:"id"`
	AnalysisID                  string `json:"analysis_id"`
	VersionID                   int    `json:"version_id"`
	ActiveVersionID             int    `json:"active_version_id,omitempty"`
	ActivePolicySHA256          string `json:"active_policy_sha256"`
	CandidatePolicySHA256       string `json:"candidate_policy_sha256"`
	SampleSource                string `json:"sample_source"`
	SampleCount                 int    `json:"sample_count"`
	DecisionChangeCount         int    `json:"decision_change_count"`
	AllowToDenyCount            int    `json:"allow_to_deny_count"`
	DenyToAllowCount            int    `json:"deny_to_allow_count"`
	QuarantineChangeCount       int    `json:"quarantine_change_count"`
	VLANChangeCount             int    `json:"vlan_change_count"`
	BandwidthProfileChangeCount int    `json:"bandwidth_profile_change_count"`
	ACLPolicyChangeCount        int    `json:"acl_policy_change_count"`
	PortalProfileChangeCount    int    `json:"portal_profile_change_count"`
	SessionTimeoutChangeCount   int    `json:"session_timeout_change_count"`
	ServiceChainChangeCount     int    `json:"service_chain_change_count"`
	ConflictCount               int    `json:"conflict_count"`
	InvalidRuleCount            int    `json:"invalid_rule_count"`
	ShadowedRuleCount           int    `json:"shadowed_rule_count"`
	IneffectiveRuleCount        int    `json:"ineffective_rule_count"`
	RiskLevel                   string `json:"risk_level"`
	Actor                       string `json:"actor,omitempty"`
	SummaryJSON                 string `json:"summary_json"`
	ResultJSON                  string `json:"result_json"`
	CreatedAt                   string `json:"created_at"`
}

type PolicySimulationAnalysisSummary struct {
	TotalAnalyses            int    `json:"total_analyses"`
	LastAnalysisID           string `json:"last_analysis_id,omitempty"`
	LastRiskLevel            string `json:"last_risk_level,omitempty"`
	LastCreatedAt            string `json:"last_created_at,omitempty"`
	LastSampleCount          int    `json:"last_sample_count"`
	LastDecisionChangeCount  int    `json:"last_decision_change_count"`
	LastShadowedRuleCount    int    `json:"last_shadowed_rule_count"`
	LastIneffectiveRuleCount int    `json:"last_ineffective_rule_count"`
	CriticalCount            int    `json:"critical_count"`
	HighCount                int    `json:"high_count"`
	MediumCount              int    `json:"medium_count"`
	LowCount                 int    `json:"low_count"`
	UnknownCount             int    `json:"unknown_count"`
}

type PolicyEngineReplaySampleRecord struct {
	EvaluationID       string `json:"evaluation_id"`
	EvaluatedAt        string `json:"evaluated_at"`
	PolicySetHash      string `json:"policy_set_hash"`
	RequestHash        string `json:"request_hash"`
	Decision           string `json:"decision"`
	Allowed            bool   `json:"allowed"`
	Quarantine         bool   `json:"quarantine"`
	MatchedRulesJSON   string `json:"matched_rules_json"`
	ConflictsJSON      string `json:"conflicts_json"`
	TraceJSON          string `json:"trace_json"`
	RequestSummaryJSON string `json:"request_summary_json"`
	RequestReplayJSON  string `json:"request_replay_json"`
}

func RecordPolicySimulationAnalysis(record PolicySimulationAnalysisRecord, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	record.AnalysisID = strings.TrimSpace(record.AnalysisID)
	record.ActivePolicySHA256 = strings.TrimSpace(record.ActivePolicySHA256)
	record.CandidatePolicySHA256 = strings.TrimSpace(record.CandidatePolicySHA256)
	record.SampleSource = strings.TrimSpace(record.SampleSource)
	record.RiskLevel = strings.ToLower(strings.TrimSpace(record.RiskLevel))
	if record.SampleSource == "" {
		record.SampleSource = "unknown"
	}
	if record.AnalysisID == "" || record.VersionID <= 0 || record.ActivePolicySHA256 == "" || record.CandidatePolicySHA256 == "" {
		return fmt.Errorf("analysis_id, version_id, active_policy_sha256, and candidate_policy_sha256 are required")
	}
	switch record.RiskLevel {
	case "unknown", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("policy simulation risk level %q is invalid", record.RiskLevel)
	}
	record.SummaryJSON = defaultJSONObject(record.SummaryJSON)
	record.ResultJSON = defaultJSONObject(record.ResultJSON)
	_, err := DB.Exec(`INSERT INTO policy_simulation_analyses (
		analysis_id, version_id, active_version_id, active_policy_sha256, candidate_policy_sha256,
		sample_source, sample_count, decision_change_count, allow_to_deny_count, deny_to_allow_count,
		quarantine_change_count, vlan_change_count, bandwidth_profile_change_count, acl_policy_change_count,
		portal_profile_change_count, session_timeout_change_count, service_chain_change_count, conflict_count, invalid_rule_count,
		shadowed_rule_count, ineffective_rule_count, risk_level, actor, summary_json, result_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(analysis_id) DO UPDATE SET
		version_id = excluded.version_id,
		active_version_id = excluded.active_version_id,
		active_policy_sha256 = excluded.active_policy_sha256,
		candidate_policy_sha256 = excluded.candidate_policy_sha256,
		sample_source = excluded.sample_source,
		sample_count = excluded.sample_count,
		decision_change_count = excluded.decision_change_count,
		allow_to_deny_count = excluded.allow_to_deny_count,
		deny_to_allow_count = excluded.deny_to_allow_count,
		quarantine_change_count = excluded.quarantine_change_count,
		vlan_change_count = excluded.vlan_change_count,
		bandwidth_profile_change_count = excluded.bandwidth_profile_change_count,
		acl_policy_change_count = excluded.acl_policy_change_count,
		portal_profile_change_count = excluded.portal_profile_change_count,
		session_timeout_change_count = excluded.session_timeout_change_count,
		service_chain_change_count = excluded.service_chain_change_count,
		conflict_count = excluded.conflict_count,
		invalid_rule_count = excluded.invalid_rule_count,
		shadowed_rule_count = excluded.shadowed_rule_count,
		ineffective_rule_count = excluded.ineffective_rule_count,
		risk_level = excluded.risk_level,
		actor = excluded.actor,
		summary_json = excluded.summary_json,
		result_json = excluded.result_json`,
		record.AnalysisID, record.VersionID, intOrNull(record.ActiveVersionID), record.ActivePolicySHA256, record.CandidatePolicySHA256,
		record.SampleSource, nonNegative(record.SampleCount), nonNegative(record.DecisionChangeCount), nonNegative(record.AllowToDenyCount), nonNegative(record.DenyToAllowCount),
		nonNegative(record.QuarantineChangeCount), nonNegative(record.VLANChangeCount), nonNegative(record.BandwidthProfileChangeCount), nonNegative(record.ACLPolicyChangeCount),
		nonNegative(record.PortalProfileChangeCount), nonNegative(record.SessionTimeoutChangeCount), nonNegative(record.ServiceChainChangeCount), nonNegative(record.ConflictCount), nonNegative(record.InvalidRuleCount),
		nonNegative(record.ShadowedRuleCount), nonNegative(record.IneffectiveRuleCount), record.RiskLevel, nullIfEmpty(record.Actor), record.SummaryJSON, record.ResultJSON)
	if err != nil {
		return err
	}
	return prunePolicySimulationAnalyses(retentionLimit)
}

func ListPolicySimulationAnalyses(limit int) ([]PolicySimulationAnalysisRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, analysis_id, version_id, COALESCE(active_version_id, 0),
		active_policy_sha256, candidate_policy_sha256, sample_source, sample_count, decision_change_count,
		allow_to_deny_count, deny_to_allow_count, quarantine_change_count, vlan_change_count,
		bandwidth_profile_change_count, acl_policy_change_count, portal_profile_change_count,
		session_timeout_change_count, COALESCE(service_chain_change_count, 0), conflict_count, invalid_rule_count, shadowed_rule_count,
		ineffective_rule_count, risk_level, COALESCE(actor, ''), summary_json, result_json, created_at
		FROM policy_simulation_analyses ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicySimulationAnalysisRecord
	for rows.Next() {
		item, err := scanPolicySimulationAnalysis(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func SummarizePolicySimulationAnalyses() (PolicySimulationAnalysisSummary, error) {
	var summary PolicySimulationAnalysisSummary
	if DB == nil {
		return summary, nil
	}
	rows, err := DB.Query(`SELECT risk_level, analysis_id, created_at, sample_count, decision_change_count,
		shadowed_rule_count, ineffective_rule_count
		FROM policy_simulation_analyses ORDER BY created_at DESC, id DESC`)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var risk, analysisID, createdAt string
		var samples, changes, shadowed, ineffective int
		if err := rows.Scan(&risk, &analysisID, &createdAt, &samples, &changes, &shadowed, &ineffective); err != nil {
			return summary, err
		}
		summary.TotalAnalyses++
		if summary.LastAnalysisID == "" {
			summary.LastAnalysisID = analysisID
			summary.LastRiskLevel = risk
			summary.LastCreatedAt = createdAt
			summary.LastSampleCount = samples
			summary.LastDecisionChangeCount = changes
			summary.LastShadowedRuleCount = shadowed
			summary.LastIneffectiveRuleCount = ineffective
		}
		switch risk {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.UnknownCount++
		}
	}
	return summary, rows.Err()
}

func ListPolicyEngineReplaySamples(limit int) ([]PolicyEngineReplaySampleRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT evaluation_id, evaluated_at, policy_set_hash, request_hash,
		decision, allowed, quarantine, matched_rules_json, conflicts_json, trace_json,
		request_summary_json, COALESCE(request_replay_json, '{}')
		FROM policy_engine_evaluations ORDER BY evaluated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []PolicyEngineReplaySampleRecord
	for rows.Next() {
		var item PolicyEngineReplaySampleRecord
		if err := rows.Scan(&item.EvaluationID, &item.EvaluatedAt, &item.PolicySetHash, &item.RequestHash,
			&item.Decision, &item.Allowed, &item.Quarantine, &item.MatchedRulesJSON, &item.ConflictsJSON,
			&item.TraceJSON, &item.RequestSummaryJSON, &item.RequestReplayJSON); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanPolicySimulationAnalysis(rows interface {
	Scan(dest ...any) error
}) (PolicySimulationAnalysisRecord, error) {
	var item PolicySimulationAnalysisRecord
	err := rows.Scan(&item.ID, &item.AnalysisID, &item.VersionID, &item.ActiveVersionID,
		&item.ActivePolicySHA256, &item.CandidatePolicySHA256, &item.SampleSource, &item.SampleCount,
		&item.DecisionChangeCount, &item.AllowToDenyCount, &item.DenyToAllowCount, &item.QuarantineChangeCount,
		&item.VLANChangeCount, &item.BandwidthProfileChangeCount, &item.ACLPolicyChangeCount, &item.PortalProfileChangeCount,
		&item.SessionTimeoutChangeCount, &item.ServiceChainChangeCount, &item.ConflictCount, &item.InvalidRuleCount, &item.ShadowedRuleCount,
		&item.IneffectiveRuleCount, &item.RiskLevel, &item.Actor, &item.SummaryJSON, &item.ResultJSON, &item.CreatedAt)
	return item, err
}

func prunePolicySimulationAnalyses(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM policy_simulation_analyses
		WHERE id NOT IN (
			SELECT id FROM policy_simulation_analyses ORDER BY created_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	return err
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
