package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"go.uber.org/zap"
)

type policyEngineReport struct {
	SchemaVersion int                              `json:"schema_version"`
	Status        string                           `json:"status"`
	Message       string                           `json:"message"`
	Config        policyEngineConfigView           `json:"config"`
	Summary       db.PolicyEngineEvaluationSummary `json:"summary"`
	Rules         []policyRuleStatus               `json:"rules"`
	Fields        []policy.FieldSpec               `json:"fields"`
	Operators     []policy.OperatorSpec            `json:"operators"`
	Recent        []policyEngineEvaluationView     `json:"recent_evaluations"`
}

type policyEngineConfigView struct {
	TypedEngineEnabled       bool   `json:"typed_engine_enabled"`
	Mode                     string `json:"mode"`
	FailClosed               bool   `json:"fail_closed"`
	AuditEnabled             bool   `json:"audit_enabled"`
	AllowLegacyConditions    bool   `json:"allow_legacy_conditions"`
	RequireTypedRules        bool   `json:"require_typed_rules"`
	MaxExpressionDepth       int    `json:"max_expression_depth"`
	MaxExpressionNodes       int    `json:"max_expression_nodes"`
	MaxListValues            int    `json:"max_list_values"`
	EvaluationRetentionLimit int    `json:"evaluation_retention_limit"`
}

type policyRuleStatus struct {
	ID          int                    `json:"id"`
	Name        string                 `json:"name"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Action      string                 `json:"action"`
	Typed       bool                   `json:"typed"`
	Legacy      bool                   `json:"legacy"`
	Valid       bool                   `json:"valid"`
	Error       string                 `json:"error,omitempty"`
	Expression  policy.TypedExpression `json:"expression,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type policyEngineEvaluationView struct {
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
	MatchedRuleCount   int    `json:"matched_rule_count"`
	ConflictCount      int    `json:"conflict_count"`
	TraceNodeCount     int    `json:"trace_node_count"`
	LegacyRuleCount    int    `json:"legacy_rule_count"`
	TypedRuleCount     int    `json:"typed_rule_count"`
	InvalidRuleCount   int    `json:"invalid_rule_count"`
	LatencyMS          int64  `json:"latency_ms"`
}

func HandleGetPolicyEngine(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report, err := buildPolicyEngineReport(cfg, 25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func HandleValidatePolicyExpression(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	raw, err := expressionPayloadRaw(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	expr, legacy, err := policy.CompileMatchConditions(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":      true,
		"legacy":     legacy,
		"typed":      !legacy,
		"expression": expr,
	})
}

func HandleEvaluatePolicyEngine(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req policy.Request
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	engine := policy.NewEngine(logging.L())
	started := time.Now()
	result, err := engine.EvaluateDetailed(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	latency := time.Since(started)
	if cfg.Policy.AuditEnabled {
		if err := recordPolicyEvaluation(req, result, latency); err != nil {
			logging.L().Warn("record policy engine evaluation failed", zap.Error(err))
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func buildPolicyEngineReport(cfg *config.Config, recentLimit int) (policyEngineReport, error) {
	engine := policy.NewEngine(logging.L())
	rules, err := engine.LoadRules()
	if err != nil {
		return policyEngineReport{}, err
	}
	summary, err := db.SummarizePolicyEngine(cfg.Policy.EvaluationRetentionLimit)
	if err != nil {
		return policyEngineReport{}, err
	}
	recent, err := db.ListPolicyEngineEvaluations(recentLimit)
	if err != nil {
		return policyEngineReport{}, err
	}
	report := policyEngineReport{
		SchemaVersion: policy.TypedPolicySchemaVersion,
		Config:        policyEngineConfigFromConfig(cfg),
		Summary:       summary,
		Rules:         analyzePolicyRules(rules),
		Fields:        policy.FieldCatalog(),
		Operators:     policy.OperatorCatalog(),
		Recent:        policyEngineEvaluationViews(recent),
	}
	report.Status, report.Message = policyEngineReportStatus(cfg, report)
	return report, nil
}

func policyEngineConfigFromConfig(cfg *config.Config) policyEngineConfigView {
	policyCfg := cfg.Policy
	return policyEngineConfigView{
		TypedEngineEnabled:       policyCfg.TypedEngineEnabled,
		Mode:                     defaultString(policyCfg.Mode, "monitor"),
		FailClosed:               policyCfg.FailClosed,
		AuditEnabled:             policyCfg.AuditEnabled,
		AllowLegacyConditions:    policyCfg.AllowLegacyConditions,
		RequireTypedRules:        policyCfg.RequireTypedRules,
		MaxExpressionDepth:       policyCfg.MaxExpressionDepth,
		MaxExpressionNodes:       policyCfg.MaxExpressionNodes,
		MaxListValues:            policyCfg.MaxListValues,
		EvaluationRetentionLimit: policyCfg.EvaluationRetentionLimit,
	}
}

func analyzePolicyRules(rules []policy.Rule) []policyRuleStatus {
	out := make([]policyRuleStatus, 0, len(rules))
	for _, rule := range rules {
		item := policyRuleStatus{
			ID: rule.ID, Name: rule.Name, Priority: rule.Priority, Enabled: rule.Enabled,
			Action: strings.ToLower(strings.TrimSpace(rule.Action)), Description: rule.Description,
		}
		expr, legacy, err := policy.CompileMatchConditions(rule.MatchConditions)
		item.Legacy = legacy
		item.Typed = !legacy
		item.Expression = expr
		item.Valid = err == nil
		if err != nil {
			item.Error = err.Error()
		}
		out = append(out, item)
	}
	return out
}

func policyEngineReportStatus(cfg *config.Config, report policyEngineReport) (string, string) {
	if !cfg.Policy.TypedEngineEnabled {
		return "disabled", "Typed policy engine is disabled; legacy policy rules still exist but are not production-ready for NAS-0029."
	}
	invalid := 0
	legacy := 0
	enabled := 0
	for _, rule := range report.Rules {
		if !rule.Enabled {
			continue
		}
		enabled++
		if !rule.Valid {
			invalid++
		}
		if rule.Legacy {
			legacy++
		}
	}
	if invalid > 0 && cfg.Policy.FailClosed {
		return "blocked", fmt.Sprintf("%d enabled policy rule(s) are invalid and fail-closed is enabled.", invalid)
	}
	if cfg.Policy.RequireTypedRules && legacy > 0 {
		return "blocked", fmt.Sprintf("%d enabled policy rule(s) still use legacy match_conditions while typed rules are required.", legacy)
	}
	if enabled == 0 {
		return "degraded", "No enabled policy rules are available; requests will default deny."
	}
	if legacy > 0 {
		return "degraded", fmt.Sprintf("Typed policy engine is active with %d legacy rule(s) still allowed for migration.", legacy)
	}
	return "passed", "Typed policy engine is active with all enabled rules represented as typed expressions."
}

func expressionPayloadRaw(payload map[string]any) (json.RawMessage, error) {
	if payload == nil {
		return nil, fmt.Errorf("request body is required")
	}
	value, ok := payload["match_conditions"]
	if !ok {
		value = payload["expression"]
	}
	if value == nil {
		return nil, fmt.Errorf("match_conditions or expression is required")
	}
	if raw, ok := value.(string); ok {
		if strings.TrimSpace(raw) == "" {
			return json.RawMessage(`{}`), nil
		}
		if !json.Valid([]byte(raw)) {
			return nil, fmt.Errorf("expression JSON is invalid")
		}
		return json.RawMessage(raw), nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func recordPolicyEvaluation(req policy.Request, result *policy.EvaluationResult, latency time.Duration) error {
	if result == nil {
		return nil
	}
	decision := "deny"
	if result.Decision.Allow {
		decision = "allow"
	}
	if result.Decision.Quarantine {
		decision = "quarantine"
	}
	matched, _ := json.Marshal(result.MatchedRules)
	conflicts, _ := json.Marshal(result.Conflicts)
	trace, _ := json.Marshal(result.Trace)
	summary := map[string]any{
		"role":            req.Role,
		"groups":          len(req.Groups),
		"realm":           req.Realm,
		"tenant":          req.Tenant,
		"auth_method":     req.AuthMethod,
		"identity_source": req.IdentitySource,
		"ssid":            req.SSID,
		"nas_identifier":  req.NASIdentifier,
		"nas_port_type":   req.NASPortType,
		"site":            req.Site,
		"vendor":          req.Vendor,
		"vlan":            req.VLAN,
		"posture":         req.Posture,
		"risk_score":      req.RiskScore,
	}
	requestSummary, _ := json.Marshal(summary)
	return db.RecordPolicyEngineEvaluation(db.PolicyEngineEvaluation{
		EvaluationID:       result.EvaluationID,
		EvaluatedAt:        result.EvaluatedAt,
		PolicySetHash:      result.PolicySetHash,
		RequestHash:        result.RequestHash,
		UsernameHash:       req.Username,
		CallingStationHash: req.CallingStationID,
		Tenant:             req.Tenant,
		Decision:           decision,
		Allowed:            result.Decision.Allow,
		Quarantine:         result.Decision.Quarantine,
		MatchedRulesJSON:   string(matched),
		ConflictsJSON:      string(conflicts),
		TraceJSON:          string(trace),
		RequestSummaryJSON: string(requestSummary),
		LegacyRuleCount:    result.LegacyRuleCount,
		TypedRuleCount:     result.TypedRuleCount,
		InvalidRuleCount:   result.InvalidRuleCount,
		LatencyMS:          latency.Milliseconds(),
	}, config.Get().Policy.EvaluationRetentionLimit)
}

func policyEngineEvaluationViews(records []db.PolicyEngineEvaluation) []policyEngineEvaluationView {
	out := make([]policyEngineEvaluationView, 0, len(records))
	for _, record := range records {
		out = append(out, policyEngineEvaluationView{
			ID:                 record.ID,
			EvaluationID:       record.EvaluationID,
			EvaluatedAt:        record.EvaluatedAt,
			PolicySetHash:      record.PolicySetHash,
			RequestHash:        record.RequestHash,
			UsernameHash:       record.UsernameHash,
			CallingStationHash: record.CallingStationHash,
			Tenant:             record.Tenant,
			Decision:           record.Decision,
			Allowed:            record.Allowed,
			Quarantine:         record.Quarantine,
			MatchedRuleCount:   jsonArrayCount(record.MatchedRulesJSON),
			ConflictCount:      jsonArrayCount(record.ConflictsJSON),
			TraceNodeCount:     jsonArrayCount(record.TraceJSON),
			LegacyRuleCount:    record.LegacyRuleCount,
			TypedRuleCount:     record.TypedRuleCount,
			InvalidRuleCount:   record.InvalidRuleCount,
			LatencyMS:          record.LatencyMS,
		})
	}
	return out
}

func jsonArrayCount(raw string) int {
	var items []any
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return 0
	}
	return len(items)
}
