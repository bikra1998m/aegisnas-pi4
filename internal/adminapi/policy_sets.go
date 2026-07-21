package adminapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
)

var syncRuntimeEnforcementForPolicySetFn = enforcement.SyncRuntimeEnforcement

type policySetGovernanceReport struct {
	SchemaVersion int                        `json:"schema_version"`
	Status        string                     `json:"status"`
	Message       string                     `json:"message"`
	Config        policySetGovernanceConfig  `json:"config"`
	Summary       db.PolicySetVersionSummary `json:"summary"`
	Active        *policySetVersionView      `json:"active,omitempty"`
	Versions      []policySetVersionView     `json:"versions"`
	Events        []policySetActivationEvent `json:"events"`
}

type policySetGovernanceConfig struct {
	ApprovalRequired bool `json:"approval_required"`
	MinApprovals     int  `json:"min_approvals"`
	MakerChecker     bool `json:"maker_checker"`
	MaxDepth         int  `json:"max_depth"`
	RetentionLimit   int  `json:"retention_limit"`
}

type policySetVersionView struct {
	db.PolicySetVersion
	Approvals []db.PolicySetApproval `json:"approvals,omitempty"`
	Content   policy.PolicySet       `json:"content"`
}

type policySetActivationEvent struct {
	ID                int    `json:"id"`
	VersionID         int    `json:"version_id"`
	PreviousVersionID int    `json:"previous_version_id,omitempty"`
	EventType         string `json:"event_type"`
	Status            string `json:"status"`
	Actor             string `json:"actor,omitempty"`
	Summary           string `json:"summary,omitempty"`
	Details           any    `json:"details,omitempty"`
	CreatedAt         string `json:"created_at"`
}

type createPolicySetVersionRequest struct {
	SetKey              string            `json:"set_key"`
	Description         string            `json:"description"`
	Content             *policy.PolicySet `json:"content"`
	FromCurrent         bool              `json:"from_current"`
	ParentVersionID     int               `json:"parent_version_id"`
	RollbackOfVersionID int               `json:"rollback_of_version_id"`
	Submit              bool              `json:"submit"`
}

type policySetActionRequest struct {
	Comment string `json:"comment"`
	Reason  string `json:"reason"`
	Note    string `json:"note"`
}

func HandleGetPolicySets(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report, err := buildPolicySetGovernanceReport(cfg, 25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func HandleListPolicySetVersions(w http.ResponseWriter, r *http.Request) {
	limit := intQuery(r, "limit", 100, 1, 1000)
	versions, err := db.ListPolicySetVersions(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views, err := policySetVersionViews(versions, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

func HandleCreatePolicySetVersion(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req createPolicySetVersionRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	set, err := policySetFromCreateRequest(req, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	summary, contentJSON, err := summarizePolicySetForStorage(set, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status := db.PolicySetStatusDraft
	if req.Submit {
		status = db.PolicySetStatusPendingApproval
	}
	version, err := db.CreatePolicySetVersion(r.Context(), db.CreatePolicySetVersionRequest{
		SetKey:              summary.Key,
		Description:         req.Description,
		ParentVersionID:     req.ParentVersionID,
		RollbackOfVersionID: req.RollbackOfVersionID,
		ContentJSON:         contentJSON,
		ContentSHA256:       summary.ContentHash,
		PolicySHA256:        summary.PolicyHash,
		RuleCount:           summary.RuleCount,
		ChildSetCount:       summary.ChildSetCount,
		MaxDepth:            summary.MaxDepth,
		ApprovalRequired:    cfg.Policy.VersionApprovalRequired,
		MinApprovals:        cfg.Policy.VersionMinApprovals,
		CreatedBy:           userFromRequest(r),
		Status:              status,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "create_policy_set_version", fmt.Sprintf("%s v%d", version.SetKey, version.Version), version.Status)
	view, err := policySetVersionViewFromVersion(version, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func HandleGetPolicySetVersion(w http.ResponseWriter, r *http.Request) {
	version, err := policySetVersionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if version == nil {
		http.Error(w, "policy set version not found", http.StatusNotFound)
		return
	}
	view, err := policySetVersionViewFromVersion(*version, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func HandleSubmitPolicySetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	version, err := db.SubmitPolicySetVersion(r.Context(), id, userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "submit_policy_set_version", strconv.Itoa(id), "pending_approval")
	writePolicySetVersionView(w, *version)
}

func HandleApprovePolicySetVersion(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req policySetActionRequest
	_ = decodeOptionalBody(r, &req)
	version, err := db.ApprovePolicySetVersion(r.Context(), id, userFromRequest(r), req.Comment, cfg.Policy.VersionMinApprovals, cfg.Policy.VersionMakerChecker)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "approve_policy_set_version", strconv.Itoa(id), version.Status)
	writePolicySetVersionView(w, *version)
}

func HandleRejectPolicySetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req policySetActionRequest
	_ = decodeOptionalBody(r, &req)
	version, err := db.RejectPolicySetVersion(r.Context(), id, userFromRequest(r), req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "reject_policy_set_version", strconv.Itoa(id), "rejected")
	writePolicySetVersionView(w, *version)
}

func HandleActivatePolicySetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req policySetActionRequest
	_ = decodeOptionalBody(r, &req)
	if err := activatePolicySetVersion(r, id, req.Note, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	version, err := db.GetPolicySetVersion(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePolicySetVersionView(w, *version)
}

func HandleRollbackPolicySetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req policySetActionRequest
	_ = decodeOptionalBody(r, &req)
	note := defaultString(req.Note, fmt.Sprintf("Rollback to policy set version %d", id))
	if err := activatePolicySetVersion(r, id, note, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	version, err := db.GetPolicySetVersion(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePolicySetVersionView(w, *version)
}

func HandleComparePolicySetVersions(w http.ResponseWriter, r *http.Request) {
	fromID, err := strconv.Atoi(chi.URLParam(r, "fromID"))
	if err != nil || fromID <= 0 {
		http.Error(w, "invalid from version id", http.StatusBadRequest)
		return
	}
	toID, err := strconv.Atoi(chi.URLParam(r, "toID"))
	if err != nil || toID <= 0 {
		http.Error(w, "invalid to version id", http.StatusBadRequest)
		return
	}
	from, err := db.GetPolicySetVersion(fromID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	to, err := db.GetPolicySetVersion(toID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if from == nil || to == nil {
		http.Error(w, "policy set version not found", http.StatusNotFound)
		return
	}
	fromSet, err := policy.ParsePolicySet(from.ContentJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	toSet, err := policy.ParsePolicySet(to.ContentJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := config.Get()
	maxDepth := 0
	if cfg != nil {
		maxDepth = cfg.Policy.MaxPolicySetDepth
	}
	diff, err := policy.ComparePolicySets(fromSet, toSet, maxDepth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func HandleSimulatePolicySetVersion(w http.ResponseWriter, r *http.Request) {
	version, err := policySetVersionFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if version == nil {
		http.Error(w, "policy set version not found", http.StatusNotFound)
		return
	}
	var req policy.Request
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	set, err := policy.ParsePolicySet(version.ContentJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := config.Get()
	maxDepth := 0
	if cfg != nil {
		maxDepth = cfg.Policy.MaxPolicySetDepth
	}
	rules, err := policy.FlattenPolicySet(set, maxDepth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := policy.EvaluateRules(&req, rules, logging.L())
	decision := "deny"
	if result.Decision.Allow {
		decision = "allow"
	}
	if result.Decision.Quarantine {
		decision = "quarantine"
	}
	resultJSON, _ := json.Marshal(result)
	_ = db.RecordPolicySetSimulation(db.PolicySetSimulation{
		VersionID:        version.ID,
		EvaluationID:     result.EvaluationID,
		PolicySHA256:     result.PolicySetHash,
		RequestHash:      result.RequestHash,
		Decision:         decision,
		Allowed:          result.Decision.Allow,
		Quarantine:       result.Decision.Quarantine,
		ConflictCount:    len(result.Conflicts),
		MatchedRuleCount: len(result.MatchedRules),
		TraceNodeCount:   len(result.Trace),
		Actor:            userFromRequest(r),
		ResultJSON:       string(resultJSON),
	})
	writeJSON(w, http.StatusOK, result)
}

func buildPolicySetGovernanceReport(cfg *config.Config, limit int) (policySetGovernanceReport, error) {
	summary, err := db.SummarizePolicySetVersions()
	if err != nil {
		return policySetGovernanceReport{}, err
	}
	versions, err := db.ListPolicySetVersions(limit)
	if err != nil {
		return policySetGovernanceReport{}, err
	}
	views, err := policySetVersionViews(versions, false)
	if err != nil {
		return policySetGovernanceReport{}, err
	}
	events, err := db.ListPolicySetActivationEvents(limit)
	if err != nil {
		return policySetGovernanceReport{}, err
	}
	activeVersion, err := db.GetActivePolicySetVersion("default")
	if err != nil {
		return policySetGovernanceReport{}, err
	}
	var active *policySetVersionView
	if activeVersion != nil {
		view, err := policySetVersionViewFromVersion(*activeVersion, false)
		if err != nil {
			return policySetGovernanceReport{}, err
		}
		active = &view
	}
	report := policySetGovernanceReport{
		SchemaVersion: policy.PolicySetSchemaVersion,
		Config: policySetGovernanceConfig{
			ApprovalRequired: cfg.Policy.VersionApprovalRequired,
			MinApprovals:     cfg.Policy.VersionMinApprovals,
			MakerChecker:     cfg.Policy.VersionMakerChecker,
			MaxDepth:         cfg.Policy.MaxPolicySetDepth,
			RetentionLimit:   cfg.Policy.VersionRetentionLimit,
		},
		Summary:  summary,
		Active:   active,
		Versions: views,
		Events:   policySetActivationEventViews(events),
	}
	report.Status, report.Message = policySetGovernanceStatus(report)
	return report, nil
}

func policySetGovernanceStatus(report policySetGovernanceReport) (string, string) {
	switch {
	case report.Config.ApprovalRequired && report.Config.MinApprovals < 1:
		return "blocked", "Policy version approval is required but no approval threshold is configured."
	case report.Active == nil:
		if report.Summary.TotalVersions == 0 {
			return "degraded", "No immutable policy set versions exist yet; live evaluation still uses legacy policy_rules."
		}
		return "degraded", "Policy set versions exist but no approved version is active."
	case report.Active.ApprovalRequired && report.Active.ApprovalCount < report.Active.MinApprovals:
		return "blocked", "The active policy set version does not have the configured approval evidence."
	case report.Summary.PendingApprovalCount > 0:
		return "degraded", fmt.Sprintf("%d policy set version(s) are waiting for approval.", report.Summary.PendingApprovalCount)
	default:
		return "passed", fmt.Sprintf("Policy set version %d is active with immutable approval evidence.", report.Active.Version)
	}
}

func policySetFromCreateRequest(req createPolicySetVersionRequest, cfg *config.Config) (policy.PolicySet, error) {
	if req.Content != nil {
		set := policy.NormalizePolicySet(*req.Content)
		if err := policy.ValidatePolicySet(set, cfg.Policy.MaxPolicySetDepth); err != nil {
			return policy.PolicySet{}, err
		}
		return set, nil
	}
	rules, err := loadPolicyRulesForVersion()
	if err != nil {
		return policy.PolicySet{}, err
	}
	if len(rules) == 0 {
		return policy.PolicySet{}, fmt.Errorf("no policy rules are available to version")
	}
	return policy.PolicySetFromRules(req.SetKey, "Default Policy Set", req.Description, rules), nil
}

func summarizePolicySetForStorage(set policy.PolicySet, cfg *config.Config) (policy.PolicySetSummary, string, error) {
	set = policy.NormalizePolicySet(set)
	summary, err := policy.SummarizePolicySet(set, cfg.Policy.MaxPolicySetDepth)
	if err != nil {
		return policy.PolicySetSummary{}, "", err
	}
	data, err := json.Marshal(set)
	if err != nil {
		return policy.PolicySetSummary{}, "", err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err == nil {
		data = compact.Bytes()
	}
	return summary, string(data), nil
}

func loadPolicyRulesForVersion() ([]policy.Rule, error) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), priority, enabled, match_conditions, action,
		vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine
		FROM policy_rules ORDER BY priority DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []policy.Rule
	for rows.Next() {
		rule, err := scanPolicyRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func replacePolicyRulesTx(tx *sql.Tx, rules []policy.Rule) error {
	if _, err := tx.Exec(`DELETE FROM policy_rules`); err != nil {
		return err
	}
	for _, rule := range rules {
		match := string(policy.NormalizeRule(rule).MatchConditions)
		if _, err := tx.Exec(`INSERT INTO policy_rules (
			name, description, priority, enabled, match_conditions, action, vlan, bandwidth_profile,
			session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rule.Name, rule.Description, rule.Priority, rule.Enabled, match, rule.Action,
			intPtrOrNull(rule.VLAN), stringPtrOrNull(rule.BandwidthProfile), intPtrOrNull(rule.SessionTimeout),
			intPtrOrNull(rule.IdleTimeout), stringPtrOrNull(rule.PortalProfile), stringPtrOrNull(rule.ACLPolicyName),
			rule.Quarantine); err != nil {
			return err
		}
	}
	return nil
}

func activatePolicySetVersion(r *http.Request, id int, note string, rollback bool) error {
	cfg := config.Get()
	if cfg == nil {
		return fmt.Errorf("configuration not loaded")
	}
	version, err := db.GetPolicySetVersion(id)
	if err != nil {
		return err
	}
	if version == nil {
		return fmt.Errorf("policy set version not found")
	}
	if cfg.Policy.VersionApprovalRequired && version.ApprovalCount < cfg.Policy.VersionMinApprovals {
		return fmt.Errorf("policy set version %d has %d approval(s), requires %d", id, version.ApprovalCount, cfg.Policy.VersionMinApprovals)
	}
	set, err := policy.ParsePolicySet(version.ContentJSON)
	if err != nil {
		return err
	}
	rules, err := policy.FlattenPolicySet(set, cfg.Policy.MaxPolicySetDepth)
	if err != nil {
		return err
	}
	tx, err := db.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveConfigSnapshot(tx, userFromRequest(r)); err != nil {
		return fmt.Errorf("save pre-activation snapshot: %w", err)
	}
	if err := replacePolicyRulesTx(tx, rules); err != nil {
		return fmt.Errorf("replace policy rules: %w", err)
	}
	previousID, err := db.MarkPolicySetVersionActiveTx(tx, id, userFromRequest(r), note)
	if err != nil {
		return err
	}
	eventType := "activate_policy_set_version"
	if rollback {
		eventType = "rollback_policy_set_version"
		if err := db.InsertPolicySetActivationEventTx(tx, id, previousID, "rollback", "active", userFromRequest(r), note, map[string]any{"previous_version_id": previousID}); err != nil {
			return err
		}
	}
	auditTx(tx, r, eventType, strconv.Itoa(id), "active")
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := syncRuntimeEnforcementForPolicySetFn(cfg); err != nil {
		return fmt.Errorf("runtime enforcement sync after policy activation: %w", err)
	}
	return nil
}

func policySetVersionViews(versions []db.PolicySetVersion, includeApprovals bool) ([]policySetVersionView, error) {
	out := make([]policySetVersionView, 0, len(versions))
	for _, version := range versions {
		view, err := policySetVersionViewFromVersion(version, includeApprovals)
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

func policySetVersionViewFromVersion(version db.PolicySetVersion, includeApprovals bool) (policySetVersionView, error) {
	set, err := policy.ParsePolicySet(version.ContentJSON)
	if err != nil {
		return policySetVersionView{}, err
	}
	view := policySetVersionView{PolicySetVersion: version, Content: set}
	if includeApprovals {
		approvals, err := db.ListPolicySetApprovals(version.ID)
		if err != nil {
			return policySetVersionView{}, err
		}
		view.Approvals = approvals
	}
	return view, nil
}

func policySetActivationEventViews(events []db.PolicySetActivationEvent) []policySetActivationEvent {
	out := make([]policySetActivationEvent, 0, len(events))
	for _, event := range events {
		var details any
		if strings.TrimSpace(event.DetailsJSON) != "" {
			_ = json.Unmarshal([]byte(event.DetailsJSON), &details)
		}
		out = append(out, policySetActivationEvent{
			ID: event.ID, VersionID: event.VersionID, PreviousVersionID: event.PreviousVersionID,
			EventType: event.EventType, Status: event.Status, Actor: event.Actor, Summary: event.Summary,
			Details: details, CreatedAt: event.CreatedAt,
		})
	}
	return out
}

func scanPolicyRule(rows interface {
	Scan(dest ...any) error
}) (policy.Rule, error) {
	var rule policy.Rule
	var vlan, sessionTimeout, idleTimeout sql.NullInt64
	var bandwidthProfile, portalProfile, aclPolicyName sql.NullString
	var matchConditions string
	if err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.Priority, &rule.Enabled, &matchConditions, &rule.Action,
		&vlan, &bandwidthProfile, &sessionTimeout, &idleTimeout, &portalProfile, &aclPolicyName, &rule.Quarantine); err != nil {
		return policy.Rule{}, err
	}
	rule.MatchConditions = json.RawMessage(matchConditions)
	if vlan.Valid {
		v := int(vlan.Int64)
		rule.VLAN = &v
	}
	if bandwidthProfile.Valid {
		value := bandwidthProfile.String
		rule.BandwidthProfile = &value
	}
	if sessionTimeout.Valid {
		value := int(sessionTimeout.Int64)
		rule.SessionTimeout = &value
	}
	if idleTimeout.Valid {
		value := int(idleTimeout.Int64)
		rule.IdleTimeout = &value
	}
	if portalProfile.Valid {
		value := portalProfile.String
		rule.PortalProfile = &value
	}
	if aclPolicyName.Valid {
		value := aclPolicyName.String
		rule.ACLPolicyName = &value
	}
	return policy.NormalizeRule(rule), nil
}

func policySetVersionFromRequest(r *http.Request) (*db.PolicySetVersion, error) {
	id, err := policySetVersionIDFromRequest(r)
	if err != nil {
		return nil, err
	}
	return db.GetPolicySetVersion(id)
}

func policySetVersionIDFromRequest(r *http.Request) (int, error) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid policy set version id")
	}
	return id, nil
}

func writePolicySetVersionView(w http.ResponseWriter, version db.PolicySetVersion) {
	view, err := policySetVersionViewFromVersion(version, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func decodeOptionalBody(r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		if err.Error() == "EOF" {
			return nil
		}
		return err
	}
	return nil
}

func intQuery(r *http.Request, name string, fallback, min, max int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func intPtrOrNull(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func stringPtrOrNull(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return strings.TrimSpace(*value)
}

func sortPolicySetRulesForView(rules []policy.Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].Name < rules[j].Name
		}
		return rules[i].Priority > rules[j].Priority
	})
}
