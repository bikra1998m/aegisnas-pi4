package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"go.uber.org/zap"
)

const subscriberServiceChainsSchemaVersion = 1

type subscriberServiceChainsReport struct {
	SchemaVersion int                               `json:"schema_version"`
	Status        string                            `json:"status"`
	Message       string                            `json:"message"`
	Config        subscriberServiceChainsConfigView `json:"config"`
	Summary       db.SubscriberServiceChainSummary  `json:"summary"`
	Recent        []subscriberServiceChainView      `json:"recent_chains"`
	Events        []db.SubscriberServiceEventRecord `json:"recent_events"`
}

type subscriberServiceChainsConfigView struct {
	TypedEngineEnabled    bool `json:"typed_engine_enabled"`
	FailClosed            bool `json:"fail_closed"`
	AuditEnabled          bool `json:"audit_enabled"`
	MaxServiceChainLength int  `json:"max_service_chain_length"`
}

type subscriberServiceChainRequest struct {
	SessionID        string                 `json:"session_id,omitempty"`
	Username         string                 `json:"username,omitempty"`
	CallingStationID string                 `json:"calling_station_id,omitempty"`
	Tenant           string                 `json:"tenant,omitempty"`
	Request          policy.Request         `json:"request,omitempty"`
	Services         []policy.ServiceIntent `json:"services,omitempty"`
	Reason           string                 `json:"reason,omitempty"`
}

type subscriberServiceChainPreview struct {
	SchemaVersion int                           `json:"schema_version"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	SessionID     string                        `json:"session_id,omitempty"`
	ChainID       string                        `json:"chain_id,omitempty"`
	Decision      policy.Decision               `json:"decision"`
	MatchedRules  []policy.MatchedRule          `json:"matched_rules,omitempty"`
	Conflicts     []string                      `json:"conflicts,omitempty"`
	Validation    policy.ServiceChainValidation `json:"validation"`
	PolicySetHash string                        `json:"policy_set_hash,omitempty"`
	RequestHash   string                        `json:"request_hash,omitempty"`
}

type subscriberServiceChainActivationResponse struct {
	SchemaVersion int                               `json:"schema_version"`
	Status        string                            `json:"status"`
	Message       string                            `json:"message"`
	Preview       subscriberServiceChainPreview     `json:"preview"`
	Chain         subscriberServiceChainView        `json:"chain"`
	Events        []db.SubscriberServiceEventRecord `json:"events,omitempty"`
}

type subscriberServiceChainRollbackRequest struct {
	Reason string `json:"reason,omitempty"`
}

type subscriberServiceChainView struct {
	db.SubscriberServiceChainRecord
	Decision any                    `json:"decision,omitempty"`
	Services []policy.ServiceIntent `json:"services,omitempty"`
}

func HandleGetSubscriberServiceChains(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 1000)
	report, err := buildSubscriberServiceChainsReport(cfg, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func HandlePreviewSubscriberServiceChain(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var payload subscriberServiceChainRequest
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	preview, err := previewSubscriberServiceChain(cfg, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func HandleActivateSubscriberServiceChain(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var payload subscriberServiceChainRequest
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	preview, err := previewSubscriberServiceChain(cfg, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !preview.Validation.Valid || preview.Validation.ServiceCount == 0 {
		http.Error(w, "subscriber service chain is invalid or empty", http.StatusBadRequest)
		return
	}
	if !preview.Decision.Allow {
		http.Error(w, "policy decision denied service-chain activation", http.StatusForbidden)
		return
	}

	decisionJSON, _ := json.Marshal(preview.Decision)
	servicesJSON, _ := json.Marshal(preview.Validation.Services)
	record, err := db.ActivateSubscriberServiceChain(db.SubscriberServiceActivationRequest{
		SessionID:        preview.SessionID,
		Username:         firstNonEmpty(payload.Username, payload.Request.Username),
		CallingStationID: firstNonEmpty(payload.CallingStationID, payload.Request.CallingStationID),
		Tenant:           firstNonEmpty(payload.Tenant, payload.Request.Tenant),
		PolicySetHash:    preview.PolicySetHash,
		RequestHash:      preview.RequestHash,
		ServiceChainHash: preview.Validation.ChainHash,
		ServiceCount:     preview.Validation.ServiceCount,
		RequiredCount:    preview.Validation.Required,
		OptionalCount:    preview.Validation.Optional,
		DecisionJSON:     string(decisionJSON),
		ServicesJSON:     string(servicesJSON),
		Actor:            userFromRequest(r),
		ActivationMode:   "policy",
		StartedAt:        time.Now().UTC(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events, err := db.ListSubscriberServiceEvents(record.ChainID, 100)
	if err != nil {
		logging.L().Warn("list subscriber service events failed", zap.String("chain_id", record.ChainID), zap.Error(err))
	}
	audit(r, "activate_subscriber_service_chain", record.ChainID, "activated")
	writeJSON(w, http.StatusOK, subscriberServiceChainActivationResponse{
		SchemaVersion: subscriberServiceChainsSchemaVersion,
		Status:        "activated",
		Message:       "Subscriber service chain activated and accounting evidence recorded.",
		Preview:       preview,
		Chain:         subscriberServiceChainRecordView(record),
		Events:        events,
	})
}

func HandleRollbackSubscriberServiceChain(w http.ResponseWriter, r *http.Request) {
	chainID := strings.TrimSpace(chi.URLParam(r, "chainID"))
	if chainID == "" {
		http.Error(w, "chain_id is required", http.StatusBadRequest)
		return
	}
	var payload subscriberServiceChainRollbackRequest
	if r.Body != nil {
		_ = decodeBody(r, &payload)
	}
	reason := strings.TrimSpace(payload.Reason)
	if reason == "" {
		reason = "operator rollback"
	}
	record, err := db.RollbackSubscriberServiceChain(chainID, userFromRequest(r), reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events, err := db.ListSubscriberServiceEvents(record.ChainID, 100)
	if err != nil {
		logging.L().Warn("list subscriber service rollback events failed", zap.String("chain_id", record.ChainID), zap.Error(err))
	}
	audit(r, "rollback_subscriber_service_chain", record.ChainID, "rolled_back")
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": subscriberServiceChainsSchemaVersion,
		"status":         "rolled_back",
		"message":        "Subscriber service chain rollback recorded.",
		"chain":          subscriberServiceChainRecordView(record),
		"events":         events,
	})
}

func buildSubscriberServiceChainsReport(cfg *config.Config, limit int) (subscriberServiceChainsReport, error) {
	summary, err := db.SummarizeSubscriberServiceChains()
	if err != nil {
		return subscriberServiceChainsReport{}, err
	}
	chains, err := db.ListSubscriberServiceChains(limit)
	if err != nil {
		return subscriberServiceChainsReport{}, err
	}
	events, err := db.ListSubscriberServiceEvents("", limit)
	if err != nil {
		return subscriberServiceChainsReport{}, err
	}
	report := subscriberServiceChainsReport{
		SchemaVersion: subscriberServiceChainsSchemaVersion,
		Config: subscriberServiceChainsConfigView{
			TypedEngineEnabled:    cfg.Policy.TypedEngineEnabled,
			FailClosed:            cfg.Policy.FailClosed,
			AuditEnabled:          cfg.Policy.AuditEnabled,
			MaxServiceChainLength: effectiveMaxServiceChainLength(cfg),
		},
		Summary: summary,
		Events:  events,
	}
	for _, record := range chains {
		report.Recent = append(report.Recent, subscriberServiceChainRecordView(record))
	}
	switch {
	case !cfg.Policy.TypedEngineEnabled:
		report.Status = "blocked"
		report.Message = "Typed policy engine is disabled; service chains require deterministic policy decisions."
	case cfg.Policy.MaxServiceChainLength < 0 || cfg.Policy.MaxServiceChainLength > policy.MaxServiceChainLength:
		report.Status = "blocked"
		report.Message = "Configured max_service_chain_length is outside the supported range."
	case summary.FailedChains > 0 || summary.FailedEvents > 0:
		report.Status = "degraded"
		report.Message = "Subscriber service chain history contains failed activation evidence."
	case summary.TotalChains == 0:
		report.Status = "degraded"
		report.Message = "No subscriber service chain activation evidence exists yet."
	default:
		report.Status = "passed"
		report.Message = "Subscriber service chains are configured and activation evidence is available."
	}
	return report, nil
}

func previewSubscriberServiceChain(cfg *config.Config, payload subscriberServiceChainRequest) (subscriberServiceChainPreview, error) {
	req := normalizeSubscriberPolicyRequest(payload)
	if req.Username == "" && req.CallingStationID == "" && req.NASIdentifier == "" && req.NASIPAddress == "" && len(payload.Services) == 0 {
		return subscriberServiceChainPreview{}, fmt.Errorf("policy request or services are required")
	}
	engine := policy.NewEngine(logging.L())
	result, err := engine.EvaluateDetailed(&req)
	if err != nil {
		return subscriberServiceChainPreview{}, err
	}
	services := payload.Services
	if len(services) == 0 {
		services = result.Decision.ServiceChain
	}
	services = policy.NormalizeServiceChain(services)
	validation := policy.SummarizeServiceChain(services)
	maxLength := effectiveMaxServiceChainLength(cfg)
	if err := policy.ValidateServiceChainWithLimit(services, maxLength); err != nil {
		validation.Valid = false
		validation.Errors = append(validation.Errors, err.Error())
	}
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		sessionID = deriveSubscriberSessionID(req)
	}
	chainID := ""
	if sessionID != "" && validation.ChainHash != "" && validation.ServiceCount > 0 {
		chainID = db.SubscriberServiceChainID(sessionID, result.PolicySetHash, result.RequestHash, validation.ChainHash)
	}
	status := "ready"
	message := "Subscriber service chain preview is valid."
	if !result.Decision.Allow {
		status = "denied"
		message = "Policy decision denies activation."
	} else if !validation.Valid {
		status = "invalid"
		message = "Subscriber service chain is invalid."
	} else if validation.ServiceCount == 0 {
		status = "empty"
		message = "Policy decision did not produce service-chain intents."
	}
	return subscriberServiceChainPreview{
		SchemaVersion: subscriberServiceChainsSchemaVersion,
		Status:        status,
		Message:       message,
		SessionID:     sessionID,
		ChainID:       chainID,
		Decision:      result.Decision,
		MatchedRules:  result.MatchedRules,
		Conflicts:     result.Conflicts,
		Validation:    validation,
		PolicySetHash: result.PolicySetHash,
		RequestHash:   result.RequestHash,
	}, nil
}

func normalizeSubscriberPolicyRequest(payload subscriberServiceChainRequest) policy.Request {
	req := payload.Request
	if req.Username == "" {
		req.Username = strings.TrimSpace(payload.Username)
	}
	if req.CallingStationID == "" {
		req.CallingStationID = strings.TrimSpace(payload.CallingStationID)
	}
	if req.Tenant == "" {
		req.Tenant = strings.TrimSpace(payload.Tenant)
	}
	if req.EvaluatedAt.IsZero() {
		req.EvaluatedAt = time.Now().UTC()
	}
	return req
}

func deriveSubscriberSessionID(req policy.Request) string {
	parts := []string{req.Username, req.CallingStationID, req.NASIdentifier, req.NASIPAddress, req.NASPortID, req.SSID}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	joined := strings.Join(parts, "|")
	if strings.Trim(joined, "|") == "" {
		return ""
	}
	return "policy-" + db.HashEAPIdentity(joined)[:24]
}

func subscriberServiceChainRecordView(record db.SubscriberServiceChainRecord) subscriberServiceChainView {
	view := subscriberServiceChainView{SubscriberServiceChainRecord: record}
	if json.Valid([]byte(record.DecisionJSON)) {
		_ = json.Unmarshal([]byte(record.DecisionJSON), &view.Decision)
	}
	if json.Valid([]byte(record.ServicesJSON)) {
		_ = json.Unmarshal([]byte(record.ServicesJSON), &view.Services)
		view.Services = policy.NormalizeServiceChain(view.Services)
	}
	return view
}

func effectiveMaxServiceChainLength(cfg *config.Config) int {
	if cfg == nil || cfg.Policy.MaxServiceChainLength <= 0 || cfg.Policy.MaxServiceChainLength > policy.MaxServiceChainLength {
		return policy.MaxServiceChainLength
	}
	return cfg.Policy.MaxServiceChainLength
}
