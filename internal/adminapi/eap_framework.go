package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	eappkg "github.com/yourorg/aegisnas-pi4/internal/eap"
)

type eapFrameworkResponse struct {
	eappkg.Report
	Events []db.EAPMethodEvent `json:"events,omitempty"`
}

type eapEvaluationRequest struct {
	Method                      string            `json:"method"`
	InnerMethod                 string            `json:"inner_method"`
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	UserName                    string            `json:"user_name"`
	CallingStationID            string            `json:"calling_station_id"`
	IdentitySource              string            `json:"identity_source"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	CertificatePresented        bool              `json:"certificate_presented"`
	TLSVersion                  string            `json:"tls_version"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

func HandleGetEAPFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.EAPMethodEventFilter{
		Method:   r.URL.Query().Get("method"),
		Decision: r.URL.Query().Get("decision"),
		NASType:  r.URL.Query().Get("nas_type"),
		Limit:    limit,
	}
	events, err := db.ListEAPMethodEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeEAPMethodEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildFrameworkReport(cfg, eapRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, eapFrameworkResponse{Report: report, Events: events})
}

func HandleEvaluateEAPFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req eapEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.Evaluate(cfg, eappkg.EvaluationRequest{
		Method:                      req.Method,
		InnerMethod:                 req.InnerMethod,
		NASType:                     req.NASType,
		IdentitySource:              req.IdentitySource,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		CertificatePresented:        req.CertificatePresented,
		TLSVersion:                  req.TLSVersion,
	})
	if req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		_ = db.RecordEAPMethodEvent(db.EAPMethodEvent{
			ObservedAt:                  time.Now().UTC(),
			Method:                      decision.Method,
			InnerMethod:                 decision.InnerMethod,
			Decision:                    decision.Decision,
			Reason:                      decision.Reason,
			NASIdentifier:               req.NASIdentifier,
			NASType:                     req.NASType,
			UserNameHash:                db.HashEAPIdentity(req.UserName),
			CallingStationHash:          db.HashEAPIdentity(req.CallingStationID),
			IdentitySource:              decision.IdentitySource,
			EAPMessagePresent:           req.EAPMessagePresent,
			MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
			CertificatePresented:        req.CertificatePresented,
			TLSVersion:                  req.TLSVersion,
			PolicyMode:                  decision.PolicyMode,
			LatencyMS:                   latency,
			Details:                     req.Details,
		}, cfg.Radius.EAP.Framework.EventRetentionLimit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled,
	})
}

func eapRuntimeSummaryFromDB(summary db.EAPMethodEventSummary) eappkg.RuntimeSummary {
	return eappkg.RuntimeSummary{
		TotalEvents:        summary.TotalEvents,
		Accepted:           summary.Accepted,
		Rejected:           summary.Rejected,
		MonitorAllowed:     summary.MonitorAllowed,
		Unsupported:        summary.Unsupported,
		ByMethod:           summary.ByMethod,
		ByDecision:         summary.ByDecision,
		LastEventAt:        summary.LastEventAt,
		LastRejectedReason: summary.LastRejectedReason,
	}
}

func parseBoundedInt(raw string, fallback, min, max int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
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
