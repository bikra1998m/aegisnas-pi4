package adminapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetOutboundDACClient(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       radius.BuildOutboundDACReport(cfg),
	})
}

func HandlePreviewOutboundDAC(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	request, ok := decodeOutboundDACRequest(w, r)
	if !ok {
		return
	}
	preview, err := radius.PreviewOutboundDAC(r.Context(), cfg, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "preview_outbound_dac", preview.Target.Endpoint, preview.Status)
	writeJSON(w, http.StatusOK, preview)
}

func HandleSendOutboundDAC(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	request, ok := decodeOutboundDACRequest(w, r)
	if !ok {
		return
	}
	identity := adminIdentityFromRequest(r)
	requestedBy := firstNonEmptyAdminString(identity.Subject, identity.Role, "admin")
	result, err := radius.SendOutboundDAC(r.Context(), cfg, request, requestedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "send_outbound_dac", result.Request.RequestID, result.Status)
	writeJSON(w, http.StatusOK, result)
}

func HandleListOutboundDACHistory(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseAccountingSpoolLimit(r.URL.Query().Get("limit"), 100)
	query := db.OutboundDACRequestQuery{
		Status:        strings.TrimSpace(r.URL.Query().Get("status")),
		Action:        strings.TrimSpace(r.URL.Query().Get("action")),
		TargetAddress: strings.TrimSpace(r.URL.Query().Get("target_address")),
		SessionID:     strings.TrimSpace(r.URL.Query().Get("session_id")),
		Limit:         limit,
	}
	records, err := db.ListOutboundDACRequests(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	attemptRequestID := strings.TrimSpace(r.URL.Query().Get("request_id"))
	attempts, err := db.ListOutboundDACAttempts(attemptRequestID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.GetOutboundDACSummary(config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth).OutboundHistoryLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"records":      records,
		"attempts":     attempts,
	})
}

func decodeOutboundDACRequest(w http.ResponseWriter, r *http.Request) (radius.OutboundDACRequest, bool) {
	var request radius.OutboundDACRequest
	if r.Body == nil {
		http.Error(w, "outbound DAC request body is required", http.StatusBadRequest)
		return request, false
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid outbound DAC request", http.StatusBadRequest)
		return request, false
	}
	return request, true
}
