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

type outboundDACReplayRequest struct {
	BatchSize int `json:"batch_size"`
}

type outboundDACQueueIDRequest struct {
	QueueID string `json:"queue_id"`
	Reason  string `json:"reason,omitempty"`
}

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

func HandleGetNASOwnership(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       radius.BuildNASCapabilityOwnershipReport(cfg),
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

func HandleEnqueueOutboundDAC(w http.ResponseWriter, r *http.Request) {
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
	result, err := radius.EnqueueOutboundDAC(r.Context(), cfg, request, requestedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "enqueue_outbound_dac", result.Queue.QueueID, result.Status)
	writeJSON(w, http.StatusOK, result)
}

func HandleReplayOutboundDACQueue(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request outboundDACReplayRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid replay request", http.StatusBadRequest)
			return
		}
	}
	report, err := radius.ReplayOutboundDACQueue(r.Context(), cfg, request.BatchSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "replay_outbound_dac_queue", "due", report.Status)
	writeJSON(w, http.StatusOK, report)
}

func HandleCancelOutboundDACQueue(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request outboundDACQueueIDRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid cancel request", http.StatusBadRequest)
			return
		}
	}
	identity := adminIdentityFromRequest(r)
	result, err := radius.CancelOutboundDACQueue(r.Context(), cfg, request.QueueID, firstNonEmptyAdminString(identity.Subject, identity.Role, "admin"), request.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "cancel_outbound_dac_queue", result.Queue.QueueID, result.Status)
	writeJSON(w, http.StatusOK, result)
}

func HandleRetryOutboundDACQueue(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var request outboundDACQueueIDRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "invalid retry request", http.StatusBadRequest)
			return
		}
	}
	result, err := radius.RetryOutboundDACQueue(r.Context(), cfg, request.QueueID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "retry_outbound_dac_queue", result.Queue.QueueID, result.Status)
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
	queueStatus := strings.TrimSpace(r.URL.Query().Get("queue_status"))
	queueID := strings.TrimSpace(r.URL.Query().Get("queue_id"))
	queueRecords, err := db.ListOutboundDACQueue(queueStatus, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queueAttempts, err := db.ListOutboundDACQueueAttempts(queueID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.GetOutboundDACSummary(config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth).OutboundHistoryLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queueSummary, err := db.GetOutboundDACQueueSummary(config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth).OutboundMaxQueueRecords)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"summary":        summary,
		"records":        records,
		"attempts":       attempts,
		"queue_summary":  queueSummary,
		"queue_records":  queueRecords,
		"queue_attempts": queueAttempts,
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
