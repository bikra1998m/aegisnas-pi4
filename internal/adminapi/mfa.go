package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	mfapkg "github.com/yourorg/aegisnas-pi4/internal/mfa"
)

type mfaUsernameRequest struct {
	Username string `json:"username"`
}

type mfaVerifyRequest struct {
	Username string `json:"username"`
	Code     string `json:"code"`
}

func HandleGetMFA(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := mfapkg.BuildReport(cfg)
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	method := strings.TrimSpace(r.URL.Query().Get("method"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)
	var events []db.MFAEvent
	var err error
	if decision != "" || method != "" || limit != 100 {
		events, err = db.ListMFAEvents(decision, method, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"events":       events,
	})
}

func HandleEnrollMFA(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req mfaUsernameRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	enrollment, err := mfapkg.EnrollTOTP(r.Context(), cfg, req.Username)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "mfa.enroll", "username_hash="+enrollment.UsernameHash, "success")
	writeJSON(w, http.StatusCreated, enrollment)
}

func HandleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req mfaVerifyRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	result, err := mfapkg.VerifyOTP(r.Context(), cfg, req.Username, req.Code, mfapkg.StepUpContext{
		Username: req.Username,
		Source:   "admin-api",
	}, true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func HandleRotateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req mfaUsernameRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	codes, err := mfapkg.RotateRecoveryCodes(req.Username, cfg)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "mfa.recovery.rotate", "username_hash="+db.HashIdentityUsername(req.Username), "success")
	writeJSON(w, http.StatusCreated, map[string]any{
		"username_hash":  db.HashIdentityUsername(req.Username),
		"recovery_codes": codes,
	})
}
