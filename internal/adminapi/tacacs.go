package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/tacacs"
	"go.uber.org/zap"
)

type tacacsCommandSetRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Enabled         *bool    `json:"enabled,omitempty"`
	DefaultAction   string   `json:"default_action"`
	Permit          []string `json:"permit"`
	Deny            []string `json:"deny"`
	Roles           []string `json:"roles"`
	PrivilegeLevels []int    `json:"privilege_levels"`
	Vendors         []string `json:"vendors"`
	Tenants         []string `json:"tenants"`
}

type tacacsEvaluateRequest struct {
	SessionID      uint32   `json:"session_id"`
	Username       string   `json:"username"`
	Role           string   `json:"role"`
	Tenant         string   `json:"tenant"`
	ClientName     string   `json:"client_name"`
	ClientIP       string   `json:"client_ip"`
	Vendor         string   `json:"vendor"`
	Model          string   `json:"model"`
	Service        string   `json:"service"`
	Port           string   `json:"port"`
	RemoteAddress  string   `json:"remote_address"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	PrivilegeLevel int      `json:"privilege_level"`
	Authenticated  bool     `json:"authenticated"`
}

func HandleGetTACACS(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseOptionalLimit(r, 25, 100)
	writeJSON(w, http.StatusOK, tacacs.BuildReport(cfg, limit))
}

func HandleEvaluateTACACSCommand(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var payload tacacsEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req := tacacs.CommandRequest{
		SessionID: payload.SessionID,
		Username:  payload.Username,
		Role:      payload.Role,
		Tenant:    payload.Tenant,
		Client: tacacs.ClientIdentity{
			Name:    strings.TrimSpace(payload.ClientName),
			IP:      strings.TrimSpace(payload.ClientIP),
			Vendor:  strings.TrimSpace(payload.Vendor),
			Model:   strings.TrimSpace(payload.Model),
			Tenant:  strings.TrimSpace(payload.Tenant),
			Known:   true,
			Enabled: true,
		},
		Service:        payload.Service,
		Port:           payload.Port,
		RemoteAddress:  payload.RemoteAddress,
		Command:        payload.Command,
		Args:           payload.Args,
		PrivilegeLevel: payload.PrivilegeLevel,
		Authenticated:  payload.Authenticated,
	}
	if strings.TrimSpace(req.Username) == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Command) == "" && len(req.Args) == 0 {
		http.Error(w, "command or args are required", http.StatusBadRequest)
		return
	}
	decision, err := tacacs.EvaluateCommand(r.Context(), cfg, req, zap.NewNop())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "evaluate_tacacs_command", decision.CommandHash, decision.Status)
	writeJSON(w, http.StatusOK, decision)
}

func HandleCreateTACACSCommandSet(w http.ResponseWriter, r *http.Request) {
	handleUpsertTACACSCommandSet(w, r, "")
}

func HandleUpdateTACACSCommandSet(w http.ResponseWriter, r *http.Request) {
	handleUpsertTACACSCommandSet(w, r, chi.URLParam(r, "name"))
}

func handleUpsertTACACSCommandSet(w http.ResponseWriter, r *http.Request, pathName string) {
	var payload tacacsCommandSetRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(pathName) != "" {
		payload.Name = pathName
	}
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	actor := userFromRequest(r)
	record, err := db.UpsertTACACSCommandSet(db.TACACSCommandSetRecord{
		Name:            payload.Name,
		Description:     payload.Description,
		Enabled:         enabled,
		DefaultAction:   payload.DefaultAction,
		Permit:          payload.Permit,
		Deny:            payload.Deny,
		Roles:           payload.Roles,
		PrivilegeLevels: payload.PrivilegeLevels,
		Vendors:         payload.Vendors,
		Tenants:         payload.Tenants,
		Source:          "api",
		CreatedBy:       actor,
		UpdatedBy:       actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "upsert_tacacs_command_set", record.Name, "saved")
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": tacacs.ReportSchemaVersion,
		"command_set":    record,
	})
}

func parseOptionalLimit(r *http.Request, defaultLimit, maxLimit int) int {
	limit := defaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func tacacsReportForSupportBundle() (map[string]any, error) {
	cfg := config.Get()
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	return map[string]any{"tacacs": tacacs.BuildReport(cfg, 25)}, nil
}
