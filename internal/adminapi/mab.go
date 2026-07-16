package adminapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	mabpkg "github.com/yourorg/aegisnas-pi4/internal/mab"
)

type mabEvaluateRequest struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	CallingStationID  string `json:"calling_station_id"`
	CalledStationID   string `json:"called_station_id"`
	NASIdentifier     string `json:"nas_identifier"`
	NASIPAddress      string `json:"nas_ip_address"`
	NASPort           string `json:"nas_port"`
	NASPortType       string `json:"nas_port_type"`
	EAPMessagePresent bool   `json:"eap_message_present"`
	RecordAudit       bool   `json:"record_audit"`
}

func HandleGetMAB(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := mabpkg.BuildReport(cfg)
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	mac := strings.TrimSpace(r.URL.Query().Get("mac"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 100)
	var events []db.MABEvent
	var err error
	if decision != "" || mac != "" || limit != 100 {
		events, err = db.ListMABEvents(decision, mac, limit)
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

func HandleListMABEndpoints(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 500)
	endpoints, err := db.ListMABEndpoints(status, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"endpoints":    endpoints,
	})
}

func HandleUpsertMABEndpoint(w http.ResponseWriter, r *http.Request) {
	var endpoint db.MABEndpoint
	if err := decodeBody(r, &endpoint); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if pathMAC := strings.TrimSpace(chi.URLParam(r, "mac")); pathMAC != "" {
		endpoint.MAC = pathMAC
	}
	stored, err := db.UpsertMABEndpoint(endpoint, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	audit(r, "mab.endpoint.upsert", "mac_hash="+db.HashMABMAC(stored.MAC), "success")
	writeJSON(w, http.StatusCreated, stored)
}

func HandleDeleteMABEndpoint(w http.ResponseWriter, r *http.Request) {
	mac := strings.TrimSpace(chi.URLParam(r, "mac"))
	deleted, err := db.DeleteMABEndpoint(mac)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "MAB endpoint not found"})
		return
	}
	audit(r, "mab.endpoint.delete", "mac_hash="+db.HashMABMAC(mac), "success")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func HandleEvaluateMAB(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req mabEvaluateRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	result := mabpkg.Evaluate(cfg, mabpkg.AccessRequest{
		Username:          req.Username,
		Password:          req.Password,
		CallingStationID:  req.CallingStationID,
		CalledStationID:   req.CalledStationID,
		NASIdentifier:     req.NASIdentifier,
		NASIPAddress:      req.NASIPAddress,
		NASPort:           req.NASPort,
		NASPortType:       req.NASPortType,
		EAPMessagePresent: req.EAPMessagePresent,
	}, req.RecordAudit)
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}
