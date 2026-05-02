package adminapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/portal/guestworkflow"
)

func HandleListGuestRegistrations(w http.ResponseWriter, r *http.Request) {
	service := guestworkflow.New(config.Get(), nil, nil)
	records, err := service.List(strings.TrimSpace(r.URL.Query().Get("status")), 100, adminTenantScopesFromRequest(r)...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func HandleApproveGuestRegistration(w http.ResponseWriter, r *http.Request) {
	service := guestworkflow.New(config.Get(), nil, nil)
	record, err := service.GetByID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !tenantAllowed(r, record.Tenant) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	record, err = service.ApproveByID(r.Context(), chi.URLParam(r, "id"), userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func HandleRejectGuestRegistration(w http.ResponseWriter, r *http.Request) {
	payload := map[string]string{}
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	service := guestworkflow.New(config.Get(), nil, nil)
	record, err := service.GetByID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !tenantAllowed(r, record.Tenant) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	record, err = service.RejectByID(r.Context(), chi.URLParam(r, "id"), userFromRequest(r), strings.TrimSpace(payload["reason"]))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, record)
}
