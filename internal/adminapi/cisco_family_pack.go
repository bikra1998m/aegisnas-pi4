package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const ciscoFamilyPackReleaseScope = "External Cisco, Airespace/WLC, ASA/VPN, VPN3000/5000, Starent, Meraki, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0061-release-certification-checklist.md."

type ciscoFamilyPackResponse struct {
	GeneratedAt                   string                               `json:"generated_at"`
	Report                        productconfigs.CiscoFamilyPackReport `json:"report"`
	Evidence                      ciscoFamilyPackEvidence              `json:"evidence"`
	ReleaseScope                  string                               `json:"release_scope"`
	ReleaseCertificationChecklist string                               `json:"release_certification_checklist"`
}

type ciscoFamilyPackEvidence struct {
	Summary      db.CiscoFamilyPackDBSummary `json:"summary"`
	RecentEvents []db.CiscoFamilyPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetCiscoFamilyPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildCiscoFamilyPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cisco family pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateCiscoFamilyPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cisco family pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := ciscoFamilyPackHistory(parseCiscoFamilyPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cisco family pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ciscoFamilyPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      ciscoFamilyPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  ciscoFamilyPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0061-release-certification-checklist.md",
	})
}

func HandleRecordCiscoFamilyPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Cisco family pack event cannot be recorded"})
		return
	}
	report, err := buildCiscoFamilyPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cisco family pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.CiscoFamilyPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Cisco family pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Cisco family pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordCiscoFamilyPackEvent(db.CiscoFamilyPackEventInput{
		Operation:                 "record",
		Status:                    status,
		ReleaseProfileID:          report.ReleaseProfileID,
		SourceSHA256:              report.SourceSHA256,
		AttributeCount:            report.Summary.AttributeCount,
		NativeSemanticMappings:    report.Summary.NativeSemanticMappings,
		TypedPassThroughMappings:  report.Summary.TypedPassThroughMappings,
		GrammarRuleCount:          report.Summary.GrammarRuleCount,
		SoftwareCertifiedMappings: report.Summary.SoftwareCertifiedMappings,
		SoftwareBlockedMappings:   report.Summary.SoftwareBlockedMappings,
		ExternalRequiredMappings:  report.Summary.ExternalRequiredMappings,
		VendorCount:               report.Summary.VendorCount,
		Fingerprint:               report.Summary.Fingerprint,
		SummaryJSON:               string(summaryJSON),
		ReportJSON:                string(reportJSON),
		Actor:                     actor,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Cisco family pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateCiscoFamilyPackReport(report); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"event_id":     eventID,
			"status":       status,
			"error":        err.Error(),
			"report":       report,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":                    time.Now().UTC().Format(time.RFC3339),
		"event_id":                        eventID,
		"status":                          status,
		"report":                          report,
		"release_scope":                   ciscoFamilyPackReleaseScope,
		"release_certification_checklist": "docs/nas-0061-release-certification-checklist.md",
	})
}

func HandleListCiscoFamilyPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := ciscoFamilyPackHistory(parseCiscoFamilyPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cisco family pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildCiscoFamilyPackForRequest() (productconfigs.CiscoFamilyPackReport, error) {
	return productconfigs.BuildCiscoFamilyPackReport()
}

func ciscoFamilyPackHistory(limit int) (db.CiscoFamilyPackDBSummary, []db.CiscoFamilyPackEvent, error) {
	if db.DB == nil {
		return db.CiscoFamilyPackDBSummary{}, nil, nil
	}
	summary, err := db.GetCiscoFamilyPackSummary()
	if err != nil {
		return db.CiscoFamilyPackDBSummary{}, nil, err
	}
	events, err := db.ListCiscoFamilyPackEvents(limit)
	if err != nil {
		return db.CiscoFamilyPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseCiscoFamilyPackLimit(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > 500 {
		return 500
	}
	return limit
}
