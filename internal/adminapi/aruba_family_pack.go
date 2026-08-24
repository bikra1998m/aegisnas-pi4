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

const arubaFamilyPackReleaseScope = "External ArubaOS, Aruba Central, ClearPass, HP/ArubaOS-Switch, Aerohive/Extreme, Colubris/MSM, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0062-release-certification-checklist.md."

type arubaFamilyPackResponse struct {
	GeneratedAt                   string                               `json:"generated_at"`
	Report                        productconfigs.ArubaFamilyPackReport `json:"report"`
	Evidence                      arubaFamilyPackEvidence              `json:"evidence"`
	ReleaseScope                  string                               `json:"release_scope"`
	ReleaseCertificationChecklist string                               `json:"release_certification_checklist"`
}

type arubaFamilyPackEvidence struct {
	Summary      db.ArubaFamilyPackDBSummary `json:"summary"`
	RecentEvents []db.ArubaFamilyPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetArubaFamilyPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildArubaFamilyPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Aruba family pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateArubaFamilyPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Aruba family pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := arubaFamilyPackHistory(parseArubaFamilyPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Aruba family pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, arubaFamilyPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      arubaFamilyPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  arubaFamilyPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0062-release-certification-checklist.md",
	})
}

func HandleRecordArubaFamilyPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Aruba family pack event cannot be recorded"})
		return
	}
	report, err := buildArubaFamilyPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Aruba family pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.ArubaFamilyPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Aruba family pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Aruba family pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordArubaFamilyPackEvent(db.ArubaFamilyPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Aruba family pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateArubaFamilyPackReport(report); err != nil {
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
		"release_scope":                   arubaFamilyPackReleaseScope,
		"release_certification_checklist": "docs/nas-0062-release-certification-checklist.md",
	})
}

func HandleListArubaFamilyPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := arubaFamilyPackHistory(parseArubaFamilyPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Aruba family pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildArubaFamilyPackForRequest() (productconfigs.ArubaFamilyPackReport, error) {
	return productconfigs.BuildArubaFamilyPackReport()
}

func arubaFamilyPackHistory(limit int) (db.ArubaFamilyPackDBSummary, []db.ArubaFamilyPackEvent, error) {
	if db.DB == nil {
		return db.ArubaFamilyPackDBSummary{}, nil, nil
	}
	summary, err := db.GetArubaFamilyPackSummary()
	if err != nil {
		return db.ArubaFamilyPackDBSummary{}, nil, err
	}
	events, err := db.ListArubaFamilyPackEvents(limit)
	if err != nil {
		return db.ArubaFamilyPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseArubaFamilyPackLimit(value string, fallback int) int {
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
