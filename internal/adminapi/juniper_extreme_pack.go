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

const juniperExtremePackReleaseScope = "External Junos, ERX/E-Series, ExtremeXOS/Switch Engine, Juniper Mist, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0063-release-certification-checklist.md."

type juniperExtremePackResponse struct {
	GeneratedAt                   string                                  `json:"generated_at"`
	Report                        productconfigs.JuniperExtremePackReport `json:"report"`
	Evidence                      juniperExtremePackEvidence              `json:"evidence"`
	ReleaseScope                  string                                  `json:"release_scope"`
	ReleaseCertificationChecklist string                                  `json:"release_certification_checklist"`
}

type juniperExtremePackEvidence struct {
	Summary      db.JuniperExtremePackDBSummary `json:"summary"`
	RecentEvents []db.JuniperExtremePackEvent   `json:"recent_events,omitempty"`
}

func HandleGetJuniperExtremePack(w http.ResponseWriter, r *http.Request) {
	report, err := buildJuniperExtremePackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Juniper/Extreme pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateJuniperExtremePackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Juniper/Extreme pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := juniperExtremePackHistory(parseJuniperExtremePackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Juniper/Extreme pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, juniperExtremePackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      juniperExtremePackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  juniperExtremePackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0063-release-certification-checklist.md",
	})
}

func HandleRecordJuniperExtremePack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Juniper/Extreme pack event cannot be recorded"})
		return
	}
	report, err := buildJuniperExtremePackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Juniper/Extreme pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.JuniperExtremePackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Juniper/Extreme pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Juniper/Extreme pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordJuniperExtremePackEvent(db.JuniperExtremePackEventInput{
		Operation:                 "record",
		Status:                    status,
		ReleaseProfileID:          report.ReleaseProfileID,
		SourceSHA256:              report.SourceSHA256,
		AttributeCount:            report.Summary.AttributeCount,
		NativeSemanticMappings:    report.Summary.NativeSemanticMappings,
		TypedPassThroughMappings:  report.Summary.TypedPassThroughMappings,
		SensitiveRedactedMappings: report.Summary.SensitiveRedactedMappings,
		GrammarRuleCount:          report.Summary.GrammarRuleCount,
		SoftwareCertifiedMappings: report.Summary.SoftwareCertifiedMappings,
		SoftwareBlockedMappings:   report.Summary.SoftwareBlockedMappings,
		ExternalRequiredMappings:  report.Summary.ExternalRequiredMappings,
		VendorCount:               report.Summary.VendorCount,
		ProductScopeCount:         report.Summary.ProductScopeCount,
		Fingerprint:               report.Summary.Fingerprint,
		SummaryJSON:               string(summaryJSON),
		ReportJSON:                string(reportJSON),
		Actor:                     actor,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Juniper/Extreme pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateJuniperExtremePackReport(report); err != nil {
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
		"release_scope":                   juniperExtremePackReleaseScope,
		"release_certification_checklist": "docs/nas-0063-release-certification-checklist.md",
	})
}

func HandleListJuniperExtremePackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := juniperExtremePackHistory(parseJuniperExtremePackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Juniper/Extreme pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildJuniperExtremePackForRequest() (productconfigs.JuniperExtremePackReport, error) {
	return productconfigs.BuildJuniperExtremePackReport()
}

func juniperExtremePackHistory(limit int) (db.JuniperExtremePackDBSummary, []db.JuniperExtremePackEvent, error) {
	if db.DB == nil {
		return db.JuniperExtremePackDBSummary{}, nil, nil
	}
	summary, err := db.GetJuniperExtremePackSummary()
	if err != nil {
		return db.JuniperExtremePackDBSummary{}, nil, err
	}
	events, err := db.ListJuniperExtremePackEvents(limit)
	if err != nil {
		return db.JuniperExtremePackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseJuniperExtremePackLimit(value string, fallback int) int {
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
