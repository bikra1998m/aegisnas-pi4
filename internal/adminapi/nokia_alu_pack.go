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

const nokiaALUPackReleaseScope = "External Nokia SR OS, Alcatel AAT, Alcatel ESAM, Alcatel-Lucent service-router, ALU-AAA, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0069-release-certification-checklist.md."

type nokiaALUPackResponse struct {
	GeneratedAt                   string                            `json:"generated_at"`
	Report                        productconfigs.NokiaALUPackReport `json:"report"`
	Evidence                      nokiaALUPackEvidence              `json:"evidence"`
	ReleaseScope                  string                            `json:"release_scope"`
	ReleaseCertificationChecklist string                            `json:"release_certification_checklist"`
}

type nokiaALUPackEvidence struct {
	Summary      db.NokiaALUPackDBSummary `json:"summary"`
	RecentEvents []db.NokiaALUPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetNokiaALUPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildNokiaALUPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Nokia/ALU pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateNokiaALUPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Nokia/ALU pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := nokiaALUPackHistory(parseNokiaALUPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Nokia/ALU pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, nokiaALUPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      nokiaALUPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  nokiaALUPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0069-release-certification-checklist.md",
	})
}

func HandleRecordNokiaALUPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Nokia/ALU pack event cannot be recorded"})
		return
	}
	report, err := buildNokiaALUPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Nokia/ALU pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.NokiaALUPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Nokia/ALU pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Nokia/ALU pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordNokiaALUPackEvent(db.NokiaALUPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Nokia/ALU pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateNokiaALUPackReport(report); err != nil {
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
		"release_scope":                   nokiaALUPackReleaseScope,
		"release_certification_checklist": "docs/nas-0069-release-certification-checklist.md",
	})
}

func HandleListNokiaALUPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := nokiaALUPackHistory(parseNokiaALUPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Nokia/ALU pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildNokiaALUPackForRequest() (productconfigs.NokiaALUPackReport, error) {
	return productconfigs.BuildNokiaALUPackReport()
}

func nokiaALUPackHistory(limit int) (db.NokiaALUPackDBSummary, []db.NokiaALUPackEvent, error) {
	if db.DB == nil {
		return db.NokiaALUPackDBSummary{}, nil, nil
	}
	summary, err := db.GetNokiaALUPackSummary()
	if err != nil {
		return db.NokiaALUPackDBSummary{}, nil, err
	}
	events, err := db.ListNokiaALUPackEvents(limit)
	if err != nil {
		return db.NokiaALUPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseNokiaALUPackLimit(value string, fallback int) int {
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
