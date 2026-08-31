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

const ruckusICXPackReleaseScope = "External Ruckus SmartZone, ZoneDirector, Unleashed, Ruckus One, ICX/FastIron, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0064-release-certification-checklist.md."

type ruckusICXPackResponse struct {
	GeneratedAt                   string                             `json:"generated_at"`
	Report                        productconfigs.RuckusICXPackReport `json:"report"`
	Evidence                      ruckusICXPackEvidence              `json:"evidence"`
	ReleaseScope                  string                             `json:"release_scope"`
	ReleaseCertificationChecklist string                             `json:"release_certification_checklist"`
}

type ruckusICXPackEvidence struct {
	Summary      db.RuckusICXPackDBSummary `json:"summary"`
	RecentEvents []db.RuckusICXPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetRuckusICXPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildRuckusICXPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Ruckus/ICX pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateRuckusICXPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Ruckus/ICX pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := ruckusICXPackHistory(parseRuckusICXPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Ruckus/ICX pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ruckusICXPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      ruckusICXPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  ruckusICXPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0064-release-certification-checklist.md",
	})
}

func HandleRecordRuckusICXPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Ruckus/ICX pack event cannot be recorded"})
		return
	}
	report, err := buildRuckusICXPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Ruckus/ICX pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.RuckusICXPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Ruckus/ICX pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Ruckus/ICX pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordRuckusICXPackEvent(db.RuckusICXPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Ruckus/ICX pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateRuckusICXPackReport(report); err != nil {
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
		"release_scope":                   ruckusICXPackReleaseScope,
		"release_certification_checklist": "docs/nas-0064-release-certification-checklist.md",
	})
}

func HandleListRuckusICXPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := ruckusICXPackHistory(parseRuckusICXPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Ruckus/ICX pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildRuckusICXPackForRequest() (productconfigs.RuckusICXPackReport, error) {
	return productconfigs.BuildRuckusICXPackReport()
}

func ruckusICXPackHistory(limit int) (db.RuckusICXPackDBSummary, []db.RuckusICXPackEvent, error) {
	if db.DB == nil {
		return db.RuckusICXPackDBSummary{}, nil, nil
	}
	summary, err := db.GetRuckusICXPackSummary()
	if err != nil {
		return db.RuckusICXPackDBSummary{}, nil, err
	}
	events, err := db.ListRuckusICXPackEvents(limit)
	if err != nil {
		return db.RuckusICXPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseRuckusICXPackLimit(value string, fallback int) int {
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
