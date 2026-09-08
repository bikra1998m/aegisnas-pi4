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

const longTailNamespaceReleaseScope = "Long-tail vendor hardware, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0072-release-certification-checklist.md."

type longTailNamespaceResponse struct {
	GeneratedAt                   string                                 `json:"generated_at"`
	Report                        productconfigs.LongTailNamespaceReport `json:"report"`
	Evidence                      longTailNamespaceEvidence              `json:"evidence"`
	ReleaseScope                  string                                 `json:"release_scope"`
	ReleaseCertificationChecklist string                                 `json:"release_certification_checklist"`
}

type longTailNamespaceEvidence struct {
	Summary      db.LongTailNamespaceDBSummary `json:"summary"`
	RecentEvents []db.LongTailNamespaceEvent   `json:"recent_events,omitempty"`
}

func HandleGetLongTailNamespaces(w http.ResponseWriter, r *http.Request) {
	report, err := buildLongTailNamespaceForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "long-tail namespace program is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateLongTailNamespaceReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "long-tail namespace program is incomplete: " + err.Error()})
		return
	}
	summary, events, err := longTailNamespaceHistory(parseLongTailNamespaceLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "long-tail namespace history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, longTailNamespaceResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      longTailNamespaceEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  longTailNamespaceReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0072-release-certification-checklist.md",
	})
}

func HandleRecordLongTailNamespaces(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; long-tail namespace event cannot be recorded"})
		return
	}
	report, err := buildLongTailNamespaceForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "long-tail namespace program is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.LongTailNamespaceExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal long-tail namespace summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal long-tail namespace report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordLongTailNamespaceEvent(db.LongTailNamespaceEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record long-tail namespace event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateLongTailNamespaceReport(report); err != nil {
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
		"release_scope":                   longTailNamespaceReleaseScope,
		"release_certification_checklist": "docs/nas-0072-release-certification-checklist.md",
	})
}

func HandleListLongTailNamespacesHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := longTailNamespaceHistory(parseLongTailNamespaceLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "long-tail namespace history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildLongTailNamespaceForRequest() (productconfigs.LongTailNamespaceReport, error) {
	return productconfigs.BuildLongTailNamespaceReport()
}

func longTailNamespaceHistory(limit int) (db.LongTailNamespaceDBSummary, []db.LongTailNamespaceEvent, error) {
	if db.DB == nil {
		return db.LongTailNamespaceDBSummary{}, nil, nil
	}
	summary, err := db.GetLongTailNamespaceSummary()
	if err != nil {
		return db.LongTailNamespaceDBSummary{}, nil, err
	}
	events, err := db.ListLongTailNamespaceEvents(limit)
	if err != nil {
		return db.LongTailNamespaceDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseLongTailNamespaceLimit(value string, fallback int) int {
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
