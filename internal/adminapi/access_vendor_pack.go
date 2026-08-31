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

const accessVendorPackReleaseScope = "External Cambium cnMaestro/ePMP/PMP, TP-Link Omada, D-Link/Nuclias, access point, switch, gateway, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0067-release-certification-checklist.md."

type accessVendorPackResponse struct {
	GeneratedAt                   string                                `json:"generated_at"`
	Report                        productconfigs.AccessVendorPackReport `json:"report"`
	Evidence                      accessVendorPackEvidence              `json:"evidence"`
	ReleaseScope                  string                                `json:"release_scope"`
	ReleaseCertificationChecklist string                                `json:"release_certification_checklist"`
}

type accessVendorPackEvidence struct {
	Summary      db.AccessVendorPackDBSummary `json:"summary"`
	RecentEvents []db.AccessVendorPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetAccessVendorPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildAccessVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "access vendor pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateAccessVendorPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "access vendor pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := accessVendorPackHistory(parseAccessVendorPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "access vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, accessVendorPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      accessVendorPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  accessVendorPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0067-release-certification-checklist.md",
	})
}

func HandleRecordAccessVendorPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; access vendor pack event cannot be recorded"})
		return
	}
	report, err := buildAccessVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "access vendor pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.AccessVendorPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal access vendor pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal access vendor pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordAccessVendorPackEvent(db.AccessVendorPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record access vendor pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateAccessVendorPackReport(report); err != nil {
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
		"release_scope":                   accessVendorPackReleaseScope,
		"release_certification_checklist": "docs/nas-0067-release-certification-checklist.md",
	})
}

func HandleListAccessVendorPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := accessVendorPackHistory(parseAccessVendorPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "access vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildAccessVendorPackForRequest() (productconfigs.AccessVendorPackReport, error) {
	return productconfigs.BuildAccessVendorPackReport()
}

func accessVendorPackHistory(limit int) (db.AccessVendorPackDBSummary, []db.AccessVendorPackEvent, error) {
	if db.DB == nil {
		return db.AccessVendorPackDBSummary{}, nil, nil
	}
	summary, err := db.GetAccessVendorPackSummary()
	if err != nil {
		return db.AccessVendorPackDBSummary{}, nil, err
	}
	events, err := db.ListAccessVendorPackEvents(limit)
	if err != nil {
		return db.AccessVendorPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseAccessVendorPackLimit(value string, fallback int) int {
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
