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

const switchingVendorPackReleaseScope = "External switch firmware, controller APIs, FreeRADIUS-on-Linux, CoA/Disconnect, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0071-release-certification-checklist.md."

type switchingVendorPackResponse struct {
	GeneratedAt                   string                                   `json:"generated_at"`
	Report                        productconfigs.SwitchingVendorPackReport `json:"report"`
	Evidence                      switchingVendorPackEvidence              `json:"evidence"`
	ReleaseScope                  string                                   `json:"release_scope"`
	ReleaseCertificationChecklist string                                   `json:"release_certification_checklist"`
}

type switchingVendorPackEvidence struct {
	Summary      db.SwitchingVendorPackDBSummary `json:"summary"`
	RecentEvents []db.SwitchingVendorPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetSwitchingVendorPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildSwitchingVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching vendor pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateSwitchingVendorPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching vendor pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := switchingVendorPackHistory(parseSwitchingVendorPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, switchingVendorPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      switchingVendorPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  switchingVendorPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0071-release-certification-checklist.md",
	})
}

func HandleRecordSwitchingVendorPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; switching vendor pack event cannot be recorded"})
		return
	}
	report, err := buildSwitchingVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching vendor pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.SwitchingVendorPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal switching vendor pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal switching vendor pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordSwitchingVendorPackEvent(db.SwitchingVendorPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record switching vendor pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateSwitchingVendorPackReport(report); err != nil {
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
		"release_scope":                   switchingVendorPackReleaseScope,
		"release_certification_checklist": "docs/nas-0071-release-certification-checklist.md",
	})
}

func HandleListSwitchingVendorPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := switchingVendorPackHistory(parseSwitchingVendorPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "switching vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildSwitchingVendorPackForRequest() (productconfigs.SwitchingVendorPackReport, error) {
	return productconfigs.BuildSwitchingVendorPackReport()
}

func switchingVendorPackHistory(limit int) (db.SwitchingVendorPackDBSummary, []db.SwitchingVendorPackEvent, error) {
	if db.DB == nil {
		return db.SwitchingVendorPackDBSummary{}, nil, nil
	}
	summary, err := db.GetSwitchingVendorPackSummary()
	if err != nil {
		return db.SwitchingVendorPackDBSummary{}, nil, err
	}
	events, err := db.ListSwitchingVendorPackEvents(limit)
	if err != nil {
		return db.SwitchingVendorPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseSwitchingVendorPackLimit(value string, fallback int) int {
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
