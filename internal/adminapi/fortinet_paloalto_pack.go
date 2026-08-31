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

const fortinetPaloAltoPackReleaseScope = "External FortiGate, FortiWiFi, FortiAuthenticator, FortiNAC, FortiAP, FortiSwitch, FortiDeceptor, FortiWAN, PAN-OS, GlobalProtect, Panorama, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0065-release-certification-checklist.md."

type fortinetPaloAltoPackResponse struct {
	GeneratedAt                   string                                    `json:"generated_at"`
	Report                        productconfigs.FortinetPaloAltoPackReport `json:"report"`
	Evidence                      fortinetPaloAltoPackEvidence              `json:"evidence"`
	ReleaseScope                  string                                    `json:"release_scope"`
	ReleaseCertificationChecklist string                                    `json:"release_certification_checklist"`
}

type fortinetPaloAltoPackEvidence struct {
	Summary      db.FortinetPaloAltoPackDBSummary `json:"summary"`
	RecentEvents []db.FortinetPaloAltoPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetFortinetPaloAltoPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildFortinetPaloAltoPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Fortinet/Palo Alto pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateFortinetPaloAltoPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Fortinet/Palo Alto pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := fortinetPaloAltoPackHistory(parseFortinetPaloAltoPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Fortinet/Palo Alto pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, fortinetPaloAltoPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      fortinetPaloAltoPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  fortinetPaloAltoPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0065-release-certification-checklist.md",
	})
}

func HandleRecordFortinetPaloAltoPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; Fortinet/Palo Alto pack event cannot be recorded"})
		return
	}
	report, err := buildFortinetPaloAltoPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Fortinet/Palo Alto pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.FortinetPaloAltoPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Fortinet/Palo Alto pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal Fortinet/Palo Alto pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordFortinetPaloAltoPackEvent(db.FortinetPaloAltoPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record Fortinet/Palo Alto pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateFortinetPaloAltoPackReport(report); err != nil {
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
		"release_scope":                   fortinetPaloAltoPackReleaseScope,
		"release_certification_checklist": "docs/nas-0065-release-certification-checklist.md",
	})
}

func HandleListFortinetPaloAltoPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := fortinetPaloAltoPackHistory(parseFortinetPaloAltoPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Fortinet/Palo Alto pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildFortinetPaloAltoPackForRequest() (productconfigs.FortinetPaloAltoPackReport, error) {
	return productconfigs.BuildFortinetPaloAltoPackReport()
}

func fortinetPaloAltoPackHistory(limit int) (db.FortinetPaloAltoPackDBSummary, []db.FortinetPaloAltoPackEvent, error) {
	if db.DB == nil {
		return db.FortinetPaloAltoPackDBSummary{}, nil, nil
	}
	summary, err := db.GetFortinetPaloAltoPackSummary()
	if err != nil {
		return db.FortinetPaloAltoPackDBSummary{}, nil, err
	}
	events, err := db.ListFortinetPaloAltoPackEvents(limit)
	if err != nil {
		return db.FortinetPaloAltoPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseFortinetPaloAltoPackLimit(value string, fallback int) int {
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
