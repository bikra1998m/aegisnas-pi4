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

const mikroTikPackReleaseScope = "External RouterOS, CAPsMAN, PPP/PPPoE, hotspot, FreeRADIUS-on-Linux, CoA/Disconnect, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0070-release-certification-checklist.md."

type mikroTikPackResponse struct {
	GeneratedAt                   string                            `json:"generated_at"`
	Report                        productconfigs.MikroTikPackReport `json:"report"`
	Evidence                      mikroTikPackEvidence              `json:"evidence"`
	ReleaseScope                  string                            `json:"release_scope"`
	ReleaseCertificationChecklist string                            `json:"release_certification_checklist"`
}

type mikroTikPackEvidence struct {
	Summary      db.MikroTikPackDBSummary `json:"summary"`
	RecentEvents []db.MikroTikPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetMikroTikPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildMikroTikPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MikroTik pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateMikroTikPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MikroTik pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := mikroTikPackHistory(parseMikroTikPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MikroTik pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, mikroTikPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      mikroTikPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  mikroTikPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0070-release-certification-checklist.md",
	})
}

func HandleRecordMikroTikPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; MikroTik pack event cannot be recorded"})
		return
	}
	report, err := buildMikroTikPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MikroTik pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.MikroTikPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal MikroTik pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal MikroTik pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordMikroTikPackEvent(db.MikroTikPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record MikroTik pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateMikroTikPackReport(report); err != nil {
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
		"release_scope":                   mikroTikPackReleaseScope,
		"release_certification_checklist": "docs/nas-0070-release-certification-checklist.md",
	})
}

func HandleListMikroTikPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := mikroTikPackHistory(parseMikroTikPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MikroTik pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildMikroTikPackForRequest() (productconfigs.MikroTikPackReport, error) {
	return productconfigs.BuildMikroTikPackReport()
}

func mikroTikPackHistory(limit int) (db.MikroTikPackDBSummary, []db.MikroTikPackEvent, error) {
	if db.DB == nil {
		return db.MikroTikPackDBSummary{}, nil, nil
	}
	summary, err := db.GetMikroTikPackSummary()
	if err != nil {
		return db.MikroTikPackDBSummary{}, nil, err
	}
	events, err := db.ListMikroTikPackEvents(limit)
	if err != nil {
		return db.MikroTikPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseMikroTikPackLimit(value string, fallback int) int {
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
