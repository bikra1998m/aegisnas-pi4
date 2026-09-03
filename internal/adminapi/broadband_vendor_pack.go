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

const broadbandVendorPackReleaseScope = "External Huawei MA/NE/CloudEngine/WLAN/iMaster, H3C Comware/iMC/BRAS/BNG, ZTE ZX/BNG/PPPoE, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0068-release-certification-checklist.md."

type broadbandVendorPackResponse struct {
	GeneratedAt                   string                                   `json:"generated_at"`
	Report                        productconfigs.BroadbandVendorPackReport `json:"report"`
	Evidence                      broadbandVendorPackEvidence              `json:"evidence"`
	ReleaseScope                  string                                   `json:"release_scope"`
	ReleaseCertificationChecklist string                                   `json:"release_certification_checklist"`
}

type broadbandVendorPackEvidence struct {
	Summary      db.BroadbandVendorPackDBSummary `json:"summary"`
	RecentEvents []db.BroadbandVendorPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetBroadbandVendorPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildBroadbandVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broadband vendor pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateBroadbandVendorPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broadband vendor pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := broadbandVendorPackHistory(parseBroadbandVendorPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broadband vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, broadbandVendorPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      broadbandVendorPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  broadbandVendorPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0068-release-certification-checklist.md",
	})
}

func HandleRecordBroadbandVendorPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; broadband vendor pack event cannot be recorded"})
		return
	}
	report, err := buildBroadbandVendorPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broadband vendor pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.BroadbandVendorPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal broadband vendor pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal broadband vendor pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordBroadbandVendorPackEvent(db.BroadbandVendorPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record broadband vendor pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateBroadbandVendorPackReport(report); err != nil {
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
		"release_scope":                   broadbandVendorPackReleaseScope,
		"release_certification_checklist": "docs/nas-0068-release-certification-checklist.md",
	})
}

func HandleListBroadbandVendorPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := broadbandVendorPackHistory(parseBroadbandVendorPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broadband vendor pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildBroadbandVendorPackForRequest() (productconfigs.BroadbandVendorPackReport, error) {
	return productconfigs.BuildBroadbandVendorPackReport()
}

func broadbandVendorPackHistory(limit int) (db.BroadbandVendorPackDBSummary, []db.BroadbandVendorPackEvent, error) {
	if db.DB == nil {
		return db.BroadbandVendorPackDBSummary{}, nil, nil
	}
	summary, err := db.GetBroadbandVendorPackSummary()
	if err != nil {
		return db.BroadbandVendorPackDBSummary{}, nil, err
	}
	events, err := db.ListBroadbandVendorPackEvents(limit)
	if err != nil {
		return db.BroadbandVendorPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseBroadbandVendorPackLimit(value string, fallback int) int {
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
