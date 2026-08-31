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

const cloudControllerPackReleaseScope = "External Meraki Dashboard, UniFi Network, TIP OpenWiFi OWGW/uCentral, access point, gateway, switch, appliance, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0066-release-certification-checklist.md."

type cloudControllerPackResponse struct {
	GeneratedAt                   string                                   `json:"generated_at"`
	Report                        productconfigs.CloudControllerPackReport `json:"report"`
	Evidence                      cloudControllerPackEvidence              `json:"evidence"`
	ReleaseScope                  string                                   `json:"release_scope"`
	ReleaseCertificationChecklist string                                   `json:"release_certification_checklist"`
}

type cloudControllerPackEvidence struct {
	Summary      db.CloudControllerPackDBSummary `json:"summary"`
	RecentEvents []db.CloudControllerPackEvent   `json:"recent_events,omitempty"`
}

func HandleGetCloudControllerPack(w http.ResponseWriter, r *http.Request) {
	report, err := buildCloudControllerPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud controller pack is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateCloudControllerPackReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud controller pack is incomplete: " + err.Error()})
		return
	}
	summary, events, err := cloudControllerPackHistory(parseCloudControllerPackLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud controller pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cloudControllerPackResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      cloudControllerPackEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  cloudControllerPackReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0066-release-certification-checklist.md",
	})
}

func HandleRecordCloudControllerPack(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; cloud controller pack event cannot be recorded"})
		return
	}
	report, err := buildCloudControllerPackForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud controller pack is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.SoftwareCertifiedMappings != productconfigs.CloudControllerPackExpectedAttributeCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal cloud controller pack summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal cloud controller pack report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordCloudControllerPackEvent(db.CloudControllerPackEventInput{
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record cloud controller pack event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateCloudControllerPackReport(report); err != nil {
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
		"release_scope":                   cloudControllerPackReleaseScope,
		"release_certification_checklist": "docs/nas-0066-release-certification-checklist.md",
	})
}

func HandleListCloudControllerPackHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := cloudControllerPackHistory(parseCloudControllerPackLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud controller pack history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildCloudControllerPackForRequest() (productconfigs.CloudControllerPackReport, error) {
	return productconfigs.BuildCloudControllerPackReport()
}

func cloudControllerPackHistory(limit int) (db.CloudControllerPackDBSummary, []db.CloudControllerPackEvent, error) {
	if db.DB == nil {
		return db.CloudControllerPackDBSummary{}, nil, nil
	}
	summary, err := db.GetCloudControllerPackSummary()
	if err != nil {
		return db.CloudControllerPackDBSummary{}, nil, err
	}
	events, err := db.ListCloudControllerPackEvents(limit)
	if err != nil {
		return db.CloudControllerPackDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseCloudControllerPackLimit(value string, fallback int) int {
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
