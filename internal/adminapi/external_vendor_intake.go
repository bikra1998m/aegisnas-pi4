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

const externalVendorIntakeReleaseScope = "External vendor hardware, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence are tracked in docs/nas-0073-release-certification-checklist.md."

type externalVendorIntakeResponse struct {
	GeneratedAt                   string                                              `json:"generated_at"`
	Governance                    productconfigs.ExternalVendorIntakeGovernanceReport `json:"governance"`
	Evidence                      externalVendorIntakeEvidence                        `json:"evidence"`
	ReleaseScope                  string                                              `json:"release_scope"`
	ReleaseCertificationChecklist string                                              `json:"release_certification_checklist"`
}

type externalVendorIntakePreviewResponse struct {
	GeneratedAt                   string                                    `json:"generated_at"`
	Status                        string                                    `json:"status"`
	Report                        productconfigs.ExternalVendorIntakeReport `json:"report"`
	ReleaseScope                  string                                    `json:"release_scope"`
	ReleaseCertificationChecklist string                                    `json:"release_certification_checklist"`
}

type externalVendorIntakeEvidence struct {
	Summary      db.ExternalVendorIntakeDBSummary `json:"summary"`
	RecentEvents []db.ExternalVendorIntakeEvent   `json:"recent_events,omitempty"`
}

func HandleGetExternalVendorIntake(w http.ResponseWriter, r *http.Request) {
	governance := productconfigs.BuildExternalVendorIntakeGovernanceReport()
	if err := productconfigs.ValidateExternalVendorIntakeGovernanceReport(governance); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "external vendor intake governance is incomplete: " + err.Error()})
		return
	}
	summary, events, err := externalVendorIntakeHistory(parseExternalVendorIntakeLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "external vendor intake history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, externalVendorIntakeResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Governance:                    governance,
		Evidence:                      externalVendorIntakeEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  externalVendorIntakeReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0073-release-certification-checklist.md",
	})
}

func HandlePreviewExternalVendorIntake(w http.ResponseWriter, r *http.Request) {
	input, ok := decodeExternalVendorIntakeRequest(w, r)
	if !ok {
		return
	}
	report := productconfigs.BuildExternalVendorIntakeReport(input)
	writeJSON(w, http.StatusOK, externalVendorIntakePreviewResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Status:                        report.Status,
		Report:                        report,
		ReleaseScope:                  externalVendorIntakeReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0073-release-certification-checklist.md",
	})
}

func HandleRecordExternalVendorIntake(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; external vendor intake event cannot be recorded"})
		return
	}
	input, ok := decodeExternalVendorIntakeRequest(w, r)
	if !ok {
		return
	}
	report := productconfigs.BuildExternalVendorIntakeReport(input)
	status := "recorded"
	if err := productconfigs.ValidateExternalVendorIntakeReport(report); err != nil {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal external vendor intake summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal external vendor intake report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordExternalVendorIntakeEvent(db.ExternalVendorIntakeEventInput{
		Operation:                  "record",
		Status:                     status,
		ReleaseProfileID:           report.DictionaryReleaseProfileID,
		ReleaseSourceSHA256:        report.SourceSHA256,
		VendorName:                 report.Vendor.CanonicalName,
		PEN:                        report.Vendor.PEN,
		PackKey:                    report.Vendor.IntendedPackKey,
		DictionaryName:             report.Vendor.DictionaryName,
		SourceURL:                  report.Provenance.SourceURL,
		DictionarySHA256:           report.Provenance.ComputedSHA256,
		LicenseID:                  report.Provenance.LicenseID,
		LicenseState:               report.Provenance.LicenseState,
		ProvenanceState:            report.Provenance.ProvenanceState,
		PENState:                   report.Provenance.PENState,
		SemanticState:              report.Provenance.SemanticState,
		AttributeCount:             report.Summary.AttributeCount,
		RuntimeDecodableAttributes: report.Summary.RuntimeDecodableAttributes,
		MetadataOnlyAttributes:     report.Summary.MetadataOnlyAttributes,
		NativeSemanticMappings:     report.Summary.NativeSemanticMappings,
		TypedPassthroughMappings:   report.Summary.TypedPassthroughMappings,
		SensitiveRedactedMappings:  report.Summary.SensitiveRedactedMappings,
		SoftwareReadyAttributes:    report.Summary.SoftwareReadyAttributes,
		SoftwareBlockedAttributes:  report.Summary.SoftwareBlockedAttributes,
		ExternalRequiredAttributes: report.Summary.ExternalCertificationRequirements,
		Fingerprint:                report.Summary.Fingerprint,
		SummaryJSON:                string(summaryJSON),
		ReportJSON:                 string(reportJSON),
		Actor:                      actor,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record external vendor intake event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateExternalVendorIntakeReport(report); err != nil {
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
		"release_scope":                   externalVendorIntakeReleaseScope,
		"release_certification_checklist": "docs/nas-0073-release-certification-checklist.md",
	})
}

func HandleListExternalVendorIntakeHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := externalVendorIntakeHistory(parseExternalVendorIntakeLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "external vendor intake history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func decodeExternalVendorIntakeRequest(w http.ResponseWriter, r *http.Request) (productconfigs.ExternalVendorIntakeRequest, bool) {
	var input productconfigs.ExternalVendorIntakeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(productconfigs.ExternalVendorIntakeMaxBytes)+65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid external vendor intake request: " + err.Error()})
		return productconfigs.ExternalVendorIntakeRequest{}, false
	}
	return input, true
}

func externalVendorIntakeHistory(limit int) (db.ExternalVendorIntakeDBSummary, []db.ExternalVendorIntakeEvent, error) {
	if db.DB == nil {
		return db.ExternalVendorIntakeDBSummary{}, nil, nil
	}
	summary, err := db.GetExternalVendorIntakeSummary()
	if err != nil {
		return db.ExternalVendorIntakeDBSummary{}, nil, err
	}
	events, err := db.ListExternalVendorIntakeEvents(limit)
	if err != nil {
		return db.ExternalVendorIntakeDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseExternalVendorIntakeLimit(value string, fallback int) int {
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
