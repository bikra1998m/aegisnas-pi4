package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const vendorMappingCertificationReleaseScope = "External FreeRADIUS production Linux, vendor hardware/controller firmware, HA failover, performance, soak, security audit, production deployment, and customer acceptance evidence are tracked in docs/nas-0060-release-certification-checklist.md."

type vendorMappingCertificationResponse struct {
	GeneratedAt                   string                                          `json:"generated_at"`
	Report                        productconfigs.VendorMappingCertificationReport `json:"report"`
	Evidence                      vendorMappingCertificationEvidence              `json:"evidence"`
	ReleaseScope                  string                                          `json:"release_scope"`
	ReleaseCertificationChecklist string                                          `json:"release_certification_checklist"`
}

type vendorMappingCertificationEvidence struct {
	Summary      db.VendorMappingCertificationDBSummary `json:"summary"`
	RecentEvents []db.VendorMappingCertificationEvent   `json:"recent_events,omitempty"`
}

func HandleGetVendorMappingCertification(w http.ResponseWriter, r *http.Request) {
	report, err := buildVendorMappingCertificationForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor mapping certification is unavailable: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateVendorMappingCertificationReport(report); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor mapping certification is incomplete: " + err.Error()})
		return
	}
	summary, events, err := vendorMappingCertificationHistory(parseVendorMappingCertificationLimit(r.URL.Query().Get("history_limit"), 20))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor mapping certification history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, vendorMappingCertificationResponse{
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Report:                        report,
		Evidence:                      vendorMappingCertificationEvidence{Summary: summary, RecentEvents: events},
		ReleaseScope:                  vendorMappingCertificationReleaseScope,
		ReleaseCertificationChecklist: "docs/nas-0060-release-certification-checklist.md",
	})
}

func HandleRecordVendorMappingCertification(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database is unavailable; vendor mapping certification event cannot be recorded"})
		return
	}
	report, err := buildVendorMappingCertificationForRequest()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor mapping certification is unavailable: " + err.Error()})
		return
	}
	status := "recorded"
	if report.Summary.SoftwareBlockedMappings > 0 || report.Summary.CertifiedMappings != productconfigs.VendorMappingCertificationBaselineCount {
		status = "blocked"
	}
	summaryJSON, err := json.Marshal(report.Summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal vendor mapping certification summary: " + err.Error()})
		return
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal vendor mapping certification report: " + err.Error()})
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	eventID, err := db.RecordVendorMappingCertificationEvent(db.VendorMappingCertificationEventInput{
		Operation:                "record",
		Status:                   status,
		ReleaseProfileID:         report.ReleaseProfileID,
		SourceSHA256:             report.SourceSHA256,
		BaselinePartialMappings:  report.BaselinePartialMappings,
		CertifiedMappings:        report.Summary.CertifiedMappings,
		SoftwareBlockedMappings:  report.Summary.SoftwareBlockedMappings,
		ExternalRequiredMappings: report.Summary.ExternalRequiredMappings,
		VendorCount:              report.Summary.VendorCount,
		Fingerprint:              report.Summary.Fingerprint,
		SummaryJSON:              string(summaryJSON),
		ReportJSON:               string(reportJSON),
		Actor:                    actor,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record vendor mapping certification event: " + err.Error()})
		return
	}
	if err := productconfigs.ValidateVendorMappingCertificationReport(report); err != nil {
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
		"release_scope":                   vendorMappingCertificationReleaseScope,
		"release_certification_checklist": "docs/nas-0060-release-certification-checklist.md",
	})
}

func HandleListVendorMappingCertificationHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := vendorMappingCertificationHistory(parseVendorMappingCertificationLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "vendor mapping certification history: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"events":       events,
	})
}

func buildVendorMappingCertificationForRequest() (productconfigs.VendorMappingCertificationReport, error) {
	return buildVendorMappingCertificationForConfig(config.Get())
}

func buildVendorMappingCertificationForConfig(cfg *config.Config) (productconfigs.VendorMappingCertificationReport, error) {
	compatibility := productconfigs.AegisNASVendorCompatibilityReport()
	if cfg != nil && len(cfg.Radius.Vendor.CompatibilityPacks) > 0 {
		compatibility.ActivePacks = normalizeVendorCompatibilityPackKeys(cfg.Radius.Vendor.CompatibilityPacks)
	}
	if cfg != nil {
		vendor := cfg.Radius.Vendor
		compatibility.Catalog = productconfigs.AegisNASVendorDictionaryCatalogFor(vendor.Name, vendor.ID)
		for index := range compatibility.Packs {
			if compatibility.Packs[index].Key == productconfigs.VendorPackAegisNAS {
				compatibility.Packs[index].VendorName = strings.TrimSpace(vendor.Name)
				compatibility.Packs[index].VendorID = vendor.ID
			}
		}
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) > 0 {
		imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
		compatibility.Catalog = productconfigs.MergeVendorDictionaryCatalogs("built-in AegisNAS, "+imported.Source, compatibility.Catalog, imported)
	}
	return productconfigs.BuildVendorMappingCertificationReport(compatibility.Catalog, compatibility.Packs, compatibility.ActivePacks)
}

func vendorMappingCertificationHistory(limit int) (db.VendorMappingCertificationDBSummary, []db.VendorMappingCertificationEvent, error) {
	if db.DB == nil {
		return db.VendorMappingCertificationDBSummary{}, nil, nil
	}
	summary, err := db.GetVendorMappingCertificationSummary()
	if err != nil {
		return db.VendorMappingCertificationDBSummary{}, nil, err
	}
	events, err := db.ListVendorMappingCertificationEvents(limit)
	if err != nil {
		return db.VendorMappingCertificationDBSummary{}, nil, err
	}
	return summary, events, nil
}

func parseVendorMappingCertificationLimit(value string, fallback int) int {
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
