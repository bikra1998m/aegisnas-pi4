package adminapi

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func HandleGetVendorObservability(w http.ResponseWriter, r *http.Request) {
	limit := parseVendorObservabilityLimit(r.URL.Query().Get("limit"), 100)
	records, err := db.ListVendorObservability(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.GetVendorObservabilitySummary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"vendors":      records,
		"count":        len(records),
	})
}

func HandleExportVendorObservability(w http.ResponseWriter, r *http.Request) {
	records, err := db.ListVendorObservability(5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "csv":
		payload, err := vendorObservabilityCSV(records)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-vendor-observability.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		summary, err := db.GetVendorObservabilitySummary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload, err := vendorObservabilityJSONPayload(summary, records)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-vendor-observability.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func vendorObservabilityCSV(records []db.VendorObservabilityRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{
		"vendor_key",
		"nas_type",
		"compatibility_score",
		"auth_success_count",
		"auth_failure_count",
		"vsa_parsed_count",
		"vsa_parse_failure_count",
		"unsupported_attribute_count",
		"coa_success_count",
		"coa_failure_count",
		"disconnect_success_count",
		"disconnect_failure_count",
		"last_event_at",
		"last_message",
	}); err != nil {
		return nil, err
	}
	for _, item := range records {
		if err := writer.Write([]string{
			item.VendorKey,
			item.NASType,
			strconv.Itoa(item.CompatibilityScore),
			strconv.Itoa(item.AuthSuccessCount),
			strconv.Itoa(item.AuthFailureCount),
			strconv.Itoa(item.VSAParsedCount),
			strconv.Itoa(item.VSAParseFailureCount),
			strconv.Itoa(item.UnsupportedAttributeCount),
			strconv.Itoa(item.CoASuccessCount),
			strconv.Itoa(item.CoAFailureCount),
			strconv.Itoa(item.DisconnectSuccessCount),
			strconv.Itoa(item.DisconnectFailureCount),
			item.LastEventAt,
			item.LastMessage,
		}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func vendorObservabilityJSONPayload(summary db.VendorObservabilitySummary, records []db.VendorObservabilityRecord) ([]byte, error) {
	data, err := jsonMarshalIndented(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"vendors":      records,
		"count":        len(records),
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func parseVendorObservabilityLimit(raw string, fallback int) int {
	if fallback <= 0 {
		fallback = 100
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 5000 {
		return 5000
	}
	return value
}

func vendorObservabilityStatus(summary db.VendorObservabilitySummary) string {
	switch {
	case summary.VSAParseFailureCount > 0 || summary.CoAFailureCount > 0 || summary.DisconnectFailureCount > 0:
		return "degraded"
	case summary.UnsupportedAttributeCount > 0 || summary.AuthFailureCount > 0:
		return "warned"
	default:
		return "ok"
	}
}

func vendorObservabilityMessage(summary db.VendorObservabilitySummary) string {
	if summary.TotalVendors == 0 {
		return "No vendor observability counters have been recorded yet."
	}
	return fmt.Sprintf("%d vendor profile(s), compatibility score %d, %d auth failure(s), %d unsupported attribute(s).",
		summary.TotalVendors,
		summary.CompatibilityScore,
		summary.AuthFailureCount,
		summary.UnsupportedAttributeCount,
	)
}
