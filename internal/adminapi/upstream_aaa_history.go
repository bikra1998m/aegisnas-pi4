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

func HandleListUpstreamAAAHistory(w http.ResponseWriter, r *http.Request) {
	serverName := strings.TrimSpace(r.URL.Query().Get("server"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseUpstreamAAAHistoryLimit(r.URL.Query().Get("limit"), 200)

	history, err := db.ListUpstreamAAAHistory(serverName, status, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := db.GetUpstreamAAAHistoryStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"server":       serverName,
		"status":       status,
		"history":      history,
		"count":        len(history),
		"stats":        stats,
	})
}

func HandleExportUpstreamAAAHistory(w http.ResponseWriter, r *http.Request) {
	serverName := strings.TrimSpace(r.URL.Query().Get("server"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	history, err := db.ListUpstreamAAAHistory(serverName, status, 5000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	filenamePrefix := "aegisnas-upstream-aaa-history"
	if serverName != "" {
		filenamePrefix += "-" + sanitizeDownloadName(serverName)
	}
	if status != "" {
		filenamePrefix += "-" + sanitizeDownloadName(status)
	}

	switch format {
	case "", "csv":
		payload, err := upstreamAAAHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case "json":
		payload, err := upstreamAAAHistoryJSONPayload(serverName, status, history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filenamePrefix))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func upstreamAAAHistoryCSV(history []db.UpstreamAAAHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "checked_at", "created_at", "server_name", "address", "auth_port", "acct_port", "status", "message", "response_code", "latency_ms", "supports_status_server", "transport", "radsec_port", "tls_version", "tls_cipher_suite", "tls_alpn", "peer_subject", "peer_issuer", "peer_serial", "peer_not_after"}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			fmt.Sprint(item.ID),
			item.CheckedAt,
			item.CreatedAt,
			item.ServerName,
			item.Address,
			strconv.Itoa(item.AuthPort),
			strconv.Itoa(item.AcctPort),
			item.Status,
			item.Message,
			item.ResponseCode,
			fmt.Sprint(item.LatencyMs),
			strconv.FormatBool(item.SupportsStatusServer),
			item.Transport,
			strconv.Itoa(item.RadSecPort),
			item.TLSVersion,
			item.TLSCipherSuite,
			item.TLSALPN,
			item.PeerSubject,
			item.PeerIssuer,
			item.PeerSerial,
			item.PeerNotAfter,
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

func upstreamAAAHistoryJSONPayload(serverName, status string, history []db.UpstreamAAAHistoryRecord) ([]byte, error) {
	data, err := jsonMarshalIndented(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"server":       serverName,
		"status":       status,
		"history":      history,
		"count":        len(history),
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func parseUpstreamAAAHistoryLimit(raw string, fallback int) int {
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
