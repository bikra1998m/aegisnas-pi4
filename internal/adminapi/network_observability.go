package adminapi

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

const observabilityLeaseWindow = 24 * time.Hour

func HandleGetNetworkObservability(w http.ResponseWriter, r *http.Request) {
	applyStats, err := db.GetNetworkApplyStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	leaseTrends, err := db.GetDHCPLeaseTrendSummary(observabilityLeaseWindow)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	controllerStatus, err := db.GetRuntimeStatus(integrations.ControllerComponent())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	recoveryState, err := CurrentNetworkRecoveryState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"apply_stats":     applyStats,
		"lease_trends":    leaseTrends,
		"controller_sync": controllerStatus,
		"recovery":        recoveryState,
	})
}

func HandleExportNetworkApplyHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListNetworkApplyHistory(1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-network-apply-history.csv"`)
		payload, err := networkApplyHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-network-apply-history.json"`)
		payload, err := networkApplyHistoryJSONPayload(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func HandleExportDHCPLeaseHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListDHCPLeaseHistory(2000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-dhcp-lease-history.csv"`)
		payload, err := dhcpLeaseHistoryCSV(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-dhcp-lease-history.json"`)
		payload, err := dhcpLeaseHistoryJSONPayload(history)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	default:
		http.Error(w, "unsupported export format", http.StatusBadRequest)
	}
}

func networkApplyHistoryJSONPayload(history []db.NetworkApplyHistoryRecord) ([]byte, error) {
	return json.Marshal(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"history":      history,
		"count":        len(history),
	})
}

func networkApplyHistoryCSV(history []db.NetworkApplyHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "created_at", "action", "status", "summary", "backup_id", "rollback_id", "actor", "details_json"}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			fmt.Sprint(item.ID),
			item.CreatedAt,
			item.Action,
			item.Status,
			item.Summary,
			item.BackupID,
			item.RollbackID,
			item.Actor,
			string(item.Details),
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

func dhcpLeaseHistoryJSONPayload(history []db.DHCPLeaseHistoryRecord) ([]byte, error) {
	return json.Marshal(map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"history":      history,
		"count":        len(history),
	})
}

func dhcpLeaseHistoryCSV(history []db.DHCPLeaseHistoryRecord) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "observed_at", "mac", "ip", "hostname", "client_id", "reservation", "expired", "expires_at", "remaining_seconds"}); err != nil {
		return nil, err
	}
	for _, item := range history {
		if err := writer.Write([]string{
			fmt.Sprint(item.ID),
			item.ObservedAt,
			item.MAC,
			item.IP,
			item.Hostname,
			item.ClientID,
			fmt.Sprint(item.Reservation),
			fmt.Sprint(item.Expired),
			item.ExpiresAt,
			fmt.Sprint(item.RemainingSeconds),
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
