package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	maxNetworkApplyHistoryRows = 1000
	maxDHCPLeaseHistoryRows    = 5000
)

type NetworkApplyHistoryRecord struct {
	ID         int             `json:"id"`
	Action     string          `json:"action"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	BackupID   string          `json:"backup_id,omitempty"`
	RollbackID string          `json:"rollback_id,omitempty"`
	Actor      string          `json:"actor,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
	CreatedAt  string          `json:"created_at"`
}

type DHCPLeaseHistoryRecord struct {
	ID               int    `json:"id"`
	ObservedAt       string `json:"observed_at"`
	MAC              string `json:"mac"`
	IP               string `json:"ip"`
	Hostname         string `json:"hostname"`
	ClientID         string `json:"client_id"`
	Reservation      bool   `json:"reservation"`
	Expired          bool   `json:"expired"`
	ExpiresAt        string `json:"expires_at"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

type DHCPLeaseObservation struct {
	MAC              string
	IP               string
	Hostname         string
	ClientID         string
	Reservation      bool
	Expired          bool
	ExpiresAt        string
	RemainingSeconds int64
}

func RecordNetworkApplyHistory(action, status, summary, backupID, rollbackID, actor string, details any) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	var detailsJSON string
	if details != nil {
		data, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("encode network apply history details: %w", err)
		}
		detailsJSON = string(data)
	}
	if _, err := DB.Exec(`INSERT INTO network_apply_history (action, status, summary, backup_id, rollback_id, actor, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(action),
		strings.TrimSpace(status),
		strings.TrimSpace(summary),
		strings.TrimSpace(backupID),
		strings.TrimSpace(rollbackID),
		strings.TrimSpace(actor),
		detailsJSON,
	); err != nil {
		return fmt.Errorf("insert network apply history: %w", err)
	}
	return trimNetworkApplyHistory(maxNetworkApplyHistoryRows)
}

func ListNetworkApplyHistory(limit int) ([]NetworkApplyHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := DB.Query(`SELECT id, action, status, COALESCE(summary, ''), COALESCE(backup_id, ''), COALESCE(rollback_id, ''),
		COALESCE(actor, ''), COALESCE(details_json, ''), created_at
		FROM network_apply_history
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list network apply history: %w", err)
	}
	defer rows.Close()

	history := []NetworkApplyHistoryRecord{}
	for rows.Next() {
		var (
			item       NetworkApplyHistoryRecord
			detailsRaw string
		)
		if err := rows.Scan(&item.ID, &item.Action, &item.Status, &item.Summary, &item.BackupID, &item.RollbackID, &item.Actor, &detailsRaw, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan network apply history: %w", err)
		}
		if strings.TrimSpace(detailsRaw) != "" {
			item.Details = json.RawMessage(detailsRaw)
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network apply history: %w", err)
	}
	return history, nil
}

func StoreDHCPLeaseObservations(observedAt time.Time, leases []DHCPLeaseObservation) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if len(leases) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("begin dhcp lease history transaction: %w", err)
	}
	defer tx.Rollback()

	observed := observedAt.UTC().Format(time.RFC3339)
	stmt, err := tx.Prepare(`INSERT INTO dhcp_lease_history (observed_at, mac, ip, hostname, client_id, reservation, expired, expires_at, remaining_seconds)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare dhcp lease history insert: %w", err)
	}
	defer stmt.Close()

	for _, lease := range leases {
		if _, err := stmt.Exec(
			observed,
			strings.TrimSpace(lease.MAC),
			strings.TrimSpace(lease.IP),
			strings.TrimSpace(lease.Hostname),
			strings.TrimSpace(lease.ClientID),
			boolToSQLite(lease.Reservation),
			boolToSQLite(lease.Expired),
			strings.TrimSpace(lease.ExpiresAt),
			lease.RemainingSeconds,
		); err != nil {
			return fmt.Errorf("insert dhcp lease history: %w", err)
		}
	}

	if err := trimDHCPLeaseHistoryTx(tx, maxDHCPLeaseHistoryRows); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dhcp lease history: %w", err)
	}
	return nil
}

func ListDHCPLeaseHistory(limit int) ([]DHCPLeaseHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, observed_at, mac, ip, COALESCE(hostname, ''), COALESCE(client_id, ''), reservation, expired,
		COALESCE(expires_at, ''), remaining_seconds
		FROM dhcp_lease_history
		ORDER BY datetime(observed_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list dhcp lease history: %w", err)
	}
	defer rows.Close()

	history := []DHCPLeaseHistoryRecord{}
	for rows.Next() {
		var (
			item                         DHCPLeaseHistoryRecord
			reservationValue, expiredVal int
			remaining                    sql.NullInt64
		)
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.MAC, &item.IP, &item.Hostname, &item.ClientID, &reservationValue, &expiredVal, &item.ExpiresAt, &remaining); err != nil {
			return nil, fmt.Errorf("scan dhcp lease history: %w", err)
		}
		item.Reservation = reservationValue == 1
		item.Expired = expiredVal == 1
		if remaining.Valid {
			item.RemainingSeconds = remaining.Int64
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dhcp lease history: %w", err)
	}
	return history, nil
}

func trimNetworkApplyHistory(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM network_apply_history
		WHERE id NOT IN (
			SELECT id FROM network_apply_history ORDER BY datetime(created_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim network apply history: %w", err)
	}
	return nil
}

func trimDHCPLeaseHistoryTx(tx *sql.Tx, maxRows int) error {
	if tx == nil || maxRows <= 0 {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM dhcp_lease_history
		WHERE id NOT IN (
			SELECT id FROM dhcp_lease_history ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows); err != nil {
		return fmt.Errorf("trim dhcp lease history: %w", err)
	}
	return nil
}

func boolToSQLite(value bool) int {
	if value {
		return 1
	}
	return 0
}
