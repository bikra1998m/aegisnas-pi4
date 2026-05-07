package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

const maxHAHistoryRows = 2000

type HAHistoryRecord struct {
	ID        int             `json:"id"`
	EventType string          `json:"event_type"`
	Status    string          `json:"status"`
	Summary   string          `json:"summary"`
	NodeRole  string          `json:"node_role,omitempty"`
	Actor     string          `json:"actor,omitempty"`
	Details   json.RawMessage `json:"details,omitempty"`
	CreatedAt string          `json:"created_at"`
}

type HAHistoryStats struct {
	TotalRecords          int    `json:"total_records"`
	FailoverPromotions    int    `json:"failover_promotions"`
	FailoverReturns       int    `json:"failover_returns"`
	PeerFailures          int    `json:"peer_failures"`
	PeerRecoveries        int    `json:"peer_recoveries"`
	VIPAcquisitions       int    `json:"vip_acquisitions"`
	VIPPreemptions        int    `json:"vip_preemptions"`
	VIPReleases           int    `json:"vip_releases"`
	ReplicationPublishes  int    `json:"replication_publishes"`
	ReplicationFailures   int    `json:"replication_failures"`
	ReplicationStaleCount int    `json:"replication_stale_count"`
	SharedStages          int    `json:"shared_stages"`
	Activations           int    `json:"activations"`
	LastEventAt           string `json:"last_event_at"`
}

func RecordHAHistory(eventType, status, summary, nodeRole, actor string, details any) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	var detailsJSON string
	if details != nil {
		data, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("encode ha history details: %w", err)
		}
		detailsJSON = string(data)
	}
	if _, err := DB.Exec(`INSERT INTO ha_history (event_type, status, summary, node_role, actor, details_json)
		VALUES (?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(eventType),
		strings.TrimSpace(status),
		strings.TrimSpace(summary),
		strings.TrimSpace(nodeRole),
		strings.TrimSpace(actor),
		detailsJSON,
	); err != nil {
		return fmt.Errorf("insert ha history: %w", err)
	}
	return trimHAHistory(maxHAHistoryRows)
}

func ListHAHistory(limit int) ([]HAHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_type, status, COALESCE(summary, ''), COALESCE(node_role, ''), COALESCE(actor, ''),
		COALESCE(details_json, ''), created_at
		FROM ha_history
		ORDER BY datetime(created_at) DESC, id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list ha history: %w", err)
	}
	defer rows.Close()

	history := []HAHistoryRecord{}
	for rows.Next() {
		var (
			item       HAHistoryRecord
			detailsRaw string
		)
		if err := rows.Scan(&item.ID, &item.EventType, &item.Status, &item.Summary, &item.NodeRole, &item.Actor, &detailsRaw, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ha history: %w", err)
		}
		if strings.TrimSpace(detailsRaw) != "" {
			item.Details = json.RawMessage(detailsRaw)
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ha history: %w", err)
	}
	return history, nil
}

func GetHAHistoryStats() (HAHistoryStats, error) {
	if DB == nil {
		return HAHistoryStats{}, fmt.Errorf("database not initialized")
	}
	var stats HAHistoryStats
	err := DB.QueryRow(`SELECT
		COUNT(*),
		SUM(CASE WHEN event_type = 'failover' AND status = 'promoted' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'failover' AND status = 'returned' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'peer_health' AND status = 'failed' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'peer_health' AND status = 'recovered' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'vip_lease' AND status = 'acquired' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'vip_lease' AND status = 'preempted' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'vip_lease' AND status = 'released' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'replication_publish' AND status = 'success' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'replication_publish' AND status = 'failed' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'replication_freshness' AND status = 'stale' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'replication_stage' AND status = 'staged' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type = 'replication_activate' AND status = 'activated' THEN 1 ELSE 0 END),
		COALESCE(MAX(created_at), '')
		FROM ha_history`).Scan(
		&stats.TotalRecords,
		&stats.FailoverPromotions,
		&stats.FailoverReturns,
		&stats.PeerFailures,
		&stats.PeerRecoveries,
		&stats.VIPAcquisitions,
		&stats.VIPPreemptions,
		&stats.VIPReleases,
		&stats.ReplicationPublishes,
		&stats.ReplicationFailures,
		&stats.ReplicationStaleCount,
		&stats.SharedStages,
		&stats.Activations,
		&stats.LastEventAt,
	)
	if err != nil {
		return HAHistoryStats{}, fmt.Errorf("get ha history stats: %w", err)
	}
	return stats, nil
}

func trimHAHistory(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM ha_history
		WHERE id NOT IN (
			SELECT id FROM ha_history ORDER BY datetime(created_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim ha history: %w", err)
	}
	return nil
}

func countHAHistoryRows() (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM ha_history`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func scanNullableInt(value sql.NullInt64) int {
	if !value.Valid {
		return 0
	}
	return int(value.Int64)
}
