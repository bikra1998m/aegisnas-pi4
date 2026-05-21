package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

const maxIntegrationHistoryRows = 4000

type IntegrationHistoryRecord struct {
	ID        int             `json:"id"`
	Component string          `json:"component"`
	Status    string          `json:"status"`
	Summary   string          `json:"summary"`
	Details   json.RawMessage `json:"details,omitempty"`
	CreatedAt string          `json:"created_at"`
}

type IntegrationHistoryStats struct {
	TotalRecords           int    `json:"total_records"`
	ControllerEventCount   int    `json:"controller_event_count"`
	ControllerSuccessCount int    `json:"controller_success_count"`
	ControllerFailureCount int    `json:"controller_failure_count"`
	MDMSyncEventCount      int    `json:"mdm_sync_event_count"`
	MDMSyncSuccessCount    int    `json:"mdm_sync_success_count"`
	MDMSyncFailureCount    int    `json:"mdm_sync_failure_count"`
	PostureEventCount      int    `json:"posture_event_count"`
	PostureSuccessCount    int    `json:"posture_success_count"`
	PostureFailureCount    int    `json:"posture_failure_count"`
	LastEventAt            string `json:"last_event_at"`
}

func RecordIntegrationHistory(component, status, summary string, details any) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	var detailsJSON string
	if details != nil {
		data, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("encode integration history details: %w", err)
		}
		detailsJSON = string(data)
	}
	if _, err := DB.Exec(`INSERT INTO integration_history (component, status, summary, details_json)
		VALUES (?, ?, ?, ?)`,
		strings.TrimSpace(component),
		strings.TrimSpace(status),
		strings.TrimSpace(summary),
		detailsJSON,
	); err != nil {
		return fmt.Errorf("insert integration history: %w", err)
	}
	return trimIntegrationHistory(maxIntegrationHistoryRows)
}

func ListIntegrationHistory(component string, limit int) ([]IntegrationHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	component = strings.TrimSpace(component)

	query := `SELECT id, component, status, COALESCE(summary, ''), COALESCE(details_json, ''), created_at
		FROM integration_history`
	args := []any{}
	if component != "" {
		query += ` WHERE component = ?`
		args = append(args, component)
	}
	query += ` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list integration history: %w", err)
	}
	defer rows.Close()

	history := []IntegrationHistoryRecord{}
	for rows.Next() {
		var (
			item       IntegrationHistoryRecord
			detailsRaw string
		)
		if err := rows.Scan(&item.ID, &item.Component, &item.Status, &item.Summary, &detailsRaw, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan integration history: %w", err)
		}
		if strings.TrimSpace(detailsRaw) != "" {
			item.Details = json.RawMessage(detailsRaw)
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate integration history: %w", err)
	}
	return history, nil
}

func GetIntegrationHistoryStats() (IntegrationHistoryStats, error) {
	if DB == nil {
		return IntegrationHistoryStats{}, fmt.Errorf("database not initialized")
	}
	var stats IntegrationHistoryStats
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN component = 'controller_automation' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'controller_automation' AND status = 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'controller_automation' AND status <> 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'mdm_sync' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'mdm_sync' AND status = 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'mdm_sync' AND status <> 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'posture_checks' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'posture_checks' AND status = 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN component = 'posture_checks' AND status <> 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), '')
		FROM integration_history`).Scan(
		&stats.TotalRecords,
		&stats.ControllerEventCount,
		&stats.ControllerSuccessCount,
		&stats.ControllerFailureCount,
		&stats.MDMSyncEventCount,
		&stats.MDMSyncSuccessCount,
		&stats.MDMSyncFailureCount,
		&stats.PostureEventCount,
		&stats.PostureSuccessCount,
		&stats.PostureFailureCount,
		&stats.LastEventAt,
	)
	if err != nil {
		return IntegrationHistoryStats{}, fmt.Errorf("get integration history stats: %w", err)
	}
	return stats, nil
}

func trimIntegrationHistory(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM integration_history
		WHERE id NOT IN (
			SELECT id FROM integration_history ORDER BY datetime(created_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim integration history: %w", err)
	}
	return nil
}

func countIntegrationHistoryRows() (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM integration_history`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
