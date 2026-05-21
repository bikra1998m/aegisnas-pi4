package db

import (
	"fmt"
	"strings"
)

type AuditHistoryRecord struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Details   string `json:"details"`
	Result    string `json:"result"`
	IPAddress string `json:"ip_address"`
}

type AuditHistoryStats struct {
	TotalRecords       int    `json:"total_records"`
	UniqueUsers        int    `json:"unique_users"`
	ExportActionCount  int    `json:"export_action_count"`
	StagedChangeCount  int    `json:"staged_change_count"`
	NetworkActionCount int    `json:"network_action_count"`
	HAActionCount      int    `json:"ha_action_count"`
	UpgradeActionCount int    `json:"upgrade_action_count"`
	GuestActionCount   int    `json:"guest_action_count"`
	LastRecordedAt     string `json:"last_recorded_at"`
}

func ListAuditHistory(userFilter, actionPrefix string, limit int) ([]AuditHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	userFilter = strings.TrimSpace(userFilter)
	actionPrefix = strings.TrimSpace(actionPrefix)

	query := `SELECT id, CAST(timestamp AS TEXT), COALESCE(user, ''), action, COALESCE(details, ''), COALESCE(result, ''), COALESCE(ip_address, '')
		FROM audit_logs WHERE 1=1`
	args := []any{}
	if userFilter != "" {
		query += ` AND user = ?`
		args = append(args, userFilter)
	}
	if actionPrefix != "" {
		query += ` AND action LIKE ?`
		args = append(args, actionPrefix+"%")
	}
	query += ` ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit history: %w", err)
	}
	defer rows.Close()

	history := []AuditHistoryRecord{}
	for rows.Next() {
		var item AuditHistoryRecord
		if err := rows.Scan(&item.ID, &item.Timestamp, &item.User, &item.Action, &item.Details, &item.Result, &item.IPAddress); err != nil {
			return nil, fmt.Errorf("scan audit history: %w", err)
		}
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit history: %w", err)
	}
	return history, nil
}

func GetAuditHistoryStats() (AuditHistoryStats, error) {
	if DB == nil {
		return AuditHistoryStats{}, fmt.Errorf("database not initialized")
	}
	var stats AuditHistoryStats
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COUNT(DISTINCT NULLIF(TRIM(COALESCE(user, '')), '')),
		COALESCE(SUM(CASE WHEN action LIKE 'download_%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action LIKE 'stage_%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action LIKE '%network%' OR action LIKE '%hostapd%' OR action LIKE '%radius%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action LIKE '%ha_%' OR action LIKE 'activate_ha%' OR action LIKE 'import_ha%' OR action LIKE 'stage_shared_ha%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action LIKE '%upgrade%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN action LIKE 'guest_%' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(CAST(timestamp AS TEXT)), '')
		FROM audit_logs`).Scan(
		&stats.TotalRecords,
		&stats.UniqueUsers,
		&stats.ExportActionCount,
		&stats.StagedChangeCount,
		&stats.NetworkActionCount,
		&stats.HAActionCount,
		&stats.UpgradeActionCount,
		&stats.GuestActionCount,
		&stats.LastRecordedAt,
	)
	if err != nil {
		return AuditHistoryStats{}, fmt.Errorf("get audit history stats: %w", err)
	}
	return stats, nil
}
