package db

import (
	"fmt"
	"strings"
)

type SessionHistoryQuery struct {
	Username     string
	AuthMethod   string
	ActiveOnly   *bool
	TenantScopes []string
	Limit        int
}

type SessionHistoryRecord struct {
	ID               string `json:"id"`
	Username         string `json:"username"`
	MAC              string `json:"mac"`
	IP               string `json:"ip"`
	AuthMethod       string `json:"auth_method"`
	IdentitySource   string `json:"identity_source"`
	VLAN             int    `json:"vlan"`
	Role             string `json:"role"`
	BandwidthProfile string `json:"bandwidth_profile"`
	FilterID         string `json:"filter_id"`
	RadiusClass      string `json:"radius_class"`
	SessionTimeout   int    `json:"session_timeout"`
	IdleTimeout      int    `json:"idle_timeout"`
	AcctSessionTime  int64  `json:"acct_session_time"`
	CalledStationID  string `json:"called_station_id"`
	NASIdentifier    string `json:"nas_identifier"`
	RadiusSessionID  string `json:"radius_session_id"`
	StartTime        string `json:"start_time"`
	LastActivity     string `json:"last_activity"`
	EndTime          string `json:"end_time"`
	StopReason       string `json:"stop_reason"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
	TotalBytes       int64  `json:"total_bytes"`
}

type SessionHistoryStats struct {
	TotalRecords            int    `json:"total_records"`
	ActiveCount             int    `json:"active_count"`
	EndedCount              int    `json:"ended_count"`
	AccountedRecordCount    int    `json:"accounted_record_count"`
	BytesInTotal            int64  `json:"bytes_in_total"`
	BytesOutTotal           int64  `json:"bytes_out_total"`
	TrafficTotal            int64  `json:"traffic_total"`
	AcctSessionSecondsTotal int64  `json:"acct_session_seconds_total"`
	AvgAcctSessionSeconds   int64  `json:"avg_acct_session_seconds"`
	MaxAcctSessionSeconds   int64  `json:"max_acct_session_seconds"`
	LastStartedAt           string `json:"last_started_at"`
	LastEndedAt             string `json:"last_ended_at"`
}

func ListSessionHistory(query SessionHistoryQuery) ([]SessionHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if query.Limit <= 0 {
		query.Limit = 200
	}
	if query.Limit > 5000 {
		query.Limit = 5000
	}

	baseQuery := `SELECT
		id,
		COALESCE(username, ''),
		COALESCE(mac, ''),
		COALESCE(ip, ''),
		COALESCE(auth_method, ''),
		COALESCE(identity_source, ''),
		COALESCE(vlan, 0),
		COALESCE(role, ''),
		COALESCE(bandwidth_profile, ''),
		COALESCE(filter_id, ''),
		COALESCE(radius_class, ''),
		COALESCE(session_timeout, 0),
		COALESCE(idle_timeout, 0),
		COALESCE(acct_session_time, 0),
		COALESCE(called_station_id, ''),
		COALESCE(nas_identifier, ''),
		COALESCE(radius_session_id, ''),
		CAST(start_time AS TEXT),
		COALESCE(CAST(last_activity AS TEXT), ''),
		COALESCE(CAST(end_time AS TEXT), ''),
		COALESCE(stop_reason, ''),
		COALESCE(bytes_in, 0),
		COALESCE(bytes_out, 0)
		FROM sessions`
	clauses, args := sessionHistoryClauses(query)
	if len(clauses) > 0 {
		baseQuery += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	baseQuery += ` ORDER BY datetime(start_time) DESC, id DESC LIMIT ?`
	args = append(args, query.Limit)

	rows, err := DB.Query(baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list session history: %w", err)
	}
	defer rows.Close()

	history := []SessionHistoryRecord{}
	for rows.Next() {
		var item SessionHistoryRecord
		if err := rows.Scan(
			&item.ID,
			&item.Username,
			&item.MAC,
			&item.IP,
			&item.AuthMethod,
			&item.IdentitySource,
			&item.VLAN,
			&item.Role,
			&item.BandwidthProfile,
			&item.FilterID,
			&item.RadiusClass,
			&item.SessionTimeout,
			&item.IdleTimeout,
			&item.AcctSessionTime,
			&item.CalledStationID,
			&item.NASIdentifier,
			&item.RadiusSessionID,
			&item.StartTime,
			&item.LastActivity,
			&item.EndTime,
			&item.StopReason,
			&item.BytesIn,
			&item.BytesOut,
		); err != nil {
			return nil, fmt.Errorf("scan session history: %w", err)
		}
		item.TotalBytes = item.BytesIn + item.BytesOut
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session history: %w", err)
	}
	return history, nil
}

func GetSessionHistoryStats(query SessionHistoryQuery) (SessionHistoryStats, error) {
	if DB == nil {
		return SessionHistoryStats{}, fmt.Errorf("database not initialized")
	}

	baseQuery := `SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN end_time IS NULL THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN end_time IS NOT NULL THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(acct_session_time, 0) > 0 OR COALESCE(bytes_in, 0) > 0 OR COALESCE(bytes_out, 0) > 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(COALESCE(bytes_in, 0)), 0),
		COALESCE(SUM(COALESCE(bytes_out, 0)), 0),
		COALESCE(SUM(COALESCE(bytes_in, 0) + COALESCE(bytes_out, 0)), 0),
		COALESCE(SUM(COALESCE(acct_session_time, 0)), 0),
		COALESCE(CAST(AVG(COALESCE(acct_session_time, 0)) AS INTEGER), 0),
		COALESCE(MAX(COALESCE(acct_session_time, 0)), 0),
		COALESCE(MAX(CAST(start_time AS TEXT)), ''),
		COALESCE(MAX(CASE WHEN end_time IS NOT NULL THEN CAST(end_time AS TEXT) END), '')
		FROM sessions`
	clauses, args := sessionHistoryClauses(query)
	if len(clauses) > 0 {
		baseQuery += ` WHERE ` + strings.Join(clauses, " AND ")
	}

	var stats SessionHistoryStats
	if err := DB.QueryRow(baseQuery, args...).Scan(
		&stats.TotalRecords,
		&stats.ActiveCount,
		&stats.EndedCount,
		&stats.AccountedRecordCount,
		&stats.BytesInTotal,
		&stats.BytesOutTotal,
		&stats.TrafficTotal,
		&stats.AcctSessionSecondsTotal,
		&stats.AvgAcctSessionSeconds,
		&stats.MaxAcctSessionSeconds,
		&stats.LastStartedAt,
		&stats.LastEndedAt,
	); err != nil {
		return SessionHistoryStats{}, fmt.Errorf("get session history stats: %w", err)
	}
	return stats, nil
}

func sessionHistoryClauses(query SessionHistoryQuery) ([]string, []any) {
	clauses := []string{}
	args := []any{}

	if username := strings.TrimSpace(query.Username); username != "" {
		clauses = append(clauses, "username = ?")
		args = append(args, username)
	}
	if authMethod := strings.TrimSpace(query.AuthMethod); authMethod != "" {
		clauses = append(clauses, "COALESCE(auth_method, '') = ?")
		args = append(args, authMethod)
	}
	if query.ActiveOnly != nil {
		if *query.ActiveOnly {
			clauses = append(clauses, "end_time IS NULL")
		} else {
			clauses = append(clauses, "end_time IS NOT NULL")
		}
	}
	if scopes := normalizeSessionHistoryScopes(query.TenantScopes); len(scopes) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(scopes)), ",")
		clauses = append(clauses, fmt.Sprintf(`COALESCE(
			(SELECT tenant FROM local_users WHERE username = sessions.username LIMIT 1),
			(SELECT tenant FROM device_inventory WHERE mac = sessions.mac LIMIT 1),
			''
		) IN (%s)`, placeholders))
		for _, scope := range scopes {
			args = append(args, scope)
		}
	}
	return clauses, args
}

func normalizeSessionHistoryScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
