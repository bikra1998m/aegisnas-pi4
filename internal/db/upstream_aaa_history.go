package db

import (
	"fmt"
	"strings"
)

const maxUpstreamAAAHistoryRows = 6000

type UpstreamAAAHistoryRecord struct {
	ID                   int    `json:"id"`
	ServerName           string `json:"server_name"`
	Address              string `json:"address"`
	AuthPort             int    `json:"auth_port"`
	AcctPort             int    `json:"acct_port"`
	Status               string `json:"status"`
	Message              string `json:"message"`
	ResponseCode         string `json:"response_code"`
	LatencyMs            int64  `json:"latency_ms"`
	SupportsStatusServer bool   `json:"supports_status_server"`
	CheckedAt            string `json:"checked_at"`
	CreatedAt            string `json:"created_at"`
	Transport            string `json:"transport"`
	RadSecPort           int    `json:"radsec_port,omitempty"`
	TLSVersion           string `json:"tls_version,omitempty"`
	TLSCipherSuite       string `json:"tls_cipher_suite,omitempty"`
	TLSALPN              string `json:"tls_alpn,omitempty"`
	PeerSubject          string `json:"peer_subject,omitempty"`
	PeerIssuer           string `json:"peer_issuer,omitempty"`
	PeerSerial           string `json:"peer_serial,omitempty"`
	PeerNotAfter         string `json:"peer_not_after,omitempty"`
}

type UpstreamAAAHistoryStats struct {
	TotalRecords  int    `json:"total_records"`
	OKCount       int    `json:"ok_count"`
	DegradedCount int    `json:"degraded_count"`
	DownCount     int    `json:"down_count"`
	DisabledCount int    `json:"disabled_count"`
	AvgLatencyMs  int64  `json:"avg_latency_ms"`
	LastCheckedAt string `json:"last_checked_at"`
}

func RecordUpstreamAAAHistory(serverName, address string, authPort, acctPort int, status, message, responseCode string, latencyMs int64, supportsStatusServer bool, checkedAt string) error {
	return RecordUpstreamAAAHistoryRecord(UpstreamAAAHistoryRecord{
		ServerName: serverName, Address: address, AuthPort: authPort, AcctPort: acctPort,
		Status: status, Message: message, ResponseCode: responseCode, LatencyMs: latencyMs,
		SupportsStatusServer: supportsStatusServer, CheckedAt: checkedAt, Transport: "udp",
	})
}

func RecordUpstreamAAAHistoryRecord(record UpstreamAAAHistoryRecord) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if _, err := DB.Exec(`INSERT INTO upstream_aaa_history
		(server_name, address, auth_port, acct_port, status, message, response_code, latency_ms, supports_status_server, checked_at,
		 transport, radsec_port, tls_version, tls_cipher_suite, tls_alpn, peer_subject, peer_issuer, peer_serial, peer_not_after)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ServerName), strings.TrimSpace(record.Address), record.AuthPort, record.AcctPort,
		strings.TrimSpace(record.Status), strings.TrimSpace(record.Message), strings.TrimSpace(record.ResponseCode), record.LatencyMs,
		boolToSQLite(record.SupportsStatusServer), strings.TrimSpace(record.CheckedAt), strings.TrimSpace(record.Transport), record.RadSecPort,
		strings.TrimSpace(record.TLSVersion), strings.TrimSpace(record.TLSCipherSuite), strings.TrimSpace(record.TLSALPN),
		strings.TrimSpace(record.PeerSubject), strings.TrimSpace(record.PeerIssuer), strings.TrimSpace(record.PeerSerial), strings.TrimSpace(record.PeerNotAfter),
	); err != nil {
		return fmt.Errorf("insert upstream aaa history: %w", err)
	}
	return trimUpstreamAAAHistory(maxUpstreamAAAHistoryRows)
}

func ListUpstreamAAAHistory(serverName, status string, limit int) ([]UpstreamAAAHistoryRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	serverName = strings.TrimSpace(serverName)
	status = strings.TrimSpace(status)

	query := `SELECT id, COALESCE(server_name, ''), COALESCE(address, ''), COALESCE(auth_port, 0), COALESCE(acct_port, 0),
		COALESCE(status, ''), COALESCE(message, ''), COALESCE(response_code, ''), COALESCE(latency_ms, 0),
		COALESCE(supports_status_server, 0), COALESCE(checked_at, ''), COALESCE(created_at, ''), COALESCE(transport, 'udp'),
		COALESCE(radsec_port, 0), COALESCE(tls_version, ''), COALESCE(tls_cipher_suite, ''), COALESCE(tls_alpn, ''),
		COALESCE(peer_subject, ''), COALESCE(peer_issuer, ''), COALESCE(peer_serial, ''), COALESCE(peer_not_after, '')
		FROM upstream_aaa_history WHERE 1=1`
	args := []any{}
	if serverName != "" {
		query += ` AND server_name = ?`
		args = append(args, serverName)
	}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY datetime(checked_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list upstream aaa history: %w", err)
	}
	defer rows.Close()

	history := []UpstreamAAAHistoryRecord{}
	for rows.Next() {
		var item UpstreamAAAHistoryRecord
		var supports int
		if err := rows.Scan(&item.ID, &item.ServerName, &item.Address, &item.AuthPort, &item.AcctPort, &item.Status, &item.Message, &item.ResponseCode, &item.LatencyMs, &supports, &item.CheckedAt, &item.CreatedAt,
			&item.Transport, &item.RadSecPort, &item.TLSVersion, &item.TLSCipherSuite, &item.TLSALPN, &item.PeerSubject, &item.PeerIssuer, &item.PeerSerial, &item.PeerNotAfter); err != nil {
			return nil, fmt.Errorf("scan upstream aaa history: %w", err)
		}
		item.SupportsStatusServer = supports == 1
		history = append(history, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate upstream aaa history: %w", err)
	}
	return history, nil
}

func GetUpstreamAAAHistoryStats() (UpstreamAAAHistoryStats, error) {
	if DB == nil {
		return UpstreamAAAHistoryStats{}, fmt.Errorf("database not initialized")
	}
	var stats UpstreamAAAHistoryStats
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'disabled' THEN 1 ELSE 0 END), 0),
		COALESCE(CAST(ROUND(AVG(CASE WHEN latency_ms > 0 THEN latency_ms END), 0) AS INTEGER), 0),
		COALESCE(MAX(checked_at), '')
		FROM upstream_aaa_history`).Scan(
		&stats.TotalRecords,
		&stats.OKCount,
		&stats.DegradedCount,
		&stats.DownCount,
		&stats.DisabledCount,
		&stats.AvgLatencyMs,
		&stats.LastCheckedAt,
	)
	if err != nil {
		return UpstreamAAAHistoryStats{}, fmt.Errorf("get upstream aaa history stats: %w", err)
	}
	return stats, nil
}

func trimUpstreamAAAHistory(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM upstream_aaa_history
		WHERE id NOT IN (
			SELECT id FROM upstream_aaa_history ORDER BY datetime(checked_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim upstream aaa history: %w", err)
	}
	return nil
}

func countUpstreamAAAHistoryRows() (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM upstream_aaa_history`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
