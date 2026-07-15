package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

const maxRadiusFallbackEvents = 6000

type RadiusFallbackEvent struct {
	ID              int    `json:"id"`
	ObservedAt      string `json:"observed_at"`
	Source          string `json:"source"`
	UsernameHash    string `json:"username_hash"`
	Realm           string `json:"realm,omitempty"`
	IdentitySource  string `json:"identity_source,omitempty"`
	Role            string `json:"role,omitempty"`
	Decision        string `json:"decision"`
	Reason          string `json:"reason"`
	UpstreamStatus  string `json:"upstream_status,omitempty"`
	PolicyMode      string `json:"policy_mode"`
	FailClosed      bool   `json:"fail_closed"`
	OutageStartedAt string `json:"outage_started_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	DetailsJSON     string `json:"details_json,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type RadiusFallbackEventSummary struct {
	TotalRecords       int    `json:"total_records"`
	AllowedCount       int    `json:"allowed_count"`
	DeniedCount        int    `json:"denied_count"`
	MonitorCount       int    `json:"monitor_count"`
	LastObservedAt     string `json:"last_observed_at"`
	LastDecision       string `json:"last_decision"`
	LastReason         string `json:"last_reason"`
	LastPolicyMode     string `json:"last_policy_mode"`
	LastUpstreamStatus string `json:"last_upstream_status"`
}

func RecordRadiusFallbackEvent(record RadiusFallbackEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxRadiusFallbackEvents
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal fallback event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	if _, err := DB.Exec(`INSERT INTO radius_fallback_events
		(observed_at, source, username_hash, realm, identity_source, role, decision, reason, upstream_status,
		 policy_mode, fail_closed, outage_started_at, expires_at, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ObservedAt),
		strings.TrimSpace(record.Source),
		strings.TrimSpace(record.UsernameHash),
		strings.TrimSpace(record.Realm),
		strings.TrimSpace(record.IdentitySource),
		strings.TrimSpace(record.Role),
		strings.TrimSpace(record.Decision),
		strings.TrimSpace(record.Reason),
		strings.TrimSpace(record.UpstreamStatus),
		strings.TrimSpace(record.PolicyMode),
		boolToSQLite(record.FailClosed),
		strings.TrimSpace(record.OutageStartedAt),
		strings.TrimSpace(record.ExpiresAt),
		detailsJSON,
	); err != nil {
		return fmt.Errorf("insert radius fallback event: %w", err)
	}
	return trimRadiusFallbackEvents(retentionLimit)
}

func ListRadiusFallbackEvents(decision, source string, limit int) ([]RadiusFallbackEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	decision = strings.TrimSpace(decision)
	source = strings.TrimSpace(source)

	query := `SELECT id, COALESCE(observed_at, ''), COALESCE(source, ''), COALESCE(username_hash, ''),
		COALESCE(realm, ''), COALESCE(identity_source, ''), COALESCE(role, ''), COALESCE(decision, ''),
		COALESCE(reason, ''), COALESCE(upstream_status, ''), COALESCE(policy_mode, ''), COALESCE(fail_closed, 0),
		COALESCE(outage_started_at, ''), COALESCE(expires_at, ''), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM radius_fallback_events WHERE 1=1`
	args := []any{}
	if decision != "" {
		query += ` AND decision = ?`
		args = append(args, decision)
	}
	if source != "" {
		query += ` AND source = ?`
		args = append(args, source)
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list radius fallback events: %w", err)
	}
	defer rows.Close()

	events := []RadiusFallbackEvent{}
	for rows.Next() {
		var item RadiusFallbackEvent
		var failClosed int
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.Source, &item.UsernameHash, &item.Realm,
			&item.IdentitySource, &item.Role, &item.Decision, &item.Reason, &item.UpstreamStatus,
			&item.PolicyMode, &failClosed, &item.OutageStartedAt, &item.ExpiresAt, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan radius fallback event: %w", err)
		}
		item.FailClosed = failClosed == 1
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate radius fallback events: %w", err)
	}
	return events, nil
}

func GetRadiusFallbackEventSummary() (RadiusFallbackEventSummary, error) {
	if DB == nil {
		return RadiusFallbackEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary RadiusFallbackEventSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'allowed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN policy_mode = 'monitor' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM radius_fallback_events`).Scan(&summary.TotalRecords, &summary.AllowedCount, &summary.DeniedCount, &summary.MonitorCount, &summary.LastObservedAt); err != nil {
		return RadiusFallbackEventSummary{}, fmt.Errorf("get radius fallback event summary: %w", err)
	}
	if summary.LastObservedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(decision, ''), COALESCE(reason, ''), COALESCE(policy_mode, ''), COALESCE(upstream_status, '')
			FROM radius_fallback_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastDecision, &summary.LastReason, &summary.LastPolicyMode, &summary.LastUpstreamStatus)
	}
	return summary, nil
}

func trimRadiusFallbackEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM radius_fallback_events
		WHERE id NOT IN (
			SELECT id FROM radius_fallback_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim radius fallback events: %w", err)
	}
	return nil
}
