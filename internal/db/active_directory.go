package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxActiveDirectoryRecords = 6000

type ActiveDirectoryEvent struct {
	ID            int      `json:"id"`
	ObservedAt    string   `json:"observed_at"`
	Domain        string   `json:"domain,omitempty"`
	Realm         string   `json:"realm,omitempty"`
	SourceName    string   `json:"source_name"`
	UsernameHash  string   `json:"username_hash"`
	PrincipalHash string   `json:"principal_hash,omitempty"`
	AuthMethod    string   `json:"auth_method"`
	Decision      string   `json:"decision"`
	Reason        string   `json:"reason"`
	LatencyMS     int64    `json:"latency_ms"`
	Role          string   `json:"role,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	CacheUsed     bool     `json:"cache_used"`
	DetailsJSON   string   `json:"details_json,omitempty"`
	CreatedAt     string   `json:"created_at"`
}

type ActiveDirectoryEventSummary struct {
	TotalRecords   int    `json:"total_records"`
	AcceptedCount  int    `json:"accepted_count"`
	RejectedCount  int    `json:"rejected_count"`
	NotFoundCount  int    `json:"not_found_count"`
	FailureCount   int    `json:"failure_count"`
	SkippedCount   int    `json:"skipped_count"`
	CacheHitCount  int    `json:"cache_hit_count"`
	LastObservedAt string `json:"last_observed_at,omitempty"`
	LastSourceName string `json:"last_source_name,omitempty"`
	LastAuthMethod string `json:"last_auth_method,omitempty"`
	LastDecision   string `json:"last_decision,omitempty"`
	LastReason     string `json:"last_reason,omitempty"`
	LastLatencyMS  int64  `json:"last_latency_ms,omitempty"`
}

type ActiveDirectoryGroupCacheEntry struct {
	SourceName    string   `json:"source_name"`
	UsernameHash  string   `json:"username_hash"`
	PrincipalHash string   `json:"principal_hash,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Realm         string   `json:"realm,omitempty"`
	Role          string   `json:"role,omitempty"`
	Groups        []string `json:"groups"`
	LastSuccessAt string   `json:"last_success_at"`
	ExpiresAt     string   `json:"expires_at"`
}

type ActiveDirectoryGroupCacheSummary struct {
	TotalEntries   int    `json:"total_entries"`
	ExpiredEntries int    `json:"expired_entries"`
	LastSuccessAt  string `json:"last_success_at,omitempty"`
	NextExpiresAt  string `json:"next_expires_at,omitempty"`
}

type ActiveDirectoryHealthCheck struct {
	ID          int    `json:"id"`
	CheckedAt   string `json:"checked_at"`
	Domain      string `json:"domain,omitempty"`
	Realm       string `json:"realm,omitempty"`
	Component   string `json:"component"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
	DetailsJSON string `json:"details_json,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type ActiveDirectoryHealthSummary struct {
	TotalRecords  int    `json:"total_records"`
	OKCount       int    `json:"ok_count"`
	DegradedCount int    `json:"degraded_count"`
	BlockedCount  int    `json:"blocked_count"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	LastComponent string `json:"last_component,omitempty"`
	LastStatus    string `json:"last_status,omitempty"`
	LastMessage   string `json:"last_message,omitempty"`
	LastLatencyMS int64  `json:"last_latency_ms,omitempty"`
}

func RecordActiveDirectoryEvent(record ActiveDirectoryEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxActiveDirectoryRecords
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal Active Directory event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	groupsJSON, err := json.Marshal(uniqueActiveDirectoryStrings(record.Groups))
	if err != nil {
		return fmt.Errorf("marshal Active Directory groups: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO active_directory_events
		(observed_at, domain, realm, source_name, username_hash, principal_hash, auth_method, decision, reason, latency_ms, role, groups_json, cache_used, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ObservedAt),
		activeDirectoryNullString(record.Domain),
		activeDirectoryNullString(record.Realm),
		firstActiveDirectoryString(record.SourceName, "active-directory"),
		strings.TrimSpace(record.UsernameHash),
		activeDirectoryNullString(record.PrincipalHash),
		strings.TrimSpace(record.AuthMethod),
		strings.TrimSpace(record.Decision),
		strings.TrimSpace(record.Reason),
		record.LatencyMS,
		activeDirectoryNullString(record.Role),
		string(groupsJSON),
		boolToSQLite(record.CacheUsed),
		detailsJSON)
	if err != nil {
		return fmt.Errorf("insert Active Directory event: %w", err)
	}
	return trimActiveDirectoryEvents(retentionLimit)
}

func ListActiveDirectoryEvents(source, decision string, limit int) ([]ActiveDirectoryEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	query := `SELECT id, COALESCE(observed_at, ''), COALESCE(domain, ''), COALESCE(realm, ''),
		COALESCE(source_name, ''), COALESCE(username_hash, ''), COALESCE(principal_hash, ''),
		COALESCE(auth_method, ''), COALESCE(decision, ''), COALESCE(reason, ''),
		COALESCE(latency_ms, 0), COALESCE(role, ''), COALESCE(groups_json, '[]'),
		COALESCE(cache_used, 0), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM active_directory_events WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(source) != "" {
		query += ` AND source_name = ?`
		args = append(args, strings.TrimSpace(source))
	}
	if strings.TrimSpace(decision) != "" {
		query += ` AND decision = ?`
		args = append(args, strings.TrimSpace(decision))
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list Active Directory events: %w", err)
	}
	defer rows.Close()

	events := []ActiveDirectoryEvent{}
	for rows.Next() {
		var item ActiveDirectoryEvent
		var groupsJSON string
		var cacheUsed int
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.Domain, &item.Realm, &item.SourceName,
			&item.UsernameHash, &item.PrincipalHash, &item.AuthMethod, &item.Decision, &item.Reason,
			&item.LatencyMS, &item.Role, &groupsJSON, &cacheUsed, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan Active Directory event: %w", err)
		}
		item.CacheUsed = cacheUsed == 1
		_ = json.Unmarshal([]byte(groupsJSON), &item.Groups)
		events = append(events, item)
	}
	return events, rows.Err()
}

func GetActiveDirectoryEventSummary() (ActiveDirectoryEventSummary, error) {
	if DB == nil {
		return ActiveDirectoryEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary ActiveDirectoryEventSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'rejected' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'not_found' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'failed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'skipped' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN cache_used = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM active_directory_events`).Scan(&summary.TotalRecords, &summary.AcceptedCount, &summary.RejectedCount,
		&summary.NotFoundCount, &summary.FailureCount, &summary.SkippedCount, &summary.CacheHitCount, &summary.LastObservedAt); err != nil {
		return ActiveDirectoryEventSummary{}, fmt.Errorf("get Active Directory event summary: %w", err)
	}
	if summary.LastObservedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(source_name, ''), COALESCE(auth_method, ''), COALESCE(decision, ''),
			COALESCE(reason, ''), COALESCE(latency_ms, 0)
			FROM active_directory_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastSourceName, &summary.LastAuthMethod, &summary.LastDecision, &summary.LastReason, &summary.LastLatencyMS)
	}
	return summary, nil
}

func UpsertActiveDirectoryGroupCache(sourceName, username, principal, domain, realm, role string, groups []string, ttlSeconds int, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	sourceName = firstActiveDirectoryString(sourceName, "active-directory")
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return fmt.Errorf("username is required")
	}
	if ttlSeconds <= 0 {
		return fmt.Errorf("ttlSeconds must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	groupsJSON, err := json.Marshal(uniqueActiveDirectoryStrings(groups))
	if err != nil {
		return fmt.Errorf("marshal Active Directory group cache: %w", err)
	}
	lastSuccessAt := now.UTC().Format(time.RFC3339)
	expiresAt := now.UTC().Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)
	_, err = DB.Exec(`INSERT INTO active_directory_group_cache
		(source_name, username_hash, principal_hash, domain, realm, role, groups_json, last_success_at, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_name, username_hash) DO UPDATE SET
			principal_hash = excluded.principal_hash,
			domain = excluded.domain,
			realm = excluded.realm,
			role = excluded.role,
			groups_json = excluded.groups_json,
			last_success_at = excluded.last_success_at,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`,
		sourceName, usernameHash, activeDirectoryNullString(HashActiveDirectoryPrincipal(principal)), activeDirectoryNullString(domain), activeDirectoryNullString(realm),
		activeDirectoryNullString(role), string(groupsJSON), lastSuccessAt, expiresAt, lastSuccessAt)
	if err != nil {
		return fmt.Errorf("upsert Active Directory group cache: %w", err)
	}
	return nil
}

func GetActiveDirectoryGroupCache(sourceName, username string, now time.Time) (ActiveDirectoryGroupCacheEntry, bool, error) {
	if DB == nil {
		return ActiveDirectoryGroupCacheEntry{}, false, fmt.Errorf("database not initialized")
	}
	sourceName = firstActiveDirectoryString(sourceName, "active-directory")
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return ActiveDirectoryGroupCacheEntry{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var entry ActiveDirectoryGroupCacheEntry
	var groupsJSON string
	err := DB.QueryRow(`SELECT COALESCE(source_name, ''), COALESCE(username_hash, ''), COALESCE(principal_hash, ''),
		COALESCE(domain, ''), COALESCE(realm, ''), COALESCE(role, ''), COALESCE(groups_json, '[]'),
		COALESCE(last_success_at, ''), COALESCE(expires_at, '')
		FROM active_directory_group_cache WHERE source_name = ? AND username_hash = ? AND datetime(expires_at) > datetime(?)`,
		sourceName, usernameHash, now.UTC().Format(time.RFC3339)).
		Scan(&entry.SourceName, &entry.UsernameHash, &entry.PrincipalHash, &entry.Domain, &entry.Realm, &entry.Role,
			&groupsJSON, &entry.LastSuccessAt, &entry.ExpiresAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return ActiveDirectoryGroupCacheEntry{}, false, nil
		}
		return ActiveDirectoryGroupCacheEntry{}, false, fmt.Errorf("get Active Directory group cache: %w", err)
	}
	if err := json.Unmarshal([]byte(groupsJSON), &entry.Groups); err != nil {
		return ActiveDirectoryGroupCacheEntry{}, false, fmt.Errorf("parse Active Directory group cache: %w", err)
	}
	return entry, true, nil
}

func GetActiveDirectoryGroupCacheSummary(now time.Time) (ActiveDirectoryGroupCacheSummary, error) {
	if DB == nil {
		return ActiveDirectoryGroupCacheSummary{}, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var summary ActiveDirectoryGroupCacheSummary
	if err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN datetime(expires_at) <= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(last_success_at), ''),
		COALESCE(MIN(CASE WHEN datetime(expires_at) > datetime(?) THEN expires_at ELSE NULL END), '')
		FROM active_directory_group_cache`, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).
		Scan(&summary.TotalEntries, &summary.ExpiredEntries, &summary.LastSuccessAt, &summary.NextExpiresAt); err != nil {
		return ActiveDirectoryGroupCacheSummary{}, fmt.Errorf("get Active Directory group cache summary: %w", err)
	}
	return summary, nil
}

func RecordActiveDirectoryHealthCheck(record ActiveDirectoryHealthCheck, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxActiveDirectoryRecords
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal Active Directory health details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO active_directory_health_checks
		(checked_at, domain, realm, component, status, message, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.CheckedAt), activeDirectoryNullString(record.Domain), activeDirectoryNullString(record.Realm),
		strings.TrimSpace(record.Component), strings.TrimSpace(record.Status), activeDirectoryNullString(record.Message),
		record.LatencyMS, detailsJSON)
	if err != nil {
		return fmt.Errorf("insert Active Directory health check: %w", err)
	}
	return trimActiveDirectoryHealthChecks(retentionLimit)
}

func ListActiveDirectoryHealthChecks(component string, limit int) ([]ActiveDirectoryHealthCheck, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 5000 {
		limit = 5000
	}
	query := `SELECT id, COALESCE(checked_at, ''), COALESCE(domain, ''), COALESCE(realm, ''),
		COALESCE(component, ''), COALESCE(status, ''), COALESCE(message, ''),
		COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM active_directory_health_checks WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(component) != "" {
		query += ` AND component = ?`
		args = append(args, strings.TrimSpace(component))
	}
	query += ` ORDER BY datetime(checked_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list Active Directory health checks: %w", err)
	}
	defer rows.Close()

	checks := []ActiveDirectoryHealthCheck{}
	for rows.Next() {
		var item ActiveDirectoryHealthCheck
		if err := rows.Scan(&item.ID, &item.CheckedAt, &item.Domain, &item.Realm, &item.Component,
			&item.Status, &item.Message, &item.LatencyMS, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan Active Directory health check: %w", err)
		}
		checks = append(checks, item)
	}
	return checks, rows.Err()
}

func GetActiveDirectoryHealthSummary() (ActiveDirectoryHealthSummary, error) {
	if DB == nil {
		return ActiveDirectoryHealthSummary{}, fmt.Errorf("database not initialized")
	}
	var summary ActiveDirectoryHealthSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(checked_at), '')
		FROM active_directory_health_checks`).Scan(&summary.TotalRecords, &summary.OKCount, &summary.DegradedCount, &summary.BlockedCount, &summary.LastCheckedAt); err != nil {
		return ActiveDirectoryHealthSummary{}, fmt.Errorf("get Active Directory health summary: %w", err)
	}
	if summary.LastCheckedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(component, ''), COALESCE(status, ''), COALESCE(message, ''), COALESCE(latency_ms, 0)
			FROM active_directory_health_checks ORDER BY datetime(checked_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastComponent, &summary.LastStatus, &summary.LastMessage, &summary.LastLatencyMS)
	}
	return summary, nil
}

func HashActiveDirectoryPrincipal(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func trimActiveDirectoryEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM active_directory_events
		WHERE id NOT IN (
			SELECT id FROM active_directory_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	return err
}

func trimActiveDirectoryHealthChecks(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM active_directory_health_checks
		WHERE id NOT IN (
			SELECT id FROM active_directory_health_checks ORDER BY datetime(checked_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	return err
}

func activeDirectoryNullString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func firstActiveDirectoryString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueActiveDirectoryStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
