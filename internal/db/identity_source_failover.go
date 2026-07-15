package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxIdentitySourceEvents = 6000

var identitySourceCacheBcryptCost = bcrypt.DefaultCost

type IdentitySourceRecord struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Config    string `json:"config,omitempty"`
	Enabled   bool   `json:"enabled"`
	Priority  int    `json:"priority"`
	CreatedAt string `json:"created_at,omitempty"`
}

type IdentitySourceEvent struct {
	ID           int    `json:"id"`
	ObservedAt   string `json:"observed_at"`
	SourceName   string `json:"source_name"`
	SourceType   string `json:"source_type"`
	UsernameHash string `json:"username_hash"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason"`
	LatencyMS    int64  `json:"latency_ms"`
	CircuitState string `json:"circuit_state"`
	CacheUsed    bool   `json:"cache_used"`
	DetailsJSON  string `json:"details_json,omitempty"`
	CreatedAt    string `json:"created_at"`
}

type IdentitySourceEventSummary struct {
	TotalRecords           int    `json:"total_records"`
	AcceptedCount          int    `json:"accepted_count"`
	RejectedCount          int    `json:"rejected_count"`
	NotFoundCount          int    `json:"not_found_count"`
	FailureCount           int    `json:"failure_count"`
	SkippedCount           int    `json:"skipped_count"`
	StaleAcceptedCount     int    `json:"stale_accepted_count"`
	SplitDeniedCount       int    `json:"split_denied_count"`
	CacheHitCount          int    `json:"cache_hit_count"`
	LastObservedAt         string `json:"last_observed_at"`
	LastSourceName         string `json:"last_source_name"`
	LastSourceType         string `json:"last_source_type"`
	LastDecision           string `json:"last_decision"`
	LastReason             string `json:"last_reason"`
	LastCircuitState       string `json:"last_circuit_state"`
	OpenCircuitSourceCount int    `json:"open_circuit_source_count"`
}

type IdentitySourceCircuitState struct {
	SourceName     string `json:"source_name"`
	State          string `json:"state"`
	FailureCount   int    `json:"failure_count"`
	LastObservedAt string `json:"last_observed_at,omitempty"`
	LastReason     string `json:"last_reason,omitempty"`
	OpenedAt       string `json:"opened_at,omitempty"`
	ReopensAt      string `json:"reopens_at,omitempty"`
}

type IdentitySourceCacheEntry struct {
	SourceName     string   `json:"source_name"`
	UsernameHash   string   `json:"username_hash"`
	Role           string   `json:"role"`
	Groups         []string `json:"groups"`
	IdentitySource string   `json:"identity_source"`
	LastSuccessAt  string   `json:"last_success_at"`
	ExpiresAt      string   `json:"expires_at"`
}

type IdentitySourceCacheSummary struct {
	TotalEntries   int    `json:"total_entries"`
	ExpiredEntries int    `json:"expired_entries"`
	LastSuccessAt  string `json:"last_success_at,omitempty"`
	NextExpiresAt  string `json:"next_expires_at,omitempty"`
}

func ListIdentitySourceRecords() ([]IdentitySourceRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(`SELECT id, COALESCE(name, ''), COALESCE(type, ''), COALESCE(config, ''),
		COALESCE(enabled, 0), COALESCE(priority, 0), COALESCE(created_at, '')
		FROM identity_sources ORDER BY priority ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list identity sources: %w", err)
	}
	defer rows.Close()

	records := []IdentitySourceRecord{}
	for rows.Next() {
		var item IdentitySourceRecord
		var enabled int
		if err := rows.Scan(&item.ID, &item.Name, &item.Type, &item.Config, &enabled, &item.Priority, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity source: %w", err)
		}
		item.Enabled = enabled == 1
		records = append(records, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity sources: %w", err)
	}
	return records, nil
}

func RecordIdentitySourceEvent(record IdentitySourceEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxIdentitySourceEvents
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal identity source event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	if _, err := DB.Exec(`INSERT INTO identity_source_events
		(observed_at, source_name, source_type, username_hash, decision, reason, latency_ms, circuit_state, cache_used, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ObservedAt),
		strings.TrimSpace(record.SourceName),
		strings.TrimSpace(record.SourceType),
		strings.TrimSpace(record.UsernameHash),
		strings.TrimSpace(record.Decision),
		strings.TrimSpace(record.Reason),
		record.LatencyMS,
		strings.TrimSpace(record.CircuitState),
		boolToSQLite(record.CacheUsed),
		detailsJSON,
	); err != nil {
		return fmt.Errorf("insert identity source event: %w", err)
	}
	return trimIdentitySourceEvents(retentionLimit)
}

func ListIdentitySourceEvents(source, decision string, limit int) ([]IdentitySourceEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	source = strings.TrimSpace(source)
	decision = strings.TrimSpace(decision)

	query := `SELECT id, COALESCE(observed_at, ''), COALESCE(source_name, ''), COALESCE(source_type, ''),
		COALESCE(username_hash, ''), COALESCE(decision, ''), COALESCE(reason, ''), COALESCE(latency_ms, 0),
		COALESCE(circuit_state, ''), COALESCE(cache_used, 0), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM identity_source_events WHERE 1=1`
	args := []any{}
	if source != "" {
		query += ` AND source_name = ?`
		args = append(args, source)
	}
	if decision != "" {
		query += ` AND decision = ?`
		args = append(args, decision)
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identity source events: %w", err)
	}
	defer rows.Close()

	events := []IdentitySourceEvent{}
	for rows.Next() {
		var item IdentitySourceEvent
		var cacheUsed int
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.SourceName, &item.SourceType, &item.UsernameHash,
			&item.Decision, &item.Reason, &item.LatencyMS, &item.CircuitState, &cacheUsed, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan identity source event: %w", err)
		}
		item.CacheUsed = cacheUsed == 1
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity source events: %w", err)
	}
	return events, nil
}

func GetIdentitySourceEventSummary() (IdentitySourceEventSummary, error) {
	if DB == nil {
		return IdentitySourceEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary IdentitySourceEventSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'rejected' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'not_found' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'failed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'skipped' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'stale_accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'split_denied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN cache_used = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM identity_source_events`).Scan(&summary.TotalRecords, &summary.AcceptedCount, &summary.RejectedCount,
		&summary.NotFoundCount, &summary.FailureCount, &summary.SkippedCount, &summary.StaleAcceptedCount,
		&summary.SplitDeniedCount, &summary.CacheHitCount, &summary.LastObservedAt); err != nil {
		return IdentitySourceEventSummary{}, fmt.Errorf("get identity source event summary: %w", err)
	}
	if summary.LastObservedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(source_name, ''), COALESCE(source_type, ''), COALESCE(decision, ''),
			COALESCE(reason, ''), COALESCE(circuit_state, '')
			FROM identity_source_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastSourceName, &summary.LastSourceType, &summary.LastDecision, &summary.LastReason, &summary.LastCircuitState)
	}
	_ = DB.QueryRow(`SELECT COUNT(*) FROM (
		SELECT source_name FROM identity_source_events WHERE circuit_state = 'open' GROUP BY source_name
	)`).Scan(&summary.OpenCircuitSourceCount)
	return summary, nil
}

func GetIdentitySourceCircuitState(sourceName string, maxFailures, circuitOpenSeconds int, now time.Time) (IdentitySourceCircuitState, error) {
	if DB == nil {
		return IdentitySourceCircuitState{}, fmt.Errorf("database not initialized")
	}
	sourceName = strings.TrimSpace(sourceName)
	state := IdentitySourceCircuitState{SourceName: sourceName, State: "closed"}
	if sourceName == "" {
		return state, nil
	}
	if maxFailures <= 0 {
		maxFailures = 3
	}
	if circuitOpenSeconds <= 0 {
		circuitOpenSeconds = 300
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	rows, err := DB.Query(`SELECT COALESCE(observed_at, ''), COALESCE(decision, ''), COALESCE(reason, '')
		FROM identity_source_events WHERE source_name = ?
		ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`, sourceName, maxFailures)
	if err != nil {
		return state, fmt.Errorf("get identity source circuit events: %w", err)
	}
	defer rows.Close()

	consecutiveFailures := 0
	var oldestFailureAt time.Time
	for rows.Next() {
		var observedAt, decision, reason string
		if err := rows.Scan(&observedAt, &decision, &reason); err != nil {
			return state, fmt.Errorf("scan identity source circuit event: %w", err)
		}
		if state.LastObservedAt == "" {
			state.LastObservedAt = observedAt
			state.LastReason = reason
		}
		if decision != "failed" {
			break
		}
		consecutiveFailures++
		parsed, parseErr := time.Parse(time.RFC3339, observedAt)
		if parseErr == nil {
			oldestFailureAt = parsed
		}
	}
	if err := rows.Err(); err != nil {
		return state, fmt.Errorf("iterate identity source circuit events: %w", err)
	}
	state.FailureCount = consecutiveFailures
	if consecutiveFailures < maxFailures || oldestFailureAt.IsZero() {
		return state, nil
	}
	reopensAt := oldestFailureAt.Add(time.Duration(circuitOpenSeconds) * time.Second)
	if now.Before(reopensAt) {
		state.State = "open"
		state.OpenedAt = oldestFailureAt.Format(time.RFC3339)
		state.ReopensAt = reopensAt.Format(time.RFC3339)
	}
	return state, nil
}

func UpsertIdentitySourceCache(sourceName, username, password, role, identitySource string, groups []string, ttlSeconds int, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	sourceName = strings.TrimSpace(sourceName)
	usernameHash := HashIdentityUsername(username)
	if sourceName == "" || usernameHash == "" {
		return fmt.Errorf("source name and username are required")
	}
	if ttlSeconds <= 0 {
		return fmt.Errorf("ttlSeconds must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("marshal identity source cache groups: %w", err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), identitySourceCacheBcryptCost)
	if err != nil {
		return fmt.Errorf("hash identity source cache credential: %w", err)
	}
	lastSuccessAt := now.UTC().Format(time.RFC3339)
	expiresAt := now.UTC().Add(time.Duration(ttlSeconds) * time.Second).Format(time.RFC3339)

	_, err = DB.Exec(`INSERT INTO identity_source_cache
		(source_name, username_hash, password_hash, role, groups_json, identity_source, last_success_at, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_name, username_hash) DO UPDATE SET
			password_hash = excluded.password_hash,
			role = excluded.role,
			groups_json = excluded.groups_json,
			identity_source = excluded.identity_source,
			last_success_at = excluded.last_success_at,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`,
		sourceName, usernameHash, string(passwordHash), strings.TrimSpace(role), string(groupsJSON),
		strings.TrimSpace(identitySource), lastSuccessAt, expiresAt, lastSuccessAt)
	if err != nil {
		return fmt.Errorf("upsert identity source cache: %w", err)
	}
	return nil
}

func VerifyIdentitySourceCache(sourceName, username, password string, now time.Time) (IdentitySourceCacheEntry, bool, error) {
	if DB == nil {
		return IdentitySourceCacheEntry{}, false, fmt.Errorf("database not initialized")
	}
	sourceName = strings.TrimSpace(sourceName)
	usernameHash := HashIdentityUsername(username)
	if sourceName == "" || usernameHash == "" {
		return IdentitySourceCacheEntry{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var entry IdentitySourceCacheEntry
	var passwordHash, groupsJSON string
	err := DB.QueryRow(`SELECT source_name, username_hash, password_hash, COALESCE(role, ''),
		COALESCE(groups_json, '[]'), COALESCE(identity_source, ''), COALESCE(last_success_at, ''), COALESCE(expires_at, '')
		FROM identity_source_cache WHERE source_name = ? AND username_hash = ? AND datetime(expires_at) > datetime(?)`,
		sourceName, usernameHash, now.UTC().Format(time.RFC3339)).
		Scan(&entry.SourceName, &entry.UsernameHash, &passwordHash, &entry.Role, &groupsJSON,
			&entry.IdentitySource, &entry.LastSuccessAt, &entry.ExpiresAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return IdentitySourceCacheEntry{}, false, nil
		}
		return IdentitySourceCacheEntry{}, false, fmt.Errorf("get identity source cache: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return IdentitySourceCacheEntry{}, false, nil
	}
	if err := json.Unmarshal([]byte(groupsJSON), &entry.Groups); err != nil {
		return IdentitySourceCacheEntry{}, false, fmt.Errorf("parse identity source cache groups: %w", err)
	}
	return entry, true, nil
}

func GetIdentitySourceCacheSummary(now time.Time) (IdentitySourceCacheSummary, error) {
	if DB == nil {
		return IdentitySourceCacheSummary{}, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var summary IdentitySourceCacheSummary
	if err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN datetime(expires_at) <= datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(last_success_at), ''),
		COALESCE(MIN(CASE WHEN datetime(expires_at) > datetime(?) THEN expires_at ELSE NULL END), '')
		FROM identity_source_cache`, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).
		Scan(&summary.TotalEntries, &summary.ExpiredEntries, &summary.LastSuccessAt, &summary.NextExpiresAt); err != nil {
		return IdentitySourceCacheSummary{}, fmt.Errorf("get identity source cache summary: %w", err)
	}
	return summary, nil
}

func HashIdentityUsername(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func trimIdentitySourceEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM identity_source_events
		WHERE id NOT IN (
			SELECT id FROM identity_source_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim identity source events: %w", err)
	}
	return nil
}
