package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	SubscriberServiceChainStatusPreviewed  = "previewed"
	SubscriberServiceChainStatusActive     = "active"
	SubscriberServiceChainStatusPartial    = "partial"
	SubscriberServiceChainStatusFailed     = "failed"
	SubscriberServiceChainStatusRolledBack = "rolled_back"
)

type SubscriberServiceChainRecord struct {
	ID                 int    `json:"id"`
	ChainID            string `json:"chain_id"`
	SessionID          string `json:"session_id"`
	UsernameHash       string `json:"username_hash,omitempty"`
	CallingStationHash string `json:"calling_station_hash,omitempty"`
	Tenant             string `json:"tenant,omitempty"`
	Status             string `json:"status"`
	PolicySetHash      string `json:"policy_set_hash"`
	RequestHash        string `json:"request_hash"`
	ServiceChainHash   string `json:"service_chain_hash"`
	ServiceCount       int    `json:"service_count"`
	RequiredCount      int    `json:"required_count"`
	OptionalCount      int    `json:"optional_count"`
	ActivatedCount     int    `json:"activated_count"`
	FailedCount        int    `json:"failed_count"`
	RolledBackCount    int    `json:"rolled_back_count"`
	ActivationMode     string `json:"activation_mode"`
	DecisionJSON       string `json:"decision_json"`
	ServicesJSON       string `json:"services_json"`
	FailureReason      string `json:"failure_reason,omitempty"`
	Actor              string `json:"actor,omitempty"`
	StartedAt          string `json:"started_at"`
	UpdatedAt          string `json:"updated_at"`
	CompletedAt        string `json:"completed_at,omitempty"`
	RolledBackAt       string `json:"rolled_back_at,omitempty"`
	CreatedAt          string `json:"created_at"`
}

type SubscriberServiceEventRecord struct {
	ID              int    `json:"id"`
	ChainID         string `json:"chain_id"`
	SessionID       string `json:"session_id"`
	ServiceKey      string `json:"service_key,omitempty"`
	ServiceSequence int    `json:"service_sequence,omitempty"`
	ServiceType     string `json:"service_type,omitempty"`
	VendorPack      string `json:"vendor_pack,omitempty"`
	EventType       string `json:"event_type"`
	Status          string `json:"status"`
	Actor           string `json:"actor,omitempty"`
	DetailsJSON     string `json:"details_json"`
	ObservedAt      string `json:"observed_at"`
	CreatedAt       string `json:"created_at"`
}

type SubscriberServiceAccountingRecord struct {
	ID              int    `json:"id"`
	ChainID         string `json:"chain_id"`
	SessionID       string `json:"session_id"`
	ServiceKey      string `json:"service_key"`
	AccountingClass string `json:"accounting_class,omitempty"`
	Status          string `json:"status"`
	StartedAt       string `json:"started_at"`
	LastInterimAt   string `json:"last_interim_at,omitempty"`
	StoppedAt       string `json:"stopped_at,omitempty"`
	InputOctets     int64  `json:"input_octets"`
	OutputOctets    int64  `json:"output_octets"`
	InterimCount    int    `json:"interim_count"`
	DetailsJSON     string `json:"details_json"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type SubscriberServiceChainSummary struct {
	TotalChains          int    `json:"total_chains"`
	ActiveChains         int    `json:"active_chains"`
	PartialChains        int    `json:"partial_chains"`
	FailedChains         int    `json:"failed_chains"`
	RolledBackChains     int    `json:"rolled_back_chains"`
	TotalServices        int    `json:"total_services"`
	ActivatedServices    int    `json:"activated_services"`
	FailedServices       int    `json:"failed_services"`
	RolledBackServices   int    `json:"rolled_back_services"`
	TotalEvents          int    `json:"total_events"`
	FailedEvents         int    `json:"failed_events"`
	StartedAccounting    int    `json:"started_accounting"`
	LastChainID          string `json:"last_chain_id,omitempty"`
	LastStatus           string `json:"last_status,omitempty"`
	LastUpdatedAt        string `json:"last_updated_at,omitempty"`
	LastServiceChainHash string `json:"last_service_chain_hash,omitempty"`
}

type SubscriberServiceActivationRequest struct {
	SessionID        string
	Username         string
	CallingStationID string
	Tenant           string
	PolicySetHash    string
	RequestHash      string
	ServiceChainHash string
	ServiceCount     int
	RequiredCount    int
	OptionalCount    int
	DecisionJSON     string
	ServicesJSON     string
	Actor            string
	ActivationMode   string
	FailureReason    string
	StartedAt        time.Time
}

type storedSubscriberServiceIntent struct {
	Key             string `json:"key"`
	Type            string `json:"type,omitempty"`
	VendorPack      string `json:"vendor_pack,omitempty"`
	Sequence        int    `json:"sequence"`
	Optional        bool   `json:"optional,omitempty"`
	AccountingClass string `json:"accounting_class,omitempty"`
}

func ActivateSubscriberServiceChain(req SubscriberServiceActivationRequest) (SubscriberServiceChainRecord, error) {
	if DB == nil {
		return SubscriberServiceChainRecord{}, fmt.Errorf("database is not initialized")
	}
	req = normalizeSubscriberServiceActivationRequest(req)
	if err := validateSubscriberServiceActivationRequest(req); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	services, err := decodeStoredSubscriberServices(req.ServicesJSON)
	if err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	now := time.Now().UTC()
	if req.StartedAt.IsZero() {
		req.StartedAt = now
	}
	chainID := SubscriberServiceChainID(req.SessionID, req.PolicySetHash, req.RequestHash, req.ServiceChainHash)
	status := SubscriberServiceChainStatusActive
	activated := req.ServiceCount
	failed := 0
	completedAt := req.StartedAt.UTC().Format(time.RFC3339Nano)
	if strings.TrimSpace(req.FailureReason) != "" {
		status = SubscriberServiceChainStatusFailed
		activated = 0
		failed = req.ServiceCount
		completedAt = ""
	}
	tx, err := DB.Begin()
	if err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO subscriber_service_chains (
		chain_id, session_id, username_hash, calling_station_hash, tenant, status, policy_set_hash, request_hash,
		service_chain_hash, service_count, required_count, optional_count, activated_count, failed_count,
		rolled_back_count, activation_mode, decision_json, services_json, failure_reason, actor,
		started_at, updated_at, completed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(chain_id) DO UPDATE SET
		session_id = excluded.session_id,
		username_hash = excluded.username_hash,
		calling_station_hash = excluded.calling_station_hash,
		tenant = excluded.tenant,
		status = excluded.status,
		policy_set_hash = excluded.policy_set_hash,
		request_hash = excluded.request_hash,
		service_chain_hash = excluded.service_chain_hash,
		service_count = excluded.service_count,
		required_count = excluded.required_count,
		optional_count = excluded.optional_count,
		activated_count = excluded.activated_count,
		failed_count = excluded.failed_count,
		rolled_back_count = excluded.rolled_back_count,
		activation_mode = excluded.activation_mode,
		decision_json = excluded.decision_json,
		services_json = excluded.services_json,
		failure_reason = excluded.failure_reason,
		actor = excluded.actor,
		started_at = excluded.started_at,
		updated_at = excluded.updated_at,
		completed_at = excluded.completed_at,
		rolled_back_at = NULL`,
		chainID, req.SessionID, nullIfEmpty(HashEAPIdentity(req.Username)), nullIfEmpty(HashEAPIdentity(req.CallingStationID)),
		nullIfEmpty(req.Tenant), status, req.PolicySetHash, req.RequestHash, req.ServiceChainHash,
		req.ServiceCount, req.RequiredCount, req.OptionalCount, activated, failed, 0, req.ActivationMode,
		defaultJSONObject(req.DecisionJSON), defaultJSONObjectArray(req.ServicesJSON), nullIfEmpty(req.FailureReason),
		nullIfEmpty(req.Actor), req.StartedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		nullIfEmpty(completedAt)); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	if _, err := tx.Exec(`DELETE FROM subscriber_service_events WHERE chain_id = ?`, chainID); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	if _, err := tx.Exec(`DELETE FROM subscriber_service_accounting WHERE chain_id = ?`, chainID); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	eventStatus := "success"
	eventType := "activate"
	if failed > 0 {
		eventStatus = "failed"
		eventType = "failure"
	}
	for _, service := range services {
		details, _ := json.Marshal(map[string]any{"service": service, "service_chain_hash": req.ServiceChainHash})
		if err := insertSubscriberServiceEventTx(tx, chainID, req.SessionID, service, eventType, eventStatus, req.Actor, string(details), now); err != nil {
			return SubscriberServiceChainRecord{}, err
		}
		if eventStatus == "success" {
			if _, err := tx.Exec(`INSERT INTO subscriber_service_accounting (
				chain_id, session_id, service_key, accounting_class, status, started_at, details_json, updated_at
			) VALUES (?, ?, ?, ?, 'started', ?, ?, ?)`,
				chainID, req.SessionID, service.Key, nullIfEmpty(service.AccountingClass), req.StartedAt.UTC().Format(time.RFC3339Nano),
				string(details), now.Format(time.RFC3339Nano)); err != nil {
				return SubscriberServiceChainRecord{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	return GetSubscriberServiceChain(chainID)
}

func RollbackSubscriberServiceChain(chainID, actor, reason string) (SubscriberServiceChainRecord, error) {
	if DB == nil {
		return SubscriberServiceChainRecord{}, fmt.Errorf("database is not initialized")
	}
	chainID = strings.TrimSpace(chainID)
	if chainID == "" {
		return SubscriberServiceChainRecord{}, fmt.Errorf("chain_id is required")
	}
	record, err := GetSubscriberServiceChain(chainID)
	if err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	if record.ChainID == "" {
		return SubscriberServiceChainRecord{}, fmt.Errorf("subscriber service chain %q not found", chainID)
	}
	if record.Status == SubscriberServiceChainStatusRolledBack {
		return record, nil
	}
	services, err := decodeStoredSubscriberServices(record.ServicesJSON)
	if err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	now := time.Now().UTC()
	tx, err := DB.Begin()
	if err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE subscriber_service_chains
		SET status = ?, rolled_back_count = ?, actor = ?, failure_reason = ?, updated_at = ?, rolled_back_at = ?
		WHERE chain_id = ?`,
		SubscriberServiceChainStatusRolledBack, len(services), nullIfEmpty(actor), nullIfEmpty(reason),
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), chainID); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	if _, err := tx.Exec(`UPDATE subscriber_service_accounting
		SET status = 'stopped', stopped_at = ?, updated_at = ?
		WHERE chain_id = ? AND stopped_at IS NULL`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), chainID); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	for _, service := range services {
		details, _ := json.Marshal(map[string]any{"reason": strings.TrimSpace(reason), "service": service})
		if err := insertSubscriberServiceEventTx(tx, chainID, record.SessionID, service, "rollback", "success", actor, string(details), now); err != nil {
			return SubscriberServiceChainRecord{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SubscriberServiceChainRecord{}, err
	}
	return GetSubscriberServiceChain(chainID)
}

func GetSubscriberServiceChain(chainID string) (SubscriberServiceChainRecord, error) {
	if DB == nil {
		return SubscriberServiceChainRecord{}, nil
	}
	var record SubscriberServiceChainRecord
	err := DB.QueryRow(`SELECT id, chain_id, session_id, COALESCE(username_hash, ''), COALESCE(calling_station_hash, ''),
		COALESCE(tenant, ''), status, policy_set_hash, request_hash, service_chain_hash, service_count,
		required_count, optional_count, activated_count, failed_count, rolled_back_count, activation_mode,
		decision_json, services_json, COALESCE(failure_reason, ''), COALESCE(actor, ''), started_at, updated_at,
		COALESCE(completed_at, ''), COALESCE(rolled_back_at, ''), created_at
		FROM subscriber_service_chains WHERE chain_id = ?`, strings.TrimSpace(chainID)).Scan(
		&record.ID, &record.ChainID, &record.SessionID, &record.UsernameHash, &record.CallingStationHash,
		&record.Tenant, &record.Status, &record.PolicySetHash, &record.RequestHash, &record.ServiceChainHash,
		&record.ServiceCount, &record.RequiredCount, &record.OptionalCount, &record.ActivatedCount,
		&record.FailedCount, &record.RolledBackCount, &record.ActivationMode, &record.DecisionJSON,
		&record.ServicesJSON, &record.FailureReason, &record.Actor, &record.StartedAt, &record.UpdatedAt,
		&record.CompletedAt, &record.RolledBackAt, &record.CreatedAt)
	if err == sql.ErrNoRows {
		return SubscriberServiceChainRecord{}, nil
	}
	if err != nil && tableMissing(err) {
		return SubscriberServiceChainRecord{}, nil
	}
	return record, err
}

func ListSubscriberServiceChains(limit int) ([]SubscriberServiceChainRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, chain_id, session_id, COALESCE(username_hash, ''), COALESCE(calling_station_hash, ''),
		COALESCE(tenant, ''), status, policy_set_hash, request_hash, service_chain_hash, service_count,
		required_count, optional_count, activated_count, failed_count, rolled_back_count, activation_mode,
		decision_json, services_json, COALESCE(failure_reason, ''), COALESCE(actor, ''), started_at, updated_at,
		COALESCE(completed_at, ''), COALESCE(rolled_back_at, ''), created_at
		FROM subscriber_service_chains ORDER BY updated_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []SubscriberServiceChainRecord
	for rows.Next() {
		var record SubscriberServiceChainRecord
		if err := rows.Scan(&record.ID, &record.ChainID, &record.SessionID, &record.UsernameHash, &record.CallingStationHash,
			&record.Tenant, &record.Status, &record.PolicySetHash, &record.RequestHash, &record.ServiceChainHash,
			&record.ServiceCount, &record.RequiredCount, &record.OptionalCount, &record.ActivatedCount,
			&record.FailedCount, &record.RolledBackCount, &record.ActivationMode, &record.DecisionJSON,
			&record.ServicesJSON, &record.FailureReason, &record.Actor, &record.StartedAt, &record.UpdatedAt,
			&record.CompletedAt, &record.RolledBackAt, &record.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func ListSubscriberServiceEvents(chainID string, limit int) ([]SubscriberServiceEventRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT id, chain_id, session_id, COALESCE(service_key, ''), COALESCE(service_sequence, 0),
		COALESCE(service_type, ''), COALESCE(vendor_pack, ''), event_type, status, COALESCE(actor, ''),
		details_json, observed_at, created_at FROM subscriber_service_events`
	args := []any{}
	if strings.TrimSpace(chainID) != "" {
		query += ` WHERE chain_id = ?`
		args = append(args, strings.TrimSpace(chainID))
	}
	query += ` ORDER BY observed_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []SubscriberServiceEventRecord
	for rows.Next() {
		var record SubscriberServiceEventRecord
		if err := rows.Scan(&record.ID, &record.ChainID, &record.SessionID, &record.ServiceKey,
			&record.ServiceSequence, &record.ServiceType, &record.VendorPack, &record.EventType,
			&record.Status, &record.Actor, &record.DetailsJSON, &record.ObservedAt, &record.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func SummarizeSubscriberServiceChains() (SubscriberServiceChainSummary, error) {
	var summary SubscriberServiceChainSummary
	if DB == nil {
		return summary, nil
	}
	rows, err := DB.Query(`SELECT chain_id, status, service_chain_hash, service_count, activated_count,
		failed_count, rolled_back_count, updated_at
		FROM subscriber_service_chains ORDER BY updated_at DESC, id DESC`)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var chainID, status, chainHash, updatedAt string
		var services, activated, failed, rolledBack int
		if err := rows.Scan(&chainID, &status, &chainHash, &services, &activated, &failed, &rolledBack, &updatedAt); err != nil {
			return summary, err
		}
		summary.TotalChains++
		summary.TotalServices += services
		summary.ActivatedServices += activated
		summary.FailedServices += failed
		summary.RolledBackServices += rolledBack
		if summary.LastChainID == "" {
			summary.LastChainID = chainID
			summary.LastStatus = status
			summary.LastUpdatedAt = updatedAt
			summary.LastServiceChainHash = chainHash
		}
		switch status {
		case SubscriberServiceChainStatusActive:
			summary.ActiveChains++
		case SubscriberServiceChainStatusPartial:
			summary.PartialChains++
		case SubscriberServiceChainStatusFailed:
			summary.FailedChains++
		case SubscriberServiceChainStatusRolledBack:
			summary.RolledBackChains++
		}
	}
	if err := rows.Err(); err != nil {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM subscriber_service_events`).Scan(&summary.TotalEvents); err != nil && !tableMissing(err) {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM subscriber_service_events WHERE status = 'failed'`).Scan(&summary.FailedEvents); err != nil && !tableMissing(err) {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM subscriber_service_accounting WHERE status IN ('started', 'interim')`).Scan(&summary.StartedAccounting); err != nil && !tableMissing(err) {
		return summary, err
	}
	return summary, nil
}

func SubscriberServiceChainID(sessionID, policySetHash, requestHash, serviceChainHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(sessionID),
		strings.TrimSpace(policySetHash),
		strings.TrimSpace(requestHash),
		strings.TrimSpace(serviceChainHash),
	}, "|")))
	return "ssc-" + hex.EncodeToString(sum[:])[:24]
}

func normalizeSubscriberServiceActivationRequest(req SubscriberServiceActivationRequest) SubscriberServiceActivationRequest {
	req.SessionID = strings.TrimSpace(req.SessionID)
	req.Username = strings.TrimSpace(req.Username)
	req.CallingStationID = strings.TrimSpace(req.CallingStationID)
	req.Tenant = strings.TrimSpace(req.Tenant)
	req.PolicySetHash = strings.TrimSpace(req.PolicySetHash)
	req.RequestHash = strings.TrimSpace(req.RequestHash)
	req.ServiceChainHash = strings.TrimSpace(req.ServiceChainHash)
	req.Actor = strings.TrimSpace(req.Actor)
	req.ActivationMode = strings.ToLower(strings.TrimSpace(req.ActivationMode))
	if req.ActivationMode == "" {
		req.ActivationMode = "policy"
	}
	req.DecisionJSON = defaultJSONObject(req.DecisionJSON)
	req.ServicesJSON = defaultJSONObjectArray(req.ServicesJSON)
	return req
}

func validateSubscriberServiceActivationRequest(req SubscriberServiceActivationRequest) error {
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if req.PolicySetHash == "" || len(req.PolicySetHash) != 64 {
		return fmt.Errorf("policy_set_hash must be a 64-character SHA-256 hex value")
	}
	if req.RequestHash == "" || len(req.RequestHash) != 64 {
		return fmt.Errorf("request_hash must be a 64-character SHA-256 hex value")
	}
	if req.ServiceChainHash == "" || len(req.ServiceChainHash) != 64 {
		return fmt.Errorf("service_chain_hash must be a 64-character SHA-256 hex value")
	}
	if req.ServiceCount <= 0 {
		return fmt.Errorf("service_count must be positive")
	}
	if req.RequiredCount < 0 || req.OptionalCount < 0 || req.RequiredCount+req.OptionalCount != req.ServiceCount {
		return fmt.Errorf("required_count and optional_count must add up to service_count")
	}
	return nil
}

func decodeStoredSubscriberServices(raw string) ([]storedSubscriberServiceIntent, error) {
	raw = defaultJSONObjectArray(raw)
	var services []storedSubscriberServiceIntent
	if err := json.Unmarshal([]byte(raw), &services); err != nil {
		return nil, fmt.Errorf("decode services_json: %w", err)
	}
	for i := range services {
		services[i].Key = strings.TrimSpace(services[i].Key)
		services[i].Type = strings.TrimSpace(services[i].Type)
		services[i].VendorPack = strings.TrimSpace(services[i].VendorPack)
		services[i].AccountingClass = strings.TrimSpace(services[i].AccountingClass)
		if services[i].Key == "" {
			return nil, fmt.Errorf("services_json[%d].key is required", i)
		}
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("services_json must contain at least one service")
	}
	return services, nil
}

func insertSubscriberServiceEventTx(tx *sql.Tx, chainID, sessionID string, service storedSubscriberServiceIntent, eventType, status, actor, detailsJSON string, observedAt time.Time) error {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	_, err := tx.Exec(`INSERT INTO subscriber_service_events (
		chain_id, session_id, service_key, service_sequence, service_type, vendor_pack,
		event_type, status, actor, details_json, observed_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(chainID), strings.TrimSpace(sessionID), nullIfEmpty(service.Key), service.Sequence,
		nullIfEmpty(service.Type), nullIfEmpty(service.VendorPack), strings.TrimSpace(eventType),
		strings.TrimSpace(status), nullIfEmpty(actor), defaultJSONObject(detailsJSON), observedAt.UTC().Format(time.RFC3339Nano))
	return err
}
