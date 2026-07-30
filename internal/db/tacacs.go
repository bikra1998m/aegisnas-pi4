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

type TACACSCommandSetRecord struct {
	ID              int      `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Enabled         bool     `json:"enabled"`
	DefaultAction   string   `json:"default_action"`
	Permit          []string `json:"permit"`
	Deny            []string `json:"deny"`
	Roles           []string `json:"roles,omitempty"`
	PrivilegeLevels []int    `json:"privilege_levels,omitempty"`
	Vendors         []string `json:"vendors,omitempty"`
	Tenants         []string `json:"tenants,omitempty"`
	Source          string   `json:"source"`
	ContentHash     string   `json:"content_hash"`
	CreatedBy       string   `json:"created_by,omitempty"`
	UpdatedBy       string   `json:"updated_by,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

type TACACSAuthorizationEvent struct {
	ID                 int      `json:"id,omitempty"`
	EventID            string   `json:"event_id"`
	SessionID          uint32   `json:"session_id"`
	UsernameHash       string   `json:"username_hash,omitempty"`
	Role               string   `json:"role,omitempty"`
	Tenant             string   `json:"tenant,omitempty"`
	ClientName         string   `json:"client_name,omitempty"`
	ClientIP           string   `json:"client_ip,omitempty"`
	Vendor             string   `json:"vendor,omitempty"`
	Service            string   `json:"service,omitempty"`
	Port               string   `json:"port,omitempty"`
	RemoteAddress      string   `json:"remote_address,omitempty"`
	Command            string   `json:"command"`
	CommandHash        string   `json:"command_hash"`
	PrivilegeLevel     int      `json:"privilege_level"`
	Decision           string   `json:"decision"`
	Reason             string   `json:"reason,omitempty"`
	MatchedCommandSet  string   `json:"matched_command_set,omitempty"`
	PolicyEvaluationID string   `json:"policy_evaluation_id,omitempty"`
	Args               []string `json:"args,omitempty"`
	RequestJSON        string   `json:"request_json,omitempty"`
	ResponseJSON       string   `json:"response_json,omitempty"`
	LatencyMS          int64    `json:"latency_ms"`
	CreatedAt          string   `json:"created_at,omitempty"`
}

type TACACSAccountingRecord struct {
	ID             int      `json:"id,omitempty"`
	RecordID       string   `json:"record_id"`
	SessionID      uint32   `json:"session_id"`
	TaskID         string   `json:"task_id,omitempty"`
	UsernameHash   string   `json:"username_hash,omitempty"`
	Role           string   `json:"role,omitempty"`
	Tenant         string   `json:"tenant,omitempty"`
	ClientName     string   `json:"client_name,omitempty"`
	ClientIP       string   `json:"client_ip,omitempty"`
	Vendor         string   `json:"vendor,omitempty"`
	Service        string   `json:"service,omitempty"`
	Port           string   `json:"port,omitempty"`
	RemoteAddress  string   `json:"remote_address,omitempty"`
	Command        string   `json:"command,omitempty"`
	CommandHash    string   `json:"command_hash,omitempty"`
	PrivilegeLevel int      `json:"privilege_level"`
	Flags          int      `json:"flags"`
	Status         string   `json:"status"`
	Args           []string `json:"args,omitempty"`
	RequestJSON    string   `json:"request_json,omitempty"`
	CreatedAt      string   `json:"created_at,omitempty"`
}

type TACACSProtocolEvent struct {
	ID          int    `json:"id,omitempty"`
	EventID     string `json:"event_id"`
	SessionID   uint32 `json:"session_id"`
	ClientName  string `json:"client_name,omitempty"`
	ClientIP    string `json:"client_ip,omitempty"`
	EventType   string `json:"event_type"`
	Status      string `json:"status"`
	Summary     string `json:"summary,omitempty"`
	DetailsJSON string `json:"details_json,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type TACACSSummary struct {
	CommandSetCount        int    `json:"command_set_count"`
	EnabledCommandSets     int    `json:"enabled_command_sets"`
	AuthorizationEvents    int    `json:"authorization_events"`
	PermitCount            int    `json:"permit_count"`
	DenyCount              int    `json:"deny_count"`
	ErrorCount             int    `json:"error_count"`
	AccountingRecords      int    `json:"accounting_records"`
	ProtocolEvents         int    `json:"protocol_events"`
	LastAuthorizationAt    string `json:"last_authorization_at,omitempty"`
	LastAuthorizationID    string `json:"last_authorization_id,omitempty"`
	LastAuthorizationState string `json:"last_authorization_state,omitempty"`
	LastAccountingAt       string `json:"last_accounting_at,omitempty"`
	LastAccountingID       string `json:"last_accounting_id,omitempty"`
}

func UpsertTACACSCommandSet(record TACACSCommandSetRecord) (TACACSCommandSetRecord, error) {
	if DB == nil {
		return TACACSCommandSetRecord{}, fmt.Errorf("database is not initialized")
	}
	normalized, err := normalizeTACACSCommandSetRecord(record)
	if err != nil {
		return TACACSCommandSetRecord{}, err
	}
	permitJSON, _ := json.Marshal(normalized.Permit)
	denyJSON, _ := json.Marshal(normalized.Deny)
	rolesJSON, _ := json.Marshal(normalized.Roles)
	levelsJSON, _ := json.Marshal(normalized.PrivilegeLevels)
	vendorsJSON, _ := json.Marshal(normalized.Vendors)
	tenantsJSON, _ := json.Marshal(normalized.Tenants)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = DB.Exec(`INSERT INTO tacacs_command_sets (
		name, description, enabled, default_action, permit_json, deny_json, roles_json,
		privilege_levels_json, vendors_json, tenants_json, source, content_hash,
		created_by, updated_by, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(name) DO UPDATE SET
		description = excluded.description,
		enabled = excluded.enabled,
		default_action = excluded.default_action,
		permit_json = excluded.permit_json,
		deny_json = excluded.deny_json,
		roles_json = excluded.roles_json,
		privilege_levels_json = excluded.privilege_levels_json,
		vendors_json = excluded.vendors_json,
		tenants_json = excluded.tenants_json,
		source = excluded.source,
		content_hash = excluded.content_hash,
		updated_by = excluded.updated_by,
		updated_at = excluded.updated_at`,
		normalized.Name, nullIfEmpty(normalized.Description), normalized.Enabled, normalized.DefaultAction,
		string(permitJSON), string(denyJSON), string(rolesJSON), string(levelsJSON), string(vendorsJSON),
		string(tenantsJSON), normalized.Source, normalized.ContentHash, nullIfEmpty(normalized.CreatedBy),
		nullIfEmpty(normalized.UpdatedBy), now, now)
	if err != nil {
		return TACACSCommandSetRecord{}, err
	}
	return GetTACACSCommandSet(normalized.Name)
}

func NormalizeTACACSCommandSetRecord(record TACACSCommandSetRecord) (TACACSCommandSetRecord, error) {
	return normalizeTACACSCommandSetRecord(record)
}

func GetTACACSCommandSet(name string) (TACACSCommandSetRecord, error) {
	if DB == nil {
		return TACACSCommandSetRecord{}, fmt.Errorf("database is not initialized")
	}
	row := DB.QueryRow(`SELECT id, name, COALESCE(description, ''), enabled, default_action, permit_json,
		deny_json, roles_json, privilege_levels_json, vendors_json, tenants_json, source,
		content_hash, COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tacacs_command_sets WHERE name = ?`, strings.TrimSpace(name))
	record, err := scanTACACSCommandSet(row)
	if err != nil {
		return TACACSCommandSetRecord{}, err
	}
	return record, nil
}

func ListTACACSCommandSets(enabledOnly bool) ([]TACACSCommandSetRecord, error) {
	if DB == nil {
		return nil, nil
	}
	query := `SELECT id, name, COALESCE(description, ''), enabled, default_action, permit_json,
		deny_json, roles_json, privilege_levels_json, vendors_json, tenants_json, source,
		content_hash, COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tacacs_command_sets`
	if enabledOnly {
		query += ` WHERE enabled = 1`
	}
	query += ` ORDER BY enabled DESC, name`
	rows, err := DB.Query(query)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TACACSCommandSetRecord
	for rows.Next() {
		record, err := scanTACACSCommandSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func RecordTACACSAuthorizationEvent(record TACACSAuthorizationEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeTACACSAuthorizationEvent(record)
	argsJSON, _ := json.Marshal(normalized.Args)
	_, err := DB.Exec(`INSERT INTO tacacs_authorization_events (
		event_id, session_id, username_hash, role, tenant, client_name, client_ip, vendor, service,
		port, remote_address, command, command_hash, privilege_level, decision, reason,
		matched_command_set, policy_evaluation_id, args_json, request_json, response_json, latency_ms
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO UPDATE SET
		decision = excluded.decision,
		reason = excluded.reason,
		response_json = excluded.response_json,
		latency_ms = excluded.latency_ms`,
		normalized.EventID, normalized.SessionID, nullIfEmpty(normalized.UsernameHash), nullIfEmpty(normalized.Role),
		nullIfEmpty(normalized.Tenant), nullIfEmpty(normalized.ClientName), nullIfEmpty(normalized.ClientIP),
		nullIfEmpty(normalized.Vendor), nullIfEmpty(normalized.Service), nullIfEmpty(normalized.Port),
		nullIfEmpty(normalized.RemoteAddress), normalized.Command, normalized.CommandHash, normalized.PrivilegeLevel,
		normalized.Decision, nullIfEmpty(normalized.Reason), nullIfEmpty(normalized.MatchedCommandSet),
		nullIfEmpty(normalized.PolicyEvaluationID), string(argsJSON), defaultJSONObject(normalized.RequestJSON),
		defaultJSONObject(normalized.ResponseJSON), normalized.LatencyMS)
	if err != nil {
		return err
	}
	return pruneTACACSAuthorizations(retentionLimit)
}

func RecordTACACSAccountingRecord(record TACACSAccountingRecord, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeTACACSAccountingRecord(record)
	argsJSON, _ := json.Marshal(normalized.Args)
	_, err := DB.Exec(`INSERT INTO tacacs_accounting_records (
		record_id, session_id, task_id, username_hash, role, tenant, client_name, client_ip, vendor,
		service, port, remote_address, command, command_hash, privilege_level, flags, status,
		args_json, request_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(record_id) DO UPDATE SET
		status = 'duplicate'`,
		normalized.RecordID, normalized.SessionID, nullIfEmpty(normalized.TaskID), nullIfEmpty(normalized.UsernameHash),
		nullIfEmpty(normalized.Role), nullIfEmpty(normalized.Tenant), nullIfEmpty(normalized.ClientName),
		nullIfEmpty(normalized.ClientIP), nullIfEmpty(normalized.Vendor), nullIfEmpty(normalized.Service),
		nullIfEmpty(normalized.Port), nullIfEmpty(normalized.RemoteAddress), nullIfEmpty(normalized.Command),
		nullIfEmpty(normalized.CommandHash), normalized.PrivilegeLevel, normalized.Flags, normalized.Status,
		string(argsJSON), defaultJSONObject(normalized.RequestJSON))
	if err != nil {
		return err
	}
	return pruneTACACSAccounting(retentionLimit)
}

func RecordTACACSProtocolEvent(record TACACSProtocolEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeTACACSProtocolEvent(record)
	_, err := DB.Exec(`INSERT INTO tacacs_protocol_events (
		event_id, session_id, client_name, client_ip, event_type, status, summary, details_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO UPDATE SET
		status = excluded.status,
		summary = excluded.summary,
		details_json = excluded.details_json`,
		normalized.EventID, normalized.SessionID, nullIfEmpty(normalized.ClientName), nullIfEmpty(normalized.ClientIP),
		normalized.EventType, normalized.Status, nullIfEmpty(normalized.Summary), defaultJSONObject(normalized.DetailsJSON))
	if err != nil {
		return err
	}
	return pruneTACACSProtocolEvents(retentionLimit)
}

func SummarizeTACACS(retentionLimit int) (TACACSSummary, error) {
	var summary TACACSSummary
	if DB == nil {
		return summary, nil
	}
	if err := DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN enabled THEN 1 ELSE 0 END), 0) FROM tacacs_command_sets`).Scan(&summary.CommandSetCount, &summary.EnabledCommandSets); err != nil && !tableMissing(err) {
		return summary, err
	}
	limit := retentionLimit
	if limit <= 0 || limit > 1000000 {
		limit = 10000
	}
	rows, err := DB.Query(`SELECT event_id, decision, created_at FROM tacacs_authorization_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if !tableMissing(err) {
			return summary, err
		}
	} else {
		for rows.Next() {
			var eventID, decision, createdAt string
			if err := rows.Scan(&eventID, &decision, &createdAt); err != nil {
				rows.Close()
				return summary, err
			}
			summary.AuthorizationEvents++
			if summary.LastAuthorizationAt == "" {
				summary.LastAuthorizationAt = createdAt
				summary.LastAuthorizationID = eventID
				summary.LastAuthorizationState = decision
			}
			switch decision {
			case "permit":
				summary.PermitCount++
			case "deny":
				summary.DenyCount++
			case "error":
				summary.ErrorCount++
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return summary, err
		}
		rows.Close()
	}
	if err := DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(created_at), '') FROM tacacs_accounting_records`).Scan(&summary.AccountingRecords, &summary.LastAccountingAt); err != nil && !tableMissing(err) {
		return summary, err
	}
	if summary.LastAccountingAt != "" {
		_ = DB.QueryRow(`SELECT record_id FROM tacacs_accounting_records ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&summary.LastAccountingID)
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM tacacs_protocol_events`).Scan(&summary.ProtocolEvents); err != nil && !tableMissing(err) {
		return summary, err
	}
	return summary, nil
}

func ListTACACSAuthorizationEvents(limit int) ([]TACACSAuthorizationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, session_id, COALESCE(username_hash, ''), COALESCE(role, ''),
		COALESCE(tenant, ''), COALESCE(client_name, ''), COALESCE(client_ip, ''), COALESCE(vendor, ''),
		COALESCE(service, ''), COALESCE(port, ''), COALESCE(remote_address, ''), command, command_hash,
		privilege_level, decision, COALESCE(reason, ''), COALESCE(matched_command_set, ''),
		COALESCE(policy_evaluation_id, ''), args_json, request_json, response_json, latency_ms, created_at
		FROM tacacs_authorization_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TACACSAuthorizationEvent
	for rows.Next() {
		record, err := scanTACACSAuthorizationEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func ListTACACSAccountingRecords(limit int) ([]TACACSAccountingRecord, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, record_id, session_id, COALESCE(task_id, ''), COALESCE(username_hash, ''),
		COALESCE(role, ''), COALESCE(tenant, ''), COALESCE(client_name, ''), COALESCE(client_ip, ''),
		COALESCE(vendor, ''), COALESCE(service, ''), COALESCE(port, ''), COALESCE(remote_address, ''),
		COALESCE(command, ''), COALESCE(command_hash, ''), privilege_level, flags, status, args_json,
		request_json, created_at
		FROM tacacs_accounting_records ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TACACSAccountingRecord
	for rows.Next() {
		var record TACACSAccountingRecord
		var argsJSON string
		if err := rows.Scan(&record.ID, &record.RecordID, &record.SessionID, &record.TaskID, &record.UsernameHash,
			&record.Role, &record.Tenant, &record.ClientName, &record.ClientIP, &record.Vendor, &record.Service,
			&record.Port, &record.RemoteAddress, &record.Command, &record.CommandHash, &record.PrivilegeLevel,
			&record.Flags, &record.Status, &argsJSON, &record.RequestJSON, &record.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(argsJSON), &record.Args)
		out = append(out, record)
	}
	return out, rows.Err()
}

func normalizeTACACSCommandSetRecord(record TACACSCommandSetRecord) (TACACSCommandSetRecord, error) {
	record.Name = strings.TrimSpace(record.Name)
	if record.Name == "" {
		return record, fmt.Errorf("command set name is required")
	}
	record.Description = strings.TrimSpace(record.Description)
	record.DefaultAction = strings.ToLower(strings.TrimSpace(record.DefaultAction))
	if record.DefaultAction == "" {
		record.DefaultAction = "deny"
	}
	if record.DefaultAction != "permit" && record.DefaultAction != "deny" {
		return record, fmt.Errorf("default_action %q is invalid", record.DefaultAction)
	}
	record.Permit = normalizeTACACSStringList(record.Permit, false)
	record.Deny = normalizeTACACSStringList(record.Deny, false)
	if record.Enabled && len(record.Permit)+len(record.Deny) == 0 && record.DefaultAction == "deny" {
		return record, fmt.Errorf("at least one permit pattern is required when default_action is deny")
	}
	record.Roles = normalizeTACACSStringList(record.Roles, true)
	record.Vendors = normalizeTACACSStringList(record.Vendors, true)
	record.Tenants = normalizeTACACSStringList(record.Tenants, true)
	levels := make([]int, 0, len(record.PrivilegeLevels))
	seenLevels := map[int]bool{}
	for _, level := range record.PrivilegeLevels {
		if level < 0 || level > 15 {
			return record, fmt.Errorf("privilege level %d is out of range", level)
		}
		if !seenLevels[level] {
			levels = append(levels, level)
			seenLevels[level] = true
		}
	}
	record.PrivilegeLevels = levels
	record.Source = strings.ToLower(strings.TrimSpace(record.Source))
	if record.Source == "" {
		record.Source = "api"
	}
	switch record.Source {
	case "api", "config", "migration":
	default:
		return record, fmt.Errorf("source %q is invalid", record.Source)
	}
	record.ContentHash = tacacsContentHash(record)
	return record, nil
}

func normalizeTACACSAuthorizationEvent(record TACACSAuthorizationEvent) TACACSAuthorizationEvent {
	record.EventID = strings.TrimSpace(record.EventID)
	if record.EventID == "" {
		record.EventID = tacacsHashParts("tacacs-authz", fmt.Sprint(record.SessionID), record.Command, time.Now().UTC().Format(time.RFC3339Nano))
	}
	record.UsernameHash = HashEAPIdentity(record.UsernameHash)
	record.Role = strings.TrimSpace(record.Role)
	record.Tenant = strings.TrimSpace(record.Tenant)
	record.ClientName = strings.TrimSpace(record.ClientName)
	record.ClientIP = strings.TrimSpace(record.ClientIP)
	record.Vendor = strings.ToLower(strings.TrimSpace(record.Vendor))
	record.Service = strings.ToLower(strings.TrimSpace(record.Service))
	record.Port = strings.TrimSpace(record.Port)
	record.RemoteAddress = strings.TrimSpace(record.RemoteAddress)
	record.Command = strings.TrimSpace(record.Command)
	if record.Command == "" {
		record.Command = "unknown"
	}
	record.CommandHash = HashCommand(record.Command)
	if record.PrivilegeLevel < 0 {
		record.PrivilegeLevel = 0
	}
	if record.PrivilegeLevel > 15 {
		record.PrivilegeLevel = 15
	}
	record.Decision = strings.ToLower(strings.TrimSpace(record.Decision))
	if record.Decision != "permit" && record.Decision != "deny" && record.Decision != "error" {
		record.Decision = "error"
	}
	record.Args = normalizeTACACSStringList(record.Args, false)
	return record
}

func normalizeTACACSAccountingRecord(record TACACSAccountingRecord) TACACSAccountingRecord {
	record.RecordID = strings.TrimSpace(record.RecordID)
	if record.RecordID == "" {
		record.RecordID = tacacsHashParts("tacacs-acct", fmt.Sprint(record.SessionID), record.TaskID, strings.Join(record.Args, "\x00"))
	}
	record.UsernameHash = HashEAPIdentity(record.UsernameHash)
	record.Role = strings.TrimSpace(record.Role)
	record.Tenant = strings.TrimSpace(record.Tenant)
	record.ClientName = strings.TrimSpace(record.ClientName)
	record.ClientIP = strings.TrimSpace(record.ClientIP)
	record.Vendor = strings.ToLower(strings.TrimSpace(record.Vendor))
	record.Service = strings.ToLower(strings.TrimSpace(record.Service))
	record.Port = strings.TrimSpace(record.Port)
	record.RemoteAddress = strings.TrimSpace(record.RemoteAddress)
	record.Command = strings.TrimSpace(record.Command)
	if record.Command != "" {
		record.CommandHash = HashCommand(record.Command)
	}
	if record.PrivilegeLevel < 0 {
		record.PrivilegeLevel = 0
	}
	if record.PrivilegeLevel > 15 {
		record.PrivilegeLevel = 15
	}
	record.Status = strings.ToLower(strings.TrimSpace(record.Status))
	if record.Status == "" {
		record.Status = "recorded"
	}
	if record.Status != "recorded" && record.Status != "duplicate" && record.Status != "error" {
		record.Status = "error"
	}
	record.Args = normalizeTACACSStringList(record.Args, false)
	return record
}

func normalizeTACACSProtocolEvent(record TACACSProtocolEvent) TACACSProtocolEvent {
	record.EventID = strings.TrimSpace(record.EventID)
	if record.EventID == "" {
		record.EventID = tacacsHashParts("tacacs-event", fmt.Sprint(record.SessionID), record.EventType, time.Now().UTC().Format(time.RFC3339Nano))
	}
	record.ClientName = strings.TrimSpace(record.ClientName)
	record.ClientIP = strings.TrimSpace(record.ClientIP)
	record.EventType = strings.ToLower(strings.TrimSpace(record.EventType))
	switch record.EventType {
	case "connection", "authentication", "authorization", "accounting", "protocol_error":
	default:
		record.EventType = "protocol_error"
	}
	record.Status = strings.ToLower(strings.TrimSpace(record.Status))
	switch record.Status {
	case "ok", "denied", "failed", "error":
	default:
		record.Status = "error"
	}
	record.Summary = strings.TrimSpace(record.Summary)
	record.DetailsJSON = defaultJSONObject(record.DetailsJSON)
	return record
}

func scanTACACSCommandSet(rows interface {
	Scan(dest ...any) error
}) (TACACSCommandSetRecord, error) {
	var record TACACSCommandSetRecord
	var permitJSON, denyJSON, rolesJSON, levelsJSON, vendorsJSON, tenantsJSON string
	if err := rows.Scan(&record.ID, &record.Name, &record.Description, &record.Enabled, &record.DefaultAction,
		&permitJSON, &denyJSON, &rolesJSON, &levelsJSON, &vendorsJSON, &tenantsJSON, &record.Source,
		&record.ContentHash, &record.CreatedBy, &record.UpdatedBy, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return record, err
	}
	_ = json.Unmarshal([]byte(permitJSON), &record.Permit)
	_ = json.Unmarshal([]byte(denyJSON), &record.Deny)
	_ = json.Unmarshal([]byte(rolesJSON), &record.Roles)
	_ = json.Unmarshal([]byte(levelsJSON), &record.PrivilegeLevels)
	_ = json.Unmarshal([]byte(vendorsJSON), &record.Vendors)
	_ = json.Unmarshal([]byte(tenantsJSON), &record.Tenants)
	return record, nil
}

func scanTACACSAuthorizationEvent(rows interface {
	Scan(dest ...any) error
}) (TACACSAuthorizationEvent, error) {
	var record TACACSAuthorizationEvent
	var argsJSON string
	if err := rows.Scan(&record.ID, &record.EventID, &record.SessionID, &record.UsernameHash, &record.Role,
		&record.Tenant, &record.ClientName, &record.ClientIP, &record.Vendor, &record.Service, &record.Port,
		&record.RemoteAddress, &record.Command, &record.CommandHash, &record.PrivilegeLevel, &record.Decision,
		&record.Reason, &record.MatchedCommandSet, &record.PolicyEvaluationID, &argsJSON, &record.RequestJSON,
		&record.ResponseJSON, &record.LatencyMS, &record.CreatedAt); err != nil {
		return record, err
	}
	_ = json.Unmarshal([]byte(argsJSON), &record.Args)
	return record, nil
}

func pruneTACACSAuthorizations(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM tacacs_authorization_events
		WHERE id NOT IN (
			SELECT id FROM tacacs_authorization_events ORDER BY created_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	return err
}

func pruneTACACSAccounting(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM tacacs_accounting_records
		WHERE id NOT IN (
			SELECT id FROM tacacs_accounting_records ORDER BY created_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	return err
}

func pruneTACACSProtocolEvents(retentionLimit int) error {
	if DB == nil || retentionLimit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM tacacs_protocol_events
		WHERE id NOT IN (
			SELECT id FROM tacacs_protocol_events ORDER BY created_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	return err
}

func normalizeTACACSStringList(values []string, lower bool) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func tacacsContentHash(record TACACSCommandSetRecord) string {
	payload := map[string]any{
		"name":             record.Name,
		"description":      record.Description,
		"enabled":          record.Enabled,
		"default_action":   record.DefaultAction,
		"permit":           record.Permit,
		"deny":             record.Deny,
		"roles":            record.Roles,
		"privilege_levels": record.PrivilegeLevels,
		"vendors":          record.Vendors,
		"tenants":          record.Tenants,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func tacacsHashParts(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HashCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	return tacacsHashParts("command", command)
}

func LocalUserRole(username string) (string, string, bool, error) {
	if DB == nil {
		return "", "", false, fmt.Errorf("database is not initialized")
	}
	var role, tenant sql.NullString
	err := DB.QueryRow(`SELECT COALESCE(role, ''), COALESCE(tenant, '') FROM local_users WHERE username = ?`, strings.TrimSpace(username)).Scan(&role, &tenant)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	return role.String, tenant.String, true, nil
}
