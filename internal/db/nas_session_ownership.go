package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	NASSessionOwnershipStatusActive   = "active"
	NASSessionOwnershipStatusStale    = "stale"
	NASSessionOwnershipStatusReleased = "released"
	NASSessionOwnershipStatusUnknown  = "unknown"
)

type NASSessionOwnershipRecord struct {
	ID                  int            `json:"id"`
	SessionID           string         `json:"session_id"`
	AcctSessionID       string         `json:"acct_session_id,omitempty"`
	UsernameHash        string         `json:"username_hash,omitempty"`
	CallingStationHash  string         `json:"calling_station_hash,omitempty"`
	FramedIPAddress     string         `json:"framed_ip_address,omitempty"`
	NASIdentifier       string         `json:"nas_identifier,omitempty"`
	NASIPAddress        string         `json:"nas_ip_address,omitempty"`
	RadiusClientID      int            `json:"radius_client_id,omitempty"`
	ShortName           string         `json:"shortname,omitempty"`
	NASType             string         `json:"nas_type"`
	Transport           string         `json:"transport"`
	DeliveryMode        string         `json:"delivery_mode"`
	ProxyRoute          string         `json:"proxy_route,omitempty"`
	ProxyRealm          string         `json:"proxy_realm,omitempty"`
	ProxyHomeServer     string         `json:"proxy_home_server,omitempty"`
	OwnerNode           string         `json:"owner_node"`
	OwnerInstance       string         `json:"owner_instance,omitempty"`
	OwnerSource         string         `json:"owner_source"`
	OwnerStatus         string         `json:"owner_status"`
	Capabilities        map[string]any `json:"capabilities"`
	SupportedActions    []string       `json:"supported_actions"`
	SupportedTransports []string       `json:"supported_transports"`
	CapabilityHash      string         `json:"capability_hash"`
	LastSeenAt          string         `json:"last_seen_at"`
	ExpiresAt           string         `json:"expires_at,omitempty"`
	CreatedAt           string         `json:"created_at,omitempty"`
	UpdatedAt           string         `json:"updated_at,omitempty"`
}

type NASSessionOwnershipUpsert struct {
	SessionID           string
	AcctSessionID       string
	Username            string
	CallingStationID    string
	FramedIPAddress     string
	NASIdentifier       string
	NASIPAddress        string
	RadiusClientID      int
	ShortName           string
	NASType             string
	Transport           string
	DeliveryMode        string
	ProxyRoute          string
	ProxyRealm          string
	ProxyHomeServer     string
	OwnerNode           string
	OwnerInstance       string
	OwnerSource         string
	OwnerStatus         string
	Capabilities        map[string]any
	SupportedActions    []string
	SupportedTransports []string
	LastSeenAt          time.Time
	ExpiresAt           time.Time
}

type NASCapabilityClient struct {
	ID              int            `json:"id"`
	ShortName       string         `json:"shortname"`
	IPAddress       string         `json:"ipaddr"`
	NASType         string         `json:"nas_type"`
	Transport       string         `json:"transport"`
	Vendor          string         `json:"vendor,omitempty"`
	Model           string         `json:"model,omitempty"`
	FirmwareVersion string         `json:"firmware_version,omitempty"`
	OwnerTenant     string         `json:"owner_tenant,omitempty"`
	TemplateName    string         `json:"template_name,omitempty"`
	DynamicSource   string         `json:"dynamic_source,omitempty"`
	LifecycleStatus string         `json:"lifecycle_status,omitempty"`
	LastSeenAt      string         `json:"last_seen_at,omitempty"`
	Enabled         bool           `json:"enabled"`
	SecretSet       bool           `json:"secret_set"`
	Capabilities    map[string]any `json:"capabilities"`
	CapabilityHash  string         `json:"capability_hash"`
}

type NASCapabilityOwnershipSummary struct {
	SchemaVersion       int    `json:"schema_version"`
	Status              string `json:"status"`
	Message             string `json:"message"`
	EnabledClients      int    `json:"enabled_clients"`
	CapabilityClients   int    `json:"capability_clients"`
	ActiveSessions      int    `json:"active_sessions"`
	OwnedSessions       int    `json:"owned_sessions"`
	StaleSessions       int    `json:"stale_sessions"`
	UnknownSessions     int    `json:"unknown_sessions"`
	ReleasedSessions    int    `json:"released_sessions"`
	OwnershipCoverage   int    `json:"ownership_coverage_percent"`
	LastOwnershipUpdate string `json:"last_ownership_update,omitempty"`
}

func UpsertNASSessionOwnership(upsert NASSessionOwnershipUpsert) (NASSessionOwnershipRecord, error) {
	if DB == nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("database not initialized")
	}
	upsert = normalizeNASSessionOwnershipUpsert(upsert)
	if upsert.SessionID == "" {
		return NASSessionOwnershipRecord{}, fmt.Errorf("session_id is required")
	}
	capabilitiesJSON, err := jsonObjectString(upsert.Capabilities)
	if err != nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("encode capabilities: %w", err)
	}
	actionsJSON, err := jsonString(normalizeOutboundDACStringList(upsert.SupportedActions, 32))
	if err != nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("encode supported actions: %w", err)
	}
	transportsJSON, err := jsonString(normalizeOutboundDACStringList(upsert.SupportedTransports, 16))
	if err != nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("encode supported transports: %w", err)
	}
	capabilityHash := FingerprintOutboundDAC(capabilitiesJSON, actionsJSON, transportsJSON)
	_, err = DB.Exec(`INSERT INTO nas_session_ownership (
		session_id, acct_session_id, username_hash, calling_station_hash, framed_ip_address,
		nas_identifier, nas_ip_address, radius_client_id, shortname, nas_type, transport,
		delivery_mode, proxy_route, proxy_realm, proxy_home_server, owner_node, owner_instance,
		owner_source, owner_status, capabilities_json, supported_actions_json,
		supported_transports_json, capability_hash, last_seen_at, expires_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(session_id) DO UPDATE SET
		acct_session_id = excluded.acct_session_id,
		username_hash = excluded.username_hash,
		calling_station_hash = excluded.calling_station_hash,
		framed_ip_address = excluded.framed_ip_address,
		nas_identifier = excluded.nas_identifier,
		nas_ip_address = excluded.nas_ip_address,
		radius_client_id = excluded.radius_client_id,
		shortname = excluded.shortname,
		nas_type = excluded.nas_type,
		transport = excluded.transport,
		delivery_mode = excluded.delivery_mode,
		proxy_route = excluded.proxy_route,
		proxy_realm = excluded.proxy_realm,
		proxy_home_server = excluded.proxy_home_server,
		owner_node = excluded.owner_node,
		owner_instance = excluded.owner_instance,
		owner_source = excluded.owner_source,
		owner_status = excluded.owner_status,
		capabilities_json = excluded.capabilities_json,
		supported_actions_json = excluded.supported_actions_json,
		supported_transports_json = excluded.supported_transports_json,
		capability_hash = excluded.capability_hash,
		last_seen_at = excluded.last_seen_at,
		expires_at = excluded.expires_at,
		updated_at = CURRENT_TIMESTAMP`,
		upsert.SessionID, nullString(upsert.AcctSessionID), hashNullable(upsert.Username),
		hashNullable(upsert.CallingStationID), nullString(upsert.FramedIPAddress),
		nullString(upsert.NASIdentifier), nullString(upsert.NASIPAddress), nullIntIfZero(upsert.RadiusClientID),
		nullString(upsert.ShortName), upsert.NASType, upsert.Transport, upsert.DeliveryMode,
		nullString(upsert.ProxyRoute), nullString(upsert.ProxyRealm), nullString(upsert.ProxyHomeServer),
		upsert.OwnerNode, nullString(upsert.OwnerInstance), upsert.OwnerSource, upsert.OwnerStatus,
		capabilitiesJSON, actionsJSON, transportsJSON, capabilityHash, formatOutboundDACTime(upsert.LastSeenAt), nullIfEmptyTime(upsert.ExpiresAt))
	if err != nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("upsert NAS session ownership: %w", err)
	}
	return LookupNASSessionOwnership(upsert.SessionID)
}

func LookupNASSessionOwnership(sessionID string) (NASSessionOwnershipRecord, error) {
	if DB == nil {
		return NASSessionOwnershipRecord{}, fmt.Errorf("database not initialized")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return NASSessionOwnershipRecord{}, fmt.Errorf("session_id is required")
	}
	row := DB.QueryRow(nasSessionOwnershipSelectSQL()+`
		WHERE session_id = ? OR COALESCE(acct_session_id, '') = ?
		ORDER BY CASE owner_status WHEN 'active' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END, datetime(updated_at) DESC
		LIMIT 1`, sessionID, sessionID)
	return scanNASSessionOwnership(row)
}

func ListNASSessionOwnership(limit int) ([]NASSessionOwnershipRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := DB.Query(nasSessionOwnershipSelectSQL()+`
		ORDER BY CASE owner_status WHEN 'active' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END,
		datetime(updated_at) DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list NAS session ownership: %w", err)
	}
	defer rows.Close()
	var out []NASSessionOwnershipRecord
	for rows.Next() {
		record, err := scanNASSessionOwnership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func SyncNASSessionOwnershipFromSessions(ownerNode string, ttl time.Duration, limit int) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	ownerNode = strings.TrimSpace(ownerNode)
	if ownerNode == "" {
		ownerNode = "local"
	}
	if ttl <= 0 {
		ttl = 4 * time.Hour
	}
	if limit <= 0 {
		limit = 1000
	}
	rows, err := DB.Query(`SELECT
		s.id, COALESCE(s.radius_session_id, ''), COALESCE(s.username, ''),
		COALESCE(s.mac, ''), COALESCE(s.ip, ''), COALESCE(s.nas_identifier, ''),
		COALESCE(CAST(s.last_activity AS TEXT), COALESCE(CAST(s.start_time AS TEXT), '')),
		COALESCE(rc.id, 0), COALESCE(rc.shortname, ''), COALESCE(rc.ipaddr, ''),
		COALESCE(rc.nas_type, 'other'), COALESCE(rc.transport, 'udp'),
		COALESCE(rc.capabilities_json, '{}')
		FROM sessions s
		LEFT JOIN radius_clients rc ON rc.enabled = 1 AND (
			LOWER(rc.shortname) = LOWER(COALESCE(s.nas_identifier, '')) OR
			rc.ipaddr = COALESCE(s.nas_identifier, '')
		)
		WHERE s.end_time IS NULL
		ORDER BY datetime(COALESCE(s.last_activity, s.start_time)) DESC, s.id DESC
		LIMIT ?`, limit)
	if err != nil {
		return 0, fmt.Errorf("query active sessions for NAS ownership: %w", err)
	}
	upserts := []NASSessionOwnershipUpsert{}
	now := time.Now().UTC()
	for rows.Next() {
		var upsert NASSessionOwnershipUpsert
		var lastSeenRaw, capabilitiesJSON string
		if err := rows.Scan(&upsert.SessionID, &upsert.AcctSessionID, &upsert.Username,
			&upsert.CallingStationID, &upsert.FramedIPAddress, &upsert.NASIdentifier,
			&lastSeenRaw, &upsert.RadiusClientID, &upsert.ShortName, &upsert.NASIPAddress,
			&upsert.NASType, &upsert.Transport, &capabilitiesJSON); err != nil {
			return 0, fmt.Errorf("scan active session ownership: %w", err)
		}
		upsert.OwnerNode = ownerNode
		upsert.OwnerSource = "sessions"
		upsert.OwnerStatus = NASSessionOwnershipStatusActive
		upsert.DeliveryMode = "direct"
		upsert.LastSeenAt = parseDBTimeOrNow(lastSeenRaw, now)
		upsert.ExpiresAt = now.Add(ttl)
		_ = json.Unmarshal([]byte(capabilitiesJSON), &upsert.Capabilities)
		upsert.SupportedActions, upsert.SupportedTransports = SupportedNASSessionOwnershipFromCapabilities(upsert.Capabilities, upsert.Transport)
		upserts = append(upserts, upsert)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	count := 0
	for _, upsert := range upserts {
		if _, err := UpsertNASSessionOwnership(upsert); err != nil {
			return count, err
		}
		count++
	}
	_, _ = DB.Exec(`UPDATE nas_session_ownership SET owner_status = 'stale', updated_at = CURRENT_TIMESTAMP
		WHERE owner_status = 'active' AND expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')`)
	return count, nil
}

func ListNASCapabilityClients(limit int) ([]NASCapabilityClient, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	rows, err := DB.Query(nasCapabilityClientSelectSQL()+` ORDER BY enabled DESC, shortname LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list NAS capability clients: %w", err)
	}
	defer rows.Close()
	var out []NASCapabilityClient
	for rows.Next() {
		client, err := scanNASCapabilityClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, rows.Err()
}

func LookupNASCapabilityClient(address, nasIdentifier, shortName string) (NASCapabilityClient, error) {
	if DB == nil {
		return NASCapabilityClient{}, fmt.Errorf("database not initialized")
	}
	address = strings.TrimSpace(address)
	nasIdentifier = strings.TrimSpace(nasIdentifier)
	shortName = strings.TrimSpace(shortName)
	row := DB.QueryRow(nasCapabilityClientSelectSQL()+`
		WHERE enabled = 1 AND (
			(? <> '' AND ipaddr = ?) OR
			(? <> '' AND LOWER(shortname) = LOWER(?)) OR
			(? <> '' AND LOWER(shortname) = LOWER(?))
		)
		ORDER BY CASE WHEN ipaddr = ? THEN 0 ELSE 1 END, shortname LIMIT 1`,
		address, address, shortName, shortName, nasIdentifier, nasIdentifier, address)
	return scanNASCapabilityClient(row)
}

func GetNASCapabilityOwnershipSummary() (NASCapabilityOwnershipSummary, error) {
	if DB == nil {
		return NASCapabilityOwnershipSummary{}, fmt.Errorf("database not initialized")
	}
	var summary NASCapabilityOwnershipSummary
	summary.SchemaVersion = 1
	if err := DB.QueryRow(`SELECT
		COALESCE((SELECT COUNT(*) FROM radius_clients WHERE enabled = 1), 0),
		COALESCE((SELECT COUNT(*) FROM radius_clients WHERE enabled = 1 AND COALESCE(capabilities_json, '{}') <> '{}'), 0),
		COALESCE((SELECT COUNT(*) FROM sessions WHERE end_time IS NULL), 0),
		COALESCE((SELECT COUNT(*) FROM nas_session_ownership WHERE owner_status = 'active'), 0),
		COALESCE((SELECT COUNT(*) FROM nas_session_ownership WHERE owner_status = 'stale'), 0),
		COALESCE((SELECT COUNT(*) FROM nas_session_ownership WHERE owner_status = 'unknown'), 0),
		COALESCE((SELECT COUNT(*) FROM nas_session_ownership WHERE owner_status = 'released'), 0),
		COALESCE((SELECT MAX(CAST(updated_at AS TEXT)) FROM nas_session_ownership), '')`).
		Scan(&summary.EnabledClients, &summary.CapabilityClients, &summary.ActiveSessions,
			&summary.OwnedSessions, &summary.StaleSessions, &summary.UnknownSessions,
			&summary.ReleasedSessions, &summary.LastOwnershipUpdate); err != nil {
		return NASCapabilityOwnershipSummary{}, fmt.Errorf("summarize NAS capability ownership: %w", err)
	}
	if summary.ActiveSessions > 0 {
		summary.OwnershipCoverage = (summary.OwnedSessions * 100) / summary.ActiveSessions
	}
	summary.Status = "ready"
	summary.Message = "NAS capability and session ownership registry is ready."
	if summary.EnabledClients == 0 {
		summary.Status = "blocked"
		summary.Message = "No enabled NAS clients are available for capability ownership."
	} else if summary.ActiveSessions > 0 && summary.OwnedSessions == 0 {
		summary.Status = "degraded"
		summary.Message = "Active sessions exist but none have ownership rows yet."
	} else if summary.StaleSessions > 0 || summary.UnknownSessions > 0 {
		summary.Status = "degraded"
		summary.Message = "Some NAS ownership rows need reconciliation."
	}
	return summary, nil
}

func SupportedNASSessionOwnershipFromCapabilities(capabilities map[string]any, transport string) ([]string, []string) {
	actions := []string{"coa", "disconnect"}
	if capabilityBoolDefault(capabilities, "dynamic_authorization.vendor_actions", true) {
		actions = append(actions, "vendor_actions")
	}
	transports := []string{}
	transport = strings.TrimSpace(strings.ToLower(transport))
	if transport == "" || transport == "udp" {
		transports = append(transports, "udp")
	}
	if transport == "radsec" || capabilityBoolDefault(capabilities, "dynamic_authorization.transport.radsec", false) {
		transports = append(transports, "radsec")
	}
	if capabilityBoolDefault(capabilities, "dynamic_authorization.transport.proxy", true) {
		transports = append(transports, "proxy")
	}
	return normalizeOutboundDACStringList(actions, 32), normalizeOutboundDACStringList(transports, 16)
}

func nasSessionOwnershipSelectSQL() string {
	return `SELECT id, session_id, COALESCE(acct_session_id, ''), COALESCE(username_hash, ''),
		COALESCE(calling_station_hash, ''), COALESCE(framed_ip_address, ''),
		COALESCE(nas_identifier, ''), COALESCE(nas_ip_address, ''), COALESCE(radius_client_id, 0),
		COALESCE(shortname, ''), nas_type, transport, delivery_mode, COALESCE(proxy_route, ''),
		COALESCE(proxy_realm, ''), COALESCE(proxy_home_server, ''), owner_node,
		COALESCE(owner_instance, ''), owner_source, owner_status, capabilities_json,
		supported_actions_json, supported_transports_json, capability_hash,
		CAST(last_seen_at AS TEXT), COALESCE(CAST(expires_at AS TEXT), ''),
		CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM nas_session_ownership`
}

func scanNASSessionOwnership(row interface{ Scan(dest ...any) error }) (NASSessionOwnershipRecord, error) {
	var record NASSessionOwnershipRecord
	var capabilitiesJSON, actionsJSON, transportsJSON string
	if err := row.Scan(&record.ID, &record.SessionID, &record.AcctSessionID,
		&record.UsernameHash, &record.CallingStationHash, &record.FramedIPAddress,
		&record.NASIdentifier, &record.NASIPAddress, &record.RadiusClientID,
		&record.ShortName, &record.NASType, &record.Transport, &record.DeliveryMode,
		&record.ProxyRoute, &record.ProxyRealm, &record.ProxyHomeServer,
		&record.OwnerNode, &record.OwnerInstance, &record.OwnerSource,
		&record.OwnerStatus, &capabilitiesJSON, &actionsJSON, &transportsJSON,
		&record.CapabilityHash, &record.LastSeenAt, &record.ExpiresAt,
		&record.CreatedAt, &record.UpdatedAt); err != nil {
		return NASSessionOwnershipRecord{}, err
	}
	record.Capabilities = map[string]any{}
	record.SupportedActions = []string{}
	record.SupportedTransports = []string{}
	_ = json.Unmarshal([]byte(capabilitiesJSON), &record.Capabilities)
	_ = json.Unmarshal([]byte(actionsJSON), &record.SupportedActions)
	_ = json.Unmarshal([]byte(transportsJSON), &record.SupportedTransports)
	return record, nil
}

func nasCapabilityClientSelectSQL() string {
	return `SELECT id, shortname, ipaddr, COALESCE(nas_type, 'other'), COALESCE(transport, 'udp'),
		COALESCE(vendor, ''), COALESCE(model, ''), COALESCE(firmware_version, ''),
		COALESCE(owner_tenant, ''), COALESCE(template_name, ''), COALESCE(dynamic_source, 'static'),
		COALESCE(lifecycle_status, 'approved'), COALESCE(last_seen_at, ''), enabled,
		(secret != '' OR COALESCE(secret_ref, '') != ''), COALESCE(capabilities_json, '{}')
		FROM radius_clients`
}

func scanNASCapabilityClient(row interface{ Scan(dest ...any) error }) (NASCapabilityClient, error) {
	var client NASCapabilityClient
	var capabilitiesJSON string
	if err := row.Scan(&client.ID, &client.ShortName, &client.IPAddress, &client.NASType,
		&client.Transport, &client.Vendor, &client.Model, &client.FirmwareVersion,
		&client.OwnerTenant, &client.TemplateName, &client.DynamicSource,
		&client.LifecycleStatus, &client.LastSeenAt, &client.Enabled,
		&client.SecretSet, &capabilitiesJSON); err != nil {
		return NASCapabilityClient{}, err
	}
	client.Capabilities = map[string]any{}
	_ = json.Unmarshal([]byte(capabilitiesJSON), &client.Capabilities)
	client.CapabilityHash = FingerprintOutboundDAC(capabilitiesJSON)
	return client, nil
}

func normalizeNASSessionOwnershipUpsert(upsert NASSessionOwnershipUpsert) NASSessionOwnershipUpsert {
	upsert.SessionID = strings.TrimSpace(upsert.SessionID)
	upsert.AcctSessionID = strings.TrimSpace(upsert.AcctSessionID)
	upsert.Username = strings.TrimSpace(upsert.Username)
	upsert.CallingStationID = strings.TrimSpace(upsert.CallingStationID)
	upsert.FramedIPAddress = strings.TrimSpace(upsert.FramedIPAddress)
	upsert.NASIdentifier = strings.TrimSpace(upsert.NASIdentifier)
	upsert.NASIPAddress = strings.TrimSpace(upsert.NASIPAddress)
	upsert.ShortName = strings.TrimSpace(upsert.ShortName)
	upsert.NASType = strings.TrimSpace(strings.ToLower(upsert.NASType))
	if upsert.NASType == "" {
		upsert.NASType = "other"
	}
	upsert.Transport = strings.TrimSpace(strings.ToLower(upsert.Transport))
	if upsert.Transport == "" {
		upsert.Transport = "udp"
	}
	upsert.DeliveryMode = strings.TrimSpace(strings.ToLower(upsert.DeliveryMode))
	if upsert.DeliveryMode != "proxy" {
		upsert.DeliveryMode = "direct"
	}
	upsert.ProxyRoute = strings.TrimSpace(upsert.ProxyRoute)
	upsert.ProxyRealm = strings.TrimSpace(strings.ToLower(upsert.ProxyRealm))
	upsert.ProxyHomeServer = strings.TrimSpace(upsert.ProxyHomeServer)
	upsert.OwnerNode = strings.TrimSpace(upsert.OwnerNode)
	if upsert.OwnerNode == "" {
		upsert.OwnerNode = "local"
	}
	upsert.OwnerInstance = strings.TrimSpace(upsert.OwnerInstance)
	upsert.OwnerSource = strings.TrimSpace(upsert.OwnerSource)
	if upsert.OwnerSource == "" {
		upsert.OwnerSource = "session_history"
	}
	upsert.OwnerStatus = normalizeNASSessionOwnershipStatus(upsert.OwnerStatus)
	if upsert.Capabilities == nil {
		upsert.Capabilities = map[string]any{}
	}
	upsert.SupportedActions = normalizeOutboundDACStringList(upsert.SupportedActions, 32)
	upsert.SupportedTransports = normalizeOutboundDACStringList(upsert.SupportedTransports, 16)
	if upsert.LastSeenAt.IsZero() {
		upsert.LastSeenAt = time.Now().UTC()
	}
	upsert.LastSeenAt = upsert.LastSeenAt.UTC()
	if !upsert.ExpiresAt.IsZero() {
		upsert.ExpiresAt = upsert.ExpiresAt.UTC()
	}
	return upsert
}

func normalizeNASSessionOwnershipStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case NASSessionOwnershipStatusActive, NASSessionOwnershipStatusStale, NASSessionOwnershipStatusReleased, NASSessionOwnershipStatusUnknown:
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return NASSessionOwnershipStatusActive
	}
}

func hashNullable(value string) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: "sha256:" + FingerprintOutboundDAC(value), Valid: true}
}

func parseDBTimeOrNow(value string, fallback time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback.UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05-07:00", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return fallback.UTC()
}

func capabilityBoolDefault(capabilities map[string]any, path string, fallback bool) bool {
	value, ok := capabilityPathValue(capabilities, path)
	if !ok {
		return fallback
	}
	boolValue, ok := value.(bool)
	if !ok {
		return fallback
	}
	return boolValue
}

func capabilityPathValue(capabilities map[string]any, path string) (any, bool) {
	if capabilities == nil {
		return nil, false
	}
	var current any = capabilities
	for _, part := range strings.Split(path, ".") {
		node, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := node[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}
