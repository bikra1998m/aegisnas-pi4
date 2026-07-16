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

const maxMABRecords = 6000

type MABEndpoint struct {
	ID                  int    `json:"id"`
	MAC                 string `json:"mac"`
	Status              string `json:"status"`
	Role                string `json:"role,omitempty"`
	VLAN                int    `json:"vlan,omitempty"`
	BandwidthProfile    string `json:"bandwidth_profile,omitempty"`
	ACLPolicyName       string `json:"acl_policy_name,omitempty"`
	Tenant              string `json:"tenant,omitempty"`
	DeviceGroup         string `json:"device_group,omitempty"`
	Posture             string `json:"posture,omitempty"`
	Owner               string `json:"owner,omitempty"`
	Source              string `json:"source"`
	Description         string `json:"description,omitempty"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	ProfileSnapshotJSON string `json:"profile_snapshot_json,omitempty"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type MABEvent struct {
	ID               int    `json:"id"`
	ObservedAt       string `json:"observed_at"`
	MAC              string `json:"mac"`
	MACHash          string `json:"mac_hash"`
	NASIdentifier    string `json:"nas_identifier,omitempty"`
	NASIPAddress     string `json:"nas_ip_address,omitempty"`
	NASPort          string `json:"nas_port,omitempty"`
	NASPortType      string `json:"nas_port_type,omitempty"`
	CalledStationID  string `json:"called_station_id,omitempty"`
	Username         string `json:"username,omitempty"`
	Decision         string `json:"decision"`
	State            string `json:"state"`
	Reason           string `json:"reason"`
	Role             string `json:"role,omitempty"`
	VLAN             int    `json:"vlan,omitempty"`
	BandwidthProfile string `json:"bandwidth_profile,omitempty"`
	ACLPolicyName    string `json:"acl_policy_name,omitempty"`
	Tenant           string `json:"tenant,omitempty"`
	DeviceGroup      string `json:"device_group,omitempty"`
	Posture          string `json:"posture,omitempty"`
	LatencyMS        int64  `json:"latency_ms"`
	DetailsJSON      string `json:"details_json,omitempty"`
	CreatedAt        string `json:"created_at"`
}

type MABEventSummary struct {
	TotalRecords        int    `json:"total_records"`
	AcceptedCount       int    `json:"accepted_count"`
	RejectedCount       int    `json:"rejected_count"`
	QuarantinedCount    int    `json:"quarantined_count"`
	MonitorAllowedCount int    `json:"monitor_allowed_count"`
	FailOpenCount       int    `json:"fail_open_count"`
	UnsupportedCount    int    `json:"unsupported_count"`
	LastObservedAt      string `json:"last_observed_at,omitempty"`
	LastDecision        string `json:"last_decision,omitempty"`
	LastState           string `json:"last_state,omitempty"`
	LastReason          string `json:"last_reason,omitempty"`
}

type MABEndpointSummary struct {
	TotalEndpoints      int    `json:"total_endpoints"`
	ApprovedCount       int    `json:"approved_count"`
	PendingCount        int    `json:"pending_count"`
	QuarantinedCount    int    `json:"quarantined_count"`
	DeniedCount         int    `json:"denied_count"`
	ExpiredCount        int    `json:"expired_count"`
	LastUpdatedAt       string `json:"last_updated_at,omitempty"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	ProfileLinkedCount  int    `json:"profile_linked_count"`
	RoleAssignedCount   int    `json:"role_assigned_count"`
	VLANAssignedCount   int    `json:"vlan_assigned_count"`
	ACLAssignedCount    int    `json:"acl_assigned_count"`
	TenantAssignedCount int    `json:"tenant_assigned_count"`
}

type MABDeviceProfile struct {
	MAC              string   `json:"mac"`
	Tenant           string   `json:"tenant,omitempty"`
	Username         string   `json:"username,omitempty"`
	Platform         string   `json:"platform,omitempty"`
	DeviceType       string   `json:"device_type,omitempty"`
	Hostname         string   `json:"hostname,omitempty"`
	DHCPClientID     string   `json:"dhcp_client_id,omitempty"`
	DHCPFingerprint  string   `json:"dhcp_fingerprint,omitempty"`
	MACOUI           string   `json:"mac_oui,omitempty"`
	RiskScore        int      `json:"risk_score"`
	RiskReasons      []string `json:"risk_reasons,omitempty"`
	Managed          bool     `json:"managed"`
	Compliant        *bool    `json:"compliant,omitempty"`
	ComplianceStatus string   `json:"compliance_status,omitempty"`
	RemediationState string   `json:"remediation_state,omitempty"`
	LastIP           string   `json:"last_ip,omitempty"`
	LastSessionID    string   `json:"last_session_id,omitempty"`
	LastSeen         string   `json:"last_seen,omitempty"`
}

func NormalizeMABMAC(value string) string {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return ""
	}
	var hexChars strings.Builder
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9':
			hexChars.WriteRune(r)
		case r >= 'a' && r <= 'f':
			hexChars.WriteRune(r)
		case r == ':' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	digits := hexChars.String()
	if len(digits) != 12 {
		return ""
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, digits[i:i+2])
	}
	return strings.Join(parts, ":")
}

func HashMABMAC(mac string) string {
	normalized := NormalizeMABMAC(mac)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func UpsertMABEndpoint(endpoint MABEndpoint, now time.Time) (MABEndpoint, error) {
	if DB == nil {
		return MABEndpoint{}, fmt.Errorf("database not initialized")
	}
	mac := NormalizeMABMAC(endpoint.MAC)
	if mac == "" {
		return MABEndpoint{}, fmt.Errorf("valid endpoint MAC is required")
	}
	status := normalizeMABEndpointStatus(endpoint.Status)
	if status == "" {
		return MABEndpoint{}, fmt.Errorf("MAB endpoint status %q is invalid", endpoint.Status)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	profileSnapshot := strings.TrimSpace(endpoint.ProfileSnapshotJSON)
	if profileSnapshot == "" {
		profileSnapshot = "{}"
	}
	if !json.Valid([]byte(profileSnapshot)) {
		return MABEndpoint{}, fmt.Errorf("profile_snapshot_json must be valid JSON")
	}
	_, err := DB.Exec(`INSERT INTO mab_endpoints
		(mac, status, role, vlan, bandwidth_profile, acl_policy_name, tenant, device_group, posture, owner, source, description,
		 expires_at, last_seen_at, profile_snapshot_json, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			status = excluded.status,
			role = excluded.role,
			vlan = excluded.vlan,
			bandwidth_profile = excluded.bandwidth_profile,
			acl_policy_name = excluded.acl_policy_name,
			tenant = excluded.tenant,
			device_group = excluded.device_group,
			posture = excluded.posture,
			owner = excluded.owner,
			source = excluded.source,
			description = excluded.description,
			expires_at = excluded.expires_at,
			last_seen_at = COALESCE(excluded.last_seen_at, mab_endpoints.last_seen_at),
			profile_snapshot_json = excluded.profile_snapshot_json,
			updated_at = excluded.updated_at`,
		mac, status, nullMABString(endpoint.Role), endpoint.VLAN, nullMABString(endpoint.BandwidthProfile),
		nullMABString(endpoint.ACLPolicyName), nullMABString(endpoint.Tenant), nullMABString(endpoint.DeviceGroup),
		nullMABString(endpoint.Posture), nullMABString(endpoint.Owner), firstMABString(endpoint.Source, "manual"),
		nullMABString(endpoint.Description), nullMABString(endpoint.ExpiresAt), nullMABString(endpoint.LastSeenAt),
		profileSnapshot, updatedAt)
	if err != nil {
		return MABEndpoint{}, fmt.Errorf("upsert MAB endpoint: %w", err)
	}
	stored, found, err := GetMABEndpoint(mac)
	if err != nil {
		return MABEndpoint{}, err
	}
	if !found {
		return MABEndpoint{}, fmt.Errorf("MAB endpoint %s was not stored", mac)
	}
	return stored, nil
}

func GetMABEndpoint(mac string) (MABEndpoint, bool, error) {
	if DB == nil {
		return MABEndpoint{}, false, fmt.Errorf("database not initialized")
	}
	normalized := NormalizeMABMAC(mac)
	if normalized == "" {
		return MABEndpoint{}, false, nil
	}
	item, err := scanMABEndpoint(DB.QueryRow(`SELECT id, mac, status, COALESCE(role, ''), COALESCE(vlan, 0),
		COALESCE(bandwidth_profile, ''), COALESCE(acl_policy_name, ''), COALESCE(tenant, ''),
		COALESCE(device_group, ''), COALESCE(posture, ''), COALESCE(owner, ''), COALESCE(source, ''),
		COALESCE(description, ''), COALESCE(expires_at, ''), COALESCE(last_seen_at, ''),
		COALESCE(profile_snapshot_json, '{}'), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM mab_endpoints WHERE mac = ?`, normalized))
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return MABEndpoint{}, false, nil
		}
		return MABEndpoint{}, false, fmt.Errorf("get MAB endpoint: %w", err)
	}
	return item, true, nil
}

func ListMABEndpoints(status string, limit int) ([]MABEndpoint, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 50000 {
		limit = 50000
	}
	query := `SELECT id, mac, status, COALESCE(role, ''), COALESCE(vlan, 0),
		COALESCE(bandwidth_profile, ''), COALESCE(acl_policy_name, ''), COALESCE(tenant, ''),
		COALESCE(device_group, ''), COALESCE(posture, ''), COALESCE(owner, ''), COALESCE(source, ''),
		COALESCE(description, ''), COALESCE(expires_at, ''), COALESCE(last_seen_at, ''),
		COALESCE(profile_snapshot_json, '{}'), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM mab_endpoints WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(status) != "" {
		normalizedStatus := normalizeMABEndpointStatus(status)
		if normalizedStatus == "" {
			return nil, fmt.Errorf("MAB endpoint status %q is invalid", status)
		}
		query += ` AND status = ?`
		args = append(args, normalizedStatus)
	}
	query += ` ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list MAB endpoints: %w", err)
	}
	defer rows.Close()
	items := []MABEndpoint{}
	for rows.Next() {
		item, err := scanMABEndpoint(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func DeleteMABEndpoint(mac string) (bool, error) {
	if DB == nil {
		return false, fmt.Errorf("database not initialized")
	}
	normalized := NormalizeMABMAC(mac)
	if normalized == "" {
		return false, fmt.Errorf("valid endpoint MAC is required")
	}
	result, err := DB.Exec(`DELETE FROM mab_endpoints WHERE mac = ?`, normalized)
	if err != nil {
		return false, fmt.Errorf("delete MAB endpoint: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

func TouchMABEndpoint(mac string, seenAt time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	normalized := NormalizeMABMAC(mac)
	if normalized == "" {
		return nil
	}
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	_, err := DB.Exec(`UPDATE mab_endpoints SET last_seen_at = ?, updated_at = ? WHERE mac = ?`,
		seenAt.UTC().Format(time.RFC3339), seenAt.UTC().Format(time.RFC3339), normalized)
	if err != nil {
		return fmt.Errorf("touch MAB endpoint: %w", err)
	}
	return nil
}

func GetMABEndpointSummary() (MABEndpointSummary, error) {
	if DB == nil {
		return MABEndpointSummary{}, fmt.Errorf("database not initialized")
	}
	var summary MABEndpointSummary
	err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'quarantined' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'denied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(updated_at), ''),
		COALESCE(MAX(last_seen_at), ''),
		COALESCE(SUM(CASE WHEN profile_snapshot_json <> '{}' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(role, '') <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(vlan, 0) > 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(acl_policy_name, '') <> '' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(tenant, '') <> '' THEN 1 ELSE 0 END), 0)
		FROM mab_endpoints`).Scan(&summary.TotalEndpoints, &summary.ApprovedCount, &summary.PendingCount,
		&summary.QuarantinedCount, &summary.DeniedCount, &summary.ExpiredCount, &summary.LastUpdatedAt,
		&summary.LastSeenAt, &summary.ProfileLinkedCount, &summary.RoleAssignedCount, &summary.VLANAssignedCount,
		&summary.ACLAssignedCount, &summary.TenantAssignedCount)
	if err != nil {
		return MABEndpointSummary{}, fmt.Errorf("get MAB endpoint summary: %w", err)
	}
	return summary, nil
}

func RecordMABEvent(record MABEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxMABRecords
	}
	normalizedMAC := NormalizeMABMAC(record.MAC)
	if normalizedMAC == "" {
		return fmt.Errorf("valid event MAC is required")
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal MAB event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	observedAt := strings.TrimSpace(record.ObservedAt)
	if observedAt == "" {
		observedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := DB.Exec(`INSERT INTO mab_events
		(observed_at, mac, mac_hash, nas_identifier, nas_ip_address, nas_port, nas_port_type, called_station_id,
		 username, decision, state, reason, role, vlan, bandwidth_profile, acl_policy_name, tenant, device_group,
		 posture, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observedAt, normalizedMAC, HashMABMAC(normalizedMAC), nullMABString(record.NASIdentifier),
		nullMABString(record.NASIPAddress), nullMABString(record.NASPort), nullMABString(record.NASPortType),
		nullMABString(record.CalledStationID), nullMABString(record.Username), firstMABString(record.Decision, "rejected"),
		firstMABString(record.State, "unknown"), firstMABString(record.Reason, "no reason recorded"),
		nullMABString(record.Role), record.VLAN, nullMABString(record.BandwidthProfile), nullMABString(record.ACLPolicyName),
		nullMABString(record.Tenant), nullMABString(record.DeviceGroup), nullMABString(record.Posture),
		record.LatencyMS, detailsJSON)
	if err != nil {
		return fmt.Errorf("insert MAB event: %w", err)
	}
	return trimMABEvents(retentionLimit)
}

func ListMABEvents(decision, mac string, limit int) ([]MABEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	query := mabEventSelectSQL() + ` WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(decision) != "" {
		query += ` AND decision = ?`
		args = append(args, strings.TrimSpace(decision))
	}
	if normalizedMAC := NormalizeMABMAC(mac); normalizedMAC != "" {
		query += ` AND mac = ?`
		args = append(args, normalizedMAC)
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list MAB events: %w", err)
	}
	defer rows.Close()
	events := []MABEvent{}
	for rows.Next() {
		event, err := scanMABEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetMABEventSummary() (MABEventSummary, error) {
	if DB == nil {
		return MABEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary MABEventSummary
	err := DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'rejected' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'quarantined' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'monitor_allowed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'fail_open' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'unsupported' THEN 1 ELSE 0 END), 0)
		FROM mab_events`).Scan(&summary.TotalRecords, &summary.AcceptedCount, &summary.RejectedCount,
		&summary.QuarantinedCount, &summary.MonitorAllowedCount, &summary.FailOpenCount, &summary.UnsupportedCount)
	if err != nil {
		return MABEventSummary{}, fmt.Errorf("get MAB event summary: %w", err)
	}
	_ = DB.QueryRow(`SELECT COALESCE(observed_at, ''), COALESCE(decision, ''), COALESCE(state, ''), COALESCE(reason, '')
		FROM mab_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
		Scan(&summary.LastObservedAt, &summary.LastDecision, &summary.LastState, &summary.LastReason)
	return summary, nil
}

func GetMABDeviceProfile(mac string) (MABDeviceProfile, bool, error) {
	if DB == nil {
		return MABDeviceProfile{}, false, fmt.Errorf("database not initialized")
	}
	normalizedMAC := NormalizeMABMAC(mac)
	if normalizedMAC == "" {
		return MABDeviceProfile{}, false, nil
	}
	var profile MABDeviceProfile
	var riskReasonsJSON string
	var managed, compliant sql.NullInt64
	err := DB.QueryRow(`SELECT mac, COALESCE(tenant, ''), COALESCE(username, ''), COALESCE(platform, ''),
		COALESCE(device_type, ''), COALESCE(hostname, ''), COALESCE(dhcp_client_id, ''),
		COALESCE(dhcp_fingerprint, ''), COALESCE(mac_oui, ''), COALESCE(risk_score, 0),
		COALESCE(risk_reasons_json, '[]'), managed, compliant, COALESCE(compliance_status, ''),
		COALESCE(remediation_state, ''), COALESCE(last_ip, ''), COALESCE(last_session_id, ''),
		COALESCE(last_seen, '')
		FROM device_inventory WHERE mac = ?`, normalizedMAC).
		Scan(&profile.MAC, &profile.Tenant, &profile.Username, &profile.Platform, &profile.DeviceType,
			&profile.Hostname, &profile.DHCPClientID, &profile.DHCPFingerprint, &profile.MACOUI,
			&profile.RiskScore, &riskReasonsJSON, &managed, &compliant, &profile.ComplianceStatus,
			&profile.RemediationState, &profile.LastIP, &profile.LastSessionID, &profile.LastSeen)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return MABDeviceProfile{}, false, nil
		}
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return MABDeviceProfile{}, false, nil
		}
		return MABDeviceProfile{}, false, fmt.Errorf("get MAB device profile: %w", err)
	}
	profile.Managed = managed.Valid && managed.Int64 != 0
	if compliant.Valid {
		value := compliant.Int64 != 0
		profile.Compliant = &value
	}
	_ = json.Unmarshal([]byte(riskReasonsJSON), &profile.RiskReasons)
	return profile, true, nil
}

func mabEventSelectSQL() string {
	return `SELECT id, COALESCE(observed_at, ''), COALESCE(mac, ''), COALESCE(mac_hash, ''),
		COALESCE(nas_identifier, ''), COALESCE(nas_ip_address, ''), COALESCE(nas_port, ''),
		COALESCE(nas_port_type, ''), COALESCE(called_station_id, ''), COALESCE(username, ''),
		COALESCE(decision, ''), COALESCE(state, ''), COALESCE(reason, ''), COALESCE(role, ''),
		COALESCE(vlan, 0), COALESCE(bandwidth_profile, ''), COALESCE(acl_policy_name, ''),
		COALESCE(tenant, ''), COALESCE(device_group, ''), COALESCE(posture, ''),
		COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM mab_events`
}

type mabScanner interface {
	Scan(dest ...any) error
}

func scanMABEndpoint(scanner mabScanner) (MABEndpoint, error) {
	var item MABEndpoint
	if err := scanner.Scan(&item.ID, &item.MAC, &item.Status, &item.Role, &item.VLAN,
		&item.BandwidthProfile, &item.ACLPolicyName, &item.Tenant, &item.DeviceGroup, &item.Posture,
		&item.Owner, &item.Source, &item.Description, &item.ExpiresAt, &item.LastSeenAt,
		&item.ProfileSnapshotJSON, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return MABEndpoint{}, fmt.Errorf("scan MAB endpoint: %w", err)
	}
	return item, nil
}

func scanMABEvent(scanner mabScanner) (MABEvent, error) {
	var item MABEvent
	if err := scanner.Scan(&item.ID, &item.ObservedAt, &item.MAC, &item.MACHash, &item.NASIdentifier,
		&item.NASIPAddress, &item.NASPort, &item.NASPortType, &item.CalledStationID, &item.Username,
		&item.Decision, &item.State, &item.Reason, &item.Role, &item.VLAN, &item.BandwidthProfile,
		&item.ACLPolicyName, &item.Tenant, &item.DeviceGroup, &item.Posture, &item.LatencyMS,
		&item.DetailsJSON, &item.CreatedAt); err != nil {
		return MABEvent{}, fmt.Errorf("scan MAB event: %w", err)
	}
	return item, nil
}

func trimMABEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM mab_events
		WHERE id NOT IN (
			SELECT id FROM mab_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim MAB events: %w", err)
	}
	return nil
}

func normalizeMABEndpointStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "pending":
		return "pending"
	case "approved", "quarantined", "denied", "expired":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func nullMABString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func firstMABString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
