package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	NASClientEnrollmentSchemaVersion = 1

	NASClientStatusPending  = "pending"
	NASClientStatusApproved = "approved"
	NASClientStatusRejected = "rejected"
	NASClientStatusRevoked  = "revoked"
	NASClientStatusExpired  = "expired"
)

type NASClientEnrollmentRequest struct {
	EnrollmentID            string         `json:"enrollment_id,omitempty"`
	SourceIP                string         `json:"source_ip"`
	ShortName               string         `json:"shortname"`
	NASType                 string         `json:"nas_type"`
	Transport               string         `json:"transport"`
	SecretRef               string         `json:"secret_ref,omitempty"`
	RadSecCertificateCN     string         `json:"radsec_certificate_cn,omitempty"`
	RadSecCertificateIssuer string         `json:"radsec_certificate_issuer,omitempty"`
	RadSecRadiusV11         string         `json:"radsec_radius_v11,omitempty"`
	Vendor                  string         `json:"vendor,omitempty"`
	Model                   string         `json:"model,omitempty"`
	FirmwareVersion         string         `json:"firmware_version,omitempty"`
	SerialNumber            string         `json:"serial_number,omitempty"`
	Capabilities            map[string]any `json:"capabilities,omitempty"`
	OwnerTenant             string         `json:"owner_tenant,omitempty"`
	TemplateName            string         `json:"template_name,omitempty"`
	DiscoverySource         string         `json:"discovery_source,omitempty"`
	LastSeenReason          string         `json:"last_seen_reason,omitempty"`
	ExpiresAt               time.Time      `json:"-"`
	Actor                   string         `json:"-"`
}

type NASClientApprovalRequest struct {
	ShortName               string         `json:"shortname,omitempty"`
	SourceIP                string         `json:"source_ip,omitempty"`
	NASType                 string         `json:"nas_type,omitempty"`
	Transport               string         `json:"transport,omitempty"`
	Secret                  string         `json:"secret,omitempty"`
	SecretRef               string         `json:"secret_ref,omitempty"`
	RadSecCertificateCN     string         `json:"radsec_certificate_cn,omitempty"`
	RadSecCertificateIssuer string         `json:"radsec_certificate_issuer,omitempty"`
	RadSecRadiusV11         string         `json:"radsec_radius_v11,omitempty"`
	Vendor                  string         `json:"vendor,omitempty"`
	Model                   string         `json:"model,omitempty"`
	FirmwareVersion         string         `json:"firmware_version,omitempty"`
	SerialNumber            string         `json:"serial_number,omitempty"`
	Capabilities            map[string]any `json:"capabilities,omitempty"`
	OwnerTenant             string         `json:"owner_tenant,omitempty"`
	TemplateName            string         `json:"template_name,omitempty"`
	ApprovedBy              string         `json:"-"`
}

type NASClientEnrollment struct {
	ID                      int            `json:"id"`
	EnrollmentID            string         `json:"enrollment_id"`
	SourceIP                string         `json:"source_ip"`
	ShortName               string         `json:"shortname"`
	NASType                 string         `json:"nas_type"`
	Transport               string         `json:"transport"`
	SecretRef               string         `json:"secret_ref,omitempty"`
	RadSecCertificateCN     string         `json:"radsec_certificate_cn,omitempty"`
	RadSecCertificateIssuer string         `json:"radsec_certificate_issuer,omitempty"`
	RadSecRadiusV11         string         `json:"radsec_radius_v11,omitempty"`
	Vendor                  string         `json:"vendor,omitempty"`
	Model                   string         `json:"model,omitempty"`
	FirmwareVersion         string         `json:"firmware_version,omitempty"`
	SerialNumber            string         `json:"serial_number,omitempty"`
	Capabilities            map[string]any `json:"capabilities"`
	Status                  string         `json:"status"`
	DiscoverySource         string         `json:"discovery_source"`
	RequestedAt             string         `json:"requested_at"`
	ExpiresAt               string         `json:"expires_at"`
	ApprovedBy              string         `json:"approved_by,omitempty"`
	ApprovedAt              string         `json:"approved_at,omitempty"`
	RejectedBy              string         `json:"rejected_by,omitempty"`
	RejectedAt              string         `json:"rejected_at,omitempty"`
	RadiusClientID          int            `json:"radius_client_id,omitempty"`
	OwnerTenant             string         `json:"owner_tenant,omitempty"`
	TemplateName            string         `json:"template_name,omitempty"`
	LastSeenAt              string         `json:"last_seen_at,omitempty"`
	LastSeenReason          string         `json:"last_seen_reason,omitempty"`
	Drift                   map[string]any `json:"drift"`
	EvidenceSHA256          string         `json:"evidence_sha256"`
	CreatedAt               string         `json:"created_at"`
	UpdatedAt               string         `json:"updated_at"`
}

type NASClientCapabilityTemplate struct {
	ID                   int            `json:"id"`
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	NASType              string         `json:"nas_type"`
	RequiredCapabilities []string       `json:"required_capabilities"`
	AllowedVendors       []string       `json:"allowed_vendors"`
	DefaultCapabilities  map[string]any `json:"default_capabilities"`
	Enabled              bool           `json:"enabled"`
	CreatedAt            string         `json:"created_at"`
	UpdatedAt            string         `json:"updated_at"`
}

type NASClientEvent struct {
	ID             int            `json:"id"`
	EnrollmentID   string         `json:"enrollment_id,omitempty"`
	RadiusClientID int            `json:"radius_client_id,omitempty"`
	EventType      string         `json:"event_type"`
	Status         string         `json:"status"`
	Summary        string         `json:"summary"`
	Actor          string         `json:"actor,omitempty"`
	Details        map[string]any `json:"details,omitempty"`
	CreatedAt      string         `json:"created_at"`
}

type NASClientSummary struct {
	SchemaVersion       int    `json:"schema_version"`
	Status              string `json:"status"`
	Message             string `json:"message"`
	TotalEnrollments    int    `json:"total_enrollments"`
	PendingCount        int    `json:"pending_count"`
	ApprovedCount       int    `json:"approved_count"`
	RejectedCount       int    `json:"rejected_count"`
	RevokedCount        int    `json:"revoked_count"`
	ExpiredCount        int    `json:"expired_count"`
	EnabledClients      int    `json:"enabled_clients"`
	DynamicClients      int    `json:"dynamic_clients"`
	CapabilityTemplates int    `json:"capability_templates"`
	LastEventAt         string `json:"last_event_at,omitempty"`
}

func CreateOrRefreshNASClientEnrollment(req NASClientEnrollmentRequest, maxPending int) (NASClientEnrollment, error) {
	if DB == nil {
		return NASClientEnrollment{}, errors.New("database is not initialized")
	}
	normalized, err := normalizeNASClientEnrollmentRequest(req)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if maxPending <= 0 {
		maxPending = 256
	}
	now := time.Now().UTC()
	if normalized.ExpiresAt.IsZero() {
		normalized.ExpiresAt = now.Add(24 * time.Hour)
	}
	capabilitiesJSON, err := jsonObjectString(normalized.Capabilities)
	if err != nil {
		return NASClientEnrollment{}, fmt.Errorf("capabilities: %w", err)
	}
	evidence := nasClientEvidenceSHA(normalized, capabilitiesJSON)

	tx, err := DB.Begin()
	if err != nil {
		return NASClientEnrollment{}, err
	}
	defer tx.Rollback()
	if err := expireNASClientEnrollmentsTx(tx, now); err != nil {
		return NASClientEnrollment{}, err
	}

	var existingID int
	var existingStatus string
	var existingRadiusClientID sql.NullInt64
	err = tx.QueryRow(`SELECT id, status, radius_client_id FROM nas_client_enrollments WHERE enrollment_id = ?`,
		normalized.EnrollmentID).Scan(&existingID, &existingStatus, &existingRadiusClientID)
	switch {
	case err == sql.ErrNoRows:
		var pending int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM nas_client_enrollments WHERE status = ?`, NASClientStatusPending).Scan(&pending); err != nil {
			return NASClientEnrollment{}, err
		}
		if pending >= maxPending {
			return NASClientEnrollment{}, fmt.Errorf("dynamic NAS enrollment pending limit %d reached", maxPending)
		}
		_, err = tx.Exec(`INSERT INTO nas_client_enrollments (
			enrollment_id, source_ip, shortname, nas_type, transport, secret_ref, radsec_certificate_cn,
			radsec_certificate_issuer, radsec_radius_v11, vendor, model, firmware_version, serial_number,
			capabilities_json, status, discovery_source, requested_at, expires_at, owner_tenant, template_name,
			last_seen_at, last_seen_reason, drift_json, evidence_sha256, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)`,
			normalized.EnrollmentID, normalized.SourceIP, normalized.ShortName, normalized.NASType, normalized.Transport,
			nullString(normalized.SecretRef), nullString(normalized.RadSecCertificateCN), nullString(normalized.RadSecCertificateIssuer),
			nullString(normalized.RadSecRadiusV11), nullString(normalized.Vendor), nullString(normalized.Model),
			nullString(normalized.FirmwareVersion), nullString(normalized.SerialNumber), capabilitiesJSON, NASClientStatusPending,
			normalized.DiscoverySource, now.Format(time.RFC3339), normalized.ExpiresAt.Format(time.RFC3339),
			nullString(normalized.OwnerTenant), nullString(normalized.TemplateName), now.Format(time.RFC3339),
			nullString(normalized.LastSeenReason), evidence, now.Format(time.RFC3339))
		if err != nil {
			return NASClientEnrollment{}, fmt.Errorf("insert NAS client enrollment: %w", err)
		}
		if err := insertNASClientEventTx(tx, normalized.EnrollmentID, 0, "enrollment_created", NASClientStatusPending, "NAS enrollment is pending approval.", normalized.Actor, map[string]any{"source_ip": normalized.SourceIP, "shortname": normalized.ShortName}); err != nil {
			return NASClientEnrollment{}, err
		}
	case err != nil:
		return NASClientEnrollment{}, err
	default:
		nextStatus := existingStatus
		if existingStatus == NASClientStatusExpired {
			nextStatus = NASClientStatusPending
		}
		_, err = tx.Exec(`UPDATE nas_client_enrollments SET
			source_ip = ?, shortname = ?, nas_type = ?, transport = ?, secret_ref = ?,
			radsec_certificate_cn = ?, radsec_certificate_issuer = ?, radsec_radius_v11 = ?,
			vendor = ?, model = ?, firmware_version = ?, serial_number = ?, capabilities_json = ?,
			status = ?, discovery_source = ?, expires_at = ?, owner_tenant = ?, template_name = ?,
			last_seen_at = ?, last_seen_reason = ?, drift_json = '{}', evidence_sha256 = ?, updated_at = ?
			WHERE enrollment_id = ?`,
			normalized.SourceIP, normalized.ShortName, normalized.NASType, normalized.Transport,
			nullString(normalized.SecretRef), nullString(normalized.RadSecCertificateCN), nullString(normalized.RadSecCertificateIssuer),
			nullString(normalized.RadSecRadiusV11), nullString(normalized.Vendor), nullString(normalized.Model),
			nullString(normalized.FirmwareVersion), nullString(normalized.SerialNumber), capabilitiesJSON, nextStatus,
			normalized.DiscoverySource, normalized.ExpiresAt.Format(time.RFC3339), nullString(normalized.OwnerTenant),
			nullString(normalized.TemplateName), now.Format(time.RFC3339), nullString(normalized.LastSeenReason),
			evidence, now.Format(time.RFC3339), normalized.EnrollmentID)
		if err != nil {
			return NASClientEnrollment{}, fmt.Errorf("refresh NAS client enrollment: %w", err)
		}
		if existingRadiusClientID.Valid {
			_, _ = tx.Exec(`UPDATE radius_clients SET last_seen_at = ?, capabilities_json = ?, vendor = ?, model = ?,
				firmware_version = ?, serial_number = ?, owner_tenant = ?, template_name = ?
				WHERE id = ?`, now.Format(time.RFC3339), capabilitiesJSON, nullString(normalized.Vendor), nullString(normalized.Model),
				nullString(normalized.FirmwareVersion), nullString(normalized.SerialNumber), nullString(normalized.OwnerTenant),
				nullString(normalized.TemplateName), existingRadiusClientID.Int64)
		}
		eventType := "enrollment_refreshed"
		if existingStatus == NASClientStatusApproved {
			eventType = "approved_client_seen"
		}
		if err := insertNASClientEventTx(tx, normalized.EnrollmentID, int(existingRadiusClientID.Int64), eventType, nextStatus, "NAS enrollment metadata was refreshed.", normalized.Actor, map[string]any{"source_ip": normalized.SourceIP, "shortname": normalized.ShortName}); err != nil {
			return NASClientEnrollment{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return NASClientEnrollment{}, err
	}
	return GetNASClientEnrollment(normalized.EnrollmentID)
}

func ApproveNASClientEnrollment(enrollmentID string, req NASClientApprovalRequest) (NASClientEnrollment, error) {
	if DB == nil {
		return NASClientEnrollment{}, errors.New("database is not initialized")
	}
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" {
		return NASClientEnrollment{}, errors.New("enrollment_id is required")
	}
	now := time.Now().UTC()
	tx, err := DB.Begin()
	if err != nil {
		return NASClientEnrollment{}, err
	}
	defer tx.Rollback()
	if err := expireNASClientEnrollmentsTx(tx, now); err != nil {
		return NASClientEnrollment{}, err
	}
	enrollment, err := getNASClientEnrollmentTx(tx, enrollmentID)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if enrollment.Status != NASClientStatusPending {
		return NASClientEnrollment{}, fmt.Errorf("NAS enrollment %s is %s and cannot be approved", enrollmentID, enrollment.Status)
	}
	approved := approvalRequestFromEnrollment(enrollment, req)
	mergedCapabilities, err := capabilitiesWithTemplateDefaultsTx(tx, approved.TemplateName, approved.Capabilities)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	approved.Capabilities = mergedCapabilities
	if err := validateNASClientApproval(approved, enrollment); err != nil {
		_ = insertNASClientEventTx(tx, enrollmentID, enrollment.RadiusClientID, "approval_failed", enrollment.Status, err.Error(), approved.ApprovedBy, nil)
		return NASClientEnrollment{}, err
	}
	if err := validateNASClientTemplateTx(tx, approved.TemplateName, approved.Vendor, approved.Capabilities); err != nil {
		_ = insertNASClientEventTx(tx, enrollmentID, enrollment.RadiusClientID, "approval_failed", enrollment.Status, err.Error(), approved.ApprovedBy, map[string]any{"template": approved.TemplateName})
		return NASClientEnrollment{}, err
	}
	capabilitiesJSON, err := jsonObjectString(approved.Capabilities)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	secret := strings.TrimRight(approved.Secret, "\r\n")
	secretRef := strings.TrimSpace(approved.SecretRef)
	if approved.Transport == "radsec" {
		secret = "radsec"
		secretRef = ""
	}
	radiusClientID, err := upsertApprovedRadiusClientTx(tx, enrollmentID, approved, secret, secretRef, capabilitiesJSON, now)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	_, err = tx.Exec(`UPDATE nas_client_enrollments SET
		source_ip = ?, shortname = ?, nas_type = ?, transport = ?, secret_ref = ?,
		radsec_certificate_cn = ?, radsec_certificate_issuer = ?, radsec_radius_v11 = ?,
		vendor = ?, model = ?, firmware_version = ?, serial_number = ?, capabilities_json = ?,
		status = ?, approved_by = ?, approved_at = ?, radius_client_id = ?, owner_tenant = ?,
		template_name = ?, last_seen_at = ?, last_seen_reason = ?, updated_at = ?
		WHERE enrollment_id = ?`,
		approved.SourceIP, approved.ShortName, approved.NASType, approved.Transport, nullString(secretRef),
		nullString(approved.RadSecCertificateCN), nullString(approved.RadSecCertificateIssuer), nullString(approved.RadSecRadiusV11),
		nullString(approved.Vendor), nullString(approved.Model), nullString(approved.FirmwareVersion), nullString(approved.SerialNumber),
		capabilitiesJSON, NASClientStatusApproved, nullString(approved.ApprovedBy), now.Format(time.RFC3339),
		radiusClientID, nullString(approved.OwnerTenant), nullString(approved.TemplateName), now.Format(time.RFC3339),
		"approved", now.Format(time.RFC3339), enrollmentID)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if err := insertNASClientEventTx(tx, enrollmentID, radiusClientID, "enrollment_approved", NASClientStatusApproved, "NAS enrollment was approved and activated as a RADIUS client.", approved.ApprovedBy, map[string]any{"source_ip": approved.SourceIP, "shortname": approved.ShortName, "transport": approved.Transport}); err != nil {
		return NASClientEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return NASClientEnrollment{}, err
	}
	return GetNASClientEnrollment(enrollmentID)
}

func RejectNASClientEnrollment(enrollmentID, actor, reason string) (NASClientEnrollment, error) {
	return transitionNASClientEnrollment(enrollmentID, NASClientStatusRejected, "enrollment_rejected", actor, reason, false)
}

func RevokeNASClientEnrollment(enrollmentID, actor, reason string) (NASClientEnrollment, error) {
	return transitionNASClientEnrollment(enrollmentID, NASClientStatusRevoked, "enrollment_revoked", actor, reason, true)
}

func GetNASClientEnrollment(enrollmentID string) (NASClientEnrollment, error) {
	if DB == nil {
		return NASClientEnrollment{}, errors.New("database is not initialized")
	}
	tx, err := DB.Begin()
	if err != nil {
		return NASClientEnrollment{}, err
	}
	defer tx.Rollback()
	enrollment, err := getNASClientEnrollmentTx(tx, strings.TrimSpace(enrollmentID))
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return NASClientEnrollment{}, err
	}
	return enrollment, nil
}

func ListNASClientEnrollments(status string, limit int) ([]NASClientEnrollment, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "" && !validNASClientStatus(status) {
		return nil, fmt.Errorf("NAS enrollment status %q is invalid", status)
	}
	if err := ExpireNASClientEnrollments(time.Now().UTC()); err != nil {
		return nil, err
	}
	query := nasClientEnrollmentSelectSQL()
	args := []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNASClientEnrollmentRows(rows)
}

func UpsertNASClientCapabilityTemplate(template NASClientCapabilityTemplate) (NASClientCapabilityTemplate, error) {
	if DB == nil {
		return NASClientCapabilityTemplate{}, errors.New("database is not initialized")
	}
	template.Name = normalizeNASToken(template.Name, "")
	if template.Name == "" {
		return NASClientCapabilityTemplate{}, errors.New("template name is required")
	}
	template.NASType = normalizeNASToken(template.NASType, "other")
	template.Description = cleanNASClientText(template.Description, 512)
	if template.RequiredCapabilities == nil {
		template.RequiredCapabilities = []string{}
	}
	if template.AllowedVendors == nil {
		template.AllowedVendors = []string{}
	}
	if template.DefaultCapabilities == nil {
		template.DefaultCapabilities = map[string]any{}
	}
	requiredJSON, err := jsonString(template.RequiredCapabilities)
	if err != nil {
		return NASClientCapabilityTemplate{}, err
	}
	allowedJSON, err := jsonString(normalizeStringList(template.AllowedVendors))
	if err != nil {
		return NASClientCapabilityTemplate{}, err
	}
	defaultJSON, err := jsonObjectString(template.DefaultCapabilities)
	if err != nil {
		return NASClientCapabilityTemplate{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	enabled := template.Enabled
	_, err = DB.Exec(`INSERT INTO nas_client_capability_templates
		(name, description, nas_type, required_capabilities_json, allowed_vendors_json, default_capabilities_json, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			nas_type = excluded.nas_type,
			required_capabilities_json = excluded.required_capabilities_json,
			allowed_vendors_json = excluded.allowed_vendors_json,
			default_capabilities_json = excluded.default_capabilities_json,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		template.Name, nullString(template.Description), template.NASType, requiredJSON, allowedJSON, defaultJSON, enabled, now)
	if err != nil {
		return NASClientCapabilityTemplate{}, err
	}
	return GetNASClientCapabilityTemplate(template.Name)
}

func GetNASClientCapabilityTemplate(name string) (NASClientCapabilityTemplate, error) {
	if DB == nil {
		return NASClientCapabilityTemplate{}, errors.New("database is not initialized")
	}
	row := DB.QueryRow(nasClientTemplateSelectSQL()+` WHERE name = ?`, normalizeNASToken(name, ""))
	return scanNASClientTemplateRow(row)
}

func ListNASClientCapabilityTemplates() ([]NASClientCapabilityTemplate, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(nasClientTemplateSelectSQL() + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var templates []NASClientCapabilityTemplate
	for rows.Next() {
		template, err := scanNASClientTemplateScanner(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}
	return templates, rows.Err()
}

func DeleteNASClientCapabilityTemplate(name string) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	name = normalizeNASToken(name, "")
	if name == "" {
		return errors.New("template name is required")
	}
	if name == "default" {
		return errors.New("default NAS capability template cannot be deleted")
	}
	_, err := DB.Exec(`DELETE FROM nas_client_capability_templates WHERE name = ?`, name)
	return err
}

func ListNASClientEvents(limit int) ([]NASClientEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, COALESCE(enrollment_id, ''), COALESCE(radius_client_id, 0),
		event_type, status, COALESCE(summary, ''), COALESCE(actor, ''), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM nas_client_events ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []NASClientEvent
	for rows.Next() {
		var event NASClientEvent
		var details string
		if err := rows.Scan(&event.ID, &event.EnrollmentID, &event.RadiusClientID, &event.EventType, &event.Status, &event.Summary, &event.Actor, &details, &event.CreatedAt); err != nil {
			return nil, err
		}
		event.Details = map[string]any{}
		if strings.TrimSpace(details) != "" {
			_ = json.Unmarshal([]byte(details), &event.Details)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetNASClientSummary() (NASClientSummary, error) {
	summary := NASClientSummary{
		SchemaVersion: NASClientEnrollmentSchemaVersion,
		Status:        "ready",
		Message:       "Dynamic NAS client enrollment and capability inventory are available.",
	}
	if DB == nil {
		summary.Status = "disabled"
		summary.Message = "Database is not initialized."
		return summary, nil
	}
	_ = ExpireNASClientEnrollments(time.Now().UTC())
	rows, err := DB.Query(`SELECT status, COUNT(*) FROM nas_client_enrollments GROUP BY status`)
	if err != nil {
		return summary, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return summary, err
		}
		summary.TotalEnrollments += count
		switch status {
		case NASClientStatusPending:
			summary.PendingCount = count
		case NASClientStatusApproved:
			summary.ApprovedCount = count
		case NASClientStatusRejected:
			summary.RejectedCount = count
		case NASClientStatusRevoked:
			summary.RevokedCount = count
		case NASClientStatusExpired:
			summary.ExpiredCount = count
		}
	}
	if err := rows.Close(); err != nil {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE enabled = 1`).Scan(&summary.EnabledClients); err != nil {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE COALESCE(dynamic_source, 'static') <> 'static'`).Scan(&summary.DynamicClients); err != nil {
		return summary, err
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM nas_client_capability_templates WHERE enabled = 1`).Scan(&summary.CapabilityTemplates); err != nil {
		return summary, err
	}
	_ = DB.QueryRow(`SELECT COALESCE(MAX(created_at), '') FROM nas_client_events`).Scan(&summary.LastEventAt)
	if summary.PendingCount > 0 {
		summary.Status = "pending"
		summary.Message = fmt.Sprintf("%d dynamic NAS enrollment(s) require approval.", summary.PendingCount)
	}
	return summary, nil
}

func ExpireNASClientEnrollments(now time.Time) error {
	if DB == nil {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := expireNASClientEnrollmentsTx(tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func RecordNASClientHeartbeat(sourceIP, reason string, now time.Time) error {
	if DB == nil {
		return nil
	}
	sourceIP = normalizeIPAddress(sourceIP)
	if sourceIP == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := DB.Exec(`UPDATE radius_clients SET last_seen_at = ?
		WHERE enabled = 1 AND COALESCE(dynamic_source, 'static') <> 'static' AND ipaddr = ?`,
		now.Format(time.RFC3339), sourceIP)
	if err != nil {
		return err
	}
	_, _ = DB.Exec(`UPDATE nas_client_enrollments SET last_seen_at = ?, last_seen_reason = ?, updated_at = ?
		WHERE source_ip = ? AND status = ?`, now.Format(time.RFC3339), cleanNASClientText(reason, 128), now.Format(time.RFC3339), sourceIP, NASClientStatusApproved)
	return nil
}

func transitionNASClientEnrollment(enrollmentID, status, eventType, actor, reason string, disableClient bool) (NASClientEnrollment, error) {
	if DB == nil {
		return NASClientEnrollment{}, errors.New("database is not initialized")
	}
	if !validNASClientStatus(status) || status == NASClientStatusPending {
		return NASClientEnrollment{}, fmt.Errorf("NAS enrollment transition status %q is invalid", status)
	}
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" {
		return NASClientEnrollment{}, errors.New("enrollment_id is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := DB.Begin()
	if err != nil {
		return NASClientEnrollment{}, err
	}
	defer tx.Rollback()
	enrollment, err := getNASClientEnrollmentTx(tx, enrollmentID)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if disableClient && enrollment.RadiusClientID > 0 {
		if _, err := tx.Exec(`UPDATE radius_clients SET enabled = 0, lifecycle_status = ?, last_seen_at = COALESCE(last_seen_at, ?) WHERE id = ?`,
			status, now, enrollment.RadiusClientID); err != nil {
			return NASClientEnrollment{}, err
		}
	}
	_, err = tx.Exec(`UPDATE nas_client_enrollments SET status = ?, rejected_by = ?, rejected_at = ?, last_seen_reason = ?, updated_at = ?
		WHERE enrollment_id = ?`, status, nullString(actor), now, nullString(reason), now, enrollmentID)
	if err != nil {
		return NASClientEnrollment{}, err
	}
	if err := insertNASClientEventTx(tx, enrollmentID, enrollment.RadiusClientID, eventType, status, defaultTransitionSummary(status, reason), actor, map[string]any{"reason": reason}); err != nil {
		return NASClientEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return NASClientEnrollment{}, err
	}
	return GetNASClientEnrollment(enrollmentID)
}

func expireNASClientEnrollmentsTx(tx *sql.Tx, now time.Time) error {
	if tx == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := tx.Query(`SELECT enrollment_id FROM nas_client_enrollments WHERE status = ? AND expires_at < ?`,
		NASClientStatusPending, now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(`UPDATE nas_client_enrollments SET status = ?, updated_at = ?, last_seen_reason = 'expired' WHERE enrollment_id = ?`,
			NASClientStatusExpired, now.Format(time.RFC3339), id); err != nil {
			return err
		}
		if err := insertNASClientEventTx(tx, id, 0, "enrollment_expired", NASClientStatusExpired, "Pending NAS enrollment expired before approval.", "system", nil); err != nil {
			return err
		}
	}
	return nil
}

func approvalRequestFromEnrollment(enrollment NASClientEnrollment, req NASClientApprovalRequest) NASClientApprovalRequest {
	out := req
	if strings.TrimSpace(out.SourceIP) == "" {
		out.SourceIP = enrollment.SourceIP
	}
	if strings.TrimSpace(out.ShortName) == "" {
		out.ShortName = enrollment.ShortName
	}
	if strings.TrimSpace(out.NASType) == "" {
		out.NASType = enrollment.NASType
	}
	if strings.TrimSpace(out.Transport) == "" {
		out.Transport = enrollment.Transport
	}
	if strings.TrimSpace(out.SecretRef) == "" {
		out.SecretRef = enrollment.SecretRef
	}
	if strings.TrimSpace(out.RadSecCertificateCN) == "" {
		out.RadSecCertificateCN = enrollment.RadSecCertificateCN
	}
	if strings.TrimSpace(out.RadSecCertificateIssuer) == "" {
		out.RadSecCertificateIssuer = enrollment.RadSecCertificateIssuer
	}
	if strings.TrimSpace(out.RadSecRadiusV11) == "" {
		out.RadSecRadiusV11 = enrollment.RadSecRadiusV11
	}
	if strings.TrimSpace(out.Vendor) == "" {
		out.Vendor = enrollment.Vendor
	}
	if strings.TrimSpace(out.Model) == "" {
		out.Model = enrollment.Model
	}
	if strings.TrimSpace(out.FirmwareVersion) == "" {
		out.FirmwareVersion = enrollment.FirmwareVersion
	}
	if strings.TrimSpace(out.SerialNumber) == "" {
		out.SerialNumber = enrollment.SerialNumber
	}
	if out.Capabilities == nil {
		out.Capabilities = enrollment.Capabilities
	}
	if strings.TrimSpace(out.OwnerTenant) == "" {
		out.OwnerTenant = enrollment.OwnerTenant
	}
	if strings.TrimSpace(out.TemplateName) == "" {
		out.TemplateName = enrollment.TemplateName
	}
	return out
}

func validateNASClientApproval(req NASClientApprovalRequest, enrollment NASClientEnrollment) error {
	sourceIP := normalizeIPAddress(req.SourceIP)
	if sourceIP == "" {
		return errors.New("source_ip must be an IPv4 or IPv6 address")
	}
	if !validNASShortName(req.ShortName) {
		return errors.New("shortname is required and may contain only letters, numbers, dot, dash, or underscore")
	}
	transport := normalizeTransport(req.Transport)
	if transport == "" {
		return fmt.Errorf("transport %q is invalid", req.Transport)
	}
	if transport == "udp" && strings.TrimSpace(req.Secret) == "" && strings.TrimSpace(req.SecretRef) == "" && enrollment.RadiusClientID == 0 {
		return errors.New("secret or secret_ref is required before approving a UDP NAS client")
	}
	if strings.TrimSpace(req.Secret) != "" && strings.TrimSpace(req.SecretRef) != "" {
		return errors.New("secret and secret_ref cannot both be set")
	}
	if transport == "radsec" && strings.TrimSpace(req.RadSecCertificateCN) == "" {
		return errors.New("radsec_certificate_cn is required before approving a RadSec NAS client")
	}
	return nil
}

func validateNASClientTemplateTx(tx *sql.Tx, name, vendor string, capabilities map[string]any) error {
	name = normalizeNASToken(name, "default")
	template, err := getNASClientCapabilityTemplateTx(tx, name)
	if err != nil {
		return fmt.Errorf("capability template %q is unavailable: %w", name, err)
	}
	if !template.Enabled {
		return fmt.Errorf("capability template %q is disabled", name)
	}
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if len(template.AllowedVendors) > 0 {
		if vendor == "" {
			return fmt.Errorf("capability template %q requires a vendor identity", name)
		}
		allowed := false
		for _, item := range template.AllowedVendors {
			if strings.EqualFold(strings.TrimSpace(item), vendor) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("vendor %q is not allowed by capability template %q", vendor, name)
		}
	}
	var missing []string
	for _, required := range template.RequiredCapabilities {
		if !capabilityPresent(capabilities, required) {
			missing = append(missing, required)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("capability template %q requires missing capabilities: %s", name, strings.Join(missing, ", "))
	}
	return nil
}

func capabilitiesWithTemplateDefaultsTx(tx *sql.Tx, name string, capabilities map[string]any) (map[string]any, error) {
	template, err := getNASClientCapabilityTemplateTx(tx, normalizeNASToken(name, "default"))
	if err != nil {
		return nil, fmt.Errorf("capability template %q is unavailable: %w", name, err)
	}
	return mergeCapabilities(template.DefaultCapabilities, capabilities), nil
}

func mergeCapabilities(defaults, overrides map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range defaults {
		out[key] = value
	}
	for key, value := range overrides {
		if existing, ok := out[key].(map[string]any); ok {
			if incoming, ok := value.(map[string]any); ok {
				out[key] = mergeCapabilities(existing, incoming)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func upsertApprovedRadiusClientTx(tx *sql.Tx, enrollmentID string, req NASClientApprovalRequest, secret, secretRef, capabilitiesJSON string, now time.Time) (int, error) {
	var existingID int
	err := tx.QueryRow(`SELECT id FROM radius_clients WHERE enrollment_id = ? OR shortname = ? ORDER BY CASE WHEN enrollment_id = ? THEN 0 ELSE 1 END LIMIT 1`,
		enrollmentID, strings.TrimSpace(req.ShortName), enrollmentID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if err == nil {
		if strings.TrimSpace(secret) == "" && strings.TrimSpace(secretRef) == "" && req.Transport == "udp" {
			_, err = tx.Exec(`UPDATE radius_clients SET
				shortname = ?, ipaddr = ?, nas_type = ?, transport = ?, radsec_certificate_cn = ?,
				radsec_certificate_issuer = ?, radsec_radius_v11 = ?, description = ?, enabled = 1,
				dynamic_source = 'enrollment', enrollment_id = ?, capabilities_json = ?, vendor = ?, model = ?,
				firmware_version = ?, serial_number = ?, lifecycle_status = 'approved', last_seen_at = ?,
				approved_at = ?, approved_by = ?, owner_tenant = ?, template_name = ?
				WHERE id = ?`,
				req.ShortName, req.SourceIP, req.NASType, req.Transport, nullString(req.RadSecCertificateCN),
				nullString(req.RadSecCertificateIssuer), nullString(req.RadSecRadiusV11), "Dynamic NAS client enrollment "+enrollmentID,
				enrollmentID, capabilitiesJSON, nullString(req.Vendor), nullString(req.Model), nullString(req.FirmwareVersion),
				nullString(req.SerialNumber), now.Format(time.RFC3339), now.Format(time.RFC3339), nullString(req.ApprovedBy),
				nullString(req.OwnerTenant), nullString(req.TemplateName), existingID)
		} else {
			_, err = tx.Exec(`UPDATE radius_clients SET
				shortname = ?, ipaddr = ?, secret = ?, secret_ref = ?, nas_type = ?, transport = ?,
				radsec_certificate_cn = ?, radsec_certificate_issuer = ?, radsec_radius_v11 = ?,
				description = ?, enabled = 1, dynamic_source = 'enrollment', enrollment_id = ?,
				capabilities_json = ?, vendor = ?, model = ?, firmware_version = ?, serial_number = ?,
				lifecycle_status = 'approved', last_seen_at = ?, approved_at = ?, approved_by = ?,
				owner_tenant = ?, template_name = ?
				WHERE id = ?`,
				req.ShortName, req.SourceIP, secret, nullString(secretRef), req.NASType, req.Transport,
				nullString(req.RadSecCertificateCN), nullString(req.RadSecCertificateIssuer), nullString(req.RadSecRadiusV11),
				"Dynamic NAS client enrollment "+enrollmentID, enrollmentID, capabilitiesJSON, nullString(req.Vendor),
				nullString(req.Model), nullString(req.FirmwareVersion), nullString(req.SerialNumber), now.Format(time.RFC3339),
				now.Format(time.RFC3339), nullString(req.ApprovedBy), nullString(req.OwnerTenant), nullString(req.TemplateName), existingID)
		}
		return existingID, err
	}
	res, err := tx.Exec(`INSERT INTO radius_clients (
		shortname, ipaddr, secret, secret_ref, nas_type, transport, radsec_certificate_cn,
		radsec_certificate_issuer, radsec_radius_v11, description, enabled, dynamic_source,
		enrollment_id, capabilities_json, vendor, model, firmware_version, serial_number,
		lifecycle_status, last_seen_at, approved_at, approved_by, owner_tenant, template_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'enrollment', ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?)`,
		req.ShortName, req.SourceIP, secret, nullString(secretRef), req.NASType, req.Transport,
		nullString(req.RadSecCertificateCN), nullString(req.RadSecCertificateIssuer), nullString(req.RadSecRadiusV11),
		"Dynamic NAS client enrollment "+enrollmentID, enrollmentID, capabilitiesJSON, nullString(req.Vendor),
		nullString(req.Model), nullString(req.FirmwareVersion), nullString(req.SerialNumber), now.Format(time.RFC3339),
		now.Format(time.RFC3339), nullString(req.ApprovedBy), nullString(req.OwnerTenant), nullString(req.TemplateName))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		err = tx.QueryRow(`SELECT id FROM radius_clients WHERE enrollment_id = ?`, enrollmentID).Scan(&id)
	}
	return int(id), err
}

func normalizeNASClientEnrollmentRequest(req NASClientEnrollmentRequest) (NASClientEnrollmentRequest, error) {
	req.SourceIP = normalizeIPAddress(req.SourceIP)
	if req.SourceIP == "" {
		return req, errors.New("source_ip must be an IPv4 or IPv6 address")
	}
	req.ShortName = strings.TrimSpace(req.ShortName)
	if req.ShortName == "" {
		req.ShortName = "nas-" + strings.ReplaceAll(req.SourceIP, ":", "-")
		req.ShortName = strings.ReplaceAll(req.ShortName, ".", "-")
	}
	if !validNASShortName(req.ShortName) {
		return req, errors.New("shortname may contain only letters, numbers, dot, dash, or underscore")
	}
	req.NASType = normalizeNASToken(req.NASType, "other")
	req.Transport = normalizeTransport(req.Transport)
	if req.Transport == "" {
		return req, errors.New("transport must be udp or radsec")
	}
	req.SecretRef = strings.TrimSpace(req.SecretRef)
	req.RadSecCertificateCN = cleanNASClientToken(req.RadSecCertificateCN, 256)
	req.RadSecCertificateIssuer = cleanNASClientText(req.RadSecCertificateIssuer, 512)
	req.RadSecRadiusV11 = normalizeRadiusV11(req.RadSecRadiusV11)
	req.Vendor = cleanNASClientToken(req.Vendor, 128)
	req.Model = cleanNASClientText(req.Model, 128)
	req.FirmwareVersion = cleanNASClientText(req.FirmwareVersion, 128)
	req.SerialNumber = cleanNASClientText(req.SerialNumber, 128)
	req.OwnerTenant = cleanNASClientToken(req.OwnerTenant, 128)
	req.TemplateName = normalizeNASToken(req.TemplateName, "default")
	req.DiscoverySource = normalizeNASToken(req.DiscoverySource, "bootstrap")
	req.LastSeenReason = cleanNASClientText(req.LastSeenReason, 128)
	req.Actor = cleanNASClientText(req.Actor, 128)
	if req.Capabilities == nil {
		req.Capabilities = map[string]any{}
	}
	req.EnrollmentID = strings.TrimSpace(req.EnrollmentID)
	if req.EnrollmentID == "" {
		req.EnrollmentID = generatedEnrollmentID(req)
	}
	if !validNASIdentifier(req.EnrollmentID) {
		return req, errors.New("enrollment_id may contain only letters, numbers, dot, dash, or underscore")
	}
	return req, nil
}

func nasClientEnrollmentSelectSQL() string {
	return `SELECT id, enrollment_id, source_ip, shortname, nas_type, transport, COALESCE(secret_ref, ''),
		COALESCE(radsec_certificate_cn, ''), COALESCE(radsec_certificate_issuer, ''), COALESCE(radsec_radius_v11, ''),
		COALESCE(vendor, ''), COALESCE(model, ''), COALESCE(firmware_version, ''), COALESCE(serial_number, ''),
		COALESCE(capabilities_json, '{}'), status, COALESCE(discovery_source, ''), COALESCE(requested_at, ''),
		COALESCE(expires_at, ''), COALESCE(approved_by, ''), COALESCE(approved_at, ''), COALESCE(rejected_by, ''),
		COALESCE(rejected_at, ''), COALESCE(radius_client_id, 0), COALESCE(owner_tenant, ''), COALESCE(template_name, ''),
		COALESCE(last_seen_at, ''), COALESCE(last_seen_reason, ''), COALESCE(drift_json, '{}'), COALESCE(evidence_sha256, ''),
		COALESCE(created_at, ''), COALESCE(updated_at, '') FROM nas_client_enrollments`
}

func getNASClientEnrollmentTx(tx *sql.Tx, enrollmentID string) (NASClientEnrollment, error) {
	row := tx.QueryRow(nasClientEnrollmentSelectSQL()+` WHERE enrollment_id = ?`, enrollmentID)
	return scanNASClientEnrollmentScanner(row)
}

func scanNASClientEnrollmentRows(rows *sql.Rows) ([]NASClientEnrollment, error) {
	var out []NASClientEnrollment
	for rows.Next() {
		enrollment, err := scanNASClientEnrollmentScanner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, enrollment)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanNASClientEnrollmentScanner(row scanner) (NASClientEnrollment, error) {
	var enrollment NASClientEnrollment
	var capabilitiesJSON, driftJSON string
	if err := row.Scan(&enrollment.ID, &enrollment.EnrollmentID, &enrollment.SourceIP, &enrollment.ShortName,
		&enrollment.NASType, &enrollment.Transport, &enrollment.SecretRef, &enrollment.RadSecCertificateCN,
		&enrollment.RadSecCertificateIssuer, &enrollment.RadSecRadiusV11, &enrollment.Vendor, &enrollment.Model,
		&enrollment.FirmwareVersion, &enrollment.SerialNumber, &capabilitiesJSON, &enrollment.Status,
		&enrollment.DiscoverySource, &enrollment.RequestedAt, &enrollment.ExpiresAt, &enrollment.ApprovedBy,
		&enrollment.ApprovedAt, &enrollment.RejectedBy, &enrollment.RejectedAt, &enrollment.RadiusClientID,
		&enrollment.OwnerTenant, &enrollment.TemplateName, &enrollment.LastSeenAt, &enrollment.LastSeenReason,
		&driftJSON, &enrollment.EvidenceSHA256, &enrollment.CreatedAt, &enrollment.UpdatedAt); err != nil {
		return NASClientEnrollment{}, err
	}
	enrollment.Capabilities = map[string]any{}
	enrollment.Drift = map[string]any{}
	_ = json.Unmarshal([]byte(capabilitiesJSON), &enrollment.Capabilities)
	_ = json.Unmarshal([]byte(driftJSON), &enrollment.Drift)
	return enrollment, nil
}

func nasClientTemplateSelectSQL() string {
	return `SELECT id, name, COALESCE(description, ''), nas_type, COALESCE(required_capabilities_json, '[]'),
		COALESCE(allowed_vendors_json, '[]'), COALESCE(default_capabilities_json, '{}'), enabled,
		COALESCE(created_at, ''), COALESCE(updated_at, '') FROM nas_client_capability_templates`
}

func scanNASClientTemplateRow(row *sql.Row) (NASClientCapabilityTemplate, error) {
	return scanNASClientTemplateScanner(row)
}

func getNASClientCapabilityTemplateTx(tx *sql.Tx, name string) (NASClientCapabilityTemplate, error) {
	return scanNASClientTemplateScanner(tx.QueryRow(nasClientTemplateSelectSQL()+` WHERE name = ?`, normalizeNASToken(name, "")))
}

func scanNASClientTemplateScanner(row scanner) (NASClientCapabilityTemplate, error) {
	var template NASClientCapabilityTemplate
	var requiredJSON, allowedJSON, defaultsJSON string
	var enabled any
	if err := row.Scan(&template.ID, &template.Name, &template.Description, &template.NASType, &requiredJSON, &allowedJSON, &defaultsJSON, &enabled, &template.CreatedAt, &template.UpdatedAt); err != nil {
		return NASClientCapabilityTemplate{}, err
	}
	template.Enabled = scanBool(enabled)
	template.RequiredCapabilities = []string{}
	template.AllowedVendors = []string{}
	template.DefaultCapabilities = map[string]any{}
	_ = json.Unmarshal([]byte(requiredJSON), &template.RequiredCapabilities)
	_ = json.Unmarshal([]byte(allowedJSON), &template.AllowedVendors)
	_ = json.Unmarshal([]byte(defaultsJSON), &template.DefaultCapabilities)
	return template, nil
}

func insertNASClientEventTx(tx *sql.Tx, enrollmentID string, radiusClientID int, eventType, status, summary, actor string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := jsonString(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO nas_client_events (enrollment_id, radius_client_id, event_type, status, summary, actor, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, nullString(enrollmentID), nullInt(radiusClientID), eventType, status, summary, nullString(actor), detailsJSON)
	return err
}

func generatedEnrollmentID(req NASClientEnrollmentRequest) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		req.SourceIP,
		strings.ToLower(req.ShortName),
		strings.ToLower(req.Vendor),
		strings.ToLower(req.Model),
		strings.ToLower(req.SerialNumber),
	}, "|")))
	return "nas-" + hex.EncodeToString(h[:])[:24]
}

func nasClientEvidenceSHA(req NASClientEnrollmentRequest, capabilitiesJSON string) string {
	payload := strings.Join([]string{
		req.EnrollmentID,
		req.SourceIP,
		req.ShortName,
		req.NASType,
		req.Transport,
		req.Vendor,
		req.Model,
		req.FirmwareVersion,
		req.SerialNumber,
		capabilitiesJSON,
		req.TemplateName,
	}, "\x00")
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

func capabilityPresent(capabilities map[string]any, path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return true
	}
	var current any = capabilities
	for _, part := range strings.Split(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		object, ok := current.(map[string]any)
		if !ok {
			return false
		}
		value, ok := object[part]
		if !ok {
			return false
		}
		current = value
	}
	return truthyCapability(current)
}

func truthyCapability(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return strings.TrimSpace(v) != ""
	case float64:
		return v != 0
	case int:
		return v != 0
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

func jsonObjectString(value map[string]any) (string, error) {
	if value == nil {
		value = map[string]any{}
	}
	return jsonString(value)
}

func jsonString(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func normalizeIPAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizeTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "udp":
		return "udp"
	case "radsec":
		return "radsec"
	default:
		return ""
	}
}

func normalizeRadiusV11(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow", "require":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "forbid"
	}
}

func normalizeNASToken(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	if !validNASIdentifier(value) {
		return fallback
	}
	return value
}

func validNASShortName(value string) bool {
	return validNASIdentifier(value)
}

func validNASIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func cleanNASClientToken(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = cleanNASClientText(value, maxLen)
	if strings.ContainsAny(value, "\t\r\n{}\"") {
		return ""
	}
	return value
}

func cleanNASClientText(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, value)
	if maxLen > 0 && len(value) > maxLen {
		value = value[:maxLen]
	}
	return value
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func validNASClientStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case NASClientStatusPending, NASClientStatusApproved, NASClientStatusRejected, NASClientStatusRevoked, NASClientStatusExpired:
		return true
	default:
		return false
	}
}

func nullString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func nullInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func scanBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case int:
		return v != 0
	case []byte:
		return string(v) == "1" || strings.EqualFold(string(v), "true")
	case string:
		return v == "1" || strings.EqualFold(v, "true")
	default:
		return false
	}
}

func defaultTransitionSummary(status, reason string) string {
	reason = strings.TrimSpace(reason)
	if reason != "" {
		return reason
	}
	switch status {
	case NASClientStatusRejected:
		return "NAS enrollment was rejected."
	case NASClientStatusRevoked:
		return "NAS client was revoked and disabled."
	default:
		return "NAS enrollment status changed."
	}
}
