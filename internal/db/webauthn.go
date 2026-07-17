package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxAdminWebAuthnEvents = 6000

type AdminWebAuthnCredential struct {
	ID                   string   `json:"id"`
	CredentialIDHash     string   `json:"credential_id_hash"`
	CredentialIDB64      string   `json:"credential_id_b64,omitempty"`
	UsernameHash         string   `json:"username_hash"`
	Subject              string   `json:"subject"`
	DisplayName          string   `json:"display_name,omitempty"`
	CredentialName       string   `json:"credential_name,omitempty"`
	PublicKeyCOSEB64     string   `json:"-"`
	PublicKeyAlg         int      `json:"public_key_alg"`
	SignCount            uint32   `json:"sign_count"`
	Transports           []string `json:"transports,omitempty"`
	AAGUID               string   `json:"aaguid,omitempty"`
	AttestationFormat    string   `json:"attestation_format,omitempty"`
	UserVerifiedRequired bool     `json:"user_verified_required"`
	BackupEligible       bool     `json:"backup_eligible"`
	BackupState          bool     `json:"backup_state"`
	Enabled              bool     `json:"enabled"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	LastUsedAt           string   `json:"last_used_at,omitempty"`
	RevokedAt            string   `json:"revoked_at,omitempty"`
	RevokedBy            string   `json:"revoked_by,omitempty"`
}

type AdminWebAuthnChallenge struct {
	ID             string   `json:"id"`
	StateHash      string   `json:"-"`
	Challenge      string   `json:"challenge,omitempty"`
	ChallengeHash  string   `json:"-"`
	Ceremony       string   `json:"ceremony"`
	Status         string   `json:"status"`
	UsernameHash   string   `json:"username_hash"`
	Subject        string   `json:"subject"`
	DisplayName    string   `json:"display_name,omitempty"`
	CredentialName string   `json:"credential_name,omitempty"`
	Role           string   `json:"role,omitempty"`
	Source         string   `json:"source,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	Tenants        []string `json:"tenants,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	FirstFactor    string   `json:"first_factor,omitempty"`
	Origin         string   `json:"origin,omitempty"`
	RPID           string   `json:"rp_id,omitempty"`
	AttemptCount   int      `json:"attempt_count"`
	MaxAttempts    int      `json:"max_attempts"`
	ExpiresAt      string   `json:"expires_at"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	VerifiedAt     string   `json:"verified_at,omitempty"`
	FailureReason  string   `json:"failure_reason,omitempty"`
	DetailsJSON    string   `json:"details_json,omitempty"`
}

type AdminWebAuthnEvent struct {
	ID               int    `json:"id"`
	ObservedAt       string `json:"observed_at"`
	UsernameHash     string `json:"username_hash"`
	Subject          string `json:"subject,omitempty"`
	Source           string `json:"source"`
	Ceremony         string `json:"ceremony"`
	Decision         string `json:"decision"`
	Reason           string `json:"reason"`
	CredentialIDHash string `json:"credential_id_hash,omitempty"`
	Role             string `json:"role,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Origin           string `json:"origin,omitempty"`
	RPID             string `json:"rp_id,omitempty"`
	DetailsJSON      string `json:"details_json,omitempty"`
	CreatedAt        string `json:"created_at"`
}

type AdminWebAuthnCredentialSummary struct {
	EnrolledUsers      int    `json:"enrolled_users"`
	EnabledCredentials int    `json:"enabled_credentials"`
	RevokedCredentials int    `json:"revoked_credentials"`
	PendingChallenges  int    `json:"pending_challenges"`
	ExpiredChallenges  int    `json:"expired_challenges"`
	LastEnrollmentAt   string `json:"last_enrollment_at,omitempty"`
	LastUsedAt         string `json:"last_used_at,omitempty"`
}

type AdminWebAuthnEventSummary struct {
	TotalRecords         int    `json:"total_records"`
	RegistrationCount    int    `json:"registration_count"`
	ChallengeIssuedCount int    `json:"challenge_issued_count"`
	AcceptedCount        int    `json:"accepted_count"`
	DeniedCount          int    `json:"denied_count"`
	MonitorAllowedCount  int    `json:"monitor_allowed_count"`
	LastObservedAt       string `json:"last_observed_at,omitempty"`
	LastDecision         string `json:"last_decision,omitempty"`
	LastReason           string `json:"last_reason,omitempty"`
	LastCeremony         string `json:"last_ceremony,omitempty"`
}

func HashAdminWebAuthnCredentialID(credentialID []byte) string {
	sum := sha256.Sum256(credentialID)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HashAdminWebAuthnState(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func HashAdminWebAuthnChallenge(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func UpsertAdminWebAuthnCredential(record AdminWebAuthnCredential, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.CredentialIDHash) == "" ||
		strings.TrimSpace(record.CredentialIDB64) == "" || strings.TrimSpace(record.UsernameHash) == "" ||
		strings.TrimSpace(record.Subject) == "" || strings.TrimSpace(record.PublicKeyCOSEB64) == "" {
		return fmt.Errorf("credential id, username hash, subject, and public key are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	transportsJSON := encodeAdminWebAuthnStringArray(record.Transports)
	updatedAt := now.UTC().Format(time.RFC3339)
	_, err := DB.Exec(`INSERT INTO admin_webauthn_credentials
		(id, credential_id_hash, credential_id_b64, username_hash, subject, display_name, credential_name,
		 public_key_cose_b64, public_key_alg, sign_count, transports_json, aaguid, attestation_format,
		 user_verified_required, backup_eligible, backup_state, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(credential_id_hash) DO UPDATE SET
			username_hash = excluded.username_hash,
			subject = excluded.subject,
			display_name = excluded.display_name,
			credential_name = excluded.credential_name,
			public_key_cose_b64 = excluded.public_key_cose_b64,
			public_key_alg = excluded.public_key_alg,
			sign_count = excluded.sign_count,
			transports_json = excluded.transports_json,
			aaguid = excluded.aaguid,
			attestation_format = excluded.attestation_format,
			user_verified_required = excluded.user_verified_required,
			backup_eligible = excluded.backup_eligible,
			backup_state = excluded.backup_state,
			enabled = excluded.enabled,
			revoked_at = NULL,
			revoked_by = NULL,
			updated_at = excluded.updated_at`,
		strings.TrimSpace(record.ID), strings.TrimSpace(record.CredentialIDHash), strings.TrimSpace(record.CredentialIDB64),
		strings.TrimSpace(record.UsernameHash), strings.TrimSpace(record.Subject), nullString(record.DisplayName),
		nullString(record.CredentialName), strings.TrimSpace(record.PublicKeyCOSEB64), record.PublicKeyAlg,
		record.SignCount, transportsJSON, nullString(record.AAGUID), nullString(record.AttestationFormat),
		boolToSQLite(record.UserVerifiedRequired), boolToSQLite(record.BackupEligible), boolToSQLite(record.BackupState),
		boolToSQLite(record.Enabled), updatedAt)
	if err != nil {
		return fmt.Errorf("upsert admin WebAuthn credential: %w", err)
	}
	return nil
}

func GetAdminWebAuthnCredentialByHash(credentialIDHash string) (AdminWebAuthnCredential, bool, error) {
	if DB == nil {
		return AdminWebAuthnCredential{}, false, fmt.Errorf("database not initialized")
	}
	credentialIDHash = strings.TrimSpace(credentialIDHash)
	if credentialIDHash == "" {
		return AdminWebAuthnCredential{}, false, nil
	}
	var item AdminWebAuthnCredential
	var transportsRaw string
	var enabled, uvRequired, backupEligible, backupState int
	err := DB.QueryRow(`SELECT id, credential_id_hash, credential_id_b64, username_hash, subject,
		COALESCE(display_name, ''), COALESCE(credential_name, ''), public_key_cose_b64, public_key_alg,
		COALESCE(sign_count, 0), COALESCE(transports_json, '[]'), COALESCE(aaguid, ''),
		COALESCE(attestation_format, ''), COALESCE(user_verified_required, 0),
		COALESCE(backup_eligible, 0), COALESCE(backup_state, 0), COALESCE(enabled, 1),
		COALESCE(created_at, ''), COALESCE(updated_at, ''), COALESCE(last_used_at, ''),
		COALESCE(revoked_at, ''), COALESCE(revoked_by, '')
		FROM admin_webauthn_credentials WHERE credential_id_hash = ?`, credentialIDHash).
		Scan(&item.ID, &item.CredentialIDHash, &item.CredentialIDB64, &item.UsernameHash, &item.Subject,
			&item.DisplayName, &item.CredentialName, &item.PublicKeyCOSEB64, &item.PublicKeyAlg, &item.SignCount,
			&transportsRaw, &item.AAGUID, &item.AttestationFormat, &uvRequired, &backupEligible, &backupState,
			&enabled, &item.CreatedAt, &item.UpdatedAt, &item.LastUsedAt, &item.RevokedAt, &item.RevokedBy)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return AdminWebAuthnCredential{}, false, nil
		}
		return AdminWebAuthnCredential{}, false, fmt.Errorf("get admin WebAuthn credential: %w", err)
	}
	item.Transports = decodeAdminWebAuthnStringArray(transportsRaw)
	item.Enabled = enabled == 1
	item.UserVerifiedRequired = uvRequired == 1
	item.BackupEligible = backupEligible == 1
	item.BackupState = backupState == 1
	return item, true, nil
}

func ListAdminWebAuthnCredentials(subject string, includeRevoked bool, limit int) ([]AdminWebAuthnCredential, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	query := `SELECT id, credential_id_hash, credential_id_b64, username_hash, subject,
		COALESCE(display_name, ''), COALESCE(credential_name, ''), public_key_cose_b64, public_key_alg,
		COALESCE(sign_count, 0), COALESCE(transports_json, '[]'), COALESCE(aaguid, ''),
		COALESCE(attestation_format, ''), COALESCE(user_verified_required, 0),
		COALESCE(backup_eligible, 0), COALESCE(backup_state, 0), COALESCE(enabled, 1),
		COALESCE(created_at, ''), COALESCE(updated_at, ''), COALESCE(last_used_at, ''),
		COALESCE(revoked_at, ''), COALESCE(revoked_by, '')
		FROM admin_webauthn_credentials WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(subject) != "" {
		query += ` AND subject = ?`
		args = append(args, strings.TrimSpace(subject))
	}
	if !includeRevoked {
		query += ` AND revoked_at IS NULL AND enabled = 1`
	}
	query += ` ORDER BY datetime(updated_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list admin WebAuthn credentials: %w", err)
	}
	defer rows.Close()
	items := []AdminWebAuthnCredential{}
	for rows.Next() {
		var item AdminWebAuthnCredential
		var transportsRaw string
		var enabled, uvRequired, backupEligible, backupState int
		if err := rows.Scan(&item.ID, &item.CredentialIDHash, &item.CredentialIDB64, &item.UsernameHash, &item.Subject,
			&item.DisplayName, &item.CredentialName, &item.PublicKeyCOSEB64, &item.PublicKeyAlg, &item.SignCount,
			&transportsRaw, &item.AAGUID, &item.AttestationFormat, &uvRequired, &backupEligible, &backupState,
			&enabled, &item.CreatedAt, &item.UpdatedAt, &item.LastUsedAt, &item.RevokedAt, &item.RevokedBy); err != nil {
			return nil, fmt.Errorf("scan admin WebAuthn credential: %w", err)
		}
		item.Transports = decodeAdminWebAuthnStringArray(transportsRaw)
		item.Enabled = enabled == 1
		item.UserVerifiedRequired = uvRequired == 1
		item.BackupEligible = backupEligible == 1
		item.BackupState = backupState == 1
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin WebAuthn credentials: %w", err)
	}
	return items, nil
}

func RevokeAdminWebAuthnCredential(id, actor string, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("credential id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := DB.Exec(`UPDATE admin_webauthn_credentials
		SET enabled = 0, revoked_at = ?, revoked_by = ?, updated_at = ?
		WHERE id = ? AND revoked_at IS NULL`,
		now.UTC().Format(time.RFC3339), nullString(actor), now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("revoke admin WebAuthn credential: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("credential not found or already revoked")
	}
	return nil
}

func TouchAdminWebAuthnCredentialUse(credentialIDHash string, signCount uint32, backupState bool, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := DB.Exec(`UPDATE admin_webauthn_credentials
		SET sign_count = ?, backup_state = ?, last_used_at = ?, updated_at = ?
		WHERE credential_id_hash = ?`,
		signCount, boolToSQLite(backupState), now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), credentialIDHash)
	if err != nil {
		return fmt.Errorf("touch admin WebAuthn credential: %w", err)
	}
	return nil
}

func InsertAdminWebAuthnChallenge(record AdminWebAuthnChallenge, details any) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.StateHash) == "" ||
		strings.TrimSpace(record.Challenge) == "" || strings.TrimSpace(record.ChallengeHash) == "" ||
		strings.TrimSpace(record.Ceremony) == "" || strings.TrimSpace(record.UsernameHash) == "" ||
		strings.TrimSpace(record.Subject) == "" {
		return fmt.Errorf("challenge id, state, challenge, ceremony, username hash, and subject are required")
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal admin WebAuthn challenge details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	now := strings.TrimSpace(record.CreatedAt)
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}
	status := strings.TrimSpace(record.Status)
	if status == "" {
		status = "pending"
	}
	if record.MaxAttempts <= 0 {
		record.MaxAttempts = 5
	}
	_, err := DB.Exec(`INSERT INTO admin_webauthn_challenges
		(id, state_hash, challenge, challenge_hash, ceremony, status, username_hash, subject, display_name,
		 credential_name, role, source, provider, tenants_json, groups_json, first_factor, origin, rp_id,
		 attempt_count, max_attempts, expires_at, created_at, updated_at, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ID), strings.TrimSpace(record.StateHash), strings.TrimSpace(record.Challenge),
		strings.TrimSpace(record.ChallengeHash), strings.TrimSpace(record.Ceremony), status,
		strings.TrimSpace(record.UsernameHash), strings.TrimSpace(record.Subject), nullString(record.DisplayName),
		nullString(record.CredentialName), nullString(record.Role), nullString(record.Source), nullString(record.Provider),
		encodeAdminWebAuthnStringArray(record.Tenants), encodeAdminWebAuthnStringArray(record.Groups),
		nullString(record.FirstFactor), nullString(record.Origin), nullString(record.RPID), record.AttemptCount,
		record.MaxAttempts, strings.TrimSpace(record.ExpiresAt), now, now, detailsJSON)
	if err != nil {
		return fmt.Errorf("insert admin WebAuthn challenge: %w", err)
	}
	return nil
}

func GetAdminWebAuthnChallengeByStateHash(stateHash string, now time.Time) (AdminWebAuthnChallenge, bool, error) {
	if DB == nil {
		return AdminWebAuthnChallenge{}, false, fmt.Errorf("database not initialized")
	}
	stateHash = strings.TrimSpace(stateHash)
	if stateHash == "" {
		return AdminWebAuthnChallenge{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var item AdminWebAuthnChallenge
	var tenantsRaw, groupsRaw string
	err := DB.QueryRow(`SELECT id, state_hash, challenge, challenge_hash, ceremony, status, username_hash,
		subject, COALESCE(display_name, ''), COALESCE(credential_name, ''), COALESCE(role, ''),
		COALESCE(source, ''), COALESCE(provider, ''), COALESCE(tenants_json, '[]'), COALESCE(groups_json, '[]'),
		COALESCE(first_factor, ''), COALESCE(origin, ''), COALESCE(rp_id, ''), COALESCE(attempt_count, 0),
		COALESCE(max_attempts, 0), COALESCE(expires_at, ''), COALESCE(created_at, ''), COALESCE(updated_at, ''),
		COALESCE(verified_at, ''), COALESCE(failure_reason, ''), COALESCE(details_json, '{}')
		FROM admin_webauthn_challenges WHERE state_hash = ?`, stateHash).
		Scan(&item.ID, &item.StateHash, &item.Challenge, &item.ChallengeHash, &item.Ceremony, &item.Status,
			&item.UsernameHash, &item.Subject, &item.DisplayName, &item.CredentialName, &item.Role, &item.Source,
			&item.Provider, &tenantsRaw, &groupsRaw, &item.FirstFactor, &item.Origin, &item.RPID,
			&item.AttemptCount, &item.MaxAttempts, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt,
			&item.VerifiedAt, &item.FailureReason, &item.DetailsJSON)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return AdminWebAuthnChallenge{}, false, nil
		}
		return AdminWebAuthnChallenge{}, false, fmt.Errorf("get admin WebAuthn challenge: %w", err)
	}
	item.Tenants = decodeAdminWebAuthnStringArray(tenantsRaw)
	item.Groups = decodeAdminWebAuthnStringArray(groupsRaw)
	if item.Status == "pending" && item.ExpiresAt != "" {
		if expiresAt, err := time.Parse(time.RFC3339, item.ExpiresAt); err == nil && !expiresAt.After(now.UTC()) {
			_ = UpdateAdminWebAuthnChallengeStatus(item.ID, "expired", item.AttemptCount, "challenge expired", now)
			item.Status = "expired"
			item.FailureReason = "challenge expired"
		}
	}
	return item, true, nil
}

func UpdateAdminWebAuthnChallengeStatus(id, status string, attemptCount int, failureReason string, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("challenge id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	verifiedAt := sql.NullString{}
	if status == "verified" {
		verifiedAt.Valid = true
		verifiedAt.String = now.UTC().Format(time.RFC3339)
	}
	_, err := DB.Exec(`UPDATE admin_webauthn_challenges
		SET status = ?, attempt_count = ?, failure_reason = ?, updated_at = ?, verified_at = COALESCE(?, verified_at)
		WHERE id = ?`,
		strings.TrimSpace(status), attemptCount, strings.TrimSpace(failureReason), now.UTC().Format(time.RFC3339),
		verifiedAt, id)
	if err != nil {
		return fmt.Errorf("update admin WebAuthn challenge: %w", err)
	}
	return nil
}

func RecordAdminWebAuthnEvent(record AdminWebAuthnEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxAdminWebAuthnEvents
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal admin WebAuthn event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	if strings.TrimSpace(record.ObservedAt) == "" {
		record.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if _, err := DB.Exec(`INSERT INTO admin_webauthn_events
		(observed_at, username_hash, subject, source, ceremony, decision, reason, credential_id_hash,
		 role, provider, origin, rp_id, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ObservedAt), strings.TrimSpace(record.UsernameHash), nullString(record.Subject),
		strings.TrimSpace(record.Source), strings.TrimSpace(record.Ceremony), strings.TrimSpace(record.Decision),
		strings.TrimSpace(record.Reason), nullString(record.CredentialIDHash), nullString(record.Role),
		nullString(record.Provider), nullString(record.Origin), nullString(record.RPID), detailsJSON); err != nil {
		return fmt.Errorf("insert admin WebAuthn event: %w", err)
	}
	return trimAdminWebAuthnEvents(retentionLimit)
}

func ListAdminWebAuthnEvents(decision, ceremony string, limit int) ([]AdminWebAuthnEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	query := `SELECT id, COALESCE(observed_at, ''), COALESCE(username_hash, ''), COALESCE(subject, ''),
		COALESCE(source, ''), COALESCE(ceremony, ''), COALESCE(decision, ''), COALESCE(reason, ''),
		COALESCE(credential_id_hash, ''), COALESCE(role, ''), COALESCE(provider, ''), COALESCE(origin, ''),
		COALESCE(rp_id, ''), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM admin_webauthn_events WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(decision) != "" {
		query += ` AND decision = ?`
		args = append(args, strings.TrimSpace(decision))
	}
	if strings.TrimSpace(ceremony) != "" {
		query += ` AND ceremony = ?`
		args = append(args, strings.TrimSpace(ceremony))
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list admin WebAuthn events: %w", err)
	}
	defer rows.Close()
	events := []AdminWebAuthnEvent{}
	for rows.Next() {
		var item AdminWebAuthnEvent
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.UsernameHash, &item.Subject, &item.Source,
			&item.Ceremony, &item.Decision, &item.Reason, &item.CredentialIDHash, &item.Role, &item.Provider,
			&item.Origin, &item.RPID, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan admin WebAuthn event: %w", err)
		}
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin WebAuthn events: %w", err)
	}
	return events, nil
}

func GetAdminWebAuthnCredentialSummary(now time.Time) (AdminWebAuthnCredentialSummary, error) {
	if DB == nil {
		return AdminWebAuthnCredentialSummary{}, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var summary AdminWebAuthnCredentialSummary
	if err := DB.QueryRow(`SELECT
		COUNT(DISTINCT CASE WHEN enabled = 1 AND revoked_at IS NULL THEN username_hash ELSE NULL END),
		COALESCE(SUM(CASE WHEN enabled = 1 AND revoked_at IS NULL THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN revoked_at IS NOT NULL OR enabled = 0 THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), ''),
		COALESCE(MAX(last_used_at), '')
		FROM admin_webauthn_credentials`).Scan(&summary.EnrolledUsers, &summary.EnabledCredentials,
		&summary.RevokedCredentials, &summary.LastEnrollmentAt, &summary.LastUsedAt); err != nil {
		return summary, fmt.Errorf("get admin WebAuthn credential summary: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'pending' AND datetime(expires_at) > datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' OR (status = 'pending' AND datetime(expires_at) <= datetime(?)) THEN 1 ELSE 0 END), 0)
		FROM admin_webauthn_challenges`, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).
		Scan(&summary.PendingChallenges, &summary.ExpiredChallenges)
	return summary, nil
}

func GetAdminWebAuthnEventSummary() (AdminWebAuthnEventSummary, error) {
	if DB == nil {
		return AdminWebAuthnEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AdminWebAuthnEventSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'registered' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'challenge_issued' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'monitor_allowed' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM admin_webauthn_events`).Scan(&summary.TotalRecords, &summary.RegistrationCount,
		&summary.ChallengeIssuedCount, &summary.AcceptedCount, &summary.DeniedCount,
		&summary.MonitorAllowedCount, &summary.LastObservedAt); err != nil {
		return AdminWebAuthnEventSummary{}, fmt.Errorf("get admin WebAuthn event summary: %w", err)
	}
	if summary.LastObservedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(decision, ''), COALESCE(reason, ''), COALESCE(ceremony, '')
			FROM admin_webauthn_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastDecision, &summary.LastReason, &summary.LastCeremony)
	}
	return summary, nil
}

func trimAdminWebAuthnEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM admin_webauthn_events
		WHERE id NOT IN (
			SELECT id FROM admin_webauthn_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim admin WebAuthn events: %w", err)
	}
	return nil
}

func encodeCredentialIDB64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func encodeAdminWebAuthnStringArray(values []string) string {
	normalized := []string{}
	seen := map[string]struct{}{}
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
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return "[]"
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "[]"
	}
	return string(payload)
}

func decodeAdminWebAuthnStringArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}
