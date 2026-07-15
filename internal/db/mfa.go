package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const maxMFAEvents = 6000

var mfaRecoveryCodeBcryptCost = bcrypt.DefaultCost
var mfaRecoveryCodeHashFunc = func(code string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(code), mfaRecoveryCodeBcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash MFA recovery code: %w", err)
	}
	return string(hash), nil
}
var mfaRecoveryCodeCompareFunc = func(hash, code string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil
}

func SetMFARecoveryCodeBcryptCostForTesting(cost int) func() {
	previous := mfaRecoveryCodeBcryptCost
	mfaRecoveryCodeBcryptCost = cost
	return func() {
		mfaRecoveryCodeBcryptCost = previous
	}
}

func SetMFARecoveryCodeHasherForTesting(hashFunc func(string) (string, error), compareFunc func(string, string) bool) func() {
	previousHash := mfaRecoveryCodeHashFunc
	previousCompare := mfaRecoveryCodeCompareFunc
	mfaRecoveryCodeHashFunc = hashFunc
	mfaRecoveryCodeCompareFunc = compareFunc
	return func() {
		mfaRecoveryCodeHashFunc = previousHash
		mfaRecoveryCodeCompareFunc = previousCompare
	}
}

type MFATOTPSecret struct {
	ID               int    `json:"id"`
	UsernameHash     string `json:"username_hash"`
	SecretCiphertext string `json:"-"`
	SecretNonce      string `json:"-"`
	Algorithm        string `json:"algorithm"`
	Digits           int    `json:"digits"`
	PeriodSeconds    int    `json:"period_seconds"`
	Issuer           string `json:"issuer"`
	Enabled          bool   `json:"enabled"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	LastVerifiedAt   string `json:"last_verified_at,omitempty"`
}

type MFAChallenge struct {
	ID             string `json:"id"`
	StateHash      string `json:"-"`
	UsernameHash   string `json:"username_hash"`
	Source         string `json:"source"`
	Role           string `json:"role,omitempty"`
	IdentitySource string `json:"identity_source,omitempty"`
	AuthMethod     string `json:"auth_method,omitempty"`
	ChallengeType  string `json:"challenge_type"`
	Status         string `json:"status"`
	AttemptCount   int    `json:"attempt_count"`
	MaxAttempts    int    `json:"max_attempts"`
	Prompt         string `json:"prompt,omitempty"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	VerifiedAt     string `json:"verified_at,omitempty"`
	FailureReason  string `json:"failure_reason,omitempty"`
	DetailsJSON    string `json:"details_json,omitempty"`
}

type MFAEvent struct {
	ID             int    `json:"id"`
	ObservedAt     string `json:"observed_at"`
	UsernameHash   string `json:"username_hash"`
	Source         string `json:"source"`
	Method         string `json:"method"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	ChallengeID    string `json:"challenge_id,omitempty"`
	Role           string `json:"role,omitempty"`
	IdentitySource string `json:"identity_source,omitempty"`
	AuthMethod     string `json:"auth_method,omitempty"`
	DetailsJSON    string `json:"details_json,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type MFAEventSummary struct {
	TotalRecords         int    `json:"total_records"`
	ChallengeIssuedCount int    `json:"challenge_issued_count"`
	AcceptedCount        int    `json:"accepted_count"`
	DeniedCount          int    `json:"denied_count"`
	MonitorAllowedCount  int    `json:"monitor_allowed_count"`
	EnrollmentCount      int    `json:"enrollment_count"`
	RecoveryUsedCount    int    `json:"recovery_used_count"`
	LastObservedAt       string `json:"last_observed_at,omitempty"`
	LastDecision         string `json:"last_decision,omitempty"`
	LastReason           string `json:"last_reason,omitempty"`
	LastMethod           string `json:"last_method,omitempty"`
}

type MFACredentialSummary struct {
	EnrolledUsers          int    `json:"enrolled_users"`
	EnabledUsers           int    `json:"enabled_users"`
	RecoveryCodesAvailable int    `json:"recovery_codes_available"`
	RecoveryCodesUsed      int    `json:"recovery_codes_used"`
	PendingChallenges      int    `json:"pending_challenges"`
	ExpiredChallenges      int    `json:"expired_challenges"`
	LastEnrollmentAt       string `json:"last_enrollment_at,omitempty"`
	LastVerifiedAt         string `json:"last_verified_at,omitempty"`
}

func UpsertMFATOTPSecret(username, ciphertext, nonce, algorithm string, digits, periodSeconds int, issuer string, enabled bool, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return fmt.Errorf("username is required")
	}
	if strings.TrimSpace(ciphertext) == "" || strings.TrimSpace(nonce) == "" {
		return fmt.Errorf("ciphertext and nonce are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	_, err := DB.Exec(`INSERT INTO mfa_totp_secrets
		(username_hash, secret_ciphertext, secret_nonce, algorithm, digits, period_seconds, issuer, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username_hash) DO UPDATE SET
			secret_ciphertext = excluded.secret_ciphertext,
			secret_nonce = excluded.secret_nonce,
			algorithm = excluded.algorithm,
			digits = excluded.digits,
			period_seconds = excluded.period_seconds,
			issuer = excluded.issuer,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at,
			last_verified_at = NULL`,
		usernameHash, strings.TrimSpace(ciphertext), strings.TrimSpace(nonce), strings.TrimSpace(algorithm),
		digits, periodSeconds, strings.TrimSpace(issuer), boolToSQLite(enabled), updatedAt)
	if err != nil {
		return fmt.Errorf("upsert MFA TOTP secret: %w", err)
	}
	return nil
}

func GetMFATOTPSecret(username string) (MFATOTPSecret, bool, error) {
	if DB == nil {
		return MFATOTPSecret{}, false, fmt.Errorf("database not initialized")
	}
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return MFATOTPSecret{}, false, nil
	}
	var item MFATOTPSecret
	var enabled int
	err := DB.QueryRow(`SELECT id, username_hash, secret_ciphertext, secret_nonce, algorithm, digits,
		period_seconds, issuer, enabled, COALESCE(created_at, ''), COALESCE(updated_at, ''),
		COALESCE(last_verified_at, '')
		FROM mfa_totp_secrets WHERE username_hash = ?`, usernameHash).
		Scan(&item.ID, &item.UsernameHash, &item.SecretCiphertext, &item.SecretNonce, &item.Algorithm,
			&item.Digits, &item.PeriodSeconds, &item.Issuer, &enabled, &item.CreatedAt, &item.UpdatedAt, &item.LastVerifiedAt)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return MFATOTPSecret{}, false, nil
		}
		return MFATOTPSecret{}, false, fmt.Errorf("get MFA TOTP secret: %w", err)
	}
	item.Enabled = enabled == 1
	return item, true, nil
}

func TouchMFATOTPVerified(username string, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return fmt.Errorf("username is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := DB.Exec(`UPDATE mfa_totp_secrets SET last_verified_at = ?, updated_at = ? WHERE username_hash = ?`,
		now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), usernameHash)
	if err != nil {
		return fmt.Errorf("touch MFA TOTP verification: %w", err)
	}
	return nil
}

func ReplaceMFARecoveryCodes(username string, codeHashes []string, expiresAt string, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" {
		return fmt.Errorf("username is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("begin MFA recovery code replacement: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM mfa_recovery_codes WHERE username_hash = ? AND used_at IS NULL`, usernameHash); err != nil {
		return fmt.Errorf("delete active MFA recovery codes: %w", err)
	}
	createdAt := now.UTC().Format(time.RFC3339)
	for _, hash := range codeHashes {
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO mfa_recovery_codes (username_hash, code_hash, expires_at, created_at)
			VALUES (?, ?, ?, ?)`, usernameHash, hash, nullString(expiresAt), createdAt); err != nil {
			return fmt.Errorf("insert MFA recovery code: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MFA recovery code replacement: %w", err)
	}
	return nil
}

func VerifyMFARecoveryCode(username, code string, now time.Time) (bool, error) {
	if DB == nil {
		return false, fmt.Errorf("database not initialized")
	}
	usernameHash := HashIdentityUsername(username)
	if usernameHash == "" || strings.TrimSpace(code) == "" {
		return false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := DB.Query(`SELECT id, code_hash FROM mfa_recovery_codes
		WHERE username_hash = ? AND used_at IS NULL
			AND (expires_at IS NULL OR datetime(expires_at) > datetime(?))
		ORDER BY id ASC`, usernameHash, now.UTC().Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("list MFA recovery codes: %w", err)
	}
	type candidate struct {
		id   int
		hash string
	}
	candidates := []candidate{}
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.hash); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("scan MFA recovery code: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, fmt.Errorf("iterate MFA recovery codes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("close MFA recovery code cursor: %w", err)
	}
	for _, item := range candidates {
		if mfaRecoveryCodeCompareFunc(item.hash, code) {
			if _, err := DB.Exec(`UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
				now.UTC().Format(time.RFC3339), item.id); err != nil {
				return false, fmt.Errorf("consume MFA recovery code: %w", err)
			}
			return true, nil
		}
	}
	return false, nil
}

func HashMFARecoveryCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("recovery code is required")
	}
	return mfaRecoveryCodeHashFunc(code)
}

func InsertMFAChallenge(record MFAChallenge, details any) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.StateHash) == "" || strings.TrimSpace(record.UsernameHash) == "" {
		return fmt.Errorf("challenge id, state hash, and username hash are required")
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal MFA challenge details: %w", err)
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
	challengeType := strings.TrimSpace(record.ChallengeType)
	if challengeType == "" {
		challengeType = "totp"
	}
	if record.MaxAttempts <= 0 {
		record.MaxAttempts = 5
	}
	_, err := DB.Exec(`INSERT INTO mfa_challenges
		(id, state_hash, username_hash, source, role, identity_source, auth_method, challenge_type,
		 status, attempt_count, max_attempts, prompt, expires_at, created_at, updated_at, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ID), strings.TrimSpace(record.StateHash), strings.TrimSpace(record.UsernameHash),
		strings.TrimSpace(record.Source), strings.TrimSpace(record.Role), strings.TrimSpace(record.IdentitySource),
		strings.TrimSpace(record.AuthMethod), challengeType, status, record.AttemptCount, record.MaxAttempts,
		strings.TrimSpace(record.Prompt), strings.TrimSpace(record.ExpiresAt), now, now, detailsJSON)
	if err != nil {
		return fmt.Errorf("insert MFA challenge: %w", err)
	}
	return nil
}

func GetMFAChallengeByStateHash(stateHash string, now time.Time) (MFAChallenge, bool, error) {
	if DB == nil {
		return MFAChallenge{}, false, fmt.Errorf("database not initialized")
	}
	stateHash = strings.TrimSpace(stateHash)
	if stateHash == "" {
		return MFAChallenge{}, false, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var item MFAChallenge
	err := DB.QueryRow(`SELECT id, state_hash, username_hash, COALESCE(source, ''), COALESCE(role, ''),
		COALESCE(identity_source, ''), COALESCE(auth_method, ''), COALESCE(challenge_type, ''),
		COALESCE(status, ''), COALESCE(attempt_count, 0), COALESCE(max_attempts, 0), COALESCE(prompt, ''),
		COALESCE(expires_at, ''), COALESCE(created_at, ''), COALESCE(updated_at, ''),
		COALESCE(verified_at, ''), COALESCE(failure_reason, ''), COALESCE(details_json, '{}')
		FROM mfa_challenges WHERE state_hash = ?`, stateHash).
		Scan(&item.ID, &item.StateHash, &item.UsernameHash, &item.Source, &item.Role, &item.IdentitySource,
			&item.AuthMethod, &item.ChallengeType, &item.Status, &item.AttemptCount, &item.MaxAttempts,
			&item.Prompt, &item.ExpiresAt, &item.CreatedAt, &item.UpdatedAt, &item.VerifiedAt,
			&item.FailureReason, &item.DetailsJSON)
	if err != nil {
		if err == sql.ErrNoRows || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return MFAChallenge{}, false, nil
		}
		return MFAChallenge{}, false, fmt.Errorf("get MFA challenge: %w", err)
	}
	if item.Status == "pending" && item.ExpiresAt != "" {
		if expiresAt, err := time.Parse(time.RFC3339, item.ExpiresAt); err == nil && !expiresAt.After(now.UTC()) {
			_ = UpdateMFAChallengeStatus(item.ID, "expired", item.AttemptCount, "challenge expired", now)
			item.Status = "expired"
			item.FailureReason = "challenge expired"
		}
	}
	return item, true, nil
}

func UpdateMFAChallengeStatus(id, status string, attemptCount int, failureReason string, now time.Time) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(id) == "" {
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
	_, err := DB.Exec(`UPDATE mfa_challenges
		SET status = ?, attempt_count = ?, failure_reason = ?, updated_at = ?, verified_at = COALESCE(?, verified_at)
		WHERE id = ?`,
		strings.TrimSpace(status), attemptCount, strings.TrimSpace(failureReason), now.UTC().Format(time.RFC3339),
		verifiedAt, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("update MFA challenge: %w", err)
	}
	return nil
}

func RecordMFAEvent(record MFAEvent, details any, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if retentionLimit <= 0 {
		retentionLimit = maxMFAEvents
	}
	detailsJSON := strings.TrimSpace(record.DetailsJSON)
	if details != nil {
		payload, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal MFA event details: %w", err)
		}
		detailsJSON = string(payload)
	}
	if detailsJSON == "" {
		detailsJSON = "{}"
	}
	if strings.TrimSpace(record.ObservedAt) == "" {
		record.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if _, err := DB.Exec(`INSERT INTO mfa_events
		(observed_at, username_hash, source, method, decision, reason, challenge_id, role, identity_source, auth_method, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(record.ObservedAt), strings.TrimSpace(record.UsernameHash), strings.TrimSpace(record.Source),
		strings.TrimSpace(record.Method), strings.TrimSpace(record.Decision), strings.TrimSpace(record.Reason),
		strings.TrimSpace(record.ChallengeID), strings.TrimSpace(record.Role), strings.TrimSpace(record.IdentitySource),
		strings.TrimSpace(record.AuthMethod), detailsJSON); err != nil {
		return fmt.Errorf("insert MFA event: %w", err)
	}
	return trimMFAEvents(retentionLimit)
}

func ListMFAEvents(decision, method string, limit int) ([]MFAEvent, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	query := `SELECT id, COALESCE(observed_at, ''), COALESCE(username_hash, ''), COALESCE(source, ''),
		COALESCE(method, ''), COALESCE(decision, ''), COALESCE(reason, ''), COALESCE(challenge_id, ''),
		COALESCE(role, ''), COALESCE(identity_source, ''), COALESCE(auth_method, ''), COALESCE(details_json, '{}'),
		COALESCE(created_at, '')
		FROM mfa_events WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(decision) != "" {
		query += ` AND decision = ?`
		args = append(args, strings.TrimSpace(decision))
	}
	if strings.TrimSpace(method) != "" {
		query += ` AND method = ?`
		args = append(args, strings.TrimSpace(method))
	}
	query += ` ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list MFA events: %w", err)
	}
	defer rows.Close()
	events := []MFAEvent{}
	for rows.Next() {
		var item MFAEvent
		if err := rows.Scan(&item.ID, &item.ObservedAt, &item.UsernameHash, &item.Source, &item.Method,
			&item.Decision, &item.Reason, &item.ChallengeID, &item.Role, &item.IdentitySource, &item.AuthMethod,
			&item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan MFA event: %w", err)
		}
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate MFA events: %w", err)
	}
	return events, nil
}

func GetMFAEventSummary() (MFAEventSummary, error) {
	if DB == nil {
		return MFAEventSummary{}, fmt.Errorf("database not initialized")
	}
	var summary MFAEventSummary
	if err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'challenge_issued' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'monitor_allowed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'enrolled' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN method = 'recovery' AND decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM mfa_events`).Scan(&summary.TotalRecords, &summary.ChallengeIssuedCount, &summary.AcceptedCount,
		&summary.DeniedCount, &summary.MonitorAllowedCount, &summary.EnrollmentCount, &summary.RecoveryUsedCount,
		&summary.LastObservedAt); err != nil {
		return MFAEventSummary{}, fmt.Errorf("get MFA event summary: %w", err)
	}
	if summary.LastObservedAt != "" {
		_ = DB.QueryRow(`SELECT COALESCE(decision, ''), COALESCE(reason, ''), COALESCE(method, '')
			FROM mfa_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT 1`).
			Scan(&summary.LastDecision, &summary.LastReason, &summary.LastMethod)
	}
	return summary, nil
}

func GetMFACredentialSummary(now time.Time) (MFACredentialSummary, error) {
	if DB == nil {
		return MFACredentialSummary{}, fmt.Errorf("database not initialized")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var summary MFACredentialSummary
	if err := DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(created_at), ''), COALESCE(MAX(last_verified_at), '')
		FROM mfa_totp_secrets`).Scan(&summary.EnrolledUsers, &summary.EnabledUsers, &summary.LastEnrollmentAt, &summary.LastVerifiedAt); err != nil {
		return summary, fmt.Errorf("get MFA credential summary: %w", err)
	}
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN used_at IS NULL AND (expires_at IS NULL OR datetime(expires_at) > datetime(?)) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END), 0)
		FROM mfa_recovery_codes`, now.UTC().Format(time.RFC3339)).
		Scan(&summary.RecoveryCodesAvailable, &summary.RecoveryCodesUsed)
	_ = DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status = 'pending' AND datetime(expires_at) > datetime(?) THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' OR (status = 'pending' AND datetime(expires_at) <= datetime(?)) THEN 1 ELSE 0 END), 0)
		FROM mfa_challenges`, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).
		Scan(&summary.PendingChallenges, &summary.ExpiredChallenges)
	return summary, nil
}

func trimMFAEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM mfa_events
		WHERE id NOT IN (
			SELECT id FROM mfa_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim MFA events: %w", err)
	}
	return nil
}
