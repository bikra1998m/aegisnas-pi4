package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrVendorIdentityMigrationNotFound = errors.New("vendor identity migration not found")

type VendorIdentityAssignment struct {
	PEN                 uint32     `json:"pen"`
	VendorName          string     `json:"vendor_name"`
	Organization        string     `json:"organization"`
	RegistryURL         string     `json:"registry_url"`
	RegistryLastUpdated string     `json:"registry_last_updated"`
	RegistrySHA256      string     `json:"registry_sha256"`
	RecordSHA256        string     `json:"record_sha256"`
	EvidenceJSON        string     `json:"-"`
	Active              bool       `json:"active"`
	VerifiedAt          time.Time  `json:"verified_at"`
	ActivatedAt         *time.Time `json:"activated_at,omitempty"`
	RetiredAt           *time.Time `json:"retired_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

type VendorIdentityMigration struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	FromVendorName     string     `json:"from_vendor_name"`
	FromPEN            uint32     `json:"from_pen"`
	ToVendorName       string     `json:"to_vendor_name"`
	ToPEN              uint32     `json:"to_pen"`
	Organization       string     `json:"organization"`
	EvidenceJSON       string     `json:"-"`
	BeforeJSON         string     `json:"-"`
	AfterJSON          string     `json:"-"`
	ConfigChecksum     string     `json:"config_checksum"`
	ConfirmationSHA256 string     `json:"-"`
	ExpiresAt          time.Time  `json:"expires_at"`
	CreatedBy          string     `json:"created_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	AppliedAt          *time.Time `json:"applied_at,omitempty"`
	RolledBackAt       *time.Time `json:"rolled_back_at,omitempty"`
	Failure            string     `json:"failure,omitempty"`
}

type VendorIdentityMigrationMetrics struct {
	Previewed  int64      `json:"previewed"`
	Applying   int64      `json:"applying"`
	Applied    int64      `json:"applied"`
	Failed     int64      `json:"failed"`
	RolledBack int64      `json:"rolled_back"`
	LastEvent  *time.Time `json:"last_event_at,omitempty"`
}

func CreateVendorIdentityMigration(handle *sql.DB, migration VendorIdentityMigration) error {
	if handle == nil {
		return errors.New("database handle is required")
	}
	_, err := handle.Exec(`INSERT INTO vendor_identity_migrations (
		id, status, from_vendor_name, from_pen, to_vendor_name, to_pen, organization,
		evidence_json, before_json, after_json, config_checksum, confirmation_sha256,
		expires_at, created_by, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		migration.ID, migration.Status, migration.FromVendorName, migration.FromPEN,
		migration.ToVendorName, migration.ToPEN, migration.Organization, migration.EvidenceJSON,
		migration.BeforeJSON, migration.AfterJSON, migration.ConfigChecksum,
		migration.ConfirmationSHA256, migration.ExpiresAt.UTC(), migration.CreatedBy,
		migration.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("create vendor identity migration: %w", err)
	}
	return nil
}

func GetVendorIdentityMigration(handle *sql.DB, id string) (VendorIdentityMigration, error) {
	if handle == nil {
		return VendorIdentityMigration{}, errors.New("database handle is required")
	}
	row := handle.QueryRow(`SELECT id, status, from_vendor_name, from_pen, to_vendor_name,
		to_pen, organization, evidence_json, before_json, after_json, config_checksum,
		confirmation_sha256, expires_at, COALESCE(created_by, ''), created_at,
		applied_at, rolled_back_at, COALESCE(failure, '')
		FROM vendor_identity_migrations WHERE id = ?`, id)
	migration, err := scanVendorIdentityMigration(row)
	if errors.Is(err, sql.ErrNoRows) {
		return VendorIdentityMigration{}, ErrVendorIdentityMigrationNotFound
	}
	return migration, err
}

func ListVendorIdentityMigrations(handle *sql.DB, limit int) ([]VendorIdentityMigration, error) {
	if handle == nil {
		return nil, errors.New("database handle is required")
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := handle.Query(`SELECT id, status, from_vendor_name, from_pen, to_vendor_name,
		to_pen, organization, evidence_json, before_json, after_json, config_checksum,
		confirmation_sha256, expires_at, COALESCE(created_by, ''), created_at,
		applied_at, rolled_back_at, COALESCE(failure, '')
		FROM vendor_identity_migrations ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list vendor identity migrations: %w", err)
	}
	defer rows.Close()
	var result []VendorIdentityMigration
	for rows.Next() {
		migration, err := scanVendorIdentityMigration(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, migration)
	}
	return result, rows.Err()
}

type vendorIdentityScanner interface {
	Scan(dest ...any) error
}

func scanVendorIdentityMigration(scanner vendorIdentityScanner) (VendorIdentityMigration, error) {
	var migration VendorIdentityMigration
	var appliedAt, rolledBackAt sql.NullTime
	err := scanner.Scan(
		&migration.ID, &migration.Status, &migration.FromVendorName, &migration.FromPEN,
		&migration.ToVendorName, &migration.ToPEN, &migration.Organization, &migration.EvidenceJSON,
		&migration.BeforeJSON, &migration.AfterJSON, &migration.ConfigChecksum,
		&migration.ConfirmationSHA256, &migration.ExpiresAt, &migration.CreatedBy,
		&migration.CreatedAt, &appliedAt, &rolledBackAt, &migration.Failure,
	)
	if err != nil {
		return VendorIdentityMigration{}, err
	}
	if appliedAt.Valid {
		migration.AppliedAt = &appliedAt.Time
	}
	if rolledBackAt.Valid {
		migration.RolledBackAt = &rolledBackAt.Time
	}
	return migration, nil
}

func ClaimVendorIdentityMigration(handle *sql.DB, id string, now time.Time) (bool, error) {
	result, err := handle.Exec(`UPDATE vendor_identity_migrations SET status = 'applying', failure = NULL
		WHERE id = ? AND status = 'previewed' AND expires_at >= ?`, id, now.UTC())
	if err != nil {
		return false, fmt.Errorf("claim vendor identity migration: %w", err)
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func FailVendorIdentityMigration(handle *sql.DB, id, failure string) error {
	_, err := handle.Exec(`UPDATE vendor_identity_migrations SET status = 'failed', failure = ?
		WHERE id = ? AND status IN ('previewed', 'applying')`, failure, id)
	return err
}

func CompleteVendorIdentityMigration(handle *sql.DB, migration VendorIdentityMigration, assignment VendorIdentityAssignment, now time.Time) error {
	tx, err := handle.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE vendor_identity_assignments SET active = 0, retired_at = ? WHERE active = 1 AND pen <> ?`, now.UTC(), assignment.PEN); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO vendor_identity_assignments (
		pen, vendor_name, organization, registry_url, registry_last_updated,
		registry_sha256, record_sha256, evidence_json, active, verified_at, activated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
	ON CONFLICT(pen) DO UPDATE SET vendor_name = excluded.vendor_name,
		organization = excluded.organization, registry_url = excluded.registry_url,
		registry_last_updated = excluded.registry_last_updated,
		registry_sha256 = excluded.registry_sha256, record_sha256 = excluded.record_sha256,
		evidence_json = excluded.evidence_json, active = 1, verified_at = excluded.verified_at,
		activated_at = excluded.activated_at, retired_at = NULL`, assignment.PEN,
		assignment.VendorName, assignment.Organization, assignment.RegistryURL,
		assignment.RegistryLastUpdated, assignment.RegistrySHA256, assignment.RecordSHA256,
		assignment.EvidenceJSON, assignment.VerifiedAt.UTC(), now.UTC()); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE vendor_identity_migrations SET status = 'applied', applied_at = ?, failure = NULL
		WHERE id = ? AND status = 'applying'`, now.UTC(), migration.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("vendor identity migration %s is not in applying state", migration.ID)
	}
	return tx.Commit()
}

func RollbackVendorIdentityMigration(handle *sql.DB, id string, fromPEN, toPEN uint32, now time.Time) error {
	tx, err := handle.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE vendor_identity_assignments SET active = 0, retired_at = ? WHERE pen = ?`, now.UTC(), toPEN); err != nil {
		return err
	}
	if fromPEN != 55555 {
		if _, err := tx.Exec(`UPDATE vendor_identity_assignments SET active = 1, activated_at = ?, retired_at = NULL WHERE pen = ?`, now.UTC(), fromPEN); err != nil {
			return err
		}
	}
	result, err := tx.Exec(`UPDATE vendor_identity_migrations SET status = 'rolled_back', rolled_back_at = ?
		WHERE id = ? AND status IN ('applied', 'applying', 'failed')`, now.UTC(), id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("vendor identity migration %s is not recoverable", id)
	}
	return tx.Commit()
}

func ActiveVendorIdentityAssignment(handle *sql.DB) (*VendorIdentityAssignment, error) {
	row := handle.QueryRow(`SELECT pen, vendor_name, organization, registry_url,
		registry_last_updated, registry_sha256, record_sha256, evidence_json, active,
		verified_at, activated_at, retired_at, created_at
		FROM vendor_identity_assignments WHERE active = 1 LIMIT 1`)
	var assignment VendorIdentityAssignment
	var activatedAt, retiredAt sql.NullTime
	if err := row.Scan(&assignment.PEN, &assignment.VendorName, &assignment.Organization,
		&assignment.RegistryURL, &assignment.RegistryLastUpdated, &assignment.RegistrySHA256,
		&assignment.RecordSHA256, &assignment.EvidenceJSON, &assignment.Active,
		&assignment.VerifiedAt, &activatedAt, &retiredAt, &assignment.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if activatedAt.Valid {
		assignment.ActivatedAt = &activatedAt.Time
	}
	if retiredAt.Valid {
		assignment.RetiredAt = &retiredAt.Time
	}
	return &assignment, nil
}

func VendorIdentityMetrics(handle *sql.DB) (VendorIdentityMigrationMetrics, error) {
	metrics := VendorIdentityMigrationMetrics{}
	rows, err := handle.Query(`SELECT status, COUNT(*) FROM vendor_identity_migrations GROUP BY status`)
	if err != nil {
		return metrics, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return metrics, err
		}
		switch status {
		case "previewed":
			metrics.Previewed = count
		case "applying":
			metrics.Applying = count
		case "applied":
			metrics.Applied = count
		case "failed":
			metrics.Failed = count
		case "rolled_back":
			metrics.RolledBack = count
		}
	}
	if err := rows.Err(); err != nil {
		return metrics, err
	}
	var last sql.NullString
	if err := handle.QueryRow(`SELECT MAX(COALESCE(rolled_back_at, applied_at, created_at)) FROM vendor_identity_migrations`).Scan(&last); err != nil {
		return metrics, err
	}
	if last.Valid {
		parsed := parseSessionAnalyticsTime(last.String)
		if !parsed.IsZero() {
			metrics.LastEvent = &parsed
		}
	}
	return metrics, nil
}
