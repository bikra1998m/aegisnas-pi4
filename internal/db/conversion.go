package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type ConversionOptions struct {
	TargetSchema       string
	AllowPrecisionLoss bool
}

type ConversionTable struct {
	Name         string `json:"name"`
	Rows         int64  `json:"rows"`
	SourceSHA256 string `json:"source_sha256"`
	TargetSHA256 string `json:"target_sha256"`
}

// ConversionReport describes an isolated rehearsal, never service activation.
// It intentionally contains no DSN, row values or database credentials.
type ConversionReport struct {
	SchemaVersion                  int               `json:"schema_version"`
	Status                         string            `json:"status"`
	TargetSchema                   string            `json:"target_schema"`
	TargetSchemaCreated            bool              `json:"target_schema_created"`
	OriginalVersion                int               `json:"original_database_version"`
	DatabaseVersion                int               `json:"database_version"`
	SnapshotSHA256                 string            `json:"snapshot_sha256"`
	Tables                         []ConversionTable `json:"tables"`
	Sequences                      map[string]int64  `json:"sequence_next_values"`
	TimestampValuesTruncated       int64             `json:"timestamp_values_truncated"`
	RealValuesRounded              int64             `json:"real_values_rounded"`
	ProductionActivationAuthorized bool              `json:"production_activation_authorized"`
}

var conversionSchemaName = regexp.MustCompile(`^aegis_conversion_[a-z0-9_]{1,40}$`)

// ConvertSQLiteToPostgreSQL snapshots and upgrades a private SQLite copy, then
// imports into a NEW, owner-only schema. Existing schemas and active configuration
// are never modified. On failure the private target schema is retained for review;
// its data transaction is rolled back, and the receipt must not be treated as ready.
func ConvertSQLiteToPostgreSQL(ctx context.Context, source string, cfg config.DatabaseConfig,
	resolve func(context.Context, string) (string, error), options ConversionOptions) (report ConversionReport, err error) {
	report = ConversionReport{SchemaVersion: 1, Status: "failed", TargetSchema: options.TargetSchema, Sequences: map[string]int64{}}
	if normalizeBackend(cfg.Backend) != DialectPostgreSQL || !conversionSchemaName.MatchString(options.TargetSchema) {
		return report, fmt.Errorf("conversion requires PostgreSQL and a new aegis_conversion_ schema name with 1-40 lowercase letters, digits or underscores")
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	snapshot, cleanup, err := conversionSnapshot(ctx, source)
	if err != nil {
		return report, err
	}
	defer cleanup()
	file, err := os.Open(snapshot)
	if err != nil {
		return report, fmt.Errorf("open conversion snapshot")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	file.Close()
	if copyErr != nil {
		return report, fmt.Errorf("hash conversion snapshot")
	}
	report.SnapshotSHA256 = hex.EncodeToString(hash.Sum(nil))
	sqlite, err := OpenSQLite(snapshot)
	if err != nil {
		return report, fmt.Errorf("open private conversion database")
	}
	defer func() { sqlite.Close(); forgetHandle(sqlite) }()
	report.OriginalVersion, err = CurrentSchemaVersionHandle(sqlite)
	if err != nil || report.OriginalVersion < 1 || report.OriginalVersion > LatestSchemaVersion() {
		return report, fmt.Errorf("source must have a supported AegisNAS schema version between 1 and %d", LatestSchemaVersion())
	}
	if err := MigrateHandle(sqlite); err != nil {
		return report, fmt.Errorf("migrate private SQLite snapshot failed")
	}
	report.DatabaseVersion = LatestSchemaVersion()
	if err := validateConversionSQLite(ctx, sqlite); err != nil {
		return report, err
	}
	plan, err := BuildConnectionPlan(ctx, cfg, resolve)
	if err != nil {
		return report, fmt.Errorf("conversion target connection policy failed")
	}
	admin, err := openConnectionPlan(ctx, plan)
	if err != nil {
		return report, fmt.Errorf("connect conversion target failed")
	}
	defer admin.Close()
	conn, err := admin.Conn(ctx)
	if err != nil {
		return report, fmt.Errorf("open conversion schema control connection")
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(7144231, hashtext(?))", options.TargetSchema).Scan(&locked); err != nil || !locked {
		return report, fmt.Errorf("conversion schema is already in use or cannot be locked")
	}
	// The control connection stays open until conversion finishes. Closing the
	// database below releases its session advisory lock even after cancellation.
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("begin private schema creation")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "CREATE SCHEMA "+conversionQuote(options.TargetSchema)); err != nil {
		return report, fmt.Errorf("target schema must not already exist and the target role must permit schema creation")
	}
	if _, err := tx.ExecContext(ctx, "REVOKE ALL ON SCHEMA "+conversionQuote(options.TargetSchema)+" FROM PUBLIC"); err != nil {
		return report, fmt.Errorf("protect new conversion schema")
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("commit private schema creation")
	}
	report.TargetSchemaCreated = true
	// Exclude public and all caller-supplied search_path entries. Every subsequent
	// migration, insert and verification is scoped to the schema just created.
	plan.DataSourceName = setPostgreSQLParameter(plan.DataSourceName, "search_path", options.TargetSchema)
	target, err := openConnectionPlan(ctx, plan)
	if err != nil {
		return report, fmt.Errorf("connect private conversion schema")
	}
	registerHandleDialect(target, DialectPostgreSQL)
	defer func() { target.Close(); forgetHandle(target) }()
	if err := MigrateHandle(target); err != nil {
		return report, fmt.Errorf("migrate private PostgreSQL schema failed")
	}
	if err := convertSnapshotRows(ctx, sqlite, target, options, &report); err != nil {
		return report, err
	}
	report.Status = "verified_rehearsal"
	return report, nil
}

func conversionQuote(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }

func conversionSnapshot(ctx context.Context, source string) (string, func(), error) {
	noop := func() {}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 8<<30 {
		return "", noop, fmt.Errorf("source must be an existing nonempty regular SQLite file at most 8 GiB")
	}
	absolute, err := filepath.Abs(source)
	if err != nil {
		return "", noop, fmt.Errorf("resolve SQLite source")
	}
	path := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := url.URL{Scheme: "file", Path: path}
	u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}.Encode()
	handle, err := sql.Open("sqlite", u.String())
	if err != nil {
		return "", noop, fmt.Errorf("open read-only SQLite source")
	}
	defer handle.Close()
	directory, err := os.MkdirTemp("", "aegis-conversion-*")
	if err != nil {
		return "", noop, fmt.Errorf("create private conversion workspace")
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	snapshot := filepath.Join(directory, "snapshot.db")
	if _, err := handle.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("snapshot SQLite source failed")
	}
	info, err = os.Stat(snapshot)
	if err != nil || info.Size() > 8<<30 {
		cleanup()
		return "", noop, fmt.Errorf("SQLite snapshot exceeds 8 GiB limit")
	}
	if err := os.Chmod(snapshot, 0600); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("protect SQLite snapshot")
	}
	return snapshot, cleanup, nil
}

func validateConversionSQLite(ctx context.Context, source *sql.DB) error {
	var integrity string
	if err := source.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("conversion snapshot integrity check failed")
	}
	rows, err := source.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("check conversion source foreign keys")
	}
	invalid := rows.Next()
	scanErr := rows.Err()
	rows.Close()
	if invalid || scanErr != nil {
		return fmt.Errorf("conversion source contains invalid foreign keys")
	}
	var custom int
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").Scan(&custom); err != nil || custom != 0 {
		return fmt.Errorf("conversion does not support source views or triggers")
	}
	return nil
}

// Migration helpers currently use their own SQL transactions; target DDL is
// intentionally retained on failure. Only the row import is a single transaction.
// Successful conversion never edits service DSNs or grants application roles access.
