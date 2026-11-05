package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestConversionValueValidation(t *testing.T) {
	for _, test := range []struct {
		name, kind string
		value      any
		allow      bool
		want       any
		fail       bool
	}{
		{"null", "text", nil, false, nil, false},
		{"boolean-zero", "boolean", int64(0), false, false, false},
		{"boolean-one", "boolean", int64(1), false, true, false},
		{"boolean-invalid", "boolean", int64(2), false, nil, true},
		{"boolean-string", "boolean", "1", false, nil, true},
		{"integer-64", "bigint", int64(1) << 50, false, int64(1) << 50, false},
		{"integer-text", "bigint", "12", false, nil, true},
		{"float-integer-overflow", "double precision", int64(math.MaxInt64), false, nil, true},
		{"real-exact", "real", 0.5, false, 0.5, false},
		{"real-rounding-refused", "real", 0.1, false, nil, true},
		{"real-rounding-explicit", "real", 0.1, true, float64(float32(0.1)), false},
		{"real-overflow", "real", math.MaxFloat64, true, nil, true},
		{"nan", "double precision", math.NaN(), true, nil, true},
		{"timestamp-invalid", "timestamp with time zone", "secret-invalid-time", false, nil, true},
		{"timestamp-offset", "timestamp with time zone", "2026-01-02T06:30:00.123456+05:30", false, time.Date(2026, 1, 2, 1, 0, 0, 123456000, time.UTC), false},
		{"timestamp-truncation-refused", "timestamp with time zone", "2026-01-02T01:00:00.123456789Z", false, nil, true},
		{"timestamp-truncation-explicit", "timestamp with time zone", "2026-01-02T01:00:00.123456789Z", true, time.Date(2026, 1, 2, 1, 0, 0, 123456000, time.UTC), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := ConversionReport{}
			got, err := conversionValue(test.value, test.kind, ConversionOptions{AllowPrecisionLoss: test.allow}, &report)
			if test.fail {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "secret-invalid-time")
			} else {
				require.NoError(t, err)
				require.Equal(t, test.want, got)
			}
		})
	}
}

func TestConversionSourceAndPolicyGuards(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	missing := filepath.Join(directory, "absent.db")
	_, cleanup, err := conversionSnapshot(ctx, missing)
	cleanup()
	require.Error(t, err)
	_, err = os.Stat(missing)
	require.True(t, os.IsNotExist(err))
	for _, schema := range []string{"public", "aegis_conversion_", "aegis_conversion_x;DROP SCHEMA public", "aegis_conversion_UPPER"} {
		_, err := ConvertSQLiteToPostgreSQL(ctx, missing, config.DatabaseConfig{Backend: "postgres"}, nil, ConversionOptions{TargetSchema: schema})
		require.Error(t, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = ConvertSQLiteToPostgreSQL(cancelled, missing, config.DatabaseConfig{Backend: "postgres"}, nil, ConversionOptions{TargetSchema: "aegis_conversion_cancel"})
	require.ErrorIs(t, err, context.Canceled)
	source := filepath.Join(directory, "schema-future.db")
	handle, err := OpenSQLite(source)
	require.NoError(t, err)
	_, err = handle.Exec("CREATE TABLE schema_version(version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES(9999)")
	require.NoError(t, err)
	require.NoError(t, handle.Close())
	_, err = ConvertSQLiteToPostgreSQL(ctx, source, config.DatabaseConfig{Backend: "postgres"}, nil, ConversionOptions{TargetSchema: "aegis_conversion_future"})
	require.ErrorContains(t, err, "supported AegisNAS schema version")
}

func conversionOldSQLite(t *testing.T) (string, *sql.DB) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "old source #1's.db")
	handle, err := OpenSQLite(source)
	require.NoError(t, err)
	t.Cleanup(func() { handle.Close(); forgetHandle(handle) })
	_, err = handle.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; " + schemaV1 + "; CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP); INSERT INTO schema_version(version) VALUES(1)")
	require.NoError(t, err)
	_, err = handle.Exec(`INSERT INTO roles(id,name,priority) VALUES(900,'old-role',1099511627776),(1000,'deleted-role',0);
	 DELETE FROM roles WHERE id=1000;
	 INSERT INTO local_users(id,username,password_hash,role) VALUES(41,'original-user','fixture-hash-not-for-deployment','old-role');
	 INSERT INTO identity_sources(name,type,config,enabled) VALUES('disabled','local','{}',0);
	 INSERT INTO sessions(id,username,start_time,bytes_in,bytes_out) VALUES('Z-session','original-user','2026-01-02 03:04:05',1099511627776,2199023255552),('a-session','original-user','2026-01-02 03:04:05',42,43);`)
	require.NoError(t, err)
	return source, handle
}

func TestConversionSnapshotIncludesWAL(t *testing.T) {
	source, handle := conversionOldSQLite(t)
	before, err := os.ReadFile(source + "-wal")
	require.NoError(t, err)
	snapshot, cleanup, err := conversionSnapshot(context.Background(), source)
	require.NoError(t, err)
	defer cleanup()
	copy, err := OpenSQLite(snapshot)
	require.NoError(t, err)
	defer copy.Close()
	var value int64
	require.NoError(t, copy.QueryRow("SELECT priority FROM roles WHERE id=900").Scan(&value))
	require.Equal(t, int64(1)<<40, value)
	version, err := CurrentSchemaVersionHandle(handle)
	require.NoError(t, err)
	require.Equal(t, 1, version)
	after, err := os.ReadFile(source + "-wal")
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(before), sha256.Sum256(after))
}

func TestSQLitePostgreSQLConversionLive(t *testing.T) {
	dsn := os.Getenv("AEGIS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AEGIS_TEST_POSTGRES_DSN to a disposable PostgreSQL database for conversion rehearsals")
	}
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	cfg := config.DatabaseConfig{Backend: "postgres", SSLMode: u.Query().Get("sslmode"), DSNRef: "env:AEGIS_TEST_POSTGRES_DSN", AllowUnsafePostgreSQLSSLMode: true, MaxOpenConns: 2, ConnectTimeoutSeconds: 5, StatementTimeoutMilliseconds: 30000}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "require"
	}
	resolve := func(context.Context, string) (string, error) { return dsn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	admin, err := OpenDatabaseConfig(ctx, cfg, resolve)
	require.NoError(t, err)
	defer admin.Close()
	schema := func() string { return fmt.Sprintf("aegis_conversion_%d", time.Now().UnixNano()) }
	convert := func(t *testing.T, source string, options ConversionOptions) (ConversionReport, error) {
		t.Helper()
		report, err := ConvertSQLiteToPostgreSQL(ctx, source, cfg, resolve, options)
		if report.TargetSchemaCreated {
			t.Cleanup(func() { require.NoError(t, dropOwnedPostgreSQLTestSchema(admin, options.TargetSchema)) })
		}
		return report, err
	}
	source, sqlite := conversionOldSQLite(t)
	walBefore, err := os.ReadFile(source + "-wal")
	require.NoError(t, err)
	t.Run("OldVersionRowsConstraintsSequences", func(t *testing.T) {
		options := ConversionOptions{TargetSchema: schema()}
		report, err := convert(t, source, options)
		require.NoError(t, err)
		require.Equal(t, "verified_rehearsal", report.Status)
		require.Equal(t, 1, report.OriginalVersion)
		require.Equal(t, LatestSchemaVersion(), report.DatabaseVersion)
		require.False(t, report.ProductionActivationAuthorized)
		require.Greater(t, len(report.Tables), 175)
		for _, table := range report.Tables {
			require.Equal(t, table.SourceSHA256, table.TargetSHA256, table.Name)
		}
		require.Equal(t, int64(1001), report.Sequences["roles.id"])
		prefix := conversionQuote(options.TargetSchema) + "."
		var priority, next int64
		var enabled bool
		require.NoError(t, admin.QueryRow("SELECT priority FROM "+prefix+"roles WHERE id=900").Scan(&priority))
		require.Equal(t, int64(1)<<40, priority)
		require.NoError(t, admin.QueryRow("SELECT enabled FROM "+prefix+"identity_sources WHERE name='disabled'").Scan(&enabled))
		require.False(t, enabled)
		require.NoError(t, admin.QueryRow("INSERT INTO "+prefix+"roles(name) VALUES('next-role') RETURNING id").Scan(&next))
		require.Equal(t, int64(1001), next)
		var grants int
		require.NoError(t, admin.QueryRow(`SELECT count(*) FROM pg_namespace n, LATERAL aclexplode(n.nspacl) a WHERE n.nspname=? AND a.grantee=0`, options.TargetSchema).Scan(&grants))
		require.Zero(t, grants)
		var deferred int
		require.NoError(t, admin.QueryRow(`SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname=? AND c.contype='f' AND c.condeferrable`, options.TargetSchema).Scan(&deferred))
		require.Zero(t, deferred)
		_, err = admin.Exec("INSERT INTO " + prefix + "nas_client_enrollments(enrollment_id,source_ip,shortname,requested_at,expires_at,evidence_sha256,radius_client_id) VALUES('bad','127.0.0.1','bad',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'hash',999999)")
		require.Error(t, err, "converted FK remains enforced")
		reused, err := ConvertSQLiteToPostgreSQL(ctx, source, cfg, resolve, options)
		require.Error(t, err)
		require.False(t, reused.TargetSchemaCreated)
		var retained string
		require.NoError(t, admin.QueryRow("SELECT name FROM "+prefix+"roles WHERE id=1001").Scan(&retained))
		require.Equal(t, "next-role", retained)
	})
	version, err := CurrentSchemaVersionHandle(sqlite)
	require.NoError(t, err)
	require.Equal(t, 1, version)
	walAfter, err := os.ReadFile(source + "-wal")
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(walBefore), sha256.Sum256(walAfter))
	t.Run("PrecisionOptInAndFailedImportRollback", func(t *testing.T) {
		_, err := sqlite.Exec("UPDATE local_users SET updated_at='2026-01-02T03:04:05.123456789Z' WHERE id=41")
		require.NoError(t, err)
		report, err := convert(t, source, ConversionOptions{TargetSchema: schema()})
		require.ErrorContains(t, err, "allow-precision-loss")
		require.Equal(t, "failed", report.Status)
		var count int
		require.NoError(t, admin.QueryRow("SELECT count(*) FROM "+conversionQuote(report.TargetSchema)+".local_users").Scan(&count))
		require.Zero(t, count, "failed import transaction must not leave copied users")
		report, err = convert(t, source, ConversionOptions{TargetSchema: schema(), AllowPrecisionLoss: true})
		require.NoError(t, err)
		require.Equal(t, int64(1), report.TimestampValuesTruncated)
	})
	t.Run("UnknownTablesRefused", func(t *testing.T) {
		_, err := sqlite.Exec("CREATE TABLE custom_not_to_drop(id INTEGER PRIMARY KEY, value TEXT)")
		require.NoError(t, err)
		_, err = convert(t, source, ConversionOptions{TargetSchema: schema(), AllowPrecisionLoss: true})
		require.ErrorContains(t, err, "table sets differ")
	})
	t.Run("ResolverErrorsRedacted", func(t *testing.T) {
		_, err := ConvertSQLiteToPostgreSQL(ctx, source, cfg, func(context.Context, string) (string, error) { return "", errors.New("SECRET-DSN-CONTENTS") }, ConversionOptions{TargetSchema: schema()})
		require.Error(t, err)
		require.NotContains(t, err.Error(), "SECRET-DSN-CONTENTS")
	})
}
