package db

import (
	"database/sql"
	"fmt"
	"strings"
)

func CurrentSchemaVersionHandle(handle *sql.DB) (int, error) {
	if handle == nil {
		return 0, fmt.Errorf("database handle is required")
	}
	var version int
	err := handle.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return 0, nil
		}
		return 0, err
	}
	return version, nil
}

func CurrentSchemaVersion() (int, error) {
	return CurrentSchemaVersionHandle(GetDB())
}

func MigrateHandle(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}

	_, err := handle.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	currentVersion, err := CurrentSchemaVersionHandle(handle)
	if err != nil {
		return fmt.Errorf("get current schema version: %w", err)
	}

	migrations := []struct {
		version int
		sql     string
	}{
		{1, schemaV1},
		{2, schemaV2},
		{3, schemaV3},
		{4, schemaV4},
		{5, schemaV5},
		{6, schemaV6},
		{7, schemaV7},
		{8, schemaV8},
		{9, schemaV9},
		{10, schemaV10},
		{11, schemaV11},
		{12, schemaV12},
		{13, schemaV13},
		{14, schemaV14},
		{15, schemaV15},
		{LatestSchemaVersion(), schemaV16},
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}
		if _, err := handle.Exec(m.sql); err != nil {
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if _, err := handle.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}

	if err := ensureRadiusClientCompatibilityColumns(handle); err != nil {
		return fmt.Errorf("repair radius client schema: %w", err)
	}
	if err := ensureRadSecCompatibilityColumns(handle); err != nil {
		return fmt.Errorf("repair RadSec schema: %w", err)
	}
	if err := ensureDeviceInventoryProfilingColumns(handle); err != nil {
		return fmt.Errorf("repair device inventory schema: %w", err)
	}
	if err := ensureACLPolicyBindingColumns(handle); err != nil {
		return fmt.Errorf("repair ACL policy binding schema: %w", err)
	}
	if err := ensureRadiusClientSecretColumns(handle); err != nil {
		return fmt.Errorf("repair radius client secret schema: %w", err)
	}

	return nil
}

func ensureRadiusClientSecretColumns(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_clients")
	if err != nil || !exists {
		return err
	}
	hasColumn, err := tableHasColumn(handle, "radius_clients", "secret_ref")
	if err != nil {
		return err
	}
	if !hasColumn {
		if _, err := handle.Exec(`ALTER TABLE radius_clients ADD COLUMN secret_ref TEXT`); err != nil {
			return err
		}
	}
	_, err = handle.Exec(`CREATE INDEX IF NOT EXISTS idx_radius_clients_secret_ref ON radius_clients(secret_ref)`)
	return err
}

func ensureRadSecCompatibilityColumns(handle *sql.DB) error {
	tables := []struct {
		name    string
		columns []struct{ name, sql string }
	}{
		{"radius_clients", []struct{ name, sql string }{
			{"transport", `ALTER TABLE radius_clients ADD COLUMN transport TEXT NOT NULL DEFAULT 'udp'`},
			{"radsec_certificate_cn", `ALTER TABLE radius_clients ADD COLUMN radsec_certificate_cn TEXT`},
			{"radsec_certificate_issuer", `ALTER TABLE radius_clients ADD COLUMN radsec_certificate_issuer TEXT`},
			{"radsec_radius_v11", `ALTER TABLE radius_clients ADD COLUMN radsec_radius_v11 TEXT`},
		}},
		{"upstream_aaa_history", []struct{ name, sql string }{
			{"transport", `ALTER TABLE upstream_aaa_history ADD COLUMN transport TEXT NOT NULL DEFAULT 'udp'`},
			{"radsec_port", `ALTER TABLE upstream_aaa_history ADD COLUMN radsec_port INTEGER DEFAULT 0`},
			{"tls_version", `ALTER TABLE upstream_aaa_history ADD COLUMN tls_version TEXT`},
			{"tls_cipher_suite", `ALTER TABLE upstream_aaa_history ADD COLUMN tls_cipher_suite TEXT`},
			{"tls_alpn", `ALTER TABLE upstream_aaa_history ADD COLUMN tls_alpn TEXT`},
			{"peer_subject", `ALTER TABLE upstream_aaa_history ADD COLUMN peer_subject TEXT`},
			{"peer_issuer", `ALTER TABLE upstream_aaa_history ADD COLUMN peer_issuer TEXT`},
			{"peer_serial", `ALTER TABLE upstream_aaa_history ADD COLUMN peer_serial TEXT`},
			{"peer_not_after", `ALTER TABLE upstream_aaa_history ADD COLUMN peer_not_after DATETIME`},
		}},
	}
	for _, table := range tables {
		exists, err := tableExists(handle, table.name)
		if err != nil || !exists {
			if err != nil {
				return err
			}
			continue
		}
		for _, column := range table.columns {
			hasColumn, err := tableHasColumn(handle, table.name, column.name)
			if err != nil {
				return err
			}
			if !hasColumn {
				if _, err := handle.Exec(column.sql); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func ensureACLPolicyBindingColumns(handle *sql.DB) error {
	columns := []struct {
		table string
		name  string
		sql   string
	}{
		{"roles", "acl_policy_name", `ALTER TABLE roles ADD COLUMN acl_policy_name TEXT`},
		{"policy_rules", "acl_policy_name", `ALTER TABLE policy_rules ADD COLUMN acl_policy_name TEXT`},
		{"sessions", "acl_policy_name", `ALTER TABLE sessions ADD COLUMN acl_policy_name TEXT`},
	}
	for _, column := range columns {
		exists, err := tableExists(handle, column.table)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		hasColumn, err := tableHasColumn(handle, column.table, column.name)
		if err != nil {
			return err
		}
		if hasColumn {
			continue
		}
		if _, err := handle.Exec(column.sql); err != nil {
			return err
		}
	}
	return nil
}

func ensureRadiusClientCompatibilityColumns(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_clients")
	if err != nil || !exists {
		return err
	}

	hasNASType, err := tableHasColumn(handle, "radius_clients", "nas_type")
	if err != nil || hasNASType {
		return err
	}
	_, err = handle.Exec(`ALTER TABLE radius_clients ADD COLUMN nas_type TEXT DEFAULT 'other'`)
	return err
}

func ensureDeviceInventoryProfilingColumns(handle *sql.DB) error {
	exists, err := tableExists(handle, "device_inventory")
	if err != nil || !exists {
		return err
	}
	columns := []struct {
		name string
		sql  string
	}{
		{"hostname", `ALTER TABLE device_inventory ADD COLUMN hostname TEXT`},
		{"dhcp_client_id", `ALTER TABLE device_inventory ADD COLUMN dhcp_client_id TEXT`},
		{"dhcp_fingerprint", `ALTER TABLE device_inventory ADD COLUMN dhcp_fingerprint TEXT`},
		{"lldp_chassis_id", `ALTER TABLE device_inventory ADD COLUMN lldp_chassis_id TEXT`},
		{"lldp_port_id", `ALTER TABLE device_inventory ADD COLUMN lldp_port_id TEXT`},
		{"cdp_device_id", `ALTER TABLE device_inventory ADD COLUMN cdp_device_id TEXT`},
		{"cdp_port_id", `ALTER TABLE device_inventory ADD COLUMN cdp_port_id TEXT`},
		{"mac_oui", `ALTER TABLE device_inventory ADD COLUMN mac_oui TEXT`},
		{"risk_score", `ALTER TABLE device_inventory ADD COLUMN risk_score INTEGER DEFAULT 0`},
		{"risk_reasons_json", `ALTER TABLE device_inventory ADD COLUMN risk_reasons_json TEXT`},
	}
	for _, column := range columns {
		hasColumn, err := tableHasColumn(handle, "device_inventory", column.name)
		if err != nil {
			return err
		}
		if hasColumn {
			continue
		}
		if _, err := handle.Exec(column.sql); err != nil {
			return err
		}
	}
	return nil
}

func tableExists(handle *sql.DB, table string) (bool, error) {
	var count int
	err := handle.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
	return count > 0, err
}

func tableHasColumn(handle *sql.DB, table, column string) (bool, error) {
	rows, err := handle.Query(fmt.Sprintf("PRAGMA table_info('%s')", strings.ReplaceAll(table, "'", "''")))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}
