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

const dynamicNASClientTablesSQL = `
CREATE TABLE IF NOT EXISTS nas_client_enrollments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	enrollment_id TEXT UNIQUE NOT NULL,
	source_ip TEXT NOT NULL,
	shortname TEXT NOT NULL,
	nas_type TEXT NOT NULL DEFAULT 'other',
	transport TEXT NOT NULL DEFAULT 'udp',
	secret_ref TEXT,
	radsec_certificate_cn TEXT,
	radsec_certificate_issuer TEXT,
	radsec_radius_v11 TEXT,
	vendor TEXT,
	model TEXT,
	firmware_version TEXT,
	serial_number TEXT,
	capabilities_json TEXT NOT NULL DEFAULT '{}',
	status TEXT NOT NULL DEFAULT 'pending',
	discovery_source TEXT NOT NULL DEFAULT 'bootstrap',
	requested_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	approved_by TEXT,
	approved_at DATETIME,
	rejected_by TEXT,
	rejected_at DATETIME,
	radius_client_id INTEGER,
	owner_tenant TEXT,
	template_name TEXT,
	last_seen_at DATETIME,
	last_seen_reason TEXT,
	drift_json TEXT NOT NULL DEFAULT '{}',
	evidence_sha256 TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY(radius_client_id) REFERENCES radius_clients(id),
	CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired')),
	CHECK (transport IN ('udp', 'radsec'))
);

CREATE TABLE IF NOT EXISTS nas_client_capability_templates (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	description TEXT,
	nas_type TEXT NOT NULL DEFAULT 'other',
	required_capabilities_json TEXT NOT NULL DEFAULT '[]',
	allowed_vendors_json TEXT NOT NULL DEFAULT '[]',
	default_capabilities_json TEXT NOT NULL DEFAULT '{}',
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nas_client_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	enrollment_id TEXT,
	radius_client_id INTEGER,
	event_type TEXT NOT NULL,
	status TEXT NOT NULL,
	summary TEXT,
	actor TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nas_client_enrollments_status ON nas_client_enrollments(status, requested_at);
CREATE INDEX IF NOT EXISTS idx_nas_client_enrollments_source ON nas_client_enrollments(source_ip, status);
CREATE INDEX IF NOT EXISTS idx_nas_client_enrollments_radius_client ON nas_client_enrollments(radius_client_id);
CREATE INDEX IF NOT EXISTS idx_nas_client_templates_enabled ON nas_client_capability_templates(enabled, name);
CREATE INDEX IF NOT EXISTS idx_nas_client_events_enrollment ON nas_client_events(enrollment_id, created_at);
CREATE INDEX IF NOT EXISTS idx_nas_client_events_radius_client ON nas_client_events(radius_client_id, created_at);

INSERT OR IGNORE INTO nas_client_capability_templates
	(name, description, nas_type, required_capabilities_json, allowed_vendors_json, default_capabilities_json, enabled)
VALUES
	('default', 'Default dynamic NAS capability gate for RADIUS authentication and accounting clients.', 'other', '[]', '[]', '{"radius":{"authentication":true,"accounting":true},"policy":{"role":true,"vlan":true}}', 1);
`

func MigrateHandle(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)

	_, err := handle.Exec(SQLForDialect(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`, dialect))
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
		{16, schemaV16},
		{17, schemaV17},
		{18, schemaV18},
		{19, schemaV19},
		{20, schemaV20},
		{21, schemaV21},
		{22, schemaV22},
		{23, schemaV23},
		{24, schemaV24},
		{25, schemaV25},
		{26, schemaV26},
		{27, schemaV27},
		{28, schemaV28},
		{29, schemaV29},
		{30, schemaV30},
		{31, schemaV31},
		{32, schemaV32},
		{33, schemaV33},
		{34, schemaV34},
		{35, schemaV35},
		{36, schemaV36},
		{LatestSchemaVersion(), schemaV37},
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}
		if _, err := handle.Exec(SQLForDialect(m.sql, dialect)); err != nil {
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
	if err := ensureDatabaseBackendEventsTable(handle); err != nil {
		return fmt.Errorf("repair database backend event schema: %w", err)
	}
	if err := ensureRadiusPacketHardeningEventsTable(handle); err != nil {
		return fmt.Errorf("repair RADIUS packet hardening event schema: %w", err)
	}
	if err := ensureRadiusAccountingSpoolTables(handle); err != nil {
		return fmt.Errorf("repair RADIUS accounting spool schema: %w", err)
	}
	if err := ensureDynamicNASClientTables(handle); err != nil {
		return fmt.Errorf("repair dynamic NAS client schema: %w", err)
	}
	if err := ensureRadiusFallbackEventTable(handle); err != nil {
		return fmt.Errorf("repair RADIUS fallback event schema: %w", err)
	}
	if err := ensureIdentitySourceFailoverTables(handle); err != nil {
		return fmt.Errorf("repair identity source failover schema: %w", err)
	}
	if err := ensureMFATables(handle); err != nil {
		return fmt.Errorf("repair MFA schema: %w", err)
	}
	if err := ensureActiveDirectoryTables(handle); err != nil {
		return fmt.Errorf("repair Active Directory schema: %w", err)
	}
	if err := ensureMABTables(handle); err != nil {
		return fmt.Errorf("repair MAB schema: %w", err)
	}
	if err := ensureAdminWebAuthnTables(handle); err != nil {
		return fmt.Errorf("repair admin WebAuthn schema: %w", err)
	}
	if err := ensureEAPFrameworkTables(handle); err != nil {
		return fmt.Errorf("repair EAP framework schema: %w", err)
	}
	if err := ensureCertificateLifecycleTables(handle); err != nil {
		return fmt.Errorf("repair certificate lifecycle schema: %w", err)
	}
	if err := ensureSupplicantLifecycleTables(handle); err != nil {
		return fmt.Errorf("repair supplicant lifecycle schema: %w", err)
	}
	if err := ensurePolicyEngineTables(handle); err != nil {
		return fmt.Errorf("repair policy engine schema: %w", err)
	}
	if err := ensurePolicySetVersionTables(handle); err != nil {
		return fmt.Errorf("repair policy set version schema: %w", err)
	}
	if err := ensurePolicySimulationAnalysisTables(handle); err != nil {
		return fmt.Errorf("repair policy simulation analysis schema: %w", err)
	}
	if err := ensureSubscriberServiceChainTables(handle); err != nil {
		return fmt.Errorf("repair subscriber service chain schema: %w", err)
	}

	return nil
}

func ensurePolicySimulationAnalysisTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	if exists, err := tableExists(handle, "policy_engine_evaluations"); err != nil {
		return err
	} else if exists {
		hasColumn, err := tableHasColumn(handle, "policy_engine_evaluations", "request_replay_json")
		if err != nil {
			return err
		}
		if !hasColumn {
			if _, err := handle.Exec(SQLForDialect(`ALTER TABLE policy_engine_evaluations ADD COLUMN request_replay_json TEXT NOT NULL DEFAULT '{}'`, dialect)); err != nil {
				return err
			}
		}
	}
	_, err := handle.Exec(SQLForDialect(policySimulationAnalysisTablesSQL, dialect))
	return err
}

func ensureSubscriberServiceChainTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	if exists, err := tableExists(handle, "policy_rules"); err != nil {
		return err
	} else if exists {
		hasColumn, err := tableHasColumn(handle, "policy_rules", "service_chain_json")
		if err != nil {
			return err
		}
		if !hasColumn {
			if _, err := handle.Exec(SQLForDialect(`ALTER TABLE policy_rules ADD COLUMN service_chain_json TEXT NOT NULL DEFAULT '[]'`, dialect)); err != nil {
				return err
			}
		}
	}
	if exists, err := tableExists(handle, "policy_simulation_analyses"); err != nil {
		return err
	} else if exists {
		hasColumn, err := tableHasColumn(handle, "policy_simulation_analyses", "service_chain_change_count")
		if err != nil {
			return err
		}
		if !hasColumn {
			if _, err := handle.Exec(SQLForDialect(`ALTER TABLE policy_simulation_analyses ADD COLUMN service_chain_change_count INTEGER DEFAULT 0`, dialect)); err != nil {
				return err
			}
		}
	}
	_, err := handle.Exec(SQLForDialect(subscriberServiceChainTablesSQL, dialect))
	return err
}

func ensurePolicySetVersionTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV35, dialect))
	return err
}

func ensurePolicyEngineTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV34, dialect))
	return err
}

func ensureSupplicantLifecycleTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV33, dialect))
	return err
}

func ensureCertificateLifecycleTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV32, dialect))
	return err
}

func ensureEAPFrameworkTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	if _, err := handle.Exec(SQLForDialect(schemaV27, dialect)); err != nil {
		return err
	}
	if _, err := handle.Exec(SQLForDialect(schemaV28, dialect)); err != nil {
		return err
	}
	if _, err := handle.Exec(SQLForDialect(schemaV29, dialect)); err != nil {
		return err
	}
	if _, err := handle.Exec(SQLForDialect(schemaV30, dialect)); err != nil {
		return err
	}
	_, err := handle.Exec(SQLForDialect(schemaV31, dialect))
	return err
}

func ensureMABTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV25, dialect))
	return err
}

func ensureAdminWebAuthnTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV26, dialect))
	return err
}

func ensureActiveDirectoryTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV24, dialect))
	return err
}

func ensureMFATables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV23, dialect))
	return err
}

func ensureIdentitySourceFailoverTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV22, dialect))
	return err
}

func ensureRadiusFallbackEventTable(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	_, err := handle.Exec(SQLForDialect(schemaV21, dialect))
	return err
}

func ensureDynamicNASClientTables(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_clients")
	if err != nil {
		return err
	}
	if exists {
		columns := []struct {
			name string
			sql  string
		}{
			{"dynamic_source", `ALTER TABLE radius_clients ADD COLUMN dynamic_source TEXT NOT NULL DEFAULT 'static'`},
			{"enrollment_id", `ALTER TABLE radius_clients ADD COLUMN enrollment_id TEXT`},
			{"capabilities_json", `ALTER TABLE radius_clients ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '{}'`},
			{"vendor", `ALTER TABLE radius_clients ADD COLUMN vendor TEXT`},
			{"model", `ALTER TABLE radius_clients ADD COLUMN model TEXT`},
			{"firmware_version", `ALTER TABLE radius_clients ADD COLUMN firmware_version TEXT`},
			{"serial_number", `ALTER TABLE radius_clients ADD COLUMN serial_number TEXT`},
			{"lifecycle_status", `ALTER TABLE radius_clients ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'approved'`},
			{"last_seen_at", `ALTER TABLE radius_clients ADD COLUMN last_seen_at DATETIME`},
			{"approved_at", `ALTER TABLE radius_clients ADD COLUMN approved_at DATETIME`},
			{"approved_by", `ALTER TABLE radius_clients ADD COLUMN approved_by TEXT`},
			{"owner_tenant", `ALTER TABLE radius_clients ADD COLUMN owner_tenant TEXT`},
			{"template_name", `ALTER TABLE radius_clients ADD COLUMN template_name TEXT`},
		}
		for _, column := range columns {
			hasColumn, err := tableHasColumn(handle, "radius_clients", column.name)
			if err != nil {
				return err
			}
			if !hasColumn {
				if _, err := handle.Exec(SQLForDialect(column.sql, DialectForHandle(handle))); err != nil {
					return err
				}
			}
		}
		if _, err := handle.Exec(`CREATE INDEX IF NOT EXISTS idx_radius_clients_enrollment_id ON radius_clients(enrollment_id)`); err != nil {
			return err
		}
		if _, err := handle.Exec(`CREATE INDEX IF NOT EXISTS idx_radius_clients_dynamic_source ON radius_clients(dynamic_source, lifecycle_status)`); err != nil {
			return err
		}
		if _, err := handle.Exec(`CREATE INDEX IF NOT EXISTS idx_radius_clients_last_seen ON radius_clients(last_seen_at)`); err != nil {
			return err
		}
	}

	enrollmentsExist, err := tableExists(handle, "nas_client_enrollments")
	if err != nil {
		return err
	}
	templatesExist, err := tableExists(handle, "nas_client_capability_templates")
	if err != nil {
		return err
	}
	eventsExist, err := tableExists(handle, "nas_client_events")
	if err != nil {
		return err
	}
	if enrollmentsExist && templatesExist && eventsExist {
		_, err = handle.Exec(SQLForDialect(`INSERT OR IGNORE INTO nas_client_capability_templates
			(name, description, nas_type, required_capabilities_json, allowed_vendors_json, default_capabilities_json, enabled)
			VALUES ('default', 'Default dynamic NAS capability gate for RADIUS authentication and accounting clients.', 'other', '[]', '[]', '{"radius":{"authentication":true,"accounting":true},"policy":{"role":true,"vlan":true}}', 1)`, DialectForHandle(handle)))
		return err
	}

	_, err = handle.Exec(SQLForDialect(dynamicNASClientTablesSQL, DialectForHandle(handle)))
	return err
}

func ensureRadiusAccountingSpoolTables(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_accounting_spool")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := handle.Exec(SQLForDialect(schemaV19, DialectForHandle(handle))); err != nil {
			return err
		}
		return nil
	}
	attemptsExists, err := tableExists(handle, "radius_accounting_spool_attempts")
	if err != nil {
		return err
	}
	if !attemptsExists {
		_, err = handle.Exec(SQLForDialect(schemaV19, DialectForHandle(handle)))
		return err
	}
	return nil
}

func ensureRadiusPacketHardeningEventsTable(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_packet_hardening_events")
	if err != nil || exists {
		return err
	}
	_, err = handle.Exec(SQLForDialect(schemaV18, DialectForHandle(handle)))
	return err
}

func ensureDatabaseBackendEventsTable(handle *sql.DB) error {
	exists, err := tableExists(handle, "database_backend_events")
	if err != nil || exists {
		return err
	}
	_, err = handle.Exec(SQLForDialect(schemaV17, DialectForHandle(handle)))
	return err
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
	switch DialectForHandle(handle) {
	case DialectPostgreSQL:
		err := handle.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?`, table).Scan(&count)
		return count > 0, err
	default:
		err := handle.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
		return count > 0, err
	}
}

func tableHasColumn(handle *sql.DB, table, column string) (bool, error) {
	if DialectForHandle(handle) == DialectPostgreSQL {
		var count int
		err := handle.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?`, table, column).Scan(&count)
		return count > 0, err
	}
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
