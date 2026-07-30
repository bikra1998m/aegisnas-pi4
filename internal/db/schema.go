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
		{37, schemaV37},
		{38, schemaV38},
		{LatestSchemaVersion(), schemaV39},
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
	if err := ensureTACACSTables(handle); err != nil {
		return fmt.Errorf("repair TACACS+ schema: %w", err)
	}
	if err := ensureTenantIsolationTables(handle); err != nil {
		return fmt.Errorf("repair tenant isolation schema: %w", err)
	}

	return nil
}

func ensureTenantIsolationTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	dialect := DialectForHandle(handle)
	for _, column := range []struct {
		table string
		name  string
		sql   string
	}{
		{"policy_set_versions", "tenant", `ALTER TABLE policy_set_versions ADD COLUMN tenant TEXT`},
		{"policy_set_activation_events", "tenant", `ALTER TABLE policy_set_activation_events ADD COLUMN tenant TEXT`},
		{"policy_set_simulations", "tenant", `ALTER TABLE policy_set_simulations ADD COLUMN tenant TEXT`},
		{"policy_simulation_analyses", "tenant", `ALTER TABLE policy_simulation_analyses ADD COLUMN tenant TEXT`},
	} {
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
		if !hasColumn {
			if _, err := handle.Exec(SQLForDialect(column.sql, dialect)); err != nil {
				return err
			}
		}
	}
	if err := ensurePolicySetTenantScope(handle, dialect); err != nil {
		return err
	}
	_, err := handle.Exec(SQLForDialect(tenantIsolationTablesSQL, dialect))
	return err
}

func ensurePolicySetTenantScope(handle *sql.DB, dialect Dialect) error {
	exists, err := tableExists(handle, "policy_set_versions")
	if err != nil || !exists {
		return err
	}
	switch dialect {
	case DialectPostgreSQL:
		return ensurePostgreSQLPolicySetTenantScope(handle)
	default:
		return ensureSQLitePolicySetTenantScope(handle)
	}
}

func ensurePostgreSQLPolicySetTenantScope(handle *sql.DB) error {
	_, err := handle.Exec(`
UPDATE policy_set_versions SET tenant = '' WHERE tenant IS NULL;
ALTER TABLE policy_set_versions ALTER COLUMN tenant SET DEFAULT '';
ALTER TABLE policy_set_versions ALTER COLUMN tenant SET NOT NULL;
ALTER TABLE policy_set_versions DROP CONSTRAINT IF EXISTS policy_set_versions_set_key_version_key;
DROP INDEX IF EXISTS idx_policy_set_versions_one_active;
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_set_versions_unique_tenant_version ON policy_set_versions(set_key, tenant, version);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_set_versions_one_active ON policy_set_versions(set_key, tenant) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_policy_set_versions_tenant_status ON policy_set_versions(tenant, set_key, status, version DESC);
`)
	return err
}

func ensureSQLitePolicySetTenantScope(handle *sql.DB) error {
	var ddl string
	err := handle.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'policy_set_versions'`).Scan(&ddl)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	normalizedDDL := strings.ToLower(strings.Join(strings.Fields(ddl), " "))
	if strings.Contains(normalizedDDL, "unique (set_key, tenant, version)") {
		return nil
	}
	if _, err := handle.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer handle.Exec(`PRAGMA foreign_keys=ON`)

	tx, err := handle.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`DROP TABLE IF EXISTS policy_set_versions_v39`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE policy_set_versions_v39 (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	set_key TEXT NOT NULL DEFAULT 'default',
	tenant TEXT NOT NULL DEFAULT '',
	version INTEGER NOT NULL,
	status TEXT NOT NULL DEFAULT 'draft',
	description TEXT,
	parent_version_id INTEGER,
	rollback_of_version_id INTEGER,
	content_json TEXT NOT NULL,
	content_sha256 TEXT NOT NULL,
	policy_sha256 TEXT NOT NULL,
	rule_count INTEGER DEFAULT 0,
	child_set_count INTEGER DEFAULT 0,
	max_depth INTEGER DEFAULT 1,
	approval_required BOOLEAN DEFAULT 1,
	min_approvals INTEGER DEFAULT 1,
	created_by TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	submitted_by TEXT,
	submitted_at DATETIME,
	activated_by TEXT,
	activated_at DATETIME,
	superseded_at DATETIME,
	rejected_by TEXT,
	rejected_at DATETIME,
	rejection_reason TEXT,
	activation_note TEXT,
	CHECK (status IN ('draft', 'pending_approval', 'approved', 'active', 'superseded', 'rejected')),
	CHECK (version > 0),
	CHECK (rule_count >= 0),
	CHECK (child_set_count >= 0),
	CHECK (max_depth >= 1),
	CHECK (min_approvals >= 0),
	CHECK (length(content_sha256) = 64),
	CHECK (length(policy_sha256) = 64),
	UNIQUE (set_key, tenant, version)
)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO policy_set_versions_v39 (
	id, set_key, tenant, version, status, description, parent_version_id, rollback_of_version_id,
	content_json, content_sha256, policy_sha256, rule_count, child_set_count, max_depth,
	approval_required, min_approvals, created_by, created_at, submitted_by, submitted_at,
	activated_by, activated_at, superseded_at, rejected_by, rejected_at, rejection_reason, activation_note
)
SELECT id, set_key, COALESCE(tenant, ''), version, status, description, parent_version_id, rollback_of_version_id,
	content_json, content_sha256, policy_sha256, rule_count, child_set_count, max_depth,
	approval_required, min_approvals, created_by, created_at, submitted_by, submitted_at,
	activated_by, activated_at, superseded_at, rejected_by, rejected_at, rejection_reason, activation_note
FROM policy_set_versions`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE policy_set_versions`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE policy_set_versions_v39 RENAME TO policy_set_versions`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_set_versions_one_active ON policy_set_versions(set_key, tenant) WHERE status = 'active'`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_set_versions_unique_tenant_version ON policy_set_versions(set_key, tenant, version)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policy_set_versions_tenant_status ON policy_set_versions(tenant, set_key, status, version DESC)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_policy_set_versions_content_hash ON policy_set_versions(content_sha256)`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func ensureTACACSTables(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	_, err := handle.Exec(SQLForDialect(tacacsTablesSQL, DialectForHandle(handle)))
	return err
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
