package db

import (
	"fmt"
)

func Migrate() error {
	db := GetDB()

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	var currentVersion int
	err = db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
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
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}
		if _, err := db.Exec(m.sql); err != nil {
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if _, err := db.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}
	return nil
}

const schemaV1 = `
-- Users (local)
CREATE TABLE IF NOT EXISTS local_users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL,
	full_name TEXT,
	email TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vouchers
CREATE TABLE IF NOT EXISTS vouchers (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	code TEXT UNIQUE NOT NULL,
	role TEXT NOT NULL,
	duration_minutes INTEGER NOT NULL,
	usage_limit INTEGER DEFAULT 1,
	used_count INTEGER DEFAULT 0,
	expires_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Roles
CREATE TABLE IF NOT EXISTS roles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	description TEXT,
	vlan INTEGER,
	bandwidth_profile TEXT,
	session_timeout INTEGER,
	idle_timeout INTEGER,
	portal_profile TEXT,
	priority INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Bandwidth profiles
CREATE TABLE IF NOT EXISTS bandwidth_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	download_rate_kbps INTEGER NOT NULL,
	upload_rate_kbps INTEGER NOT NULL,
	burst_kb INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Portal profiles
CREATE TABLE IF NOT EXISTS portal_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	branding TEXT,
	success_url TEXT,
	logout_url TEXT,
	terms_text TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Identity sources
CREATE TABLE IF NOT EXISTS identity_sources (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	type TEXT NOT NULL, -- 'local', 'ldap'
	config TEXT,        -- JSON config
	enabled BOOLEAN DEFAULT 1,
	priority INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL,
	mac TEXT,
	ip TEXT,
	auth_method TEXT,
	vlan INTEGER,
	role TEXT,
	bandwidth_profile TEXT,
	start_time DATETIME NOT NULL,
	last_activity DATETIME,
	end_time DATETIME,
	stop_reason TEXT,
	radius_session_id TEXT,
	bytes_in INTEGER DEFAULT 0,
	bytes_out INTEGER DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Config revisions
CREATE TABLE IF NOT EXISTS config_revisions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	revision INTEGER NOT NULL,
	signature TEXT,
	config_data TEXT NOT NULL,
	checksum TEXT NOT NULL,
	created_by TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	severity TEXT NOT NULL, -- 'info', 'warning', 'critical'
	source TEXT NOT NULL,
	message TEXT NOT NULL,
	details TEXT,
	acknowledged BOOLEAN DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	user TEXT,
	action TEXT NOT NULL,
	details TEXT,
	result TEXT,
	ip_address TEXT
);

-- AI recommendations
CREATE TABLE IF NOT EXISTS ai_recommendations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	severity TEXT NOT NULL,
	source TEXT NOT NULL,
	confidence REAL DEFAULT 0.0,
	title TEXT NOT NULL,
	description TEXT,
	remediation TEXT,
	acknowledged BOOLEAN DEFAULT 0,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Policy rules table
CREATE TABLE IF NOT EXISTS policy_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	description TEXT,
	priority INTEGER DEFAULT 0,          -- higher priority evaluated first
	enabled BOOLEAN DEFAULT 1,
	
	-- Match conditions (JSON or columns)
	match_conditions TEXT NOT NULL,      -- JSON object with conditions
	
	-- Result actions
	action TEXT NOT NULL DEFAULT 'allow', -- 'allow', 'deny', 'quarantine'
	vlan INTEGER,
	bandwidth_profile TEXT,
	session_timeout INTEGER,
	idle_timeout INTEGER,
	portal_profile TEXT,
	quarantine BOOLEAN DEFAULT 0,
	
	-- Metadata
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS radius_clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	shortname TEXT UNIQUE NOT NULL,
	ipaddr TEXT NOT NULL,
	secret TEXT NOT NULL,
	nas_type TEXT DEFAULT 'other',
	description TEXT,
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Staged configuration changes
CREATE TABLE IF NOT EXISTS config_staging (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	resource_type TEXT NOT NULL,  -- e.g., 'vlan', 'user', 'role'
	resource_id TEXT,             -- ID of the resource (null for create)
	operation TEXT NOT NULL,      -- 'create', 'update', 'delete'
	data TEXT,                    -- JSON payload for create/update
	created_by TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	applied BOOLEAN DEFAULT 0,
	applied_at DATETIME
);

-- API tokens for admin authentication
CREATE TABLE IF NOT EXISTS api_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	token TEXT UNIQUE NOT NULL,
	description TEXT,
	created_by TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	last_used DATETIME,
	expires_at DATETIME,
	enabled BOOLEAN DEFAULT 1
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_username_end ON sessions(username, end_time);

-- Example default rule: allow all authenticated users
INSERT OR IGNORE INTO policy_rules (name, priority, match_conditions, action, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile)
VALUES ('default-allow', 1, '{"authenticated": true}', 'allow', NULL, NULL, 28800, 3600, 'default-guest');
`

const schemaV2 = `
ALTER TABLE sessions ADD COLUMN identity_source TEXT;
ALTER TABLE sessions ADD COLUMN filter_id TEXT;
ALTER TABLE sessions ADD COLUMN radius_class TEXT;
ALTER TABLE sessions ADD COLUMN session_timeout INTEGER;
ALTER TABLE sessions ADD COLUMN idle_timeout INTEGER;
ALTER TABLE sessions ADD COLUMN acct_session_time INTEGER DEFAULT 0;
ALTER TABLE sessions ADD COLUMN called_station_id TEXT;
ALTER TABLE sessions ADD COLUMN nas_identifier TEXT;
`

const schemaV3 = `
CREATE TABLE IF NOT EXISTS runtime_status (
	component TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	message TEXT,
	details TEXT,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_runtime_status_updated_at ON runtime_status(updated_at);
`
