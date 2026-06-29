package db

func LatestSchemaVersion() int {
	return 11
}

func Migrate() error {
	return MigrateHandle(GetDB())
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

const schemaV4 = `
CREATE TABLE IF NOT EXISTS guest_registrations (
	id TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	full_name TEXT,
	email TEXT,
	phone TEXT,
	company TEXT,
	purpose TEXT,
	sponsor_name TEXT,
	sponsor_email TEXT,
	sponsor_phone TEXT,
	client_mac TEXT,
	client_ip TEXT,
	portal_base_url TEXT,
	username TEXT,
	role TEXT NOT NULL,
	approval_token_hash TEXT,
	guest_token_hash TEXT NOT NULL,
	approved_by TEXT,
	rejection_reason TEXT,
	approval_delivery_status TEXT,
	approval_delivery_error TEXT,
	invite_delivery_status TEXT,
	invite_delivery_error TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	approved_at DATETIME,
	rejected_at DATETIME,
	completed_at DATETIME,
	expires_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_guest_registrations_status ON guest_registrations(status);
CREATE INDEX IF NOT EXISTS idx_guest_registrations_created_at ON guest_registrations(created_at);
CREATE INDEX IF NOT EXISTS idx_guest_registrations_approval_token ON guest_registrations(approval_token_hash);
`

const schemaV5 = `
CREATE TABLE IF NOT EXISTS device_inventory (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mac TEXT UNIQUE NOT NULL,
	tenant TEXT,
	username TEXT,
	friendly_name TEXT,
	ownership TEXT,
	platform TEXT,
	device_type TEXT,
	user_agent TEXT,
	source TEXT,
	hostname TEXT,
	dhcp_client_id TEXT,
	dhcp_fingerprint TEXT,
	lldp_chassis_id TEXT,
	lldp_port_id TEXT,
	cdp_device_id TEXT,
	cdp_port_id TEXT,
	mac_oui TEXT,
	risk_score INTEGER DEFAULT 0,
	risk_reasons_json TEXT,
	managed BOOLEAN DEFAULT 0,
	compliant BOOLEAN,
	compliance_status TEXT,
	remediation_state TEXT,
	mdm_provider TEXT,
	mdm_device_id TEXT,
	certificate_serial TEXT,
	certificate_subject TEXT,
	certificate_valid_until DATETIME,
	last_ip TEXT,
	last_session_id TEXT,
	first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
	last_seen DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_certificates (
	id TEXT PRIMARY KEY,
	device_mac TEXT NOT NULL,
	username TEXT,
	common_name TEXT NOT NULL,
	serial_number TEXT NOT NULL,
	cert_path TEXT NOT NULL,
	key_path TEXT NOT NULL,
	ca_path TEXT NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	expires_at DATETIME,
	revoked_at DATETIME,
	revoke_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_inventory_username ON device_inventory(username);
CREATE INDEX IF NOT EXISTS idx_device_inventory_last_seen ON device_inventory(last_seen);
CREATE INDEX IF NOT EXISTS idx_device_inventory_compliance ON device_inventory(compliance_status);
CREATE INDEX IF NOT EXISTS idx_device_certificates_device_mac ON device_certificates(device_mac);
`

const schemaV6 = `
ALTER TABLE local_users ADD COLUMN tenant TEXT;
ALTER TABLE guest_registrations ADD COLUMN tenant TEXT;

CREATE TABLE IF NOT EXISTS admin_principals (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subject TEXT UNIQUE NOT NULL,
	provider TEXT,
	display_name TEXT,
	email TEXT,
	role TEXT NOT NULL DEFAULT 'read_only',
	tenants TEXT,
	groups_json TEXT,
	disabled BOOLEAN DEFAULT 0,
	last_login DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
	token_hash TEXT PRIMARY KEY,
	subject TEXT NOT NULL,
	role TEXT NOT NULL,
	source TEXT NOT NULL,
	provider TEXT,
	tenants TEXT,
	groups_json TEXT,
	expires_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_local_users_tenant ON local_users(tenant);
CREATE INDEX IF NOT EXISTS idx_guest_registrations_tenant ON guest_registrations(tenant);
CREATE INDEX IF NOT EXISTS idx_device_inventory_tenant ON device_inventory(tenant);
CREATE INDEX IF NOT EXISTS idx_admin_principals_role ON admin_principals(role);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_subject ON admin_sessions(subject);
`

const schemaV7 = `
CREATE TABLE IF NOT EXISTS network_apply_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	action TEXT NOT NULL,
	status TEXT NOT NULL,
	summary TEXT,
	backup_id TEXT,
	rollback_id TEXT,
	actor TEXT,
	details_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dhcp_lease_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	mac TEXT NOT NULL,
	ip TEXT NOT NULL,
	hostname TEXT,
	client_id TEXT,
	reservation BOOLEAN DEFAULT 0,
	expired BOOLEAN DEFAULT 0,
	expires_at TEXT,
	remaining_seconds INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_network_apply_history_created_at ON network_apply_history(created_at);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_history_observed_at ON dhcp_lease_history(observed_at);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_history_mac ON dhcp_lease_history(mac);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_history_ip ON dhcp_lease_history(ip);
`

const schemaV8 = `
CREATE TABLE IF NOT EXISTS ha_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_type TEXT NOT NULL,
	status TEXT NOT NULL,
	summary TEXT,
	node_role TEXT,
	actor TEXT,
	details_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ha_history_created_at ON ha_history(created_at);
CREATE INDEX IF NOT EXISTS idx_ha_history_event_type ON ha_history(event_type);
`

const schemaV9 = `
CREATE TABLE IF NOT EXISTS integration_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	component TEXT NOT NULL,
	status TEXT NOT NULL,
	summary TEXT,
	details_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_integration_history_created_at ON integration_history(created_at);
CREATE INDEX IF NOT EXISTS idx_integration_history_component ON integration_history(component);
`

const schemaV10 = `
CREATE TABLE IF NOT EXISTS upstream_aaa_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	server_name TEXT,
	address TEXT,
	auth_port INTEGER,
	acct_port INTEGER,
	status TEXT NOT NULL,
	message TEXT,
	response_code TEXT,
	latency_ms INTEGER DEFAULT 0,
	supports_status_server BOOLEAN DEFAULT 0,
	checked_at DATETIME NOT NULL,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_upstream_aaa_history_checked_at ON upstream_aaa_history(checked_at);
CREATE INDEX IF NOT EXISTS idx_upstream_aaa_history_server_name ON upstream_aaa_history(server_name);
CREATE INDEX IF NOT EXISTS idx_upstream_aaa_history_status ON upstream_aaa_history(status);
`

const schemaV11 = `
CREATE TABLE IF NOT EXISTS vendor_observability (
	vendor_key TEXT NOT NULL,
	nas_type TEXT NOT NULL DEFAULT 'global',
	auth_success_count INTEGER DEFAULT 0,
	auth_failure_count INTEGER DEFAULT 0,
	vsa_parsed_count INTEGER DEFAULT 0,
	vsa_parse_failure_count INTEGER DEFAULT 0,
	unsupported_attribute_count INTEGER DEFAULT 0,
	coa_success_count INTEGER DEFAULT 0,
	coa_failure_count INTEGER DEFAULT 0,
	disconnect_success_count INTEGER DEFAULT 0,
	disconnect_failure_count INTEGER DEFAULT 0,
	last_message TEXT,
	last_event_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (vendor_key, nas_type)
);

CREATE INDEX IF NOT EXISTS idx_vendor_observability_last_event ON vendor_observability(last_event_at);
CREATE INDEX IF NOT EXISTS idx_vendor_observability_score_inputs ON vendor_observability(auth_failure_count, vsa_parse_failure_count, unsupported_attribute_count, coa_failure_count, disconnect_failure_count);
`
