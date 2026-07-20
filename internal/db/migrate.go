package db

func LatestSchemaVersion() int {
	return 34
}

func Migrate() error {
	if err := MigrateHandle(GetDB()); err != nil {
		return err
	}
	return RecordBackendEvent("migrated")
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

const schemaV12 = `
CREATE TABLE IF NOT EXISTS acl_policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT UNIQUE NOT NULL,
	description TEXT,
	inbound_acl TEXT,
	outbound_acl TEXT,
	rules_json TEXT NOT NULL DEFAULT '[]',
	enabled BOOLEAN DEFAULT 1,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_acl_policies_enabled_name ON acl_policies(enabled, name);
`

const schemaV13 = `
ALTER TABLE roles ADD COLUMN acl_policy_name TEXT;
ALTER TABLE policy_rules ADD COLUMN acl_policy_name TEXT;
ALTER TABLE sessions ADD COLUMN acl_policy_name TEXT;

CREATE INDEX IF NOT EXISTS idx_roles_acl_policy_name ON roles(acl_policy_name);
CREATE INDEX IF NOT EXISTS idx_policy_rules_acl_policy_name ON policy_rules(acl_policy_name);
CREATE INDEX IF NOT EXISTS idx_sessions_acl_policy_name ON sessions(acl_policy_name);
`

const schemaV14 = `
ALTER TABLE radius_clients ADD COLUMN transport TEXT NOT NULL DEFAULT 'udp';
ALTER TABLE radius_clients ADD COLUMN radsec_certificate_cn TEXT;
ALTER TABLE radius_clients ADD COLUMN radsec_certificate_issuer TEXT;
ALTER TABLE radius_clients ADD COLUMN radsec_radius_v11 TEXT;

ALTER TABLE upstream_aaa_history ADD COLUMN transport TEXT NOT NULL DEFAULT 'udp';
ALTER TABLE upstream_aaa_history ADD COLUMN radsec_port INTEGER DEFAULT 0;
ALTER TABLE upstream_aaa_history ADD COLUMN tls_version TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN tls_cipher_suite TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN tls_alpn TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN peer_subject TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN peer_issuer TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN peer_serial TEXT;
ALTER TABLE upstream_aaa_history ADD COLUMN peer_not_after DATETIME;

CREATE INDEX IF NOT EXISTS idx_radius_clients_transport ON radius_clients(transport);
CREATE INDEX IF NOT EXISTS idx_upstream_aaa_history_transport ON upstream_aaa_history(transport);
`

const schemaV15 = `
CREATE TABLE IF NOT EXISTS vendor_identity_assignments (
	pen INTEGER PRIMARY KEY,
	vendor_name TEXT NOT NULL,
	organization TEXT NOT NULL,
	registry_url TEXT NOT NULL,
	registry_last_updated TEXT NOT NULL,
	registry_sha256 TEXT NOT NULL,
	record_sha256 TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	active BOOLEAN NOT NULL DEFAULT 0,
	verified_at DATETIME NOT NULL,
	activated_at DATETIME,
	retired_at DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHECK (pen > 0 AND pen < 4294967295),
	CHECK (length(registry_sha256) = 64),
	CHECK (length(record_sha256) = 64)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_identity_one_active
	ON vendor_identity_assignments(active) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_vendor_identity_assignment_verified
	ON vendor_identity_assignments(verified_at DESC);

CREATE TABLE IF NOT EXISTS vendor_identity_migrations (
	id TEXT PRIMARY KEY,
	status TEXT NOT NULL,
	from_vendor_name TEXT NOT NULL,
	from_pen INTEGER NOT NULL,
	to_vendor_name TEXT NOT NULL,
	to_pen INTEGER NOT NULL,
	organization TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	before_json TEXT NOT NULL,
	after_json TEXT NOT NULL,
	config_checksum TEXT NOT NULL,
	confirmation_sha256 TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	created_by TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	applied_at DATETIME,
	rolled_back_at DATETIME,
	failure TEXT,
	CHECK (status IN ('previewed', 'applying', 'applied', 'failed', 'rolled_back')),
	CHECK (from_pen > 0 AND from_pen < 4294967295),
	CHECK (to_pen > 0 AND to_pen < 4294967295),
	CHECK (length(config_checksum) = 64),
	CHECK (length(confirmation_sha256) = 64)
);

CREATE INDEX IF NOT EXISTS idx_vendor_identity_migrations_created
	ON vendor_identity_migrations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vendor_identity_migrations_status
	ON vendor_identity_migrations(status, created_at DESC);
`

const schemaV16 = `
ALTER TABLE radius_clients ADD COLUMN secret_ref TEXT;
CREATE INDEX IF NOT EXISTS idx_radius_clients_secret_ref ON radius_clients(secret_ref);
`

const schemaV17 = `
CREATE TABLE IF NOT EXISTS database_backend_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	backend TEXT NOT NULL,
	status TEXT NOT NULL,
	schema_version INTEGER NOT NULL DEFAULT 0,
	detail_json TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_database_backend_events_created_at ON database_backend_events(created_at);
CREATE INDEX IF NOT EXISTS idx_database_backend_events_backend_status ON database_backend_events(backend, status);
`

const schemaV18 = `
CREATE TABLE IF NOT EXISTS radius_packet_hardening_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	source_ip TEXT,
	direction TEXT NOT NULL,
	packet_code TEXT,
	packet_identifier INTEGER DEFAULT 0,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	message TEXT,
	packet_length INTEGER DEFAULT 0,
	attribute_count INTEGER DEFAULT 0,
	proxy_state_count INTEGER DEFAULT 0,
	proxy_state_bytes INTEGER DEFAULT 0,
	message_authenticator_present BOOLEAN DEFAULT 0,
	replay_detected BOOLEAN DEFAULT 0,
	rate_limited BOOLEAN DEFAULT 0,
	details_json TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_radius_packet_hardening_events_observed_at ON radius_packet_hardening_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_radius_packet_hardening_events_source ON radius_packet_hardening_events(source_ip, observed_at);
CREATE INDEX IF NOT EXISTS idx_radius_packet_hardening_events_decision ON radius_packet_hardening_events(decision, reason);
`

const schemaV19 = `
CREATE TABLE IF NOT EXISTS radius_accounting_spool (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	record_id TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL,
	route TEXT,
	realm TEXT,
	server_name TEXT,
	username TEXT,
	session_id TEXT,
	acct_status_type TEXT,
	payload_json TEXT NOT NULL,
	payload_sha256 TEXT NOT NULL,
	attempt_count INTEGER NOT NULL DEFAULT 0,
	max_attempts INTEGER NOT NULL DEFAULT 10,
	last_error TEXT,
	last_response_code TEXT,
	last_attempt_at DATETIME,
	next_attempt_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	owner_node TEXT,
	locked_until DATETIME,
	sent_at DATETIME,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS radius_accounting_spool_attempts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	spool_id INTEGER NOT NULL,
	record_id TEXT NOT NULL,
	attempt_number INTEGER NOT NULL,
	result TEXT NOT NULL,
	error TEXT,
	response_code TEXT,
	route TEXT,
	realm TEXT,
	server_name TEXT,
	latency_ms INTEGER DEFAULT 0,
	attempted_at DATETIME NOT NULL,
	next_attempt_at DATETIME,
	FOREIGN KEY(spool_id) REFERENCES radius_accounting_spool(id)
);

CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_status_next ON radius_accounting_spool(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_expires ON radius_accounting_spool(expires_at);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_session ON radius_accounting_spool(session_id, acct_status_type);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_owner_lock ON radius_accounting_spool(owner_node, locked_until);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_attempts_record ON radius_accounting_spool_attempts(record_id, attempted_at);
CREATE INDEX IF NOT EXISTS idx_radius_accounting_spool_attempts_spool ON radius_accounting_spool_attempts(spool_id, attempted_at);
`

const schemaV20 = `
ALTER TABLE radius_clients ADD COLUMN dynamic_source TEXT NOT NULL DEFAULT 'static';
ALTER TABLE radius_clients ADD COLUMN enrollment_id TEXT;
ALTER TABLE radius_clients ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE radius_clients ADD COLUMN vendor TEXT;
ALTER TABLE radius_clients ADD COLUMN model TEXT;
ALTER TABLE radius_clients ADD COLUMN firmware_version TEXT;
ALTER TABLE radius_clients ADD COLUMN serial_number TEXT;
ALTER TABLE radius_clients ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'approved';
ALTER TABLE radius_clients ADD COLUMN last_seen_at DATETIME;
ALTER TABLE radius_clients ADD COLUMN approved_at DATETIME;
ALTER TABLE radius_clients ADD COLUMN approved_by TEXT;
ALTER TABLE radius_clients ADD COLUMN owner_tenant TEXT;
ALTER TABLE radius_clients ADD COLUMN template_name TEXT;

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

CREATE INDEX IF NOT EXISTS idx_radius_clients_enrollment_id ON radius_clients(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_radius_clients_dynamic_source ON radius_clients(dynamic_source, lifecycle_status);
CREATE INDEX IF NOT EXISTS idx_radius_clients_last_seen ON radius_clients(last_seen_at);
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

const schemaV21 = `
CREATE TABLE IF NOT EXISTS radius_fallback_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	source TEXT NOT NULL,
	username_hash TEXT NOT NULL,
	realm TEXT,
	identity_source TEXT,
	role TEXT,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	upstream_status TEXT,
	policy_mode TEXT NOT NULL,
	fail_closed BOOLEAN DEFAULT 1,
	outage_started_at DATETIME,
	expires_at DATETIME,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_radius_fallback_events_observed_at ON radius_fallback_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_radius_fallback_events_decision ON radius_fallback_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_radius_fallback_events_username_hash ON radius_fallback_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_radius_fallback_events_source ON radius_fallback_events(source, observed_at);
`

const schemaV22 = `
CREATE TABLE IF NOT EXISTS identity_source_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	source_name TEXT NOT NULL,
	source_type TEXT NOT NULL,
	username_hash TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	latency_ms INTEGER DEFAULT 0,
	circuit_state TEXT NOT NULL DEFAULT 'closed',
	cache_used BOOLEAN DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS identity_source_cache (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	source_name TEXT NOT NULL,
	username_hash TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	role TEXT,
	groups_json TEXT NOT NULL DEFAULT '[]',
	identity_source TEXT,
	last_success_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(source_name, username_hash)
);

CREATE INDEX IF NOT EXISTS idx_identity_source_events_observed_at ON identity_source_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_source_events_source ON identity_source_events(source_name, observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_source_events_decision ON identity_source_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_source_events_username_hash ON identity_source_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_identity_source_cache_source_hash ON identity_source_cache(source_name, username_hash);
CREATE INDEX IF NOT EXISTS idx_identity_source_cache_expires ON identity_source_cache(expires_at);
`

const schemaV23 = `
CREATE TABLE IF NOT EXISTS mfa_totp_secrets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username_hash TEXT NOT NULL UNIQUE,
	secret_ciphertext TEXT NOT NULL,
	secret_nonce TEXT NOT NULL,
	algorithm TEXT NOT NULL DEFAULT 'SHA1',
	digits INTEGER NOT NULL DEFAULT 6,
	period_seconds INTEGER NOT NULL DEFAULT 30,
	issuer TEXT NOT NULL DEFAULT 'AegisNAS',
	enabled BOOLEAN NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_verified_at DATETIME
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username_hash TEXT NOT NULL,
	code_hash TEXT NOT NULL,
	used_at DATETIME,
	expires_at DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
	id TEXT PRIMARY KEY,
	state_hash TEXT NOT NULL UNIQUE,
	username_hash TEXT NOT NULL,
	source TEXT NOT NULL,
	role TEXT,
	identity_source TEXT,
	auth_method TEXT,
	challenge_type TEXT NOT NULL DEFAULT 'totp',
	status TEXT NOT NULL DEFAULT 'pending',
	attempt_count INTEGER NOT NULL DEFAULT 0,
	max_attempts INTEGER NOT NULL DEFAULT 5,
	prompt TEXT,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	verified_at DATETIME,
	failure_reason TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	CHECK (status IN ('pending', 'verified', 'expired', 'failed'))
);

CREATE TABLE IF NOT EXISTS mfa_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	username_hash TEXT NOT NULL,
	source TEXT NOT NULL,
	method TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	challenge_id TEXT,
	role TEXT,
	identity_source TEXT,
	auth_method TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_totp_secrets_username ON mfa_totp_secrets(username_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_username ON mfa_recovery_codes(username_hash, used_at, expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_state ON mfa_challenges(state_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_status_expires ON mfa_challenges(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_username ON mfa_challenges(username_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_mfa_events_observed_at ON mfa_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_mfa_events_decision ON mfa_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_mfa_events_username_hash ON mfa_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_mfa_events_method ON mfa_events(method, observed_at);
`

const schemaV24 = `
CREATE TABLE IF NOT EXISTS active_directory_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	domain TEXT,
	realm TEXT,
	source_name TEXT NOT NULL DEFAULT 'active-directory',
	username_hash TEXT NOT NULL,
	principal_hash TEXT,
	auth_method TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	latency_ms INTEGER DEFAULT 0,
	role TEXT,
	groups_json TEXT NOT NULL DEFAULT '[]',
	cache_used BOOLEAN DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS active_directory_group_cache (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username_hash TEXT NOT NULL,
	principal_hash TEXT,
	source_name TEXT NOT NULL DEFAULT 'active-directory',
	domain TEXT,
	realm TEXT,
	role TEXT,
	groups_json TEXT NOT NULL DEFAULT '[]',
	last_success_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(source_name, username_hash)
);

CREATE TABLE IF NOT EXISTS active_directory_health_checks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	checked_at DATETIME NOT NULL,
	domain TEXT,
	realm TEXT,
	component TEXT NOT NULL,
	status TEXT NOT NULL,
	message TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_active_directory_events_observed_at ON active_directory_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_events_decision ON active_directory_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_events_source ON active_directory_events(source_name, observed_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_events_username ON active_directory_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_group_cache_source_hash ON active_directory_group_cache(source_name, username_hash);
CREATE INDEX IF NOT EXISTS idx_active_directory_group_cache_expires ON active_directory_group_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_health_checked_at ON active_directory_health_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_active_directory_health_component ON active_directory_health_checks(component, checked_at);
`

const schemaV25 = `
CREATE TABLE IF NOT EXISTS mab_endpoints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mac TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL DEFAULT 'pending',
	role TEXT,
	vlan INTEGER DEFAULT 0,
	bandwidth_profile TEXT,
	acl_policy_name TEXT,
	tenant TEXT,
	device_group TEXT,
	posture TEXT,
	owner TEXT,
	source TEXT NOT NULL DEFAULT 'manual',
	description TEXT,
	expires_at DATETIME,
	last_seen_at DATETIME,
	profile_snapshot_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHECK (status IN ('approved', 'pending', 'quarantined', 'denied', 'expired'))
);

CREATE TABLE IF NOT EXISTS mab_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	mac TEXT NOT NULL,
	mac_hash TEXT NOT NULL,
	nas_identifier TEXT,
	nas_ip_address TEXT,
	nas_port TEXT,
	nas_port_type TEXT,
	called_station_id TEXT,
	username TEXT,
	decision TEXT NOT NULL,
	state TEXT NOT NULL,
	reason TEXT NOT NULL,
	role TEXT,
	vlan INTEGER DEFAULT 0,
	bandwidth_profile TEXT,
	acl_policy_name TEXT,
	tenant TEXT,
	device_group TEXT,
	posture TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mab_endpoints_status ON mab_endpoints(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_mab_endpoints_tenant ON mab_endpoints(tenant, status);
CREATE INDEX IF NOT EXISTS idx_mab_endpoints_last_seen ON mab_endpoints(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_mab_events_observed_at ON mab_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_mab_events_decision ON mab_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_mab_events_mac_hash ON mab_events(mac_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_mab_events_nas ON mab_events(nas_identifier, nas_ip_address, observed_at);
`

const schemaV26 = `
CREATE TABLE IF NOT EXISTS admin_webauthn_credentials (
	id TEXT PRIMARY KEY,
	credential_id_hash TEXT NOT NULL UNIQUE,
	credential_id_b64 TEXT NOT NULL,
	username_hash TEXT NOT NULL,
	subject TEXT NOT NULL,
	display_name TEXT,
	credential_name TEXT,
	public_key_cose_b64 TEXT NOT NULL,
	public_key_alg INTEGER NOT NULL,
	sign_count INTEGER NOT NULL DEFAULT 0,
	transports_json TEXT NOT NULL DEFAULT '[]',
	aaguid TEXT,
	attestation_format TEXT,
	user_verified_required BOOLEAN DEFAULT 0,
	backup_eligible BOOLEAN DEFAULT 0,
	backup_state BOOLEAN DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used_at DATETIME,
	revoked_at DATETIME,
	revoked_by TEXT
);

CREATE TABLE IF NOT EXISTS admin_webauthn_challenges (
	id TEXT PRIMARY KEY,
	state_hash TEXT NOT NULL UNIQUE,
	challenge TEXT NOT NULL,
	challenge_hash TEXT NOT NULL,
	ceremony TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	username_hash TEXT NOT NULL,
	subject TEXT NOT NULL,
	display_name TEXT,
	credential_name TEXT,
	role TEXT,
	source TEXT,
	provider TEXT,
	tenants_json TEXT NOT NULL DEFAULT '[]',
	groups_json TEXT NOT NULL DEFAULT '[]',
	first_factor TEXT,
	origin TEXT,
	rp_id TEXT,
	attempt_count INTEGER NOT NULL DEFAULT 0,
	max_attempts INTEGER NOT NULL DEFAULT 5,
	expires_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	verified_at DATETIME,
	failure_reason TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	CHECK (ceremony IN ('registration', 'authentication')),
	CHECK (status IN ('pending', 'verified', 'expired', 'failed'))
);

CREATE TABLE IF NOT EXISTS admin_webauthn_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	username_hash TEXT NOT NULL,
	subject TEXT,
	source TEXT NOT NULL,
	ceremony TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	credential_id_hash TEXT,
	role TEXT,
	provider TEXT,
	origin TEXT,
	rp_id TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_webauthn_credentials_subject ON admin_webauthn_credentials(subject, enabled);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_credentials_username ON admin_webauthn_credentials(username_hash, enabled);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_credentials_hash ON admin_webauthn_credentials(credential_id_hash);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_challenges_state ON admin_webauthn_challenges(state_hash);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_challenges_status_expires ON admin_webauthn_challenges(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_challenges_username ON admin_webauthn_challenges(username_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_events_observed_at ON admin_webauthn_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_events_decision ON admin_webauthn_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_events_username ON admin_webauthn_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_admin_webauthn_events_ceremony ON admin_webauthn_events(ceremony, observed_at);
`

const schemaV27 = `
CREATE TABLE IF NOT EXISTS eap_method_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	method TEXT NOT NULL,
	inner_method TEXT,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	user_name_hash TEXT,
	calling_station_hash TEXT,
	identity_source TEXT,
	eap_message_present BOOLEAN DEFAULT 0,
	message_authenticator_present BOOLEAN DEFAULT 0,
	certificate_presented BOOLEAN DEFAULT 0,
	tls_version TEXT,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eap_method_events_observed_at ON eap_method_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_method_events_method ON eap_method_events(method, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_method_events_decision ON eap_method_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_method_events_nas ON eap_method_events(nas_identifier, nas_type, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_method_events_user ON eap_method_events(user_name_hash, observed_at);
`

const schemaV28 = `
CREATE TABLE IF NOT EXISTS eap_teap_chain_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	chain_mode TEXT NOT NULL,
	chain_state TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	outer_identity_hash TEXT,
	user_identity_hash TEXT,
	machine_identity_hash TEXT,
	identity_source TEXT,
	inner_method TEXT,
	crypto_binding_valid BOOLEAN DEFAULT 0,
	channel_binding_present BOOLEAN DEFAULT 0,
	channel_binding_valid BOOLEAN DEFAULT 0,
	identity_type_present BOOLEAN DEFAULT 0,
	pac_presented BOOLEAN DEFAULT 0,
	pac_provisioning_requested BOOLEAN DEFAULT 0,
	eap_payload_present BOOLEAN DEFAULT 0,
	basic_password_auth BOOLEAN DEFAULT 0,
	intermediate_result_present BOOLEAN DEFAULT 0,
	intermediate_result_success BOOLEAN DEFAULT 0,
	final_result_present BOOLEAN DEFAULT 0,
	final_result_success BOOLEAN DEFAULT 0,
	step_count INTEGER DEFAULT 0,
	tls_version TEXT,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_observed_at ON eap_teap_chain_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_decision ON eap_teap_chain_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_chain_mode ON eap_teap_chain_events(chain_mode, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_nas ON eap_teap_chain_events(nas_identifier, nas_type, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_user ON eap_teap_chain_events(user_identity_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_teap_chain_events_machine ON eap_teap_chain_events(machine_identity_hash, observed_at);
`

const schemaV29 = `
CREATE TABLE IF NOT EXISTS eap_fast_pwd_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	method TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	identity_hash TEXT,
	calling_station_hash TEXT,
	identity_source TEXT,
	inner_method TEXT,
	crypto_binding_valid BOOLEAN DEFAULT 0,
	pac_presented BOOLEAN DEFAULT 0,
	pac_provisioning_requested BOOLEAN DEFAULT 0,
	pac_opaque_key_available BOOLEAN DEFAULT 0,
	anonymous_provisioning BOOLEAN DEFAULT 0,
	eap_payload_present BOOLEAN DEFAULT 0,
	provisioning_attempt_count INTEGER DEFAULT 0,
	password_proof_valid BOOLEAN DEFAULT 0,
	replay_detected BOOLEAN DEFAULT 0,
	pwd_group INTEGER DEFAULT 0,
	pwd_server_id_hash TEXT,
	tls_version TEXT,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eap_fast_pwd_events_observed_at ON eap_fast_pwd_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_fast_pwd_events_method ON eap_fast_pwd_events(method, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_fast_pwd_events_decision ON eap_fast_pwd_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_fast_pwd_events_nas ON eap_fast_pwd_events(nas_identifier, nas_type, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_fast_pwd_events_identity ON eap_fast_pwd_events(identity_hash, observed_at);
`

const schemaV30 = `
CREATE TABLE IF NOT EXISTS eap_sim_aka_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	method TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	identity_hash TEXT,
	permanent_identity_hash TEXT,
	pseudonym_identity_hash TEXT,
	reauth_identity_hash TEXT,
	calling_station_hash TEXT,
	identity_source TEXT,
	vector_provider TEXT,
	vector_provider_available BOOLEAN DEFAULT 0,
	vector_available BOOLEAN DEFAULT 0,
	vector_fresh BOOLEAN DEFAULT 0,
	vector_age_seconds INTEGER DEFAULT 0,
	triplet_count INTEGER DEFAULT 0,
	quintuplet_count INTEGER DEFAULT 0,
	res_valid BOOLEAN DEFAULT 0,
	mac_valid BOOLEAN DEFAULT 0,
	autn_valid BOOLEAN DEFAULT 0,
	auts_valid BOOLEAN DEFAULT 0,
	resync_requested BOOLEAN DEFAULT 0,
	resync_age_seconds INTEGER DEFAULT 0,
	network_name_hash TEXT,
	kdf_valid BOOLEAN DEFAULT 0,
	replay_detected BOOLEAN DEFAULT 0,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_observed_at ON eap_sim_aka_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_method ON eap_sim_aka_events(method, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_decision ON eap_sim_aka_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_nas ON eap_sim_aka_events(nas_identifier, nas_type, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_identity ON eap_sim_aka_events(identity_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_permanent_identity ON eap_sim_aka_events(permanent_identity_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_sim_aka_events_pseudonym_identity ON eap_sim_aka_events(pseudonym_identity_hash, observed_at);
`

const schemaV31 = `
CREATE TABLE IF NOT EXISTS eap_machine_user_correlations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	correlation_key TEXT NOT NULL,
	correlation_id_hash TEXT,
	correlation_mode TEXT NOT NULL,
	correlation_state TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	calling_station_hash TEXT,
	machine_calling_station_hash TEXT,
	user_calling_station_hash TEXT,
	machine_nas_identifier TEXT,
	user_nas_identifier TEXT,
	outer_identity_hash TEXT,
	machine_identity_hash TEXT,
	user_identity_hash TEXT,
	identity_source TEXT,
	machine_method TEXT,
	user_method TEXT,
	machine_authenticated BOOLEAN DEFAULT 0,
	user_authenticated BOOLEAN DEFAULT 0,
	same_calling_station BOOLEAN DEFAULT 0,
	same_nas BOOLEAN DEFAULT 0,
	machine_before_user BOOLEAN DEFAULT 0,
	machine_auth_age_seconds INTEGER DEFAULT 0,
	user_auth_age_seconds INTEGER DEFAULT 0,
	machine_role TEXT,
	user_role TEXT,
	effective_role TEXT,
	device_posture TEXT,
	conflict_detected BOOLEAN DEFAULT 0,
	stale_machine_auth BOOLEAN DEFAULT 0,
	teap_chain_complete BOOLEAN DEFAULT 0,
	identity_type_present BOOLEAN DEFAULT 0,
	crypto_binding_valid BOOLEAN DEFAULT 0,
	channel_binding_valid BOOLEAN DEFAULT 0,
	replay_detected BOOLEAN DEFAULT 0,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS eap_machine_user_session_state (
	correlation_key TEXT PRIMARY KEY,
	updated_at DATETIME NOT NULL,
	decision TEXT NOT NULL,
	correlation_state TEXT NOT NULL,
	correlation_mode TEXT NOT NULL,
	nas_identifier TEXT,
	nas_type TEXT,
	calling_station_hash TEXT,
	machine_identity_hash TEXT,
	user_identity_hash TEXT,
	machine_method TEXT,
	user_method TEXT,
	machine_authenticated BOOLEAN DEFAULT 0,
	user_authenticated BOOLEAN DEFAULT 0,
	machine_auth_age_seconds INTEGER DEFAULT 0,
	user_auth_age_seconds INTEGER DEFAULT 0,
	effective_role TEXT,
	device_posture TEXT,
	conflict_detected BOOLEAN DEFAULT 0,
	stale_machine_auth BOOLEAN DEFAULT 0,
	policy_mode TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_observed_at ON eap_machine_user_correlations(observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_decision ON eap_machine_user_correlations(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_mode ON eap_machine_user_correlations(correlation_mode, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_state ON eap_machine_user_correlations(correlation_state, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_nas ON eap_machine_user_correlations(nas_identifier, nas_type, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_machine ON eap_machine_user_correlations(machine_identity_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_user ON eap_machine_user_correlations(user_identity_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_correlations_calling ON eap_machine_user_correlations(calling_station_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_state_updated ON eap_machine_user_session_state(updated_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_state_decision ON eap_machine_user_session_state(decision, updated_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_state_machine ON eap_machine_user_session_state(machine_identity_hash, updated_at);
CREATE INDEX IF NOT EXISTS idx_eap_machine_user_state_user ON eap_machine_user_session_state(user_identity_hash, updated_at);
`

const schemaV32 = `
CREATE TABLE IF NOT EXISTS certificate_lifecycle_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	protocol TEXT NOT NULL,
	decision TEXT NOT NULL,
	reason TEXT NOT NULL,
	template TEXT,
	issuer TEXT,
	issuer_state TEXT,
	tenant TEXT,
	device_id_hash TEXT,
	subject_hash TEXT,
	san_hash TEXT,
	serial_hash TEXT,
	existing_serial_hash TEXT,
	renewal BOOLEAN DEFAULT 0,
	renewal_due BOOLEAN DEFAULT 0,
	inventory_status TEXT,
	revocation_blocked BOOLEAN DEFAULT 0,
	key_type TEXT,
	key_bits INTEGER DEFAULT 0,
	curve TEXT,
	validity_days INTEGER DEFAULT 0,
	escrow_requested BOOLEAN DEFAULT 0,
	proof_of_possession BOOLEAN DEFAULT 0,
	csr_present BOOLEAN DEFAULT 0,
	csr_valid BOOLEAN DEFAULT 0,
	csr_signature_valid BOOLEAN DEFAULT 0,
	device_bound BOOLEAN DEFAULT 0,
	revocation_checked BOOLEAN DEFAULT 0,
	crl_reachable BOOLEAN DEFAULT 0,
	ocsp_reachable BOOLEAN DEFAULT 0,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificate_lifecycle_inventory (
	certificate_key TEXT PRIMARY KEY,
	updated_at DATETIME NOT NULL,
	status TEXT NOT NULL,
	protocol TEXT,
	template TEXT,
	issuer TEXT,
	issuer_state TEXT,
	tenant TEXT,
	device_id_hash TEXT,
	subject_hash TEXT,
	san_hash TEXT,
	serial_hash TEXT,
	key_type TEXT,
	key_bits INTEGER DEFAULT 0,
	curve TEXT,
	not_before DATETIME,
	not_after DATETIME,
	renewal_due BOOLEAN DEFAULT 0,
	revoked_at DATETIME,
	revoke_reason TEXT,
	policy_mode TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_observed_at ON certificate_lifecycle_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_decision ON certificate_lifecycle_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_protocol ON certificate_lifecycle_events(protocol, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_template ON certificate_lifecycle_events(template, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_issuer ON certificate_lifecycle_events(issuer, issuer_state, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_device ON certificate_lifecycle_events(device_id_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_events_serial ON certificate_lifecycle_events(serial_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_inventory_status ON certificate_lifecycle_inventory(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_inventory_issuer ON certificate_lifecycle_inventory(issuer, issuer_state, updated_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_inventory_device ON certificate_lifecycle_inventory(device_id_hash, updated_at);
CREATE INDEX IF NOT EXISTS idx_certificate_lifecycle_inventory_serial ON certificate_lifecycle_inventory(serial_hash, updated_at);
`

const schemaV33 = `
CREATE TABLE IF NOT EXISTS supplicant_lifecycle_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	observed_at DATETIME NOT NULL,
	protocol TEXT NOT NULL,
	platform TEXT NOT NULL,
	decision TEXT NOT NULL,
	action TEXT NOT NULL,
	reason TEXT NOT NULL,
	username_hash TEXT,
	device_id_hash TEXT,
	tenant TEXT,
	eap_method TEXT,
	inner_method TEXT,
	identity_source TEXT,
	password_expired BOOLEAN DEFAULT 0,
	days_until_expiry INTEGER DEFAULT 0,
	password_change_requested BOOLEAN DEFAULT 0,
	password_change_required BOOLEAN DEFAULT 0,
	password_changed BOOLEAN DEFAULT 0,
	old_password_verified BOOLEAN DEFAULT 0,
	new_password_meets_policy BOOLEAN DEFAULT 0,
	mfa_complete BOOLEAN DEFAULT 0,
	tls_protected BOOLEAN DEFAULT 0,
	verifier_compatible BOOLEAN DEFAULT 0,
	profile_requested BOOLEAN DEFAULT 0,
	profile_signed BOOLEAN DEFAULT 0,
	signing_key_available BOOLEAN DEFAULT 0,
	trust_anchor_pinned BOOLEAN DEFAULT 0,
	server_name_matched BOOLEAN DEFAULT 0,
	delivery_token_valid BOOLEAN DEFAULT 0,
	device_managed BOOLEAN DEFAULT 0,
	certificate_lifecycle_ready BOOLEAN DEFAULT 0,
	policy_mode TEXT,
	latency_ms INTEGER DEFAULT 0,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS supplicant_profile_deliveries (
	delivery_key TEXT PRIMARY KEY,
	updated_at DATETIME NOT NULL,
	status TEXT NOT NULL,
	platform TEXT NOT NULL,
	username_hash TEXT,
	device_id_hash TEXT,
	tenant TEXT,
	ssid TEXT,
	eap_method TEXT,
	inner_method TEXT,
	profile_hash TEXT,
	signature_fingerprint TEXT,
	content_type TEXT,
	file_extension TEXT,
	expires_at DATETIME,
	policy_mode TEXT,
	details_json TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_observed_at ON supplicant_lifecycle_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_decision ON supplicant_lifecycle_events(decision, observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_platform ON supplicant_lifecycle_events(platform, observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_eap ON supplicant_lifecycle_events(eap_method, inner_method, observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_username ON supplicant_lifecycle_events(username_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_lifecycle_events_device ON supplicant_lifecycle_events(device_id_hash, observed_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_profile_deliveries_status ON supplicant_profile_deliveries(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_profile_deliveries_platform ON supplicant_profile_deliveries(platform, updated_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_profile_deliveries_username ON supplicant_profile_deliveries(username_hash, updated_at);
CREATE INDEX IF NOT EXISTS idx_supplicant_profile_deliveries_device ON supplicant_profile_deliveries(device_id_hash, updated_at);
`

const schemaV34 = `
CREATE TABLE IF NOT EXISTS policy_engine_evaluations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	evaluation_id TEXT UNIQUE NOT NULL,
	evaluated_at DATETIME NOT NULL,
	policy_set_hash TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	username_hash TEXT,
	calling_station_hash TEXT,
	tenant TEXT,
	decision TEXT NOT NULL,
	allowed BOOLEAN DEFAULT 0,
	quarantine BOOLEAN DEFAULT 0,
	matched_rules_json TEXT NOT NULL DEFAULT '[]',
	conflicts_json TEXT NOT NULL DEFAULT '[]',
	trace_json TEXT NOT NULL DEFAULT '[]',
	request_summary_json TEXT NOT NULL DEFAULT '{}',
	legacy_rule_count INTEGER DEFAULT 0,
	typed_rule_count INTEGER DEFAULT 0,
	invalid_rule_count INTEGER DEFAULT 0,
	latency_ms INTEGER DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHECK (decision IN ('allow', 'deny', 'quarantine'))
);

CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_evaluated_at ON policy_engine_evaluations(evaluated_at);
CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_decision ON policy_engine_evaluations(decision, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_policy_hash ON policy_engine_evaluations(policy_set_hash, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_username ON policy_engine_evaluations(username_hash, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_calling_station ON policy_engine_evaluations(calling_station_hash, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_policy_engine_evaluations_tenant ON policy_engine_evaluations(tenant, evaluated_at);
`
