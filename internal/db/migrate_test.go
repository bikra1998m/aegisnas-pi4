package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrate(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	err = Init(tmpfile.Name())
	require.NoError(t, err)
	defer Close()

	err = Migrate()
	assert.NoError(t, err)

	var version int
	err = DB.QueryRow("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version)
	assert.NoError(t, err)
	assert.Equal(t, LatestSchemaVersion(), version)

	tables := []string{"local_users", "roles", "bandwidth_profiles", "sessions", "runtime_status", "guest_registrations", "device_inventory", "device_certificates", "admin_principals", "admin_sessions", "network_apply_history", "dhcp_lease_history", "ha_history", "integration_history", "upstream_aaa_history", "vendor_observability", "acl_policies", "vendor_identity_assignments", "vendor_identity_migrations", "database_backend_events", "radius_packet_hardening_events", "radius_accounting_spool", "radius_accounting_spool_attempts", "radacct", "radpostauth", "radius_sql_accounting_reconcile_events", "nas_client_enrollments", "nas_client_capability_templates", "nas_client_events", "radius_fallback_events", "identity_source_events", "identity_source_cache", "mfa_totp_secrets", "mfa_recovery_codes", "mfa_challenges", "mfa_events", "active_directory_events", "active_directory_group_cache", "active_directory_health_checks", "mab_endpoints", "mab_events", "admin_webauthn_credentials", "admin_webauthn_challenges", "admin_webauthn_events", "eap_method_events", "eap_teap_chain_events", "eap_fast_pwd_events", "eap_sim_aka_events", "eap_machine_user_correlations", "eap_machine_user_session_state", "certificate_lifecycle_events", "certificate_lifecycle_inventory", "supplicant_lifecycle_events", "supplicant_profile_deliveries", "policy_engine_evaluations", "policy_set_versions", "policy_set_approvals", "policy_set_activation_events", "policy_set_simulations", "policy_simulation_analyses", "subscriber_service_chains", "subscriber_service_events", "subscriber_service_accounting", "tacacs_command_sets", "tacacs_authorization_events", "tacacs_accounting_records", "tacacs_protocol_events", "tenant_profiles", "tenant_resource_bindings", "tenant_isolation_events"}
	for _, tbl := range tables {
		var count int
		err = DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 1, count, "table %s should exist", tbl)
	}

	var sessionTimeoutColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('sessions') WHERE name='session_timeout'").Scan(&sessionTimeoutColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, sessionTimeoutColumnCount)

	var nasTypeColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('radius_clients') WHERE name='nas_type'").Scan(&nasTypeColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, nasTypeColumnCount)
	var replayColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('policy_engine_evaluations') WHERE name='request_replay_json'").Scan(&replayColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, replayColumnCount)
	var serviceChainColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('policy_rules') WHERE name='service_chain_json'").Scan(&serviceChainColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, serviceChainColumnCount)
	var serviceChainChangeColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('policy_simulation_analyses') WHERE name='service_chain_change_count'").Scan(&serviceChainChangeColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, serviceChainChangeColumnCount)
	for _, binding := range []struct {
		table  string
		column string
	}{
		{"policy_set_versions", "tenant"},
		{"policy_set_activation_events", "tenant"},
		{"policy_set_simulations", "tenant"},
		{"policy_simulation_analyses", "tenant"},
	} {
		var columnCount int
		err = DB.QueryRow("SELECT count(*) FROM pragma_table_info(?) WHERE name=?", binding.table, binding.column).Scan(&columnCount)
		assert.NoError(t, err)
		assert.Equal(t, 1, columnCount, "%s.%s should exist", binding.table, binding.column)
	}
	for _, column := range []string{"transport", "radsec_certificate_cn", "radsec_certificate_issuer", "radsec_radius_v11", "secret_ref", "dynamic_source", "enrollment_id", "capabilities_json", "vendor", "model", "firmware_version", "serial_number", "lifecycle_status", "last_seen_at", "approved_at", "approved_by", "owner_tenant", "template_name"} {
		var count int
		err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('radius_clients') WHERE name=?", column).Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 1, count, "radius_clients.%s should exist", column)
	}
	for _, column := range []string{"transport", "radsec_port", "tls_version", "tls_cipher_suite", "tls_alpn", "peer_subject", "peer_issuer", "peer_serial", "peer_not_after"} {
		var count int
		err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('upstream_aaa_history') WHERE name=?", column).Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 1, count, "upstream_aaa_history.%s should exist", column)
	}

	for _, binding := range []struct {
		table  string
		column string
	}{
		{"roles", "acl_policy_name"},
		{"policy_rules", "acl_policy_name"},
		{"sessions", "acl_policy_name"},
	} {
		var columnCount int
		err = DB.QueryRow("SELECT count(*) FROM pragma_table_info(?) WHERE name=?", binding.table, binding.column).Scan(&columnCount)
		assert.NoError(t, err)
		assert.Equal(t, 1, columnCount, "%s.%s should exist", binding.table, binding.column)
	}

	for _, column := range []string{"hostname", "dhcp_client_id", "dhcp_fingerprint", "lldp_chassis_id", "lldp_port_id", "cdp_device_id", "cdp_port_id", "mac_oui", "risk_score", "risk_reasons_json"} {
		var columnCount int
		err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('device_inventory') WHERE name=?", column).Scan(&columnCount)
		assert.NoError(t, err)
		assert.Equal(t, 1, columnCount, "device_inventory.%s should exist", column)
	}

	var backendEventCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM database_backend_events WHERE backend = 'sqlite' AND status = 'migrated'").Scan(&backendEventCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, backendEventCount)
}

func TestMigrateRepairsLegacyRadiusClientNASTypeColumn(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-legacy-radius-clients-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	err = Init(tmpfile.Name())
	require.NoError(t, err)
	defer Close()

	_, err = DB.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = DB.Exec("INSERT INTO schema_version (version) VALUES (?)", LatestSchemaVersion())
	require.NoError(t, err)
	_, err = DB.Exec(`CREATE TABLE radius_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		shortname TEXT UNIQUE NOT NULL,
		ipaddr TEXT NOT NULL,
		secret TEXT NOT NULL,
		enabled BOOLEAN DEFAULT 1
	)`)
	require.NoError(t, err)
	_, err = DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, enabled)
		VALUES ('legacy-ap', '10.20.0.2', 'secret', 1)`)
	require.NoError(t, err)

	err = Migrate()
	require.NoError(t, err)

	var nasTypeColumnCount int
	err = DB.QueryRow("SELECT count(*) FROM pragma_table_info('radius_clients') WHERE name='nas_type'").Scan(&nasTypeColumnCount)
	assert.NoError(t, err)
	assert.Equal(t, 1, nasTypeColumnCount)

	var nasType string
	err = DB.QueryRow("SELECT nas_type FROM radius_clients WHERE shortname = 'legacy-ap'").Scan(&nasType)
	assert.NoError(t, err)
	assert.Equal(t, "other", nasType)
}

func TestSeed(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	err = Init(tmpfile.Name())
	require.NoError(t, err)
	defer Close()

	err = Migrate()
	require.NoError(t, err)

	err = Seed()
	assert.NoError(t, err)

	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM roles").Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 4, count)

	err = DB.QueryRow("SELECT COUNT(*) FROM local_users WHERE username='admin'").Scan(&count)
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
}
