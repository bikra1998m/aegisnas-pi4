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

	tables := []string{"local_users", "roles", "bandwidth_profiles", "sessions", "runtime_status", "guest_registrations", "device_inventory", "device_certificates", "admin_principals", "admin_sessions", "network_apply_history", "dhcp_lease_history", "ha_history", "integration_history", "upstream_aaa_history", "vendor_observability", "acl_policies", "vendor_identity_assignments", "vendor_identity_migrations"}
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
	for _, column := range []string{"transport", "radsec_certificate_cn", "radsec_certificate_issuer", "radsec_radius_v11", "secret_ref"} {
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
