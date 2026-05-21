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
	assert.Equal(t, 9, version)

	tables := []string{"local_users", "roles", "bandwidth_profiles", "sessions", "runtime_status", "guest_registrations", "device_inventory", "device_certificates", "admin_principals", "admin_sessions", "network_apply_history", "dhcp_lease_history", "ha_history", "integration_history"}
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
