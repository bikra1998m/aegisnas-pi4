package session

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func setupTestDB(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	err = db.Init(tmpfile.Name())
	require.NoError(t, err)
	err = db.Migrate()
	require.NoError(t, err)
	err = db.Seed()
	require.NoError(t, err)
}

func TestManager_EnforceConcurrentLimit(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	// Insert two active sessions for user "testuser"
	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, start_time) VALUES ('s1', 'testuser', ?), ('s2', 'testuser', ?)`,
		time.Now(), time.Now())
	require.NoError(t, err)

	exceeded, err := mgr.EnforceConcurrentLimit("testuser")
	assert.NoError(t, err)
	assert.True(t, exceeded)
}

func TestManager_TerminateSession(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, start_time) VALUES ('test', 'user', ?)`, time.Now())
	require.NoError(t, err)

	mgr.terminateSession("test", "test reason")

	var endTime sql.NullString
	var reason string
	err = db.DB.QueryRow("SELECT end_time, stop_reason FROM sessions WHERE id = 'test'").Scan(&endTime, &reason)
	assert.NoError(t, err)
	assert.True(t, endTime.Valid)
	assert.NotEmpty(t, endTime.String)
	assert.Equal(t, "test reason", reason)
}

func TestManager_ReclassifyByCriteriaImmediateSessionTimeout(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	start := time.Now().Add(-2 * time.Hour)
	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, start_time, last_activity) VALUES ('coa-session-timeout', 'user', ?, ?)`, start, time.Now())
	require.NoError(t, err)

	ok, err := mgr.ReclassifyByCriteria("coa-session-timeout", "", "", PolicyUpdate{SessionTimeout: 60})
	require.NoError(t, err)
	require.True(t, ok)

	var endTime sql.NullString
	var reason string
	err = db.DB.QueryRow("SELECT end_time, stop_reason FROM sessions WHERE id = 'coa-session-timeout'").Scan(&endTime, &reason)
	require.NoError(t, err)
	assert.True(t, endTime.Valid)
	assert.Equal(t, "Session timeout reached", reason)
}

func TestManager_ReclassifyByCriteriaImmediateIdleTimeout(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	start := time.Now().Add(-30 * time.Minute)
	lastActivity := time.Now().Add(-20 * time.Minute)
	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, start_time, last_activity) VALUES ('coa-idle-timeout', 'user', ?, ?)`, start, lastActivity)
	require.NoError(t, err)

	ok, err := mgr.ReclassifyByCriteria("coa-idle-timeout", "", "", PolicyUpdate{IdleTimeout: 60})
	require.NoError(t, err)
	require.True(t, ok)

	var endTime sql.NullString
	var reason string
	err = db.DB.QueryRow("SELECT end_time, stop_reason FROM sessions WHERE id = 'coa-idle-timeout'").Scan(&endTime, &reason)
	require.NoError(t, err)
	assert.True(t, endTime.Valid)
	assert.Equal(t, "Idle timeout reached", reason)
}

func TestManager_ReclassifyByCriteriaVLANChangeRequiresReauth(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, mac, ip, vlan, start_time, last_activity) VALUES ('coa-vlan', 'user', 'aa:bb', '10.20.0.10', 20, ?, ?)`,
		time.Now().Add(-5*time.Minute), time.Now())
	require.NoError(t, err)

	ok, err := mgr.ReclassifyByCriteria("coa-vlan", "", "", PolicyUpdate{VLAN: 30})
	require.NoError(t, err)
	require.True(t, ok)

	var endTime sql.NullString
	var reason string
	err = db.DB.QueryRow("SELECT end_time, COALESCE(stop_reason, '') FROM sessions WHERE id = 'coa-vlan'").Scan(&endTime, &reason)
	require.NoError(t, err)
	assert.True(t, endTime.Valid)
	assert.Equal(t, "VLAN reassignment requested", reason)
}
