package session

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func setupTestDB(t *testing.T) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	err := db.Init(dbPath)
	require.NoError(t, err)
	err = db.Migrate()
	require.NoError(t, err)
	err = db.Seed()
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})
}

func requireSessionStopped(t *testing.T, sessionID, expectedReason string) {
	t.Helper()

	var (
		endTime sql.NullString
		reason  string
	)

	require.Eventually(t, func() bool {
		err := db.DB.QueryRow("SELECT end_time, COALESCE(stop_reason, '') FROM sessions WHERE id = ?", sessionID).Scan(&endTime, &reason)
		return err == nil && endTime.Valid && reason == expectedReason
	}, time.Second, 10*time.Millisecond)

	assert.NotEmpty(t, endTime.String)
	assert.Equal(t, expectedReason, reason)
}

func TestManager_EnforceConcurrentLimit(t *testing.T) {
	setupTestDB(t)

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

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	_, err = db.DB.Exec(`INSERT INTO sessions (id, username, start_time) VALUES ('test', 'user', ?)`, time.Now())
	require.NoError(t, err)

	mgr.terminateSession("test", "test reason")

	requireSessionStopped(t, "test", "test reason")
}

func TestManager_EnforceTimeoutsKeepsFreshSessionWithOffsetTimestamp(t *testing.T) {
	setupTestDB(t)

	cfg := &config.Config{}
	logger := zap.NewNop()
	mgr, err := NewManager(cfg, logger)
	require.NoError(t, err)

	behindUTC := time.FixedZone("EDT", -4*60*60)
	fresh := time.Now().Add(-1 * time.Minute).In(behindUTC)
	_, err = db.DB.Exec(`INSERT INTO sessions (
			id, username, role, start_time, last_activity, session_timeout, idle_timeout
		) VALUES ('fresh-offset', 'guest1', 'guest-basic', ?, ?, 3600, 600)`,
		fresh.Format("2006-01-02 15:04:05.999999999 -0700 MST"),
		fresh.Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	require.NoError(t, err)

	mgr.enforceTimeouts()

	var ended sql.NullString
	err = db.DB.QueryRow(`SELECT end_time FROM sessions WHERE id = 'fresh-offset'`).Scan(&ended)
	require.NoError(t, err)
	require.False(t, ended.Valid, "fresh offset timestamp session should remain active")
}

func TestManager_ReclassifyByCriteriaImmediateSessionTimeout(t *testing.T) {
	setupTestDB(t)

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

	requireSessionStopped(t, "coa-session-timeout", "Session timeout reached")
}

func TestManager_ReclassifyByCriteriaImmediateIdleTimeout(t *testing.T) {
	setupTestDB(t)

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

	requireSessionStopped(t, "coa-idle-timeout", "Idle timeout reached")
}

func TestManager_ReclassifyByCriteriaVLANChangeRequiresReauth(t *testing.T) {
	setupTestDB(t)

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

	requireSessionStopped(t, "coa-vlan", "VLAN reassignment requested")
}
