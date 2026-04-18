package acceptance

import (
	"testing"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	session "github.com/yourorg/aegisnas-pi4/internal/sessions"
	"go.uber.org/zap"
)

func TestSessionTimeoutEnforcement(t *testing.T) {
	// Create a session with short idle timeout
	_, err := db.DB.Exec(`INSERT INTO sessions (id, username, start_time, last_activity, role)
		VALUES ('timeout-test', 'testuser', ?, ?, 'guest-basic')`, time.Now().Add(-1*time.Hour), time.Now().Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	// Set role idle timeout to 5 minutes
	_, err = db.DB.Exec(`UPDATE roles SET idle_timeout = 300 WHERE name = 'guest-basic'`)
	if err != nil {
		t.Fatalf("failed to set idle timeout: %v", err)
	}

	mgr, err := session.NewManager(testCfg, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	// Trigger enforcement
	mgr.StartTimeoutEnforcer(nil, 0) // manual call
	// Wait a bit for enforcement goroutine
	time.Sleep(100 * time.Millisecond)

	// Check session was terminated
	var endTime string
	err = db.DB.QueryRow("SELECT end_time FROM sessions WHERE id = 'timeout-test'").Scan(&endTime)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if endTime == "" {
		t.Error("session should have been terminated due to idle timeout")
	}
}
