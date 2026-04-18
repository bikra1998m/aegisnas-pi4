package acceptance

import (
	"testing"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func TestRADIUSAccounting(t *testing.T) {
	// Insert a test session start
	rec := &radius.AccountingRecord{
		SessionID:        "test-session-1",
		Username:         "testuser",
		CallingStationID: "aa:bb:cc:dd:ee:ff",
		FramedIPAddress:  "10.0.0.100",
		AcctStatusType:   "Start",
		Timestamp:        time.Now(),
	}
	err := radius.ProcessAccounting(rec)
	if err != nil {
		t.Fatalf("accounting start failed: %v", err)
	}

	// Verify session record exists
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ? AND end_time IS NULL", rec.SessionID).Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1 {
		t.Error("session not recorded in database")
	}

	// Send Stop
	rec.AcctStatusType = "Stop"
	rec.Timestamp = time.Now()
	rec.AcctInputOctets = 1024
	rec.AcctOutputOctets = 2048
	err = radius.ProcessAccounting(rec)
	if err != nil {
		t.Fatalf("accounting stop failed: %v", err)
	}

	// Verify end_time set
	var endTime string
	err = db.DB.QueryRow("SELECT end_time FROM sessions WHERE id = ?", rec.SessionID).Scan(&endTime)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if endTime == "" {
		t.Error("end_time not set")
	}
}
