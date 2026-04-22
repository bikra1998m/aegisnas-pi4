package radius

import (
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

// AccountingRecord represents a RADIUS accounting packet.
type AccountingRecord struct {
	SessionID        string
	Username         string
	NASIPAddress     string
	NASPort          int
	AcctStatusType   string // Start, Stop, Interim-Update
	AcctInputOctets  uint64
	AcctOutputOctets uint64
	AcctSessionTime  int
	CalledStationID  string
	CallingStationID string
	FramedIPAddress  string
	StopReason       string
	Role             string
	BandwidthProfile string
	FilterID         string
	RadiusClass      string
	VLAN             int
	SessionTimeout   int
	IdleTimeout      int
	Timestamp        time.Time
}

// ProcessAccounting stores an accounting record in the database.
func ProcessAccounting(rec *AccountingRecord) error {
	logger := zap.L()
	if db.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	switch rec.AcctStatusType {
	case "Start":
		_, err := db.DB.Exec(`INSERT INTO sessions (id, username, mac, ip, start_time, last_activity, radius_session_id)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				username = excluded.username,
				mac = excluded.mac,
				ip = excluded.ip,
				last_activity = excluded.last_activity,
				radius_session_id = excluded.radius_session_id`,
			rec.SessionID, rec.Username, rec.CallingStationID, rec.FramedIPAddress,
			rec.Timestamp, rec.Timestamp, rec.SessionID)
		if err != nil {
			logger.Error("accounting start insert failed", zap.Error(err))
			return err
		}
	case "Stop":
		stopReason := strings.TrimSpace(rec.StopReason)
		if stopReason == "" {
			stopReason = "user"
		}
		_, err := db.DB.Exec(`UPDATE sessions SET end_time = ?, stop_reason = ?, bytes_in = ?, bytes_out = ?, acct_session_time = ?, last_activity = ?
			WHERE radius_session_id = ? OR id = ?`,
			rec.Timestamp, stopReason, rec.AcctInputOctets, rec.AcctOutputOctets, rec.AcctSessionTime, rec.Timestamp, rec.SessionID, rec.SessionID)
		if err != nil {
			logger.Error("accounting stop update failed", zap.Error(err))
			return err
		}
	case "Interim-Update":
		_, err := db.DB.Exec(`UPDATE sessions SET bytes_in = ?, bytes_out = ?, acct_session_time = ?, last_activity = ?
			WHERE radius_session_id = ? OR id = ?`,
			rec.AcctInputOctets, rec.AcctOutputOctets, rec.AcctSessionTime, rec.Timestamp, rec.SessionID, rec.SessionID)
		if err != nil {
			logger.Error("accounting interim update failed", zap.Error(err))
			return err
		}
	}
	logger.Info("accounting processed",
		zap.String("session_id", rec.SessionID),
		zap.String("status", rec.AcctStatusType))
	return nil
}
