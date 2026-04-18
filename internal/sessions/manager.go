package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
)

// Manager handles session lifecycle and enforcement.
type Manager struct {
	cfg    *config.Config
	logger *zap.Logger
	db     *sql.DB
}

func NewManager(cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	return &Manager{
		cfg:    cfg,
		logger: logger,
		db:     db.DB,
	}, nil
}

// ActiveSession represents an ongoing user session.
type ActiveSession struct {
	ID               string    `json:"id"`
	Username         string    `json:"username"`
	MAC              string    `json:"mac"`
	IP               string    `json:"ip"`
	AuthMethod       string    `json:"auth_method"`
	IdentitySource   string    `json:"identity_source,omitempty"`
	FilterID         string    `json:"filter_id,omitempty"`
	RadiusClass      string    `json:"radius_class,omitempty"`
	CalledStationID  string    `json:"called_station_id,omitempty"`
	NASIdentifier    string    `json:"nas_identifier,omitempty"`
	VLAN             int       `json:"vlan"`
	Role             string    `json:"role"`
	BandwidthProfile string    `json:"bandwidth_profile"`
	StartTime        time.Time `json:"start_time"`
	LastActivity     time.Time `json:"last_activity"`
	BytesIn          uint64    `json:"bytes_in"`
	BytesOut         uint64    `json:"bytes_out"`
	SessionTimeout   int       `json:"session_timeout"` // absolute timeout in seconds
	IdleTimeout      int       `json:"idle_timeout"`    // idle timeout in seconds
}

// PolicyUpdate represents AAA-driven changes to an active session.
type PolicyUpdate struct {
	Role             string
	VLAN             int
	BandwidthProfile string
	FilterID         string
	RadiusClass      string
	SessionTimeout   int
	IdleTimeout      int
}

// StartCleanupTask periodically removes expired sessions.
func (m *Manager) StartCleanupTask(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

// StartInterimAccountingTask periodically sends RADIUS Interim-Update records
// for active sessions so upstream AAA systems receive stable accounting.
func (m *Manager) StartInterimAccountingTask(ctx context.Context, interval time.Duration) {
	if interval <= 0 || ctx == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sendInterimAccounting()
		}
	}
}

// StartTimeoutEnforcer periodically checks for sessions that exceed idle or absolute timeouts.
func (m *Manager) StartTimeoutEnforcer(ctx context.Context, interval time.Duration) {
	if ctx == nil || interval <= 0 {
		m.enforceTimeouts()
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.enforceTimeouts()
		}
	}
}

func (m *Manager) cleanupExpiredSessions() {
	// End sessions that have an end_time set (already closed) – nothing to do here.
	// Actually we need to remove stale session records from active cache? We don't have a separate cache; the DB is source of truth.
	// We can clean up old ended sessions older than e.g., 7 days.
	_, err := m.db.Exec(`DELETE FROM sessions WHERE end_time IS NOT NULL AND end_time < datetime('now', '-7 days')`)
	if err != nil {
		m.logger.Error("failed to cleanup old sessions", zap.Error(err))
	}
}

func (m *Manager) enforceTimeouts() {
	m.terminateExpiredBySQL(time.Now())

	// Fetch all active sessions
	rows, err := m.db.Query(`SELECT id, start_time, last_activity, role, session_timeout, idle_timeout
		FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		m.logger.Error("failed to query active sessions", zap.Error(err))
		return
	}
	defer rows.Close()

	now := time.Now()
	expired := make(map[string]string)
	for rows.Next() {
		var (
			idRaw        any
			startTimeRaw any
			lastActivity any
			roleRaw      any
			sessionTO    sql.NullInt32
			idleTO       sql.NullInt32
		)
		if err := rows.Scan(&idRaw, &startTimeRaw, &lastActivity, &roleRaw, &sessionTO, &idleTO); err != nil {
			m.logger.Error("scan session row", zap.Error(err))
			continue
		}
		id := dbTimeString(idRaw)
		role := dbTimeString(roleRaw)
		startTime := parseDBTime(dbTimeString(startTimeRaw))

		// Determine absolute timeout
		absTimeout := sessionTO.Int32
		if absTimeout == 0 {
			if err := m.db.QueryRow("SELECT session_timeout FROM roles WHERE name = ?", role).Scan(&absTimeout); err != nil {
				absTimeout = 28800 // default 8 hours
			}
		}
		if absTimeout > 0 {
			expiry := startTime.Add(time.Duration(absTimeout) * time.Second)
			if startTime.IsZero() || now.After(expiry) {
				expired[id] = "Session timeout reached"
				continue
			}
		}

		// Determine idle timeout
		idleTimeout := idleTO.Int32
		if idleTimeout == 0 {
			if err := m.db.QueryRow("SELECT idle_timeout FROM roles WHERE name = ?", role).Scan(&idleTimeout); err != nil {
				idleTimeout = 3600 // default 1 hour
			}
		}
		lastActivityRaw := dbTimeString(lastActivity)
		if idleTimeout > 0 && lastActivityRaw != "" {
			lastActivityTime := parseDBTime(lastActivityRaw)
			expiry := lastActivityTime.Add(time.Duration(idleTimeout) * time.Second)
			if lastActivityTime.IsZero() || now.After(expiry) {
				expired[id] = "Idle timeout reached"
				continue
			}
		}
	}
	_ = rows.Close()
	for sessionID, reason := range expired {
		m.terminateSession(sessionID, reason)
	}
	if err := enforcement.SyncRuntimeEnforcement(m.cfg); err != nil {
		m.logger.Warn("failed to sync runtime enforcement after timeout sweep", zap.Error(err))
	}
}

func (m *Manager) terminateExpiredBySQL(now time.Time) {
	_, err := m.db.Exec(`
		UPDATE sessions
		SET end_time = ?, stop_reason = 'Idle timeout reached'
		WHERE id IN (
			SELECT s.id
			FROM sessions s
			LEFT JOIN roles r ON s.role = r.name
			WHERE s.end_time IS NULL
				AND COALESCE(s.idle_timeout, r.idle_timeout, 0) > 0
				AND s.last_activity IS NOT NULL
				AND s.last_activity < datetime('now', '-' || COALESCE(s.idle_timeout, r.idle_timeout) || ' seconds')
		)`, now)
	if err != nil {
		m.logger.Warn("sql idle timeout sweep failed", zap.Error(err))
	}

	_, err = m.db.Exec(`
		UPDATE sessions
		SET end_time = ?, stop_reason = 'Session timeout reached'
		WHERE id IN (
			SELECT s.id
			FROM sessions s
			LEFT JOIN roles r ON s.role = r.name
			WHERE s.end_time IS NULL
				AND COALESCE(s.session_timeout, r.session_timeout, 0) > 0
				AND s.start_time < datetime('now', '-' || COALESCE(s.session_timeout, r.session_timeout) || ' seconds')
		)`, now)
	if err != nil {
		m.logger.Warn("sql session timeout sweep failed", zap.Error(err))
	}
}

func (m *Manager) terminateSession(sessionID, reason string) {
	_, err := m.db.Exec(`UPDATE sessions SET end_time = ?, stop_reason = ? WHERE id = ? AND end_time IS NULL`,
		time.Now(), reason, sessionID)
	if err != nil {
		m.logger.Error("failed to terminate session", zap.String("session_id", sessionID), zap.Error(err))
	} else {
		if syncErr := enforcement.SyncRuntimeEnforcement(m.cfg); syncErr != nil {
			m.logger.Warn("failed to sync runtime enforcement after terminate", zap.String("session_id", sessionID), zap.Error(syncErr))
		}
		m.logger.Info("session terminated", zap.String("session_id", sessionID), zap.String("reason", reason))
		go func() {
			var username, mac, ip, calledStationID string
			var startTimeRaw any
			row := m.db.QueryRow("SELECT username, mac, ip, COALESCE(called_station_id, ''), start_time FROM sessions WHERE id = ?", sessionID)
			_ = row.Scan(&username, &mac, &ip, &calledStationID, &startTimeRaw)
			rec := &radius.AccountingRecord{
				SessionID:        sessionID,
				Username:         username,
				CallingStationID: mac,
				CalledStationID:  calledStationID,
				FramedIPAddress:  ip,
				AcctStatusType:   "Stop",
				AcctSessionTime:  int(time.Since(parseDBTime(dbTimeString(startTimeRaw))).Seconds()),
				StopReason:       reason,
				Timestamp:        time.Now(),
			}
			if err := radius.SendAccounting(context.Background(), m.cfg, rec); err != nil {
				m.logger.Warn("failed to send stop accounting", zap.String("session_id", sessionID), zap.Error(err))
			}
			if err := radius.ProcessAccounting(rec); err != nil {
				m.logger.Warn("failed to update local accounting state", zap.String("session_id", sessionID), zap.Error(err))
			}
		}()
	}
}

// EnforceConcurrentLimit checks if a user has exceeded max concurrent sessions.
func (m *Manager) EnforceConcurrentLimit(username string) (bool, error) {
	// Default max concurrent sessions = 2 until a role-specific limit is configured.
	maxSessions := 2
	var count int
	err := m.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username = ? AND end_time IS NULL`, username).Scan(&count)
	if err != nil {
		return false, err
	}
	return count >= maxSessions, nil
}

// UpdateLastActivity updates the last_activity timestamp for a session.
func (m *Manager) UpdateLastActivity(sessionID string) error {
	_, err := m.db.Exec(`UPDATE sessions SET last_activity = ? WHERE id = ?`, time.Now(), sessionID)
	return err
}

// TerminateByCriteria ends the first active session matching any provided key.
func (m *Manager) TerminateByCriteria(sessionID, username, mac, reason string) (bool, error) {
	session, err := m.findActiveSession(sessionID, username, mac)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	m.terminateSession(session.ID, reason)
	return true, nil
}

// ReclassifyByCriteria updates policy fields on the first active session matching any provided key.
func (m *Manager) ReclassifyByCriteria(sessionID, username, mac string, update PolicyUpdate) (bool, error) {
	session, err := m.findActiveSession(sessionID, username, mac)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	if update.Role == "" {
		update.Role = session.Role
	}
	if update.VLAN == 0 {
		update.VLAN = session.VLAN
	}
	if update.BandwidthProfile == "" {
		update.BandwidthProfile = session.BandwidthProfile
	}
	if update.FilterID == "" {
		update.FilterID = session.FilterID
	}
	if update.RadiusClass == "" {
		update.RadiusClass = session.RadiusClass
	}
	if update.SessionTimeout == 0 {
		update.SessionTimeout = session.SessionTimeout
	}
	if update.IdleTimeout == 0 {
		update.IdleTimeout = session.IdleTimeout
	}

	_, err = m.db.Exec(`UPDATE sessions
		SET role = ?, vlan = ?, bandwidth_profile = ?, filter_id = ?, radius_class = ?, session_timeout = ?, idle_timeout = ?, last_activity = ?
		WHERE id = ? AND end_time IS NULL`,
		nullIfEmptyString(update.Role), nullIfZeroInt(update.VLAN), nullIfEmptyString(update.BandwidthProfile),
		nullIfEmptyString(update.FilterID), nullIfEmptyString(update.RadiusClass),
		nullIfZeroInt(update.SessionTimeout), nullIfZeroInt(update.IdleTimeout), time.Now(), session.ID)
	if err != nil {
		return false, err
	}
	if err := enforcement.SyncRuntimeEnforcement(m.cfg); err != nil {
		m.logger.Warn("failed to sync runtime enforcement after coa update", zap.String("session_id", session.ID), zap.Error(err))
	}
	if update.VLAN != 0 && update.VLAN != session.VLAN {
		m.terminateSession(session.ID, "VLAN reassignment requested")
		return true, nil
	}
	if reason := immediatePolicyReason(session.StartTime, session.LastActivity, update.SessionTimeout, update.IdleTimeout); reason != "" {
		m.terminateSession(session.ID, reason)
	}
	return true, nil
}

// GetActiveSession returns an active session by ID.
func (m *Manager) GetActiveSession(sessionID string) (*ActiveSession, error) {
	var s ActiveSession
	var startTimeRaw any
	var lastActivity any
	var sessionTimeout, idleTimeout sql.NullInt32
	err := m.db.QueryRow(`SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(identity_source, ''), COALESCE(filter_id, ''), COALESCE(radius_class, ''), COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''),
		COALESCE(vlan, 0), COALESCE(role, ''), COALESCE(bandwidth_profile, ''), start_time, last_activity, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), session_timeout, idle_timeout
		FROM sessions WHERE id = ? AND end_time IS NULL`, sessionID).Scan(
		&s.ID, &s.Username, &s.MAC, &s.IP, &s.AuthMethod, &s.IdentitySource, &s.FilterID, &s.RadiusClass, &s.CalledStationID, &s.NASIdentifier,
		&s.VLAN, &s.Role, &s.BandwidthProfile,
		&startTimeRaw, &lastActivity, &s.BytesIn, &s.BytesOut, &sessionTimeout, &idleTimeout)
	if err != nil {
		return nil, err
	}
	s.StartTime = parseDBTime(dbTimeString(startTimeRaw))
	s.LastActivity = parseDBTime(dbTimeString(lastActivity))
	if sessionTimeout.Valid {
		s.SessionTimeout = int(sessionTimeout.Int32)
	}
	if idleTimeout.Valid {
		s.IdleTimeout = int(idleTimeout.Int32)
	}
	if s.SessionTimeout == 0 || s.IdleTimeout == 0 {
		var roleSessionTimeout, roleIdleTimeout sql.NullInt32
		err = m.db.QueryRow("SELECT session_timeout, idle_timeout FROM roles WHERE name = ?", s.Role).Scan(&roleSessionTimeout, &roleIdleTimeout)
		if err == nil {
			if s.SessionTimeout == 0 && roleSessionTimeout.Valid {
				s.SessionTimeout = int(roleSessionTimeout.Int32)
			}
			if s.IdleTimeout == 0 && roleIdleTimeout.Valid {
				s.IdleTimeout = int(roleIdleTimeout.Int32)
			}
		}
	}
	return &s, nil
}

// HTTP Handlers

func (m *Manager) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	rows, err := m.db.Query(`SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(vlan, 0), start_time, end_time
		FROM sessions ORDER BY start_time DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var (
			id, username, mac, ip, authMethod string
			vlan                              int
			startTime                         any
			endTime                           any
		)
		rows.Scan(&id, &username, &mac, &ip, &authMethod, &vlan, &startTime, &endTime)
		s := map[string]interface{}{
			"id":          id,
			"username":    username,
			"mac":         mac,
			"ip":          ip,
			"auth_method": authMethod,
			"vlan":        vlan,
			"start_time":  dbTimeString(startTime),
		}
		if value := dbTimeString(endTime); value != "" {
			s["end_time"] = value
		}
		sessions = append(sessions, s)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (m *Manager) HandleListActiveSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := m.db.Query(`SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(vlan, 0), start_time
		FROM sessions WHERE end_time IS NULL ORDER BY start_time DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var id, username, mac, ip, authMethod string
		var vlan int
		var startTime any
		rows.Scan(&id, &username, &mac, &ip, &authMethod, &vlan, &startTime)
		sessions = append(sessions, map[string]interface{}{
			"id":          id,
			"username":    username,
			"mac":         mac,
			"ip":          ip,
			"auth_method": authMethod,
			"vlan":        vlan,
			"start_time":  dbTimeString(startTime),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (m *Manager) HandleGetSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	session, err := m.GetActiveSession(sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "session not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (m *Manager) HandleTerminateSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	m.terminateSession(sessionID, "Admin termination")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Manager) HandleListUserSessions(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	rows, err := m.db.Query(`SELECT id, COALESCE(mac, ''), COALESCE(ip, ''), start_time, end_time FROM sessions WHERE username = ? ORDER BY start_time DESC`, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var id, mac, ip string
		var startTime any
		var endTime any
		rows.Scan(&id, &mac, &ip, &startTime, &endTime)
		s := map[string]interface{}{
			"id":         id,
			"mac":        mac,
			"ip":         ip,
			"start_time": dbTimeString(startTime),
		}
		if value := dbTimeString(endTime); value != "" {
			s["end_time"] = value
		}
		sessions = append(sessions, s)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func parseDBTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	value = strings.TrimSpace(value)
	if index := strings.Index(value, " m="); index >= 0 {
		value = value[:index]
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700 -0700",
		"2006-01-02 15:04:05 -0700 -0700",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func dbTimeString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case time.Time:
		return v.Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(v)
	}
}

func (m *Manager) sendInterimAccounting() {
	rows, err := m.db.Query(`SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(called_station_id, ''), start_time, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0)
		FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		m.logger.Warn("failed to query sessions for interim accounting", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			sessionID       string
			username        string
			mac             string
			ip              string
			calledStationID string
			startTimeRaw    any
			bytesIn         uint64
			bytesOut        uint64
		)
		if err := rows.Scan(&sessionID, &username, &mac, &ip, &calledStationID, &startTimeRaw, &bytesIn, &bytesOut); err != nil {
			m.logger.Warn("scan interim accounting row", zap.Error(err))
			continue
		}
		start := parseDBTime(dbTimeString(startTimeRaw))
		rec := &radius.AccountingRecord{
			SessionID:        sessionID,
			Username:         username,
			CallingStationID: mac,
			CalledStationID:  calledStationID,
			FramedIPAddress:  ip,
			AcctStatusType:   "Interim-Update",
			AcctInputOctets:  bytesIn,
			AcctOutputOctets: bytesOut,
			AcctSessionTime:  int(time.Since(start).Seconds()),
			Timestamp:        time.Now(),
		}
		if err := radius.SendAccounting(context.Background(), m.cfg, rec); err != nil {
			m.logger.Warn("failed to send interim accounting", zap.String("session_id", sessionID), zap.Error(err))
		}
		if err := radius.ProcessAccounting(rec); err != nil {
			m.logger.Warn("failed to update local accounting state", zap.String("session_id", sessionID), zap.Error(err))
		}
	}
}

func (m *Manager) findActiveSession(sessionID, username, mac string) (*ActiveSession, error) {
	candidates := []struct {
		value string
		query string
	}{
		{sessionID, `SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(identity_source, ''), COALESCE(filter_id, ''), COALESCE(radius_class, ''), COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''), COALESCE(vlan, 0), COALESCE(role, ''), COALESCE(bandwidth_profile, ''), start_time, last_activity, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), session_timeout, idle_timeout FROM sessions WHERE id = ? AND end_time IS NULL LIMIT 1`},
		{sessionID, `SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(identity_source, ''), COALESCE(filter_id, ''), COALESCE(radius_class, ''), COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''), COALESCE(vlan, 0), COALESCE(role, ''), COALESCE(bandwidth_profile, ''), start_time, last_activity, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), session_timeout, idle_timeout FROM sessions WHERE radius_session_id = ? AND end_time IS NULL LIMIT 1`},
		{username, `SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(identity_source, ''), COALESCE(filter_id, ''), COALESCE(radius_class, ''), COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''), COALESCE(vlan, 0), COALESCE(role, ''), COALESCE(bandwidth_profile, ''), start_time, last_activity, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), session_timeout, idle_timeout FROM sessions WHERE username = ? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1`},
		{mac, `SELECT id, COALESCE(username, ''), COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(identity_source, ''), COALESCE(filter_id, ''), COALESCE(radius_class, ''), COALESCE(called_station_id, ''), COALESCE(nas_identifier, ''), COALESCE(vlan, 0), COALESCE(role, ''), COALESCE(bandwidth_profile, ''), start_time, last_activity, COALESCE(bytes_in, 0), COALESCE(bytes_out, 0), session_timeout, idle_timeout FROM sessions WHERE mac = ? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1`},
	}

	for _, candidate := range candidates {
		if candidate.value == "" {
			continue
		}
		var (
			s            ActiveSession
			startTimeRaw any
			lastActivity any
			sessionTO    sql.NullInt32
			idleTO       sql.NullInt32
		)
		err := m.db.QueryRow(candidate.query, candidate.value).Scan(
			&s.ID, &s.Username, &s.MAC, &s.IP, &s.AuthMethod, &s.IdentitySource, &s.FilterID, &s.RadiusClass, &s.CalledStationID, &s.NASIdentifier,
			&s.VLAN, &s.Role, &s.BandwidthProfile,
			&startTimeRaw, &lastActivity, &s.BytesIn, &s.BytesOut, &sessionTO, &idleTO)
		if err == nil {
			s.StartTime = parseDBTime(dbTimeString(startTimeRaw))
			s.LastActivity = parseDBTime(dbTimeString(lastActivity))
			if sessionTO.Valid {
				s.SessionTimeout = int(sessionTO.Int32)
			}
			if idleTO.Valid {
				s.IdleTimeout = int(idleTO.Int32)
			}
			return &s, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	return nil, sql.ErrNoRows
}

func nullIfEmptyString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullIfZeroInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func immediatePolicyReason(startTime, lastActivity time.Time, sessionTimeout, idleTimeout int) string {
	now := time.Now()
	if sessionTimeout > 0 && !startTime.IsZero() {
		if !now.Before(startTime.Add(time.Duration(sessionTimeout) * time.Second)) {
			return "Session timeout reached"
		}
	}

	if lastActivity.IsZero() {
		lastActivity = startTime
	}
	if idleTimeout > 0 && !lastActivity.IsZero() {
		if !now.Before(lastActivity.Add(time.Duration(idleTimeout) * time.Second)) {
			return "Idle timeout reached"
		}
	}

	return ""
}
