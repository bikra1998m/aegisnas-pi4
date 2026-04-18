package portal

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"go.uber.org/zap"
)

// ClientState represents the state of a client in the captive portal.
type ClientState string

const (
	StateUnknown         ClientState = "unknown"
	StateUnauthenticated ClientState = "unauthenticated"
	StateAuthenticating  ClientState = "authenticating"
	StateAuthenticated   ClientState = "authenticated"
)

// Client represents a tracked client (MAC/IP pair).
type Client struct {
	MAC              string
	IP               string
	State            ClientState
	Username         string
	SessionID        string
	LastSeen         time.Time
	RedirectURL      string
	AuthMethod       string
	IdentitySource   string
	Role             string
	BandwidthProfile string
	FilterID         string
	RadiusClass      string
	CalledStationID  string
	NASIdentifier    string
	StartTime        time.Time
	VLAN             int
	SessionTimeout   int
	IdleTimeout      int
}

// StateMachine manages captive portal client states.
type StateMachine struct {
	mu      sync.RWMutex
	clients map[string]*Client
	logger  *zap.Logger
}

func NewStateMachine(logger *zap.Logger) *StateMachine {
	return &StateMachine{
		clients: make(map[string]*Client),
		logger:  logger,
	}
}

// GetOrCreate returns existing client or creates a new one in unauthenticated state.
func (sm *StateMachine) GetOrCreate(mac, ip string) *Client {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if client, exists := sm.clients[mac]; exists {
		client.LastSeen = time.Now()
		if client.IP != ip {
			client.IP = ip
		}
		return client
	}

	client := &Client{
		MAC:      mac,
		IP:       ip,
		State:    StateUnauthenticated,
		LastSeen: time.Now(),
	}
	sm.clients[mac] = client
	sm.logger.Debug("new portal client", zap.String("mac", mac), zap.String("ip", ip))
	return client
}

// Transition moves a client to a new state and persists authenticated sessions.
func (sm *StateMachine) Transition(mac string, newState ClientState, username, sessionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	client, exists := sm.clients[mac]
	if !exists {
		return fmt.Errorf("client %s not found", mac)
	}

	oldState := client.State
	client.State = newState
	client.Username = username
	client.SessionID = sessionID
	client.LastSeen = time.Now()
	if newState == StateAuthenticated && client.StartTime.IsZero() {
		client.StartTime = time.Now()
	}

	sm.logger.Info("client state transition",
		zap.String("mac", mac),
		zap.String("old", string(oldState)),
		zap.String("new", string(newState)),
		zap.String("username", username))

	if newState == StateAuthenticated {
		if err := sm.persistSession(client); err != nil {
			sm.logger.Error("failed to persist session", zap.Error(err))
		} else if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
			sm.logger.Warn("failed to sync runtime enforcement after authenticate", zap.Error(err))
		}
	}
	return nil
}

// EndSession marks the client's active session as closed in both memory and DB.
func (sm *StateMachine) EndSession(mac, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	client, exists := sm.clients[mac]
	if !exists {
		return nil
	}

	if db.DB != nil && client.SessionID != "" {
		stopReason := strings.TrimSpace(reason)
		if stopReason == "" {
			stopReason = "user logout"
		}
		if _, err := db.DB.Exec(`UPDATE sessions SET end_time = ?, stop_reason = ? WHERE id = ? AND end_time IS NULL`,
			time.Now(), stopReason, client.SessionID); err != nil {
			return err
		}
		if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
			sm.logger.Warn("failed to sync runtime enforcement after portal logout", zap.Error(err))
		}
	}

	client.State = StateUnauthenticated
	client.Username = ""
	client.SessionID = ""
	client.AuthMethod = ""
	client.IdentitySource = ""
	client.Role = ""
	client.BandwidthProfile = ""
	client.FilterID = ""
	client.RadiusClass = ""
	client.CalledStationID = ""
	client.NASIdentifier = ""
	client.StartTime = time.Time{}
	client.VLAN = 0
	client.SessionTimeout = 0
	client.IdleTimeout = 0
	client.LastSeen = time.Now()
	return nil
}

// IsAuthenticated checks if a client is still authenticated.
func (sm *StateMachine) IsAuthenticated(mac string) bool {
	sm.mu.RLock()
	client, exists := sm.clients[mac]
	sm.mu.RUnlock()
	if !exists || client.State != StateAuthenticated {
		return false
	}
	return sm.ensureSessionStillActive(mac, client)
}

// ShouldRedirect returns true if client's HTTP traffic should be redirected to portal.
func (sm *StateMachine) ShouldRedirect(mac string) bool {
	sm.mu.RLock()
	client, exists := sm.clients[mac]
	sm.mu.RUnlock()
	if !exists {
		return true
	}
	if client.State != StateAuthenticated {
		return true
	}
	return !sm.ensureSessionStillActive(mac, client)
}

// GetClient returns client information.
func (sm *StateMachine) GetClient(mac string) (*Client, bool) {
	sm.mu.RLock()
	client, exists := sm.clients[mac]
	sm.mu.RUnlock()
	if !exists {
		return nil, false
	}
	if client.State == StateAuthenticated && !sm.ensureSessionStillActive(mac, client) {
		return nil, false
	}
	return client, true
}

// CleanupIdle removes clients not seen for longer than idleTimeout.
func (sm *StateMachine) CleanupIdle(idleTimeout time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	for mac, client := range sm.clients {
		if now.Sub(client.LastSeen) > idleTimeout {
			sm.logger.Debug("removing idle client", zap.String("mac", mac))
			delete(sm.clients, mac)
		}
	}
}

func (sm *StateMachine) persistSession(client *Client) error {
	if db.DB == nil {
		return nil
	}
	startTime := client.StartTime
	if startTime.IsZero() {
		startTime = time.Now()
	}
	lastActivity := client.LastSeen
	if lastActivity.IsZero() {
		lastActivity = startTime
	}
	_, err := db.DB.Exec(`INSERT INTO sessions (
			id, username, mac, ip, auth_method, vlan, role, bandwidth_profile,
			start_time, last_activity, radius_session_id, identity_source, filter_id,
			radius_class, session_timeout, idle_timeout, called_station_id, nas_identifier
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			username = excluded.username,
			mac = excluded.mac,
			ip = excluded.ip,
			auth_method = excluded.auth_method,
			vlan = excluded.vlan,
			role = excluded.role,
			bandwidth_profile = excluded.bandwidth_profile,
			last_activity = excluded.last_activity,
			radius_session_id = excluded.radius_session_id,
			identity_source = excluded.identity_source,
			filter_id = excluded.filter_id,
			radius_class = excluded.radius_class,
			session_timeout = excluded.session_timeout,
			idle_timeout = excluded.idle_timeout,
			called_station_id = excluded.called_station_id,
			nas_identifier = excluded.nas_identifier`,
		client.SessionID, client.Username, client.MAC, client.IP, client.AuthMethod, client.VLAN, client.Role,
		nullIfEmpty(client.BandwidthProfile), startTime, lastActivity, client.SessionID, client.IdentitySource,
		nullIfEmpty(client.FilterID), nullIfEmpty(client.RadiusClass), nullIfZero(client.SessionTimeout),
		nullIfZero(client.IdleTimeout), nullIfEmpty(client.CalledStationID), nullIfEmpty(client.NASIdentifier))
	return err
}

// LoadSessionsFromDB restores authenticated sessions from database (on startup).
func (sm *StateMachine) LoadSessionsFromDB() error {
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query(`SELECT id, username, mac, ip, auth_method, vlan, role, bandwidth_profile,
		identity_source, filter_id, radius_class, session_timeout, idle_timeout,
		called_station_id, nas_identifier, start_time, last_activity
		FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for rows.Next() {
		var (
			c               Client
			authMethod      sql.NullString
			vlan            sql.NullInt32
			role            sql.NullString
			bandwidth       sql.NullString
			identitySource  sql.NullString
			filterID        sql.NullString
			radiusClass     sql.NullString
			sessionTimeout  sql.NullInt32
			idleTimeout     sql.NullInt32
			calledStationID sql.NullString
			nasIdentifier   sql.NullString
			startTime       sql.NullString
			lastActivity    sql.NullString
		)
		if err := rows.Scan(&c.SessionID, &c.Username, &c.MAC, &c.IP, &authMethod, &vlan, &role, &bandwidth,
			&identitySource, &filterID, &radiusClass, &sessionTimeout, &idleTimeout,
			&calledStationID, &nasIdentifier, &startTime, &lastActivity); err != nil {
			sm.logger.Error("scan session row", zap.Error(err))
			continue
		}
		c.State = StateAuthenticated
		c.LastSeen = parseNullableTime(lastActivity)
		if c.LastSeen.IsZero() {
			c.LastSeen = time.Now()
		}
		c.StartTime = parseNullableTime(startTime)
		if authMethod.Valid {
			c.AuthMethod = authMethod.String
		}
		if vlan.Valid {
			c.VLAN = int(vlan.Int32)
		}
		if role.Valid {
			c.Role = role.String
		}
		if bandwidth.Valid {
			c.BandwidthProfile = bandwidth.String
		}
		if identitySource.Valid {
			c.IdentitySource = identitySource.String
		}
		if filterID.Valid {
			c.FilterID = filterID.String
		}
		if radiusClass.Valid {
			c.RadiusClass = radiusClass.String
		}
		if sessionTimeout.Valid {
			c.SessionTimeout = int(sessionTimeout.Int32)
		}
		if idleTimeout.Valid {
			c.IdleTimeout = int(idleTimeout.Int32)
		}
		if calledStationID.Valid {
			c.CalledStationID = calledStationID.String
		}
		if nasIdentifier.Valid {
			c.NASIdentifier = nasIdentifier.String
		}
		sm.clients[c.MAC] = &c
		sm.logger.Debug("restored session from DB", zap.String("mac", c.MAC), zap.String("user", c.Username))
	}
	return nil
}

func (sm *StateMachine) ensureSessionStillActive(mac string, client *Client) bool {
	if db.DB == nil || client == nil || client.SessionID == "" {
		return true
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ? AND end_time IS NULL`, client.SessionID).Scan(&count); err != nil {
		return true
	}
	if count > 0 {
		return true
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	current, ok := sm.clients[mac]
	if !ok || current.SessionID != client.SessionID {
		return false
	}
	current.State = StateUnauthenticated
	current.Username = ""
	current.SessionID = ""
	current.AuthMethod = ""
	current.IdentitySource = ""
	current.Role = ""
	current.BandwidthProfile = ""
	current.FilterID = ""
	current.RadiusClass = ""
	current.CalledStationID = ""
	current.NASIdentifier = ""
	current.StartTime = time.Time{}
	current.VLAN = 0
	current.SessionTimeout = 0
	current.IdleTimeout = 0
	return false
}

func parseNullableTime(value sql.NullString) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	raw := strings.TrimSpace(value.String)
	if index := strings.Index(raw, " m="); index >= 0 {
		raw = raw[:index]
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700 -0700",
		"2006-01-02 15:04:05 -0700 -0700",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullIfZero(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
