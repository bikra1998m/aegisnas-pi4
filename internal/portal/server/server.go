package server

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"github.com/yourorg/aegisnas-pi4/internal/portal"
	"github.com/yourorg/aegisnas-pi4/internal/portal/auth"
	"github.com/yourorg/aegisnas-pi4/internal/portal/guestworkflow"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg          *config.Config
	logger       *zap.Logger
	templates    *template.Template
	stateMachine *portal.StateMachine
	rateLimiter  *auth.RateLimiter
	guestFlows   *guestworkflow.Service
	onboarding   *onboarding.Service
}

func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	sm := portal.NewStateMachine(logger)
	if err := sm.LoadSessionsFromDB(); err != nil {
		logger.Warn("failed to load sessions from DB", zap.Error(err))
	}

	limiter := auth.NewRateLimiter(rate.Limit(5.0/60.0), 5)

	return &Server{
		cfg:          cfg,
		logger:       logger,
		templates:    tmpl,
		stateMachine: sm,
		rateLimiter:  limiter,
		guestFlows:   guestworkflow.New(cfg, logger, nil),
		onboarding:   onboarding.New(cfg, logger),
	}, nil
}

func StaticHandler() (http.Handler, error) {
	staticSubtree, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("portal static assets: %w", err)
	}
	return http.FileServer(http.FS(staticSubtree)), nil
}

// HandleLoginPage serves the login form.
func (s *Server) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPOnly(r.RemoteAddr)
	mac := r.URL.Query().Get("client_mac")
	if mac == "" {
		mac = "unknown"
	}
	s.observeClient(r, mac, clientIP, "", "")
	if s.stateMachine.IsAuthenticated(mac) {
		http.Redirect(w, r, "/success", http.StatusFound)
		return
	}

	data := map[string]any{
		"Branding":   s.cfg.Portal.Branding,
		"ClientMAC":  mac,
		"ClientIP":   clientIP,
		"Error":      r.URL.Query().Get("error"),
		"VoucherURL": "/voucher?client_mac=" + mac,
		"RegisterURL": func() string {
			if !s.cfg.Portal.GuestWorkflows.SelfRegistrationEnabled {
				return ""
			}
			return "/register?client_mac=" + mac
		}(),
	}
	s.render(w, "login.html", data)
}

// HandleLogin processes username/password login.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPOnly(r.RemoteAddr)
	mac := r.FormValue("client_mac")
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	s.observeClient(r, mac, clientIP, username, "")

	if !s.rateLimiter.Allow(clientIP) {
		http.Redirect(w, r, "/?error=rate_limited&client_mac="+mac, http.StatusFound)
		return
	}

	authResult, err := auth.AuthenticateUser(r.Context(), auth.LoginRequest{
		Username:         username,
		Password:         password,
		CallingStationID: mac,
		CalledStationID:  s.cfg.Radius.NASIdentifier,
		FramedIPAddress:  clientIP,
		NASPort:          1,
	})
	if err != nil {
		s.logger.Error("user validation error", zap.String("username", username), zap.Error(err))
		http.Redirect(w, r, "/?error=internal_error&client_mac="+mac, http.StatusFound)
		return
	}
	if authResult == nil || !authResult.Accepted {
		http.Redirect(w, r, "/?error=invalid_credentials&client_mac="+mac, http.StatusFound)
		return
	}

	if err := s.establishAuthenticatedSession(clientIP, mac, authResult); err != nil {
		s.logger.Error("failed to apply session policy", zap.String("username", username), zap.Error(err))
		http.Redirect(w, r, "/?error=policy_denied&client_mac="+mac, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/success?client_mac="+mac, http.StatusFound)
}

// HandleVoucherPage serves the voucher login form.
func (s *Server) HandleVoucherPage(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("client_mac")
	s.observeClient(r, mac, clientIPOnly(r.RemoteAddr), "", "")
	data := map[string]any{
		"Branding":  s.cfg.Portal.Branding,
		"ClientMAC": mac,
		"Error":     r.URL.Query().Get("error"),
	}
	s.render(w, "voucher.html", data)
}

// HandleVoucherLogin processes voucher code.
func (s *Server) HandleVoucherLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPOnly(r.RemoteAddr)
	mac := r.FormValue("client_mac")
	code := strings.TrimSpace(r.FormValue("voucher_code"))
	s.observeClient(r, mac, clientIP, "", "")

	if !s.rateLimiter.Allow(clientIP) {
		http.Redirect(w, r, "/voucher?error=rate_limited&client_mac="+mac, http.StatusFound)
		return
	}

	role, durationMinutes, err := radius.ValidateVoucher(code)
	if err != nil {
		http.Redirect(w, r, "/voucher?error=invalid_voucher&client_mac="+mac, http.StatusFound)
		return
	}

	username := "voucher_" + code
	sessionID := uuid.NewString()
	client := s.stateMachine.GetOrCreate(mac, clientIP)
	authResult := &auth.Result{
		Accepted:       true,
		Username:       username,
		Role:           role,
		IdentitySource: "voucher",
		AuthMethod:     "voucher",
		SessionTimeout: durationMinutes * 60,
	}
	if err := s.populateAuthenticatedClient(client, authResult, sessionID); err != nil {
		s.logger.Error("failed to apply voucher policy", zap.String("voucher", code), zap.Error(err))
		http.Redirect(w, r, "/voucher?error=policy_denied&client_mac="+mac, http.StatusFound)
		return
	}
	if err := s.stateMachine.Transition(mac, portal.StateAuthenticated, username, sessionID); err != nil {
		s.logger.Error("state transition failed", zap.Error(err))
		http.Redirect(w, r, "/voucher?error=session_error&client_mac="+mac, http.StatusFound)
		return
	}

	s.sendAccounting(&radius.AccountingRecord{
		SessionID:        sessionID,
		Username:         username,
		CallingStationID: mac,
		CalledStationID:  client.CalledStationID,
		FramedIPAddress:  clientIP,
		AcctStatusType:   "Start",
		Role:             client.Role,
		BandwidthProfile: client.BandwidthProfile,
		FilterID:         client.FilterID,
		RadiusClass:      client.RadiusClass,
		VLAN:             client.VLAN,
		SessionTimeout:   client.SessionTimeout,
		IdleTimeout:      client.IdleTimeout,
		Timestamp:        time.Now(),
	})

	http.Redirect(w, r, "/success?client_mac="+mac, http.StatusFound)
}

// HandleSuccess shows success page after login.
func (s *Server) HandleSuccess(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("client_mac")
	client, ok := s.stateMachine.GetClient(mac)
	if !ok || client.State != portal.StateAuthenticated {
		http.Redirect(w, r, "/?client_mac="+mac, http.StatusFound)
		return
	}
	data := map[string]any{
		"Branding":   s.cfg.Portal.Branding,
		"Username":   client.Username,
		"SuccessURL": s.cfg.Portal.SuccessURL,
		"ClientMAC":  mac,
		"OnboardingURL": func() string {
			if !s.cfg.Onboarding.PortalEnabled {
				return ""
			}
			return "/onboarding?client_mac=" + url.QueryEscape(mac)
		}(),
	}
	s.observeClient(r, mac, client.IP, client.Username, client.SessionID)
	s.render(w, "success.html", data)
}

// HandleStatus shows connection status page.
func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("client_mac")
	client, ok := s.stateMachine.GetClient(mac)
	authenticated := ok && client.State == portal.StateAuthenticated

	data := map[string]any{
		"Branding":      s.cfg.Portal.Branding,
		"Authenticated": authenticated,
		"Username":      "",
		"IP":            clientIPOnly(r.RemoteAddr),
		"MAC":           mac,
	}
	if authenticated {
		data["Username"] = client.Username
		data["SuccessURL"] = s.cfg.Portal.SuccessURL
		if s.cfg.Onboarding.PortalEnabled {
			data["OnboardingURL"] = "/onboarding?client_mac=" + url.QueryEscape(mac)
		}
		s.observeClient(r, mac, client.IP, client.Username, client.SessionID)
	}
	s.render(w, "status.html", data)
}

// HandleLogout terminates the session.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	mac := r.URL.Query().Get("client_mac")
	if mac == "" && r.Method == http.MethodPost {
		mac = r.FormValue("client_mac")
	}

	if mac != "" {
		client, ok := s.stateMachine.GetClient(mac)
		if ok && client.State == portal.StateAuthenticated {
			s.sendAccounting(&radius.AccountingRecord{
				SessionID:        client.SessionID,
				Username:         client.Username,
				CallingStationID: mac,
				CalledStationID:  client.CalledStationID,
				FramedIPAddress:  client.IP,
				AcctStatusType:   "Stop",
				AcctSessionTime:  sessionAgeSeconds(client.StartTime),
				StopReason:       "user logout",
				Role:             client.Role,
				BandwidthProfile: client.BandwidthProfile,
				FilterID:         client.FilterID,
				RadiusClass:      client.RadiusClass,
				VLAN:             client.VLAN,
				SessionTimeout:   client.SessionTimeout,
				IdleTimeout:      client.IdleTimeout,
				Timestamp:        time.Now(),
			})
			if err := s.stateMachine.EndSession(mac, "user logout"); err != nil {
				s.logger.Warn("failed to close portal session", zap.String("mac", mac), zap.Error(err))
			}
		}
	}
	http.Redirect(w, r, "/?client_mac="+mac+"&logout=1", http.StatusFound)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("template render error", zap.String("template", name), zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) populateAuthenticatedClient(client *portal.Client, authResult *auth.Result, sessionID string) error {
	if client == nil || authResult == nil {
		return fmt.Errorf("client and auth result are required")
	}

	now := time.Now()
	client.Username = authResult.Username
	client.SessionID = sessionID
	client.AuthMethod = authResult.AuthMethod
	client.IdentitySource = authResult.IdentitySource
	client.Role = firstNonEmpty(authResult.Role, s.cfg.Policy.DefaultRole)
	client.BandwidthProfile = authResult.BandwidthProfile
	client.FilterID = authResult.FilterID
	client.RadiusClass = authResult.RadiusClass
	client.CalledStationID = s.cfg.Radius.NASIdentifier
	client.NASIdentifier = s.cfg.Radius.NASIdentifier
	client.StartTime = now
	client.LastSeen = now
	client.VLAN = authResult.VLAN
	client.SessionTimeout = authResult.SessionTimeout
	client.IdleTimeout = authResult.IdleTimeout

	roleProfile, err := lookupRoleProfile(client.Role)
	if err != nil {
		return err
	}
	if client.VLAN == 0 {
		client.VLAN = roleProfile.VLAN
	}
	if client.BandwidthProfile == "" {
		client.BandwidthProfile = roleProfile.BandwidthProfile
	}
	if client.SessionTimeout == 0 {
		client.SessionTimeout = roleProfile.SessionTimeout
	}
	if client.IdleTimeout == 0 {
		client.IdleTimeout = roleProfile.IdleTimeout
	}
	if client.VLAN == 0 {
		client.VLAN = getVLANForRole(client.Role)
	}

	engine := policy.NewEngine(s.logger)
	decision, err := engine.Evaluate(&policy.Request{
		Username:         client.Username,
		Role:             client.Role,
		Groups:           authResult.Groups,
		AuthMethod:       client.AuthMethod,
		IdentitySource:   client.IdentitySource,
		NASIdentifier:    client.NASIdentifier,
		CallingStationID: client.MAC,
		Authenticated:    true,
	})
	if err != nil {
		return err
	}
	if decision != nil {
		if !decision.Allow {
			return fmt.Errorf("session rejected by policy")
		}
		if decision.VLAN != nil {
			client.VLAN = *decision.VLAN
		}
		if decision.BandwidthProfile != nil {
			client.BandwidthProfile = *decision.BandwidthProfile
		}
		if decision.SessionTimeout != nil {
			client.SessionTimeout = *decision.SessionTimeout
		}
		if decision.IdleTimeout != nil {
			client.IdleTimeout = *decision.IdleTimeout
		}
	}

	return nil
}

func (s *Server) establishAuthenticatedSession(clientIP, mac string, authResult *auth.Result) error {
	sessionID := uuid.NewString()
	client := s.stateMachine.GetOrCreate(mac, clientIP)
	if err := s.populateAuthenticatedClient(client, authResult, sessionID); err != nil {
		return err
	}
	if err := s.stateMachine.Transition(mac, portal.StateAuthenticated, authResult.Username, sessionID); err != nil {
		return err
	}
	s.sendAccounting(&radius.AccountingRecord{
		SessionID:        sessionID,
		Username:         authResult.Username,
		CallingStationID: mac,
		CalledStationID:  client.CalledStationID,
		FramedIPAddress:  clientIP,
		AcctStatusType:   "Start",
		Role:             client.Role,
		BandwidthProfile: client.BandwidthProfile,
		FilterID:         client.FilterID,
		RadiusClass:      client.RadiusClass,
		VLAN:             client.VLAN,
		SessionTimeout:   client.SessionTimeout,
		IdleTimeout:      client.IdleTimeout,
		Timestamp:        time.Now(),
	})
	return nil
}

type roleProfile struct {
	VLAN             int
	BandwidthProfile string
	SessionTimeout   int
	IdleTimeout      int
}

func lookupRoleProfile(role string) (roleProfile, error) {
	if strings.TrimSpace(role) == "" || db.DB == nil {
		return roleProfile{}, nil
	}
	var (
		vlan      sqlNullInt
		bandwidth sqlNullString
		sessionTO sqlNullInt
		idleTO    sqlNullInt
	)
	err := db.DB.QueryRow(`SELECT vlan, bandwidth_profile, session_timeout, idle_timeout FROM roles WHERE name = ?`, role).
		Scan(&vlan, &bandwidth, &sessionTO, &idleTO)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return roleProfile{}, nil
		}
		return roleProfile{}, err
	}
	profile := roleProfile{}
	if vlan.Valid {
		profile.VLAN = vlan.Int
	}
	if bandwidth.Valid {
		profile.BandwidthProfile = bandwidth.String
	}
	if sessionTO.Valid {
		profile.SessionTimeout = sessionTO.Int
	}
	if idleTO.Valid {
		profile.IdleTimeout = idleTO.Int
	}
	return profile, nil
}

type sqlNullString struct {
	String string
	Valid  bool
}

type sqlNullInt struct {
	Int   int
	Valid bool
}

func (n *sqlNullString) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		n.Valid = false
		n.String = ""
	case string:
		n.Valid = true
		n.String = v
	case []byte:
		n.Valid = true
		n.String = string(v)
	default:
		return fmt.Errorf("unsupported string source %T", src)
	}
	return nil
}

func (n *sqlNullInt) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		n.Valid = false
		n.Int = 0
	case int64:
		n.Valid = true
		n.Int = int(v)
	case int:
		n.Valid = true
		n.Int = v
	case []byte:
		var parsed int
		if _, err := fmt.Sscanf(string(v), "%d", &parsed); err != nil {
			return err
		}
		n.Valid = true
		n.Int = parsed
	default:
		return fmt.Errorf("unsupported int source %T", src)
	}
	return nil
}

func (s *Server) sendAccounting(rec *radius.AccountingRecord) {
	if rec == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(max(5, s.cfg.Radius.RequestTimeoutSeconds))*time.Second)
		defer cancel()
		if err := radius.SendAccounting(ctx, s.cfg, rec); err != nil {
			s.logger.Warn("failed to send radius accounting",
				zap.String("session_id", rec.SessionID),
				zap.String("status", rec.AcctStatusType),
				zap.Error(err))
		}
	}()
}

func clientIPOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func sessionAgeSeconds(start time.Time) int {
	if start.IsZero() {
		return 0
	}
	return int(time.Since(start).Seconds())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func getVLANForRole(role string) int {
	profile, err := lookupRoleProfile(role)
	if err != nil || profile.VLAN == 0 {
		return 20
	}
	return profile.VLAN
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Server) observeClient(r *http.Request, mac, ip, username, sessionID string) {
	if s.onboarding == nil {
		return
	}
	_ = s.onboarding.ObserveDevice(mac, ip, username, sessionID, r.UserAgent(), "portal")
}
