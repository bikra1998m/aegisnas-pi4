package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	ldapclient "github.com/yourorg/aegisnas-pi4/internal/ldap"
	aegisradius "github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Result captures the authenticated identity plus any policy hints returned by
// the upstream AAA stack.
type Result struct {
	Accepted         bool
	Username         string
	Role             string
	Groups           []string
	IdentitySource   string
	AuthMethod       string
	ReplyMessage     string
	FilterID         string
	ACLPolicyName    string
	RadiusClass      string
	BandwidthProfile string
	VLAN             int
	SessionTimeout   int
	IdleTimeout      int
}

// LoginRequest describes the portal login attempt.
type LoginRequest struct {
	Username         string
	Password         string
	CallingStationID string
	CalledStationID  string
	FramedIPAddress  string
	NASPort          int
}

// ValidateUser checks username/password against local users.
func ValidateUser(username, password string) (bool, string, error) {
	var hash, role string
	err := db.DB.QueryRow("SELECT password_hash, role FROM local_users WHERE username = ?", username).Scan(&hash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", nil
		}
		return false, "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false, "", nil
	}
	return true, role, nil
}

// RateLimiter implements a per-IP token bucket rate limiter.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[ip] = limiter
		go rl.cleanup(ip)
	}
	return limiter.Allow()
}

func (rl *RateLimiter) cleanup(ip string) {
	time.Sleep(10 * time.Minute)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.limiters, ip)
}

// AuthenticateUser validates a portal login against the configured auth chain.
//
// When portal.radius_auth is enabled we use the local FreeRADIUS broker as the
// first AAA hop so Access-Accept/Reject and accounting stay aligned with the
// external upstream configuration. Local admin auth remains available as a
// break-glass path, and local/LDAP fallback is used when upstream AAA is
// unavailable and local_fallback is enabled.
func AuthenticateUser(ctx context.Context, req LoginRequest) (*Result, error) {
	cfg := config.Get()
	if cfg == nil {
		return nil, errors.New("configuration not loaded")
	}

	breakGlassResult, breakGlassErr := authenticateLocal(req.Username, req.Password)
	if breakGlassErr != nil {
		return nil, breakGlassErr
	}
	if breakGlassResult.Accepted && breakGlassResult.Role == "admin" {
		return breakGlassResult, nil
	}

	if cfg.Portal.RadiusAuth {
		brokerResult, err := aegisradius.AuthenticatePAP(ctx, cfg, aegisradius.BrokerAuthRequest{
			Username:         req.Username,
			Password:         req.Password,
			CallingStationID: req.CallingStationID,
			CalledStationID:  req.CalledStationID,
			FramedIPAddress:  req.FramedIPAddress,
			NASPort:          req.NASPort,
		})
		if err == nil {
			if !brokerResult.Accepted {
				return &Result{
					Accepted:     false,
					ReplyMessage: strings.TrimSpace(brokerResult.ReplyMessage),
				}, nil
			}

			policy, mapErr := aegisradius.ResolveSessionPolicy(cfg.Policy.DefaultRole, brokerResult)
			if mapErr != nil {
				return nil, mapErr
			}
			return &Result{
				Accepted:         true,
				Username:         req.Username,
				Role:             policy.Role,
				IdentitySource:   policy.IdentitySource,
				AuthMethod:       "radius-pap",
				ReplyMessage:     brokerResult.ReplyMessage,
				FilterID:         policy.FilterID,
				ACLPolicyName:    policy.ACLPolicyName,
				RadiusClass:      policy.RadiusClass,
				BandwidthProfile: policy.BandwidthProfile,
				VLAN:             policy.VLAN,
				SessionTimeout:   policy.SessionTimeout,
				IdleTimeout:      policy.IdleTimeout,
			}, nil
		}

		zap.L().Warn("upstream radius authentication unavailable",
			zap.String("username", req.Username),
			zap.Error(err))

		if cfg.Portal.LocalFallback {
			fallbackResult, fallbackErr := authenticateFallback(req.Username, req.Password)
			if fallbackErr != nil {
				return nil, fallbackErr
			}
			if fallbackResult.Accepted {
				fallbackResult.ReplyMessage = "upstream AAA unavailable; local fallback granted"
				return fallbackResult, nil
			}
		}

		return &Result{
			Accepted:     false,
			ReplyMessage: "upstream AAA unavailable",
		}, nil
	}

	return authenticateFallback(req.Username, req.Password)
}

func authenticateFallback(username, password string) (*Result, error) {
	localResult, err := authenticateLocal(username, password)
	if err != nil {
		return nil, err
	}
	if localResult.Accepted {
		return localResult, nil
	}
	return authenticateLDAP(username, password)
}

func authenticateLocal(username, password string) (*Result, error) {
	valid, role, err := ValidateUser(username, password)
	if err != nil {
		return nil, err
	}
	if !valid {
		return &Result{Accepted: false}, nil
	}
	return &Result{
		Accepted:       true,
		Username:       username,
		Role:           role,
		IdentitySource: "local",
		AuthMethod:     "portal-local",
	}, nil
}

func authenticateLDAP(username, password string) (*Result, error) {
	cfg := config.Get()
	if cfg == nil || !cfg.LDAP.Enabled {
		return &Result{Accepted: false}, nil
	}

	client, err := ldapclient.NewClient(&cfg.LDAP, zap.L())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	ok, err := client.Authenticate(username, password)
	if err != nil || !ok {
		return &Result{Accepted: false}, err
	}

	groups, err := client.GetUserGroups(username)
	if err != nil {
		return nil, err
	}
	role, err := ldapclient.GetRoleForGroups(groups)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(role) == "" {
		role = cfg.Policy.DefaultRole
	}

	return &Result{
		Accepted:       true,
		Username:       username,
		Role:           role,
		Groups:         groups,
		IdentitySource: "ldap",
		AuthMethod:     "portal-ldap",
	}, nil
}
