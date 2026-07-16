package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/activedirectory"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	identityfailover "github.com/yourorg/aegisnas-pi4/internal/identity"
	ldapclient "github.com/yourorg/aegisnas-pi4/internal/ldap"
	"github.com/yourorg/aegisnas-pi4/internal/mfa"
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
	MFARequired      bool
	MFAState         string
	MFAPrompt        string
	MFAExpiresAt     string
}

// LoginRequest describes the portal login attempt.
type LoginRequest struct {
	Username         string
	Password         string
	CallingStationID string
	CalledStationID  string
	FramedIPAddress  string
	NASPort          int
	OTP              string
	MFAState         string
}

// ValidateUser checks username/password against local users.
func ValidateUser(username, password string) (bool, string, error) {
	valid, role, _, err := ValidateUserDetailed(username, password)
	return valid, role, err
}

// ValidateUserDetailed checks username/password and distinguishes a missing
// local user from an existing user with a bad password.
func ValidateUserDetailed(username, password string) (bool, string, bool, error) {
	var hash, role string
	err := db.DB.QueryRow("SELECT password_hash, role FROM local_users WHERE username = ?", username).Scan(&hash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", false, nil
		}
		return false, "", false, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false, "", true, nil
	}
	return true, role, true, nil
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

	if strings.TrimSpace(req.MFAState) != "" {
		return authenticateMFAChallenge(ctx, cfg, req)
	}

	breakGlassResult, breakGlassErr := authenticateLocal(req.Username, req.Password)
	if breakGlassErr != nil {
		return nil, breakGlassErr
	}
	if breakGlassResult.Accepted && breakGlassResult.Role == "admin" {
		return applyMFA(ctx, cfg, req, breakGlassResult)
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
			if brokerResult.Challenge {
				return &Result{
					Accepted:     false,
					MFARequired:  true,
					MFAState:     brokerResult.ChallengeState,
					MFAPrompt:    firstNonEmpty(brokerResult.ChallengePrompt, "Enter one-time password"),
					ReplyMessage: strings.TrimSpace(brokerResult.ReplyMessage),
				}, nil
			}
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
			result := &Result{
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
			}
			return applyMFA(ctx, cfg, req, result)
		}

		zap.L().Warn("upstream radius authentication unavailable",
			zap.String("username", req.Username),
			zap.Error(err))

		if cfg.Portal.LocalFallback {
			fallbackResult, fallbackErr := authenticateFallback(ctx, req.Username, req.Password)
			if fallbackErr != nil {
				return nil, fallbackErr
			}
			if fallbackResult.Accepted {
				decision := aegisradius.EvaluateFallbackPolicy(cfg, aegisradius.FallbackEvaluationRequest{
					Username:       req.Username,
					Role:           fallbackResult.Role,
					IdentitySource: fallbackResult.IdentitySource,
					Source:         "portal",
				})
				if recordErr := aegisradius.RecordFallbackDecision(cfg, decision); recordErr != nil {
					zap.L().Warn("record radius fallback decision failed",
						zap.String("username_hash", decision.UsernameHash),
						zap.Error(recordErr))
				}
				if !decision.Allowed {
					zap.L().Warn("upstream radius local fallback denied by policy",
						zap.String("username_hash", decision.UsernameHash),
						zap.String("reason", decision.Reason))
					return &Result{
						Accepted:     false,
						ReplyMessage: "upstream AAA unavailable; local fallback denied by policy",
					}, nil
				}
				fallbackResult.ReplyMessage = "upstream AAA unavailable; local fallback granted"
				return applyMFA(ctx, cfg, req, fallbackResult)
			}
		}

		return &Result{
			Accepted:     false,
			ReplyMessage: "upstream AAA unavailable",
		}, nil
	}

	result, err := authenticateFallback(ctx, req.Username, req.Password)
	if err != nil || result == nil || !result.Accepted {
		return result, err
	}
	return applyMFA(ctx, cfg, req, result)
}

func authenticateMFAChallenge(ctx context.Context, cfg *config.Config, req LoginRequest) (*Result, error) {
	if mfa.IsLocalState(req.MFAState) {
		verified, err := mfa.VerifyChallenge(ctx, cfg, req.MFAState, req.Username, req.OTP)
		if err != nil {
			return nil, err
		}
		if !verified.Allowed {
			return &Result{Accepted: false, ReplyMessage: verified.Reason}, nil
		}
		authMethod := strings.TrimSpace(verified.AuthMethod)
		if authMethod == "" {
			authMethod = "portal-local"
		}
		return &Result{
			Accepted:       true,
			Username:       req.Username,
			Role:           verified.Role,
			IdentitySource: verified.IdentitySource,
			AuthMethod:     authMethod + "+mfa-" + verified.Method,
			ReplyMessage:   "MFA challenge verified",
		}, nil
	}
	if !cfg.Portal.RadiusAuth {
		return &Result{Accepted: false, ReplyMessage: "unknown MFA challenge"}, nil
	}
	brokerResult, err := aegisradius.AuthenticatePAP(ctx, cfg, aegisradius.BrokerAuthRequest{
		Username:         req.Username,
		Password:         req.OTP,
		CallingStationID: req.CallingStationID,
		CalledStationID:  req.CalledStationID,
		FramedIPAddress:  req.FramedIPAddress,
		NASPort:          req.NASPort,
		State:            req.MFAState,
	})
	if err != nil {
		return nil, err
	}
	if brokerResult.Challenge {
		return &Result{
			Accepted:     false,
			MFARequired:  true,
			MFAState:     brokerResult.ChallengeState,
			MFAPrompt:    firstNonEmpty(brokerResult.ChallengePrompt, "Enter one-time password"),
			ReplyMessage: brokerResult.ReplyMessage,
		}, nil
	}
	if !brokerResult.Accepted {
		return &Result{Accepted: false, ReplyMessage: strings.TrimSpace(brokerResult.ReplyMessage)}, nil
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
		AuthMethod:       "radius-pap+mfa-challenge",
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

func applyMFA(ctx context.Context, cfg *config.Config, req LoginRequest, result *Result) (*Result, error) {
	if result == nil || !result.Accepted {
		return result, nil
	}
	stepCtx := mfa.StepUpContext{
		Username:       result.Username,
		Role:           result.Role,
		IdentitySource: result.IdentitySource,
		AuthMethod:     result.AuthMethod,
		Source:         "portal",
	}
	if !mfa.RequiresStepUp(cfg, stepCtx) {
		return result, nil
	}
	policy := mfa.PolicyFromConfig(cfg)
	if policy.Mode == "monitor" {
		mfa.RecordMonitorAllowed(cfg, stepCtx, "MFA step-up would be required in enforce mode")
		return result, nil
	}
	if strings.TrimSpace(req.OTP) != "" {
		verified, err := mfa.VerifyOTP(ctx, cfg, result.Username, req.OTP, stepCtx, true)
		if err != nil {
			return nil, err
		}
		if verified.Allowed {
			result.AuthMethod = result.AuthMethod + "+mfa-" + verified.Method
			result.ReplyMessage = firstNonEmpty(result.ReplyMessage, "MFA accepted")
			return result, nil
		}
		return &Result{Accepted: false, ReplyMessage: verified.Reason}, nil
	}
	challenge, err := mfa.StartChallenge(cfg, stepCtx)
	if err != nil {
		if policy.FailClosed {
			return nil, err
		}
		result.ReplyMessage = "MFA challenge unavailable; fail-open policy allowed login"
		return result, nil
	}
	return &Result{
		Accepted:     false,
		Username:     result.Username,
		Role:         result.Role,
		MFARequired:  true,
		MFAState:     challenge.State,
		MFAPrompt:    challenge.Prompt,
		MFAExpiresAt: challenge.ExpiresAt,
		ReplyMessage: "MFA required",
	}, nil
}

func authenticateFallback(ctx context.Context, username, password string) (*Result, error) {
	cfg := config.Get()
	policy := identityfailover.FailoverPolicyFromConfig(cfg)
	if !policy.Enabled {
		localResult, err := authenticateLocal(username, password)
		if err != nil {
			return nil, err
		}
		if localResult.Accepted {
			return localResult, nil
		}
		return authenticateLDAP(username, password)
	}

	type credentialReject struct {
		sourceName string
		sourceType string
	}
	var firstReject *credentialReject
	var attempted int
	var skipped int
	for _, source := range identityfailover.BuildSourcePlan(cfg) {
		if !source.Executable {
			skipped++
			recordIdentitySourceEvent(policy, source, username, "skipped", source.Reason, 0, source.CircuitState.State, false, nil)
			continue
		}
		attempted++
		started := time.Now()
		result, decision, reason, err := authenticateIdentitySource(ctx, source, username, password, policy)
		latencyMS := time.Since(started).Milliseconds()
		if err != nil {
			recordIdentitySourceEvent(policy, source, username, "failed", err.Error(), latencyMS, "closed", false, map[string]any{"reason": reason})
			if source.Type == "ldap" || source.Type == "active_directory" {
				if cached, ok, cacheErr := authenticateStaleIdentityCache(source, username, password, policy); cacheErr != nil {
					zap.L().Warn("identity source stale cache lookup failed",
						zap.String("source", source.Name),
						zap.Error(cacheErr))
				} else if ok {
					recordIdentitySourceEvent(policy, source, username, "stale_accepted", "ldap unavailable; stale cache accepted", latencyMS, "closed", true, nil)
					return cached, nil
				}
			}
			continue
		}
		recordIdentitySourceEvent(policy, source, username, decision, reason, latencyMS, "closed", false, nil)
		switch decision {
		case "accepted":
			if firstReject != nil && splitResultDenied(policy) {
				recordIdentitySourceEvent(policy, source, username, "split_denied",
					"identity source accepted after earlier credential rejection", latencyMS, "closed", false,
					map[string]any{"first_reject_source": firstReject.sourceName, "first_reject_type": firstReject.sourceType})
				return &Result{Accepted: false, ReplyMessage: "identity source split-result policy denied login"}, nil
			}
			return result, nil
		case "rejected":
			if firstReject == nil {
				firstReject = &credentialReject{sourceName: source.Name, sourceType: source.Type}
			}
		}
	}
	if firstReject != nil {
		return &Result{Accepted: false, ReplyMessage: "invalid credentials"}, nil
	}
	if policy.Mode == "enforce" && policy.FailClosed && attempted == 0 && skipped > 0 {
		return &Result{Accepted: false, ReplyMessage: "identity sources unavailable"}, nil
	}
	return &Result{Accepted: false}, nil
}

func authenticateLocal(username, password string) (*Result, error) {
	valid, role, _, err := ValidateUserDetailed(username, password)
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

func authenticateIdentitySource(ctx context.Context, source identityfailover.SourcePlan, username, password string, policy identityfailover.FailoverPolicy) (*Result, string, string, error) {
	select {
	case <-ctx.Done():
		return nil, "failed", "request context cancelled", ctx.Err()
	default:
	}
	switch source.Type {
	case "local":
		return authenticateLocalSource(source, username, password)
	case "ldap":
		result, err := authenticateLDAP(username, password)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "user not found") {
				return &Result{Accepted: false}, "not_found", "user not found", nil
			}
			return nil, "failed", "ldap error", err
		}
		if !result.Accepted {
			return result, "rejected", "invalid credentials", nil
		}
		if policy.CacheCredentials && db.DB != nil {
			if cacheErr := db.UpsertIdentitySourceCache(source.Name, username, password, result.Role, result.IdentitySource, result.Groups, policy.StaleCacheSeconds, time.Now().UTC()); cacheErr != nil {
				zap.L().Warn("identity source credential cache update failed",
					zap.String("source", source.Name),
					zap.Error(cacheErr))
			}
		}
		return result, "accepted", "credentials accepted", nil
	case "active_directory":
		result, err := activedirectory.Authenticate(ctx, config.Get(), source.Name, username, password)
		if err != nil {
			return nil, "failed", "active directory error", err
		}
		if !result.Accepted {
			reason := strings.TrimSpace(result.ReplyMessage)
			if reason == "" {
				reason = "invalid credentials"
			}
			if strings.Contains(strings.ToLower(reason), "not found") {
				return &Result{Accepted: false}, "not_found", reason, nil
			}
			return &Result{Accepted: false, ReplyMessage: reason}, "rejected", reason, nil
		}
		portalResult := &Result{
			Accepted:       true,
			Username:       username,
			Role:           result.Role,
			Groups:         result.Groups,
			IdentitySource: source.Name,
			AuthMethod:     result.AuthMethod,
			ReplyMessage:   result.ReplyMessage,
		}
		if policy.CacheCredentials && db.DB != nil {
			if cacheErr := db.UpsertIdentitySourceCache(source.Name, username, password, portalResult.Role, portalResult.IdentitySource, portalResult.Groups, policy.StaleCacheSeconds, time.Now().UTC()); cacheErr != nil {
				zap.L().Warn("identity source credential cache update failed",
					zap.String("source", source.Name),
					zap.Error(cacheErr))
			}
		}
		return portalResult, "accepted", "credentials accepted", nil
	default:
		return &Result{Accepted: false}, "skipped", "unsupported identity source type", nil
	}
}

func authenticateLocalSource(source identityfailover.SourcePlan, username, password string) (*Result, string, string, error) {
	valid, role, found, err := ValidateUserDetailed(username, password)
	if err != nil {
		return nil, "failed", "local database error", err
	}
	if !found {
		return &Result{Accepted: false}, "not_found", "user not found", nil
	}
	if !valid {
		return &Result{Accepted: false}, "rejected", "invalid credentials", nil
	}
	return &Result{
		Accepted:       true,
		Username:       username,
		Role:           role,
		IdentitySource: source.Name,
		AuthMethod:     "portal-local",
	}, "accepted", "credentials accepted", nil
}

func authenticateStaleIdentityCache(source identityfailover.SourcePlan, username, password string, policy identityfailover.FailoverPolicy) (*Result, bool, error) {
	if !policy.CacheCredentials || db.DB == nil {
		return nil, false, nil
	}
	entry, ok, err := db.VerifyIdentitySourceCache(source.Name, username, password, time.Now().UTC())
	if err != nil || !ok {
		return nil, ok, err
	}
	authMethod := "portal-ldap-cache"
	if strings.TrimSpace(entry.IdentitySource) != "" {
		authMethod = "portal-" + strings.TrimSpace(entry.IdentitySource) + "-cache"
	}
	return &Result{
		Accepted:       true,
		Username:       username,
		Role:           entry.Role,
		Groups:         entry.Groups,
		IdentitySource: entry.IdentitySource,
		AuthMethod:     authMethod,
		ReplyMessage:   "identity source unavailable; stale cache accepted",
	}, true, nil
}

func recordIdentitySourceEvent(policy identityfailover.FailoverPolicy, source identityfailover.SourcePlan, username, decision, reason string, latencyMS int64, circuitState string, cacheUsed bool, details any) {
	if err := identityfailover.RecordEvent(policy, identityfailover.EventRecord{
		SourceName:   source.Name,
		SourceType:   source.Type,
		Username:     username,
		Decision:     decision,
		Reason:       reason,
		LatencyMS:    latencyMS,
		CircuitState: circuitState,
		CacheUsed:    cacheUsed,
		Details:      details,
	}); err != nil {
		zap.L().Warn("record identity source event failed",
			zap.String("source", source.Name),
			zap.String("decision", decision),
			zap.Error(err))
	}
}

func splitResultDenied(policy identityfailover.FailoverPolicy) bool {
	switch identityfailover.NormalizeSplitResultPolicy(policy.SplitResultPolicy) {
	case "prefer_success":
		return false
	default:
		return true
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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
