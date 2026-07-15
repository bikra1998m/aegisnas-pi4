package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

const (
	SchemaVersion     = 1
	localStatePrefix  = "aegis1."
	defaultSource     = "portal"
	defaultMethodTOTP = "totp"
)

type Policy struct {
	SchemaVersion     int      `json:"schema_version"`
	Enabled           bool     `json:"enabled"`
	Mode              string   `json:"mode"`
	FailClosed        bool     `json:"fail_closed"`
	OTPEnabled        bool     `json:"otp_enabled"`
	Issuer            string   `json:"issuer"`
	Algorithm         string   `json:"algorithm"`
	Digits            int      `json:"digits"`
	PeriodSeconds     int      `json:"period_seconds"`
	WindowSteps       int      `json:"window_steps"`
	MaxAttempts       int      `json:"max_attempts"`
	SealingKeyRefSet  bool     `json:"sealing_key_ref_set"`
	StepUpRoles       []string `json:"step_up_roles"`
	StepUpRealms      []string `json:"step_up_realms"`
	RequiredForAdmins bool     `json:"required_for_admins"`
	ChallengeEnabled  bool     `json:"challenge_enabled"`
	ChallengeTTL      int      `json:"challenge_ttl_seconds"`
	ChallengeMax      int      `json:"challenge_max_pending"`
	ChallengePrompt   string   `json:"challenge_prompt"`
	RecoveryEnabled   bool     `json:"recovery_enabled"`
	RecoveryCodeCount int      `json:"recovery_code_count"`
	RecoveryCodeBytes int      `json:"recovery_code_bytes"`
	RecoveryCodeTTL   int      `json:"recovery_code_ttl_seconds"`
	AuditEnabled      bool     `json:"audit_enabled"`
	RetentionLimit    int      `json:"retention_limit"`
}

type Summary struct {
	StepUpRoleCount       int    `json:"step_up_role_count"`
	StepUpRealmCount      int    `json:"step_up_realm_count"`
	AdminStepUp           bool   `json:"admin_step_up"`
	PortalMFAReady        bool   `json:"portal_mfa_ready"`
	RadiusChallengeReady  bool   `json:"radius_challenge_ready"`
	SealingKeyFingerprint string `json:"sealing_key_fingerprint,omitempty"`
}

type Report struct {
	SchemaVersion int                     `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Enabled       bool                    `json:"enabled"`
	Status        string                  `json:"status"`
	Message       string                  `json:"message"`
	Policy        Policy                  `json:"policy"`
	Summary       Summary                 `json:"summary"`
	Credentials   db.MFACredentialSummary `json:"credentials"`
	AuditSummary  db.MFAEventSummary      `json:"audit_summary"`
	Recent        []db.MFAEvent           `json:"recent,omitempty"`
}

type StepUpContext struct {
	Username       string
	Role           string
	IdentitySource string
	AuthMethod     string
	Source         string
}

type Challenge struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Prompt    string `json:"prompt"`
	ExpiresAt string `json:"expires_at"`
}

type Enrollment struct {
	UsernameHash  string   `json:"username_hash"`
	Secret        string   `json:"secret"`
	OTPAuthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

type VerifyResult struct {
	Allowed  bool   `json:"allowed"`
	Method   string `json:"method,omitempty"`
	Reason   string `json:"reason"`
	Consumed bool   `json:"consumed_recovery_code,omitempty"`
}

type VerifiedChallenge struct {
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason"`
	UsernameHash   string `json:"username_hash,omitempty"`
	Role           string `json:"role,omitempty"`
	IdentitySource string `json:"identity_source,omitempty"`
	AuthMethod     string `json:"auth_method,omitempty"`
	Source         string `json:"source,omitempty"`
	Method         string `json:"method,omitempty"`
}

func PolicyFromConfig(cfg *config.Config) Policy {
	raw := config.MFAConfig{}
	if cfg != nil {
		raw = config.EffectiveMFAConfig(cfg.MFA)
	}
	return Policy{
		SchemaVersion:     SchemaVersion,
		Enabled:           raw.Enabled,
		Mode:              normalizeMode(raw.Mode),
		FailClosed:        raw.FailClosed,
		OTPEnabled:        raw.OTP.Enabled,
		Issuer:            strings.TrimSpace(raw.OTP.Issuer),
		Algorithm:         strings.ToUpper(strings.TrimSpace(raw.OTP.Algorithm)),
		Digits:            raw.OTP.Digits,
		PeriodSeconds:     raw.OTP.PeriodSeconds,
		WindowSteps:       raw.OTP.WindowSteps,
		MaxAttempts:       raw.OTP.MaxAttempts,
		SealingKeyRefSet:  strings.TrimSpace(raw.OTP.SealingKeyRef) != "",
		StepUpRoles:       normalizeList(raw.OTP.StepUpRoles),
		StepUpRealms:      normalizeRealms(raw.OTP.StepUpRealms),
		RequiredForAdmins: raw.OTP.RequiredForAdmins,
		ChallengeEnabled:  raw.RadiusChallenge.Enabled,
		ChallengeTTL:      raw.RadiusChallenge.TTLSeconds,
		ChallengeMax:      raw.RadiusChallenge.MaxPending,
		ChallengePrompt:   strings.TrimSpace(raw.RadiusChallenge.Prompt),
		RecoveryEnabled:   raw.Recovery.Enabled,
		RecoveryCodeCount: raw.Recovery.CodeCount,
		RecoveryCodeBytes: raw.Recovery.CodeBytes,
		RecoveryCodeTTL:   raw.Recovery.CodeTTLSeconds,
		AuditEnabled:      raw.AuditEnabled,
		RetentionLimit:    raw.RetentionLimit,
	}
}

func BuildReport(cfg *config.Config) Report {
	now := time.Now().UTC()
	policy := PolicyFromConfig(cfg)
	report := Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Enabled:       policy.Enabled,
		Status:        "ready",
		Policy:        policy,
		Summary: Summary{
			StepUpRoleCount:      len(policy.StepUpRoles),
			StepUpRealmCount:     len(policy.StepUpRealms),
			AdminStepUp:          policy.RequiredForAdmins,
			PortalMFAReady:       cfg != nil && cfg.Portal.Enabled && policy.Enabled && policy.OTPEnabled,
			RadiusChallengeReady: policy.Enabled && policy.ChallengeEnabled,
		},
	}
	if cfg != nil {
		raw := config.EffectiveMFAConfig(cfg.MFA)
		report.Summary.SealingKeyFingerprint = secrets.Fingerprint(raw.OTP.SealingKeyRef)
	}
	if db.DB != nil {
		if summary, err := db.GetMFACredentialSummary(now); err == nil {
			report.Credentials = summary
		}
		if audit, err := db.GetMFAEventSummary(); err == nil {
			report.AuditSummary = audit
		}
		if recent, err := db.ListMFAEvents("", "", 25); err == nil {
			report.Recent = recent
		}
	}

	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "MFA is disabled; first-factor authentication behavior is unchanged."
	case !policy.OTPEnabled:
		report.Status = "blocked"
		report.Message = "MFA is enabled but OTP verification is disabled."
	case !policy.SealingKeyRefSet:
		report.Status = "blocked"
		report.Message = "MFA needs a configured OTP sealing key reference."
	case db.DB == nil:
		report.Status = "blocked"
		report.Message = "MFA audit and challenge state require the database."
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "MFA is in monitor mode; step-up decisions are audited but not enforced."
	case !policy.FailClosed:
		report.Status = "degraded"
		report.Message = "MFA enforcement is active but fail_closed is disabled."
	case report.Credentials.EnabledUsers == 0:
		report.Status = "degraded"
		report.Message = "MFA enforcement is configured but no users are enrolled yet."
	default:
		report.Message = "MFA is enforceable with encrypted TOTP secrets, recovery codes, challenge state, and audit evidence."
	}
	return report
}

func RequiresStepUp(cfg *config.Config, ctx StepUpContext) bool {
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled || !policy.OTPEnabled {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(ctx.Role))
	if policy.RequiredForAdmins {
		switch role {
		case "admin", "super_admin", "ops_admin":
			return true
		}
	}
	for _, candidate := range policy.StepUpRoles {
		if strings.EqualFold(candidate, role) {
			return true
		}
	}
	realm := usernameRealm(ctx.Username)
	for _, candidate := range policy.StepUpRealms {
		if candidate == "*" || strings.EqualFold(candidate, realm) {
			return true
		}
	}
	return false
}

func RecordMonitorAllowed(cfg *config.Config, ctx StepUpContext, reason string) {
	policy := PolicyFromConfig(cfg)
	recordEvent(policy, db.MFAEvent{
		ObservedAt:     time.Now().UTC().Format(time.RFC3339),
		UsernameHash:   db.HashIdentityUsername(ctx.Username),
		Source:         sourceOrDefault(ctx.Source),
		Method:         defaultMethodTOTP,
		Decision:       "monitor_allowed",
		Reason:         strings.TrimSpace(reason),
		Role:           strings.TrimSpace(ctx.Role),
		IdentitySource: strings.TrimSpace(ctx.IdentitySource),
		AuthMethod:     strings.TrimSpace(ctx.AuthMethod),
	}, nil)
}

func StartChallenge(cfg *config.Config, ctx StepUpContext) (Challenge, error) {
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled || !policy.OTPEnabled {
		return Challenge{}, fmt.Errorf("MFA is not enabled")
	}
	if cfg == nil {
		return Challenge{}, fmt.Errorf("configuration not loaded")
	}
	if db.DB == nil {
		return Challenge{}, fmt.Errorf("database not initialized")
	}
	now := time.Now().UTC()
	if summary, err := db.GetMFACredentialSummary(now); err == nil && policy.ChallengeMax > 0 && summary.PendingChallenges >= policy.ChallengeMax {
		return Challenge{}, fmt.Errorf("maximum pending MFA challenges reached")
	}
	raw := config.EffectiveMFAConfig(cfg.MFA)
	stateBytes := raw.RadiusChallenge.StateBytes
	if stateBytes <= 0 {
		stateBytes = 32
	}
	randomState, err := randomBase64URL(stateBytes)
	if err != nil {
		return Challenge{}, err
	}
	randomID, err := randomBase64URL(18)
	if err != nil {
		return Challenge{}, err
	}
	state := localStatePrefix + randomState
	expiresAt := now.Add(time.Duration(policy.ChallengeTTL) * time.Second)
	challenge := Challenge{
		ID:        "mfa_" + randomID,
		State:     state,
		Prompt:    policy.ChallengePrompt,
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	record := db.MFAChallenge{
		ID:             challenge.ID,
		StateHash:      StateHash(state),
		UsernameHash:   db.HashIdentityUsername(ctx.Username),
		Source:         sourceOrDefault(ctx.Source),
		Role:           strings.TrimSpace(ctx.Role),
		IdentitySource: strings.TrimSpace(ctx.IdentitySource),
		AuthMethod:     strings.TrimSpace(ctx.AuthMethod),
		ChallengeType:  defaultMethodTOTP,
		Status:         "pending",
		MaxAttempts:    policy.MaxAttempts,
		Prompt:         challenge.Prompt,
		ExpiresAt:      challenge.ExpiresAt,
		CreatedAt:      now.Format(time.RFC3339),
	}
	if err := db.InsertMFAChallenge(record, map[string]any{
		"schema_version": SchemaVersion,
		"source":         record.Source,
	}); err != nil {
		return Challenge{}, err
	}
	recordEvent(policy, db.MFAEvent{
		ObservedAt:     now.Format(time.RFC3339),
		UsernameHash:   record.UsernameHash,
		Source:         record.Source,
		Method:         defaultMethodTOTP,
		Decision:       "challenge_issued",
		Reason:         "step-up MFA challenge issued",
		ChallengeID:    record.ID,
		Role:           record.Role,
		IdentitySource: record.IdentitySource,
		AuthMethod:     record.AuthMethod,
	}, nil)
	return challenge, nil
}

func VerifyChallenge(ctx context.Context, cfg *config.Config, state, username, code string) (VerifiedChallenge, error) {
	policy := PolicyFromConfig(cfg)
	now := time.Now().UTC()
	if !IsLocalState(state) {
		return VerifiedChallenge{Allowed: false, Reason: "not an AegisNAS MFA challenge"}, nil
	}
	if db.DB == nil {
		return VerifiedChallenge{}, fmt.Errorf("database not initialized")
	}
	challenge, ok, err := db.GetMFAChallengeByStateHash(StateHash(state), now)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	if !ok {
		return VerifiedChallenge{Allowed: false, Reason: "challenge not found"}, nil
	}
	eventBase := db.MFAEvent{
		ObservedAt:     now.Format(time.RFC3339),
		UsernameHash:   challenge.UsernameHash,
		Source:         sourceOrDefault(challenge.Source),
		Method:         defaultMethodTOTP,
		ChallengeID:    challenge.ID,
		Role:           challenge.Role,
		IdentitySource: challenge.IdentitySource,
		AuthMethod:     challenge.AuthMethod,
	}
	if challenge.Status != "pending" {
		eventBase.Decision = "denied"
		eventBase.Reason = "challenge is not pending"
		recordEvent(policy, eventBase, map[string]any{"status": challenge.Status})
		return VerifiedChallenge{Allowed: false, Reason: eventBase.Reason}, nil
	}
	if usernameHash := db.HashIdentityUsername(username); usernameHash != "" && usernameHash != challenge.UsernameHash {
		eventBase.Decision = "denied"
		eventBase.Reason = "challenge username mismatch"
		_ = db.UpdateMFAChallengeStatus(challenge.ID, "failed", challenge.AttemptCount+1, eventBase.Reason, now)
		recordEvent(policy, eventBase, nil)
		return VerifiedChallenge{Allowed: false, Reason: eventBase.Reason}, nil
	}
	result, err := VerifyOTP(ctx, cfg, username, code, StepUpContext{
		Username:       username,
		Role:           challenge.Role,
		IdentitySource: challenge.IdentitySource,
		AuthMethod:     challenge.AuthMethod,
		Source:         challenge.Source,
	}, false)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	if result.Allowed {
		if err := db.UpdateMFAChallengeStatus(challenge.ID, "verified", challenge.AttemptCount+1, "", now); err != nil {
			return VerifiedChallenge{}, err
		}
		eventBase.Decision = "accepted"
		eventBase.Reason = "step-up MFA challenge verified"
		eventBase.Method = result.Method
		recordEvent(policy, eventBase, nil)
		return VerifiedChallenge{
			Allowed:        true,
			Reason:         eventBase.Reason,
			UsernameHash:   challenge.UsernameHash,
			Role:           challenge.Role,
			IdentitySource: challenge.IdentitySource,
			AuthMethod:     challenge.AuthMethod,
			Source:         challenge.Source,
			Method:         result.Method,
		}, nil
	}
	attempts := challenge.AttemptCount + 1
	status := "pending"
	if attempts >= challenge.MaxAttempts {
		status = "failed"
	}
	if err := db.UpdateMFAChallengeStatus(challenge.ID, status, attempts, result.Reason, now); err != nil {
		return VerifiedChallenge{}, err
	}
	eventBase.Decision = "denied"
	eventBase.Reason = result.Reason
	eventBase.Method = result.Method
	recordEvent(policy, eventBase, map[string]any{"attempt_count": attempts, "status": status})
	return VerifiedChallenge{Allowed: false, Reason: result.Reason}, nil
}

func VerifyOTP(ctx context.Context, cfg *config.Config, username, code string, stepCtx StepUpContext, audit bool) (VerifyResult, error) {
	policy := PolicyFromConfig(cfg)
	now := time.Now().UTC()
	method := defaultMethodTOTP
	reason := "invalid one-time password"
	event := db.MFAEvent{
		ObservedAt:     now.Format(time.RFC3339),
		UsernameHash:   db.HashIdentityUsername(username),
		Source:         sourceOrDefault(stepCtx.Source),
		Method:         method,
		Decision:       "denied",
		Reason:         reason,
		Role:           strings.TrimSpace(stepCtx.Role),
		IdentitySource: strings.TrimSpace(stepCtx.IdentitySource),
		AuthMethod:     strings.TrimSpace(stepCtx.AuthMethod),
	}
	code = normalizeCode(code)
	if code == "" {
		event.Reason = "missing one-time password"
		if audit {
			recordEvent(policy, event, nil)
		}
		return VerifyResult{Allowed: false, Method: method, Reason: event.Reason}, nil
	}
	secretRecord, ok, err := db.GetMFATOTPSecret(username)
	if err != nil {
		return VerifyResult{}, err
	}
	if !ok || !secretRecord.Enabled {
		event.Reason = "user is not enrolled for MFA"
		if audit {
			recordEvent(policy, event, nil)
		}
		return VerifyResult{Allowed: false, Method: method, Reason: event.Reason}, nil
	}
	secret, err := openStoredSecret(ctx, cfg, secretRecord, event.UsernameHash)
	if err != nil {
		return VerifyResult{}, err
	}
	if VerifyTOTP(secret, code, TOTPOptions{
		Algorithm:     secretRecord.Algorithm,
		Digits:        secretRecord.Digits,
		PeriodSeconds: secretRecord.PeriodSeconds,
		WindowSteps:   policy.WindowSteps,
		Now:           now,
	}) {
		if err := db.TouchMFATOTPVerified(username, now); err != nil {
			return VerifyResult{}, err
		}
		event.Decision = "accepted"
		event.Reason = "one-time password accepted"
		if audit {
			recordEvent(policy, event, nil)
		}
		return VerifyResult{Allowed: true, Method: method, Reason: event.Reason}, nil
	}
	recoveryOK, err := db.VerifyMFARecoveryCode(username, code, now)
	if err != nil {
		return VerifyResult{}, err
	}
	if recoveryOK {
		event.Method = "recovery"
		event.Decision = "accepted"
		event.Reason = "MFA recovery code accepted"
		if audit {
			recordEvent(policy, event, nil)
		}
		return VerifyResult{Allowed: true, Method: "recovery", Reason: event.Reason, Consumed: true}, nil
	}
	if audit {
		recordEvent(policy, event, nil)
	}
	return VerifyResult{Allowed: false, Method: method, Reason: reason}, nil
}

func EnrollTOTP(ctx context.Context, cfg *config.Config, username string) (Enrollment, error) {
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled || !policy.OTPEnabled {
		return Enrollment{}, fmt.Errorf("MFA TOTP is not enabled")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return Enrollment{}, fmt.Errorf("username is required")
	}
	secretBytes := 20
	secretRaw := make([]byte, secretBytes)
	if _, err := rand.Read(secretRaw); err != nil {
		return Enrollment{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretRaw)
	usernameHash := db.HashIdentityUsername(username)
	ciphertext, nonce, err := sealSecret(ctx, cfg, usernameHash, secret)
	if err != nil {
		return Enrollment{}, err
	}
	if err := db.UpsertMFATOTPSecret(username, ciphertext, nonce, policy.Algorithm, policy.Digits, policy.PeriodSeconds, policy.Issuer, true, time.Now().UTC()); err != nil {
		return Enrollment{}, err
	}
	recoveryCodes, err := rotateRecoveryCodes(username, policy)
	if err != nil {
		return Enrollment{}, err
	}
	recordEvent(policy, db.MFAEvent{
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		UsernameHash: usernameHash,
		Source:       "admin-api",
		Method:       defaultMethodTOTP,
		Decision:     "enrolled",
		Reason:       "TOTP secret enrolled",
	}, map[string]any{"recovery_codes": len(recoveryCodes)})
	return Enrollment{
		UsernameHash:  usernameHash,
		Secret:        secret,
		OTPAuthURL:    otpAuthURL(policy, username, secret),
		RecoveryCodes: recoveryCodes,
	}, nil
}

func RotateRecoveryCodes(username string, cfg *config.Config) ([]string, error) {
	policy := PolicyFromConfig(cfg)
	if !policy.RecoveryEnabled {
		return nil, fmt.Errorf("MFA recovery codes are disabled")
	}
	codes, err := rotateRecoveryCodes(username, policy)
	if err != nil {
		return nil, err
	}
	recordEvent(policy, db.MFAEvent{
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		UsernameHash: db.HashIdentityUsername(username),
		Source:       "admin-api",
		Method:       "recovery",
		Decision:     "enrolled",
		Reason:       "MFA recovery codes rotated",
	}, map[string]any{"recovery_codes": len(codes)})
	return codes, nil
}

func IsLocalState(state string) bool {
	return strings.HasPrefix(strings.TrimSpace(state), localStatePrefix)
}

func StateHash(state string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(state)))
	return hex.EncodeToString(sum[:])
}

type TOTPOptions struct {
	Algorithm     string
	Digits        int
	PeriodSeconds int
	WindowSteps   int
	Now           time.Time
}

func VerifyTOTP(secret, code string, opts TOTPOptions) bool {
	secret = strings.TrimSpace(secret)
	code = normalizeCode(code)
	if secret == "" || code == "" {
		return false
	}
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		if padded := addBase32Padding(strings.ToUpper(secret)); padded != "" {
			secretBytes, err = base32.StdEncoding.DecodeString(padded)
		}
		if err != nil {
			return false
		}
	}
	if opts.PeriodSeconds <= 0 {
		opts.PeriodSeconds = 30
	}
	if opts.Digits == 0 {
		opts.Digits = 6
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	counter := opts.Now.Unix() / int64(opts.PeriodSeconds)
	for offset := -opts.WindowSteps; offset <= opts.WindowSteps; offset++ {
		candidate := counter + int64(offset)
		if candidate < 0 {
			continue
		}
		expected := hotp(secretBytes, uint64(candidate), opts)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func GenerateTOTP(secret string, opts TOTPOptions) string {
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	if opts.PeriodSeconds <= 0 {
		opts.PeriodSeconds = 30
	}
	if opts.Digits == 0 {
		opts.Digits = 6
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	return hotp(secretBytes, uint64(opts.Now.Unix()/int64(opts.PeriodSeconds)), opts)
}

func hotp(secret []byte, counter uint64, opts TOTPOptions) string {
	if int64(counter) < 0 {
		return ""
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(hashFactory(opts.Algorithm), secret)
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	mod := uint32(math.Pow10(opts.Digits))
	return fmt.Sprintf("%0*d", opts.Digits, value%mod)
}

func hashFactory(algorithm string) func() hash.Hash {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

func openStoredSecret(ctx context.Context, cfg *config.Config, record db.MFATOTPSecret, usernameHash string) (string, error) {
	key, err := resolveSealingKey(ctx, cfg)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(record.SecretCiphertext)
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(record.SecretNonce)
	if err != nil {
		return "", fmt.Errorf("decode TOTP secret nonce: %w", err)
	}
	block, err := aes.NewCipher(sha256Bytes(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(usernameHash))
	if err != nil {
		return "", fmt.Errorf("open TOTP secret: %w", err)
	}
	return string(plaintext), nil
}

func sealSecret(ctx context.Context, cfg *config.Config, usernameHash, secret string) (string, string, error) {
	key, err := resolveSealingKey(ctx, cfg)
	if err != nil {
		return "", "", err
	}
	block, err := aes.NewCipher(sha256Bytes(key))
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("generate TOTP secret nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), []byte(usernameHash))
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func resolveSealingKey(ctx context.Context, cfg *config.Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	raw := config.EffectiveMFAConfig(cfg.MFA)
	ref := strings.TrimSpace(raw.OTP.SealingKeyRef)
	if ref == "" {
		return nil, fmt.Errorf("mfa.otp.sealing_key_ref is required")
	}
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	value, err := secrets.ResolveConfiguredSecret(ctx, resolver, "mfa.otp.sealing_key_ref", "", ref)
	if err != nil {
		return nil, err
	}
	if len([]byte(value)) < 16 {
		return nil, fmt.Errorf("mfa.otp.sealing_key_ref must resolve to at least 16 bytes")
	}
	return []byte(value), nil
}

func sha256Bytes(input []byte) []byte {
	sum := sha256.Sum256(input)
	return sum[:]
}

func rotateRecoveryCodes(username string, policy Policy) ([]string, error) {
	if !policy.RecoveryEnabled {
		return nil, nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	codes := make([]string, 0, policy.RecoveryCodeCount)
	hashes := make([]string, 0, policy.RecoveryCodeCount)
	for i := 0; i < policy.RecoveryCodeCount; i++ {
		code, err := randomRecoveryCode(policy.RecoveryCodeBytes)
		if err != nil {
			return nil, err
		}
		normalized := normalizeCode(code)
		hash, err := db.HashMFARecoveryCode(normalized)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	expiresAt := ""
	if policy.RecoveryCodeTTL > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(policy.RecoveryCodeTTL) * time.Second).Format(time.RFC3339)
	}
	if err := db.ReplaceMFARecoveryCodes(username, hashes, expiresAt, time.Now().UTC()); err != nil {
		return nil, err
	}
	return codes, nil
}

func randomRecoveryCode(byteCount int) (string, error) {
	if byteCount <= 0 {
		byteCount = 16
	}
	raw := make([]byte, byteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate MFA recovery code: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if len(encoded) > 20 {
		encoded = encoded[:20]
	}
	parts := []string{}
	for len(encoded) > 0 {
		n := 4
		if len(encoded) < n {
			n = len(encoded)
		}
		parts = append(parts, encoded[:n])
		encoded = encoded[n:]
	}
	return strings.Join(parts, "-"), nil
}

func randomBase64URL(byteCount int) (string, error) {
	raw := make([]byte, byteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func otpAuthURL(policy Policy, username, secret string) string {
	issuer := strings.TrimSpace(policy.Issuer)
	label := issuer + ":" + strings.TrimSpace(username)
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", strings.ToUpper(strings.TrimSpace(policy.Algorithm)))
	values.Set("digits", strconv.Itoa(policy.Digits))
	values.Set("period", strconv.Itoa(policy.PeriodSeconds))
	return "otpauth://totp/" + url.PathEscape(label) + "?" + values.Encode()
}

func recordEvent(policy Policy, event db.MFAEvent, details any) {
	if !policy.AuditEnabled || db.DB == nil || strings.TrimSpace(event.UsernameHash) == "" {
		return
	}
	if strings.TrimSpace(event.Source) == "" {
		event.Source = defaultSource
	}
	if strings.TrimSpace(event.Method) == "" {
		event.Method = defaultMethodTOTP
	}
	if strings.TrimSpace(event.ObservedAt) == "" {
		event.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_ = db.RecordMFAEvent(event, details, policy.RetentionLimit)
}

func normalizeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "monitor"
	}
	return mode
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeRealms(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range normalizeList(values) {
		out = append(out, value)
	}
	return out
}

func usernameRealm(username string) string {
	username = strings.TrimSpace(username)
	if at := strings.LastIndex(username, "@"); at >= 0 && at < len(username)-1 {
		return strings.ToLower(username[at+1:])
	}
	return ""
}

func sourceOrDefault(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return defaultSource
	}
	return source
}

func normalizeCode(code string) string {
	replacer := strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "", "\r", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(code)))
}

func addBase32Padding(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	remainder := len(value) % 8
	if remainder == 0 {
		return value
	}
	return value + strings.Repeat("=", 8-remainder)
}
