package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	SchemaVersion = 1

	credentialTypePublicKey = "public-key"
	ceremonyRegistration    = "registration"
	ceremonyAuthentication  = "authentication"
	localStatePrefix        = "aegis-wa1."

	coseAlgES256 = -7
	coseAlgRS256 = -257

	authFlagUP = 0x01
	authFlagUV = 0x04
	authFlagBE = 0x08
	authFlagBS = 0x10
	authFlagAT = 0x40
)

type Policy struct {
	SchemaVersion             int      `json:"schema_version"`
	Enabled                   bool     `json:"enabled"`
	Mode                      string   `json:"mode"`
	FailClosed                bool     `json:"fail_closed"`
	RPIDConfigured            bool     `json:"rp_id_configured"`
	RPID                      string   `json:"rp_id,omitempty"`
	RPName                    string   `json:"rp_name"`
	Origins                   []string `json:"origins"`
	ChallengeTTLSeconds       int      `json:"challenge_ttl_seconds"`
	SessionTTLSeconds         int      `json:"session_ttl_seconds"`
	MaxPending                int      `json:"max_pending"`
	UserVerification          string   `json:"user_verification"`
	Attestation               string   `json:"attestation"`
	ResidentKey               string   `json:"resident_key"`
	RequireForRoles           []string `json:"require_for_roles"`
	RequireForSSO             bool     `json:"require_for_sso"`
	RequireForTokenLogin      bool     `json:"require_for_token_login"`
	BreakGlassAllowed         bool     `json:"break_glass_allowed"`
	AllowBootstrapEnrollment  bool     `json:"allow_bootstrap_enrollment"`
	AuditEnabled              bool     `json:"audit_enabled"`
	RetentionLimit            int      `json:"retention_limit"`
	SupportedAlgorithms       []int    `json:"supported_algorithms"`
	SignatureCounterEnforced  bool     `json:"signature_counter_enforced"`
	AttestationTrustStoreMode string   `json:"attestation_trust_store_mode"`
}

type Summary struct {
	OriginCount        int    `json:"origin_count"`
	RequireRoleCount   int    `json:"require_role_count"`
	AdminSessionTTL    int    `json:"admin_session_ttl_seconds"`
	ChallengeTTL       int    `json:"challenge_ttl_seconds"`
	BrowserAPIRequired bool   `json:"browser_api_required"`
	DatabaseRequired   bool   `json:"database_required"`
	LastRPID           string `json:"last_rp_id,omitempty"`
}

type Report struct {
	SchemaVersion int                               `json:"schema_version"`
	GeneratedAt   string                            `json:"generated_at"`
	Enabled       bool                              `json:"enabled"`
	Status        string                            `json:"status"`
	Message       string                            `json:"message"`
	Policy        Policy                            `json:"policy"`
	Summary       Summary                           `json:"summary"`
	Credentials   db.AdminWebAuthnCredentialSummary `json:"credentials"`
	AuditSummary  db.AdminWebAuthnEventSummary      `json:"audit_summary"`
	Recent        []db.AdminWebAuthnEvent           `json:"recent,omitempty"`
	CredentialsBy []db.AdminWebAuthnCredential      `json:"credentials_by_subject,omitempty"`
}

type RuntimeContext struct {
	Origin string
	RPID   string
}

type PrincipalContext struct {
	Subject        string
	Username       string
	DisplayName    string
	Role           string
	Source         string
	Provider       string
	Tenants        []string
	Groups         []string
	FirstFactor    string
	BreakGlass     bool
	CredentialName string
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type PublicKeyCredentialParameters struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type RelyingPartyEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type AuthenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	RequireResident  bool   `json:"requireResidentKey"`
	UserVerification string `json:"userVerification"`
}

type CreationOptions struct {
	RP                     RelyingPartyEntity              `json:"rp"`
	User                   UserEntity                      `json:"user"`
	Challenge              string                          `json:"challenge"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                int                             `json:"timeout"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection AuthenticatorSelection          `json:"authenticatorSelection"`
	Attestation            string                          `json:"attestation"`
}

type RequestOptions struct {
	Challenge        string                          `json:"challenge"`
	Timeout          int                             `json:"timeout"`
	RPID             string                          `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                          `json:"userVerification"`
}

type RegistrationChallenge struct {
	State     string          `json:"state"`
	ExpiresAt string          `json:"expires_at"`
	PublicKey CreationOptions `json:"publicKey"`
}

type AuthenticationChallenge struct {
	State     string         `json:"state"`
	ExpiresAt string         `json:"expires_at"`
	PublicKey RequestOptions `json:"publicKey"`
}

type RegistrationCredential struct {
	ID       string                         `json:"id"`
	RawID    string                         `json:"rawId"`
	Type     string                         `json:"type"`
	Response RegistrationCredentialResponse `json:"response"`
}

type RegistrationCredentialResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	Transports        []string `json:"transports,omitempty"`
}

type AssertionCredential struct {
	ID       string                      `json:"id"`
	RawID    string                      `json:"rawId"`
	Type     string                      `json:"type"`
	Response AssertionCredentialResponse `json:"response"`
}

type AssertionCredentialResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type RegistrationResult struct {
	Credential db.AdminWebAuthnCredential `json:"credential"`
	Reason     string                     `json:"reason"`
}

type AuthenticationResult struct {
	Allowed          bool      `json:"allowed"`
	Reason           string    `json:"reason"`
	Subject          string    `json:"subject,omitempty"`
	DisplayName      string    `json:"display_name,omitempty"`
	Role             string    `json:"role,omitempty"`
	Source           string    `json:"source,omitempty"`
	Provider         string    `json:"provider,omitempty"`
	Tenants          []string  `json:"tenants,omitempty"`
	Groups           []string  `json:"groups,omitempty"`
	FirstFactor      string    `json:"first_factor,omitempty"`
	CredentialIDHash string    `json:"credential_id_hash,omitempty"`
	SessionExpiresAt time.Time `json:"-"`
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

type parsedAuthenticatorData struct {
	RPIDHash       []byte
	Flags          byte
	SignCount      uint32
	AAGUID         []byte
	CredentialID   []byte
	PublicKeyCOSE  []byte
	BackupEligible bool
	BackupState    bool
}

func PolicyFromConfig(cfg *config.Config) Policy {
	raw := config.AdminWebAuthnConfig{}
	if cfg != nil {
		raw = config.EffectiveAdminWebAuthnConfig(cfg.AdminWebAuthn)
	}
	rpID := strings.TrimSpace(raw.RPID)
	return Policy{
		SchemaVersion:             SchemaVersion,
		Enabled:                   raw.Enabled,
		Mode:                      normalizeMode(raw.Mode),
		FailClosed:                raw.FailClosed,
		RPIDConfigured:            rpID != "",
		RPID:                      rpID,
		RPName:                    strings.TrimSpace(raw.RPName),
		Origins:                   normalizeOrigins(raw.Origins),
		ChallengeTTLSeconds:       raw.ChallengeTTLSeconds,
		SessionTTLSeconds:         raw.SessionTTLSeconds,
		MaxPending:                raw.MaxPending,
		UserVerification:          normalizeWebAuthnChoice(raw.UserVerification, "preferred"),
		Attestation:               normalizeWebAuthnChoice(raw.Attestation, "none"),
		ResidentKey:               normalizeWebAuthnChoice(raw.ResidentKey, "preferred"),
		RequireForRoles:           normalizeList(raw.RequireForRoles),
		RequireForSSO:             raw.RequireForSSO,
		RequireForTokenLogin:      raw.RequireForTokenLogin,
		BreakGlassAllowed:         raw.BreakGlassAllowed,
		AllowBootstrapEnrollment:  raw.AllowBootstrapEnrollment,
		AuditEnabled:              raw.AuditEnabled,
		RetentionLimit:            raw.RetentionLimit,
		SupportedAlgorithms:       []int{coseAlgES256, coseAlgRS256},
		SignatureCounterEnforced:  true,
		AttestationTrustStoreMode: "none",
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
			OriginCount:        len(policy.Origins),
			RequireRoleCount:   len(policy.RequireForRoles),
			AdminSessionTTL:    policy.SessionTTLSeconds,
			ChallengeTTL:       policy.ChallengeTTLSeconds,
			BrowserAPIRequired: true,
			DatabaseRequired:   true,
			LastRPID:           policy.RPID,
		},
	}
	if db.DB != nil {
		if summary, err := db.GetAdminWebAuthnCredentialSummary(now); err == nil {
			report.Credentials = summary
		}
		if audit, err := db.GetAdminWebAuthnEventSummary(); err == nil {
			report.AuditSummary = audit
		}
		if recent, err := db.ListAdminWebAuthnEvents("", "", 25); err == nil {
			report.Recent = recent
		}
	}
	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "Admin passkey MFA is disabled; admin session behavior is unchanged."
	case db.DB == nil:
		report.Status = "blocked"
		report.Message = "Admin passkey MFA requires database-backed challenges, credentials, and audit events."
	case policy.RPID == "":
		report.Status = "blocked"
		report.Message = "Admin passkey MFA needs an explicit relying-party ID for production enforcement."
	case len(policy.Origins) == 0:
		report.Status = "blocked"
		report.Message = "Admin passkey MFA needs at least one configured HTTPS origin for production enforcement."
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "Admin passkey MFA is in monitor mode; step-up decisions are audited but not enforced."
	case !policy.FailClosed:
		report.Status = "degraded"
		report.Message = "Admin passkey MFA enforcement is active but fail_closed is disabled."
	case policy.BreakGlassAllowed:
		report.Status = "degraded"
		report.Message = "Admin passkey MFA allows break-glass bearer tokens; keep this only for governed recovery."
	case report.Credentials.EnabledCredentials == 0:
		report.Status = "blocked"
		report.Message = "Admin passkey MFA enforcement is configured but no passkey credentials are enrolled."
	default:
		report.Message = "Admin passkey MFA is enforceable with bounded challenges, verified assertions, short-lived sessions, and audit evidence."
	}
	return report
}

func RequiredFor(policy Policy, principal PrincipalContext) bool {
	if !policy.Enabled {
		return false
	}
	if principal.BreakGlass && policy.BreakGlassAllowed {
		return false
	}
	firstFactor := strings.ToLower(strings.TrimSpace(principal.FirstFactor))
	if firstFactor == "sso" && !policy.RequireForSSO {
		return false
	}
	if firstFactor == "token" && !policy.RequireForTokenLogin {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(principal.Role))
	for _, required := range policy.RequireForRoles {
		if strings.EqualFold(required, role) {
			return true
		}
	}
	return false
}

func ResolveRuntimeContext(cfg *config.Config, originHint, hostHint string) (RuntimeContext, error) {
	policy := PolicyFromConfig(cfg)
	origin := strings.TrimSpace(originHint)
	if origin == "" {
		origin = "http://" + strings.TrimSpace(hostHint)
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return RuntimeContext{}, fmt.Errorf("invalid WebAuthn origin %q", origin)
	}
	origin = parsed.Scheme + "://" + parsed.Host
	if len(policy.Origins) > 0 && !originAllowed(origin, policy.Origins) {
		return RuntimeContext{}, fmt.Errorf("origin %q is not allowed for admin WebAuthn", origin)
	}
	host := strings.ToLower(parsed.Hostname())
	rpID := strings.ToLower(strings.TrimSpace(policy.RPID))
	if rpID == "" {
		rpID = host
	}
	if !rpIDMatchesOrigin(rpID, host) {
		return RuntimeContext{}, fmt.Errorf("rp_id %q is not valid for origin host %q", rpID, host)
	}
	return RuntimeContext{Origin: origin, RPID: rpID}, nil
}

func BeginRegistration(cfg *config.Config, runtime RuntimeContext, principal PrincipalContext) (RegistrationChallenge, error) {
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled {
		return RegistrationChallenge{}, fmt.Errorf("admin WebAuthn is not enabled")
	}
	if db.DB == nil {
		return RegistrationChallenge{}, fmt.Errorf("database not initialized")
	}
	now := time.Now().UTC()
	if summary, err := db.GetAdminWebAuthnCredentialSummary(now); err == nil && policy.MaxPending > 0 && summary.PendingChallenges >= policy.MaxPending {
		return RegistrationChallenge{}, fmt.Errorf("maximum pending admin WebAuthn challenges reached")
	}
	subject := strings.TrimSpace(firstNonEmpty(principal.Subject, principal.Username))
	if subject == "" {
		return RegistrationChallenge{}, fmt.Errorf("subject is required")
	}
	username := strings.TrimSpace(firstNonEmpty(principal.Username, subject))
	displayName := strings.TrimSpace(firstNonEmpty(principal.DisplayName, subject))
	challenge, err := randomBase64URL(32)
	if err != nil {
		return RegistrationChallenge{}, err
	}
	state, err := randomState()
	if err != nil {
		return RegistrationChallenge{}, err
	}
	id, err := randomID("wac_")
	if err != nil {
		return RegistrationChallenge{}, err
	}
	expiresAt := now.Add(time.Duration(policy.ChallengeTTLSeconds) * time.Second)
	existing, _ := db.ListAdminWebAuthnCredentials(subject, false, 1000)
	exclude := make([]PublicKeyCredentialDescriptor, 0, len(existing))
	for _, item := range existing {
		exclude = append(exclude, PublicKeyCredentialDescriptor{Type: credentialTypePublicKey, ID: item.CredentialIDB64, Transports: item.Transports})
	}
	userID := sha256.Sum256([]byte(strings.ToLower(username)))
	options := CreationOptions{
		RP: RelyingPartyEntity{ID: runtime.RPID, Name: policy.RPName},
		User: UserEntity{
			ID:          base64.RawURLEncoding.EncodeToString(userID[:]),
			Name:        username,
			DisplayName: displayName,
		},
		Challenge:          challenge,
		PubKeyCredParams:   []PublicKeyCredentialParameters{{Type: credentialTypePublicKey, Alg: coseAlgES256}, {Type: credentialTypePublicKey, Alg: coseAlgRS256}},
		Timeout:            policy.ChallengeTTLSeconds * 1000,
		ExcludeCredentials: exclude,
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:      policy.ResidentKey,
			RequireResident:  policy.ResidentKey == "required",
			UserVerification: policy.UserVerification,
		},
		Attestation: policy.Attestation,
	}
	record := db.AdminWebAuthnChallenge{
		ID:             id,
		StateHash:      db.HashAdminWebAuthnState(state),
		Challenge:      challenge,
		ChallengeHash:  db.HashAdminWebAuthnChallenge(challenge),
		Ceremony:       ceremonyRegistration,
		Status:         "pending",
		UsernameHash:   db.HashIdentityUsername(username),
		Subject:        subject,
		DisplayName:    displayName,
		CredentialName: strings.TrimSpace(principal.CredentialName),
		Role:           strings.TrimSpace(principal.Role),
		Source:         sourceOrDefault(principal.Source),
		Provider:       strings.TrimSpace(principal.Provider),
		Tenants:        principal.Tenants,
		Groups:         principal.Groups,
		FirstFactor:    strings.TrimSpace(principal.FirstFactor),
		Origin:         runtime.Origin,
		RPID:           runtime.RPID,
		MaxAttempts:    5,
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		CreatedAt:      now.Format(time.RFC3339),
	}
	if err := db.InsertAdminWebAuthnChallenge(record, map[string]any{"schema_version": SchemaVersion}); err != nil {
		return RegistrationChallenge{}, err
	}
	recordEvent(policy, db.AdminWebAuthnEvent{
		ObservedAt:   now.Format(time.RFC3339),
		UsernameHash: record.UsernameHash,
		Subject:      subject,
		Source:       record.Source,
		Ceremony:     ceremonyRegistration,
		Decision:     "challenge_issued",
		Reason:       "admin passkey registration challenge issued",
		Role:         record.Role,
		Provider:     record.Provider,
		Origin:       runtime.Origin,
		RPID:         runtime.RPID,
	}, nil)
	return RegistrationChallenge{State: state, ExpiresAt: record.ExpiresAt, PublicKey: options}, nil
}

func FinishRegistration(cfg *config.Config, state string, credential RegistrationCredential, observedOrigin string) (RegistrationResult, error) {
	policy := PolicyFromConfig(cfg)
	now := time.Now().UTC()
	challenge, ok, err := loadPendingChallenge(state, ceremonyRegistration, now)
	if err != nil {
		return RegistrationResult{}, err
	}
	if !ok {
		return RegistrationResult{}, fmt.Errorf("registration challenge not found")
	}
	eventBase := db.AdminWebAuthnEvent{
		ObservedAt:   now.Format(time.RFC3339),
		UsernameHash: challenge.UsernameHash,
		Subject:      challenge.Subject,
		Source:       sourceOrDefault(challenge.Source),
		Ceremony:     ceremonyRegistration,
		Role:         challenge.Role,
		Provider:     challenge.Provider,
		Origin:       challenge.Origin,
		RPID:         challenge.RPID,
	}
	fail := func(reason string) (RegistrationResult, error) {
		_ = db.UpdateAdminWebAuthnChallengeStatus(challenge.ID, "failed", challenge.AttemptCount+1, reason, now)
		eventBase.Decision = "denied"
		eventBase.Reason = reason
		recordEvent(policy, eventBase, nil)
		return RegistrationResult{}, fmt.Errorf("%s", reason)
	}
	if !sameOrigin(challenge.Origin, observedOrigin) {
		return fail("origin mismatch")
	}
	rawID, err := decodeBase64URL(firstNonEmpty(credential.RawID, credential.ID))
	if err != nil || len(rawID) == 0 {
		return fail("credential rawId is invalid")
	}
	clientDataJSON, err := decodeBase64URL(credential.Response.ClientDataJSON)
	if err != nil {
		return fail("clientDataJSON is invalid")
	}
	if err := verifyClientData(clientDataJSON, "webauthn.create", challenge.Challenge, challenge.Origin); err != nil {
		return fail(err.Error())
	}
	attestationObject, err := decodeBase64URL(credential.Response.AttestationObject)
	if err != nil {
		return fail("attestationObject is invalid")
	}
	att, err := parseAttestationObject(attestationObject)
	if err != nil {
		return fail(err.Error())
	}
	if !bytes.Equal(att.authData.RPIDHash, rpIDHash(challenge.RPID)) {
		return fail("rp_id hash mismatch")
	}
	if att.authData.Flags&authFlagUP == 0 {
		return fail("user presence flag is missing")
	}
	if policy.UserVerification == "required" && att.authData.Flags&authFlagUV == 0 {
		return fail("user verification flag is required")
	}
	if !bytes.Equal(rawID, att.authData.CredentialID) {
		return fail("credential id mismatch")
	}
	alg, err := coseAlgorithm(att.authData.PublicKeyCOSE)
	if err != nil {
		return fail(err.Error())
	}
	if alg != coseAlgES256 && alg != coseAlgRS256 {
		return fail("unsupported credential public-key algorithm")
	}
	credentialHash := db.HashAdminWebAuthnCredentialID(rawID)
	eventBase.CredentialIDHash = credentialHash
	record := db.AdminWebAuthnCredential{
		ID:                   stableCredentialRecordID(credentialHash),
		CredentialIDHash:     credentialHash,
		CredentialIDB64:      base64.RawURLEncoding.EncodeToString(rawID),
		UsernameHash:         challenge.UsernameHash,
		Subject:              challenge.Subject,
		DisplayName:          challenge.DisplayName,
		CredentialName:       firstNonEmpty(challenge.CredentialName, "Admin passkey"),
		PublicKeyCOSEB64:     base64.RawURLEncoding.EncodeToString(att.authData.PublicKeyCOSE),
		PublicKeyAlg:         alg,
		SignCount:            att.authData.SignCount,
		Transports:           normalizeList(credential.Response.Transports),
		AAGUID:               hex.EncodeToString(att.authData.AAGUID),
		AttestationFormat:    att.format,
		UserVerifiedRequired: policy.UserVerification == "required",
		BackupEligible:       att.authData.BackupEligible,
		BackupState:          att.authData.BackupState,
		Enabled:              true,
	}
	if err := db.UpsertAdminWebAuthnCredential(record, now); err != nil {
		return RegistrationResult{}, err
	}
	if err := db.UpdateAdminWebAuthnChallengeStatus(challenge.ID, "verified", challenge.AttemptCount+1, "", now); err != nil {
		return RegistrationResult{}, err
	}
	eventBase.Decision = "registered"
	eventBase.Reason = "admin passkey credential registered"
	recordEvent(policy, eventBase, map[string]any{"algorithm": alg, "transports": record.Transports, "attestation_format": att.format})
	return RegistrationResult{Credential: record, Reason: eventBase.Reason}, nil
}

func BeginAuthentication(cfg *config.Config, runtime RuntimeContext, principal PrincipalContext) (AuthenticationChallenge, error) {
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled {
		return AuthenticationChallenge{}, fmt.Errorf("admin WebAuthn is not enabled")
	}
	if db.DB == nil {
		return AuthenticationChallenge{}, fmt.Errorf("database not initialized")
	}
	now := time.Now().UTC()
	if summary, err := db.GetAdminWebAuthnCredentialSummary(now); err == nil && policy.MaxPending > 0 && summary.PendingChallenges >= policy.MaxPending {
		return AuthenticationChallenge{}, fmt.Errorf("maximum pending admin WebAuthn challenges reached")
	}
	subject := strings.TrimSpace(firstNonEmpty(principal.Subject, principal.Username))
	if subject == "" {
		return AuthenticationChallenge{}, fmt.Errorf("subject is required")
	}
	username := strings.TrimSpace(firstNonEmpty(principal.Username, subject))
	credentials, err := db.ListAdminWebAuthnCredentials(subject, false, 1000)
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	if len(credentials) == 0 {
		return AuthenticationChallenge{}, fmt.Errorf("no passkey credentials are enrolled for this admin")
	}
	challenge, err := randomBase64URL(32)
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	state, err := randomState()
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	id, err := randomID("waa_")
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	expiresAt := now.Add(time.Duration(policy.ChallengeTTLSeconds) * time.Second)
	allow := make([]PublicKeyCredentialDescriptor, 0, len(credentials))
	for _, item := range credentials {
		allow = append(allow, PublicKeyCredentialDescriptor{Type: credentialTypePublicKey, ID: item.CredentialIDB64, Transports: item.Transports})
	}
	options := RequestOptions{
		Challenge:        challenge,
		Timeout:          policy.ChallengeTTLSeconds * 1000,
		RPID:             runtime.RPID,
		AllowCredentials: allow,
		UserVerification: policy.UserVerification,
	}
	record := db.AdminWebAuthnChallenge{
		ID:            id,
		StateHash:     db.HashAdminWebAuthnState(state),
		Challenge:     challenge,
		ChallengeHash: db.HashAdminWebAuthnChallenge(challenge),
		Ceremony:      ceremonyAuthentication,
		Status:        "pending",
		UsernameHash:  db.HashIdentityUsername(username),
		Subject:       subject,
		DisplayName:   strings.TrimSpace(principal.DisplayName),
		Role:          strings.TrimSpace(principal.Role),
		Source:        sourceOrDefault(principal.Source),
		Provider:      strings.TrimSpace(principal.Provider),
		Tenants:       principal.Tenants,
		Groups:        principal.Groups,
		FirstFactor:   strings.TrimSpace(principal.FirstFactor),
		Origin:        runtime.Origin,
		RPID:          runtime.RPID,
		MaxAttempts:   5,
		ExpiresAt:     expiresAt.Format(time.RFC3339),
		CreatedAt:     now.Format(time.RFC3339),
	}
	if err := db.InsertAdminWebAuthnChallenge(record, map[string]any{"schema_version": SchemaVersion}); err != nil {
		return AuthenticationChallenge{}, err
	}
	recordEvent(policy, db.AdminWebAuthnEvent{
		ObservedAt:   now.Format(time.RFC3339),
		UsernameHash: record.UsernameHash,
		Subject:      subject,
		Source:       record.Source,
		Ceremony:     ceremonyAuthentication,
		Decision:     "challenge_issued",
		Reason:       "admin passkey authentication challenge issued",
		Role:         record.Role,
		Provider:     record.Provider,
		Origin:       runtime.Origin,
		RPID:         runtime.RPID,
	}, nil)
	return AuthenticationChallenge{State: state, ExpiresAt: record.ExpiresAt, PublicKey: options}, nil
}

func AuthenticationChallengeForState(cfg *config.Config, state string) (AuthenticationChallenge, error) {
	policy := PolicyFromConfig(cfg)
	now := time.Now().UTC()
	challenge, ok, err := loadPendingChallenge(state, ceremonyAuthentication, now)
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	if !ok {
		return AuthenticationChallenge{}, fmt.Errorf("authentication challenge not found")
	}
	credentials, err := db.ListAdminWebAuthnCredentials(challenge.Subject, false, 1000)
	if err != nil {
		return AuthenticationChallenge{}, err
	}
	if len(credentials) == 0 {
		return AuthenticationChallenge{}, fmt.Errorf("no passkey credentials are enrolled for this admin")
	}
	allow := make([]PublicKeyCredentialDescriptor, 0, len(credentials))
	for _, item := range credentials {
		allow = append(allow, PublicKeyCredentialDescriptor{Type: credentialTypePublicKey, ID: item.CredentialIDB64, Transports: item.Transports})
	}
	return AuthenticationChallenge{
		State:     state,
		ExpiresAt: challenge.ExpiresAt,
		PublicKey: RequestOptions{
			Challenge:        challenge.Challenge,
			Timeout:          policy.ChallengeTTLSeconds * 1000,
			RPID:             challenge.RPID,
			AllowCredentials: allow,
			UserVerification: policy.UserVerification,
		},
	}, nil
}

func FinishAuthentication(cfg *config.Config, state string, credential AssertionCredential, observedOrigin string) (AuthenticationResult, error) {
	policy := PolicyFromConfig(cfg)
	now := time.Now().UTC()
	challenge, ok, err := loadPendingChallenge(state, ceremonyAuthentication, now)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if !ok {
		return AuthenticationResult{Allowed: false, Reason: "authentication challenge not found"}, nil
	}
	eventBase := db.AdminWebAuthnEvent{
		ObservedAt:   now.Format(time.RFC3339),
		UsernameHash: challenge.UsernameHash,
		Subject:      challenge.Subject,
		Source:       sourceOrDefault(challenge.Source),
		Ceremony:     ceremonyAuthentication,
		Role:         challenge.Role,
		Provider:     challenge.Provider,
		Origin:       challenge.Origin,
		RPID:         challenge.RPID,
	}
	deny := func(reason string) (AuthenticationResult, error) {
		attempts := challenge.AttemptCount + 1
		status := "pending"
		if attempts >= challenge.MaxAttempts {
			status = "failed"
		}
		_ = db.UpdateAdminWebAuthnChallengeStatus(challenge.ID, status, attempts, reason, now)
		eventBase.Decision = "denied"
		eventBase.Reason = reason
		recordEvent(policy, eventBase, map[string]any{"attempt_count": attempts, "status": status})
		return AuthenticationResult{Allowed: false, Reason: reason}, nil
	}
	if !sameOrigin(challenge.Origin, observedOrigin) {
		return deny("origin mismatch")
	}
	rawID, err := decodeBase64URL(firstNonEmpty(credential.RawID, credential.ID))
	if err != nil || len(rawID) == 0 {
		return deny("credential rawId is invalid")
	}
	credentialHash := db.HashAdminWebAuthnCredentialID(rawID)
	eventBase.CredentialIDHash = credentialHash
	stored, found, err := db.GetAdminWebAuthnCredentialByHash(credentialHash)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if !found || !stored.Enabled || stored.RevokedAt != "" {
		return deny("credential is not enrolled or is revoked")
	}
	if stored.UsernameHash != challenge.UsernameHash || stored.Subject != challenge.Subject {
		return deny("credential subject mismatch")
	}
	clientDataJSON, err := decodeBase64URL(credential.Response.ClientDataJSON)
	if err != nil {
		return deny("clientDataJSON is invalid")
	}
	if err := verifyClientData(clientDataJSON, "webauthn.get", challenge.Challenge, challenge.Origin); err != nil {
		return deny(err.Error())
	}
	authDataBytes, err := decodeBase64URL(credential.Response.AuthenticatorData)
	if err != nil {
		return deny("authenticatorData is invalid")
	}
	authData, err := parseAssertionAuthenticatorData(authDataBytes)
	if err != nil {
		return deny(err.Error())
	}
	if !bytes.Equal(authData.RPIDHash, rpIDHash(challenge.RPID)) {
		return deny("rp_id hash mismatch")
	}
	if authData.Flags&authFlagUP == 0 {
		return deny("user presence flag is missing")
	}
	if policy.UserVerification == "required" && authData.Flags&authFlagUV == 0 {
		return deny("user verification flag is required")
	}
	signature, err := decodeBase64URL(credential.Response.Signature)
	if err != nil {
		return deny("signature is invalid")
	}
	publicKeyCOSE, err := decodeBase64URL(stored.PublicKeyCOSEB64)
	if err != nil {
		return AuthenticationResult{}, fmt.Errorf("stored credential public key is invalid")
	}
	if err := verifyAssertionSignature(publicKeyCOSE, authDataBytes, clientDataJSON, signature); err != nil {
		return deny(err.Error())
	}
	if stored.SignCount > 0 && authData.SignCount > 0 && authData.SignCount <= stored.SignCount {
		return deny("signature counter replay detected")
	}
	if err := db.TouchAdminWebAuthnCredentialUse(credentialHash, authData.SignCount, authData.BackupState, now); err != nil {
		return AuthenticationResult{}, err
	}
	if err := db.UpdateAdminWebAuthnChallengeStatus(challenge.ID, "verified", challenge.AttemptCount+1, "", now); err != nil {
		return AuthenticationResult{}, err
	}
	eventBase.Decision = "accepted"
	eventBase.Reason = "admin passkey assertion verified"
	recordEvent(policy, eventBase, map[string]any{"sign_count": authData.SignCount, "backup_state": authData.BackupState})
	return AuthenticationResult{
		Allowed:          true,
		Reason:           eventBase.Reason,
		Subject:          challenge.Subject,
		DisplayName:      challenge.DisplayName,
		Role:             challenge.Role,
		Source:           firstNonEmpty(challenge.Source, "webauthn"),
		Provider:         challenge.Provider,
		Tenants:          challenge.Tenants,
		Groups:           challenge.Groups,
		FirstFactor:      challenge.FirstFactor,
		CredentialIDHash: credentialHash,
		SessionExpiresAt: now.Add(time.Duration(policy.SessionTTLSeconds) * time.Second),
	}, nil
}

func RecordMonitorAllowed(cfg *config.Config, principal PrincipalContext, runtime RuntimeContext, reason string) {
	policy := PolicyFromConfig(cfg)
	recordEvent(policy, db.AdminWebAuthnEvent{
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		UsernameHash: db.HashIdentityUsername(firstNonEmpty(principal.Username, principal.Subject)),
		Subject:      principal.Subject,
		Source:       sourceOrDefault(principal.Source),
		Ceremony:     ceremonyAuthentication,
		Decision:     "monitor_allowed",
		Reason:       strings.TrimSpace(reason),
		Role:         principal.Role,
		Provider:     principal.Provider,
		Origin:       runtime.Origin,
		RPID:         runtime.RPID,
	}, nil)
}

func loadPendingChallenge(state, ceremony string, now time.Time) (db.AdminWebAuthnChallenge, bool, error) {
	if !strings.HasPrefix(strings.TrimSpace(state), localStatePrefix) {
		return db.AdminWebAuthnChallenge{}, false, nil
	}
	challenge, ok, err := db.GetAdminWebAuthnChallengeByStateHash(db.HashAdminWebAuthnState(state), now)
	if err != nil || !ok {
		return challenge, ok, err
	}
	if challenge.Ceremony != ceremony {
		return db.AdminWebAuthnChallenge{}, false, fmt.Errorf("challenge ceremony mismatch")
	}
	if challenge.Status != "pending" {
		return db.AdminWebAuthnChallenge{}, false, fmt.Errorf("challenge is not pending")
	}
	return challenge, true, nil
}

type attestationParseResult struct {
	format   string
	authData parsedAuthenticatorData
}

func parseAttestationObject(raw []byte) (attestationParseResult, error) {
	var obj map[string]any
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return attestationParseResult{}, fmt.Errorf("decode attestationObject: %w", err)
	}
	format, _ := obj["fmt"].(string)
	authDataBytes, ok := obj["authData"].([]byte)
	if !ok || len(authDataBytes) == 0 {
		return attestationParseResult{}, errors.New("attestationObject missing authData")
	}
	authData, err := parseAttestedAuthenticatorData(authDataBytes)
	if err != nil {
		return attestationParseResult{}, err
	}
	return attestationParseResult{format: strings.TrimSpace(format), authData: authData}, nil
}

func parseAttestedAuthenticatorData(raw []byte) (parsedAuthenticatorData, error) {
	base, rest, err := parseAuthenticatorDataBase(raw)
	if err != nil {
		return parsedAuthenticatorData{}, err
	}
	if base.Flags&authFlagAT == 0 {
		return parsedAuthenticatorData{}, errors.New("attested credential data is missing")
	}
	if len(rest) < 18 {
		return parsedAuthenticatorData{}, errors.New("attested credential data is truncated")
	}
	base.AAGUID = append([]byte(nil), rest[:16]...)
	credentialIDLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if credentialIDLen <= 0 || len(rest) < credentialIDLen {
		return parsedAuthenticatorData{}, errors.New("credential id is truncated")
	}
	base.CredentialID = append([]byte(nil), rest[:credentialIDLen]...)
	base.PublicKeyCOSE = append([]byte(nil), rest[credentialIDLen:]...)
	if len(base.PublicKeyCOSE) == 0 {
		return parsedAuthenticatorData{}, errors.New("credential public key is missing")
	}
	return base, nil
}

func parseAssertionAuthenticatorData(raw []byte) (parsedAuthenticatorData, error) {
	base, _, err := parseAuthenticatorDataBase(raw)
	return base, err
}

func parseAuthenticatorDataBase(raw []byte) (parsedAuthenticatorData, []byte, error) {
	if len(raw) < 37 {
		return parsedAuthenticatorData{}, nil, errors.New("authenticator data is truncated")
	}
	flags := raw[32]
	return parsedAuthenticatorData{
		RPIDHash:       append([]byte(nil), raw[:32]...),
		Flags:          flags,
		SignCount:      binary.BigEndian.Uint32(raw[33:37]),
		BackupEligible: flags&authFlagBE != 0,
		BackupState:    flags&authFlagBS != 0,
	}, raw[37:], nil
}

func verifyClientData(raw []byte, expectedType, expectedChallenge, expectedOrigin string) error {
	var data clientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("decode clientDataJSON: %w", err)
	}
	if data.Type != expectedType {
		return fmt.Errorf("clientDataJSON type %q is invalid", data.Type)
	}
	if subtle.ConstantTimeCompare([]byte(data.Challenge), []byte(expectedChallenge)) != 1 {
		return errors.New("challenge mismatch")
	}
	if !sameOrigin(expectedOrigin, data.Origin) {
		return errors.New("clientDataJSON origin mismatch")
	}
	if data.CrossOrigin {
		return errors.New("cross-origin WebAuthn response is not accepted")
	}
	return nil
}

func coseAlgorithm(coseKey []byte) (int, error) {
	var key map[any]any
	if err := cbor.Unmarshal(coseKey, &key); err != nil {
		return 0, fmt.Errorf("decode COSE public key: %w", err)
	}
	alg, ok := intFromMap(key, 3)
	if !ok {
		return 0, errors.New("COSE public key is missing alg")
	}
	return alg, nil
}

func verifyAssertionSignature(coseKey, authenticatorData, clientDataJSON, signature []byte) error {
	publicKey, alg, err := publicKeyFromCOSE(coseKey)
	if err != nil {
		return err
	}
	clientHash := sha256.Sum256(clientDataJSON)
	message := append(append([]byte{}, authenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(message)
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if alg != coseAlgES256 {
			return errors.New("credential algorithm does not match EC public key")
		}
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return errors.New("signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		if alg != coseAlgRS256 {
			return errors.New("credential algorithm does not match RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return errors.New("signature verification failed")
		}
		return nil
	default:
		return errors.New("unsupported credential public key type")
	}
}

func publicKeyFromCOSE(coseKey []byte) (any, int, error) {
	var key map[any]any
	if err := cbor.Unmarshal(coseKey, &key); err != nil {
		return nil, 0, fmt.Errorf("decode COSE public key: %w", err)
	}
	kty, ok := intFromMap(key, 1)
	if !ok {
		return nil, 0, errors.New("COSE public key is missing kty")
	}
	alg, ok := intFromMap(key, 3)
	if !ok {
		return nil, 0, errors.New("COSE public key is missing alg")
	}
	switch kty {
	case 2:
		crv, ok := intFromMap(key, -1)
		if !ok || crv != 1 {
			return nil, 0, errors.New("only P-256 EC2 WebAuthn keys are supported")
		}
		x, ok := bytesFromMap(key, -2)
		if !ok {
			return nil, 0, errors.New("EC2 public key x coordinate is missing")
		}
		y, ok := bytesFromMap(key, -3)
		if !ok {
			return nil, 0, errors.New("EC2 public key y coordinate is missing")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, 0, errors.New("EC2 public key is not on P-256")
		}
		return pub, alg, nil
	case 3:
		nBytes, ok := bytesFromMap(key, -1)
		if !ok {
			return nil, 0, errors.New("RSA modulus is missing")
		}
		eBytes, ok := bytesFromMap(key, -2)
		if !ok {
			return nil, 0, errors.New("RSA exponent is missing")
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if e < 3 {
			return nil, 0, errors.New("RSA exponent is invalid")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, alg, nil
	default:
		return nil, 0, errors.New("unsupported COSE public-key type")
	}
}

func intFromMap(values map[any]any, key int) (int, bool) {
	value, ok := mapValueForIntKey(values, key)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case uint64:
		return int(typed), true
	case uint:
		return int(typed), true
	default:
		return 0, false
	}
}

func bytesFromMap(values map[any]any, key int) ([]byte, bool) {
	value, ok := mapValueForIntKey(values, key)
	if !ok {
		return nil, false
	}
	raw, ok := value.([]byte)
	return raw, ok
}

func mapValueForIntKey(values map[any]any, key int) (any, bool) {
	for candidate, value := range values {
		switch typed := candidate.(type) {
		case int:
			if typed == key {
				return value, true
			}
		case int64:
			if int(typed) == key {
				return value, true
			}
		case uint64:
			if typed == uint64(key) {
				return value, true
			}
		case uint:
			if int(typed) == key {
				return value, true
			}
		}
	}
	return nil, false
}

func randomState() (string, error) {
	token, err := randomBase64URL(32)
	if err != nil {
		return "", err
	}
	return localStatePrefix + token, nil
}

func randomID(prefix string) (string, error) {
	token, err := randomBase64URL(18)
	if err != nil {
		return "", err
	}
	return prefix + token, nil
}

func randomBase64URL(length int) (string, error) {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func decodeBase64URL(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty base64url value")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func rpIDHash(rpID string) []byte {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(rpID))))
	return sum[:]
}

func rpIDMatchesOrigin(rpID, host string) bool {
	rpID = strings.ToLower(strings.TrimSpace(rpID))
	host = strings.ToLower(strings.TrimSpace(host))
	if rpID == "" || host == "" {
		return false
	}
	if host == rpID || strings.HasSuffix(host, "."+rpID) {
		return true
	}
	if net.ParseIP(host) != nil && host == rpID {
		return true
	}
	return false
}

func originAllowed(origin string, allowed []string) bool {
	for _, candidate := range allowed {
		if sameOrigin(candidate, origin) {
			return true
		}
	}
	return false
}

func sameOrigin(a, b string) bool {
	pa, errA := url.Parse(strings.TrimSpace(a))
	pb, errB := url.Parse(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(pa.Scheme, pb.Scheme) && strings.EqualFold(pa.Host, pb.Host)
}

func stableCredentialRecordID(credentialHash string) string {
	credentialHash = strings.TrimPrefix(strings.TrimSpace(credentialHash), "sha256:")
	if len(credentialHash) > 24 {
		credentialHash = credentialHash[:24]
	}
	return "wac_" + credentialHash
}

func normalizeMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func normalizeWebAuthnChoice(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func normalizeOrigins(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeList(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func sourceOrDefault(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "admin-api"
	}
	return source
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func recordEvent(policy Policy, event db.AdminWebAuthnEvent, details any) {
	if !policy.AuditEnabled || db.DB == nil {
		return
	}
	_ = db.RecordAdminWebAuthnEvent(event, details, policy.RetentionLimit)
}
