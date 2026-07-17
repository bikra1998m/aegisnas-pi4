package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestWebAuthnRegistrationAndAuthentication(t *testing.T) {
	cfg := prepareWebAuthnTestConfig(t)
	runtime := RuntimeContext{Origin: "https://admin.example.com", RPID: "admin.example.com"}
	principal := PrincipalContext{
		Subject:     "oidc:alice@example.com",
		Username:    "alice@example.com",
		DisplayName: "Alice Admin",
		Role:        "super_admin",
		Source:      "sso",
		Provider:    "oidc",
		FirstFactor: "sso",
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credentialID := []byte("credential-0001")

	registration, err := BeginRegistration(cfg, runtime, principal)
	require.NoError(t, err)
	registrationCredential := buildTestRegistrationCredential(t, privateKey, credentialID, registration.PublicKey.Challenge, runtime)
	registered, err := FinishRegistration(cfg, registration.State, registrationCredential, runtime.Origin)
	require.NoError(t, err)
	assert.Equal(t, "oidc:alice@example.com", registered.Credential.Subject)
	assert.Equal(t, coseAlgES256, registered.Credential.PublicKeyAlg)

	authentication, err := BeginAuthentication(cfg, runtime, principal)
	require.NoError(t, err)
	assert.Len(t, authentication.PublicKey.AllowCredentials, 1)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(credentialID), authentication.PublicKey.AllowCredentials[0].ID)

	assertion := buildTestAssertionCredential(t, privateKey, credentialID, authentication.PublicKey.Challenge, runtime, 2)
	result, err := FinishAuthentication(cfg, authentication.State, assertion, runtime.Origin)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "oidc:alice@example.com", result.Subject)
	assert.Equal(t, "super_admin", result.Role)
	assert.Equal(t, db.HashAdminWebAuthnCredentialID(credentialID), result.CredentialIDHash)
}

func TestWebAuthnRejectsReplayCounter(t *testing.T) {
	cfg := prepareWebAuthnTestConfig(t)
	runtime := RuntimeContext{Origin: "https://admin.example.com", RPID: "admin.example.com"}
	principal := PrincipalContext{Subject: "oidc:bob@example.com", Username: "bob@example.com", Role: "super_admin", FirstFactor: "sso"}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credentialID := []byte("credential-0002")

	registration, err := BeginRegistration(cfg, runtime, principal)
	require.NoError(t, err)
	_, err = FinishRegistration(cfg, registration.State, buildTestRegistrationCredential(t, privateKey, credentialID, registration.PublicKey.Challenge, runtime), runtime.Origin)
	require.NoError(t, err)

	first, err := BeginAuthentication(cfg, runtime, principal)
	require.NoError(t, err)
	allowed, err := FinishAuthentication(cfg, first.State, buildTestAssertionCredential(t, privateKey, credentialID, first.PublicKey.Challenge, runtime, 2), runtime.Origin)
	require.NoError(t, err)
	require.True(t, allowed.Allowed)

	replay, err := BeginAuthentication(cfg, runtime, principal)
	require.NoError(t, err)
	denied, err := FinishAuthentication(cfg, replay.State, buildTestAssertionCredential(t, privateKey, credentialID, replay.PublicKey.Challenge, runtime, 2), runtime.Origin)
	require.NoError(t, err)
	assert.False(t, denied.Allowed)
	assert.Contains(t, denied.Reason, "replay")
}

func prepareWebAuthnTestConfig(t *testing.T) *config.Config {
	t.Helper()
	tmpdb, err := os.CreateTemp("", "webauthn-*.db")
	require.NoError(t, err)
	dbPath := tmpdb.Name()
	require.NoError(t, tmpdb.Close())
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
	cfg := &config.Config{
		AdminWebAuthn: config.AdminWebAuthnConfig{
			Enabled:              true,
			Mode:                 "enforce",
			FailClosed:           true,
			RPID:                 "admin.example.com",
			RPName:               "AegisNAS Admin",
			Origins:              []string{"https://admin.example.com"},
			ChallengeTTLSeconds:  300,
			SessionTTLSeconds:    28800,
			MaxPending:           10000,
			UserVerification:     "required",
			Attestation:          "none",
			ResidentKey:          "preferred",
			RequireForRoles:      []string{"super_admin"},
			RequireForSSO:        true,
			RequireForTokenLogin: true,
			BreakGlassAllowed:    false,
			AuditEnabled:         true,
			RetentionLimit:       6000,
		},
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	})
	return cfg
}

func buildTestRegistrationCredential(t *testing.T, privateKey *ecdsa.PrivateKey, credentialID []byte, challenge string, runtime RuntimeContext) RegistrationCredential {
	t.Helper()
	coseKey := buildTestCOSEKey(t, privateKey)
	authData := buildTestAttestedAuthData(t, runtime.RPID, credentialID, coseKey, 1)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"authData": authData,
		"attStmt":  map[string]any{},
	})
	require.NoError(t, err)
	clientData := buildTestClientData(t, "webauthn.create", challenge, runtime.Origin)
	return RegistrationCredential{
		ID:    base64.RawURLEncoding.EncodeToString(credentialID),
		RawID: base64.RawURLEncoding.EncodeToString(credentialID),
		Type:  credentialTypePublicKey,
		Response: RegistrationCredentialResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
			AttestationObject: base64.RawURLEncoding.EncodeToString(attestationObject),
			Transports:        []string{"internal"},
		},
	}
}

func buildTestAssertionCredential(t *testing.T, privateKey *ecdsa.PrivateKey, credentialID []byte, challenge string, runtime RuntimeContext, signCount uint32) AssertionCredential {
	t.Helper()
	authData := buildTestAssertionAuthData(runtime.RPID, signCount)
	clientData := buildTestClientData(t, "webauthn.get", challenge, runtime.Origin)
	clientHash := sha256.Sum256(clientData)
	message := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)
	return AssertionCredential{
		ID:    base64.RawURLEncoding.EncodeToString(credentialID),
		RawID: base64.RawURLEncoding.EncodeToString(credentialID),
		Type:  credentialTypePublicKey,
		Response: AssertionCredentialResponse{
			ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientData),
			AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
			Signature:         base64.RawURLEncoding.EncodeToString(signature),
		},
	}
}

func buildTestCOSEKey(t *testing.T, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	x := privateKey.PublicKey.X.Bytes()
	y := privateKey.PublicKey.Y.Bytes()
	key, err := cbor.Marshal(map[int]any{
		1:  2,
		3:  coseAlgES256,
		-1: 1,
		-2: leftPad32(x),
		-3: leftPad32(y),
	})
	require.NoError(t, err)
	return key
}

func buildTestAttestedAuthData(t *testing.T, rpID string, credentialID, coseKey []byte, signCount uint32) []byte {
	t.Helper()
	out := buildTestAssertionAuthDataWithFlags(rpID, authFlagUP|authFlagUV|authFlagAT, signCount)
	out = append(out, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(credentialID)))
	out = append(out, length...)
	out = append(out, credentialID...)
	out = append(out, coseKey...)
	return out
}

func buildTestAssertionAuthData(rpID string, signCount uint32) []byte {
	return buildTestAssertionAuthDataWithFlags(rpID, authFlagUP|authFlagUV, signCount)
}

func buildTestAssertionAuthDataWithFlags(rpID string, flags byte, signCount uint32) []byte {
	sum := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, sum[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, signCount)
	out = append(out, counter...)
	return out
}

func buildTestClientData(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	require.NoError(t, err)
	return payload
}

func leftPad32(value []byte) []byte {
	if len(value) >= 32 {
		return value
	}
	out := make([]byte, 32)
	copy(out[32-len(value):], value)
	return out
}
