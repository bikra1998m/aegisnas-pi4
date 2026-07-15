package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validRadSecTestConfig() *Config {
	return &Config{Radius: RadiusConfig{RadSec: RadiusRadSecConfig{
		Enabled: true, ListenAddress: "0.0.0.0", Port: 2083,
		CertificateFile: "/etc/aegisnas/radsec/server.crt", PrivateKeyFile: "/etc/aegisnas/radsec/server.key",
		CAFile: "/etc/aegisnas/radsec/ca.crt", TLSMinVersion: "1.2", TLSMaxVersion: "1.3",
		CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid", MaxConnections: 64,
	}}}
}

func TestValidateRadSecConfig(t *testing.T) {
	cfg := validRadSecTestConfig()
	require.NoError(t, validateRadSecConfig(cfg))

	cfg.Radius.RadSec.TLSMinVersion = "1.0"
	assert.ErrorContains(t, validateRadSecConfig(cfg), "must be 1.2 or 1.3")

	cfg = validRadSecTestConfig()
	cfg.Radius.RadSec.RadiusV11 = "require"
	assert.ErrorContains(t, validateRadSecConfig(cfg), "tls_min_version 1.3")

	cfg.Radius.RadSec.TLSMinVersion = "1.3"
	require.NoError(t, validateRadSecConfig(cfg))
}

func TestValidateRadSecClientRequiresListenerAndIdentity(t *testing.T) {
	client := RadiusClient{IP: "192.0.2.10", ShortName: "nas-01", Transport: "radsec", RadSecCertificateCN: "nas.example.net"}
	assert.ErrorContains(t, validateRadiusClientTransport(0, client, false), "enabled is false")
	require.NoError(t, validateRadiusClientTransport(0, client, true))

	client.RadSecCertificateCN = ""
	assert.ErrorContains(t, validateRadiusClientTransport(0, client, true), "certificate_cn is required")
}

func TestValidateRadSecPeerRejectsUDPFallbackAndUnsafeEnvironment(t *testing.T) {
	server := RadiusHomeServer{Name: "primary", Address: "aaa.example.net", Transport: "radsec", RadSec: RadiusRadSecPeerConfig{
		Port: 2083, ServerName: "aaa.example.net", CertificateFile: "/client.crt", PrivateKeyFile: "/client.key",
		CAFile: "/ca.crt", TLSMinVersion: "1.2", TLSMaxVersion: "1.3", CipherList: "DEFAULT@SECLEVEL=2",
		RadiusV11: "forbid", PrivateKeyPasswordEnv: "RADSEC_KEY_PASSWORD",
	}}
	require.NoError(t, validateRadSecPeer(0, server))
	server.RadSec.PrivateKeyPasswordEnv = "$(unsafe)"
	assert.ErrorContains(t, validateRadSecPeer(0, server), "not a valid environment variable name")
}

func TestValidateRadSecPeerAllowsTLSPSKWithRotation(t *testing.T) {
	server := RadiusHomeServer{Name: "primary", Address: "aaa.example.net", Transport: "radsec", RadSec: RadiusRadSecPeerConfig{
		Port: 2083, ServerName: "aaa.example.net", TLSMinVersion: "1.3", TLSMaxVersion: "1.3",
		CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "allow", MaxConnections: 16,
		PSK: RadiusRadSecPSKConfig{
			Enabled: true, Identity: "aegisnas-primary", SecretRef: "env:RADSEC_PSK_CURRENT",
			NextIdentity: "aegisnas-primary-next", NextSecretRef: "env:RADSEC_PSK_NEXT",
			NextNotBefore: "2026-08-01T00:00:00Z", NextNotAfter: "2026-08-08T00:00:00Z",
			OverlapSeconds: 86400, WarningDays: 30,
		},
	}}
	require.NoError(t, validateRadSecPeer(0, server))

	server.RadSec.PSK.NextNotAfter = "2026-07-01T00:00:00Z"
	assert.ErrorContains(t, validateRadSecPeer(0, server), "next_not_after")

	server.RadSec.PSK.NextNotAfter = "2026-08-08T00:00:00Z"
	server.RadSec.PSK.SecretRef = "vault:path"
	assert.ErrorContains(t, validateRadSecPeer(0, server), "unsupported secret provider")
}
