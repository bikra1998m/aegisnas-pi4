package radius

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBuildRadSecCredentialReportTracksTLSPSKRotation(t *testing.T) {
	cfg := &config.Config{Radius: config.RadiusConfig{Upstream: config.RadiusUpstreamConfig{
		Servers: []config.RadiusHomeServer{{Name: "psk-aaa", Address: "203.0.113.30", Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
			Port: 2083, ServerName: "aaa-psk.example.net", TLSMinVersion: "1.3", TLSMaxVersion: "1.3",
			CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid",
			PSK: config.RadiusRadSecPSKConfig{
				Enabled: true, Identity: "aegisnas-psk", SecretRef: "env:RADSEC_PSK_CURRENT",
				NextIdentity: "aegisnas-psk-next", NextSecretRef: "env:RADSEC_PSK_NEXT",
				NextNotBefore: "2099-01-01T00:00:00Z", NextNotAfter: "2099-01-08T00:00:00Z",
			},
		}}},
	}}}

	report := BuildRadSecCredentialReport(cfg)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.Summary.PSKEndpoints)
	assert.Equal(t, 1, report.Summary.RotationStaged)
	assert.Equal(t, "tls-psk", report.Upstream[0].Mode)
	assert.True(t, report.Upstream[0].PSKSecretRefSet)
	assert.NotEmpty(t, report.Upstream[0].PSKSecretRefFingerprint)
	assert.Equal(t, "staged", report.Upstream[0].RotationStatus)
}

func TestBuildRadSecCredentialReportUsesActiveTLSPSKRotation(t *testing.T) {
	now := time.Now().UTC()
	cfg := &config.Config{Radius: config.RadiusConfig{Upstream: config.RadiusUpstreamConfig{
		Servers: []config.RadiusHomeServer{{Name: "psk-aaa", Address: "203.0.113.30", Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
			Port: 2083, ServerName: "aaa-psk.example.net", TLSMinVersion: "1.3", TLSMaxVersion: "1.3",
			CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid",
			PSK: config.RadiusRadSecPSKConfig{
				Enabled: true, Identity: "aegisnas-psk", SecretRef: "env:RADSEC_PSK_CURRENT",
				NextIdentity: "aegisnas-psk-next", NextSecretRef: "env:RADSEC_PSK_NEXT",
				NextNotBefore: now.Add(-time.Minute).Format(time.RFC3339), NextNotAfter: now.Add(time.Hour).Format(time.RFC3339),
			},
		}}},
	}}}

	report := BuildRadSecCredentialReport(cfg)
	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, 1, report.Summary.RotationActive)
	assert.Equal(t, "active", report.Upstream[0].RotationStatus)
	assert.Equal(t, "aegisnas-psk-next", report.Upstream[0].EffectivePSKIdentity)
	assert.True(t, report.Upstream[0].UsingNextPSK)
	assert.NotEmpty(t, report.Upstream[0].EffectivePSKFingerprint)
}

func TestBuildRadSecCredentialReportBlocksExpiredTLSPSKRotation(t *testing.T) {
	cfg := &config.Config{Radius: config.RadiusConfig{Upstream: config.RadiusUpstreamConfig{
		Servers: []config.RadiusHomeServer{{Name: "psk-aaa", Address: "203.0.113.30", Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
			Port: 2083, ServerName: "aaa-psk.example.net", TLSMinVersion: "1.3", TLSMaxVersion: "1.3",
			CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid",
			PSK: config.RadiusRadSecPSKConfig{
				Enabled: true, Identity: "aegisnas-psk", SecretRef: "env:RADSEC_PSK_CURRENT",
				NextIdentity: "aegisnas-psk-next", NextSecretRef: "env:RADSEC_PSK_NEXT",
				NextNotBefore: "2020-01-01T00:00:00Z", NextNotAfter: "2020-01-08T00:00:00Z",
			},
		}}},
	}}}

	report := BuildRadSecCredentialReport(cfg)
	assert.Equal(t, "blocked", report.Status)
	assert.Equal(t, 1, report.Summary.RotationExpired)
	assert.Contains(t, report.Warnings[0], "expired")
}
