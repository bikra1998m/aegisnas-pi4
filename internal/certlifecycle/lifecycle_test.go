package certlifecycle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestEvaluateCertificateLifecycleAcceptsBoundCSR(t *testing.T) {
	cfg := lifecycleConfig()
	csrPEM := testCSR(t, "device-1", []string{"device-1"}, 2048)

	decision := Evaluate(cfg, EvaluationRequest{
		Protocol:              "est",
		DeviceID:              "device-1",
		CSRPEM:                csrPEM,
		RequestedValidityDays: 90,
		DeviceBound:           true,
		CRLReachable:          true,
		RevocationChecked:     true,
		CertificateSerial:     "01",
		CertificateNotAfter:   time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})

	assert.Equal(t, "accepted", decision.Decision)
	assert.Equal(t, "est", decision.Protocol)
	assert.Equal(t, "device-eap-tls", decision.Template)
	assert.Equal(t, "active", decision.IssuerState)
	assert.Equal(t, "rsa", decision.CSR.KeyType)
	assert.True(t, decision.CSR.SignatureValid)
	assert.True(t, decision.ProofOfPossession)
}

func TestEvaluateCertificateLifecycleRejectsWeakRSA(t *testing.T) {
	cfg := lifecycleConfig()
	csrPEM := testCSR(t, "device-1", []string{"device-1"}, 1024)

	decision := Evaluate(cfg, EvaluationRequest{
		Protocol:     "scep",
		DeviceID:     "device-1",
		CSRPEM:       csrPEM,
		DeviceBound:  true,
		CRLReachable: true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "RSA key")
}

func TestEvaluateCertificateLifecycleRejectsEscrowWithoutAdminApproval(t *testing.T) {
	cfg := lifecycleConfig()
	csrPEM := testCSR(t, "device-1", []string{"device-1"}, 2048)

	decision := Evaluate(cfg, EvaluationRequest{
		Protocol:        "byod",
		DeviceID:        "device-1",
		CSRPEM:          csrPEM,
		DeviceBound:     true,
		CRLReachable:    true,
		EscrowRequested: true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "escrow")
}

func TestEvaluateCertificateLifecycleMonitorAllowsMissingRevocation(t *testing.T) {
	cfg := lifecycleConfig()
	cfg.Onboarding.CertificateLifecycle.Mode = "monitor"
	csrPEM := testCSR(t, "device-1", []string{"device-1"}, 2048)

	decision := Evaluate(cfg, EvaluationRequest{
		Protocol:       "est",
		DeviceID:       "device-1",
		CSRPEM:         csrPEM,
		DeviceBound:    true,
		Renewal:        true,
		ExistingSerial: "old-serial",
	})

	assert.Equal(t, "monitor_allowed", decision.Decision)
	assert.Contains(t, decision.Reason, "CRL or OCSP")
	assert.NotEmpty(t, decision.Warnings)
}

func TestAnalyzeCSRRejectsInvalidPEM(t *testing.T) {
	analysis := AnalyzeCSR("not pem")
	assert.True(t, analysis.Present)
	assert.False(t, analysis.ValidPEM)
	assert.NotEmpty(t, analysis.Error)
}

func lifecycleConfig() *config.Config {
	return &config.Config{
		Deployment: config.DeploymentConfig{Profile: "enterprise"},
		Onboarding: config.OnboardingConfig{
			PortalEnabled:                true,
			DeviceInventoryEnabled:       true,
			CertificateEnrollmentEnabled: true,
			EAPTLSEnabled:                true,
			CAMode:                       "internal",
			CACertPath:                   "/etc/aegisnas/pki/ca.crt",
			CAKeyPath:                    "/etc/aegisnas/pki/ca.key",
			CertificateLifecycle: config.CertificateLifecycleConfig{
				Enabled:                    true,
				Mode:                       "enforce",
				FailClosed:                 true,
				DefaultTemplate:            "device-eap-tls",
				Templates:                  []string{"device-eap-tls", "byod-eap-tls"},
				ActiveIssuer:               "aegisnas-local",
				IssuerRotationMode:         "disabled",
				IssuerOverlapSeconds:       2592000,
				CertificateValidityDays:    365,
				MaxCertificateValidityDays: 825,
				RenewalWindowDays:          30,
				RequireCSR:                 true,
				RequireProofOfPossession:   true,
				RequireDeviceBinding:       true,
				RequireSubjectAltName:      true,
				AllowedKeyTypes:            []string{"rsa", "ecdsa", "ed25519"},
				MinRSABits:                 2048,
				AllowedECDSACurves:         []string{"P-256", "P-384", "P-521"},
				EscrowPolicy:               "forbid",
				CRLEnabled:                 true,
				ESTEnabled:                 true,
				SCEPEnabled:                true,
				BYODPortalEnabled:          true,
				AuditEnabled:               true,
				EventRetentionLimit:        6000,
				InventoryRetentionLimit:    100000,
			},
		},
		Radius: config.RadiusConfig{
			EAP: config.RadiusEAPConfig{
				DefaultType:          "tls",
				CheckCRL:             true,
				CAPathReloadInterval: 3600,
			},
		},
	}
}

func testCSR(t *testing.T, commonName string, dnsNames []string, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	template := x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: commonName},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
