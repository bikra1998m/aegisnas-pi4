package onboarding

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestRegisterDeviceExternalCAEnrollment(t *testing.T) {
	setupOnboardingDB(t)
	t.Setenv("AEGIS_CA_ENROLLMENT_TOKEN", "external-ca-secret")

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   "AegisNAS Test CA",
			Organization: []string{"AegisNAS Tests"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := encodePEM("CERTIFICATE", caDER)
	caCert, err := parseCertificatePEM([]byte(caPEM))
	require.NoError(t, err)

	caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer external-ca-secret", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)

		var req externalEnrollmentRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "guest1", req.Username)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", req.DeviceMAC)
		assert.NotEmpty(t, req.CSRPEM)

		block, _ := pemDecode([]byte(req.CSRPEM))
		require.NotNil(t, block)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		require.NoError(t, csr.CheckSignature())

		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(12 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		issuedDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
		require.NoError(t, err)
		writeJSON(t, w, map[string]any{
			"certificate_pem": encodePEM("CERTIFICATE", issuedDER),
			"ca_pem":          caPEM,
			"serial_number":   serial.Text(16),
			"common_name":     csr.Subject.CommonName,
			"expires_at":      template.NotAfter.UTC().Format(time.RFC3339),
		})
	}))
	defer caServer.Close()

	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: dbPathFromTest(t)},
		Onboarding: config.OnboardingConfig{
			DeviceInventoryEnabled:       true,
			CertificateEnrollmentEnabled: true,
			CAMode:                       "external",
			CAEnrollmentURL:              caServer.URL,
			CAEnrollmentTokenEnv:         "AEGIS_CA_ENROLLMENT_TOKEN",
		},
	}
	service := New(cfg, nil)

	result, err := service.RegisterDevice(context.Background(), RegisterRequest{
		MAC:          "aa:bb:cc:dd:ee:ff",
		Username:     "guest1",
		LastIP:       "192.168.50.10",
		FriendlyName: "Guest iPhone",
		Ownership:    "byod",
		Platform:     "ios",
		UserAgent:    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
		Source:       "portal-onboarding",
	})
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)
	assert.NotEmpty(t, result.CertificatePEM)
	assert.NotEmpty(t, result.PrivateKeyPEM)
	assert.NotEmpty(t, result.CertificateCAPEM)

	device, err := service.GetDeviceByMAC("aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, result.Certificate.ID, device.CertificateID)
	assert.NotEmpty(t, device.CertificateSerial)
	item, loadedCertPEM, loadedKeyPEM, loadedCAPEM, err := service.LoadCertificateBundle(result.Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, result.Certificate.ID, item.ID)
	assert.Equal(t, result.CertificatePEM, loadedCertPEM)
	assert.Equal(t, result.PrivateKeyPEM, loadedKeyPEM)
	assert.Equal(t, result.CertificateCAPEM, loadedCAPEM)

	var count int
	err = db.DB.QueryRow(`SELECT COUNT(*) FROM device_certificates WHERE id = ?`, result.Certificate.ID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestSyncFromMDMAndComplianceWebhookUseBearerTokens(t *testing.T) {
	setupOnboardingDB(t)
	t.Setenv("AEGIS_MDM_API_TOKEN", "mdm-secret")
	t.Setenv("AEGIS_COMPLIANCE_WEBHOOK_TOKEN", "compliance-secret")

	originalSync := syncRuntimeEnforcement
	syncRuntimeEnforcement = func(*config.Config) error { return nil }
	t.Cleanup(func() {
		syncRuntimeEnforcement = originalSync
	})

	require.NoError(t, db.Seed())
	_, err := db.DB.Exec(`INSERT INTO sessions (id, username, mac, ip, auth_method, role, start_time, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "guest1", "aa:bb:cc:dd:ee:ff", "192.168.50.10", "portal", "guest-basic", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	mdmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mdm-secret", r.Header.Get("Authorization"))
		writeJSON(t, w, []map[string]any{
			{
				"mac":               "aa:bb:cc:dd:ee:ff",
				"managed":           true,
				"compliant":         true,
				"compliance_status": "compliant",
				"mdm_provider":      "workspace-one-like",
				"mdm_device_id":     "device-123",
				"friendly_name":     "Guest iPhone",
				"platform":          "ios",
			},
		})
	}))
	defer mdmServer.Close()

	complianceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer compliance-secret", r.Header.Get("Authorization"))
		assert.Equal(t, http.MethodPost, r.Method)
		var payload map[string][]map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.NotEmpty(t, payload["devices"])
		writeJSON(t, w, []map[string]any{
			{
				"mac":               "aa:bb:cc:dd:ee:ff",
				"managed":           true,
				"compliant":         false,
				"compliance_status": "non_compliant",
				"remediation_state": "needs-mdm-attestation",
				"mdm_provider":      "workspace-one-like",
				"mdm_device_id":     "device-123",
			},
		})
	}))
	defer complianceServer.Close()

	cfg := &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "wan0"},
		LAN:  config.InterfaceConfig{Name: "lan0"},
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: false,
		},
		Onboarding: config.OnboardingConfig{
			DeviceInventoryEnabled: true,
		},
		Profiling: config.ProfilingConfig{
			MACInventoryEnabled: true,
			MDMSyncEnabled:      true,
			MDMProvider:         "workspace-one-like",
			MDMEndpoint:         mdmServer.URL,
			MDMAPITokenEnv:      "AEGIS_MDM_API_TOKEN",
			PostureEnabled:      true,
			ComplianceWebhook:   complianceServer.URL,
			ComplianceTokenEnv:  "AEGIS_COMPLIANCE_WEBHOOK_TOKEN",
			RemediationEnabled:  true,
		},
	}
	service := New(cfg, nil)

	mdmStats, err := service.SyncFromMDM(context.Background())
	require.NoError(t, err)
	require.NotNil(t, mdmStats)
	assert.Equal(t, "workspace-one", mdmStats.Provider)
	assert.Equal(t, 1, mdmStats.TotalRecords)
	assert.Equal(t, 1, mdmStats.ManagedRecords)
	assert.Equal(t, 1, mdmStats.CompliantRecords)

	webhookStats, err := service.SyncFromComplianceWebhook(context.Background())
	require.NoError(t, err)
	require.NotNil(t, webhookStats)
	assert.Equal(t, "compliance-webhook", webhookStats.Provider)
	assert.Equal(t, 1, webhookStats.TotalRecords)
	assert.Equal(t, 1, webhookStats.NonCompliantRecords)

	device, err := service.GetDeviceByMAC("aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	assert.Equal(t, "non_compliant", device.ComplianceStatus)
	assert.Equal(t, "workspace-one", device.MDMProvider)

	var filterID string
	err = db.DB.QueryRow(`SELECT COALESCE(filter_id, '') FROM sessions WHERE id = ?`, "session-1").Scan(&filterID)
	require.NoError(t, err)
	assert.Equal(t, "quarantine-posture", filterID)
}

func TestSyncFromMDMIntuneAdapter(t *testing.T) {
	setupOnboardingDB(t)
	t.Setenv("AEGIS_MDM_API_TOKEN", "mdm-secret")

	mdmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mdm-secret", r.Header.Get("Authorization"))
		writeJSON(t, w, map[string]any{
			"value": []map[string]any{
				{
					"id":              "intune-1",
					"deviceName":      "Corp MacBook",
					"operatingSystem": "macOS",
					"wiFiMacAddress":  "aa:bb:cc:dd:ee:11",
					"complianceState": "compliant",
					"managed":         true,
					"complianceGracePeriodExpirationDateTime": "soon",
				},
			},
		})
	}))
	defer mdmServer.Close()

	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: dbPathFromTest(t)},
		Profiling: config.ProfilingConfig{
			MDMSyncEnabled: true,
			MDMProvider:    "intune",
			MDMEndpoint:    mdmServer.URL,
			MDMAPITokenEnv: "AEGIS_MDM_API_TOKEN",
		},
	}
	service := New(cfg, nil)

	stats, err := service.SyncFromMDM(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, "intune", stats.Provider)
	assert.Equal(t, 1, stats.TotalRecords)
	assert.Equal(t, 1, stats.CompliantRecords)

	device, err := service.GetDeviceByMAC("aa:bb:cc:dd:ee:11")
	require.NoError(t, err)
	assert.Equal(t, "intune", device.MDMProvider)
	assert.Equal(t, "intune-1", device.MDMDeviceID)
	assert.Equal(t, "Corp MacBook", device.FriendlyName)
	assert.Equal(t, "macos", device.Platform)
}

func TestSyncFromMDMJamfAdapter(t *testing.T) {
	setupOnboardingDB(t)
	t.Setenv("AEGIS_MDM_API_TOKEN", "mdm-secret")

	mdmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mdm-secret", r.Header.Get("Authorization"))
		writeJSON(t, w, map[string]any{
			"results": []map[string]any{
				{
					"udid":              "jamf-1",
					"device_name":       "Student iPad",
					"platform":          "ios",
					"mac_address":       "aa:bb:cc:dd:ee:22",
					"managed":           true,
					"compliance_state":  "non_compliant",
					"remediation_state": "pending-profile",
				},
			},
		})
	}))
	defer mdmServer.Close()

	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: dbPathFromTest(t)},
		Profiling: config.ProfilingConfig{
			MDMSyncEnabled: true,
			MDMProvider:    "jamf",
			MDMEndpoint:    mdmServer.URL,
			MDMAPITokenEnv: "AEGIS_MDM_API_TOKEN",
		},
	}
	service := New(cfg, nil)

	stats, err := service.SyncFromMDM(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, "jamf", stats.Provider)
	assert.Equal(t, 1, stats.TotalRecords)
	assert.Equal(t, 1, stats.NonCompliantRecords)
	assert.Equal(t, 1, stats.RemediationRecords)

	device, err := service.GetDeviceByMAC("aa:bb:cc:dd:ee:22")
	require.NoError(t, err)
	assert.Equal(t, "jamf", device.MDMProvider)
	assert.Equal(t, "jamf-1", device.MDMDeviceID)
	assert.Equal(t, "pending-profile", device.RemediationState)
	assert.Equal(t, "non_compliant", device.ComplianceStatus)
}

func setupOnboardingDB(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "onboarding.db")
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
	})
	t.Setenv("AEGIS_TEST_DB_PATH", path)
}

func dbPathFromTest(t *testing.T) string {
	t.Helper()
	return os.Getenv("AEGIS_TEST_DB_PATH")
}

func pemDecode(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}
