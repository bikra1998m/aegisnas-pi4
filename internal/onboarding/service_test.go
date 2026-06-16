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

func TestCertificateLifecycleRevokesRenewsAndBuildsCRL(t *testing.T) {
	setupOnboardingDB(t)
	caCertPath, caKeyPath := writeTestInternalCA(t, t.TempDir())

	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: dbPathFromTest(t)},
		Onboarding: config.OnboardingConfig{
			DeviceInventoryEnabled:       true,
			CertificateEnrollmentEnabled: true,
			CAMode:                       "internal",
			CACertPath:                   caCertPath,
			CAKeyPath:                    caKeyPath,
		},
	}
	service := New(cfg, nil)

	result, err := service.RegisterDevice(context.Background(), RegisterRequest{
		MAC:          "aa:bb:cc:dd:ee:77",
		Username:     "guest1",
		LastIP:       "192.168.50.77",
		FriendlyName: "Guest Laptop",
		Ownership:    "byod",
		Platform:     "windows",
		Source:       "portal-onboarding",
	})
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)

	activeStatus, err := service.CertificateStatus(result.Certificate.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", activeStatus.Status)
	assert.False(t, activeStatus.Revoked)

	revokedStatus, err := service.RevokeCertificate(result.Certificate.ID, "lost-device")
	require.NoError(t, err)
	assert.Equal(t, "revoked", revokedStatus.Status)
	assert.True(t, revokedStatus.Revoked)
	assert.Equal(t, "lost-device", revokedStatus.RevokeReason)

	device, err := service.GetDeviceByMAC("aa:bb:cc:dd:ee:77")
	require.NoError(t, err)
	assert.Empty(t, device.CertificateID)
	assert.Empty(t, device.CertificateSerial)

	crlPEM, err := service.BuildCertificateRevocationList()
	require.NoError(t, err)
	block, _ := pemDecode(crlPEM)
	require.NotNil(t, block)
	assert.Equal(t, "X509 CRL", block.Type)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	serial, ok := parseCertificateSerial(result.Certificate.Serial)
	require.True(t, ok)
	assert.True(t, crlContainsSerial(crl, serial))

	renewed, err := service.RenewCertificate(context.Background(), result.Certificate.ID)
	require.NoError(t, err)
	require.NotNil(t, renewed.Certificate)
	assert.NotEqual(t, result.Certificate.ID, renewed.Certificate.ID)

	device, err = service.GetDeviceByMAC("aa:bb:cc:dd:ee:77")
	require.NoError(t, err)
	assert.Equal(t, renewed.Certificate.ID, device.CertificateID)
	assert.Equal(t, renewed.Certificate.Serial, device.CertificateSerial)
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

func TestObserveDHCPLeaseProfilesRecordsRiskAndQuarantines(t *testing.T) {
	setupOnboardingDB(t)

	originalSync := syncRuntimeEnforcement
	syncRuntimeEnforcement = func(*config.Config) error { return nil }
	t.Cleanup(func() {
		syncRuntimeEnforcement = originalSync
	})

	_, err := db.DB.Exec(`INSERT INTO sessions (id, username, mac, ip, auth_method, role, start_time, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-risk", "guest1", "02:11:22:33:44:55", "192.168.50.55", "portal", "guest-basic", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	cfg := &config.Config{
		Onboarding: config.OnboardingConfig{
			DeviceInventoryEnabled: true,
		},
		Profiling: config.ProfilingConfig{
			MACInventoryEnabled: true,
			PassiveEnabled:      true,
			PostureEnabled:      true,
			RemediationEnabled:  true,
		},
	}
	service := New(cfg, nil)

	stats, err := service.ObserveDHCPLeaseProfiles([]DHCPLeaseProfile{{
		MAC:              "02:11:22:33:44:55",
		IP:               "192.168.50.55",
		Expired:          true,
		RemainingSeconds: -60,
	}})
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, 1, stats.TotalRecords)
	assert.Equal(t, 1, stats.ExpiredRecords)
	assert.Equal(t, 1, stats.LocallyAdministeredMACs)
	assert.Equal(t, 1, stats.HighRiskRecords)
	assert.Equal(t, int64(1), stats.AutoQuarantinedSessions)

	device, err := service.GetDeviceByMAC("02:11:22:33:44:55")
	require.NoError(t, err)
	assert.Equal(t, "02:11:22", device.MACOUI)
	assert.Equal(t, "dhcp-lease", device.Source)
	assert.Equal(t, "192.168.50.55", device.LastIP)
	assert.GreaterOrEqual(t, device.RiskScore, highRiskProfileThreshold)
	assert.Contains(t, device.RiskReasons, "locally_administered_mac")
	assert.Contains(t, device.RiskReasons, "lease_expired")

	var filterID string
	err = db.DB.QueryRow(`SELECT COALESCE(filter_id, '') FROM sessions WHERE id = ?`, "session-risk").Scan(&filterID)
	require.NoError(t, err)
	assert.Equal(t, "quarantine-profile-risk", filterID)
}

func TestObserveProfileSignalsStoresFingerprintsAndQuarantines(t *testing.T) {
	setupOnboardingDB(t)

	originalSync := syncRuntimeEnforcement
	syncRuntimeEnforcement = func(*config.Config) error { return nil }
	t.Cleanup(func() {
		syncRuntimeEnforcement = originalSync
	})

	_, err := db.DB.Exec(`INSERT INTO sessions (id, username, mac, ip, auth_method, role, start_time, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-profile-risk", "guest1", "02:22:33:44:55:66", "192.168.50.66", "portal", "guest-basic", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	cfg := &config.Config{
		Onboarding: config.OnboardingConfig{
			DeviceInventoryEnabled: true,
		},
		Profiling: config.ProfilingConfig{
			MACInventoryEnabled: true,
			PassiveEnabled:      true,
			PostureEnabled:      true,
			RemediationEnabled:  true,
		},
	}
	service := New(cfg, nil)

	result, err := service.ObserveProfileSignals(DeviceProfileObservation{
		MAC:             "02:22:33:44:55:66",
		IP:              "192.168.50.66",
		Username:        "guest1",
		SessionID:       "session-profile-risk",
		UserAgent:       "Mozilla/5.0 (Linux; Android 14)",
		Hostname:        "WIN-LAB",
		DHCPFingerprint: "MSFT 5.0",
		LLDPChassisID:   "Cisco-C9300",
		LLDPPortID:      "Gi1/0/66",
		CDPDeviceID:     "Cisco-C9300",
		CDPPortID:       "Gi1/0/66",
		Source:          "sensor-api",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Device)
	assert.True(t, result.ObservationStored)
	assert.GreaterOrEqual(t, result.RiskScore, highRiskProfileThreshold)
	assert.Equal(t, int64(1), result.AutoQuarantinedSessions)
	assert.Equal(t, "android", result.ProfilePlatform)
	assert.Equal(t, "phone", result.ProfileDeviceType)
	assert.Equal(t, "MSFT 5.0", result.Device.DHCPFingerprint)
	assert.Equal(t, "Cisco-C9300", result.Device.LLDPChassisID)
	assert.Equal(t, "Gi1/0/66", result.Device.LLDPPortID)
	assert.Equal(t, "Cisco-C9300", result.Device.CDPDeviceID)
	assert.Equal(t, "Gi1/0/66", result.Device.CDPPortID)
	assert.Contains(t, result.RiskReasons, "locally_administered_mac")
	assert.Contains(t, result.RiskReasons, "profile_platform_mismatch")
	assert.Contains(t, result.RiskReasons, "infrastructure_neighbor_signal")

	var filterID string
	err = db.DB.QueryRow(`SELECT COALESCE(filter_id, '') FROM sessions WHERE id = ?`, "session-profile-risk").Scan(&filterID)
	require.NoError(t, err)
	assert.Equal(t, "quarantine-profile-risk", filterID)
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

func writeTestInternalCA(t *testing.T, dir string) (string, string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2001),
		Subject: pkix.Name{
			CommonName:   "AegisNAS Internal Test CA",
			Organization: []string{"AegisNAS Tests"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, []byte(encodePEM("CERTIFICATE", caDER)), 0600))
	require.NoError(t, os.WriteFile(keyPath, []byte(encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))), 0600))
	return certPath, keyPath
}

func crlContainsSerial(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func pemDecode(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(value))
}
