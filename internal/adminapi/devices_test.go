package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
)

func TestHandleObserveDeviceProfile(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	cfg := config.Get()
	cfg.Onboarding.DeviceInventoryEnabled = true
	cfg.Profiling.MACInventoryEnabled = true
	cfg.Profiling.PassiveEnabled = true
	cfg.Profiling.PostureEnabled = true
	cfg.Profiling.RemediationEnabled = false

	body := []byte(`{
		"mac":"00:11:22:33:44:55",
		"ip":"192.168.50.44",
		"username":"alice",
		"user_agent":"Mozilla/5.0 (Linux; Android 14)",
		"hostname":"WIN-LAB",
		"dhcp_fingerprint":"MSFT 5.0",
		"lldp_chassis_id":"Cisco-C9300",
		"lldp_port_id":"Gi1/0/44",
		"cdp_device_id":"Cisco-C9300",
		"cdp_port_id":"Gi1/0/44",
		"source":"sensor-api"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profile-observations", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	HandleObserveDeviceProfile(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload onboarding.DeviceProfileObservationResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.NotNil(t, payload.Device)
	assert.True(t, payload.ObservationStored)
	assert.Equal(t, "android", payload.ProfilePlatform)
	assert.Equal(t, "phone", payload.ProfileDeviceType)
	assert.Equal(t, "00:11:22:33:44:55", payload.Device.MAC)
	assert.Equal(t, "MSFT 5.0", payload.Device.DHCPFingerprint)
	assert.Equal(t, "Cisco-C9300", payload.Device.LLDPChassisID)
	assert.Equal(t, "Gi1/0/44", payload.Device.CDPPortID)
	assert.Contains(t, payload.RiskReasons, "profile_platform_mismatch")
	assert.Contains(t, payload.RiskReasons, "infrastructure_neighbor_signal")
}

func TestHandleRevokeDeviceCertificate(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.DB.Exec(`INSERT INTO device_inventory (mac, certificate_serial, certificate_subject, certificate_valid_until, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, "aa:bb:cc:dd:ee:99", "abc123", "guest-aa", now, now, now)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO device_certificates (id, device_mac, username, common_name, serial_number, cert_path, key_path, ca_path, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "cert-99", "aa:bb:cc:dd:ee:99", "guest1", "guest-aa", "abc123", "cert.pem", "key.pem", "ca.pem", now, now)
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Post("/api/v1/devices/certificates/{id}/revoke", HandleRevokeDeviceCertificate)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/certificates/cert-99/revoke", bytes.NewReader([]byte(`{"reason":"lost-device"}`)))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload onboarding.CertificateLifecycleStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "revoked", payload.Status)
	assert.Equal(t, "lost-device", payload.RevokeReason)

	var serial string
	err = db.DB.QueryRow(`SELECT COALESCE(certificate_serial, '') FROM device_inventory WHERE mac = ?`, "aa:bb:cc:dd:ee:99").Scan(&serial)
	require.NoError(t, err)
	assert.Empty(t, serial)
}
