package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
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
