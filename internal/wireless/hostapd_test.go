package wireless

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestGenerateHostapdConfigDisabled(t *testing.T) {
	text, err := GenerateHostapdConfig(&config.Config{})
	require.NoError(t, err)
	assert.Contains(t, text, "wireless is disabled")
}

func TestGenerateHostapdConfigEnterpriseAndPortal(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "eth0"},
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Database: config.DatabaseConfig{
			Path: "/tmp/aegis.db",
		},
		Health: config.HealthConfig{
			Port: 8080,
		},
		Telemetry: config.TelemetryConfig{
			Enabled:        true,
			PrometheusPort: 9090,
		},
		Radius: config.RadiusConfig{
			Secret:                "radius-secret",
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
		},
		Portal: config.PortalConfig{
			Enabled: true,
		},
		Wireless: config.WirelessConfig{
			Enabled:        true,
			Interface:      "wlan0",
			CountryCode:    "US",
			Driver:         "nl80211",
			HWMode:         "g",
			Channel:        6,
			BeaconInterval: 100,
			WMMEnabled:     true,
			HTEnabled:      true,
			SSIDs: []config.SSIDConfig{
				{
					Name:            "Guest",
					AuthMode:        "captive-portal",
					ClientIsolation: true,
					PortalProfile:   "Guest Portal",
				},
				{
					Name:       "Staff",
					AuthMode:   "wpa3-personal",
					Passphrase: "supersecret123",
				},
				{
					Name:             "Corp",
					AuthMode:         "wpa2-enterprise",
					Bridge:           "br-corp",
					DynamicVLAN:      true,
					IdentitySource:   "ldap-main",
					BandwidthProfile: "corp-fast",
				},
			},
		},
	}

	text, err := GenerateHostapdConfig(cfg)
	require.NoError(t, err)

	assert.Contains(t, text, "interface=wlan0")
	assert.Contains(t, text, "ssid=Guest")
	assert.Contains(t, text, "ssid=Staff")
	assert.Contains(t, text, "ssid=Corp")
	assert.Contains(t, text, "auth_server_addr=127.0.0.1")
	assert.Contains(t, text, "dynamic_vlan=1")
	assert.Contains(t, text, "# captive portal access is enforced by the AegisNAS gateway and portal services")
	assert.Contains(t, text, "# aegisnas_identity_source=ldap-main")
	assert.Contains(t, text, "wpa_key_mgmt=SAE")
	assert.Contains(t, text, "ieee80211w=2")
	assert.True(t, strings.HasSuffix(text, "\n"))
}
