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
			Enabled:             true,
			Interface:           "wlan0",
			CountryCode:         "US",
			Driver:              "nl80211",
			HWMode:              "g",
			Channel:             6,
			BeaconInterval:      100,
			WMMEnabled:          true,
			HTEnabled:           true,
			HostapdVLANFilePath: "/tmp/aegisnas-vlans.conf",
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
	assert.Contains(t, text, "dynamic_vlan=2")
	assert.Contains(t, text, "vlan_file=/tmp/aegisnas-vlans.conf")
	assert.Contains(t, text, "# captive portal access is enforced by the AegisNAS gateway and portal services")
	assert.Contains(t, text, "# aegisnas_identity_source=ldap-main")
	assert.Contains(t, text, "wpa_key_mgmt=SAE")
	assert.Contains(t, text, "ieee80211w=2")
	assert.True(t, strings.HasSuffix(text, "\n"))
}

func TestGenerateHostapdConfigRendersRoamingLifecycle(t *testing.T) {
	t.Setenv("AEGIS_FT_KEY_SEED", "test-ft-seed-that-is-long-enough")
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
			Roaming: config.WirelessRoamingConfig{
				Enabled:               true,
				Mode:                  "enforce",
				FailClosed:            true,
				IEEE80211R:            true,
				IEEE80211K:            true,
				IEEE80211V:            true,
				MobilityDomain:        "4f57",
				PMFRequired:           true,
				R0KeyLifetimeSeconds:  7200,
				ReassociationDeadline: 1200,
				NASIdentifier:         "aegis-ap-1",
				R1KeyHolder:           "00:11:22:33:44:55",
				KeySeedRef:            "env:AEGIS_FT_KEY_SEED",
				KeyRotationMode:       "active",
				RRMNeighborReport:     true,
				RRMBeaconReport:       true,
				BSSTransition:         true,
				NeighborAPs: []config.WirelessNeighborAPConfig{
					{
						Name:          "ap-2",
						BSSID:         "02:11:22:33:44:55",
						NASIdentifier: "aegis-ap-2",
						R1KeyHolder:   "02:11:22:33:44:55",
						SSIDs:         []string{"Corp"},
						Channel:       6,
						OpClass:       81,
						Preference:    255,
					},
				},
				Profiles: []config.WirelessRoamingProfileConfig{
					{
						Name:        "corp-fast-roam",
						Enabled:     true,
						IEEE80211R:  true,
						IEEE80211K:  true,
						IEEE80211V:  true,
						PMFRequired: true,
						NeighborAPs: []string{"ap-2"},
					},
				},
			},
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", RoamingProfile: "corp-fast-roam"},
			},
		},
	}

	text, err := GenerateHostapdConfig(cfg)
	require.NoError(t, err)

	assert.Contains(t, text, "wpa_key_mgmt=WPA-EAP FT-EAP")
	assert.Contains(t, text, "mobility_domain=4f57")
	assert.Contains(t, text, "r0_key_lifetime=7200")
	assert.Contains(t, text, "reassociation_deadline=1200")
	assert.Contains(t, text, "nas_identifier=aegis-ap-1")
	assert.Contains(t, text, "r1_key_holder=001122334455")
	assert.Contains(t, text, "r0kh=02:11:22:33:44:55 aegis-ap-2 ")
	assert.Contains(t, text, "r1kh=02:11:22:33:44:55 021122334455 ")
	assert.Contains(t, text, "rrm_neighbor_report=1")
	assert.Contains(t, text, "rrm_beacon_report=1")
	assert.Contains(t, text, "bss_transition=1")
	assert.NotContains(t, text, "test-ft-seed-that-is-long-enough")
}

func TestGenerateHostapdConfigRendersPasspointLifecycle(t *testing.T) {
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
			Passpoint: config.WirelessPasspointConfig{
				Enabled:           true,
				Mode:              "enforce",
				FailClosed:        true,
				Interworking:      true,
				HS20:              true,
				AccessNetworkType: 2,
				Internet:          true,
				Profiles: []config.WirelessPasspointProfileConfig{
					{
						Name:                 "corp-passpoint",
						Enabled:              true,
						Interworking:         true,
						HS20:                 true,
						HESSID:               "02:11:22:33:44:55",
						DisableDGAF:          true,
						ProxyARP:             true,
						DomainNames:          []string{"corp.example.com"},
						RoamingConsortiumOIs: []string{"112233"},
						OperatorFriendlyNames: []config.WirelessLocalizedTextConfig{
							{Language: "eng", Text: "AegisNAS"},
						},
						VenueNames: []config.WirelessLocalizedTextConfig{
							{Language: "eng", Text: "AegisNAS Lab"},
						},
						NAIRealms: []config.WirelessPasspointNAIRealmConfig{
							{Realm: "corp.example.com", Encoding: 0, EAPMethods: []string{"tls", "ttls"}, AuthParams: []string{"5:6"}},
						},
						CellularNetworks: []config.WirelessPasspointCellularNetworkConfig{
							{MCC: "310", MNC: "260"},
						},
						WANMetrics: config.WirelessPasspointWANMetricsConfig{
							Enabled:      true,
							WANInfo:      "01",
							DownlinkKbps: 100000,
							UplinkKbps:   50000,
							DownlinkLoad: 1,
							UplinkLoad:   1,
						},
						ConnectionCapabilities: []config.WirelessPasspointConnectionCapabilityConfig{
							{Protocol: 6, Port: 443, Status: 1},
						},
						OSU: config.WirelessPasspointOSUConfig{
							Enabled:   true,
							SSID:      "Aegis OSU",
							ServerURI: "https://osu.example.com/signup",
							FriendlyNames: []config.WirelessLocalizedTextConfig{
								{Language: "eng", Text: "AegisNAS Signup"},
							},
							NAI:        "anonymous@corp.example.com",
							MethodList: []int{1},
							ServiceDescriptions: []config.WirelessLocalizedTextConfig{
								{Language: "eng", Text: "Corporate onboarding"},
							},
						},
					},
				},
			},
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", PasspointProfile: "corp-passpoint"},
			},
		},
	}

	text, err := GenerateHostapdConfig(cfg)
	require.NoError(t, err)

	assert.Contains(t, text, "# aegisnas_passpoint_profile=corp-passpoint")
	assert.Contains(t, text, "interworking=1")
	assert.Contains(t, text, "access_network_type=2")
	assert.Contains(t, text, "hessid=02:11:22:33:44:55")
	assert.Contains(t, text, "venue_name=eng:AegisNAS Lab")
	assert.Contains(t, text, "domain_name=corp.example.com")
	assert.Contains(t, text, "roaming_consortium=112233")
	assert.Contains(t, text, "nai_realm=0,corp.example.com,13[5:6],21[5:6]")
	assert.Contains(t, text, "anqp_3gpp_cell_net=310,260")
	assert.Contains(t, text, "hs20=1")
	assert.Contains(t, text, "disable_dgaf=1")
	assert.Contains(t, text, "proxy_arp=1")
	assert.Contains(t, text, "hs20_oper_friendly_name=eng:AegisNAS")
	assert.Contains(t, text, "hs20_wan_metrics=01:100000:50000:1:1:0")
	assert.Contains(t, text, "hs20_conn_capab=6:443:1")
	assert.Contains(t, text, "osu_ssid=Aegis OSU")
	assert.Contains(t, text, "osu_server_uri=https://osu.example.com/signup")
	assert.Contains(t, text, "osu_friendly_name=eng:AegisNAS Signup")
	assert.Contains(t, text, "osu_method_list=1")
	assert.Contains(t, text, "osu_service_desc=eng:Corporate onboarding")
}

func TestGenerateHostapdConfigAndPPSKFile(t *testing.T) {
	t.Setenv("AEGIS_TEST_PPSK", "camera-secret-123")
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
			Secret:                "testing-secret",
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
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
			PPSK: config.WirelessPPSKConfig{
				Enabled:             true,
				Mode:                "enforce",
				FailClosed:          true,
				PSKFilePath:         "/tmp/aegisnas-ppsk.psk",
				RotationMode:        "active",
				MinPassphraseLength: 8,
				Profiles: []config.WirelessPPSKProfileConfig{
					{Name: "iot-ppsk", Enabled: true, Mode: "enforce", Groups: []string{"cameras"}},
				},
				Groups: []config.WirelessPPSKGroupConfig{
					{Name: "cameras", Enabled: true, VLAN: 30},
				},
				Credentials: []config.WirelessPPSKCredentialConfig{
					{ID: "camera-1", Enabled: true, MAC: "02:11:22:33:44:55", Profile: "iot-ppsk", Group: "cameras", SecretRef: "env:AEGIS_TEST_PPSK"},
				},
			},
			SSIDs: []config.SSIDConfig{
				{Name: "IoT", AuthMode: "wpa2-personal", PPSKProfile: "iot-ppsk"},
			},
		},
	}

	text, err := GenerateHostapdConfig(cfg)
	require.NoError(t, err)
	assert.Contains(t, text, "# aegisnas_ppsk_profile=iot-ppsk")
	assert.Contains(t, text, "wpa_psk_file=/tmp/aegisnas-ppsk.psk")
	assert.NotContains(t, text, "wpa_passphrase=")
	assert.NotContains(t, text, "camera-secret-123")

	pskFile, err := GeneratePPSKFile(cfg)
	require.NoError(t, err)
	assert.Contains(t, pskFile, "02:11:22:33:44:55 camera-secret-123")
	assert.Contains(t, pskFile, "credential=camera-1")
}

func TestHostapdDynamicVLANModeUsesFallbackWhenConfigured(t *testing.T) {
	assert.Equal(t, 0, HostapdDynamicVLANMode(config.SSIDConfig{}))
	assert.Equal(t, 2, HostapdDynamicVLANMode(config.SSIDConfig{DynamicVLAN: true}))
	assert.Equal(t, 1, HostapdDynamicVLANMode(config.SSIDConfig{DynamicVLAN: true, VLAN: 30}))
}
