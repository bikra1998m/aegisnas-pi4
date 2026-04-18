package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoad(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := `
mode: two-nic
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.1.1/24
database:
  path: /tmp/aegis.db
logging:
  level: info
  output: stdout
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
radius:
  secret: secret
  clients:
    - ip: 127.0.0.1
      secret: testing
      shortname: local
`
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)
	assert.Equal(t, "two-nic", cfg.Mode)
	assert.Equal(t, "eth0", cfg.WAN.Name)
	assert.Equal(t, "eth1", cfg.LAN.Name)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.True(t, cfg.Telemetry.Enabled)

	err = cfg.Validate()
	assert.NoError(t, err)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "invalid mode",
			cfg: &Config{
				Mode: "invalid",
			},
			wantErr: "mode must be 'two-nic' or 'trunk'",
		},
		{
			name: "invalid deployment profile",
			cfg: &Config{
				Mode:       "two-nic",
				Deployment: DeploymentConfig{Profile: "ultra"},
				WAN:        InterfaceConfig{Name: "eth0"},
				LAN:        InterfaceConfig{Name: "eth1"},
				Database:   DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:     HealthConfig{Port: 8080},
				Telemetry:  TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
				},
			},
			wantErr: "deployment.profile",
		},
		{
			name: "invalid deployment form",
			cfg: &Config{
				Mode:       "two-nic",
				Deployment: DeploymentConfig{Form: "container"},
				WAN:        InterfaceConfig{Name: "eth0"},
				LAN:        InterfaceConfig{Name: "eth1"},
				Database:   DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:     HealthConfig{Port: 8080},
				Telemetry:  TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
				},
			},
			wantErr: "deployment.form",
		},
		{
			name: "two-nic missing wan",
			cfg: &Config{
				Mode: "two-nic",
				WAN:  InterfaceConfig{Name: ""},
				LAN:  InterfaceConfig{Name: "eth1"},
			},
			wantErr: "two-nic mode requires both wan.name and lan.name",
		},
		{
			name: "duplicate VLAN",
			cfg: &Config{
				Mode: "trunk",
				VLANs: []VLANConfig{
					{ID: 10, Name: "guest", Subnet: "10.0.0.0/24"},
					{ID: 10, Name: "corp", Subnet: "10.1.0.0/24"},
				},
			},
			wantErr: "duplicate VLAN ID 10",
		},
		{
			name: "invalid subnet",
			cfg: &Config{
				Mode: "trunk",
				VLANs: []VLANConfig{
					{ID: 20, Subnet: "not-a-subnet"},
				},
			},
			wantErr: "subnet invalid",
		},
		{
			name: "upstream radius missing server",
			cfg: &Config{
				Mode:      "two-nic",
				WAN:       InterfaceConfig{Name: "eth0"},
				LAN:       InterfaceConfig{Name: "eth1"},
				Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:    HealthConfig{Port: 8080},
				Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
					Upstream: RadiusUpstreamConfig{
						Enabled:           true,
						Realm:             "aegis-upstream",
						PoolStrategy:      "fail-over",
						StatusCheck:       "status-server",
						ResponseWindow:    20,
						ZombiePeriod:      40,
						ReviveInterval:    120,
						CheckInterval:     30,
						NumAnswersToAlive: 3,
					},
				},
			},
			wantErr: "requires at least one upstream server",
		},
		{
			name: "upstream radius invalid pool strategy",
			cfg: &Config{
				Mode:      "two-nic",
				WAN:       InterfaceConfig{Name: "eth0"},
				LAN:       InterfaceConfig{Name: "eth1"},
				Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:    HealthConfig{Port: 8080},
				Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
					Upstream: RadiusUpstreamConfig{
						Enabled:           true,
						Realm:             "aegis-upstream",
						PoolStrategy:      "bad-strategy",
						StatusCheck:       "status-server",
						ResponseWindow:    20,
						ZombiePeriod:      40,
						ReviveInterval:    120,
						CheckInterval:     30,
						NumAnswersToAlive: 3,
						Servers: []RadiusHomeServer{
							{Name: "primary", Address: "10.0.0.10", Secret: "secret"},
						},
					},
				},
			},
			wantErr: "pool_strategy",
		},
		{
			name: "wireless enterprise without radius secret",
			cfg: &Config{
				Mode:      "two-nic",
				WAN:       InterfaceConfig{Name: "eth0"},
				LAN:       InterfaceConfig{Name: "eth1"},
				Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:    HealthConfig{Port: 8080},
				Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
				},
				Wireless: WirelessConfig{
					Enabled:        true,
					Interface:      "wlan0",
					CountryCode:    "US",
					HWMode:         "g",
					Channel:        6,
					BeaconInterval: 100,
					SSIDs: []SSIDConfig{
						{Name: "Corp", AuthMode: "wpa2-enterprise"},
					},
				},
			},
			wantErr: "requires radius.secret",
		},
		{
			name: "wireless wpa3 personal without passphrase",
			cfg: &Config{
				Mode:      "two-nic",
				WAN:       InterfaceConfig{Name: "eth0"},
				LAN:       InterfaceConfig{Name: "eth1"},
				Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
				Health:    HealthConfig{Port: 8080},
				Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
				Radius: RadiusConfig{
					AuthPort:              1812,
					AcctPort:              1813,
					RequestTimeoutSeconds: 5,
				},
				Wireless: WirelessConfig{
					Enabled:        true,
					Interface:      "wlan0",
					CountryCode:    "US",
					HWMode:         "g",
					Channel:        6,
					BeaconInterval: 100,
					SSIDs: []SSIDConfig{
						{Name: "Staff", AuthMode: "wpa3-personal"},
					},
				},
			},
			wantErr: "passphrase must be 8-63 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSaveSettingsMap(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "settings-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := `
mode: two-nic
wan:
  name: eth0
  dhcp: true
lan:
  name: eth1
  address: 192.168.50.1/24
database:
  path: /tmp/aegis.db
logging:
  level: info
  output: stdout
health:
  port: 8080
telemetry:
  enabled: true
  prometheus_port: 9090
radius:
  secret: radius-secret
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
portal:
  enabled: true
`
	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	next, err := SaveSettingsMap(map[string]any{
		"deployment": map[string]any{
			"profile": "lite",
			"form":    "virtual",
			"hardware": map[string]any{
				"memory_mb":          1024,
				"cpu_cores":          4,
				"prefer_external_ap": true,
			},
		},
		"policy": map[string]any{
			"runtime_shaping_enabled": false,
		},
		"telemetry": map[string]any{
			"enabled": false,
		},
		"portal": map[string]any{
			"radius_auth":    true,
			"local_fallback": true,
		},
		"wireless": map[string]any{
			"enabled":         true,
			"interface":       "wlan0",
			"country_code":    "US",
			"hw_mode":         "g",
			"channel":         11,
			"beacon_interval": 100,
			"ssids": []map[string]any{
				{
					"name":      "Guest",
					"auth_mode": "captive-portal",
				},
			},
		},
	})
	require.NoError(t, err)

	assert.True(t, next.Portal.RadiusAuth)
	assert.True(t, next.Wireless.Enabled)
	assert.Equal(t, "wlan0", next.Wireless.Interface)
	assert.Len(t, next.Wireless.SSIDs, 1)
	assert.Equal(t, "Guest", next.Wireless.SSIDs[0].Name)
	assert.Equal(t, "lite", next.Deployment.Profile)
	assert.Equal(t, "virtual", next.Deployment.Form)
	assert.False(t, next.Telemetry.Enabled)
	assert.False(t, next.Policy.RuntimeShapingEnabled)

	reloaded, err := Load(tmpfile.Name())
	require.NoError(t, err)
	assert.True(t, reloaded.Wireless.Enabled)
	assert.Equal(t, 11, reloaded.Wireless.Channel)
	assert.True(t, reloaded.Portal.RadiusAuth)
	assert.Equal(t, "lite", reloaded.Deployment.Profile)
	assert.Equal(t, "virtual", reloaded.Deployment.Form)
	assert.False(t, reloaded.Telemetry.Enabled)
	assert.False(t, reloaded.Policy.RuntimeShapingEnabled)
}

func TestDeploymentSummary(t *testing.T) {
	cfg := &Config{
		Deployment: DeploymentConfig{
			Profile: "lite",
			Form:    "virtual",
			Hardware: DeploymentHardwareConfig{
				MemoryMB:         1024,
				CPUCores:         2,
				PreferExternalAP: true,
			},
		},
		Policy: PolicyConfig{
			RuntimeShapingEnabled: false,
		},
		Telemetry: TelemetryConfig{
			Enabled:        false,
			PrometheusPort: 9090,
		},
		AILite: AILiteConfig{
			Enabled:             false,
			RecommendationLimit: 25,
		},
		Radius: RadiusConfig{
			MaxSessions: 256,
			Upstream: RadiusUpstreamConfig{
				StatusCheck: "none",
			},
		},
	}

	summary := DeploymentSummary(cfg)
	assert.Equal(t, "lite", summary["profile"])
	assert.Equal(t, "virtual", summary["form"])
	assert.NotEmpty(t, summary["service_plan"])
}
