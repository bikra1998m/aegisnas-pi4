package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
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
	assert.Equal(t, "lite", EffectiveAIMode(cfg))
	assert.Equal(t, "local", EffectiveAIProvider(cfg))

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

func TestConfigValidationRadiusVendor(t *testing.T) {
	productRole := productconfigs.AegisNASVendorDictionary().Attributes[0]
	base := func() *Config {
		return &Config{
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
				Vendor: RadiusVendorConfig{
					Enabled: true,
					Name:    "AegisNAS",
					ID:      55555,
					Attributes: []RadiusVendorAttribute{
						{Name: productRole.Name, Number: productRole.Number, Type: productRole.Type},
					},
				},
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	invalidID := base()
	invalidID.Radius.Vendor.ID = 0
	assert.ErrorContains(t, invalidID.Validate(), "radius.vendor.id")

	duplicateAttr := base()
	duplicateAttr.Radius.Vendor.Attributes = append(duplicateAttr.Radius.Vendor.Attributes, RadiusVendorAttribute{Name: "AegisNAS-Role-Alt", Number: productRole.Number, Type: "string"})
	assert.ErrorContains(t, duplicateAttr.Validate(), "duplicates")

	invalidType := base()
	invalidType.Radius.Vendor.Attributes[0].Type = "blob"
	assert.ErrorContains(t, invalidType.Validate(), "type")
}

func TestConfigValidationAIEngine(t *testing.T) {
	base := func() *Config {
		return &Config{
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
			AILite: AILiteConfig{
				Enabled:               true,
				Mode:                  "full",
				Provider:              "openai-compatible",
				Endpoint:              "http://127.0.0.1:11434",
				Model:                 "ops-model",
				RequestTimeoutSeconds: 20,
				MaxInputEvents:        200,
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	invalidMode := base()
	invalidMode.AILite.Mode = "magic"
	assert.ErrorContains(t, invalidMode.Validate(), "ailite.mode")

	invalidProvider := base()
	invalidProvider.AILite.Provider = "cloud-magic"
	assert.ErrorContains(t, invalidProvider.Validate(), "ailite.provider")

	missingModel := base()
	missingModel.AILite.Model = ""
	assert.ErrorContains(t, missingModel.Validate(), "ailite.model")

	badEndpoint := base()
	badEndpoint.AILite.Endpoint = "ftp://example.com"
	assert.ErrorContains(t, badEndpoint.Validate(), "ailite.endpoint")
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
				"memory_mb":            1024,
				"cpu_cores":            4,
				"prefer_external_ap":   true,
				"wireless_passthrough": true,
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
	assert.True(t, next.Deployment.Hardware.WirelessPassthrough)

	reloaded, err := Load(tmpfile.Name())
	require.NoError(t, err)
	assert.True(t, reloaded.Wireless.Enabled)
	assert.Equal(t, 11, reloaded.Wireless.Channel)
	assert.True(t, reloaded.Portal.RadiusAuth)
	assert.Equal(t, "lite", reloaded.Deployment.Profile)
	assert.Equal(t, "virtual", reloaded.Deployment.Form)
	assert.False(t, reloaded.Telemetry.Enabled)
	assert.False(t, reloaded.Policy.RuntimeShapingEnabled)
	assert.True(t, reloaded.Deployment.Hardware.WirelessPassthrough)
}

func TestDeploymentSummary(t *testing.T) {
	cfg := &Config{
		Deployment: DeploymentConfig{
			Profile: "lite",
			Form:    "virtual",
			Hardware: DeploymentHardwareConfig{
				MemoryMB:            1024,
				CPUCores:            2,
				PreferExternalAP:    true,
				WirelessPassthrough: false,
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
			Mode:                "lite",
			Provider:            "local",
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
	assert.NotEmpty(t, summary["capabilities"])
}

func TestConfigValidationVirtualWirelessRequiresPassthrough(t *testing.T) {
	cfg := &Config{
		Mode: "two-nic",
		Deployment: DeploymentConfig{
			Form: "virtual",
		},
		WAN:      InterfaceConfig{Name: "eth0"},
		LAN:      InterfaceConfig{Name: "eth1"},
		Database: DatabaseConfig{Path: "/tmp/aegis.db"},
		Health:   HealthConfig{Port: 8080},
		Telemetry: TelemetryConfig{
			Enabled:        true,
			PrometheusPort: 9090,
		},
		Radius: RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
		},
		Portal: PortalConfig{
			Enabled: true,
		},
		Wireless: WirelessConfig{
			Enabled:        true,
			Interface:      "wlan0",
			CountryCode:    "US",
			HWMode:         "g",
			Channel:        6,
			BeaconInterval: 100,
			SSIDs: []SSIDConfig{
				{Name: "Guest", AuthMode: "captive-portal"},
			},
		},
	}

	assert.ErrorContains(t, cfg.Validate(), "wireless.enabled requires deployment.hardware.wireless_passthrough")
	cfg.Deployment.Hardware.WirelessPassthrough = true
	assert.NoError(t, cfg.Validate())
}

func TestEvaluateFeatureCapabilities(t *testing.T) {
	cfg := &Config{
		Mode: "two-nic",
		Deployment: DeploymentConfig{
			Profile: "branch",
			Form:    "virtual",
			Hardware: DeploymentHardwareConfig{
				MemoryMB:            8192,
				CPUCores:            4,
				PreferExternalAP:    false,
				WirelessPassthrough: false,
			},
		},
		WAN:      InterfaceConfig{Name: "eth0"},
		LAN:      InterfaceConfig{Name: "eth1"},
		Database: DatabaseConfig{Path: "/tmp/aegis.db"},
		Health:   HealthConfig{Port: 8080},
		Telemetry: TelemetryConfig{
			Enabled:        true,
			PrometheusPort: 9090,
		},
		Policy: PolicyConfig{
			RuntimeShapingEnabled: true,
		},
		Portal: PortalConfig{
			Enabled:       true,
			LocalFallback: true,
			Branding:      "AegisNAS Guest",
			GuestWorkflows: PortalGuestWorkflowConfig{
				SelfRegistrationEnabled: true,
				SponsorApprovalEnabled:  true,
				InviteDelivery:          "email",
				ApprovalDelivery:        "email",
				EmailFrom:               "guests@example.com",
				SMTPServer:              "smtp.example.com",
				SMTPPort:                587,
			},
		},
		Onboarding: OnboardingConfig{
			DeviceInventoryEnabled:       true,
			PortalEnabled:                true,
			CertificateEnrollmentEnabled: false,
			EAPTLSEnabled:                false,
			CAMode:                       "external",
			CAEnrollmentURL:              "https://ca.example.com/enroll",
		},
		Profiling: ProfilingConfig{
			MACInventoryEnabled: true,
			PassiveEnabled:      true,
			PollIntervalSeconds: 300,
			RetentionHours:      24,
			PostureEnabled:      false,
			MDMSyncEnabled:      true,
			MDMProvider:         "workspace-one-like",
			MDMEndpoint:         "https://mdm.example.com/api",
			MDMCacheHours:       12,
		},
		Integrations: IntegrationsConfig{
			AdminSSO: AdminSSOConfig{
				Enabled:     true,
				Provider:    "oidc",
				IssuerURL:   "https://idp.example.com/.well-known/openid-configuration",
				ClientID:    "aegisnas-admin",
				RedirectURL: "https://admin.example.com/auth/callback",
				GroupsClaim: "groups",
			},
			SIEM: SIEMConfig{
				Enabled:   true,
				Provider:  "webhook",
				Endpoint:  "https://siem.example.com/collect",
				APIKeyEnv: "AEGIS_SIEM_API_KEY",
				BatchSize: 100,
			},
			Controller: ControllerConfig{
				Enabled:     true,
				Platform:    "aruba",
				Endpoint:    "https://controller.example.com/api",
				APITokenEnv: "AEGIS_CONTROLLER_API_TOKEN",
				SyncMode:    "monitor",
			},
		},
		Governance: GovernanceConfig{
			DelegatedAdminEnabled: true,
			RBACMode:              "hybrid",
			ExternalGroupsEnabled: true,
			MultiTenantEnabled:    false,
		},
		AILite: AILiteConfig{
			Enabled: true,
			Mode:    "full",
		},
		Radius: RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
			Upstream: RadiusUpstreamConfig{
				Enabled:     true,
				StatusCheck: "none",
				Servers: []RadiusHomeServer{
					{Name: "primary", Address: "10.0.0.10", Secret: "secret"},
				},
			},
		},
		Wireless: WirelessConfig{
			Enabled: true,
		},
	}

	capabilities := EvaluateFeatureCapabilities(cfg)
	require.Len(t, capabilities, 21)

	byKey := make(map[string]FeatureCapability, len(capabilities))
	for _, capability := range capabilities {
		byKey[capability.Key] = capability
	}

	assert.Equal(t, CapabilityBlocked, byKey["local_wireless"].State)
	assert.Equal(t, CapabilityEnabled, byKey["runtime_shaping"].State)
	assert.Equal(t, CapabilityBlocked, byKey["ai_mode"].State)
	assert.Equal(t, CapabilityEnabled, byKey["telemetry"].State)
	assert.Equal(t, CapabilityWarned, byKey["upstream_status_probes"].State)
	assert.Equal(t, CapabilityWarned, byKey["guest_self_registration"].State)
	assert.Equal(t, CapabilityWarned, byKey["sponsor_approval"].State)
	assert.Equal(t, CapabilityEnabled, byKey["guest_delivery"].State)
	assert.Equal(t, CapabilityWarned, byKey["device_registration_inventory"].State)
	assert.Equal(t, CapabilityWarned, byKey["onboarding_portal"].State)
	assert.Equal(t, CapabilityBlocked, byKey["certificate_enrollment"].State)
	assert.Equal(t, CapabilityBlocked, byKey["eap_tls_onboarding"].State)
	assert.Equal(t, CapabilityWarned, byKey["passive_profiling"].State)
	assert.Equal(t, CapabilityBlocked, byKey["posture_checks"].State)
	assert.Equal(t, CapabilityBlocked, byKey["mdm_uem_integration"].State)
	assert.Equal(t, CapabilityEnabled, byKey["siem_webhook_export"].State)
	assert.Equal(t, CapabilityBlocked, byKey["controller_automation"].State)
	assert.Equal(t, CapabilityBlocked, byKey["high_availability_failover"].State)
	assert.Equal(t, CapabilityWarned, byKey["admin_sso"].State)
	assert.Equal(t, CapabilityWarned, byKey["delegated_admin_rbac"].State)
	assert.Equal(t, CapabilityBlocked, byKey["multi_tenant_governance"].State)
}

func TestConfigValidationGuestWorkflows(t *testing.T) {
	base := func() *Config {
		return &Config{
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
			Portal: PortalConfig{
				Enabled:       true,
				LocalFallback: true,
				Branding:      "AegisNAS Guests",
				GuestWorkflows: PortalGuestWorkflowConfig{
					SelfRegistrationEnabled: true,
					SponsorApprovalEnabled:  true,
					InviteDelivery:          "email",
					ApprovalDelivery:        "email",
					EmailFrom:               "guests@example.com",
					SMTPServer:              "smtp.example.com",
					SMTPPort:                587,
				},
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	noFallback := base()
	noFallback.Portal.LocalFallback = false
	assert.ErrorContains(t, noFallback.Validate(), "self_registration_enabled requires portal.local_fallback")

	noApprovalDelivery := base()
	noApprovalDelivery.Portal.GuestWorkflows.ApprovalDelivery = ""
	assert.ErrorContains(t, noApprovalDelivery.Validate(), "requires approval_delivery")

	noEmailTransport := base()
	noEmailTransport.Portal.GuestWorkflows.SMTPServer = ""
	assert.ErrorContains(t, noEmailTransport.Validate(), "requires email transport configuration")

	smsInviteNoTransport := base()
	smsInviteNoTransport.Portal.GuestWorkflows.SponsorApprovalEnabled = false
	smsInviteNoTransport.Portal.GuestWorkflows.ApprovalDelivery = ""
	smsInviteNoTransport.Portal.GuestWorkflows.InviteDelivery = "sms"
	assert.ErrorContains(t, smsInviteNoTransport.Validate(), "invite_delivery=sms requires sms transport configuration")

	smsReady := base()
	smsReady.Portal.GuestWorkflows.ApprovalDelivery = "sms"
	smsReady.Portal.GuestWorkflows.InviteDelivery = "sms"
	smsReady.Portal.GuestWorkflows.SMSProvider = "twilio-like"
	smsReady.Portal.GuestWorkflows.SMSEndpoint = "https://sms.example.com/send"
	smsReady.Portal.GuestWorkflows.EmailFrom = ""
	smsReady.Portal.GuestWorkflows.SMTPServer = ""
	smsReady.Portal.GuestWorkflows.SMTPPort = 0
	assert.NoError(t, smsReady.Validate())

	liteBlocked := base()
	liteBlocked.Deployment.Profile = "lite"
	assert.ErrorContains(t, liteBlocked.Validate(), "self_registration_enabled is not supported on the lite deployment profile")
}

func TestConfigValidationOnboardingAndProfiling(t *testing.T) {
	base := func() *Config {
		return &Config{
			Mode:      "two-nic",
			WAN:       InterfaceConfig{Name: "eth0"},
			LAN:       InterfaceConfig{Name: "eth1"},
			Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
			Health:    HealthConfig{Port: 8080},
			Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
			Portal: PortalConfig{
				Enabled:       true,
				LocalFallback: true,
				Branding:      "AegisNAS Onboarding",
			},
			Radius: RadiusConfig{
				AuthPort:              1812,
				AcctPort:              1813,
				RequestTimeoutSeconds: 5,
				EAP: RadiusEAPConfig{
					DefaultType: "tls",
				},
			},
			Deployment: DeploymentConfig{
				Profile: "enterprise",
			},
			Onboarding: OnboardingConfig{
				DeviceInventoryEnabled:       true,
				PortalEnabled:                true,
				CertificateEnrollmentEnabled: true,
				EAPTLSEnabled:                true,
				CAMode:                       "internal",
				CACertPath:                   "/etc/aegisnas/pki/ca.crt",
				CAKeyPath:                    "/etc/aegisnas/pki/ca.key",
			},
			Profiling: ProfilingConfig{
				MACInventoryEnabled: true,
				PassiveEnabled:      true,
				PollIntervalSeconds: 300,
				RetentionHours:      24,
				PostureEnabled:      true,
				MDMSyncEnabled:      true,
				MDMProvider:         "workspace-one-like",
				MDMEndpoint:         "https://mdm.example.com/api",
				MDMCacheHours:       12,
			},
			Integrations: IntegrationsConfig{
				AdminSSO: AdminSSOConfig{
					Enabled:     true,
					Provider:    "oidc",
					IssuerURL:   "https://idp.example.com/.well-known/openid-configuration",
					ClientID:    "aegisnas-admin",
					RedirectURL: "https://admin.example.com/auth/callback",
					GroupsClaim: "groups",
				},
				SIEM: SIEMConfig{
					Enabled:   true,
					Provider:  "webhook",
					Endpoint:  "https://siem.example.com/collect",
					APIKeyEnv: "AEGIS_SIEM_API_KEY",
					BatchSize: 100,
				},
				Controller: ControllerConfig{
					Enabled:     true,
					Platform:    "aruba",
					Endpoint:    "https://controller.example.com/api",
					APITokenEnv: "AEGIS_CONTROLLER_API_TOKEN",
					SyncMode:    "monitor",
				},
			},
			Governance: GovernanceConfig{
				DelegatedAdminEnabled: true,
				RBACMode:              "hybrid",
				ExternalGroupsEnabled: true,
				MultiTenantEnabled:    true,
				TenantClaim:           "tenant",
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	noCA := base()
	noCA.Onboarding.CACertPath = ""
	assert.ErrorContains(t, noCA.Validate(), "requires complete CA configuration")

	noIdentity := base()
	noIdentity.Portal.LocalFallback = false
	assert.ErrorContains(t, noIdentity.Validate(), "requires an identity path")

	branchCert := base()
	branchCert.Deployment.Profile = "branch"
	assert.ErrorContains(t, branchCert.Validate(), "certificate_enrollment_enabled is only supported on the enterprise deployment profile")

	badTLS := base()
	badTLS.Radius.EAP.DefaultType = "peap"
	assert.ErrorContains(t, badTLS.Validate(), "requires radius.eap.default_type to be tls")

	badPolling := base()
	badPolling.Profiling.PollIntervalSeconds = 10
	assert.ErrorContains(t, badPolling.Validate(), "profiling.passive_enabled requires profiling.poll_interval_seconds to be at least 30")

	noComplianceSource := base()
	noComplianceSource.Profiling.MDMSyncEnabled = false
	noComplianceSource.Profiling.MDMProvider = ""
	noComplianceSource.Profiling.MDMEndpoint = ""
	assert.ErrorContains(t, noComplianceSource.Validate(), "profiling.posture_enabled requires an MDM endpoint or compliance webhook")
}

func TestConfigValidationPhase4Integrations(t *testing.T) {
	base := func() *Config {
		return &Config{
			Mode:      "two-nic",
			WAN:       InterfaceConfig{Name: "eth0"},
			LAN:       InterfaceConfig{Name: "eth1"},
			Database:  DatabaseConfig{Path: "/tmp/aegis.db"},
			Health:    HealthConfig{Port: 8080},
			Telemetry: TelemetryConfig{Enabled: true, PrometheusPort: 9090},
			Portal: PortalConfig{
				Enabled: true,
			},
			Radius: RadiusConfig{
				AuthPort:              1812,
				AcctPort:              1813,
				RequestTimeoutSeconds: 5,
			},
			Deployment: DeploymentConfig{
				Profile: "enterprise",
				Hardware: DeploymentHardwareConfig{
					MemoryMB:         16384,
					CPUCores:         8,
					PreferExternalAP: true,
				},
			},
			Profiling: ProfilingConfig{
				MDMSyncEnabled: true,
				MDMProvider:    "workspace-one-like",
				MDMEndpoint:    "https://mdm.example.com/api",
				MDMCacheHours:  12,
			},
			Integrations: IntegrationsConfig{
				AdminSSO: AdminSSOConfig{
					Enabled:     true,
					Provider:    "oidc",
					IssuerURL:   "https://idp.example.com/.well-known/openid-configuration",
					ClientID:    "aegisnas-admin",
					RedirectURL: "https://admin.example.com/auth/callback",
					GroupsClaim: "groups",
				},
				SIEM: SIEMConfig{
					Enabled:   true,
					Provider:  "webhook",
					Endpoint:  "https://siem.example.com/collect",
					APIKeyEnv: "AEGIS_SIEM_API_KEY",
					BatchSize: 100,
				},
				Controller: ControllerConfig{
					Enabled:     true,
					Platform:    "aruba",
					Endpoint:    "https://controller.example.com/api",
					APITokenEnv: "AEGIS_CONTROLLER_API_TOKEN",
					SyncMode:    "monitor",
				},
			},
			Governance: GovernanceConfig{
				DelegatedAdminEnabled: true,
				RBACMode:              "hybrid",
				ExternalGroupsEnabled: true,
				MultiTenantEnabled:    true,
				TenantClaim:           "tenant",
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	liteSSO := base()
	liteSSO.Deployment.Profile = "lite"
	liteSSO.Profiling.MDMSyncEnabled = false
	assert.ErrorContains(t, liteSSO.Validate(), "integrations.admin_sso.enabled is not supported on the lite deployment profile")

	branchMDM := base()
	branchMDM.Deployment.Profile = "branch"
	assert.ErrorContains(t, branchMDM.Validate(), "profiling.mdm_sync_enabled is only supported on the enterprise deployment profile")

	badController := base()
	badController.Wireless.Enabled = true
	badController.Wireless.Interface = "wlan0"
	badController.Wireless.CountryCode = "US"
	badController.Wireless.HWMode = "g"
	badController.Wireless.Channel = 6
	badController.Wireless.BeaconInterval = 100
	badController.Wireless.SSIDs = []SSIDConfig{{Name: "Guest", AuthMode: "captive-portal"}}
	assert.ErrorContains(t, badController.Validate(), "requires the external AP model")

	badDelegation := base()
	badDelegation.Integrations.AdminSSO.Enabled = false
	assert.ErrorContains(t, badDelegation.Validate(), "governance.delegated_admin_enabled requires integrations.admin_sso.enabled or ldap.enabled")

	badSIEM := base()
	badSIEM.Integrations.SIEM.APIKeyEnv = ""
	assert.ErrorContains(t, badSIEM.Validate(), "integrations.siem.enabled requires provider, endpoint, api_key_env, and positive batch_size")

	badTenant := base()
	badTenant.Governance.TenantClaim = ""
	assert.ErrorContains(t, badTenant.Validate(), "governance.multi_tenant_enabled requires governance.tenant_claim when admin SSO is enabled")
}

func TestConfigValidationHighAvailability(t *testing.T) {
	base := func() *Config {
		return &Config{
			Mode:     "two-nic",
			WAN:      InterfaceConfig{Name: "eth0"},
			LAN:      InterfaceConfig{Name: "eth1"},
			Database: DatabaseConfig{Path: "/tmp/aegis.db"},
			Health:   HealthConfig{Port: 8080},
			Telemetry: TelemetryConfig{
				Enabled:        true,
				PrometheusPort: 9090,
			},
			Portal: PortalConfig{
				Enabled: true,
			},
			Radius: RadiusConfig{
				AuthPort:              1812,
				AcctPort:              1813,
				RequestTimeoutSeconds: 5,
			},
			Deployment: DeploymentConfig{
				Profile: "enterprise",
				Hardware: DeploymentHardwareConfig{
					MemoryMB: 8192,
					CPUCores: 4,
				},
			},
			HighAvailability: HighAvailabilityConfig{
				Enabled:                      true,
				Role:                         "standby",
				PeerAPIURL:                   "https://peer.example.com:8083",
				VirtualIP:                    "192.168.50.2",
				HeartbeatIntervalSeconds:     5,
				FailoverTimeoutSeconds:       20,
				ReplicationIntervalSeconds:   300,
				ReplicationStaleAfterSeconds: 900,
				SharedStateDir:               "/var/lib/aegisnas/ha",
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	badProfile := base()
	badProfile.Deployment.Profile = "branch"
	assert.ErrorContains(t, badProfile.Validate(), "high_availability.enabled is only supported on the enterprise deployment profile")

	badPeer := base()
	badPeer.HighAvailability.PeerAPIURL = ""
	assert.ErrorContains(t, badPeer.Validate(), "high_availability.enabled requires role, peer_api_url, virtual_ip, and positive heartbeat/failover timers")

	badTiming := base()
	badTiming.HighAvailability.FailoverTimeoutSeconds = 5
	assert.ErrorContains(t, badTiming.Validate(), "high_availability.failover_timeout_seconds must be greater")

	badVIP := base()
	badVIP.HighAvailability.VirtualIP = "not-an-ip"
	assert.ErrorContains(t, badVIP.Validate(), "high_availability.virtual_ip")

	badReplication := base()
	badReplication.HighAvailability.ReplicationStaleAfterSeconds = 120
	badReplication.HighAvailability.ReplicationIntervalSeconds = 120
	assert.ErrorContains(t, badReplication.Validate(), "high_availability.replication_stale_after_seconds must be greater")
}
