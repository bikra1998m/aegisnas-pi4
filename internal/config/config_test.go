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
				SplitBrainProtectionEnabled:  true,
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

	badAutoStage := base()
	badAutoStage.HighAvailability.Enabled = false
	badAutoStage.HighAvailability.AutoStageSharedPackage = true
	assert.ErrorContains(t, badAutoStage.Validate(), "high_availability.auto_stage_shared_package requires high_availability.enabled")

	badAutoActivate := base()
	badAutoActivate.HighAvailability.Enabled = false
	badAutoActivate.HighAvailability.AutoActivateOnFailover = true
	assert.ErrorContains(t, badAutoActivate.Validate(), "high_availability.auto_activate_on_failover requires high_availability.enabled")

	badHoldoff := base()
	badHoldoff.HighAvailability.PreemptHoldoffSeconds = -1
	assert.ErrorContains(t, badHoldoff.Validate(), "high_availability.preempt_holdoff_seconds -1 cannot be negative")

	badWitness := base()
	badWitness.HighAvailability.Enabled = false
	badWitness.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	assert.ErrorContains(t, badWitness.Validate(), "high_availability.witness_api_url requires high_availability.enabled")

	badWitnessMode := base()
	badWitnessMode.HighAvailability.SplitBrainProtectionEnabled = false
	badWitnessMode.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	assert.ErrorContains(t, badWitnessMode.Validate(), "high_availability.witness_api_url requires high_availability.split_brain_protection_enabled")

	badWitnessURL := base()
	badWitnessURL.HighAvailability.WitnessAPIURL = "not-a-url"
	assert.ErrorContains(t, badWitnessURL.Validate(), "high_availability.witness_urls[0]")

	badWitnessToken := base()
	badWitnessToken.HighAvailability.Enabled = false
	badWitnessToken.HighAvailability.WitnessTokenEnv = "AEGIS_HA_WITNESS_TOKEN"
	assert.ErrorContains(t, badWitnessToken.Validate(), "high_availability.witness_token_env requires high_availability.enabled")

	badWitnessTokenNoURL := base()
	badWitnessTokenNoURL.HighAvailability.WitnessAPIURL = ""
	badWitnessTokenNoURL.HighAvailability.WitnessTokenEnv = "AEGIS_HA_WITNESS_TOKEN"
	assert.ErrorContains(t, badWitnessTokenNoURL.Validate(), "high_availability.witness_token_env requires high_availability.witness_api_url")

	badWitnessSigning := base()
	badWitnessSigning.HighAvailability.Enabled = false
	badWitnessSigning.HighAvailability.WitnessSigningKeyEnv = "AEGIS_HA_WITNESS_SIGNING_KEY"
	assert.ErrorContains(t, badWitnessSigning.Validate(), "high_availability.witness_signing_key_env requires high_availability.enabled")

	badWitnessSigningNoURL := base()
	badWitnessSigningNoURL.HighAvailability.WitnessAPIURL = ""
	badWitnessSigningNoURL.HighAvailability.WitnessSigningKeyEnv = "AEGIS_HA_WITNESS_SIGNING_KEY"
	assert.ErrorContains(t, badWitnessSigningNoURL.Validate(), "high_availability.witness_signing_key_env requires high_availability.witness_api_url")

	badWitnessAge := base()
	badWitnessAge.HighAvailability.WitnessMaxAgeSeconds = -1
	assert.ErrorContains(t, badWitnessAge.Validate(), "high_availability.witness_max_age_seconds")

	badWitnessAgeDisabled := base()
	badWitnessAgeDisabled.HighAvailability.Enabled = false
	badWitnessAgeDisabled.HighAvailability.WitnessMaxAgeSeconds = 30
	assert.ErrorContains(t, badWitnessAgeDisabled.Validate(), "high_availability.witness_max_age_seconds requires high_availability.enabled")

	badWitnessAgeNoURL := base()
	badWitnessAgeNoURL.HighAvailability.WitnessAPIURL = ""
	badWitnessAgeNoURL.HighAvailability.WitnessMaxAgeSeconds = 30
	assert.ErrorContains(t, badWitnessAgeNoURL.Validate(), "high_availability.witness_max_age_seconds requires high_availability.witness_api_url")

	badWitnessNode := base()
	badWitnessNode.HighAvailability.Enabled = false
	badWitnessNode.HighAvailability.WitnessRequiredNode = "witness-1"
	assert.ErrorContains(t, badWitnessNode.Validate(), "high_availability.witness_required_node requires high_availability.enabled")

	badWitnessNodeNoURL := base()
	badWitnessNodeNoURL.HighAvailability.WitnessAPIURL = ""
	badWitnessNodeNoURL.HighAvailability.WitnessRequiredNode = "witness-1"
	assert.ErrorContains(t, badWitnessNodeNoURL.Validate(), "high_availability.witness_required_node requires high_availability.witness_api_url")

	badWitnessQuorum := base()
	badWitnessQuorum.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessQuorum.HighAvailability.WitnessQuorum = 2
	assert.ErrorContains(t, badWitnessQuorum.Validate(), "high_availability.witness_quorum 2 cannot exceed configured witness count 1")

	badWitnessQuorumZero := base()
	badWitnessQuorumZero.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessQuorumZero.HighAvailability.WitnessQuorum = 0
	assert.ErrorContains(t, badWitnessQuorumZero.Validate(), "high_availability.witness_quorum 0 must be at least 1")

	badWitnessWeightNegative := base()
	badWitnessWeightNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessWeightNegative.HighAvailability.WitnessQuorum = 1
	badWitnessWeightNegative.HighAvailability.WitnessWeightThreshold = -1
	assert.ErrorContains(t, badWitnessWeightNegative.Validate(), "high_availability.witness_weight_threshold -1 cannot be negative")

	badWitnessWeightUnknown := base()
	badWitnessWeightUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessWeightUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessWeightUnknown.HighAvailability.WitnessWeights = map[string]int{"https://witness-b.example.test/ha": 2}
	assert.ErrorContains(t, badWitnessWeightUnknown.Validate(), `high_availability.witness_weights key "https://witness-b.example.test/ha" does not match a configured witness URL`)

	badWitnessWeightZero := base()
	badWitnessWeightZero.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessWeightZero.HighAvailability.WitnessQuorum = 1
	badWitnessWeightZero.HighAvailability.WitnessWeights = map[string]int{"https://witness-a.example.test/ha": 0}
	assert.ErrorContains(t, badWitnessWeightZero.Validate(), `high_availability.witness_weights["https://witness-a.example.test/ha"] 0 must be at least 1`)

	badWitnessWeightThreshold := base()
	badWitnessWeightThreshold.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha", "https://witness-b.example.test/ha"}
	badWitnessWeightThreshold.HighAvailability.WitnessQuorum = 1
	badWitnessWeightThreshold.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 2,
		"https://witness-b.example.test/ha": 1,
	}
	badWitnessWeightThreshold.HighAvailability.WitnessWeightThreshold = 5
	assert.ErrorContains(t, badWitnessWeightThreshold.Validate(), "high_availability.witness_weight_threshold 5 cannot exceed configured witness weight 3")

	badWitnessGroupUnknown := base()
	badWitnessGroupUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessGroupUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessGroupUnknown.HighAvailability.WitnessGroups = map[string]string{"https://witness-b.example.test/ha": "dc-b"}
	assert.ErrorContains(t, badWitnessGroupUnknown.Validate(), `high_availability.witness_groups key "https://witness-b.example.test/ha" does not match a configured witness URL`)

	badWitnessGroupBlank := base()
	badWitnessGroupBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessGroupBlank.HighAvailability.WitnessQuorum = 1
	badWitnessGroupBlank.HighAvailability.WitnessGroups = map[string]string{"https://witness-a.example.test/ha": " "}
	assert.ErrorContains(t, badWitnessGroupBlank.Validate(), `high_availability.witness_groups["https://witness-a.example.test/ha"] must not be blank`)

	badWitnessGroupThresholdNegative := base()
	badWitnessGroupThresholdNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessGroupThresholdNegative.HighAvailability.WitnessQuorum = 1
	badWitnessGroupThresholdNegative.HighAvailability.WitnessMinDistinctGroups = -1
	assert.ErrorContains(t, badWitnessGroupThresholdNegative.Validate(), "high_availability.witness_min_distinct_groups -1 cannot be negative")

	badWitnessGroupThresholdTooHigh := base()
	badWitnessGroupThresholdTooHigh.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha", "https://witness-b.example.test/ha"}
	badWitnessGroupThresholdTooHigh.HighAvailability.WitnessQuorum = 1
	badWitnessGroupThresholdTooHigh.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-a",
	}
	badWitnessGroupThresholdTooHigh.HighAvailability.WitnessMinDistinctGroups = 2
	assert.ErrorContains(t, badWitnessGroupThresholdTooHigh.Validate(), "high_availability.witness_min_distinct_groups 2 cannot exceed configured witness group count 1")

	badWitnessSourceUnknown := base()
	badWitnessSourceUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessSourceUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessSourceUnknown.HighAvailability.WitnessSources = map[string]string{"https://witness-b.example.test/ha": "external"}
	assert.ErrorContains(t, badWitnessSourceUnknown.Validate(), `high_availability.witness_sources key "https://witness-b.example.test/ha" does not match a configured witness URL`)

	badWitnessSourceBlank := base()
	badWitnessSourceBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessSourceBlank.HighAvailability.WitnessQuorum = 1
	badWitnessSourceBlank.HighAvailability.WitnessSources = map[string]string{"https://witness-a.example.test/ha": " "}
	assert.ErrorContains(t, badWitnessSourceBlank.Validate(), `high_availability.witness_sources["https://witness-a.example.test/ha"] must not be blank`)

	badWitnessRequiredSourceBlank := base()
	badWitnessRequiredSourceBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredSourceBlank.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredSourceBlank.HighAvailability.WitnessRequiredSources = []string{" "}
	assert.ErrorContains(t, badWitnessRequiredSourceBlank.Validate(), "high_availability.witness_required_sources entries must not be blank")

	badWitnessRequiredSourceUnknown := base()
	badWitnessRequiredSourceUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredSourceUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredSourceUnknown.HighAvailability.WitnessSources = map[string]string{"https://witness-a.example.test/ha": "local"}
	badWitnessRequiredSourceUnknown.HighAvailability.WitnessRequiredSources = []string{"external"}
	assert.ErrorContains(t, badWitnessRequiredSourceUnknown.Validate(), `high_availability.witness_required_sources entry "external" does not match a configured witness source`)

	badWitnessConfidenceSourceUnknown := base()
	badWitnessConfidenceSourceUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessConfidenceSourceUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessConfidenceSourceUnknown.HighAvailability.WitnessSourceConfidence = map[string]string{"external": "critical"}
	assert.ErrorContains(t, badWitnessConfidenceSourceUnknown.Validate(), `high_availability.witness_source_confidence key "external" does not match a configured witness source`)

	badWitnessConfidenceTierBlank := base()
	badWitnessConfidenceTierBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessConfidenceTierBlank.HighAvailability.WitnessQuorum = 1
	badWitnessConfidenceTierBlank.HighAvailability.WitnessSourceConfidence = map[string]string{"https://witness-a.example.test/ha": " "}
	assert.ErrorContains(t, badWitnessConfidenceTierBlank.Validate(), `high_availability.witness_source_confidence["https://witness-a.example.test/ha"] must not be blank`)

	badWitnessPolicyMode := base()
	badWitnessPolicyMode.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyMode.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyMode.HighAvailability.WitnessPolicyMode = "mystery"
	assert.ErrorContains(t, badWitnessPolicyMode.Validate(), `high_availability.witness_policy_mode "mystery" must be one of all, any, group_only, or source_only`)

	badWitnessPolicyAny := base()
	badWitnessPolicyAny.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyAny.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyAny.HighAvailability.WitnessPolicyMode = "any"
	assert.ErrorContains(t, badWitnessPolicyAny.Validate(), "high_availability.witness_policy_mode any requires witness_min_distinct_groups or witness_required_sources")

	badWitnessPolicyGroupOnly := base()
	badWitnessPolicyGroupOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyGroupOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyGroupOnly.HighAvailability.WitnessPolicyMode = "group_only"
	assert.ErrorContains(t, badWitnessPolicyGroupOnly.Validate(), "high_availability.witness_policy_mode group_only requires high_availability.witness_min_distinct_groups")

	badWitnessPolicySourceOnly := base()
	badWitnessPolicySourceOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicySourceOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicySourceOnly.HighAvailability.WitnessPolicyMode = "source_only"
	assert.ErrorContains(t, badWitnessPolicySourceOnly.Validate(), "high_availability.witness_policy_mode source_only requires high_availability.witness_required_sources")

	badWitnessFailureToleranceNegative := base()
	badWitnessFailureToleranceNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessFailureToleranceNegative.HighAvailability.WitnessQuorum = 1
	badWitnessFailureToleranceNegative.HighAvailability.WitnessFailureTolerance = -1
	assert.ErrorContains(t, badWitnessFailureToleranceNegative.Validate(), "high_availability.witness_failure_tolerance -1 cannot be negative")

	badWitnessFailureToleranceHigh := base()
	badWitnessFailureToleranceHigh.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessFailureToleranceHigh.HighAvailability.WitnessQuorum = 1
	badWitnessFailureToleranceHigh.HighAvailability.WitnessFailureTolerance = 2
	assert.ErrorContains(t, badWitnessFailureToleranceHigh.Validate(), "high_availability.witness_failure_tolerance 2 cannot exceed configured witness count 1")

	badWitnessFailureWeightToleranceNegative := base()
	badWitnessFailureWeightToleranceNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessFailureWeightToleranceNegative.HighAvailability.WitnessQuorum = 1
	badWitnessFailureWeightToleranceNegative.HighAvailability.WitnessFailureWeightTolerance = -1
	assert.ErrorContains(t, badWitnessFailureWeightToleranceNegative.Validate(), "high_availability.witness_failure_weight_tolerance -1 cannot be negative")

	badWitnessFailureWeightToleranceHigh := base()
	badWitnessFailureWeightToleranceHigh.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha", "https://witness-b.example.test/ha"}
	badWitnessFailureWeightToleranceHigh.HighAvailability.WitnessQuorum = 1
	badWitnessFailureWeightToleranceHigh.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 2,
		"https://witness-b.example.test/ha": 1,
	}
	badWitnessFailureWeightToleranceHigh.HighAvailability.WitnessFailureWeightTolerance = 4
	assert.ErrorContains(t, badWitnessFailureWeightToleranceHigh.Validate(), "high_availability.witness_failure_weight_tolerance 4 cannot exceed configured witness weight 3")

	badWitnessTierFailureToleranceUnknown := base()
	badWitnessTierFailureToleranceUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessTierFailureToleranceUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessTierFailureToleranceUnknown.HighAvailability.WitnessFailureToleranceByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessTierFailureToleranceUnknown.Validate(), `high_availability.witness_failure_tolerance_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessTierFailureToleranceNegative := base()
	badWitnessTierFailureToleranceNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessTierFailureToleranceNegative.HighAvailability.WitnessQuorum = 1
	badWitnessTierFailureToleranceNegative.HighAvailability.WitnessFailureToleranceByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessTierFailureToleranceNegative.Validate(), `high_availability.witness_failure_tolerance_by_tier["standard"] -1 cannot be negative`)

	badWitnessTierFailureWeightToleranceUnknown := base()
	badWitnessTierFailureWeightToleranceUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessTierFailureWeightToleranceUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessTierFailureWeightToleranceUnknown.HighAvailability.WitnessFailureWeightByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessTierFailureWeightToleranceUnknown.Validate(), `high_availability.witness_failure_weight_tolerance_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessTierFailureWeightToleranceNegative := base()
	badWitnessTierFailureWeightToleranceNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessTierFailureWeightToleranceNegative.HighAvailability.WitnessQuorum = 1
	badWitnessTierFailureWeightToleranceNegative.HighAvailability.WitnessFailureWeightByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessTierFailureWeightToleranceNegative.Validate(), `high_availability.witness_failure_weight_tolerance_by_tier["standard"] -1 cannot be negative`)

	badWitnessMinApprovalsUnknown := base()
	badWitnessMinApprovalsUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinApprovalsUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessMinApprovalsUnknown.HighAvailability.WitnessMinApprovalsByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessMinApprovalsUnknown.Validate(), `high_availability.witness_min_approvals_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessMinApprovalsNegative := base()
	badWitnessMinApprovalsNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinApprovalsNegative.HighAvailability.WitnessQuorum = 1
	badWitnessMinApprovalsNegative.HighAvailability.WitnessMinApprovalsByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessMinApprovalsNegative.Validate(), `high_availability.witness_min_approvals_by_tier["standard"] -1 cannot be negative`)

	badWitnessMinApprovalsTooHigh := base()
	badWitnessMinApprovalsTooHigh.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	badWitnessMinApprovalsTooHigh.HighAvailability.WitnessQuorum = 1
	badWitnessMinApprovalsTooHigh.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	badWitnessMinApprovalsTooHigh.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	badWitnessMinApprovalsTooHigh.HighAvailability.WitnessMinApprovalsByTier = map[string]int{"critical": 2}
	assert.ErrorContains(t, badWitnessMinApprovalsTooHigh.Validate(), `high_availability.witness_min_approvals_by_tier["critical"] 2 cannot exceed configured witness count 1 for that tier`)

	badWitnessMinWeightUnknown := base()
	badWitnessMinWeightUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinWeightUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessMinWeightUnknown.HighAvailability.WitnessMinWeightByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessMinWeightUnknown.Validate(), `high_availability.witness_min_weight_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessMinWeightNegative := base()
	badWitnessMinWeightNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinWeightNegative.HighAvailability.WitnessQuorum = 1
	badWitnessMinWeightNegative.HighAvailability.WitnessMinWeightByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessMinWeightNegative.Validate(), `high_availability.witness_min_weight_by_tier["standard"] -1 cannot be negative`)

	badWitnessMinWeightTooHigh := base()
	badWitnessMinWeightTooHigh.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	badWitnessMinWeightTooHigh.HighAvailability.WitnessQuorum = 1
	badWitnessMinWeightTooHigh.HighAvailability.WitnessWeights = map[string]int{
		"https://witness-a.example.test/ha": 2,
		"https://witness-b.example.test/ha": 1,
	}
	badWitnessMinWeightTooHigh.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	badWitnessMinWeightTooHigh.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	badWitnessMinWeightTooHigh.HighAvailability.WitnessMinWeightByTier = map[string]int{"critical": 3}
	assert.ErrorContains(t, badWitnessMinWeightTooHigh.Validate(), `high_availability.witness_min_weight_by_tier["critical"] 3 cannot exceed configured witness weight 2 for that tier`)

	badWitnessBlockingTierUnknown := base()
	badWitnessBlockingTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessBlockingTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessBlockingTierUnknown.HighAvailability.WitnessBlockingTiers = []string{"critical"}
	assert.ErrorContains(t, badWitnessBlockingTierUnknown.Validate(), `high_availability.witness_blocking_tiers entry "critical" does not match a configured witness confidence tier`)

	badWitnessReplayDisabled := base()
	badWitnessReplayDisabled.HighAvailability.Enabled = false
	badWitnessReplayDisabled.HighAvailability.WitnessReplayProtectionEnabled = true
	assert.ErrorContains(t, badWitnessReplayDisabled.Validate(), "high_availability.witness_replay_protection_enabled requires high_availability.enabled")

	badWitnessReplayNoURL := base()
	badWitnessReplayNoURL.HighAvailability.WitnessAPIURL = ""
	badWitnessReplayNoURL.HighAvailability.WitnessReplayProtectionEnabled = true
	assert.ErrorContains(t, badWitnessReplayNoURL.Validate(), "high_availability.witness_replay_protection_enabled requires high_availability.witness_api_url")

	badWitnessReplayNoSigning := base()
	badWitnessReplayNoSigning.HighAvailability.WitnessAPIURL = "https://witness.example.test/ha"
	badWitnessReplayNoSigning.HighAvailability.WitnessQuorum = 1
	badWitnessReplayNoSigning.HighAvailability.WitnessSigningKeyEnv = ""
	badWitnessReplayNoSigning.HighAvailability.WitnessReplayProtectionEnabled = true
	assert.ErrorContains(t, badWitnessReplayNoSigning.Validate(), "high_availability.witness_replay_protection_enabled requires high_availability.witness_signing_key_env")

	badSigning := base()
	badSigning.HighAvailability.Enabled = false
	badSigning.HighAvailability.ReplicationSigningKeyEnv = "AEGIS_HA_REPLICATION_SIGNING_KEY"
	assert.ErrorContains(t, badSigning.Validate(), "high_availability.replication_signing_key_env requires high_availability.enabled")

	badEncryption := base()
	badEncryption.HighAvailability.Enabled = false
	badEncryption.HighAvailability.ReplicationEncryptionKeyEnv = "AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
	assert.ErrorContains(t, badEncryption.Validate(), "high_availability.replication_encryption_key_env requires high_availability.enabled")
}
