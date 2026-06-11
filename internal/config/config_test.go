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
					Site:        "branch-lab",
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

	badMDMProvider := base()
	badMDMProvider.Profiling.MDMProvider = "mystery-mdm"
	assert.ErrorContains(t, badMDMProvider.Validate(), `profiling.mdm_provider "mystery-mdm" is invalid`)
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
					Site:        "branch-lab",
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

	missingVendorSite := base()
	missingVendorSite.Integrations.Controller.Site = ""
	assert.ErrorContains(t, missingVendorSite.Validate(), `integrations.controller.site is required for platform "aruba"`)

	genericWithoutSite := base()
	genericWithoutSite.Integrations.Controller.Platform = "generic"
	genericWithoutSite.Integrations.Controller.Site = ""
	assert.NoError(t, genericWithoutSite.Validate())

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

	badWitnessAgeByTierUnknown := base()
	badWitnessAgeByTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessAgeByTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessAgeByTierUnknown.HighAvailability.WitnessMaxAgeByTier = map[string]int{"critical": 10}
	assert.ErrorContains(t, badWitnessAgeByTierUnknown.Validate(), `high_availability.witness_max_age_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessAgeByTierNegative := base()
	badWitnessAgeByTierNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessAgeByTierNegative.HighAvailability.WitnessQuorum = 1
	badWitnessAgeByTierNegative.HighAvailability.WitnessMaxAgeByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessAgeByTierNegative.Validate(), `high_availability.witness_max_age_by_tier["standard"] -1 cannot be negative`)

	badWitnessNodeByTierUnknown := base()
	badWitnessNodeByTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessNodeByTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessNodeByTierUnknown.HighAvailability.WitnessRequiredNodeByTier = map[string]string{"critical": "witness-a"}
	assert.ErrorContains(t, badWitnessNodeByTierUnknown.Validate(), `high_availability.witness_required_node_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessNodeByTierBlank := base()
	badWitnessNodeByTierBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessNodeByTierBlank.HighAvailability.WitnessQuorum = 1
	badWitnessNodeByTierBlank.HighAvailability.WitnessRequiredNodeByTier = map[string]string{"standard": " "}
	assert.ErrorContains(t, badWitnessNodeByTierBlank.Validate(), `high_availability.witness_required_node_by_tier["standard"] must not be blank`)

	badWitnessSignatureTierUnknown := base()
	badWitnessSignatureTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessSignatureTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessSignatureTierUnknown.HighAvailability.WitnessSigningKeyEnv = "AEGIS_WITNESS_SIGNING_KEY"
	badWitnessSignatureTierUnknown.HighAvailability.WitnessSignatureRequiredTiers = []string{"critical"}
	assert.ErrorContains(t, badWitnessSignatureTierUnknown.Validate(), `high_availability.witness_signature_required_tiers entry "critical" does not match a configured witness confidence tier`)

	badWitnessSignatureTierBlank := base()
	badWitnessSignatureTierBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessSignatureTierBlank.HighAvailability.WitnessQuorum = 1
	badWitnessSignatureTierBlank.HighAvailability.WitnessSigningKeyEnv = "AEGIS_WITNESS_SIGNING_KEY"
	badWitnessSignatureTierBlank.HighAvailability.WitnessSignatureRequiredTiers = []string{" "}
	assert.ErrorContains(t, badWitnessSignatureTierBlank.Validate(), "high_availability.witness_signature_required_tiers entries must not be blank")

	badWitnessReplayTierUnknown := base()
	badWitnessReplayTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessReplayTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessReplayTierUnknown.HighAvailability.WitnessSigningKeyEnv = "AEGIS_WITNESS_SIGNING_KEY"
	badWitnessReplayTierUnknown.HighAvailability.WitnessReplayRequiredTiers = []string{"critical"}
	assert.ErrorContains(t, badWitnessReplayTierUnknown.Validate(), `high_availability.witness_replay_required_tiers entry "critical" does not match a configured witness confidence tier`)

	badWitnessReplayTierBlank := base()
	badWitnessReplayTierBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessReplayTierBlank.HighAvailability.WitnessQuorum = 1
	badWitnessReplayTierBlank.HighAvailability.WitnessSigningKeyEnv = "AEGIS_WITNESS_SIGNING_KEY"
	badWitnessReplayTierBlank.HighAvailability.WitnessReplayRequiredTiers = []string{" "}
	assert.ErrorContains(t, badWitnessReplayTierBlank.Validate(), "high_availability.witness_replay_required_tiers entries must not be blank")

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

	badWitnessRequiredGroupBlank := base()
	badWitnessRequiredGroupBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredGroupBlank.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredGroupBlank.HighAvailability.WitnessGroups = map[string]string{"https://witness-a.example.test/ha": "dc-a"}
	badWitnessRequiredGroupBlank.HighAvailability.WitnessRequiredGroups = []string{" "}
	assert.ErrorContains(t, badWitnessRequiredGroupBlank.Validate(), "high_availability.witness_required_groups entries must not be blank")

	badWitnessRequiredGroupUnknown := base()
	badWitnessRequiredGroupUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredGroupUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredGroupUnknown.HighAvailability.WitnessGroups = map[string]string{"https://witness-a.example.test/ha": "dc-a"}
	badWitnessRequiredGroupUnknown.HighAvailability.WitnessRequiredGroups = []string{"dc-b"}
	assert.ErrorContains(t, badWitnessRequiredGroupUnknown.Validate(), `high_availability.witness_required_groups entry "dc-b" does not match a configured witness group`)

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

	badWitnessRequiredURLBlank := base()
	badWitnessRequiredURLBlank.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredURLBlank.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredURLBlank.HighAvailability.WitnessRequiredURLs = []string{" "}
	assert.ErrorContains(t, badWitnessRequiredURLBlank.Validate(), "high_availability.witness_required_urls entries must not be blank")

	badWitnessRequiredURLUnknown := base()
	badWitnessRequiredURLUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredURLUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredURLUnknown.HighAvailability.WitnessRequiredURLs = []string{"https://witness-b.example.test/ha"}
	assert.ErrorContains(t, badWitnessRequiredURLUnknown.Validate(), `high_availability.witness_required_urls entry "https://witness-b.example.test/ha" does not match a configured witness URL`)

	badWitnessRequiredSourceByTierUnknownTier := base()
	badWitnessRequiredSourceByTierUnknownTier.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredSourceByTierUnknownTier.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredSourceByTierUnknownTier.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
	}
	badWitnessRequiredSourceByTierUnknownTier.HighAvailability.WitnessRequiredSourcesByTier = map[string][]string{
		"critical": {"local"},
	}
	assert.ErrorContains(t, badWitnessRequiredSourceByTierUnknownTier.Validate(), `high_availability.witness_required_sources_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessRequiredSourceByTierBlankEntry := base()
	badWitnessRequiredSourceByTierBlankEntry.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredSourceByTierBlankEntry.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredSourceByTierBlankEntry.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
	}
	badWitnessRequiredSourceByTierBlankEntry.HighAvailability.WitnessRequiredSourcesByTier = map[string][]string{
		"standard": {" "},
	}
	assert.ErrorContains(t, badWitnessRequiredSourceByTierBlankEntry.Validate(), `high_availability.witness_required_sources_by_tier["standard"] entries must not be blank`)

	badWitnessRequiredSourceByTierUnknownSource := base()
	badWitnessRequiredSourceByTierUnknownSource.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredSourceByTierUnknownSource.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredSourceByTierUnknownSource.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
	}
	badWitnessRequiredSourceByTierUnknownSource.HighAvailability.WitnessRequiredSourcesByTier = map[string][]string{
		"standard": {"external"},
	}
	assert.ErrorContains(t, badWitnessRequiredSourceByTierUnknownSource.Validate(), `high_availability.witness_required_sources_by_tier["standard"] entry "external" does not match a configured witness source`)

	badWitnessRequiredURLByTierUnknownTier := base()
	badWitnessRequiredURLByTierUnknownTier.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredURLByTierUnknownTier.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredURLByTierUnknownTier.HighAvailability.WitnessRequiredURLsByTier = map[string][]string{
		"critical": {"https://witness-a.example.test/ha"},
	}
	assert.ErrorContains(t, badWitnessRequiredURLByTierUnknownTier.Validate(), `high_availability.witness_required_urls_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessRequiredURLByTierBlankEntry := base()
	badWitnessRequiredURLByTierBlankEntry.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredURLByTierBlankEntry.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredURLByTierBlankEntry.HighAvailability.WitnessRequiredURLsByTier = map[string][]string{
		"standard": {" "},
	}
	assert.ErrorContains(t, badWitnessRequiredURLByTierBlankEntry.Validate(), `high_availability.witness_required_urls_by_tier["standard"] entries must not be blank`)

	badWitnessRequiredURLByTierUnknownURL := base()
	badWitnessRequiredURLByTierUnknownURL.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredURLByTierUnknownURL.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredURLByTierUnknownURL.HighAvailability.WitnessRequiredURLsByTier = map[string][]string{
		"standard": {"https://witness-b.example.test/ha"},
	}
	assert.ErrorContains(t, badWitnessRequiredURLByTierUnknownURL.Validate(), `high_availability.witness_required_urls_by_tier["standard"] entry "https://witness-b.example.test/ha" does not match a configured witness URL`)

	badWitnessRequiredGroupByTierUnknownTier := base()
	badWitnessRequiredGroupByTierUnknownTier.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredGroupByTierUnknownTier.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredGroupByTierUnknownTier.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
	}
	badWitnessRequiredGroupByTierUnknownTier.HighAvailability.WitnessRequiredGroupsByTier = map[string][]string{
		"critical": {"dc-a"},
	}
	assert.ErrorContains(t, badWitnessRequiredGroupByTierUnknownTier.Validate(), `high_availability.witness_required_groups_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessRequiredGroupByTierBlankEntry := base()
	badWitnessRequiredGroupByTierBlankEntry.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredGroupByTierBlankEntry.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredGroupByTierBlankEntry.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
	}
	badWitnessRequiredGroupByTierBlankEntry.HighAvailability.WitnessRequiredGroupsByTier = map[string][]string{
		"standard": {" "},
	}
	assert.ErrorContains(t, badWitnessRequiredGroupByTierBlankEntry.Validate(), `high_availability.witness_required_groups_by_tier["standard"] entries must not be blank`)

	badWitnessRequiredGroupByTierUnknownGroup := base()
	badWitnessRequiredGroupByTierUnknownGroup.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessRequiredGroupByTierUnknownGroup.HighAvailability.WitnessQuorum = 1
	badWitnessRequiredGroupByTierUnknownGroup.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
	}
	badWitnessRequiredGroupByTierUnknownGroup.HighAvailability.WitnessRequiredGroupsByTier = map[string][]string{
		"standard": {"dc-b"},
	}
	assert.ErrorContains(t, badWitnessRequiredGroupByTierUnknownGroup.Validate(), `high_availability.witness_required_groups_by_tier["standard"] entry "dc-b" does not match a configured witness group`)

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
	assert.ErrorContains(t, badWitnessPolicyMode.Validate(), `high_availability.witness_policy_mode "mystery" must be one of all, any, group_only, source_only, or url_only`)

	badWitnessPolicyAny := base()
	badWitnessPolicyAny.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyAny.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyAny.HighAvailability.WitnessPolicyMode = "any"
	assert.ErrorContains(t, badWitnessPolicyAny.Validate(), "high_availability.witness_policy_mode any requires witness_min_distinct_groups, witness_required_groups, witness_required_sources, or witness_required_urls")

	badWitnessPolicyGroupOnly := base()
	badWitnessPolicyGroupOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyGroupOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyGroupOnly.HighAvailability.WitnessPolicyMode = "group_only"
	assert.ErrorContains(t, badWitnessPolicyGroupOnly.Validate(), "high_availability.witness_policy_mode group_only requires high_availability.witness_min_distinct_groups or high_availability.witness_required_groups")

	badWitnessPolicySourceOnly := base()
	badWitnessPolicySourceOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicySourceOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicySourceOnly.HighAvailability.WitnessPolicyMode = "source_only"
	assert.ErrorContains(t, badWitnessPolicySourceOnly.Validate(), "high_availability.witness_policy_mode source_only requires high_availability.witness_required_sources")

	badWitnessPolicyURLOnly := base()
	badWitnessPolicyURLOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyURLOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyURLOnly.HighAvailability.WitnessPolicyMode = "url_only"
	assert.ErrorContains(t, badWitnessPolicyURLOnly.Validate(), "high_availability.witness_policy_mode url_only requires high_availability.witness_required_urls")

	badWitnessPolicyModeByTierUnknownTier := base()
	badWitnessPolicyModeByTierUnknownTier.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierUnknownTier.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierUnknownTier.HighAvailability.WitnessPolicyModeByTier = map[string]string{"critical": "all"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierUnknownTier.Validate(), `high_availability.witness_policy_mode_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessPolicyModeByTierInvalid := base()
	badWitnessPolicyModeByTierInvalid.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierInvalid.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierInvalid.HighAvailability.WitnessPolicyModeByTier = map[string]string{"standard": "mystery"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierInvalid.Validate(), `high_availability.witness_policy_mode_by_tier["standard"] "mystery" must be one of all, any, group_only, source_only, or url_only`)

	badWitnessPolicyModeByTierAny := base()
	badWitnessPolicyModeByTierAny.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierAny.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierAny.HighAvailability.WitnessPolicyModeByTier = map[string]string{"standard": "any"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierAny.Validate(), `high_availability.witness_policy_mode_by_tier["standard"] any requires high_availability.witness_min_distinct_groups_by_tier, high_availability.witness_required_groups_by_tier, high_availability.witness_min_distinct_sources_by_tier, high_availability.witness_required_sources_by_tier, or high_availability.witness_required_urls_by_tier`)

	badWitnessPolicyModeByTierGroupOnly := base()
	badWitnessPolicyModeByTierGroupOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierGroupOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierGroupOnly.HighAvailability.WitnessPolicyModeByTier = map[string]string{"standard": "group_only"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierGroupOnly.Validate(), `high_availability.witness_policy_mode_by_tier["standard"] group_only requires high_availability.witness_min_distinct_groups_by_tier or high_availability.witness_required_groups_by_tier`)

	badWitnessPolicyModeByTierSourceOnly := base()
	badWitnessPolicyModeByTierSourceOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierSourceOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierSourceOnly.HighAvailability.WitnessPolicyModeByTier = map[string]string{"standard": "source_only"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierSourceOnly.Validate(), `high_availability.witness_policy_mode_by_tier["standard"] source_only requires high_availability.witness_min_distinct_sources_by_tier, high_availability.witness_required_sources_by_tier, or high_availability.witness_required_urls_by_tier`)

	badWitnessPolicyModeByTierURLOnly := base()
	badWitnessPolicyModeByTierURLOnly.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessPolicyModeByTierURLOnly.HighAvailability.WitnessQuorum = 1
	badWitnessPolicyModeByTierURLOnly.HighAvailability.WitnessPolicyModeByTier = map[string]string{"standard": "url_only"}
	assert.ErrorContains(t, badWitnessPolicyModeByTierURLOnly.Validate(), `high_availability.witness_policy_mode_by_tier["standard"] url_only requires high_availability.witness_required_urls_by_tier`)

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

	badWitnessMinDistinctGroupsByTierUnknown := base()
	badWitnessMinDistinctGroupsByTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinDistinctGroupsByTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctGroupsByTierUnknown.HighAvailability.WitnessMinDistinctGroupsByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessMinDistinctGroupsByTierUnknown.Validate(), `high_availability.witness_min_distinct_groups_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessMinDistinctGroupsByTierNegative := base()
	badWitnessMinDistinctGroupsByTierNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinDistinctGroupsByTierNegative.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctGroupsByTierNegative.HighAvailability.WitnessMinDistinctGroupsByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessMinDistinctGroupsByTierNegative.Validate(), `high_availability.witness_min_distinct_groups_by_tier["standard"] -1 cannot be negative`)

	badWitnessMinDistinctGroupsByTierTooHigh := base()
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessGroups = map[string]string{
		"https://witness-a.example.test/ha": "dc-a",
		"https://witness-b.example.test/ha": "dc-b",
	}
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	badWitnessMinDistinctGroupsByTierTooHigh.HighAvailability.WitnessMinDistinctGroupsByTier = map[string]int{"critical": 2}
	assert.ErrorContains(t, badWitnessMinDistinctGroupsByTierTooHigh.Validate(), `high_availability.witness_min_distinct_groups_by_tier["critical"] 2 cannot exceed configured witness group count 1 for that tier`)

	badWitnessMinDistinctSourcesByTierUnknown := base()
	badWitnessMinDistinctSourcesByTierUnknown.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinDistinctSourcesByTierUnknown.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctSourcesByTierUnknown.HighAvailability.WitnessMinDistinctSourcesByTier = map[string]int{"critical": 1}
	assert.ErrorContains(t, badWitnessMinDistinctSourcesByTierUnknown.Validate(), `high_availability.witness_min_distinct_sources_by_tier key "critical" does not match a configured witness confidence tier`)

	badWitnessMinDistinctSourcesByTierNegative := base()
	badWitnessMinDistinctSourcesByTierNegative.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessMinDistinctSourcesByTierNegative.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctSourcesByTierNegative.HighAvailability.WitnessMinDistinctSourcesByTier = map[string]int{"standard": -1}
	assert.ErrorContains(t, badWitnessMinDistinctSourcesByTierNegative.Validate(), `high_availability.witness_min_distinct_sources_by_tier["standard"] -1 cannot be negative`)

	badWitnessMinDistinctSourcesByTierTooHigh := base()
	badWitnessMinDistinctSourcesByTierTooHigh.HighAvailability.WitnessURLs = []string{
		"https://witness-a.example.test/ha",
		"https://witness-b.example.test/ha",
	}
	badWitnessMinDistinctSourcesByTierTooHigh.HighAvailability.WitnessQuorum = 1
	badWitnessMinDistinctSourcesByTierTooHigh.HighAvailability.WitnessSources = map[string]string{
		"https://witness-a.example.test/ha": "local",
		"https://witness-b.example.test/ha": "external",
	}
	badWitnessMinDistinctSourcesByTierTooHigh.HighAvailability.WitnessSourceConfidence = map[string]string{
		"local":    "critical",
		"external": "advisory",
	}
	badWitnessMinDistinctSourcesByTierTooHigh.HighAvailability.WitnessMinDistinctSourcesByTier = map[string]int{"critical": 2}
	assert.ErrorContains(t, badWitnessMinDistinctSourcesByTierTooHigh.Validate(), `high_availability.witness_min_distinct_sources_by_tier["critical"] 2 cannot exceed configured witness source count 1 for that tier`)

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

	badWitnessReplayTierNoSigning := base()
	badWitnessReplayTierNoSigning.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessReplayTierNoSigning.HighAvailability.WitnessQuorum = 1
	badWitnessReplayTierNoSigning.HighAvailability.WitnessReplayRequiredTiers = []string{"standard"}
	assert.ErrorContains(t, badWitnessReplayTierNoSigning.Validate(), "high_availability.witness_replay_required_tiers requires high_availability.witness_signing_key_env")

	badWitnessSignatureTierNoSigning := base()
	badWitnessSignatureTierNoSigning.HighAvailability.WitnessURLs = []string{"https://witness-a.example.test/ha"}
	badWitnessSignatureTierNoSigning.HighAvailability.WitnessQuorum = 1
	badWitnessSignatureTierNoSigning.HighAvailability.WitnessSignatureRequiredTiers = []string{"standard"}
	assert.ErrorContains(t, badWitnessSignatureTierNoSigning.Validate(), "high_availability.witness_signature_required_tiers requires high_availability.witness_signing_key_env")

	badSigning := base()
	badSigning.HighAvailability.Enabled = false
	badSigning.HighAvailability.ReplicationSigningKeyEnv = "AEGIS_HA_REPLICATION_SIGNING_KEY"
	assert.ErrorContains(t, badSigning.Validate(), "high_availability.replication_signing_key_env requires high_availability.enabled")

	badEncryption := base()
	badEncryption.HighAvailability.Enabled = false
	badEncryption.HighAvailability.ReplicationEncryptionKeyEnv = "AEGIS_HA_REPLICATION_ENCRYPTION_KEY"
	assert.ErrorContains(t, badEncryption.Validate(), "high_availability.replication_encryption_key_env requires high_availability.enabled")
}

func TestConfigValidationDiagnosticsExports(t *testing.T) {
	base := func() *Config {
		return &Config{
			Mode:     "two-nic",
			WAN:      InterfaceConfig{Name: "eth0"},
			LAN:      InterfaceConfig{Name: "eth1"},
			Database: DatabaseConfig{Path: "/tmp/aegis.db"},
			Health:   HealthConfig{Port: 8080},
			Telemetry: TelemetryConfig{
				Enabled:                 true,
				PrometheusPort:          9090,
				LeaseHistoryPollSeconds: 300,
				SupportBundleExports: SupportBundleExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/support-bundles",
					IntervalMinutes: 360,
					RetentionCount:  7,
				},
				DiagnosticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/diagnostics",
					Format:          "both",
					IntervalMinutes: 60,
					RetentionCount:  14,
				},
				AuditExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/audit-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				SessionExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/session-exports",
					Format:          "both",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				SessionAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/session-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				VoucherAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/voucher-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				VoucherAgingAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/voucher-aging-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				VoucherRedemptionAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/voucher-redemption-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				VoucherExpiryAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/voucher-expiry-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				GuestLifecycleExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/guest-lifecycle-exports",
					Format:          "both",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				GuestRejectionAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/guest-rejection-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				GuestDeliveryAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/guest-delivery-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				GuestDeliveryFailuresExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/guest-delivery-failures-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				GuestSponsorAnalyticsExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/guest-sponsor-analytics-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				IntegrationExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/integration-exports",
					Format:          "both",
					IntervalMinutes: 45,
					RetentionCount:  21,
				},
				HAExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/ha-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				NetworkExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/network-exports",
					Format:          "both",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				UpstreamAAAExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/upstream-aaa-exports",
					Format:          "json",
					IntervalMinutes: 30,
					RetentionCount:  21,
				},
				UpgradeReadinessExports: DiagnosticsExportConfig{
					Enabled:         true,
					Directory:       "/var/lib/aegisnas/upgrade-readiness-exports",
					Format:          "json",
					IntervalMinutes: 120,
					RetentionCount:  14,
				},
			},
			Radius: RadiusConfig{
				AuthPort:              1812,
				AcctPort:              1813,
				RequestTimeoutSeconds: 5,
			},
		}
	}

	valid := base()
	assert.NoError(t, valid.Validate())

	badSupportBundleDisabledTelemetry := base()
	badSupportBundleDisabledTelemetry.Telemetry.Enabled = false
	assert.ErrorContains(t, badSupportBundleDisabledTelemetry.Validate(), "telemetry.support_bundle_exports.enabled requires telemetry.enabled")

	badSupportBundleDirectory := base()
	badSupportBundleDirectory.Telemetry.SupportBundleExports.Directory = ""
	assert.ErrorContains(t, badSupportBundleDirectory.Validate(), "telemetry.support_bundle_exports.enabled requires telemetry.support_bundle_exports.directory")

	badSupportBundleInterval := base()
	badSupportBundleInterval.Telemetry.SupportBundleExports.IntervalMinutes = 0
	assert.ErrorContains(t, badSupportBundleInterval.Validate(), "telemetry.support_bundle_exports.enabled requires a positive telemetry.support_bundle_exports.interval_minutes")

	badSupportBundleRetention := base()
	badSupportBundleRetention.Telemetry.SupportBundleExports.RetentionCount = 0
	assert.ErrorContains(t, badSupportBundleRetention.Validate(), "telemetry.support_bundle_exports.enabled requires a positive telemetry.support_bundle_exports.retention_count")

	badFormat := base()
	badFormat.Telemetry.DiagnosticsExports.Format = "xml"
	assert.ErrorContains(t, badFormat.Validate(), `telemetry.diagnostics_exports.format "xml" is invalid`)

	badDisabledTelemetry := base()
	badDisabledTelemetry.Telemetry.Enabled = false
	badDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	assert.ErrorContains(t, badDisabledTelemetry.Validate(), "telemetry.diagnostics_exports.enabled requires telemetry.enabled")

	badDirectory := base()
	badDirectory.Telemetry.DiagnosticsExports.Directory = ""
	assert.ErrorContains(t, badDirectory.Validate(), "telemetry.diagnostics_exports.enabled requires telemetry.diagnostics_exports.directory")

	badInterval := base()
	badInterval.Telemetry.DiagnosticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badInterval.Validate(), "telemetry.diagnostics_exports.enabled requires a positive telemetry.diagnostics_exports.interval_minutes")

	badRetention := base()
	badRetention.Telemetry.DiagnosticsExports.RetentionCount = 0
	assert.ErrorContains(t, badRetention.Validate(), "telemetry.diagnostics_exports.enabled requires a positive telemetry.diagnostics_exports.retention_count")

	badAuditFormat := base()
	badAuditFormat.Telemetry.AuditExports.Format = "xml"
	assert.ErrorContains(t, badAuditFormat.Validate(), `telemetry.audit_exports.format "xml" is invalid`)

	badAuditDisabledTelemetry := base()
	badAuditDisabledTelemetry.Telemetry.Enabled = false
	badAuditDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badAuditDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	assert.ErrorContains(t, badAuditDisabledTelemetry.Validate(), "telemetry.audit_exports.enabled requires telemetry.enabled")

	badAuditDirectory := base()
	badAuditDirectory.Telemetry.AuditExports.Directory = ""
	assert.ErrorContains(t, badAuditDirectory.Validate(), "telemetry.audit_exports.enabled requires telemetry.audit_exports.directory")

	badAuditInterval := base()
	badAuditInterval.Telemetry.AuditExports.IntervalMinutes = 0
	assert.ErrorContains(t, badAuditInterval.Validate(), "telemetry.audit_exports.enabled requires a positive telemetry.audit_exports.interval_minutes")

	badAuditRetention := base()
	badAuditRetention.Telemetry.AuditExports.RetentionCount = 0
	assert.ErrorContains(t, badAuditRetention.Validate(), "telemetry.audit_exports.enabled requires a positive telemetry.audit_exports.retention_count")

	badSessionFormat := base()
	badSessionFormat.Telemetry.SessionExports.Format = "xml"
	assert.ErrorContains(t, badSessionFormat.Validate(), `telemetry.session_exports.format "xml" is invalid`)

	badSessionDisabledTelemetry := base()
	badSessionDisabledTelemetry.Telemetry.Enabled = false
	badSessionDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badSessionDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badSessionDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	assert.ErrorContains(t, badSessionDisabledTelemetry.Validate(), "telemetry.session_exports.enabled requires telemetry.enabled")

	badSessionDirectory := base()
	badSessionDirectory.Telemetry.SessionExports.Directory = ""
	assert.ErrorContains(t, badSessionDirectory.Validate(), "telemetry.session_exports.enabled requires telemetry.session_exports.directory")

	badSessionInterval := base()
	badSessionInterval.Telemetry.SessionExports.IntervalMinutes = 0
	assert.ErrorContains(t, badSessionInterval.Validate(), "telemetry.session_exports.enabled requires a positive telemetry.session_exports.interval_minutes")

	badSessionRetention := base()
	badSessionRetention.Telemetry.SessionExports.RetentionCount = 0
	assert.ErrorContains(t, badSessionRetention.Validate(), "telemetry.session_exports.enabled requires a positive telemetry.session_exports.retention_count")

	badSessionAnalyticsFormat := base()
	badSessionAnalyticsFormat.Telemetry.SessionAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badSessionAnalyticsFormat.Validate(), `telemetry.session_analytics_exports.format "xml" is invalid`)

	badSessionAnalyticsDisabledTelemetry := base()
	badSessionAnalyticsDisabledTelemetry.Telemetry.Enabled = false
	badSessionAnalyticsDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badSessionAnalyticsDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badSessionAnalyticsDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badSessionAnalyticsDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	assert.ErrorContains(t, badSessionAnalyticsDisabledTelemetry.Validate(), "telemetry.session_analytics_exports.enabled requires telemetry.enabled")

	badSessionAnalyticsDirectory := base()
	badSessionAnalyticsDirectory.Telemetry.SessionAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badSessionAnalyticsDirectory.Validate(), "telemetry.session_analytics_exports.enabled requires telemetry.session_analytics_exports.directory")

	badSessionAnalyticsInterval := base()
	badSessionAnalyticsInterval.Telemetry.SessionAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badSessionAnalyticsInterval.Validate(), "telemetry.session_analytics_exports.enabled requires a positive telemetry.session_analytics_exports.interval_minutes")

	badSessionAnalyticsRetention := base()
	badSessionAnalyticsRetention.Telemetry.SessionAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badSessionAnalyticsRetention.Validate(), "telemetry.session_analytics_exports.enabled requires a positive telemetry.session_analytics_exports.retention_count")

	badVoucherAnalyticsFormat := base()
	badVoucherAnalyticsFormat.Telemetry.VoucherAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badVoucherAnalyticsFormat.Validate(), `telemetry.voucher_analytics_exports.format "xml" is invalid`)

	badVoucherAnalyticsDisabledTelemetry := base()
	badVoucherAnalyticsDisabledTelemetry.Telemetry.Enabled = false
	badVoucherAnalyticsDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badVoucherAnalyticsDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badVoucherAnalyticsDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badVoucherAnalyticsDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badVoucherAnalyticsDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badVoucherAnalyticsDisabledTelemetry.Validate(), "telemetry.voucher_analytics_exports.enabled requires telemetry.enabled")

	badVoucherAnalyticsDirectory := base()
	badVoucherAnalyticsDirectory.Telemetry.VoucherAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badVoucherAnalyticsDirectory.Validate(), "telemetry.voucher_analytics_exports.enabled requires telemetry.voucher_analytics_exports.directory")

	badVoucherAnalyticsInterval := base()
	badVoucherAnalyticsInterval.Telemetry.VoucherAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badVoucherAnalyticsInterval.Validate(), "telemetry.voucher_analytics_exports.enabled requires a positive telemetry.voucher_analytics_exports.interval_minutes")

	badVoucherAnalyticsRetention := base()
	badVoucherAnalyticsRetention.Telemetry.VoucherAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badVoucherAnalyticsRetention.Validate(), "telemetry.voucher_analytics_exports.enabled requires a positive telemetry.voucher_analytics_exports.retention_count")

	badVoucherAgingAnalyticsFormat := base()
	badVoucherAgingAnalyticsFormat.Telemetry.VoucherAgingAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badVoucherAgingAnalyticsFormat.Validate(), `telemetry.voucher_aging_analytics_exports.format "xml" is invalid`)

	badVoucherAgingAnalyticsDisabledTelemetry := base()
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badVoucherAgingAnalyticsDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badVoucherAgingAnalyticsDisabledTelemetry.Validate(), "telemetry.voucher_aging_analytics_exports.enabled requires telemetry.enabled")

	badVoucherAgingAnalyticsDirectory := base()
	badVoucherAgingAnalyticsDirectory.Telemetry.VoucherAgingAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badVoucherAgingAnalyticsDirectory.Validate(), "telemetry.voucher_aging_analytics_exports.enabled requires telemetry.voucher_aging_analytics_exports.directory")

	badVoucherAgingAnalyticsInterval := base()
	badVoucherAgingAnalyticsInterval.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badVoucherAgingAnalyticsInterval.Validate(), "telemetry.voucher_aging_analytics_exports.enabled requires a positive telemetry.voucher_aging_analytics_exports.interval_minutes")

	badVoucherAgingAnalyticsRetention := base()
	badVoucherAgingAnalyticsRetention.Telemetry.VoucherAgingAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badVoucherAgingAnalyticsRetention.Validate(), "telemetry.voucher_aging_analytics_exports.enabled requires a positive telemetry.voucher_aging_analytics_exports.retention_count")

	badVoucherRedemptionAnalyticsFormat := base()
	badVoucherRedemptionAnalyticsFormat.Telemetry.VoucherRedemptionAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badVoucherRedemptionAnalyticsFormat.Validate(), `telemetry.voucher_redemption_analytics_exports.format "xml" is invalid`)

	badVoucherRedemptionAnalyticsDisabledTelemetry := base()
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badVoucherRedemptionAnalyticsDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badVoucherRedemptionAnalyticsDisabledTelemetry.Validate(), "telemetry.voucher_redemption_analytics_exports.enabled requires telemetry.enabled")

	badVoucherRedemptionAnalyticsDirectory := base()
	badVoucherRedemptionAnalyticsDirectory.Telemetry.VoucherRedemptionAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badVoucherRedemptionAnalyticsDirectory.Validate(), "telemetry.voucher_redemption_analytics_exports.enabled requires telemetry.voucher_redemption_analytics_exports.directory")

	badVoucherRedemptionAnalyticsInterval := base()
	badVoucherRedemptionAnalyticsInterval.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badVoucherRedemptionAnalyticsInterval.Validate(), "telemetry.voucher_redemption_analytics_exports.enabled requires a positive telemetry.voucher_redemption_analytics_exports.interval_minutes")

	badVoucherRedemptionAnalyticsRetention := base()
	badVoucherRedemptionAnalyticsRetention.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badVoucherRedemptionAnalyticsRetention.Validate(), "telemetry.voucher_redemption_analytics_exports.enabled requires a positive telemetry.voucher_redemption_analytics_exports.retention_count")

	badVoucherExpiryAnalyticsFormat := base()
	badVoucherExpiryAnalyticsFormat.Telemetry.VoucherExpiryAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badVoucherExpiryAnalyticsFormat.Validate(), `telemetry.voucher_expiry_analytics_exports.format "xml" is invalid`)

	badVoucherExpiryAnalyticsDisabledTelemetry := base()
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badVoucherExpiryAnalyticsDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badVoucherExpiryAnalyticsDisabledTelemetry.Validate(), "telemetry.voucher_expiry_analytics_exports.enabled requires telemetry.enabled")

	badVoucherExpiryAnalyticsDirectory := base()
	badVoucherExpiryAnalyticsDirectory.Telemetry.VoucherExpiryAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badVoucherExpiryAnalyticsDirectory.Validate(), "telemetry.voucher_expiry_analytics_exports.enabled requires telemetry.voucher_expiry_analytics_exports.directory")

	badVoucherExpiryAnalyticsInterval := base()
	badVoucherExpiryAnalyticsInterval.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badVoucherExpiryAnalyticsInterval.Validate(), "telemetry.voucher_expiry_analytics_exports.enabled requires a positive telemetry.voucher_expiry_analytics_exports.interval_minutes")

	badVoucherExpiryAnalyticsRetention := base()
	badVoucherExpiryAnalyticsRetention.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badVoucherExpiryAnalyticsRetention.Validate(), "telemetry.voucher_expiry_analytics_exports.enabled requires a positive telemetry.voucher_expiry_analytics_exports.retention_count")

	badGuestLifecycleFormat := base()
	badGuestLifecycleFormat.Telemetry.GuestLifecycleExports.Format = "xml"
	assert.ErrorContains(t, badGuestLifecycleFormat.Validate(), `telemetry.guest_lifecycle_exports.format "xml" is invalid`)

	badGuestLifecycleDisabledTelemetry := base()
	badGuestLifecycleDisabledTelemetry.Telemetry.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badGuestLifecycleDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badGuestLifecycleDisabledTelemetry.Validate(), "telemetry.guest_lifecycle_exports.enabled requires telemetry.enabled")

	badGuestLifecycleDirectory := base()
	badGuestLifecycleDirectory.Telemetry.GuestLifecycleExports.Directory = ""
	assert.ErrorContains(t, badGuestLifecycleDirectory.Validate(), "telemetry.guest_lifecycle_exports.enabled requires telemetry.guest_lifecycle_exports.directory")

	badGuestLifecycleInterval := base()
	badGuestLifecycleInterval.Telemetry.GuestLifecycleExports.IntervalMinutes = 0
	assert.ErrorContains(t, badGuestLifecycleInterval.Validate(), "telemetry.guest_lifecycle_exports.enabled requires a positive telemetry.guest_lifecycle_exports.interval_minutes")

	badGuestLifecycleRetention := base()
	badGuestLifecycleRetention.Telemetry.GuestLifecycleExports.RetentionCount = 0
	assert.ErrorContains(t, badGuestLifecycleRetention.Validate(), "telemetry.guest_lifecycle_exports.enabled requires a positive telemetry.guest_lifecycle_exports.retention_count")

	badGuestDeliveryFormat := base()
	badGuestDeliveryFormat.Telemetry.GuestDeliveryAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badGuestDeliveryFormat.Validate(), `telemetry.guest_delivery_analytics_exports.format "xml" is invalid`)

	badGuestDeliveryDisabledTelemetry := base()
	badGuestDeliveryDisabledTelemetry.Telemetry.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badGuestDeliveryDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badGuestDeliveryDisabledTelemetry.Validate(), "telemetry.guest_delivery_analytics_exports.enabled requires telemetry.enabled")

	badGuestDeliveryDirectory := base()
	badGuestDeliveryDirectory.Telemetry.GuestDeliveryAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badGuestDeliveryDirectory.Validate(), "telemetry.guest_delivery_analytics_exports.enabled requires telemetry.guest_delivery_analytics_exports.directory")

	badGuestDeliveryInterval := base()
	badGuestDeliveryInterval.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badGuestDeliveryInterval.Validate(), "telemetry.guest_delivery_analytics_exports.enabled requires a positive telemetry.guest_delivery_analytics_exports.interval_minutes")

	badGuestDeliveryRetention := base()
	badGuestDeliveryRetention.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badGuestDeliveryRetention.Validate(), "telemetry.guest_delivery_analytics_exports.enabled requires a positive telemetry.guest_delivery_analytics_exports.retention_count")

	badGuestDeliveryFailuresFormat := base()
	badGuestDeliveryFailuresFormat.Telemetry.GuestDeliveryFailuresExports.Format = "xml"
	assert.ErrorContains(t, badGuestDeliveryFailuresFormat.Validate(), `telemetry.guest_delivery_failures_exports.format "xml" is invalid`)

	badGuestDeliveryFailuresDisabledTelemetry := base()
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badGuestDeliveryFailuresDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badGuestDeliveryFailuresDisabledTelemetry.Validate(), "telemetry.guest_delivery_failures_exports.enabled requires telemetry.enabled")

	badGuestDeliveryFailuresDirectory := base()
	badGuestDeliveryFailuresDirectory.Telemetry.GuestDeliveryFailuresExports.Directory = ""
	assert.ErrorContains(t, badGuestDeliveryFailuresDirectory.Validate(), "telemetry.guest_delivery_failures_exports.enabled requires telemetry.guest_delivery_failures_exports.directory")

	badGuestDeliveryFailuresInterval := base()
	badGuestDeliveryFailuresInterval.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes = 0
	assert.ErrorContains(t, badGuestDeliveryFailuresInterval.Validate(), "telemetry.guest_delivery_failures_exports.enabled requires a positive telemetry.guest_delivery_failures_exports.interval_minutes")

	badGuestDeliveryFailuresRetention := base()
	badGuestDeliveryFailuresRetention.Telemetry.GuestDeliveryFailuresExports.RetentionCount = 0
	assert.ErrorContains(t, badGuestDeliveryFailuresRetention.Validate(), "telemetry.guest_delivery_failures_exports.enabled requires a positive telemetry.guest_delivery_failures_exports.retention_count")

	badGuestSponsorFormat := base()
	badGuestSponsorFormat.Telemetry.GuestSponsorAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badGuestSponsorFormat.Validate(), `telemetry.guest_sponsor_analytics_exports.format "xml" is invalid`)

	badGuestSponsorDisabledTelemetry := base()
	badGuestSponsorDisabledTelemetry.Telemetry.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badGuestSponsorDisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	assert.ErrorContains(t, badGuestSponsorDisabledTelemetry.Validate(), "telemetry.guest_sponsor_analytics_exports.enabled requires telemetry.enabled")

	badGuestSponsorDirectory := base()
	badGuestSponsorDirectory.Telemetry.GuestSponsorAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badGuestSponsorDirectory.Validate(), "telemetry.guest_sponsor_analytics_exports.enabled requires telemetry.guest_sponsor_analytics_exports.directory")

	badGuestSponsorInterval := base()
	badGuestSponsorInterval.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badGuestSponsorInterval.Validate(), "telemetry.guest_sponsor_analytics_exports.enabled requires a positive telemetry.guest_sponsor_analytics_exports.interval_minutes")

	badGuestSponsorRetention := base()
	badGuestSponsorRetention.Telemetry.GuestSponsorAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badGuestSponsorRetention.Validate(), "telemetry.guest_sponsor_analytics_exports.enabled requires a positive telemetry.guest_sponsor_analytics_exports.retention_count")

	badGuestRejectionFormat := base()
	badGuestRejectionFormat.Telemetry.GuestRejectionAnalyticsExports.Format = "xml"
	assert.ErrorContains(t, badGuestRejectionFormat.Validate(), `telemetry.guest_rejection_analytics_exports.format "xml" is invalid`)

	badGuestRejectionDisabledTelemetry := base()
	badGuestRejectionDisabledTelemetry.Telemetry.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badGuestRejectionDisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badGuestRejectionDisabledTelemetry.Validate(), "telemetry.guest_rejection_analytics_exports.enabled requires telemetry.enabled")

	badGuestRejectionDirectory := base()
	badGuestRejectionDirectory.Telemetry.GuestRejectionAnalyticsExports.Directory = ""
	assert.ErrorContains(t, badGuestRejectionDirectory.Validate(), "telemetry.guest_rejection_analytics_exports.enabled requires telemetry.guest_rejection_analytics_exports.directory")

	badGuestRejectionInterval := base()
	badGuestRejectionInterval.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes = 0
	assert.ErrorContains(t, badGuestRejectionInterval.Validate(), "telemetry.guest_rejection_analytics_exports.enabled requires a positive telemetry.guest_rejection_analytics_exports.interval_minutes")

	badGuestRejectionRetention := base()
	badGuestRejectionRetention.Telemetry.GuestRejectionAnalyticsExports.RetentionCount = 0
	assert.ErrorContains(t, badGuestRejectionRetention.Validate(), "telemetry.guest_rejection_analytics_exports.enabled requires a positive telemetry.guest_rejection_analytics_exports.retention_count")

	badIntegrationFormat := base()
	badIntegrationFormat.Telemetry.IntegrationExports.Format = "xml"
	assert.ErrorContains(t, badIntegrationFormat.Validate(), `telemetry.integration_exports.format "xml" is invalid`)

	badIntegrationDisabledTelemetry := base()
	badIntegrationDisabledTelemetry.Telemetry.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badIntegrationDisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	assert.ErrorContains(t, badIntegrationDisabledTelemetry.Validate(), "telemetry.integration_exports.enabled requires telemetry.enabled")

	badIntegrationDirectory := base()
	badIntegrationDirectory.Telemetry.IntegrationExports.Directory = ""
	assert.ErrorContains(t, badIntegrationDirectory.Validate(), "telemetry.integration_exports.enabled requires telemetry.integration_exports.directory")

	badIntegrationInterval := base()
	badIntegrationInterval.Telemetry.IntegrationExports.IntervalMinutes = 0
	assert.ErrorContains(t, badIntegrationInterval.Validate(), "telemetry.integration_exports.enabled requires a positive telemetry.integration_exports.interval_minutes")

	badIntegrationRetention := base()
	badIntegrationRetention.Telemetry.IntegrationExports.RetentionCount = 0
	assert.ErrorContains(t, badIntegrationRetention.Validate(), "telemetry.integration_exports.enabled requires a positive telemetry.integration_exports.retention_count")

	badHAFormat := base()
	badHAFormat.Telemetry.HAExports.Format = "xml"
	assert.ErrorContains(t, badHAFormat.Validate(), `telemetry.ha_exports.format "xml" is invalid`)

	badHADisabledTelemetry := base()
	badHADisabledTelemetry.Telemetry.Enabled = false
	badHADisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badHADisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badHADisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badHADisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badHADisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badHADisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	badHADisabledTelemetry.Telemetry.IntegrationExports.Enabled = false
	assert.ErrorContains(t, badHADisabledTelemetry.Validate(), "telemetry.ha_exports.enabled requires telemetry.enabled")

	badHADirectory := base()
	badHADirectory.Telemetry.HAExports.Directory = ""
	assert.ErrorContains(t, badHADirectory.Validate(), "telemetry.ha_exports.enabled requires telemetry.ha_exports.directory")

	badHAInterval := base()
	badHAInterval.Telemetry.HAExports.IntervalMinutes = 0
	assert.ErrorContains(t, badHAInterval.Validate(), "telemetry.ha_exports.enabled requires a positive telemetry.ha_exports.interval_minutes")

	badHARetention := base()
	badHARetention.Telemetry.HAExports.RetentionCount = 0
	assert.ErrorContains(t, badHARetention.Validate(), "telemetry.ha_exports.enabled requires a positive telemetry.ha_exports.retention_count")

	badNetworkFormat := base()
	badNetworkFormat.Telemetry.NetworkExports.Format = "xml"
	assert.ErrorContains(t, badNetworkFormat.Validate(), `telemetry.network_exports.format "xml" is invalid`)

	badNetworkDisabledTelemetry := base()
	badNetworkDisabledTelemetry.Telemetry.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.IntegrationExports.Enabled = false
	badNetworkDisabledTelemetry.Telemetry.HAExports.Enabled = false
	assert.ErrorContains(t, badNetworkDisabledTelemetry.Validate(), "telemetry.network_exports.enabled requires telemetry.enabled")

	badNetworkDirectory := base()
	badNetworkDirectory.Telemetry.NetworkExports.Directory = ""
	assert.ErrorContains(t, badNetworkDirectory.Validate(), "telemetry.network_exports.enabled requires telemetry.network_exports.directory")

	badNetworkInterval := base()
	badNetworkInterval.Telemetry.NetworkExports.IntervalMinutes = 0
	assert.ErrorContains(t, badNetworkInterval.Validate(), "telemetry.network_exports.enabled requires a positive telemetry.network_exports.interval_minutes")

	badNetworkRetention := base()
	badNetworkRetention.Telemetry.NetworkExports.RetentionCount = 0
	assert.ErrorContains(t, badNetworkRetention.Validate(), "telemetry.network_exports.enabled requires a positive telemetry.network_exports.retention_count")

	badUpstreamAAAFormat := base()
	badUpstreamAAAFormat.Telemetry.UpstreamAAAExports.Format = "xml"
	assert.ErrorContains(t, badUpstreamAAAFormat.Validate(), `telemetry.upstream_aaa_exports.format "xml" is invalid`)

	badUpstreamAAADisabledTelemetry := base()
	badUpstreamAAADisabledTelemetry.Telemetry.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.IntegrationExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.HAExports.Enabled = false
	badUpstreamAAADisabledTelemetry.Telemetry.NetworkExports.Enabled = false
	assert.ErrorContains(t, badUpstreamAAADisabledTelemetry.Validate(), "telemetry.upstream_aaa_exports.enabled requires telemetry.enabled")

	badUpstreamAAADirectory := base()
	badUpstreamAAADirectory.Telemetry.UpstreamAAAExports.Directory = ""
	assert.ErrorContains(t, badUpstreamAAADirectory.Validate(), "telemetry.upstream_aaa_exports.enabled requires telemetry.upstream_aaa_exports.directory")

	badUpstreamAAAInterval := base()
	badUpstreamAAAInterval.Telemetry.UpstreamAAAExports.IntervalMinutes = 0
	assert.ErrorContains(t, badUpstreamAAAInterval.Validate(), "telemetry.upstream_aaa_exports.enabled requires a positive telemetry.upstream_aaa_exports.interval_minutes")

	badUpstreamAAARetention := base()
	badUpstreamAAARetention.Telemetry.UpstreamAAAExports.RetentionCount = 0
	assert.ErrorContains(t, badUpstreamAAARetention.Validate(), "telemetry.upstream_aaa_exports.enabled requires a positive telemetry.upstream_aaa_exports.retention_count")

	badUpgradeReadinessFormat := base()
	badUpgradeReadinessFormat.Telemetry.UpgradeReadinessExports.Format = "xml"
	assert.ErrorContains(t, badUpgradeReadinessFormat.Validate(), `telemetry.upgrade_readiness_exports.format "xml" is invalid`)

	badUpgradeReadinessDisabledTelemetry := base()
	badUpgradeReadinessDisabledTelemetry.Telemetry.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.SupportBundleExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.DiagnosticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.AuditExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.SessionExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.SessionAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.VoucherAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.VoucherAgingAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.VoucherRedemptionAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.VoucherExpiryAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.GuestLifecycleExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.GuestRejectionAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.GuestDeliveryAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.GuestDeliveryFailuresExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.GuestSponsorAnalyticsExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.IntegrationExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.HAExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.NetworkExports.Enabled = false
	badUpgradeReadinessDisabledTelemetry.Telemetry.UpstreamAAAExports.Enabled = false
	assert.ErrorContains(t, badUpgradeReadinessDisabledTelemetry.Validate(), "telemetry.upgrade_readiness_exports.enabled requires telemetry.enabled")

	badUpgradeReadinessDirectory := base()
	badUpgradeReadinessDirectory.Telemetry.UpgradeReadinessExports.Directory = ""
	assert.ErrorContains(t, badUpgradeReadinessDirectory.Validate(), "telemetry.upgrade_readiness_exports.enabled requires telemetry.upgrade_readiness_exports.directory")

	badUpgradeReadinessInterval := base()
	badUpgradeReadinessInterval.Telemetry.UpgradeReadinessExports.IntervalMinutes = 0
	assert.ErrorContains(t, badUpgradeReadinessInterval.Validate(), "telemetry.upgrade_readiness_exports.enabled requires a positive telemetry.upgrade_readiness_exports.interval_minutes")

	badUpgradeReadinessRetention := base()
	badUpgradeReadinessRetention.Telemetry.UpgradeReadinessExports.RetentionCount = 0
	assert.ErrorContains(t, badUpgradeReadinessRetention.Validate(), "telemetry.upgrade_readiness_exports.enabled requires a positive telemetry.upgrade_readiness_exports.retention_count")
}
