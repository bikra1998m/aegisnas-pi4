package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/spf13/viper"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

type Config struct {
	Mode             string                 `mapstructure:"mode"`
	Deployment       DeploymentConfig       `mapstructure:"deployment"`
	WAN              InterfaceConfig        `mapstructure:"wan"`
	LAN              InterfaceConfig        `mapstructure:"lan"`
	Network          NetworkConfig          `mapstructure:"network"`
	VLANs            []VLANConfig           `mapstructure:"vlans"`
	Database         DatabaseConfig         `mapstructure:"database"`
	Logging          LoggingConfig          `mapstructure:"logging"`
	Health           HealthConfig           `mapstructure:"health"`
	Radius           RadiusConfig           `mapstructure:"radius"`
	Portal           PortalConfig           `mapstructure:"portal"`
	LDAP             LDAPConfig             `mapstructure:"ldap"`
	Policy           PolicyConfig           `mapstructure:"policy"`
	Telemetry        TelemetryConfig        `mapstructure:"telemetry"`
	AILite           AILiteConfig           `mapstructure:"ailite"`
	Onboarding       OnboardingConfig       `mapstructure:"onboarding"`
	Profiling        ProfilingConfig        `mapstructure:"profiling"`
	Integrations     IntegrationsConfig     `mapstructure:"integrations"`
	Governance       GovernanceConfig       `mapstructure:"governance"`
	HighAvailability HighAvailabilityConfig `mapstructure:"high_availability"`
	DHCP             DHCPConfig             `mapstructure:"dhcp"`
	Wireless         WirelessConfig         `mapstructure:"wireless"`
	AdminPort        int                    `mapstructure:"admin_port"`
}

type DeploymentConfig struct {
	Profile  string                   `mapstructure:"profile"`
	Form     string                   `mapstructure:"form"`
	Hardware DeploymentHardwareConfig `mapstructure:"hardware"`
}

type DeploymentHardwareConfig struct {
	MemoryMB            int  `mapstructure:"memory_mb"`
	CPUCores            int  `mapstructure:"cpu_cores"`
	PreferExternalAP    bool `mapstructure:"prefer_external_ap"`
	WirelessPassthrough bool `mapstructure:"wireless_passthrough"`
}

type DHCPConfig struct {
	Enabled       bool                    `mapstructure:"enabled"`
	LeaseTime     string                  `mapstructure:"lease_time"`
	Authoritative bool                    `mapstructure:"authoritative"`
	StaticLeases  []DHCPStaticLeaseConfig `mapstructure:"static_leases"`
}

type InterfaceConfig struct {
	Name      string `mapstructure:"name"`
	DHCP      bool   `mapstructure:"dhcp"`
	Address   string `mapstructure:"address"`
	Gateway   string `mapstructure:"gateway"`
	DHCPRange string `mapstructure:"dhcp_range"`
}

type DHCPStaticLeaseConfig struct {
	MAC         string `mapstructure:"mac"`
	IP          string `mapstructure:"ip"`
	Hostname    string `mapstructure:"hostname"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type NetworkConfig struct {
	Interfaces   []ManagedInterfaceConfig `mapstructure:"interfaces"`
	Gateways     []GatewayConfig          `mapstructure:"gateways"`
	DNS          DNSConfig                `mapstructure:"dns"`
	StaticRoutes []StaticRouteConfig      `mapstructure:"static_routes"`
	Firewall     FirewallConfig           `mapstructure:"firewall"`
}

type ManagedInterfaceConfig struct {
	Name        string `mapstructure:"name"`
	Address     string `mapstructure:"address"`
	MTU         int    `mapstructure:"mtu"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type GatewayConfig struct {
	Name        string `mapstructure:"name"`
	Address     string `mapstructure:"address"`
	Interface   string `mapstructure:"interface"`
	Metric      int    `mapstructure:"metric"`
	Default     bool   `mapstructure:"default"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type DNSConfig struct {
	UpstreamServers []string `mapstructure:"upstream_servers"`
	SearchDomains   []string `mapstructure:"search_domains"`
	LocalDomain     string   `mapstructure:"local_domain"`
}

type StaticRouteConfig struct {
	Name        string `mapstructure:"name"`
	Destination string `mapstructure:"destination"`
	Gateway     string `mapstructure:"gateway"`
	Interface   string `mapstructure:"interface"`
	Metric      int    `mapstructure:"metric"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type FirewallConfig struct {
	Rules         []FirewallRuleConfig `mapstructure:"rules"`
	FreeSites     []FreeSiteConfig     `mapstructure:"free_sites"`
	DOSProtection DOSProtectionConfig  `mapstructure:"dos_protection"`
}

type FirewallRuleConfig struct {
	Name        string `mapstructure:"name"`
	Chain       string `mapstructure:"chain"`
	Action      string `mapstructure:"action"`
	Interface   string `mapstructure:"interface"`
	Source      string `mapstructure:"source"`
	Destination string `mapstructure:"destination"`
	Protocol    string `mapstructure:"protocol"`
	Ports       string `mapstructure:"ports"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type FreeSiteConfig struct {
	Type        string `mapstructure:"type"`
	Value       string `mapstructure:"value"`
	Enabled     bool   `mapstructure:"enabled"`
	Description string `mapstructure:"description"`
}

type DOSProtectionConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	SYNRate  string `mapstructure:"syn_rate"`
	ICMPRate string `mapstructure:"icmp_rate"`
	ConnRate string `mapstructure:"conn_rate"`
	Burst    int    `mapstructure:"burst"`
	LogDrops bool   `mapstructure:"log_drops"`
}

type VLANConfig struct {
	ID        int    `mapstructure:"id"`
	Name      string `mapstructure:"name"`
	Subnet    string `mapstructure:"subnet"`
	Gateway   string `mapstructure:"gateway"`
	Purpose   string `mapstructure:"purpose"`
	DHCPStart string `mapstructure:"dhcp_start"`
	DHCPEnd   string `mapstructure:"dhcp_end"`
}

type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Output string `mapstructure:"output"`
}

type HealthConfig struct {
	Port int `mapstructure:"port"`
}

type RadiusConfig struct {
	Clients               []RadiusClient       `mapstructure:"clients"`
	Secret                string               `mapstructure:"secret"`
	AuthPort              int                  `mapstructure:"auth_port"`
	AcctPort              int                  `mapstructure:"acct_port"`
	MaxSessions           int                  `mapstructure:"max_sessions"`
	CertDir               string               `mapstructure:"cert_dir"`
	NASIdentifier         string               `mapstructure:"nas_identifier"`
	RequestTimeoutSeconds int                  `mapstructure:"request_timeout_seconds"`
	InterimUpdateSeconds  int                  `mapstructure:"interim_update_seconds"`
	DynamicAuth           DynamicAuthConfig    `mapstructure:"dynamic_auth"`
	EAP                   RadiusEAPConfig      `mapstructure:"eap"`
	Upstream              RadiusUpstreamConfig `mapstructure:"upstream"`
	Vendor                RadiusVendorConfig   `mapstructure:"vendor"`
}

type RadiusClient struct {
	IP        string `mapstructure:"ip"`
	Secret    string `mapstructure:"secret"`
	ShortName string `mapstructure:"shortname"`
}

type RadiusUpstreamConfig struct {
	Enabled           bool               `mapstructure:"enabled"`
	Realm             string             `mapstructure:"realm"`
	PoolStrategy      string             `mapstructure:"pool_strategy"`
	StatusCheck       string             `mapstructure:"status_check"`
	ResponseWindow    int                `mapstructure:"response_window"`
	ZombiePeriod      int                `mapstructure:"zombie_period"`
	ReviveInterval    int                `mapstructure:"revive_interval"`
	CheckInterval     int                `mapstructure:"check_interval"`
	NumAnswersToAlive int                `mapstructure:"num_answers_to_alive"`
	StripRealm        bool               `mapstructure:"strip_realm"`
	Servers           []RadiusHomeServer `mapstructure:"servers"`
}

type RadiusHomeServer struct {
	Name     string `mapstructure:"name"`
	Address  string `mapstructure:"address"`
	AuthPort int    `mapstructure:"auth_port"`
	AcctPort int    `mapstructure:"acct_port"`
	Secret   string `mapstructure:"secret"`
}

type RadiusVendorConfig struct {
	Enabled    bool                    `mapstructure:"enabled"`
	Name       string                  `mapstructure:"name"`
	ID         int                     `mapstructure:"id"`
	Attributes []RadiusVendorAttribute `mapstructure:"attributes"`
}

type RadiusVendorAttribute struct {
	Name   string `mapstructure:"name"`
	Number int    `mapstructure:"number"`
	Type   string `mapstructure:"type"`
}

type DynamicAuthConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}

type RadiusEAPConfig struct {
	DefaultType   string `mapstructure:"default_type"`
	PEAPInner     string `mapstructure:"peap_inner"`
	TTLSInner     string `mapstructure:"ttls_inner"`
	TLSMinVersion string `mapstructure:"tls_min_version"`
	TLSMaxVersion string `mapstructure:"tls_max_version"`
}

type PortalConfig struct {
	Enabled        bool                      `mapstructure:"enabled"`
	Port           int                       `mapstructure:"port"`
	ListenIP       string                    `mapstructure:"listen_ip"`
	Branding       string                    `mapstructure:"branding"`
	SuccessURL     string                    `mapstructure:"success_url"`
	LogoutURL      string                    `mapstructure:"logout_url"`
	RadiusAuth     bool                      `mapstructure:"radius_auth"`
	LocalFallback  bool                      `mapstructure:"local_fallback"`
	GuestWorkflows PortalGuestWorkflowConfig `mapstructure:"guest_workflows"`
}

type PortalGuestWorkflowConfig struct {
	SelfRegistrationEnabled bool   `mapstructure:"self_registration_enabled"`
	SponsorApprovalEnabled  bool   `mapstructure:"sponsor_approval_enabled"`
	InviteDelivery          string `mapstructure:"invite_delivery"`
	ApprovalDelivery        string `mapstructure:"approval_delivery"`
	EmailFrom               string `mapstructure:"email_from"`
	SMTPServer              string `mapstructure:"smtp_server"`
	SMTPPort                int    `mapstructure:"smtp_port"`
	SMSProvider             string `mapstructure:"sms_provider"`
	SMSEndpoint             string `mapstructure:"sms_endpoint"`
}

type LDAPConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	URL          string `mapstructure:"url"`
	BaseDN       string `mapstructure:"base_dn"`
	BindDN       string `mapstructure:"bind_dn"`
	BindPassword string `mapstructure:"bind_password"`
	UserFilter   string `mapstructure:"user_filter"`
	GroupFilter  string `mapstructure:"group_filter"`
}

type PolicyConfig struct {
	DefaultRole           string `mapstructure:"default_role"`
	RuntimeShapingEnabled bool   `mapstructure:"runtime_shaping_enabled"`
}

type TelemetryConfig struct {
	Enabled                 bool `mapstructure:"enabled"`
	PrometheusPort          int  `mapstructure:"prometheus_port"`
	LeaseHistoryPollSeconds int  `mapstructure:"lease_history_poll_seconds"`
}

type AILiteConfig struct {
	Enabled               bool   `mapstructure:"enabled"`
	Mode                  string `mapstructure:"mode"`
	Provider              string `mapstructure:"provider"`
	Endpoint              string `mapstructure:"endpoint"`
	Model                 string `mapstructure:"model"`
	APIKeyEnv             string `mapstructure:"api_key_env"`
	RequestTimeoutSeconds int    `mapstructure:"request_timeout_seconds"`
	MaxInputEvents        int    `mapstructure:"max_input_events"`
	RecommendationLimit   int    `mapstructure:"recommendation_limit"`
	RemoteWebhook         string `mapstructure:"remote_webhook"`
}

type OnboardingConfig struct {
	DeviceInventoryEnabled       bool   `mapstructure:"device_inventory_enabled"`
	PortalEnabled                bool   `mapstructure:"portal_enabled"`
	CertificateEnrollmentEnabled bool   `mapstructure:"certificate_enrollment_enabled"`
	EAPTLSEnabled                bool   `mapstructure:"eap_tls_enabled"`
	CAMode                       string `mapstructure:"ca_mode"`
	CACertPath                   string `mapstructure:"ca_cert_path"`
	CAKeyPath                    string `mapstructure:"ca_key_path"`
	CAEnrollmentURL              string `mapstructure:"ca_enrollment_url"`
	CAEnrollmentTokenEnv         string `mapstructure:"ca_enrollment_token_env"`
}

type ProfilingConfig struct {
	MACInventoryEnabled bool   `mapstructure:"mac_inventory_enabled"`
	PassiveEnabled      bool   `mapstructure:"passive_enabled"`
	PollIntervalSeconds int    `mapstructure:"poll_interval_seconds"`
	RetentionHours      int    `mapstructure:"retention_hours"`
	PostureEnabled      bool   `mapstructure:"posture_enabled"`
	MDMSyncEnabled      bool   `mapstructure:"mdm_sync_enabled"`
	MDMProvider         string `mapstructure:"mdm_provider"`
	MDMEndpoint         string `mapstructure:"mdm_endpoint"`
	MDMAPITokenEnv      string `mapstructure:"mdm_api_token_env"`
	MDMCacheHours       int    `mapstructure:"mdm_cache_hours"`
	ComplianceWebhook   string `mapstructure:"compliance_webhook"`
	ComplianceTokenEnv  string `mapstructure:"compliance_token_env"`
	RemediationEnabled  bool   `mapstructure:"remediation_enabled"`
}

type IntegrationsConfig struct {
	AdminSSO   AdminSSOConfig   `mapstructure:"admin_sso"`
	SIEM       SIEMConfig       `mapstructure:"siem"`
	Controller ControllerConfig `mapstructure:"controller"`
}

type AdminSSOConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Provider        string `mapstructure:"provider"`
	IssuerURL       string `mapstructure:"issuer_url"`
	ClientID        string `mapstructure:"client_id"`
	ClientSecretEnv string `mapstructure:"client_secret_env"`
	RedirectURL     string `mapstructure:"redirect_url"`
	GroupsClaim     string `mapstructure:"groups_claim"`
}

type SIEMConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Provider  string `mapstructure:"provider"`
	Endpoint  string `mapstructure:"endpoint"`
	APIKeyEnv string `mapstructure:"api_key_env"`
	BatchSize int    `mapstructure:"batch_size"`
}

type ControllerConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Platform    string `mapstructure:"platform"`
	Endpoint    string `mapstructure:"endpoint"`
	APITokenEnv string `mapstructure:"api_token_env"`
	SyncMode    string `mapstructure:"sync_mode"`
	Site        string `mapstructure:"site"`
}

type GovernanceConfig struct {
	DelegatedAdminEnabled bool   `mapstructure:"delegated_admin_enabled"`
	RBACMode              string `mapstructure:"rbac_mode"`
	ExternalGroupsEnabled bool   `mapstructure:"external_groups_enabled"`
	MultiTenantEnabled    bool   `mapstructure:"multi_tenant_enabled"`
	TenantClaim           string `mapstructure:"tenant_claim"`
}

type HighAvailabilityConfig struct {
	Enabled                      bool   `mapstructure:"enabled"`
	Role                         string `mapstructure:"role"`
	PeerAPIURL                   string `mapstructure:"peer_api_url"`
	VirtualIP                    string `mapstructure:"virtual_ip"`
	HeartbeatIntervalSeconds     int    `mapstructure:"heartbeat_interval_seconds"`
	FailoverTimeoutSeconds       int    `mapstructure:"failover_timeout_seconds"`
	ReplicationIntervalSeconds   int    `mapstructure:"replication_interval_seconds"`
	ReplicationStaleAfterSeconds int    `mapstructure:"replication_stale_after_seconds"`
	SplitBrainProtectionEnabled  bool   `mapstructure:"split_brain_protection_enabled"`
	AutoStageSharedPackage       bool   `mapstructure:"auto_stage_shared_package"`
	AutoActivateOnFailover       bool   `mapstructure:"auto_activate_on_failover"`
	ReplicationSigningKeyEnv     string `mapstructure:"replication_signing_key_env"`
	ReplicationEncryptionKeyEnv  string `mapstructure:"replication_encryption_key_env"`
	WitnessAPIURL                string `mapstructure:"witness_api_url"`
	Preempt                      bool   `mapstructure:"preempt"`
	PreemptHoldoffSeconds        int    `mapstructure:"preempt_holdoff_seconds"`
	SharedStateDir               string `mapstructure:"shared_state_dir"`
}

type WirelessConfig struct {
	Enabled           bool         `mapstructure:"enabled"`
	CountryCode       string       `mapstructure:"country_code"`
	Interface         string       `mapstructure:"interface"`
	Driver            string       `mapstructure:"driver"`
	HWMode            string       `mapstructure:"hw_mode"`
	Channel           int          `mapstructure:"channel"`
	BeaconInterval    int          `mapstructure:"beacon_interval"`
	WMMEnabled        bool         `mapstructure:"wmm_enabled"`
	HTEnabled         bool         `mapstructure:"ht_enabled"`
	CtrlInterface     string       `mapstructure:"ctrl_interface"`
	HostapdConfigPath string       `mapstructure:"hostapd_config_path"`
	SSIDs             []SSIDConfig `mapstructure:"ssids"`
}

type SSIDConfig struct {
	Name             string `mapstructure:"name"`
	AuthMode         string `mapstructure:"auth_mode"`
	Passphrase       string `mapstructure:"passphrase"`
	VLAN             int    `mapstructure:"vlan"`
	Bridge           string `mapstructure:"bridge"`
	Hidden           bool   `mapstructure:"hidden"`
	ClientIsolation  bool   `mapstructure:"client_isolation"`
	MaxClients       int    `mapstructure:"max_clients"`
	DynamicVLAN      bool   `mapstructure:"dynamic_vlan"`
	PortalProfile    string `mapstructure:"portal_profile"`
	IdentitySource   string `mapstructure:"identity_source"`
	BandwidthProfile string `mapstructure:"bandwidth_profile"`
}

var globalConfig *Config
var globalConfigPath string

func Load(configPath string) (*Config, error) {
	return load(configPath, true)
}

func LoadCandidate(configPath string) (*Config, error) {
	return load(configPath, false)
}

func load(configPath string, persistGlobal bool) (*Config, error) {
	v := viper.New()
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/aegisnas")
	}
	v.SetEnvPrefix("AEGIS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("mode", "two-nic")
	v.SetDefault("deployment.profile", "branch")
	v.SetDefault("deployment.form", "physical")
	v.SetDefault("deployment.hardware.prefer_external_ap", false)
	v.SetDefault("deployment.hardware.wireless_passthrough", false)
	v.SetDefault("database.path", "/var/lib/aegisnas/data.db")
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("health.port", 8080)
	v.SetDefault("radius.auth_port", 1812)
	v.SetDefault("radius.acct_port", 1813)
	v.SetDefault("portal.port", 8081)
	v.SetDefault("telemetry.enabled", true)
	v.SetDefault("telemetry.prometheus_port", 9090)
	v.SetDefault("admin_port", 8083)
	v.SetDefault("ailite.enabled", true)
	v.SetDefault("ailite.mode", "lite")
	v.SetDefault("ailite.provider", "local")
	v.SetDefault("ailite.api_key_env", "AEGIS_AI_API_KEY")
	v.SetDefault("ailite.request_timeout_seconds", 20)
	v.SetDefault("ailite.max_input_events", 200)
	v.SetDefault("ailite.recommendation_limit", 100)
	v.SetDefault("onboarding.ca_mode", "none")
	v.SetDefault("profiling.poll_interval_seconds", 300)
	v.SetDefault("profiling.retention_hours", 24)
	v.SetDefault("profiling.mdm_sync_enabled", false)
	v.SetDefault("profiling.mdm_cache_hours", 12)
	v.SetDefault("integrations.siem.batch_size", 100)
	v.SetDefault("integrations.controller.sync_mode", "monitor")
	v.SetDefault("governance.rbac_mode", "local")
	v.SetDefault("high_availability.enabled", false)
	v.SetDefault("high_availability.role", "standby")
	v.SetDefault("high_availability.heartbeat_interval_seconds", 5)
	v.SetDefault("high_availability.failover_timeout_seconds", 20)
	v.SetDefault("high_availability.replication_interval_seconds", 300)
	v.SetDefault("high_availability.replication_stale_after_seconds", 900)
	v.SetDefault("high_availability.split_brain_protection_enabled", true)
	v.SetDefault("high_availability.auto_stage_shared_package", false)
	v.SetDefault("high_availability.auto_activate_on_failover", false)
	v.SetDefault("high_availability.replication_signing_key_env", "")
	v.SetDefault("high_availability.replication_encryption_key_env", "")
	v.SetDefault("high_availability.witness_api_url", "")
	v.SetDefault("high_availability.preempt", false)
	v.SetDefault("high_availability.preempt_holdoff_seconds", 0)
	v.SetDefault("high_availability.shared_state_dir", "/var/lib/aegisnas/ha")
	v.SetDefault("dhcp.enabled", true)
	v.SetDefault("dhcp.lease_time", "12h")
	v.SetDefault("dhcp.authoritative", true)
	v.SetDefault("network.dns.upstream_servers", []string{"8.8.8.8", "8.8.4.4"})
	v.SetDefault("network.dns.local_domain", "aegis.local")
	v.SetDefault("network.firewall.dos_protection.syn_rate", "50/second")
	v.SetDefault("network.firewall.dos_protection.icmp_rate", "25/second")
	v.SetDefault("network.firewall.dos_protection.conn_rate", "200/second")
	v.SetDefault("network.firewall.dos_protection.burst", 100)
	v.SetDefault("network.firewall.dos_protection.log_drops", true)
	v.SetDefault("portal.listen_ip", "10.20.0.1")
	v.SetDefault("portal.guest_workflows.invite_delivery", "none")
	v.SetDefault("portal.guest_workflows.smtp_port", 587)
	v.SetDefault("radius.max_sessions", 1024)
	v.SetDefault("radius.cert_dir", "/etc/freeradius/3.0/certs")
	v.SetDefault("radius.nas_identifier", "aegisnas")
	v.SetDefault("radius.request_timeout_seconds", 5)
	v.SetDefault("radius.interim_update_seconds", 300)
	v.SetDefault("radius.dynamic_auth.enabled", true)
	v.SetDefault("radius.dynamic_auth.port", 3799)
	v.SetDefault("radius.eap.default_type", "peap")
	v.SetDefault("radius.eap.peap_inner", "mschapv2")
	v.SetDefault("radius.eap.ttls_inner", "mschapv2")
	v.SetDefault("radius.eap.tls_min_version", "1.2")
	v.SetDefault("radius.eap.tls_max_version", "1.3")
	v.SetDefault("radius.upstream.enabled", false)
	v.SetDefault("radius.upstream.realm", "aegis-upstream")
	v.SetDefault("radius.upstream.pool_strategy", "fail-over")
	v.SetDefault("radius.upstream.status_check", "status-server")
	v.SetDefault("radius.upstream.response_window", 20)
	v.SetDefault("radius.upstream.zombie_period", 40)
	v.SetDefault("radius.upstream.revive_interval", 120)
	v.SetDefault("radius.upstream.check_interval", 30)
	v.SetDefault("radius.upstream.num_answers_to_alive", 3)
	v.SetDefault("radius.upstream.strip_realm", false)
	productVendor := productconfigs.AegisNASVendorDictionary()
	v.SetDefault("radius.vendor.enabled", false)
	v.SetDefault("radius.vendor.name", productVendor.Name)
	v.SetDefault("radius.vendor.id", productVendor.ID)
	v.SetDefault("portal.radius_auth", false)
	v.SetDefault("portal.local_fallback", true)
	v.SetDefault("policy.runtime_shaping_enabled", true)
	v.SetDefault("wireless.enabled", false)
	v.SetDefault("wireless.country_code", "US")
	v.SetDefault("wireless.driver", "nl80211")
	v.SetDefault("wireless.hw_mode", "g")
	v.SetDefault("wireless.channel", 6)
	v.SetDefault("wireless.beacon_interval", 100)
	v.SetDefault("wireless.wmm_enabled", true)
	v.SetDefault("wireless.ht_enabled", true)
	v.SetDefault("wireless.ctrl_interface", "/var/run/hostapd")
	v.SetDefault("wireless.hostapd_config_path", "/etc/hostapd/hostapd.conf")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("config read error: %w", err)
		}
		// Config file not found; proceed with defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config unmarshal error: %w", err)
	}
	if persistGlobal {
		globalConfig = &cfg
		globalConfigPath = v.ConfigFileUsed()
		if globalConfigPath == "" {
			if configPath != "" {
				globalConfigPath = configPath
			} else {
				globalConfigPath = "config.yaml"
			}
		}
	}
	return &cfg, nil
}

func Get() *Config {
	return globalConfig
}

func Path() string {
	return globalConfigPath
}

func (r *RadiusConfig) Enabled() bool {
	return r.AuthPort > 0
}

// Validate performs semantic validation of the configuration.
func (c *Config) Validate() error {
	if c.Mode != "two-nic" && c.Mode != "trunk" {
		return fmt.Errorf("mode must be 'two-nic' or 'trunk', got '%s'", c.Mode)
	}
	switch EffectiveDeploymentProfile(c.Deployment.Profile) {
	case "lite", "branch", "enterprise", "custom":
	default:
		return fmt.Errorf("deployment.profile %q is invalid", c.Deployment.Profile)
	}
	switch EffectiveDeploymentForm(c.Deployment.Form) {
	case "physical", "virtual":
	default:
		return fmt.Errorf("deployment.form %q is invalid", c.Deployment.Form)
	}
	if c.Deployment.Hardware.MemoryMB < 0 {
		return fmt.Errorf("deployment.hardware.memory_mb %d cannot be negative", c.Deployment.Hardware.MemoryMB)
	}
	if c.Deployment.Hardware.CPUCores < 0 {
		return fmt.Errorf("deployment.hardware.cpu_cores %d cannot be negative", c.Deployment.Hardware.CPUCores)
	}
	if c.Deployment.Hardware.WirelessPassthrough && EffectiveDeploymentForm(c.Deployment.Form) != "virtual" {
		return errors.New("deployment.hardware.wireless_passthrough is only valid for virtual deployments")
	}

	if c.Mode == "two-nic" {
		if c.WAN.Name == "" || c.LAN.Name == "" {
			return errors.New("two-nic mode requires both wan.name and lan.name")
		}
	} else {
		if len(c.VLANs) == 0 {
			return errors.New("trunk mode requires at least one VLAN defined")
		}
	}

	// Validate VLANs
	vlanIDs := make(map[int]bool)
	for _, v := range c.VLANs {
		if v.ID < 1 || v.ID > 4094 {
			return fmt.Errorf("VLAN ID %d out of range (1-4094)", v.ID)
		}
		if vlanIDs[v.ID] {
			return fmt.Errorf("duplicate VLAN ID %d", v.ID)
		}
		vlanIDs[v.ID] = true

		if v.Subnet != "" {
			if _, _, err := net.ParseCIDR(v.Subnet); err != nil {
				return fmt.Errorf("VLAN %d subnet invalid: %w", v.ID, err)
			}
		}
	}

	interfaceNames := map[string]struct{}{}
	for _, name := range []string{strings.TrimSpace(c.WAN.Name), strings.TrimSpace(c.LAN.Name)} {
		if name != "" {
			interfaceNames[name] = struct{}{}
		}
	}

	managedInterfaceNames := make(map[string]struct{}, len(c.Network.Interfaces))
	for i, iface := range c.Network.Interfaces {
		if strings.TrimSpace(iface.Name) == "" {
			return fmt.Errorf("network.interfaces[%d].name cannot be empty", i)
		}
		if _, exists := managedInterfaceNames[strings.TrimSpace(iface.Name)]; exists {
			return fmt.Errorf("network.interfaces[%d].name %q is duplicated", i, iface.Name)
		}
		managedInterfaceNames[strings.TrimSpace(iface.Name)] = struct{}{}
		interfaceNames[strings.TrimSpace(iface.Name)] = struct{}{}
		if iface.MTU < 0 {
			return fmt.Errorf("network.interfaces[%d].mtu %d cannot be negative", i, iface.MTU)
		}
		if iface.Enabled {
			if strings.TrimSpace(iface.Address) == "" {
				return fmt.Errorf("network.interfaces[%d].address cannot be empty when the interface is enabled", i)
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(iface.Address)); err != nil {
				return fmt.Errorf("network.interfaces[%d].address %q is invalid: %w", i, iface.Address, err)
			}
		}
	}

	gatewayNames := make(map[string]struct{}, len(c.Network.Gateways))
	for i, gateway := range c.Network.Gateways {
		name := strings.TrimSpace(gateway.Name)
		if name == "" {
			return fmt.Errorf("network.gateways[%d].name cannot be empty", i)
		}
		if _, exists := gatewayNames[name]; exists {
			return fmt.Errorf("network.gateways[%d].name %q is duplicated", i, gateway.Name)
		}
		gatewayNames[name] = struct{}{}
		if gateway.Metric < 0 {
			return fmt.Errorf("network.gateways[%d].metric %d cannot be negative", i, gateway.Metric)
		}
		if gateway.Enabled {
			if net.ParseIP(strings.TrimSpace(gateway.Address)) == nil {
				return fmt.Errorf("network.gateways[%d].address %q is invalid", i, gateway.Address)
			}
			if strings.TrimSpace(gateway.Interface) == "" {
				return fmt.Errorf("network.gateways[%d].interface cannot be empty when the gateway is enabled", i)
			}
			if _, exists := interfaceNames[strings.TrimSpace(gateway.Interface)]; !exists {
				return fmt.Errorf("network.gateways[%d].interface %q does not match wan.name, lan.name, or a managed interface", i, gateway.Interface)
			}
		}
	}

	if strings.TrimSpace(c.Network.DNS.LocalDomain) != "" && !validDomainLabelList(strings.TrimSpace(c.Network.DNS.LocalDomain)) {
		return fmt.Errorf("network.dns.local_domain %q is invalid", c.Network.DNS.LocalDomain)
	}
	for i, server := range c.Network.DNS.UpstreamServers {
		if net.ParseIP(strings.TrimSpace(server)) == nil {
			return fmt.Errorf("network.dns.upstream_servers[%d] %q is invalid", i, server)
		}
	}
	for i, domain := range c.Network.DNS.SearchDomains {
		if !validDomainLabelList(strings.TrimSpace(domain)) {
			return fmt.Errorf("network.dns.search_domains[%d] %q is invalid", i, domain)
		}
	}

	routeNames := make(map[string]struct{}, len(c.Network.StaticRoutes))
	for i, route := range c.Network.StaticRoutes {
		name := strings.TrimSpace(route.Name)
		if name == "" {
			return fmt.Errorf("network.static_routes[%d].name cannot be empty", i)
		}
		if _, exists := routeNames[name]; exists {
			return fmt.Errorf("network.static_routes[%d].name %q is duplicated", i, route.Name)
		}
		routeNames[name] = struct{}{}
		if route.Metric < 0 {
			return fmt.Errorf("network.static_routes[%d].metric %d cannot be negative", i, route.Metric)
		}
		if route.Enabled {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(route.Destination)); err != nil {
				return fmt.Errorf("network.static_routes[%d].destination %q is invalid: %w", i, route.Destination, err)
			}
			if net.ParseIP(strings.TrimSpace(route.Gateway)) == nil {
				return fmt.Errorf("network.static_routes[%d].gateway %q is invalid", i, route.Gateway)
			}
			if strings.TrimSpace(route.Interface) == "" {
				return fmt.Errorf("network.static_routes[%d].interface cannot be empty when the route is enabled", i)
			}
			if _, exists := interfaceNames[strings.TrimSpace(route.Interface)]; !exists {
				return fmt.Errorf("network.static_routes[%d].interface %q does not match wan.name, lan.name, or a managed interface", i, route.Interface)
			}
		}
	}

	for i, rule := range c.Network.Firewall.Rules {
		if strings.TrimSpace(rule.Name) == "" {
			return fmt.Errorf("network.firewall.rules[%d].name cannot be empty", i)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Chain)) {
		case "", "input", "forward":
		default:
			return fmt.Errorf("network.firewall.rules[%d].chain %q is invalid", i, rule.Chain)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Action)) {
		case "", "accept", "drop", "reject":
		default:
			return fmt.Errorf("network.firewall.rules[%d].action %q is invalid", i, rule.Action)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
		case "", "any", "tcp", "udp", "icmp":
		default:
			return fmt.Errorf("network.firewall.rules[%d].protocol %q is invalid", i, rule.Protocol)
		}
		if source := strings.TrimSpace(rule.Source); source != "" {
			if _, _, err := net.ParseCIDR(source); err != nil {
				return fmt.Errorf("network.firewall.rules[%d].source %q is invalid: %w", i, rule.Source, err)
			}
		}
		if destination := strings.TrimSpace(rule.Destination); destination != "" {
			if _, _, err := net.ParseCIDR(destination); err != nil {
				return fmt.Errorf("network.firewall.rules[%d].destination %q is invalid: %w", i, rule.Destination, err)
			}
		}
		if iface := strings.TrimSpace(rule.Interface); iface != "" {
			if _, exists := interfaceNames[iface]; !exists {
				return fmt.Errorf("network.firewall.rules[%d].interface %q does not match wan.name, lan.name, or a managed interface", i, rule.Interface)
			}
		}
	}

	for i, site := range c.Network.Firewall.FreeSites {
		switch strings.ToLower(strings.TrimSpace(site.Type)) {
		case "domain":
			if !validDomainLabelList(strings.TrimSpace(site.Value)) {
				return fmt.Errorf("network.firewall.free_sites[%d].value %q is not a valid domain", i, site.Value)
			}
		case "cidr":
			if _, _, err := net.ParseCIDR(strings.TrimSpace(site.Value)); err != nil {
				return fmt.Errorf("network.firewall.free_sites[%d].value %q is not a valid CIDR: %w", i, site.Value, err)
			}
		default:
			return fmt.Errorf("network.firewall.free_sites[%d].type %q is invalid", i, site.Type)
		}
	}

	if c.Network.Firewall.DOSProtection.Burst < 0 {
		return fmt.Errorf("network.firewall.dos_protection.burst %d cannot be negative", c.Network.Firewall.DOSProtection.Burst)
	}
	if c.Network.Firewall.DOSProtection.Enabled {
		if strings.TrimSpace(c.Network.Firewall.DOSProtection.SYNRate) == "" {
			return errors.New("network.firewall.dos_protection.syn_rate cannot be empty when DoS protection is enabled")
		}
		if strings.TrimSpace(c.Network.Firewall.DOSProtection.ICMPRate) == "" {
			return errors.New("network.firewall.dos_protection.icmp_rate cannot be empty when DoS protection is enabled")
		}
		if strings.TrimSpace(c.Network.Firewall.DOSProtection.ConnRate) == "" {
			return errors.New("network.firewall.dos_protection.conn_rate cannot be empty when DoS protection is enabled")
		}
	}

	staticLeaseMACs := make(map[string]struct{}, len(c.DHCP.StaticLeases))
	staticLeaseIPs := make(map[string]struct{}, len(c.DHCP.StaticLeases))
	for i, lease := range c.DHCP.StaticLeases {
		mac := normalizeMAC(lease.MAC)
		if mac == "" || !validMACAddress(mac) {
			return fmt.Errorf("dhcp.static_leases[%d].mac %q is invalid", i, lease.MAC)
		}
		if _, exists := staticLeaseMACs[mac]; exists {
			return fmt.Errorf("dhcp.static_leases[%d].mac %q is duplicated", i, lease.MAC)
		}
		staticLeaseMACs[mac] = struct{}{}
		if net.ParseIP(strings.TrimSpace(lease.IP)) == nil {
			return fmt.Errorf("dhcp.static_leases[%d].ip %q is invalid", i, lease.IP)
		}
		if _, exists := staticLeaseIPs[strings.TrimSpace(lease.IP)]; exists {
			return fmt.Errorf("dhcp.static_leases[%d].ip %q is duplicated", i, lease.IP)
		}
		staticLeaseIPs[strings.TrimSpace(lease.IP)] = struct{}{}
	}

	if c.Database.Path == "" {
		return errors.New("database.path cannot be empty")
	}

	if c.Health.Port < 1 || c.Health.Port > 65535 {
		return fmt.Errorf("health.port %d out of range", c.Health.Port)
	}
	if c.Telemetry.PrometheusPort < 1 || c.Telemetry.PrometheusPort > 65535 {
		return fmt.Errorf("telemetry.prometheus_port %d out of range", c.Telemetry.PrometheusPort)
	}
	if c.Telemetry.LeaseHistoryPollSeconds < 0 {
		return fmt.Errorf("telemetry.lease_history_poll_seconds %d out of range", c.Telemetry.LeaseHistoryPollSeconds)
	}
	profile := EffectiveDeploymentProfile(c.Deployment.Profile)
	switch strings.ToLower(strings.TrimSpace(c.Portal.GuestWorkflows.InviteDelivery)) {
	case "", "none", "email", "sms":
	default:
		return fmt.Errorf("portal.guest_workflows.invite_delivery %q is invalid", c.Portal.GuestWorkflows.InviteDelivery)
	}
	switch strings.ToLower(strings.TrimSpace(c.Portal.GuestWorkflows.ApprovalDelivery)) {
	case "", "email", "sms":
	default:
		return fmt.Errorf("portal.guest_workflows.approval_delivery %q is invalid", c.Portal.GuestWorkflows.ApprovalDelivery)
	}
	if c.Portal.GuestWorkflows.SMTPPort < 0 || c.Portal.GuestWorkflows.SMTPPort > 65535 {
		return fmt.Errorf("portal.guest_workflows.smtp_port %d out of range", c.Portal.GuestWorkflows.SMTPPort)
	}
	if c.Portal.GuestWorkflows.SMSProvider != "" && strings.TrimSpace(c.Portal.GuestWorkflows.SMSEndpoint) != "" {
		if err := requireHTTPURL("portal.guest_workflows.sms_endpoint", c.Portal.GuestWorkflows.SMSEndpoint); err != nil {
			return err
		}
	}
	if c.Portal.GuestWorkflows.SelfRegistrationEnabled {
		if profile == "lite" {
			return errors.New("portal.guest_workflows.self_registration_enabled is not supported on the lite deployment profile")
		}
		if !c.Portal.Enabled {
			return errors.New("portal.guest_workflows.self_registration_enabled requires portal.enabled")
		}
		if !c.Portal.LocalFallback {
			return errors.New("portal.guest_workflows.self_registration_enabled requires portal.local_fallback")
		}
		if strings.TrimSpace(c.Portal.Branding) == "" {
			return errors.New("portal.guest_workflows.self_registration_enabled requires portal.branding")
		}
	}
	if c.Portal.GuestWorkflows.SponsorApprovalEnabled {
		if profile == "lite" {
			return errors.New("portal.guest_workflows.sponsor_approval_enabled is not supported on the lite deployment profile")
		}
		if !c.Portal.GuestWorkflows.SelfRegistrationEnabled {
			return errors.New("portal.guest_workflows.sponsor_approval_enabled requires self_registration_enabled")
		}
		switch strings.ToLower(strings.TrimSpace(c.Portal.GuestWorkflows.ApprovalDelivery)) {
		case "email":
			if !emailTransportConfigured(c) {
				return errors.New("portal.guest_workflows.sponsor_approval_enabled requires email transport configuration")
			}
		case "sms":
			if !smsTransportConfigured(c) {
				return errors.New("portal.guest_workflows.sponsor_approval_enabled requires sms transport configuration")
			}
		default:
			return errors.New("portal.guest_workflows.sponsor_approval_enabled requires approval_delivery to be email or sms")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Portal.GuestWorkflows.InviteDelivery)) {
	case "email":
		if profile == "lite" {
			return errors.New("portal.guest_workflows.invite_delivery is not supported on the lite deployment profile")
		}
		if !emailTransportConfigured(c) {
			return errors.New("portal.guest_workflows.invite_delivery=email requires email transport configuration")
		}
	case "sms":
		if profile == "lite" {
			return errors.New("portal.guest_workflows.invite_delivery is not supported on the lite deployment profile")
		}
		if !smsTransportConfigured(c) {
			return errors.New("portal.guest_workflows.invite_delivery=sms requires sms transport configuration")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Onboarding.CAMode)) {
	case "", "none", "internal", "external":
	default:
		return fmt.Errorf("onboarding.ca_mode %q is invalid", c.Onboarding.CAMode)
	}
	if c.Onboarding.CAEnrollmentURL != "" {
		if err := requireHTTPURL("onboarding.ca_enrollment_url", c.Onboarding.CAEnrollmentURL); err != nil {
			return err
		}
	}
	if c.Profiling.PollIntervalSeconds < 0 {
		return fmt.Errorf("profiling.poll_interval_seconds %d cannot be negative", c.Profiling.PollIntervalSeconds)
	}
	if c.Profiling.RetentionHours < 0 {
		return fmt.Errorf("profiling.retention_hours %d cannot be negative", c.Profiling.RetentionHours)
	}
	if c.Profiling.MDMCacheHours < 0 {
		return fmt.Errorf("profiling.mdm_cache_hours %d cannot be negative", c.Profiling.MDMCacheHours)
	}
	if c.Profiling.MDMEndpoint != "" {
		if err := requireHTTPURL("profiling.mdm_endpoint", c.Profiling.MDMEndpoint); err != nil {
			return err
		}
	}
	if c.Profiling.ComplianceWebhook != "" {
		if err := requireHTTPURL("profiling.compliance_webhook", c.Profiling.ComplianceWebhook); err != nil {
			return err
		}
	}
	if c.Onboarding.DeviceInventoryEnabled && profile == "lite" {
		return errors.New("onboarding.device_inventory_enabled is not supported on the lite deployment profile")
	}
	if c.Onboarding.PortalEnabled {
		if profile == "lite" {
			return errors.New("onboarding.portal_enabled is not supported on the lite deployment profile")
		}
		if !c.Portal.Enabled {
			return errors.New("onboarding.portal_enabled requires portal.enabled")
		}
		if !identityWorkflowReady(c) {
			return errors.New("onboarding.portal_enabled requires an identity path such as portal.local_fallback, ldap.enabled, or portal.radius_auth")
		}
		if !c.Onboarding.DeviceInventoryEnabled {
			return errors.New("onboarding.portal_enabled requires onboarding.device_inventory_enabled")
		}
		if strings.EqualFold(strings.TrimSpace(c.Onboarding.CAMode), "none") {
			return errors.New("onboarding.portal_enabled requires onboarding.ca_mode to be internal or external")
		}
	}
	if c.Onboarding.CertificateEnrollmentEnabled {
		if profile != "enterprise" {
			return errors.New("onboarding.certificate_enrollment_enabled is only supported on the enterprise deployment profile")
		}
		if !c.Onboarding.PortalEnabled {
			return errors.New("onboarding.certificate_enrollment_enabled requires onboarding.portal_enabled")
		}
		if !certificateAuthorityReady(c) {
			return errors.New("onboarding.certificate_enrollment_enabled requires complete CA configuration")
		}
	}
	if c.Onboarding.EAPTLSEnabled {
		if profile == "lite" {
			return errors.New("onboarding.eap_tls_enabled is not supported on the lite deployment profile")
		}
		if !c.Onboarding.CertificateEnrollmentEnabled {
			return errors.New("onboarding.eap_tls_enabled requires onboarding.certificate_enrollment_enabled")
		}
		if !certificateAuthorityReady(c) {
			return errors.New("onboarding.eap_tls_enabled requires complete CA configuration")
		}
		if strings.ToLower(strings.TrimSpace(c.Radius.EAP.DefaultType)) != "tls" {
			return errors.New("onboarding.eap_tls_enabled requires radius.eap.default_type to be tls")
		}
	}
	if c.Profiling.MACInventoryEnabled && c.Profiling.RetentionHours == 0 {
		return errors.New("profiling.mac_inventory_enabled requires profiling.retention_hours to be greater than zero")
	}
	if c.Profiling.PassiveEnabled {
		if profile == "lite" {
			return errors.New("profiling.passive_enabled is not supported on the lite deployment profile")
		}
		if !c.Profiling.MACInventoryEnabled {
			return errors.New("profiling.passive_enabled requires profiling.mac_inventory_enabled")
		}
		if c.Profiling.PollIntervalSeconds < 30 {
			return errors.New("profiling.passive_enabled requires profiling.poll_interval_seconds to be at least 30")
		}
	}
	if c.Profiling.MDMSyncEnabled {
		if profile != "enterprise" {
			return errors.New("profiling.mdm_sync_enabled is only supported on the enterprise deployment profile")
		}
		if strings.TrimSpace(c.Profiling.MDMProvider) == "" {
			return errors.New("profiling.mdm_sync_enabled requires profiling.mdm_provider")
		}
		if strings.TrimSpace(c.Profiling.MDMEndpoint) == "" {
			return errors.New("profiling.mdm_sync_enabled requires profiling.mdm_endpoint")
		}
		if c.Profiling.MDMCacheHours == 0 {
			return errors.New("profiling.mdm_sync_enabled requires profiling.mdm_cache_hours to be greater than zero")
		}
	}
	if c.Profiling.PostureEnabled {
		if profile != "enterprise" {
			return errors.New("profiling.posture_enabled is only supported on the enterprise deployment profile")
		}
		if !c.Profiling.MACInventoryEnabled {
			return errors.New("profiling.posture_enabled requires profiling.mac_inventory_enabled")
		}
		if !profilingIntegrationReady(c) {
			return errors.New("profiling.posture_enabled requires an MDM endpoint or compliance webhook")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Integrations.AdminSSO.Provider)) {
	case "", "oidc", "saml":
	default:
		return fmt.Errorf("integrations.admin_sso.provider %q is invalid", c.Integrations.AdminSSO.Provider)
	}
	if c.Integrations.AdminSSO.IssuerURL != "" {
		if err := requireHTTPURL("integrations.admin_sso.issuer_url", c.Integrations.AdminSSO.IssuerURL); err != nil {
			return err
		}
	}
	if c.Integrations.AdminSSO.RedirectURL != "" {
		if err := requireHTTPURL("integrations.admin_sso.redirect_url", c.Integrations.AdminSSO.RedirectURL); err != nil {
			return err
		}
	}
	if c.Integrations.AdminSSO.Enabled {
		if profile == "lite" {
			return errors.New("integrations.admin_sso.enabled is not supported on the lite deployment profile")
		}
		if !adminSSOConfigured(c) {
			return errors.New("integrations.admin_sso.enabled requires provider, issuer_url, client_id, and redirect_url")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Integrations.SIEM.Provider)) {
	case "", "webhook", "splunk-hec", "elastic":
	default:
		return fmt.Errorf("integrations.siem.provider %q is invalid", c.Integrations.SIEM.Provider)
	}
	if c.Integrations.SIEM.Endpoint != "" {
		if err := requireHTTPURL("integrations.siem.endpoint", c.Integrations.SIEM.Endpoint); err != nil {
			return err
		}
	}
	if c.Integrations.SIEM.BatchSize < 0 {
		return fmt.Errorf("integrations.siem.batch_size %d cannot be negative", c.Integrations.SIEM.BatchSize)
	}
	if c.Integrations.SIEM.Enabled {
		if !siemConfigured(c) {
			return errors.New("integrations.siem.enabled requires provider, endpoint, api_key_env, and positive batch_size")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Integrations.Controller.Platform)) {
	case "", "generic", "cisco", "aruba", "juniper-mist", "ruckus", "fortinet", "mikrotik":
	default:
		return fmt.Errorf("integrations.controller.platform %q is invalid", c.Integrations.Controller.Platform)
	}
	switch strings.ToLower(strings.TrimSpace(c.Integrations.Controller.SyncMode)) {
	case "", "monitor", "push-config", "coa-only":
	default:
		return fmt.Errorf("integrations.controller.sync_mode %q is invalid", c.Integrations.Controller.SyncMode)
	}
	if c.Integrations.Controller.Endpoint != "" {
		if err := requireHTTPURL("integrations.controller.endpoint", c.Integrations.Controller.Endpoint); err != nil {
			return err
		}
	}
	if c.Integrations.Controller.Enabled {
		if profile == "lite" {
			return errors.New("integrations.controller.enabled is not supported on the lite deployment profile")
		}
		if !controllerConfigured(c) {
			return errors.New("integrations.controller.enabled requires platform, endpoint, api_token_env, and sync_mode")
		}
		if c.Wireless.Enabled {
			return errors.New("integrations.controller.enabled requires the external AP model; disable wireless.enabled before turning on controller automation")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Governance.RBACMode)) {
	case "", "local", "external-groups", "hybrid":
	default:
		return fmt.Errorf("governance.rbac_mode %q is invalid", c.Governance.RBACMode)
	}
	if c.Governance.DelegatedAdminEnabled {
		if profile == "lite" {
			return errors.New("governance.delegated_admin_enabled is not supported on the lite deployment profile")
		}
		if !delegatedAdminIdentityReady(c) {
			return errors.New("governance.delegated_admin_enabled requires integrations.admin_sso.enabled or ldap.enabled")
		}
		if strings.EqualFold(strings.TrimSpace(c.Governance.RBACMode), "external-groups") && !adminGroupSourceReady(c) {
			return errors.New("governance.rbac_mode=external-groups requires admin SSO groups_claim or LDAP group configuration")
		}
	}
	if c.Governance.MultiTenantEnabled {
		if profile != "enterprise" {
			return errors.New("governance.multi_tenant_enabled is only supported on the enterprise deployment profile")
		}
		if !c.Governance.DelegatedAdminEnabled {
			return errors.New("governance.multi_tenant_enabled requires governance.delegated_admin_enabled")
		}
		if c.Integrations.AdminSSO.Enabled && strings.TrimSpace(c.Governance.TenantClaim) == "" {
			return errors.New("governance.multi_tenant_enabled requires governance.tenant_claim when admin SSO is enabled")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.HighAvailability.Role)) {
	case "", "active", "standby":
	default:
		return fmt.Errorf("high_availability.role %q is invalid", c.HighAvailability.Role)
	}
	if c.HighAvailability.PeerAPIURL != "" {
		if err := requireHTTPURL("high_availability.peer_api_url", c.HighAvailability.PeerAPIURL); err != nil {
			return err
		}
	}
	if ip := strings.TrimSpace(c.HighAvailability.VirtualIP); ip != "" {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			return fmt.Errorf("high_availability.virtual_ip %q must be a valid IPv4 address", c.HighAvailability.VirtualIP)
		}
	}
	if c.HighAvailability.HeartbeatIntervalSeconds < 0 {
		return fmt.Errorf("high_availability.heartbeat_interval_seconds %d cannot be negative", c.HighAvailability.HeartbeatIntervalSeconds)
	}
	if c.HighAvailability.FailoverTimeoutSeconds < 0 {
		return fmt.Errorf("high_availability.failover_timeout_seconds %d cannot be negative", c.HighAvailability.FailoverTimeoutSeconds)
	}
	if c.HighAvailability.ReplicationIntervalSeconds < 0 {
		return fmt.Errorf("high_availability.replication_interval_seconds %d cannot be negative", c.HighAvailability.ReplicationIntervalSeconds)
	}
	if c.HighAvailability.ReplicationStaleAfterSeconds < 0 {
		return fmt.Errorf("high_availability.replication_stale_after_seconds %d cannot be negative", c.HighAvailability.ReplicationStaleAfterSeconds)
	}
	if c.HighAvailability.ReplicationIntervalSeconds > 0 &&
		c.HighAvailability.ReplicationStaleAfterSeconds > 0 &&
		c.HighAvailability.ReplicationStaleAfterSeconds <= c.HighAvailability.ReplicationIntervalSeconds {
		return errors.New("high_availability.replication_stale_after_seconds must be greater than high_availability.replication_interval_seconds")
	}
	if c.HighAvailability.AutoStageSharedPackage && !c.HighAvailability.Enabled {
		return errors.New("high_availability.auto_stage_shared_package requires high_availability.enabled")
	}
	if c.HighAvailability.AutoActivateOnFailover && !c.HighAvailability.Enabled {
		return errors.New("high_availability.auto_activate_on_failover requires high_availability.enabled")
	}
	if c.HighAvailability.PreemptHoldoffSeconds < 0 {
		return fmt.Errorf("high_availability.preempt_holdoff_seconds %d cannot be negative", c.HighAvailability.PreemptHoldoffSeconds)
	}
	if strings.TrimSpace(c.HighAvailability.WitnessAPIURL) != "" {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_api_url requires high_availability.enabled")
		}
		if !c.HighAvailability.SplitBrainProtectionEnabled {
			return errors.New("high_availability.witness_api_url requires high_availability.split_brain_protection_enabled")
		}
		if err := requireHTTPURL("high_availability.witness_api_url", c.HighAvailability.WitnessAPIURL); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.HighAvailability.ReplicationSigningKeyEnv) != "" && !c.HighAvailability.Enabled {
		return errors.New("high_availability.replication_signing_key_env requires high_availability.enabled")
	}
	if strings.TrimSpace(c.HighAvailability.ReplicationEncryptionKeyEnv) != "" && !c.HighAvailability.Enabled {
		return errors.New("high_availability.replication_encryption_key_env requires high_availability.enabled")
	}
	if c.HighAvailability.Enabled {
		if profile != "enterprise" {
			return errors.New("high_availability.enabled is only supported on the enterprise deployment profile")
		}
		if !highAvailabilityConfigured(c) {
			return errors.New("high_availability.enabled requires role, peer_api_url, virtual_ip, and positive heartbeat/failover timers")
		}
		if c.HighAvailability.FailoverTimeoutSeconds <= c.HighAvailability.HeartbeatIntervalSeconds {
			return errors.New("high_availability.failover_timeout_seconds must be greater than high_availability.heartbeat_interval_seconds")
		}
	}
	aiMode := EffectiveAIMode(c)
	switch aiMode {
	case "lite", "full":
	default:
		return fmt.Errorf("ailite.mode %q is invalid", c.AILite.Mode)
	}
	aiProvider := EffectiveAIProvider(c)
	switch aiProvider {
	case "local", "openai-compatible":
	default:
		return fmt.Errorf("ailite.provider %q is invalid", c.AILite.Provider)
	}
	if c.AILite.RequestTimeoutSeconds < 0 {
		return fmt.Errorf("ailite.request_timeout_seconds %d cannot be negative", c.AILite.RequestTimeoutSeconds)
	}
	if c.AILite.MaxInputEvents < 0 {
		return fmt.Errorf("ailite.max_input_events %d cannot be negative", c.AILite.MaxInputEvents)
	}
	if strings.TrimSpace(c.AILite.Endpoint) != "" {
		parsed, err := url.Parse(c.AILite.Endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("ailite.endpoint %q is invalid", c.AILite.Endpoint)
		}
		switch parsed.Scheme {
		case "http", "https":
		default:
			return fmt.Errorf("ailite.endpoint %q must use http or https", c.AILite.Endpoint)
		}
		if strings.TrimSpace(c.AILite.Model) == "" {
			return errors.New("ailite.model cannot be empty when ailite.endpoint is set")
		}
	}
	if c.AILite.Enabled && aiMode == "full" {
		if strings.TrimSpace(c.AILite.Endpoint) == "" {
			return errors.New("ailite.endpoint cannot be empty when ailite.mode is full")
		}
		if strings.TrimSpace(c.AILite.Model) == "" {
			return errors.New("ailite.model cannot be empty when ailite.mode is full")
		}
	}

	if c.Radius.AuthPort < 1 || c.Radius.AuthPort > 65535 {
		return fmt.Errorf("radius.auth_port %d out of range", c.Radius.AuthPort)
	}
	if c.Radius.AcctPort < 1 || c.Radius.AcctPort > 65535 {
		return fmt.Errorf("radius.acct_port %d out of range", c.Radius.AcctPort)
	}
	if c.Radius.RequestTimeoutSeconds < 1 {
		return fmt.Errorf("radius.request_timeout_seconds %d must be positive", c.Radius.RequestTimeoutSeconds)
	}
	if c.Radius.InterimUpdateSeconds < 0 {
		return fmt.Errorf("radius.interim_update_seconds %d cannot be negative", c.Radius.InterimUpdateSeconds)
	}
	if c.Radius.DynamicAuth.Enabled && (c.Radius.DynamicAuth.Port < 1 || c.Radius.DynamicAuth.Port > 65535) {
		return fmt.Errorf("radius.dynamic_auth.port %d out of range", c.Radius.DynamicAuth.Port)
	}
	if c.Radius.Vendor.Enabled {
		if strings.TrimSpace(c.Radius.Vendor.Name) == "" {
			return errors.New("radius.vendor.name cannot be empty when vendor attributes are enabled")
		}
		if !validRadiusDictionaryName(c.Radius.Vendor.Name) {
			return fmt.Errorf("radius.vendor.name %q is not a valid RADIUS dictionary name", c.Radius.Vendor.Name)
		}
		if c.Radius.Vendor.ID < 1 {
			return fmt.Errorf("radius.vendor.id %d must be a positive Private Enterprise Number", c.Radius.Vendor.ID)
		}
		seenVendorAttrs := make(map[int]string, len(c.Radius.Vendor.Attributes))
		for i, attr := range c.Radius.Vendor.Attributes {
			name := strings.TrimSpace(attr.Name)
			if name == "" {
				return fmt.Errorf("radius.vendor.attributes[%d].name cannot be empty", i)
			}
			if !validRadiusDictionaryName(name) {
				return fmt.Errorf("radius.vendor.attributes[%d].name %q is not a valid RADIUS dictionary name", i, name)
			}
			if attr.Number < 1 || attr.Number > 255 {
				return fmt.Errorf("radius.vendor.attributes[%d].number %d out of range", i, attr.Number)
			}
			if existing, exists := seenVendorAttrs[attr.Number]; exists {
				return fmt.Errorf("radius.vendor.attributes[%d].number %d duplicates %q", i, attr.Number, existing)
			}
			seenVendorAttrs[attr.Number] = name
			switch strings.ToLower(strings.TrimSpace(attr.Type)) {
			case "string", "integer", "ipaddr", "octets", "date":
			default:
				return fmt.Errorf("radius.vendor.attributes[%d].type %q is invalid", i, attr.Type)
			}
		}
	}
	switch c.Radius.EAP.DefaultType {
	case "", "peap", "ttls", "tls":
	default:
		return fmt.Errorf("radius.eap.default_type %q is invalid", c.Radius.EAP.DefaultType)
	}
	switch c.Radius.EAP.PEAPInner {
	case "", "mschapv2", "gtc", "tls":
	default:
		return fmt.Errorf("radius.eap.peap_inner %q is invalid", c.Radius.EAP.PEAPInner)
	}
	switch c.Radius.EAP.TTLSInner {
	case "", "mschapv2", "pap", "chap", "gtc", "tls":
	default:
		return fmt.Errorf("radius.eap.ttls_inner %q is invalid", c.Radius.EAP.TTLSInner)
	}
	switch c.Radius.EAP.TLSMinVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("radius.eap.tls_min_version %q is invalid", c.Radius.EAP.TLSMinVersion)
	}
	switch c.Radius.EAP.TLSMaxVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("radius.eap.tls_max_version %q is invalid", c.Radius.EAP.TLSMaxVersion)
	}

	for i, cl := range c.Radius.Clients {
		if cl.IP == "" {
			return fmt.Errorf("radius.client[%d] missing ip", i)
		}
		if cl.Secret == "" {
			return fmt.Errorf("radius.client[%d] missing secret", i)
		}
	}

	if c.Radius.Upstream.Enabled {
		switch c.Radius.Upstream.PoolStrategy {
		case "fail-over", "load-balance", "client-balance", "client-port-balance", "keyed-balance":
		default:
			return fmt.Errorf("radius.upstream.pool_strategy %q is invalid", c.Radius.Upstream.PoolStrategy)
		}

		switch c.Radius.Upstream.StatusCheck {
		case "status-server", "none":
		default:
			return fmt.Errorf("radius.upstream.status_check %q is invalid", c.Radius.Upstream.StatusCheck)
		}

		if strings.TrimSpace(c.Radius.Upstream.Realm) == "" {
			return errors.New("radius.upstream.realm cannot be empty when upstream is enabled")
		}
		if len(c.Radius.Upstream.Servers) == 0 {
			return errors.New("radius.upstream.enabled requires at least one upstream server")
		}
		if c.Radius.Upstream.ResponseWindow < 1 {
			return fmt.Errorf("radius.upstream.response_window %d must be positive", c.Radius.Upstream.ResponseWindow)
		}
		if c.Radius.Upstream.ZombiePeriod < 1 {
			return fmt.Errorf("radius.upstream.zombie_period %d must be positive", c.Radius.Upstream.ZombiePeriod)
		}
		if c.Radius.Upstream.ReviveInterval < 1 {
			return fmt.Errorf("radius.upstream.revive_interval %d must be positive", c.Radius.Upstream.ReviveInterval)
		}
		if c.Radius.Upstream.CheckInterval < 1 {
			return fmt.Errorf("radius.upstream.check_interval %d must be positive", c.Radius.Upstream.CheckInterval)
		}
		if c.Radius.Upstream.NumAnswersToAlive < 1 {
			return fmt.Errorf("radius.upstream.num_answers_to_alive %d must be positive", c.Radius.Upstream.NumAnswersToAlive)
		}

		seenNames := make(map[string]struct{}, len(c.Radius.Upstream.Servers))
		for i, server := range c.Radius.Upstream.Servers {
			name := strings.TrimSpace(server.Name)
			if name == "" {
				return fmt.Errorf("radius.upstream.server[%d] missing name", i)
			}
			if _, exists := seenNames[name]; exists {
				return fmt.Errorf("radius.upstream.server[%d] duplicate name %q", i, name)
			}
			seenNames[name] = struct{}{}

			if strings.TrimSpace(server.Address) == "" {
				return fmt.Errorf("radius.upstream.server[%d] missing address", i)
			}
			if strings.TrimSpace(server.Secret) == "" {
				return fmt.Errorf("radius.upstream.server[%d] missing secret", i)
			}
			if server.AuthPort != 0 && (server.AuthPort < 1 || server.AuthPort > 65535) {
				return fmt.Errorf("radius.upstream.server[%d] auth_port %d out of range", i, server.AuthPort)
			}
			if server.AcctPort != 0 && (server.AcctPort < 1 || server.AcctPort > 65535) {
				return fmt.Errorf("radius.upstream.server[%d] acct_port %d out of range", i, server.AcctPort)
			}
		}
	}

	if c.Wireless.Enabled {
		if EffectiveDeploymentForm(c.Deployment.Form) == "virtual" && !c.Deployment.Hardware.WirelessPassthrough {
			return errors.New("wireless.enabled requires deployment.hardware.wireless_passthrough on virtual appliances")
		}
		if strings.TrimSpace(c.Wireless.Interface) == "" {
			return errors.New("wireless.interface cannot be empty when wireless is enabled")
		}
		if len(c.Wireless.SSIDs) == 0 {
			return errors.New("wireless.enabled requires at least one SSID")
		}
		if len(strings.TrimSpace(c.Wireless.CountryCode)) != 2 {
			return fmt.Errorf("wireless.country_code %q must be a two-letter code", c.Wireless.CountryCode)
		}
		switch c.Wireless.HWMode {
		case "", "a", "b", "g":
		default:
			return fmt.Errorf("wireless.hw_mode %q is invalid", c.Wireless.HWMode)
		}
		if c.Wireless.Channel < 1 || c.Wireless.Channel > 196 {
			return fmt.Errorf("wireless.channel %d out of range", c.Wireless.Channel)
		}
		if c.Wireless.BeaconInterval < 25 || c.Wireless.BeaconInterval > 1000 {
			return fmt.Errorf("wireless.beacon_interval %d out of range", c.Wireless.BeaconInterval)
		}

		ssidNames := make(map[string]struct{}, len(c.Wireless.SSIDs))
		for i, ssid := range c.Wireless.SSIDs {
			name := strings.TrimSpace(ssid.Name)
			if name == "" {
				return fmt.Errorf("wireless.ssids[%d].name cannot be empty", i)
			}
			if len(name) > 32 {
				return fmt.Errorf("wireless.ssids[%d].name exceeds 32 bytes", i)
			}
			if _, exists := ssidNames[name]; exists {
				return fmt.Errorf("wireless.ssids[%d].name %q is duplicated", i, name)
			}
			ssidNames[name] = struct{}{}
			switch ssid.AuthMode {
			case "open", "captive-portal", "wpa2-personal", "wpa2-enterprise", "wpa3-personal", "wpa3-enterprise":
			default:
				return fmt.Errorf("wireless.ssids[%d].auth_mode %q is invalid", i, ssid.AuthMode)
			}
			if ssid.AuthMode == "wpa2-personal" || ssid.AuthMode == "wpa3-personal" {
				passphraseLen := len(ssid.Passphrase)
				if passphraseLen < 8 || passphraseLen > 63 {
					return fmt.Errorf("wireless.ssids[%d].passphrase must be 8-63 characters for %s", i, ssid.AuthMode)
				}
			}
			if (ssid.AuthMode == "wpa2-enterprise" || ssid.AuthMode == "wpa3-enterprise") && strings.TrimSpace(c.Radius.Secret) == "" {
				return fmt.Errorf("wireless.ssids[%d] requires radius.secret for %s", i, ssid.AuthMode)
			}
			if ssid.AuthMode == "captive-portal" && !c.Portal.Enabled {
				return fmt.Errorf("wireless.ssids[%d] requires portal.enabled for captive-portal auth", i)
			}
			if ssid.VLAN != 0 && (ssid.VLAN < 1 || ssid.VLAN > 4094) {
				return fmt.Errorf("wireless.ssids[%d].vlan %d out of range", i, ssid.VLAN)
			}
			if ssid.MaxClients < 0 {
				return fmt.Errorf("wireless.ssids[%d].max_clients cannot be negative", i)
			}
			if ssid.DynamicVLAN && ssid.AuthMode != "wpa2-enterprise" && ssid.AuthMode != "wpa3-enterprise" {
				return fmt.Errorf("wireless.ssids[%d].dynamic_vlan requires enterprise auth", i)
			}
		}
	}

	return nil
}

func emailTransportConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Portal.GuestWorkflows.EmailFrom) != "" &&
		strings.TrimSpace(c.Portal.GuestWorkflows.SMTPServer) != "" &&
		c.Portal.GuestWorkflows.SMTPPort > 0
}

func smsTransportConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Portal.GuestWorkflows.SMSProvider) != "" &&
		strings.TrimSpace(c.Portal.GuestWorkflows.SMSEndpoint) != ""
}

func identityWorkflowReady(c *Config) bool {
	if c == nil {
		return false
	}
	return c.Portal.LocalFallback || c.LDAP.Enabled || c.Portal.RadiusAuth
}

func validDomainLabelList(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, " /") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				continue
			}
			if r == '-' && i != 0 && i != len(label)-1 {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	return strings.ReplaceAll(value, "-", ":")
}

func validMACAddress(value string) bool {
	hw, err := net.ParseMAC(value)
	return err == nil && len(hw) >= 6
}

func certificateAuthorityReady(c *Config) bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.Onboarding.CAMode)) {
	case "internal":
		return strings.TrimSpace(c.Onboarding.CACertPath) != "" && strings.TrimSpace(c.Onboarding.CAKeyPath) != ""
	case "external":
		return strings.TrimSpace(c.Onboarding.CAEnrollmentURL) != ""
	default:
		return false
	}
}

func profilingIntegrationReady(c *Config) bool {
	if c == nil {
		return false
	}
	return (c.Profiling.MDMSyncEnabled && strings.TrimSpace(c.Profiling.MDMProvider) != "" && strings.TrimSpace(c.Profiling.MDMEndpoint) != "") ||
		strings.TrimSpace(c.Profiling.ComplianceWebhook) != ""
}

func adminSSOConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Integrations.AdminSSO.Provider) != "" &&
		strings.TrimSpace(c.Integrations.AdminSSO.IssuerURL) != "" &&
		strings.TrimSpace(c.Integrations.AdminSSO.ClientID) != "" &&
		strings.TrimSpace(c.Integrations.AdminSSO.RedirectURL) != ""
}

func siemConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Integrations.SIEM.Provider) != "" &&
		strings.TrimSpace(c.Integrations.SIEM.Endpoint) != "" &&
		strings.TrimSpace(c.Integrations.SIEM.APIKeyEnv) != "" &&
		c.Integrations.SIEM.BatchSize > 0
}

func controllerConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Integrations.Controller.Platform) != "" &&
		strings.TrimSpace(c.Integrations.Controller.Endpoint) != "" &&
		strings.TrimSpace(c.Integrations.Controller.APITokenEnv) != "" &&
		strings.TrimSpace(c.Integrations.Controller.SyncMode) != ""
}

func delegatedAdminIdentityReady(c *Config) bool {
	if c == nil {
		return false
	}
	return c.Integrations.AdminSSO.Enabled || c.LDAP.Enabled
}

func highAvailabilityConfigured(c *Config) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.HighAvailability.Role) != "" &&
		strings.TrimSpace(c.HighAvailability.PeerAPIURL) != "" &&
		strings.TrimSpace(c.HighAvailability.VirtualIP) != "" &&
		c.HighAvailability.HeartbeatIntervalSeconds > 0 &&
		c.HighAvailability.FailoverTimeoutSeconds > 0
}

func adminGroupSourceReady(c *Config) bool {
	if c == nil {
		return false
	}
	return (c.Integrations.AdminSSO.Enabled && strings.TrimSpace(c.Integrations.AdminSSO.GroupsClaim) != "") ||
		(c.LDAP.Enabled && strings.TrimSpace(c.LDAP.GroupFilter) != "")
}

func requireHTTPURL(fieldName, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s %q is invalid", fieldName, raw)
	}
	switch parsed.Scheme {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("%s %q must use http or https", fieldName, raw)
	}
}

func validRadiusDictionaryName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}
