package config

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Mode       string           `mapstructure:"mode"`
	Deployment DeploymentConfig `mapstructure:"deployment"`
	WAN        InterfaceConfig  `mapstructure:"wan"`
	LAN        InterfaceConfig  `mapstructure:"lan"`
	VLANs      []VLANConfig     `mapstructure:"vlans"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Health     HealthConfig     `mapstructure:"health"`
	Radius     RadiusConfig     `mapstructure:"radius"`
	Portal     PortalConfig     `mapstructure:"portal"`
	LDAP       LDAPConfig       `mapstructure:"ldap"`
	Policy     PolicyConfig     `mapstructure:"policy"`
	Telemetry  TelemetryConfig  `mapstructure:"telemetry"`
	AILite     AILiteConfig     `mapstructure:"ailite"`
	DHCP       DHCPConfig       `mapstructure:"dhcp"`
	Wireless   WirelessConfig   `mapstructure:"wireless"`
	AdminPort  int              `mapstructure:"admin_port"`
}

type DeploymentConfig struct {
	Profile  string                   `mapstructure:"profile"`
	Form     string                   `mapstructure:"form"`
	Hardware DeploymentHardwareConfig `mapstructure:"hardware"`
}

type DeploymentHardwareConfig struct {
	MemoryMB         int  `mapstructure:"memory_mb"`
	CPUCores         int  `mapstructure:"cpu_cores"`
	PreferExternalAP bool `mapstructure:"prefer_external_ap"`
}

type DHCPConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	LeaseTime     string `mapstructure:"lease_time"`
	Authoritative bool   `mapstructure:"authoritative"`
}

type InterfaceConfig struct {
	Name      string `mapstructure:"name"`
	DHCP      bool   `mapstructure:"dhcp"`
	Address   string `mapstructure:"address"`
	Gateway   string `mapstructure:"gateway"`
	DHCPRange string `mapstructure:"dhcp_range"`
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
	Enabled       bool   `mapstructure:"enabled"`
	Port          int    `mapstructure:"port"`
	ListenIP      string `mapstructure:"listen_ip"`
	Branding      string `mapstructure:"branding"`
	SuccessURL    string `mapstructure:"success_url"`
	LogoutURL     string `mapstructure:"logout_url"`
	RadiusAuth    bool   `mapstructure:"radius_auth"`
	LocalFallback bool   `mapstructure:"local_fallback"`
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
	Enabled        bool `mapstructure:"enabled"`
	PrometheusPort int  `mapstructure:"prometheus_port"`
}

type AILiteConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	RecommendationLimit int    `mapstructure:"recommendation_limit"`
	RemoteWebhook       string `mapstructure:"remote_webhook"`
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
	v.SetDefault("ailite.recommendation_limit", 100)
	v.SetDefault("dhcp.enabled", true)
	v.SetDefault("dhcp.lease_time", "12h")
	v.SetDefault("dhcp.authoritative", true)
	v.SetDefault("portal.listen_ip", "10.20.0.1")
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
	globalConfig = &cfg
	globalConfigPath = v.ConfigFileUsed()
	if globalConfigPath == "" {
		if configPath != "" {
			globalConfigPath = configPath
		} else {
			globalConfigPath = "config.yaml"
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

	if c.Database.Path == "" {
		return errors.New("database.path cannot be empty")
	}

	if c.Health.Port < 1 || c.Health.Port > 65535 {
		return fmt.Errorf("health.port %d out of range", c.Health.Port)
	}
	if c.Telemetry.PrometheusPort < 1 || c.Telemetry.PrometheusPort > 65535 {
		return fmt.Errorf("telemetry.prometheus_port %d out of range", c.Telemetry.PrometheusPort)
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
