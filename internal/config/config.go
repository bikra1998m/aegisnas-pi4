package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/vendoridentity"
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
	Identity         IdentityConfig         `mapstructure:"identity"`
	ActiveDirectory  ActiveDirectoryConfig  `mapstructure:"active_directory"`
	MFA              MFAConfig              `mapstructure:"mfa"`
	AdminWebAuthn    AdminWebAuthnConfig    `mapstructure:"admin_webauthn"`
	MAB              MABConfig              `mapstructure:"mab"`
	LDAP             LDAPConfig             `mapstructure:"ldap"`
	Policy           PolicyConfig           `mapstructure:"policy"`
	Telemetry        TelemetryConfig        `mapstructure:"telemetry"`
	AILite           AILiteConfig           `mapstructure:"ailite"`
	Onboarding       OnboardingConfig       `mapstructure:"onboarding"`
	Profiling        ProfilingConfig        `mapstructure:"profiling"`
	Integrations     IntegrationsConfig     `mapstructure:"integrations"`
	Governance       GovernanceConfig       `mapstructure:"governance"`
	Security         SecurityConfig         `mapstructure:"security"`
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
	StorageGB           int  `mapstructure:"storage_gb"`
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
	Backend                      string `mapstructure:"backend"`
	Path                         string `mapstructure:"path"`
	DSN                          string `mapstructure:"dsn"`
	DSNRef                       string `mapstructure:"dsn_ref"`
	SSLMode                      string `mapstructure:"sslmode"`
	MaxOpenConns                 int    `mapstructure:"max_open_conns"`
	MaxIdleConns                 int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetimeSeconds       int    `mapstructure:"conn_max_lifetime_seconds"`
	ConnMaxIdleTimeSeconds       int    `mapstructure:"conn_max_idle_time_seconds"`
	ConnectTimeoutSeconds        int    `mapstructure:"connect_timeout_seconds"`
	StatementTimeoutMilliseconds int    `mapstructure:"statement_timeout_milliseconds"`
	MigrationLockTimeoutSeconds  int    `mapstructure:"migration_lock_timeout_seconds"`
	ProductionRequirePostgreSQL  bool   `mapstructure:"production_require_postgresql"`
	ProductionRequireTLS         bool   `mapstructure:"production_require_tls"`
	AllowUnsafePostgreSQLSSLMode bool   `mapstructure:"allow_unsafe_postgresql_sslmode"`
	AllowInlinePostgreSQLDSN     bool   `mapstructure:"allow_inline_postgresql_dsn"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Output string `mapstructure:"output"`
}

type HealthConfig struct {
	Port int `mapstructure:"port"`
}

type RadiusConfig struct {
	Clients               []RadiusClient              `mapstructure:"clients"`
	Secret                string                      `mapstructure:"secret"`
	SecretRef             string                      `mapstructure:"secret_ref"`
	AuthPort              int                         `mapstructure:"auth_port"`
	AcctPort              int                         `mapstructure:"acct_port"`
	MaxSessions           int                         `mapstructure:"max_sessions"`
	CertDir               string                      `mapstructure:"cert_dir"`
	NASIdentifier         string                      `mapstructure:"nas_identifier"`
	RequestTimeoutSeconds int                         `mapstructure:"request_timeout_seconds"`
	InterimUpdateSeconds  int                         `mapstructure:"interim_update_seconds"`
	DynamicAuth           DynamicAuthConfig           `mapstructure:"dynamic_auth"`
	DynamicClients        RadiusDynamicClientsConfig  `mapstructure:"dynamic_clients"`
	PacketHardening       RadiusPacketHardeningConfig `mapstructure:"packet_hardening"`
	RadSec                RadiusRadSecConfig          `mapstructure:"radsec"`
	EAP                   RadiusEAPConfig             `mapstructure:"eap"`
	Upstream              RadiusUpstreamConfig        `mapstructure:"upstream"`
	Vendor                RadiusVendorConfig          `mapstructure:"vendor"`
}

type RadiusDynamicClientsConfig struct {
	Enabled               bool     `mapstructure:"enabled"`
	DiscoveryEnabled      bool     `mapstructure:"discovery_enabled"`
	ApprovalRequired      bool     `mapstructure:"approval_required"`
	EnrollmentTokenRef    string   `mapstructure:"enrollment_token_ref"`
	EnrollmentTTLSeconds  int      `mapstructure:"enrollment_ttl_seconds"`
	MaxPending            int      `mapstructure:"max_pending"`
	DiscoveryAllowedCIDRs []string `mapstructure:"discovery_allowed_cidrs"`
	DefaultNASType        string   `mapstructure:"default_nas_type"`
	DefaultTransport      string   `mapstructure:"default_transport"`
	DefaultTemplate       string   `mapstructure:"default_template"`
}

type RadiusPacketHardeningConfig struct {
	Enabled                     bool     `mapstructure:"enabled"`
	FailClosed                  bool     `mapstructure:"fail_closed"`
	RequireKnownSource          bool     `mapstructure:"require_known_source"`
	AllowTrailingPadding        bool     `mapstructure:"allow_trailing_padding"`
	AllowStatusServer           bool     `mapstructure:"allow_status_server"`
	AllowStatusClient           bool     `mapstructure:"allow_status_client"`
	RequireMessageAuthenticator string   `mapstructure:"require_message_authenticator"`
	MaxPacketBytes              int      `mapstructure:"max_packet_bytes"`
	MaxAttributesPerPacket      int      `mapstructure:"max_attributes_per_packet"`
	MaxProxyStateAttributes     int      `mapstructure:"max_proxy_state_attributes"`
	MaxProxyStateBytes          int      `mapstructure:"max_proxy_state_bytes"`
	ReplayCacheEnabled          bool     `mapstructure:"replay_cache_enabled"`
	ReplayWindowSeconds         int      `mapstructure:"replay_window_seconds"`
	ReplayCacheMaxEntries       int      `mapstructure:"replay_cache_max_entries"`
	RateLimitEnabled            bool     `mapstructure:"rate_limit_enabled"`
	PerClientRateLimitPerSecond int      `mapstructure:"per_client_rate_limit_per_second"`
	PerClientBurst              int      `mapstructure:"per_client_burst"`
	TrustedProxyCIDRs           []string `mapstructure:"trusted_proxy_cidrs"`
	EventRetentionLimit         int      `mapstructure:"event_retention_limit"`
}

type RadiusClient struct {
	IP                      string `mapstructure:"ip"`
	Secret                  string `mapstructure:"secret"`
	SecretRef               string `mapstructure:"secret_ref"`
	ShortName               string `mapstructure:"shortname"`
	NASType                 string `mapstructure:"nas_type"`
	Transport               string `mapstructure:"transport"`
	RadSecCertificateCN     string `mapstructure:"radsec_certificate_cn"`
	RadSecCertificateIssuer string `mapstructure:"radsec_certificate_issuer"`
	RadSecRadiusV11         string `mapstructure:"radsec_radius_v11"`
}

// RadiusRadSecConfig controls the inbound RFC 6614 listener. Client
// certificates are mandatory whenever the listener is enabled.
type RadiusRadSecConfig struct {
	Enabled                      bool   `mapstructure:"enabled"`
	ListenAddress                string `mapstructure:"listen_address"`
	Port                         int    `mapstructure:"port"`
	CertificateFile              string `mapstructure:"certificate_file"`
	PrivateKeyFile               string `mapstructure:"private_key_file"`
	PrivateKeyPasswordEnv        string `mapstructure:"private_key_password_env"`
	CAFile                       string `mapstructure:"ca_file"`
	CAPath                       string `mapstructure:"ca_path"`
	CheckCRL                     bool   `mapstructure:"check_crl"`
	CheckAllCRL                  bool   `mapstructure:"check_all_crl"`
	CAPathReloadInterval         int    `mapstructure:"ca_path_reload_interval"`
	TLSMinVersion                string `mapstructure:"tls_min_version"`
	TLSMaxVersion                string `mapstructure:"tls_max_version"`
	CipherList                   string `mapstructure:"cipher_list"`
	RadiusV11                    string `mapstructure:"radius_v11"`
	MaxConnections               int    `mapstructure:"max_connections"`
	LifetimeSeconds              int    `mapstructure:"lifetime_seconds"`
	IdleTimeoutSeconds           int    `mapstructure:"idle_timeout_seconds"`
	ProbeIntervalSeconds         int    `mapstructure:"probe_interval_seconds"`
	CertificateExpiryWarningDays int    `mapstructure:"certificate_expiry_warning_days"`
}

type RadiusUpstreamConfig struct {
	Enabled           bool                        `mapstructure:"enabled"`
	Realm             string                      `mapstructure:"realm"`
	PoolStrategy      string                      `mapstructure:"pool_strategy"`
	StatusCheck       string                      `mapstructure:"status_check"`
	ResponseWindow    int                         `mapstructure:"response_window"`
	ZombiePeriod      int                         `mapstructure:"zombie_period"`
	ReviveInterval    int                         `mapstructure:"revive_interval"`
	CheckInterval     int                         `mapstructure:"check_interval"`
	NumAnswersToAlive int                         `mapstructure:"num_answers_to_alive"`
	StripRealm        bool                        `mapstructure:"strip_realm"`
	Servers           []RadiusHomeServer          `mapstructure:"servers"`
	Routes            []RadiusProxyRouteConfig    `mapstructure:"routes"`
	TransportPolicy   RadiusTransportPolicyConfig `mapstructure:"transport_policy"`
	ProxyPolicy       RadiusProxyPolicyConfig     `mapstructure:"proxy_policy"`
	AccountingSpool   RadiusAccountingSpoolConfig `mapstructure:"accounting_spool"`
	FallbackPolicy    RadiusFallbackPolicyConfig  `mapstructure:"fallback_policy"`
}

type RadiusProxyRouteConfig struct {
	Name         string   `mapstructure:"name"`
	Description  string   `mapstructure:"description"`
	Enabled      bool     `mapstructure:"enabled"`
	Realm        string   `mapstructure:"realm"`
	MatchRealms  []string `mapstructure:"match_realms"`
	Default      bool     `mapstructure:"default"`
	StripRealm   bool     `mapstructure:"strip_realm"`
	PoolStrategy string   `mapstructure:"pool_strategy"`
	StatusCheck  string   `mapstructure:"status_check"`
	Servers      []string `mapstructure:"servers"`
}

type RadiusTransportPolicyConfig struct {
	Enabled                  bool                               `mapstructure:"enabled"`
	Mode                     string                             `mapstructure:"mode"`
	FailClosed               bool                               `mapstructure:"fail_closed"`
	DefaultRequiredTransport string                             `mapstructure:"default_required_transport"`
	AllowMixedTransports     bool                               `mapstructure:"allow_mixed_transports"`
	RoutePolicies            []RadiusTransportRoutePolicyConfig `mapstructure:"route_policies"`
}

type RadiusTransportRoutePolicyConfig struct {
	Route                string `mapstructure:"route"`
	RequiredTransport    string `mapstructure:"required_transport"`
	AllowMixedTransports bool   `mapstructure:"allow_mixed_transports"`
	Description          string `mapstructure:"description"`
}

type RadiusProxyPolicyConfig struct {
	Enabled          bool                           `mapstructure:"enabled"`
	FailClosed       bool                           `mapstructure:"fail_closed"`
	DefaultAction    string                         `mapstructure:"default_action"`
	LoopMarker       string                         `mapstructure:"loop_marker"`
	AddLoopMarker    bool                           `mapstructure:"add_loop_marker"`
	RejectLoopMarker bool                           `mapstructure:"reject_loop_marker"`
	MaxHops          int                            `mapstructure:"max_hops"`
	RoutePolicies    []RadiusProxyRoutePolicyConfig `mapstructure:"route_policies"`
}

type RadiusProxyRoutePolicyConfig struct {
	Route                 string                               `mapstructure:"route"`
	Direction             string                               `mapstructure:"direction"`
	TrustedSourceRealms   []string                             `mapstructure:"trusted_source_realms"`
	AllowStandard         []string                             `mapstructure:"allow_standard"`
	DenyStandard          []string                             `mapstructure:"deny_standard"`
	AllowVendorIDs        []int                                `mapstructure:"allow_vendor_ids"`
	DenyVendorIDs         []int                                `mapstructure:"deny_vendor_ids"`
	AllowVendorAttributes []RadiusProxyVendorAttributeSelector `mapstructure:"allow_vendor_attributes"`
	DenyVendorAttributes  []RadiusProxyVendorAttributeSelector `mapstructure:"deny_vendor_attributes"`
	RewriteRules          []RadiusProxyRewriteRuleConfig       `mapstructure:"rewrite_rules"`
	Description           string                               `mapstructure:"description"`
}

type RadiusProxyVendorAttributeSelector struct {
	VendorID    int    `mapstructure:"vendor_id"`
	Type        int    `mapstructure:"type"`
	Name        string `mapstructure:"name"`
	Description string `mapstructure:"description"`
}

type RadiusProxyRewriteRuleConfig struct {
	Attribute   string `mapstructure:"attribute"`
	Action      string `mapstructure:"action"`
	MatchRealm  string `mapstructure:"match_realm"`
	Replacement string `mapstructure:"replacement"`
	Description string `mapstructure:"description"`
}

type RadiusAccountingSpoolConfig struct {
	Enabled                bool `mapstructure:"enabled"`
	MaxQueueRecords        int  `mapstructure:"max_queue_records"`
	MaxAttempts            int  `mapstructure:"max_attempts"`
	InitialRetrySeconds    int  `mapstructure:"initial_retry_seconds"`
	MaxRetrySeconds        int  `mapstructure:"max_retry_seconds"`
	RecordTTLSeconds       int  `mapstructure:"record_ttl_seconds"`
	ReplayIntervalSeconds  int  `mapstructure:"replay_interval_seconds"`
	BatchSize              int  `mapstructure:"batch_size"`
	LockSeconds            int  `mapstructure:"lock_seconds"`
	SentRetentionSeconds   int  `mapstructure:"sent_retention_seconds"`
	PoisonRetentionSeconds int  `mapstructure:"poison_retention_seconds"`
}

type RadiusFallbackPolicyConfig struct {
	Enabled                  bool     `mapstructure:"enabled"`
	Mode                     string   `mapstructure:"mode"`
	FailClosed               bool     `mapstructure:"fail_closed"`
	AllowPortalLocal         bool     `mapstructure:"allow_portal_local"`
	AllowLDAP                bool     `mapstructure:"allow_ldap"`
	RequireIdentityAllowlist bool     `mapstructure:"require_identity_allowlist"`
	MaxOutageSeconds         int      `mapstructure:"max_outage_seconds"`
	StalePolicySeconds       int      `mapstructure:"stale_policy_seconds"`
	RecoverySuccesses        int      `mapstructure:"recovery_successes"`
	AllowedUsers             []string `mapstructure:"allowed_users"`
	AllowedRealms            []string `mapstructure:"allowed_realms"`
	AllowedRoles             []string `mapstructure:"allowed_roles"`
	AuditEnabled             bool     `mapstructure:"audit_enabled"`
	RetentionLimit           int      `mapstructure:"retention_limit"`
}

type RadiusHomeServer struct {
	Name      string                 `mapstructure:"name"`
	Address   string                 `mapstructure:"address"`
	AuthPort  int                    `mapstructure:"auth_port"`
	AcctPort  int                    `mapstructure:"acct_port"`
	Secret    string                 `mapstructure:"secret"`
	SecretRef string                 `mapstructure:"secret_ref"`
	Transport string                 `mapstructure:"transport"`
	RadSec    RadiusRadSecPeerConfig `mapstructure:"radsec"`
}

// RadiusRadSecPeerConfig contains outbound client identity, trust anchors, and
// connection limits for one RadSec home server.
type RadiusRadSecPeerConfig struct {
	Port                  int                   `mapstructure:"port"`
	ServerName            string                `mapstructure:"server_name"`
	CertificateFile       string                `mapstructure:"certificate_file"`
	PrivateKeyFile        string                `mapstructure:"private_key_file"`
	PrivateKeyPasswordEnv string                `mapstructure:"private_key_password_env"`
	CAFile                string                `mapstructure:"ca_file"`
	CAPath                string                `mapstructure:"ca_path"`
	CheckCRL              bool                  `mapstructure:"check_crl"`
	TLSMinVersion         string                `mapstructure:"tls_min_version"`
	TLSMaxVersion         string                `mapstructure:"tls_max_version"`
	CipherList            string                `mapstructure:"cipher_list"`
	RadiusV11             string                `mapstructure:"radius_v11"`
	MaxConnections        int                   `mapstructure:"max_connections"`
	MaxRequests           int                   `mapstructure:"max_requests"`
	LifetimeSeconds       int                   `mapstructure:"lifetime_seconds"`
	IdleTimeoutSeconds    int                   `mapstructure:"idle_timeout_seconds"`
	PSK                   RadiusRadSecPSKConfig `mapstructure:"psk"`
}

// RadiusRadSecPSKConfig enables the optional RFC 9813 TLS-PSK profile for an
// outbound RadSec home server. Secret material is always referenced through the
// enterprise secret-provider interface.
type RadiusRadSecPSKConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Identity       string `mapstructure:"identity"`
	SecretRef      string `mapstructure:"secret_ref"`
	NextIdentity   string `mapstructure:"next_identity"`
	NextSecretRef  string `mapstructure:"next_secret_ref"`
	NextNotBefore  string `mapstructure:"next_not_before"`
	NextNotAfter   string `mapstructure:"next_not_after"`
	OverlapSeconds int    `mapstructure:"overlap_seconds"`
	WarningDays    int    `mapstructure:"warning_days"`
}

type RadiusVendorConfig struct {
	Enabled               bool                               `mapstructure:"enabled"`
	Name                  string                             `mapstructure:"name"`
	ID                    int                                `mapstructure:"id"`
	DictionaryRelease     string                             `mapstructure:"dictionary_release"`
	IdentityMode          string                             `mapstructure:"identity_mode"`
	AssignedOrganization  string                             `mapstructure:"assigned_organization"`
	AssignmentRegistryURL string                             `mapstructure:"assignment_registry_url"`
	RegistryLastUpdated   string                             `mapstructure:"registry_last_updated"`
	AssignmentVerifiedAt  string                             `mapstructure:"assignment_verified_at"`
	AssignmentRegistrySHA string                             `mapstructure:"assignment_registry_sha256"`
	AssignmentRecordSHA   string                             `mapstructure:"assignment_record_sha256"`
	LegacyIDs             []int                              `mapstructure:"legacy_ids"`
	LegacyAcceptUntil     string                             `mapstructure:"legacy_accept_until"`
	CompatibilityPacks    []string                           `mapstructure:"compatibility_packs"`
	DictionaryPaths       []string                           `mapstructure:"dictionary_paths"`
	RoleMappings          []RadiusVendorRoleMapping          `mapstructure:"role_mappings"`
	ExtendedVLANMappings  []RadiusVendorExtendedVLANMapping  `mapstructure:"extended_vlan_mappings"`
	AVPairMappings        []RadiusVendorAVPairMapping        `mapstructure:"avpair_mappings"`
	PortalStatusMappings  []RadiusVendorPortalStatusMapping  `mapstructure:"portal_status_mappings"`
	SessionActionMappings []RadiusVendorSessionActionMapping `mapstructure:"session_action_mappings"`
	QuotaMappings         []RadiusVendorQuotaMapping         `mapstructure:"quota_mappings"`
	ServiceNameMappings   []RadiusVendorServiceNameMapping   `mapstructure:"service_name_mappings"`
	OpaquePassThrough     RadiusOpaquePassThroughConfig      `mapstructure:"opaque_pass_through"`
	Attributes            []RadiusVendorAttribute            `mapstructure:"attributes"`
}

type RadiusOpaquePassThroughConfig struct {
	Enabled                bool                          `mapstructure:"enabled"`
	MaxAttributesPerPacket int                           `mapstructure:"max_attributes_per_packet"`
	MaxAttributeBytes      int                           `mapstructure:"max_attribute_bytes"`
	MaxTotalBytesPerPacket int                           `mapstructure:"max_total_bytes_per_packet"`
	Rules                  []RadiusOpaquePassThroughRule `mapstructure:"rules"`
}

type RadiusOpaquePassThroughRule struct {
	Direction         string `mapstructure:"direction"`
	Kind              string `mapstructure:"kind"`
	VendorID          int    `mapstructure:"vendor_id"`
	Type              int    `mapstructure:"type"`
	MaxAttributeBytes int    `mapstructure:"max_attribute_bytes"`
	AllowKnown        bool   `mapstructure:"allow_known"`
	Description       string `mapstructure:"description"`
}

type RadiusVendorRoleMapping struct {
	Pack  string `mapstructure:"pack"`
	Role  string `mapstructure:"role"`
	Value int    `mapstructure:"value"`
}

type RadiusVendorExtendedVLANMapping struct {
	Pack         string `mapstructure:"pack"`
	Role         string `mapstructure:"role"`
	UntaggedVLAN int    `mapstructure:"untagged_vlan"`
	TaggedVLANs  []int  `mapstructure:"tagged_vlans"`
}

type RadiusVendorAVPairMapping struct {
	Pack   string   `mapstructure:"pack"`
	Role   string   `mapstructure:"role"`
	Values []string `mapstructure:"values"`
}

type RadiusVendorPortalStatusMapping struct {
	Pack          string `mapstructure:"pack"`
	PortalProfile string `mapstructure:"portal_profile"`
	Value         int    `mapstructure:"value"`
}

type RadiusVendorSessionActionMapping struct {
	Pack   string `mapstructure:"pack"`
	Role   string `mapstructure:"role"`
	Action string `mapstructure:"action"`
	Value  int    `mapstructure:"value"`
}

type RadiusVendorQuotaMapping struct {
	Pack           string `mapstructure:"pack"`
	Role           string `mapstructure:"role"`
	MaxTotalOctets int64  `mapstructure:"max_total_octets"`
}

type RadiusVendorServiceNameMapping struct {
	Pack        string `mapstructure:"pack"`
	Role        string `mapstructure:"role"`
	ServiceName string `mapstructure:"service_name"`
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
	DefaultType          string                     `mapstructure:"default_type"`
	PEAPInner            string                     `mapstructure:"peap_inner"`
	TTLSInner            string                     `mapstructure:"ttls_inner"`
	TLSMinVersion        string                     `mapstructure:"tls_min_version"`
	TLSMaxVersion        string                     `mapstructure:"tls_max_version"`
	CheckCRL             bool                       `mapstructure:"check_crl"`
	CheckAllCRL          bool                       `mapstructure:"check_all_crl"`
	CAPathReloadInterval int                        `mapstructure:"ca_path_reload_interval"`
	OCSP                 RadiusEAPOCSPConfig        `mapstructure:"ocsp"`
	Framework            RadiusEAPFramework         `mapstructure:"framework"`
	TEAP                 RadiusEAPTEAPConfig        `mapstructure:"teap"`
	MachineUser          RadiusEAPMachineUserConfig `mapstructure:"machine_user"`
	FAST                 RadiusEAPFASTConfig        `mapstructure:"fast"`
	PWD                  RadiusEAPPWDConfig         `mapstructure:"pwd"`
	SIMAKA               RadiusEAPSIMAKAConfig      `mapstructure:"sim_aka"`
}

type RadiusEAPOCSPConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	OverrideCertURL bool   `mapstructure:"override_cert_url"`
	URL             string `mapstructure:"url"`
	UseNonce        bool   `mapstructure:"use_nonce"`
	TimeoutSeconds  int    `mapstructure:"timeout_seconds"`
	SoftFail        bool   `mapstructure:"soft_fail"`
}

type RadiusEAPTEAPConfig struct {
	Enabled                bool   `mapstructure:"enabled"`
	DefaultInnerMethod     string `mapstructure:"default_inner_method"`
	ChainMode              string `mapstructure:"chain_mode"`
	RequireCryptoBinding   bool   `mapstructure:"require_crypto_binding"`
	RequireChannelBinding  bool   `mapstructure:"require_channel_binding"`
	RequireIdentityType    bool   `mapstructure:"require_identity_type"`
	RequireMachineIdentity bool   `mapstructure:"require_machine_identity"`
	RequireUserIdentity    bool   `mapstructure:"require_user_identity"`
	AllowPAC               bool   `mapstructure:"allow_pac"`
	RequirePAC             bool   `mapstructure:"require_pac"`
	PACProvisioning        string `mapstructure:"pac_provisioning"`
	PACAuthorityID         string `mapstructure:"pac_authority_id"`
	PACLifetimeSeconds     int    `mapstructure:"pac_lifetime_seconds"`
	AllowEAPPayload        bool   `mapstructure:"allow_eap_payload"`
	AllowBasicPasswordAuth bool   `mapstructure:"allow_basic_password_auth"`
	MaxChainSteps          int    `mapstructure:"max_chain_steps"`
	SessionTTLSeconds      int    `mapstructure:"session_ttl_seconds"`
	EventRetentionLimit    int    `mapstructure:"event_retention_limit"`
}

type RadiusEAPMachineUserConfig struct {
	Enabled                   bool     `mapstructure:"enabled"`
	Mode                      string   `mapstructure:"mode"`
	FailClosed                bool     `mapstructure:"fail_closed"`
	CorrelationMode           string   `mapstructure:"correlation_mode"`
	RequireTEAP               bool     `mapstructure:"require_teap"`
	RequireMachineIdentity    bool     `mapstructure:"require_machine_identity"`
	RequireUserIdentity       bool     `mapstructure:"require_user_identity"`
	RequireMachineBeforeUser  bool     `mapstructure:"require_machine_before_user"`
	RequireSameCallingStation bool     `mapstructure:"require_same_calling_station"`
	RequireSameNAS            bool     `mapstructure:"require_same_nas"`
	RequireFreshMachineAuth   bool     `mapstructure:"require_fresh_machine_auth"`
	MachineAuthTTLSeconds     int      `mapstructure:"machine_auth_ttl_seconds"`
	UserAuthTTLSeconds        int      `mapstructure:"user_auth_ttl_seconds"`
	TransitionWindowSeconds   int      `mapstructure:"transition_window_seconds"`
	AllowedMachineMethods     []string `mapstructure:"allowed_machine_methods"`
	AllowedUserMethods        []string `mapstructure:"allowed_user_methods"`
	IdentityPrecedence        string   `mapstructure:"identity_precedence"`
	RoleMergeStrategy         string   `mapstructure:"role_merge_strategy"`
	ConflictAction            string   `mapstructure:"conflict_action"`
	StaleMachineAction        string   `mapstructure:"stale_machine_action"`
	MachineIdentityPrefixes   []string `mapstructure:"machine_identity_prefixes"`
	UserIdentityPrefixes      []string `mapstructure:"user_identity_prefixes"`
	MaxActiveCorrelations     int      `mapstructure:"max_active_correlations"`
	AuditEnabled              bool     `mapstructure:"audit_enabled"`
	EventRetentionLimit       int      `mapstructure:"event_retention_limit"`
}

type RadiusEAPFASTConfig struct {
	Enabled                    bool   `mapstructure:"enabled"`
	DefaultInnerMethod         string `mapstructure:"default_inner_method"`
	RequireCryptoBinding       bool   `mapstructure:"require_crypto_binding"`
	AllowPAC                   bool   `mapstructure:"allow_pac"`
	RequirePAC                 bool   `mapstructure:"require_pac"`
	PACProvisioning            string `mapstructure:"pac_provisioning"`
	PACAuthorityID             string `mapstructure:"pac_authority_id"`
	PACLifetimeSeconds         int    `mapstructure:"pac_lifetime_seconds"`
	PACOpaqueKeyRef            string `mapstructure:"pac_opaque_key_ref"`
	AllowAnonymousProvisioning bool   `mapstructure:"allow_anonymous_provisioning"`
	AllowEAPPayload            bool   `mapstructure:"allow_eap_payload"`
	MaxProvisioningAttempts    int    `mapstructure:"max_provisioning_attempts"`
	SessionTTLSeconds          int    `mapstructure:"session_ttl_seconds"`
	EventRetentionLimit        int    `mapstructure:"event_retention_limit"`
}

type RadiusEAPPWDConfig struct {
	Enabled              bool   `mapstructure:"enabled"`
	Group                int    `mapstructure:"group"`
	ServerID             string `mapstructure:"server_id"`
	RequireStrongGroup   bool   `mapstructure:"require_strong_group"`
	PasswordSource       string `mapstructure:"password_source"`
	AllowLocalVerifier   bool   `mapstructure:"allow_local_verifier"`
	RequireIdentity      bool   `mapstructure:"require_identity"`
	RequirePasswordProof bool   `mapstructure:"require_password_proof"`
	ReplayWindowSeconds  int    `mapstructure:"replay_window_seconds"`
	FragmentSize         int    `mapstructure:"fragment_size"`
	EventRetentionLimit  int    `mapstructure:"event_retention_limit"`
}

type RadiusEAPSIMAKAConfig struct {
	Enabled                   bool     `mapstructure:"enabled"`
	Methods                   []string `mapstructure:"methods"`
	RequireIdentity           bool     `mapstructure:"require_identity"`
	RequirePermanentIdentity  bool     `mapstructure:"require_permanent_identity"`
	AllowPseudonymIdentity    bool     `mapstructure:"allow_pseudonym_identity"`
	RequirePseudonymReauth    bool     `mapstructure:"require_pseudonym_reauth"`
	PseudonymTTLSeconds       int      `mapstructure:"pseudonym_ttl_seconds"`
	ReauthTTLSeconds          int      `mapstructure:"reauth_ttl_seconds"`
	VectorProvider            string   `mapstructure:"vector_provider"`
	VectorProviderRef         string   `mapstructure:"vector_provider_ref"`
	RequireFreshVectors       bool     `mapstructure:"require_fresh_vectors"`
	MaxVectorAgeSeconds       int      `mapstructure:"max_vector_age_seconds"`
	MinTriplets               int      `mapstructure:"min_triplets"`
	MinQuintuplets            int      `mapstructure:"min_quintuplets"`
	AllowResynchronization    bool     `mapstructure:"allow_resynchronization"`
	ResyncWindowSeconds       int      `mapstructure:"resync_window_seconds"`
	RequireNetworkName        bool     `mapstructure:"require_network_name"`
	NetworkName               string   `mapstructure:"network_name"`
	RequireKDF                bool     `mapstructure:"require_kdf"`
	FailOnProviderUnavailable bool     `mapstructure:"fail_on_provider_unavailable"`
	EventRetentionLimit       int      `mapstructure:"event_retention_limit"`
}

type RadiusEAPFramework struct {
	Enabled                     bool                         `mapstructure:"enabled"`
	Mode                        string                       `mapstructure:"mode"`
	FailClosed                  bool                         `mapstructure:"fail_closed"`
	AllowedMethods              []string                     `mapstructure:"allowed_methods"`
	AllowedInnerMethods         []string                     `mapstructure:"allowed_inner_methods"`
	DefaultOuterIdentitySource  string                       `mapstructure:"default_outer_identity_source"`
	DefaultInnerIdentitySource  string                       `mapstructure:"default_inner_identity_source"`
	MethodPolicies              []RadiusEAPMethodPolicy      `mapstructure:"method_policies"`
	UnsupportedMethodAction     string                       `mapstructure:"unsupported_method_action"`
	RequireMessageAuthenticator bool                         `mapstructure:"require_message_authenticator"`
	RequireIdentityBinding      bool                         `mapstructure:"require_identity_binding"`
	TelemetryEnabled            bool                         `mapstructure:"telemetry_enabled"`
	EventRetentionLimit         int                          `mapstructure:"event_retention_limit"`
	MaxConcurrentSessions       int                          `mapstructure:"max_concurrent_sessions"`
	MethodTimeoutSeconds        int                          `mapstructure:"method_timeout_seconds"`
	FragmentSize                int                          `mapstructure:"fragment_size"`
	NakUnknownTypes             bool                         `mapstructure:"nak_unknown_types"`
	IdentitySources             []RadiusEAPIdentitySource    `mapstructure:"identity_sources"`
	VendorCompatibilityProfiles []RadiusEAPVendorProfileRule `mapstructure:"vendor_compatibility_profiles"`
}

type RadiusEAPMethodPolicy struct {
	Method                string   `mapstructure:"method"`
	Enabled               bool     `mapstructure:"enabled"`
	InnerMethods          []string `mapstructure:"inner_methods"`
	IdentitySource        string   `mapstructure:"identity_source"`
	RequireCertificate    bool     `mapstructure:"require_certificate"`
	RequireRevocation     bool     `mapstructure:"require_revocation"`
	AllowPasswordVerifier bool     `mapstructure:"allow_password_verifier"`
	MinTLSVersion         string   `mapstructure:"min_tls_version"`
	MaxTLSVersion         string   `mapstructure:"max_tls_version"`
	VendorProfiles        []string `mapstructure:"vendor_profiles"`
}

type RadiusEAPIdentitySource struct {
	Name                    string   `mapstructure:"name"`
	Source                  string   `mapstructure:"source"`
	Enabled                 bool     `mapstructure:"enabled"`
	Methods                 []string `mapstructure:"methods"`
	AllowPasswordVerifier   bool     `mapstructure:"allow_password_verifier"`
	AllowCertificateSubject bool     `mapstructure:"allow_certificate_subject"`
	Priority                int      `mapstructure:"priority"`
}

type RadiusEAPVendorProfileRule struct {
	Name            string   `mapstructure:"name"`
	NASTypes        []string `mapstructure:"nas_types"`
	AllowedMethods  []string `mapstructure:"allowed_methods"`
	RequiredMethods []string `mapstructure:"required_methods"`
	Notes           string   `mapstructure:"notes"`
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

type IdentityConfig struct {
	Failover IdentityFailoverConfig `mapstructure:"failover"`
}

type IdentityFailoverConfig struct {
	Enabled                    bool     `mapstructure:"enabled"`
	Mode                       string   `mapstructure:"mode"`
	FailClosed                 bool     `mapstructure:"fail_closed"`
	SourceOrder                []string `mapstructure:"source_order"`
	MaxFailures                int      `mapstructure:"max_failures"`
	CircuitOpenSeconds         int      `mapstructure:"circuit_open_seconds"`
	StaleCacheSeconds          int      `mapstructure:"stale_cache_seconds"`
	CacheCredentials           bool     `mapstructure:"cache_credentials"`
	SplitResultPolicy          string   `mapstructure:"split_result_policy"`
	HealthCheckIntervalSeconds int      `mapstructure:"health_check_interval_seconds"`
	AuditEnabled               bool     `mapstructure:"audit_enabled"`
	RetentionLimit             int      `mapstructure:"retention_limit"`
}

type ActiveDirectoryConfig struct {
	Enabled                    bool                          `mapstructure:"enabled"`
	Mode                       string                        `mapstructure:"mode"`
	FailClosed                 bool                          `mapstructure:"fail_closed"`
	Domain                     string                        `mapstructure:"domain"`
	Realm                      string                        `mapstructure:"realm"`
	NetBIOSDomain              string                        `mapstructure:"netbios_domain"`
	LDAPURL                    string                        `mapstructure:"ldap_url"`
	BaseDN                     string                        `mapstructure:"base_dn"`
	BindDN                     string                        `mapstructure:"bind_dn"`
	BindPassword               string                        `mapstructure:"bind_password"`
	BindPasswordRef            string                        `mapstructure:"bind_password_ref"`
	UserFilter                 string                        `mapstructure:"user_filter"`
	GroupFilter                string                        `mapstructure:"group_filter"`
	RequireLDAPS               bool                          `mapstructure:"require_ldaps"`
	NestedGroups               bool                          `mapstructure:"nested_groups"`
	AuthMethod                 string                        `mapstructure:"auth_method"`
	DefaultRole                string                        `mapstructure:"default_role"`
	GroupRoleMappings          map[string]string             `mapstructure:"group_role_mappings"`
	RequestTimeoutSeconds      int                           `mapstructure:"request_timeout_seconds"`
	GroupCacheTTLSeconds       int                           `mapstructure:"group_cache_ttl_seconds"`
	HealthCheckIntervalSeconds int                           `mapstructure:"health_check_interval_seconds"`
	ClockSkewSeconds           int                           `mapstructure:"clock_skew_seconds"`
	AuditEnabled               bool                          `mapstructure:"audit_enabled"`
	RetentionLimit             int                           `mapstructure:"retention_limit"`
	Kerberos                   ActiveDirectoryKerberosConfig `mapstructure:"kerberos"`
	Winbind                    ActiveDirectoryWinbindConfig  `mapstructure:"winbind"`
}

type ActiveDirectoryKerberosConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	KinitPath          string `mapstructure:"kinit_path"`
	KDestroyPath       string `mapstructure:"kdestroy_path"`
	Krb5ConfigPath     string `mapstructure:"krb5_config_path"`
	KeytabPath         string `mapstructure:"keytab_path"`
	ServicePrincipal   string `mapstructure:"service_principal"`
	CredentialCacheDir string `mapstructure:"credential_cache_dir"`
}

type ActiveDirectoryWinbindConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	DomainJoinRequired bool   `mapstructure:"domain_join_required"`
	WbinfoPath         string `mapstructure:"wbinfo_path"`
	NTLMAuthPath       string `mapstructure:"ntlm_auth_path"`
	AuthHelperPath     string `mapstructure:"auth_helper_path"`
}

type MFAConfig struct {
	Enabled         bool                     `mapstructure:"enabled"`
	Mode            string                   `mapstructure:"mode"`
	FailClosed      bool                     `mapstructure:"fail_closed"`
	OTP             MFAOTPConfig             `mapstructure:"otp"`
	RadiusChallenge MFARadiusChallengeConfig `mapstructure:"radius_challenge"`
	Recovery        MFARecoveryConfig        `mapstructure:"recovery"`
	AuditEnabled    bool                     `mapstructure:"audit_enabled"`
	RetentionLimit  int                      `mapstructure:"retention_limit"`
}

type MFAOTPConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	Issuer            string   `mapstructure:"issuer"`
	Algorithm         string   `mapstructure:"algorithm"`
	Digits            int      `mapstructure:"digits"`
	PeriodSeconds     int      `mapstructure:"period_seconds"`
	WindowSteps       int      `mapstructure:"window_steps"`
	MaxAttempts       int      `mapstructure:"max_attempts"`
	SealingKeyRef     string   `mapstructure:"sealing_key_ref"`
	StepUpRoles       []string `mapstructure:"step_up_roles"`
	StepUpRealms      []string `mapstructure:"step_up_realms"`
	RequiredForAdmins bool     `mapstructure:"required_for_admins"`
}

type MFARadiusChallengeConfig struct {
	Enabled                bool   `mapstructure:"enabled"`
	TTLSeconds             int    `mapstructure:"ttl_seconds"`
	MaxPending             int    `mapstructure:"max_pending"`
	Prompt                 string `mapstructure:"prompt"`
	StateBytes             int    `mapstructure:"state_bytes"`
	AllowPAPPasswordAppend bool   `mapstructure:"allow_pap_password_append"`
}

type MFARecoveryConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	CodeCount      int  `mapstructure:"code_count"`
	CodeBytes      int  `mapstructure:"code_bytes"`
	CodeTTLSeconds int  `mapstructure:"code_ttl_seconds"`
}

type AdminWebAuthnConfig struct {
	Enabled                  bool     `mapstructure:"enabled"`
	Mode                     string   `mapstructure:"mode"`
	FailClosed               bool     `mapstructure:"fail_closed"`
	RPID                     string   `mapstructure:"rp_id"`
	RPName                   string   `mapstructure:"rp_name"`
	Origins                  []string `mapstructure:"origins"`
	ChallengeTTLSeconds      int      `mapstructure:"challenge_ttl_seconds"`
	SessionTTLSeconds        int      `mapstructure:"session_ttl_seconds"`
	MaxPending               int      `mapstructure:"max_pending"`
	UserVerification         string   `mapstructure:"user_verification"`
	Attestation              string   `mapstructure:"attestation"`
	ResidentKey              string   `mapstructure:"resident_key"`
	RequireForRoles          []string `mapstructure:"require_for_roles"`
	RequireForSSO            bool     `mapstructure:"require_for_sso"`
	RequireForTokenLogin     bool     `mapstructure:"require_for_token_login"`
	BreakGlassAllowed        bool     `mapstructure:"break_glass_allowed"`
	AllowBootstrapEnrollment bool     `mapstructure:"allow_bootstrap_enrollment"`
	AuditEnabled             bool     `mapstructure:"audit_enabled"`
	RetentionLimit           int      `mapstructure:"retention_limit"`
}

type MABConfig struct {
	Enabled                   bool     `mapstructure:"enabled"`
	Mode                      string   `mapstructure:"mode"`
	FailClosed                bool     `mapstructure:"fail_closed"`
	UnknownEndpointPolicy     string   `mapstructure:"unknown_endpoint_policy"`
	DefaultRole               string   `mapstructure:"default_role"`
	GuestRole                 string   `mapstructure:"guest_role"`
	QuarantineRole            string   `mapstructure:"quarantine_role"`
	AllowedNASPortTypes       []string `mapstructure:"allowed_nas_port_types"`
	MACFormats                []string `mapstructure:"mac_formats"`
	PasswordPolicy            string   `mapstructure:"password_policy"`
	ProfilingLinkEnabled      bool     `mapstructure:"profiling_link_enabled"`
	EndpointInventoryFallback bool     `mapstructure:"endpoint_inventory_fallback"`
	RevalidateIntervalSeconds int      `mapstructure:"revalidate_interval_seconds"`
	CacheTTLSeconds           int      `mapstructure:"cache_ttl_seconds"`
	AuditEnabled              bool     `mapstructure:"audit_enabled"`
	RetentionLimit            int      `mapstructure:"retention_limit"`
}

type LDAPConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	URL             string `mapstructure:"url"`
	BaseDN          string `mapstructure:"base_dn"`
	BindDN          string `mapstructure:"bind_dn"`
	BindPassword    string `mapstructure:"bind_password"`
	BindPasswordRef string `mapstructure:"bind_password_ref"`
	UserFilter      string `mapstructure:"user_filter"`
	GroupFilter     string `mapstructure:"group_filter"`
}

type PolicyConfig struct {
	DefaultRole              string `mapstructure:"default_role"`
	RuntimeShapingEnabled    bool   `mapstructure:"runtime_shaping_enabled"`
	TypedEngineEnabled       bool   `mapstructure:"typed_engine_enabled"`
	Mode                     string `mapstructure:"mode"`
	FailClosed               bool   `mapstructure:"fail_closed"`
	AuditEnabled             bool   `mapstructure:"audit_enabled"`
	AllowLegacyConditions    bool   `mapstructure:"allow_legacy_conditions"`
	RequireTypedRules        bool   `mapstructure:"require_typed_rules"`
	MaxExpressionDepth       int    `mapstructure:"max_expression_depth"`
	MaxExpressionNodes       int    `mapstructure:"max_expression_nodes"`
	MaxListValues            int    `mapstructure:"max_list_values"`
	EvaluationRetentionLimit int    `mapstructure:"evaluation_retention_limit"`
}

type TelemetryConfig struct {
	Enabled                           bool                      `mapstructure:"enabled"`
	PrometheusPort                    int                       `mapstructure:"prometheus_port"`
	LeaseHistoryPollSeconds           int                       `mapstructure:"lease_history_poll_seconds"`
	SupportBundleExports              SupportBundleExportConfig `mapstructure:"support_bundle_exports"`
	DiagnosticsExports                DiagnosticsExportConfig   `mapstructure:"diagnostics_exports"`
	AuditExports                      DiagnosticsExportConfig   `mapstructure:"audit_exports"`
	SessionExports                    DiagnosticsExportConfig   `mapstructure:"session_exports"`
	SessionAnalyticsExports           DiagnosticsExportConfig   `mapstructure:"session_analytics_exports"`
	VoucherAnalyticsExports           DiagnosticsExportConfig   `mapstructure:"voucher_analytics_exports"`
	VoucherAgingAnalyticsExports      DiagnosticsExportConfig   `mapstructure:"voucher_aging_analytics_exports"`
	VoucherRedemptionAnalyticsExports DiagnosticsExportConfig   `mapstructure:"voucher_redemption_analytics_exports"`
	VoucherExpiryAnalyticsExports     DiagnosticsExportConfig   `mapstructure:"voucher_expiry_analytics_exports"`
	GuestLifecycleExports             DiagnosticsExportConfig   `mapstructure:"guest_lifecycle_exports"`
	GuestInviteAnalyticsExports       DiagnosticsExportConfig   `mapstructure:"guest_invite_analytics_exports"`
	GuestConversionAnalyticsExports   DiagnosticsExportConfig   `mapstructure:"guest_conversion_analytics_exports"`
	GuestRejectionAnalyticsExports    DiagnosticsExportConfig   `mapstructure:"guest_rejection_analytics_exports"`
	GuestDeliveryAnalyticsExports     DiagnosticsExportConfig   `mapstructure:"guest_delivery_analytics_exports"`
	GuestDeliveryFailuresExports      DiagnosticsExportConfig   `mapstructure:"guest_delivery_failures_exports"`
	GuestSponsorAnalyticsExports      DiagnosticsExportConfig   `mapstructure:"guest_sponsor_analytics_exports"`
	IntegrationExports                DiagnosticsExportConfig   `mapstructure:"integration_exports"`
	HAExports                         DiagnosticsExportConfig   `mapstructure:"ha_exports"`
	NetworkExports                    DiagnosticsExportConfig   `mapstructure:"network_exports"`
	UpstreamAAAExports                DiagnosticsExportConfig   `mapstructure:"upstream_aaa_exports"`
	UpgradeReadinessExports           DiagnosticsExportConfig   `mapstructure:"upgrade_readiness_exports"`
}

type SupportBundleExportConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Directory       string `mapstructure:"directory"`
	IntervalMinutes int    `mapstructure:"interval_minutes"`
	RetentionCount  int    `mapstructure:"retention_count"`
}

type DiagnosticsExportConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	Directory       string `mapstructure:"directory"`
	Format          string `mapstructure:"format"`
	IntervalMinutes int    `mapstructure:"interval_minutes"`
	RetentionCount  int    `mapstructure:"retention_count"`
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
	DeviceInventoryEnabled       bool                       `mapstructure:"device_inventory_enabled"`
	PortalEnabled                bool                       `mapstructure:"portal_enabled"`
	CertificateEnrollmentEnabled bool                       `mapstructure:"certificate_enrollment_enabled"`
	EAPTLSEnabled                bool                       `mapstructure:"eap_tls_enabled"`
	CAMode                       string                     `mapstructure:"ca_mode"`
	CACertPath                   string                     `mapstructure:"ca_cert_path"`
	CAKeyPath                    string                     `mapstructure:"ca_key_path"`
	CAEnrollmentURL              string                     `mapstructure:"ca_enrollment_url"`
	CAEnrollmentTokenEnv         string                     `mapstructure:"ca_enrollment_token_env"`
	CertificateLifecycle         CertificateLifecycleConfig `mapstructure:"certificate_lifecycle"`
	SupplicantLifecycle          SupplicantLifecycleConfig  `mapstructure:"supplicant_lifecycle"`
}

type CertificateLifecycleConfig struct {
	Enabled                    bool     `mapstructure:"enabled"`
	Mode                       string   `mapstructure:"mode"`
	FailClosed                 bool     `mapstructure:"fail_closed"`
	DefaultTemplate            string   `mapstructure:"default_template"`
	Templates                  []string `mapstructure:"templates"`
	ActiveIssuer               string   `mapstructure:"active_issuer"`
	StagedIssuer               string   `mapstructure:"staged_issuer"`
	IssuerRotationMode         string   `mapstructure:"issuer_rotation_mode"`
	IssuerOverlapSeconds       int      `mapstructure:"issuer_overlap_seconds"`
	CertificateValidityDays    int      `mapstructure:"certificate_validity_days"`
	MaxCertificateValidityDays int      `mapstructure:"max_certificate_validity_days"`
	RenewalWindowDays          int      `mapstructure:"renewal_window_days"`
	RequireCSR                 bool     `mapstructure:"require_csr"`
	RequireProofOfPossession   bool     `mapstructure:"require_proof_of_possession"`
	RequireDeviceBinding       bool     `mapstructure:"require_device_binding"`
	RequireSubjectAltName      bool     `mapstructure:"require_subject_alt_name"`
	AllowedKeyTypes            []string `mapstructure:"allowed_key_types"`
	MinRSABits                 int      `mapstructure:"min_rsa_bits"`
	AllowedECDSACurves         []string `mapstructure:"allowed_ecdsa_curves"`
	AllowServerKeyGeneration   bool     `mapstructure:"allow_server_key_generation"`
	EscrowPolicy               string   `mapstructure:"escrow_policy"`
	CRLEnabled                 bool     `mapstructure:"crl_enabled"`
	CRLPublishPath             string   `mapstructure:"crl_publish_path"`
	OCSPEnabled                bool     `mapstructure:"ocsp_enabled"`
	OCSPResponderURL           string   `mapstructure:"ocsp_responder_url"`
	ESTEnabled                 bool     `mapstructure:"est_enabled"`
	SCEPEnabled                bool     `mapstructure:"scep_enabled"`
	BYODPortalEnabled          bool     `mapstructure:"byod_portal_enabled"`
	AuditEnabled               bool     `mapstructure:"audit_enabled"`
	EventRetentionLimit        int      `mapstructure:"event_retention_limit"`
	InventoryRetentionLimit    int      `mapstructure:"inventory_retention_limit"`
}

type SupplicantLifecycleConfig struct {
	Enabled                      bool     `mapstructure:"enabled"`
	Mode                         string   `mapstructure:"mode"`
	FailClosed                   bool     `mapstructure:"fail_closed"`
	SSID                         string   `mapstructure:"ssid"`
	Security                     string   `mapstructure:"security"`
	DefaultPlatform              string   `mapstructure:"default_platform"`
	AllowedPlatforms             []string `mapstructure:"allowed_platforms"`
	DefaultEAPMethod             string   `mapstructure:"default_eap_method"`
	AllowedEAPMethods            []string `mapstructure:"allowed_eap_methods"`
	DefaultInnerMethod           string   `mapstructure:"default_inner_method"`
	AllowedInnerMethods          []string `mapstructure:"allowed_inner_methods"`
	AnonymousIdentity            string   `mapstructure:"anonymous_identity"`
	RequireAnonymousIdentity     bool     `mapstructure:"require_anonymous_identity"`
	DomainSuffix                 string   `mapstructure:"domain_suffix"`
	ServerNames                  []string `mapstructure:"server_names"`
	TrustAnchorPins              []string `mapstructure:"trust_anchor_pins"`
	RequireTrustAnchorPinning    bool     `mapstructure:"require_trust_anchor_pinning"`
	AllowPasswordChange          bool     `mapstructure:"allow_password_change"`
	PasswordChangeURL            string   `mapstructure:"password_change_url"`
	PasswordChangeProviders      []string `mapstructure:"password_change_providers"`
	RequireVerifierCompatibility bool     `mapstructure:"require_verifier_compatibility"`
	CompatibleVerifiers          []string `mapstructure:"compatible_verifiers"`
	MaxPasswordAgeDays           int      `mapstructure:"max_password_age_days"`
	ExpiryWarningDays            int      `mapstructure:"expiry_warning_days"`
	GracePeriodDays              int      `mapstructure:"grace_period_days"`
	MinPasswordLength            int      `mapstructure:"min_password_length"`
	RequireMFAForChange          bool     `mapstructure:"require_mfa_for_change"`
	RequireTLSForDelivery        bool     `mapstructure:"require_tls_for_delivery"`
	RequireSignedProfiles        bool     `mapstructure:"require_signed_profiles"`
	ProfileSigningKeyRef         string   `mapstructure:"profile_signing_key_ref"`
	ProfileValidityDays          int      `mapstructure:"profile_validity_days"`
	DeliveryTokenTTLSeconds      int      `mapstructure:"delivery_token_ttl_seconds"`
	AuditEnabled                 bool     `mapstructure:"audit_enabled"`
	EventRetentionLimit          int      `mapstructure:"event_retention_limit"`
	ProfileRetentionLimit        int      `mapstructure:"profile_retention_limit"`
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
	Enabled         bool   `mapstructure:"enabled"`
	Platform        string `mapstructure:"platform"`
	Endpoint        string `mapstructure:"endpoint"`
	APITokenEnv     string `mapstructure:"api_token_env"`
	APIUsernameEnv  string `mapstructure:"api_username_env"`
	APIPasswordEnv  string `mapstructure:"api_password_env"`
	RadiusProfile   string `mapstructure:"radius_profile"`
	RadiusServer    string `mapstructure:"radius_server"`
	RadiusSecretEnv string `mapstructure:"radius_secret_env"`
	SyncMode        string `mapstructure:"sync_mode"`
	Site            string `mapstructure:"site"`
}

type GovernanceConfig struct {
	DelegatedAdminEnabled bool   `mapstructure:"delegated_admin_enabled"`
	RBACMode              string `mapstructure:"rbac_mode"`
	ExternalGroupsEnabled bool   `mapstructure:"external_groups_enabled"`
	MultiTenantEnabled    bool   `mapstructure:"multi_tenant_enabled"`
	TenantClaim           string `mapstructure:"tenant_claim"`
}

type SecurityConfig struct {
	Secrets SecretProviderConfig `mapstructure:"secrets"`
}

type SecretProviderConfig struct {
	Enabled                     bool     `mapstructure:"enabled"`
	Providers                   []string `mapstructure:"providers"`
	FileBaseDir                 string   `mapstructure:"file_base_dir"`
	MaxSecretBytes              int      `mapstructure:"max_secret_bytes"`
	AllowInline                 bool     `mapstructure:"allow_inline"`
	ProductionRequireReferences bool     `mapstructure:"production_require_references"`
}

type HighAvailabilityConfig struct {
	Enabled                         bool                `mapstructure:"enabled"`
	Role                            string              `mapstructure:"role"`
	PeerAPIURL                      string              `mapstructure:"peer_api_url"`
	VirtualIP                       string              `mapstructure:"virtual_ip"`
	HeartbeatIntervalSeconds        int                 `mapstructure:"heartbeat_interval_seconds"`
	FailoverTimeoutSeconds          int                 `mapstructure:"failover_timeout_seconds"`
	ReplicationIntervalSeconds      int                 `mapstructure:"replication_interval_seconds"`
	ReplicationStaleAfterSeconds    int                 `mapstructure:"replication_stale_after_seconds"`
	SplitBrainProtectionEnabled     bool                `mapstructure:"split_brain_protection_enabled"`
	AutoStageSharedPackage          bool                `mapstructure:"auto_stage_shared_package"`
	AutoActivateOnFailover          bool                `mapstructure:"auto_activate_on_failover"`
	ReplicationSigningKeyEnv        string              `mapstructure:"replication_signing_key_env"`
	ReplicationEncryptionKeyEnv     string              `mapstructure:"replication_encryption_key_env"`
	WitnessAPIURL                   string              `mapstructure:"witness_api_url"`
	WitnessURLs                     []string            `mapstructure:"witness_urls"`
	WitnessQuorum                   int                 `mapstructure:"witness_quorum"`
	WitnessWeights                  map[string]int      `mapstructure:"witness_weights"`
	WitnessWeightThreshold          int                 `mapstructure:"witness_weight_threshold"`
	WitnessGroups                   map[string]string   `mapstructure:"witness_groups"`
	WitnessMinDistinctGroups        int                 `mapstructure:"witness_min_distinct_groups"`
	WitnessRequiredGroups           []string            `mapstructure:"witness_required_groups"`
	WitnessSources                  map[string]string   `mapstructure:"witness_sources"`
	WitnessRequiredSources          []string            `mapstructure:"witness_required_sources"`
	WitnessRequiredURLs             []string            `mapstructure:"witness_required_urls"`
	WitnessPolicyMode               string              `mapstructure:"witness_policy_mode"`
	WitnessPolicyModeByTier         map[string]string   `mapstructure:"witness_policy_mode_by_tier"`
	WitnessFailureTolerance         int                 `mapstructure:"witness_failure_tolerance"`
	WitnessFailureWeightTolerance   int                 `mapstructure:"witness_failure_weight_tolerance"`
	WitnessSourceConfidence         map[string]string   `mapstructure:"witness_source_confidence"`
	WitnessMinApprovalsByTier       map[string]int      `mapstructure:"witness_min_approvals_by_tier"`
	WitnessMinWeightByTier          map[string]int      `mapstructure:"witness_min_weight_by_tier"`
	WitnessMinDistinctGroupsByTier  map[string]int      `mapstructure:"witness_min_distinct_groups_by_tier"`
	WitnessMinDistinctSourcesByTier map[string]int      `mapstructure:"witness_min_distinct_sources_by_tier"`
	WitnessRequiredSourcesByTier    map[string][]string `mapstructure:"witness_required_sources_by_tier"`
	WitnessRequiredURLsByTier       map[string][]string `mapstructure:"witness_required_urls_by_tier"`
	WitnessRequiredGroupsByTier     map[string][]string `mapstructure:"witness_required_groups_by_tier"`
	WitnessMaxAgeByTier             map[string]int      `mapstructure:"witness_max_age_by_tier"`
	WitnessRequiredNodeByTier       map[string]string   `mapstructure:"witness_required_node_by_tier"`
	WitnessSignatureRequiredTiers   []string            `mapstructure:"witness_signature_required_tiers"`
	WitnessReplayRequiredTiers      []string            `mapstructure:"witness_replay_required_tiers"`
	WitnessFailureToleranceByTier   map[string]int      `mapstructure:"witness_failure_tolerance_by_tier"`
	WitnessFailureWeightByTier      map[string]int      `mapstructure:"witness_failure_weight_tolerance_by_tier"`
	WitnessBlockingTiers            []string            `mapstructure:"witness_blocking_tiers"`
	WitnessTokenEnv                 string              `mapstructure:"witness_token_env"`
	WitnessSigningKeyEnv            string              `mapstructure:"witness_signing_key_env"`
	WitnessMaxAgeSeconds            int                 `mapstructure:"witness_max_age_seconds"`
	WitnessRequiredNode             string              `mapstructure:"witness_required_node"`
	WitnessReplayProtectionEnabled  bool                `mapstructure:"witness_replay_protection_enabled"`
	Preempt                         bool                `mapstructure:"preempt"`
	PreemptHoldoffSeconds           int                 `mapstructure:"preempt_holdoff_seconds"`
	SharedStateDir                  string              `mapstructure:"shared_state_dir"`
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

func normalizeWitnessURLs(primary string, urls []string) []string {
	normalized := make([]string, 0, len(urls)+1)
	seen := map[string]struct{}{}
	appendURL := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if _, exists := seen[trimmed]; exists {
			return
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(urls) > 0 {
		for _, witnessURL := range urls {
			appendURL(witnessURL)
		}
		return normalized
	}
	appendURL(primary)
	return normalized
}

func effectiveWitnessWeights(urls []string, overrides map[string]int) (map[string]int, int) {
	weights := make(map[string]int, len(urls))
	total := 0
	for _, witnessURL := range urls {
		weight := 1
		if overrides != nil {
			if override, ok := overrides[strings.TrimSpace(witnessURL)]; ok && override > 0 {
				weight = override
			}
		}
		weights[witnessURL] = weight
		total += weight
	}
	return weights, total
}

func effectiveWitnessGroups(urls []string, overrides map[string]string) (map[string]string, []string) {
	groups := make(map[string]string, len(urls))
	distinctSet := make(map[string]struct{}, len(urls))
	distinct := make([]string, 0, len(urls))
	for _, witnessURL := range urls {
		group := strings.TrimSpace(witnessURL)
		if overrides != nil {
			if override, ok := overrides[strings.TrimSpace(witnessURL)]; ok && strings.TrimSpace(override) != "" {
				group = strings.TrimSpace(override)
			}
		}
		groups[witnessURL] = group
		if _, exists := distinctSet[group]; exists {
			continue
		}
		distinctSet[group] = struct{}{}
		distinct = append(distinct, group)
	}
	return groups, distinct
}

func effectiveWitnessSources(urls []string, overrides map[string]string) (map[string]string, []string) {
	sources := make(map[string]string, len(urls))
	distinctSet := make(map[string]struct{}, len(urls))
	distinct := make([]string, 0, len(urls))
	for _, witnessURL := range urls {
		source := strings.TrimSpace(witnessURL)
		if overrides != nil {
			if override, ok := overrides[strings.TrimSpace(witnessURL)]; ok && strings.TrimSpace(override) != "" {
				source = strings.TrimSpace(override)
			}
		}
		sources[witnessURL] = source
		if _, exists := distinctSet[source]; exists {
			continue
		}
		distinctSet[source] = struct{}{}
		distinct = append(distinct, source)
	}
	return sources, distinct
}

func normalizeWitnessPolicyMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "all":
		return "all"
	case "any":
		return "any"
	case "group_only":
		return "group_only"
	case "source_only":
		return "source_only"
	case "url_only":
		return "url_only"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeWitnessTierPolicyMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "all":
		return "all"
	case "any":
		return "any"
	case "group_only":
		return "group_only"
	case "source_only":
		return "source_only"
	case "url_only":
		return "url_only"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func effectiveWitnessConfidenceTiers(sources []string, overrides map[string]string) (map[string]string, []string) {
	tiers := make(map[string]string, len(sources))
	distinctSet := make(map[string]struct{}, len(sources)+1)
	distinct := make([]string, 0, len(sources)+1)
	for _, source := range sources {
		tier := "standard"
		if overrides != nil {
			if override, ok := overrides[strings.TrimSpace(source)]; ok && strings.TrimSpace(override) != "" {
				tier = strings.TrimSpace(override)
			}
		}
		tiers[source] = tier
		if _, exists := distinctSet[tier]; exists {
			continue
		}
		distinctSet[tier] = struct{}{}
		distinct = append(distinct, tier)
	}
	return tiers, distinct
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
var globalConfigMu sync.RWMutex

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
	v.SetDefault("database.backend", "sqlite")
	v.SetDefault("onboarding.ca_mode", "none")
	v.SetDefault("onboarding.certificate_lifecycle.enabled", false)
	v.SetDefault("onboarding.certificate_lifecycle.mode", "monitor")
	v.SetDefault("onboarding.certificate_lifecycle.fail_closed", true)
	v.SetDefault("onboarding.certificate_lifecycle.default_template", "device-eap-tls")
	v.SetDefault("onboarding.certificate_lifecycle.templates", []string{"device-eap-tls", "byod-eap-tls"})
	v.SetDefault("onboarding.certificate_lifecycle.active_issuer", "aegisnas-local")
	v.SetDefault("onboarding.certificate_lifecycle.staged_issuer", "")
	v.SetDefault("onboarding.certificate_lifecycle.issuer_rotation_mode", "disabled")
	v.SetDefault("onboarding.certificate_lifecycle.issuer_overlap_seconds", 2592000)
	v.SetDefault("onboarding.certificate_lifecycle.certificate_validity_days", 365)
	v.SetDefault("onboarding.certificate_lifecycle.max_certificate_validity_days", 825)
	v.SetDefault("onboarding.certificate_lifecycle.renewal_window_days", 30)
	v.SetDefault("onboarding.certificate_lifecycle.require_csr", true)
	v.SetDefault("onboarding.certificate_lifecycle.require_proof_of_possession", true)
	v.SetDefault("onboarding.certificate_lifecycle.require_device_binding", true)
	v.SetDefault("onboarding.certificate_lifecycle.require_subject_alt_name", true)
	v.SetDefault("onboarding.certificate_lifecycle.allowed_key_types", []string{"rsa", "ecdsa", "ed25519"})
	v.SetDefault("onboarding.certificate_lifecycle.min_rsa_bits", 2048)
	v.SetDefault("onboarding.certificate_lifecycle.allowed_ecdsa_curves", []string{"P-256", "P-384", "P-521"})
	v.SetDefault("onboarding.certificate_lifecycle.allow_server_key_generation", false)
	v.SetDefault("onboarding.certificate_lifecycle.escrow_policy", "forbid")
	v.SetDefault("onboarding.certificate_lifecycle.crl_enabled", false)
	v.SetDefault("onboarding.certificate_lifecycle.crl_publish_path", "/var/lib/aegisnas/pki/crl")
	v.SetDefault("onboarding.certificate_lifecycle.ocsp_enabled", false)
	v.SetDefault("onboarding.certificate_lifecycle.ocsp_responder_url", "")
	v.SetDefault("onboarding.certificate_lifecycle.est_enabled", true)
	v.SetDefault("onboarding.certificate_lifecycle.scep_enabled", true)
	v.SetDefault("onboarding.certificate_lifecycle.byod_portal_enabled", true)
	v.SetDefault("onboarding.certificate_lifecycle.audit_enabled", true)
	v.SetDefault("onboarding.certificate_lifecycle.event_retention_limit", 6000)
	v.SetDefault("onboarding.certificate_lifecycle.inventory_retention_limit", 100000)
	v.SetDefault("onboarding.supplicant_lifecycle.enabled", false)
	v.SetDefault("onboarding.supplicant_lifecycle.mode", "monitor")
	v.SetDefault("onboarding.supplicant_lifecycle.fail_closed", true)
	v.SetDefault("onboarding.supplicant_lifecycle.ssid", "AegisNAS-Enterprise")
	v.SetDefault("onboarding.supplicant_lifecycle.security", "wpa2-enterprise")
	v.SetDefault("onboarding.supplicant_lifecycle.default_platform", "windows")
	v.SetDefault("onboarding.supplicant_lifecycle.allowed_platforms", []string{"windows", "macos", "ios", "android", "linux"})
	v.SetDefault("onboarding.supplicant_lifecycle.default_eap_method", "tls")
	v.SetDefault("onboarding.supplicant_lifecycle.allowed_eap_methods", []string{"tls", "peap", "ttls"})
	v.SetDefault("onboarding.supplicant_lifecycle.default_inner_method", "mschapv2")
	v.SetDefault("onboarding.supplicant_lifecycle.allowed_inner_methods", []string{"mschapv2", "pap", "gtc", "tls"})
	v.SetDefault("onboarding.supplicant_lifecycle.anonymous_identity", "anonymous@aegisnas.local")
	v.SetDefault("onboarding.supplicant_lifecycle.require_anonymous_identity", true)
	v.SetDefault("onboarding.supplicant_lifecycle.domain_suffix", "")
	v.SetDefault("onboarding.supplicant_lifecycle.server_names", []string{})
	v.SetDefault("onboarding.supplicant_lifecycle.trust_anchor_pins", []string{})
	v.SetDefault("onboarding.supplicant_lifecycle.require_trust_anchor_pinning", true)
	v.SetDefault("onboarding.supplicant_lifecycle.allow_password_change", true)
	v.SetDefault("onboarding.supplicant_lifecycle.password_change_url", "")
	v.SetDefault("onboarding.supplicant_lifecycle.password_change_providers", []string{"local", "active-directory", "identity-failover"})
	v.SetDefault("onboarding.supplicant_lifecycle.require_verifier_compatibility", true)
	v.SetDefault("onboarding.supplicant_lifecycle.compatible_verifiers", []string{"local", "ldap", "active-directory", "identity-failover", "winbind"})
	v.SetDefault("onboarding.supplicant_lifecycle.max_password_age_days", 90)
	v.SetDefault("onboarding.supplicant_lifecycle.expiry_warning_days", 14)
	v.SetDefault("onboarding.supplicant_lifecycle.grace_period_days", 7)
	v.SetDefault("onboarding.supplicant_lifecycle.min_password_length", 12)
	v.SetDefault("onboarding.supplicant_lifecycle.require_mfa_for_change", true)
	v.SetDefault("onboarding.supplicant_lifecycle.require_tls_for_delivery", true)
	v.SetDefault("onboarding.supplicant_lifecycle.require_signed_profiles", true)
	v.SetDefault("onboarding.supplicant_lifecycle.profile_signing_key_ref", "")
	v.SetDefault("onboarding.supplicant_lifecycle.profile_validity_days", 365)
	v.SetDefault("onboarding.supplicant_lifecycle.delivery_token_ttl_seconds", 900)
	v.SetDefault("onboarding.supplicant_lifecycle.audit_enabled", true)
	v.SetDefault("onboarding.supplicant_lifecycle.event_retention_limit", 6000)
	v.SetDefault("onboarding.supplicant_lifecycle.profile_retention_limit", 100000)
	v.SetDefault("profiling.poll_interval_seconds", 300)
	v.SetDefault("profiling.retention_hours", 24)
	v.SetDefault("profiling.mdm_sync_enabled", false)
	v.SetDefault("profiling.mdm_cache_hours", 12)
	v.SetDefault("integrations.siem.batch_size", 100)
	v.SetDefault("integrations.controller.sync_mode", "monitor")
	v.SetDefault("governance.rbac_mode", "local")
	v.SetDefault("security.secrets.enabled", true)
	v.SetDefault("security.secrets.providers", []string{"env", "file"})
	v.SetDefault("security.secrets.file_base_dir", "/etc/aegisnas/secrets")
	v.SetDefault("security.secrets.max_secret_bytes", 8192)
	v.SetDefault("security.secrets.allow_inline", true)
	v.SetDefault("security.secrets.production_require_references", true)
	v.SetDefault("database.sslmode", "verify-full")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime_seconds", 1800)
	v.SetDefault("database.conn_max_idle_time_seconds", 300)
	v.SetDefault("database.connect_timeout_seconds", 10)
	v.SetDefault("database.statement_timeout_milliseconds", 30000)
	v.SetDefault("database.migration_lock_timeout_seconds", 30)
	v.SetDefault("database.production_require_postgresql", false)
	v.SetDefault("database.production_require_tls", true)
	v.SetDefault("database.allow_unsafe_postgresql_sslmode", false)
	v.SetDefault("database.allow_inline_postgresql_dsn", false)
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
	v.SetDefault("high_availability.witness_urls", []string{})
	v.SetDefault("high_availability.witness_quorum", 1)
	v.SetDefault("high_availability.witness_weights", map[string]int{})
	v.SetDefault("high_availability.witness_weight_threshold", 0)
	v.SetDefault("high_availability.witness_groups", map[string]string{})
	v.SetDefault("high_availability.witness_min_distinct_groups", 0)
	v.SetDefault("high_availability.witness_required_groups", []string{})
	v.SetDefault("high_availability.witness_sources", map[string]string{})
	v.SetDefault("high_availability.witness_required_sources", []string{})
	v.SetDefault("high_availability.witness_required_urls", []string{})
	v.SetDefault("high_availability.witness_policy_mode", "all")
	v.SetDefault("high_availability.witness_policy_mode_by_tier", map[string]string{})
	v.SetDefault("high_availability.witness_failure_tolerance", 0)
	v.SetDefault("high_availability.witness_failure_weight_tolerance", 0)
	v.SetDefault("high_availability.witness_source_confidence", map[string]string{})
	v.SetDefault("high_availability.witness_min_approvals_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_min_weight_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_min_distinct_groups_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_min_distinct_sources_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_required_sources_by_tier", map[string][]string{})
	v.SetDefault("high_availability.witness_required_urls_by_tier", map[string][]string{})
	v.SetDefault("high_availability.witness_required_groups_by_tier", map[string][]string{})
	v.SetDefault("high_availability.witness_max_age_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_required_node_by_tier", map[string]string{})
	v.SetDefault("high_availability.witness_signature_required_tiers", []string{})
	v.SetDefault("high_availability.witness_replay_required_tiers", []string{})
	v.SetDefault("high_availability.witness_failure_tolerance_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_failure_weight_tolerance_by_tier", map[string]int{})
	v.SetDefault("high_availability.witness_blocking_tiers", []string{})
	v.SetDefault("high_availability.witness_token_env", "")
	v.SetDefault("high_availability.witness_signing_key_env", "")
	v.SetDefault("high_availability.witness_max_age_seconds", 0)
	v.SetDefault("high_availability.witness_required_node", "")
	v.SetDefault("high_availability.witness_replay_protection_enabled", false)
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
	v.SetDefault("radius.dynamic_clients.enabled", false)
	v.SetDefault("radius.dynamic_clients.discovery_enabled", false)
	v.SetDefault("radius.dynamic_clients.approval_required", true)
	v.SetDefault("radius.dynamic_clients.enrollment_token_ref", "")
	v.SetDefault("radius.dynamic_clients.enrollment_ttl_seconds", 86400)
	v.SetDefault("radius.dynamic_clients.max_pending", 256)
	v.SetDefault("radius.dynamic_clients.discovery_allowed_cidrs", []string{})
	v.SetDefault("radius.dynamic_clients.default_nas_type", "other")
	v.SetDefault("radius.dynamic_clients.default_transport", "udp")
	v.SetDefault("radius.dynamic_clients.default_template", "default")
	v.SetDefault("radius.packet_hardening.enabled", true)
	v.SetDefault("radius.packet_hardening.fail_closed", true)
	v.SetDefault("radius.packet_hardening.require_known_source", true)
	v.SetDefault("radius.packet_hardening.allow_trailing_padding", false)
	v.SetDefault("radius.packet_hardening.allow_status_server", true)
	v.SetDefault("radius.packet_hardening.allow_status_client", false)
	v.SetDefault("radius.packet_hardening.require_message_authenticator", "auto")
	v.SetDefault("radius.packet_hardening.max_packet_bytes", 4096)
	v.SetDefault("radius.packet_hardening.max_attributes_per_packet", 128)
	v.SetDefault("radius.packet_hardening.max_proxy_state_attributes", 8)
	v.SetDefault("radius.packet_hardening.max_proxy_state_bytes", 1024)
	v.SetDefault("radius.packet_hardening.replay_cache_enabled", true)
	v.SetDefault("radius.packet_hardening.replay_window_seconds", 30)
	v.SetDefault("radius.packet_hardening.replay_cache_max_entries", 16384)
	v.SetDefault("radius.packet_hardening.rate_limit_enabled", true)
	v.SetDefault("radius.packet_hardening.per_client_rate_limit_per_second", 250)
	v.SetDefault("radius.packet_hardening.per_client_burst", 500)
	v.SetDefault("radius.packet_hardening.trusted_proxy_cidrs", []string{})
	v.SetDefault("radius.packet_hardening.event_retention_limit", 6000)
	v.SetDefault("radius.radsec.enabled", false)
	v.SetDefault("radius.radsec.listen_address", "0.0.0.0")
	v.SetDefault("radius.radsec.port", 2083)
	v.SetDefault("radius.radsec.tls_min_version", "1.2")
	v.SetDefault("radius.radsec.tls_max_version", "1.3")
	v.SetDefault("radius.radsec.cipher_list", "DEFAULT@SECLEVEL=2")
	v.SetDefault("radius.radsec.radius_v11", "forbid")
	v.SetDefault("radius.radsec.max_connections", 64)
	v.SetDefault("radius.radsec.lifetime_seconds", 86400)
	v.SetDefault("radius.radsec.idle_timeout_seconds", 300)
	v.SetDefault("radius.radsec.probe_interval_seconds", 30)
	v.SetDefault("radius.radsec.certificate_expiry_warning_days", 30)
	v.SetDefault("radius.upstream.servers[].radsec.psk.enabled", false)
	v.SetDefault("radius.upstream.servers[].radsec.psk.overlap_seconds", 86400)
	v.SetDefault("radius.upstream.servers[].radsec.psk.warning_days", 30)
	v.SetDefault("radius.eap.default_type", "peap")
	v.SetDefault("radius.eap.peap_inner", "mschapv2")
	v.SetDefault("radius.eap.ttls_inner", "mschapv2")
	v.SetDefault("radius.eap.tls_min_version", "1.2")
	v.SetDefault("radius.eap.tls_max_version", "1.3")
	v.SetDefault("radius.eap.check_crl", false)
	v.SetDefault("radius.eap.check_all_crl", false)
	v.SetDefault("radius.eap.ca_path_reload_interval", 3600)
	v.SetDefault("radius.eap.ocsp.enabled", false)
	v.SetDefault("radius.eap.ocsp.override_cert_url", false)
	v.SetDefault("radius.eap.ocsp.url", "")
	v.SetDefault("radius.eap.ocsp.use_nonce", true)
	v.SetDefault("radius.eap.ocsp.timeout_seconds", 5)
	v.SetDefault("radius.eap.ocsp.soft_fail", false)
	v.SetDefault("radius.eap.teap.enabled", true)
	v.SetDefault("radius.eap.teap.default_inner_method", "mschapv2")
	v.SetDefault("radius.eap.teap.chain_mode", "machine_then_user")
	v.SetDefault("radius.eap.teap.require_crypto_binding", true)
	v.SetDefault("radius.eap.teap.require_channel_binding", false)
	v.SetDefault("radius.eap.teap.require_identity_type", true)
	v.SetDefault("radius.eap.teap.require_machine_identity", true)
	v.SetDefault("radius.eap.teap.require_user_identity", true)
	v.SetDefault("radius.eap.teap.allow_pac", true)
	v.SetDefault("radius.eap.teap.require_pac", false)
	v.SetDefault("radius.eap.teap.pac_provisioning", "authenticated")
	v.SetDefault("radius.eap.teap.pac_authority_id", "aegisnas-teap")
	v.SetDefault("radius.eap.teap.pac_lifetime_seconds", 2592000)
	v.SetDefault("radius.eap.teap.allow_eap_payload", true)
	v.SetDefault("radius.eap.teap.allow_basic_password_auth", false)
	v.SetDefault("radius.eap.teap.max_chain_steps", 2)
	v.SetDefault("radius.eap.teap.session_ttl_seconds", 900)
	v.SetDefault("radius.eap.teap.event_retention_limit", 6000)
	v.SetDefault("radius.eap.machine_user.enabled", true)
	v.SetDefault("radius.eap.machine_user.mode", "monitor")
	v.SetDefault("radius.eap.machine_user.fail_closed", true)
	v.SetDefault("radius.eap.machine_user.correlation_mode", "machine_then_user")
	v.SetDefault("radius.eap.machine_user.require_teap", true)
	v.SetDefault("radius.eap.machine_user.require_machine_identity", true)
	v.SetDefault("radius.eap.machine_user.require_user_identity", true)
	v.SetDefault("radius.eap.machine_user.require_machine_before_user", true)
	v.SetDefault("radius.eap.machine_user.require_same_calling_station", true)
	v.SetDefault("radius.eap.machine_user.require_same_nas", false)
	v.SetDefault("radius.eap.machine_user.require_fresh_machine_auth", true)
	v.SetDefault("radius.eap.machine_user.machine_auth_ttl_seconds", 28800)
	v.SetDefault("radius.eap.machine_user.user_auth_ttl_seconds", 28800)
	v.SetDefault("radius.eap.machine_user.transition_window_seconds", 900)
	v.SetDefault("radius.eap.machine_user.allowed_machine_methods", []string{"teap", "tls"})
	v.SetDefault("radius.eap.machine_user.allowed_user_methods", []string{"teap", "peap", "ttls"})
	v.SetDefault("radius.eap.machine_user.identity_precedence", "user_over_machine")
	v.SetDefault("radius.eap.machine_user.role_merge_strategy", "user_primary")
	v.SetDefault("radius.eap.machine_user.conflict_action", "reject")
	v.SetDefault("radius.eap.machine_user.stale_machine_action", "reject")
	v.SetDefault("radius.eap.machine_user.machine_identity_prefixes", []string{"host/", "machine/"})
	v.SetDefault("radius.eap.machine_user.user_identity_prefixes", []string{})
	v.SetDefault("radius.eap.machine_user.max_active_correlations", 100000)
	v.SetDefault("radius.eap.machine_user.audit_enabled", true)
	v.SetDefault("radius.eap.machine_user.event_retention_limit", 6000)
	v.SetDefault("radius.eap.fast.enabled", true)
	v.SetDefault("radius.eap.fast.default_inner_method", "mschapv2")
	v.SetDefault("radius.eap.fast.require_crypto_binding", true)
	v.SetDefault("radius.eap.fast.allow_pac", true)
	v.SetDefault("radius.eap.fast.require_pac", false)
	v.SetDefault("radius.eap.fast.pac_provisioning", "authenticated")
	v.SetDefault("radius.eap.fast.pac_authority_id", "aegisnas-fast")
	v.SetDefault("radius.eap.fast.pac_lifetime_seconds", 2592000)
	v.SetDefault("radius.eap.fast.pac_opaque_key_ref", "")
	v.SetDefault("radius.eap.fast.allow_anonymous_provisioning", false)
	v.SetDefault("radius.eap.fast.allow_eap_payload", true)
	v.SetDefault("radius.eap.fast.max_provisioning_attempts", 3)
	v.SetDefault("radius.eap.fast.session_ttl_seconds", 900)
	v.SetDefault("radius.eap.fast.event_retention_limit", 6000)
	v.SetDefault("radius.eap.pwd.enabled", true)
	v.SetDefault("radius.eap.pwd.group", 19)
	v.SetDefault("radius.eap.pwd.server_id", "aegisnas-pwd")
	v.SetDefault("radius.eap.pwd.require_strong_group", true)
	v.SetDefault("radius.eap.pwd.password_source", "identity-failover")
	v.SetDefault("radius.eap.pwd.allow_local_verifier", true)
	v.SetDefault("radius.eap.pwd.require_identity", true)
	v.SetDefault("radius.eap.pwd.require_password_proof", true)
	v.SetDefault("radius.eap.pwd.replay_window_seconds", 30)
	v.SetDefault("radius.eap.pwd.fragment_size", 1020)
	v.SetDefault("radius.eap.pwd.event_retention_limit", 6000)
	v.SetDefault("radius.eap.sim_aka.enabled", true)
	v.SetDefault("radius.eap.sim_aka.methods", []string{"sim", "aka", "aka-prime"})
	v.SetDefault("radius.eap.sim_aka.require_identity", true)
	v.SetDefault("radius.eap.sim_aka.require_permanent_identity", true)
	v.SetDefault("radius.eap.sim_aka.allow_pseudonym_identity", true)
	v.SetDefault("radius.eap.sim_aka.require_pseudonym_reauth", false)
	v.SetDefault("radius.eap.sim_aka.pseudonym_ttl_seconds", 86400)
	v.SetDefault("radius.eap.sim_aka.reauth_ttl_seconds", 43200)
	v.SetDefault("radius.eap.sim_aka.vector_provider", "external-http")
	v.SetDefault("radius.eap.sim_aka.vector_provider_ref", "")
	v.SetDefault("radius.eap.sim_aka.require_fresh_vectors", true)
	v.SetDefault("radius.eap.sim_aka.max_vector_age_seconds", 300)
	v.SetDefault("radius.eap.sim_aka.min_triplets", 2)
	v.SetDefault("radius.eap.sim_aka.min_quintuplets", 1)
	v.SetDefault("radius.eap.sim_aka.allow_resynchronization", true)
	v.SetDefault("radius.eap.sim_aka.resync_window_seconds", 300)
	v.SetDefault("radius.eap.sim_aka.require_network_name", true)
	v.SetDefault("radius.eap.sim_aka.network_name", "")
	v.SetDefault("radius.eap.sim_aka.require_kdf", true)
	v.SetDefault("radius.eap.sim_aka.fail_on_provider_unavailable", true)
	v.SetDefault("radius.eap.sim_aka.event_retention_limit", 6000)
	v.SetDefault("radius.eap.framework.enabled", true)
	v.SetDefault("radius.eap.framework.mode", "monitor")
	v.SetDefault("radius.eap.framework.fail_closed", true)
	v.SetDefault("radius.eap.framework.allowed_methods", []string{"peap", "ttls", "tls"})
	v.SetDefault("radius.eap.framework.allowed_inner_methods", []string{"mschapv2", "pap", "chap", "gtc", "tls"})
	v.SetDefault("radius.eap.framework.default_outer_identity_source", "configured-default")
	v.SetDefault("radius.eap.framework.default_inner_identity_source", "identity-failover")
	v.SetDefault("radius.eap.framework.unsupported_method_action", "reject")
	v.SetDefault("radius.eap.framework.require_message_authenticator", true)
	v.SetDefault("radius.eap.framework.require_identity_binding", true)
	v.SetDefault("radius.eap.framework.telemetry_enabled", true)
	v.SetDefault("radius.eap.framework.event_retention_limit", 6000)
	v.SetDefault("radius.eap.framework.max_concurrent_sessions", 0)
	v.SetDefault("radius.eap.framework.method_timeout_seconds", 60)
	v.SetDefault("radius.eap.framework.fragment_size", 1024)
	v.SetDefault("radius.eap.framework.nak_unknown_types", true)
	v.SetDefault("radius.eap.framework.identity_sources", []map[string]any{
		{"name": "identity-failover", "source": "identity_failover", "enabled": true, "methods": []string{"peap", "ttls"}, "allow_password_verifier": true, "allow_certificate_subject": false, "priority": 10},
		{"name": "certificate-subject", "source": "certificate", "enabled": true, "methods": []string{"tls"}, "allow_password_verifier": false, "allow_certificate_subject": true, "priority": 20},
	})
	v.SetDefault("radius.eap.framework.method_policies", []map[string]any{
		{"method": "peap", "enabled": true, "inner_methods": []string{"mschapv2", "gtc"}, "identity_source": "identity-failover", "require_certificate": false, "require_revocation": false, "allow_password_verifier": true, "min_tls_version": "1.2", "max_tls_version": "1.3"},
		{"method": "ttls", "enabled": true, "inner_methods": []string{"mschapv2", "pap", "chap", "gtc"}, "identity_source": "identity-failover", "require_certificate": false, "require_revocation": false, "allow_password_verifier": true, "min_tls_version": "1.2", "max_tls_version": "1.3"},
		{"method": "tls", "enabled": true, "inner_methods": []string{}, "identity_source": "certificate-subject", "require_certificate": true, "require_revocation": false, "allow_password_verifier": false, "min_tls_version": "1.2", "max_tls_version": "1.3"},
	})
	v.SetDefault("radius.eap.framework.vendor_compatibility_profiles", []map[string]any{
		{"name": "enterprise-8021x", "nas_types": []string{"cisco", "aruba", "ruckus", "extreme", "juniper", "fortinet", "unifi", "other"}, "allowed_methods": []string{"peap", "ttls", "tls"}, "required_methods": []string{}, "notes": "Baseline RFC 3748 EAP pass-through and FreeRADIUS method selection for enterprise APs and switches."},
	})
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
	v.SetDefault("radius.upstream.routes", []map[string]any{})
	v.SetDefault("radius.upstream.transport_policy.enabled", true)
	v.SetDefault("radius.upstream.transport_policy.mode", "monitor")
	v.SetDefault("radius.upstream.transport_policy.fail_closed", true)
	v.SetDefault("radius.upstream.transport_policy.default_required_transport", "any")
	v.SetDefault("radius.upstream.transport_policy.allow_mixed_transports", false)
	v.SetDefault("radius.upstream.transport_policy.route_policies", []map[string]any{})
	v.SetDefault("radius.upstream.proxy_policy.enabled", true)
	v.SetDefault("radius.upstream.proxy_policy.fail_closed", true)
	v.SetDefault("radius.upstream.proxy_policy.default_action", "drop")
	v.SetDefault("radius.upstream.proxy_policy.loop_marker", "aegisnas")
	v.SetDefault("radius.upstream.proxy_policy.add_loop_marker", true)
	v.SetDefault("radius.upstream.proxy_policy.reject_loop_marker", true)
	v.SetDefault("radius.upstream.proxy_policy.max_hops", 8)
	v.SetDefault("radius.upstream.proxy_policy.route_policies", []map[string]any{})
	v.SetDefault("radius.upstream.accounting_spool.enabled", true)
	v.SetDefault("radius.upstream.accounting_spool.max_queue_records", 10000)
	v.SetDefault("radius.upstream.accounting_spool.max_attempts", 10)
	v.SetDefault("radius.upstream.accounting_spool.initial_retry_seconds", 30)
	v.SetDefault("radius.upstream.accounting_spool.max_retry_seconds", 3600)
	v.SetDefault("radius.upstream.accounting_spool.record_ttl_seconds", 604800)
	v.SetDefault("radius.upstream.accounting_spool.replay_interval_seconds", 60)
	v.SetDefault("radius.upstream.accounting_spool.batch_size", 100)
	v.SetDefault("radius.upstream.accounting_spool.lock_seconds", 120)
	v.SetDefault("radius.upstream.accounting_spool.sent_retention_seconds", 604800)
	v.SetDefault("radius.upstream.accounting_spool.poison_retention_seconds", 2592000)
	v.SetDefault("radius.upstream.fallback_policy.enabled", true)
	v.SetDefault("radius.upstream.fallback_policy.mode", "monitor")
	v.SetDefault("radius.upstream.fallback_policy.fail_closed", true)
	v.SetDefault("radius.upstream.fallback_policy.allow_portal_local", true)
	v.SetDefault("radius.upstream.fallback_policy.allow_ldap", false)
	v.SetDefault("radius.upstream.fallback_policy.require_identity_allowlist", true)
	v.SetDefault("radius.upstream.fallback_policy.max_outage_seconds", 900)
	v.SetDefault("radius.upstream.fallback_policy.stale_policy_seconds", 3600)
	v.SetDefault("radius.upstream.fallback_policy.recovery_successes", 2)
	v.SetDefault("radius.upstream.fallback_policy.allowed_users", []string{})
	v.SetDefault("radius.upstream.fallback_policy.allowed_realms", []string{})
	v.SetDefault("radius.upstream.fallback_policy.allowed_roles", []string{})
	v.SetDefault("radius.upstream.fallback_policy.audit_enabled", true)
	v.SetDefault("radius.upstream.fallback_policy.retention_limit", 6000)
	productVendor := productconfigs.AegisNASVendorDictionary()
	v.SetDefault("radius.vendor.enabled", false)
	v.SetDefault("radius.vendor.name", productVendor.Name)
	v.SetDefault("radius.vendor.id", productVendor.ID)
	if productVendor.ID == productconfigs.AegisNASPlaceholderVendorID {
		v.SetDefault("radius.vendor.identity_mode", "lab")
	} else {
		v.SetDefault("radius.vendor.identity_mode", "unverified")
	}
	v.SetDefault("radius.vendor.legacy_ids", []int{})
	v.SetDefault("radius.vendor.compatibility_packs", productconfigs.DefaultVendorCompatibilityPackKeys())
	v.SetDefault("radius.vendor.dictionary_paths", []string{})
	v.SetDefault("radius.vendor.opaque_pass_through.enabled", true)
	v.SetDefault("radius.vendor.opaque_pass_through.max_attributes_per_packet", 32)
	v.SetDefault("radius.vendor.opaque_pass_through.max_attribute_bytes", 249)
	v.SetDefault("radius.vendor.opaque_pass_through.max_total_bytes_per_packet", 2048)
	v.SetDefault("radius.vendor.opaque_pass_through.rules", []map[string]any{})
	v.SetDefault("portal.radius_auth", false)
	v.SetDefault("portal.local_fallback", true)
	v.SetDefault("identity.failover.enabled", true)
	v.SetDefault("identity.failover.mode", "monitor")
	v.SetDefault("identity.failover.fail_closed", true)
	v.SetDefault("identity.failover.source_order", []string{"local", "ldap-primary"})
	v.SetDefault("identity.failover.max_failures", 3)
	v.SetDefault("identity.failover.circuit_open_seconds", 300)
	v.SetDefault("identity.failover.stale_cache_seconds", 3600)
	v.SetDefault("identity.failover.cache_credentials", false)
	v.SetDefault("identity.failover.split_result_policy", "deny")
	v.SetDefault("identity.failover.health_check_interval_seconds", 60)
	v.SetDefault("identity.failover.audit_enabled", true)
	v.SetDefault("identity.failover.retention_limit", 6000)
	v.SetDefault("active_directory.enabled", false)
	v.SetDefault("active_directory.mode", "monitor")
	v.SetDefault("active_directory.fail_closed", true)
	v.SetDefault("active_directory.require_ldaps", true)
	v.SetDefault("active_directory.nested_groups", true)
	v.SetDefault("active_directory.auth_method", "ldap_bind")
	v.SetDefault("active_directory.user_filter", "(|(userPrincipalName=%p)(sAMAccountName=%u))")
	v.SetDefault("active_directory.group_filter", "(|(member=%D)(member:1.2.840.113556.1.4.1941:=%D))")
	v.SetDefault("active_directory.group_role_mappings", map[string]string{})
	v.SetDefault("active_directory.request_timeout_seconds", 5)
	v.SetDefault("active_directory.group_cache_ttl_seconds", 3600)
	v.SetDefault("active_directory.health_check_interval_seconds", 60)
	v.SetDefault("active_directory.clock_skew_seconds", 300)
	v.SetDefault("active_directory.audit_enabled", true)
	v.SetDefault("active_directory.retention_limit", 6000)
	v.SetDefault("active_directory.kerberos.enabled", false)
	v.SetDefault("active_directory.kerberos.kinit_path", "kinit")
	v.SetDefault("active_directory.kerberos.kdestroy_path", "kdestroy")
	v.SetDefault("active_directory.winbind.enabled", false)
	v.SetDefault("active_directory.winbind.domain_join_required", true)
	v.SetDefault("active_directory.winbind.wbinfo_path", "wbinfo")
	v.SetDefault("active_directory.winbind.ntlm_auth_path", "/usr/bin/ntlm_auth")
	v.SetDefault("mfa.enabled", false)
	v.SetDefault("mfa.mode", "monitor")
	v.SetDefault("mfa.fail_closed", true)
	v.SetDefault("mfa.otp.enabled", true)
	v.SetDefault("mfa.otp.issuer", "AegisNAS")
	v.SetDefault("mfa.otp.algorithm", "SHA1")
	v.SetDefault("mfa.otp.digits", 6)
	v.SetDefault("mfa.otp.period_seconds", 30)
	v.SetDefault("mfa.otp.window_steps", 1)
	v.SetDefault("mfa.otp.max_attempts", 5)
	v.SetDefault("mfa.otp.sealing_key_ref", "env:AEGIS_MFA_SEALING_KEY")
	v.SetDefault("mfa.otp.step_up_roles", []string{"admin", "super_admin", "ops_admin"})
	v.SetDefault("mfa.otp.step_up_realms", []string{})
	v.SetDefault("mfa.otp.required_for_admins", true)
	v.SetDefault("mfa.radius_challenge.enabled", true)
	v.SetDefault("mfa.radius_challenge.ttl_seconds", 300)
	v.SetDefault("mfa.radius_challenge.max_pending", 10000)
	v.SetDefault("mfa.radius_challenge.prompt", "Enter one-time password")
	v.SetDefault("mfa.radius_challenge.state_bytes", 32)
	v.SetDefault("mfa.radius_challenge.allow_pap_password_append", true)
	v.SetDefault("mfa.recovery.enabled", true)
	v.SetDefault("mfa.recovery.code_count", 10)
	v.SetDefault("mfa.recovery.code_bytes", 16)
	v.SetDefault("mfa.recovery.code_ttl_seconds", 0)
	v.SetDefault("mfa.audit_enabled", true)
	v.SetDefault("mfa.retention_limit", 6000)
	v.SetDefault("admin_webauthn.enabled", false)
	v.SetDefault("admin_webauthn.mode", "monitor")
	v.SetDefault("admin_webauthn.fail_closed", true)
	v.SetDefault("admin_webauthn.rp_id", "")
	v.SetDefault("admin_webauthn.rp_name", "AegisNAS Admin")
	v.SetDefault("admin_webauthn.origins", []string{})
	v.SetDefault("admin_webauthn.challenge_ttl_seconds", 300)
	v.SetDefault("admin_webauthn.session_ttl_seconds", 28800)
	v.SetDefault("admin_webauthn.max_pending", 10000)
	v.SetDefault("admin_webauthn.user_verification", "preferred")
	v.SetDefault("admin_webauthn.attestation", "none")
	v.SetDefault("admin_webauthn.resident_key", "preferred")
	v.SetDefault("admin_webauthn.require_for_roles", []string{"super_admin", "ops_admin"})
	v.SetDefault("admin_webauthn.require_for_sso", true)
	v.SetDefault("admin_webauthn.require_for_token_login", true)
	v.SetDefault("admin_webauthn.break_glass_allowed", true)
	v.SetDefault("admin_webauthn.allow_bootstrap_enrollment", false)
	v.SetDefault("admin_webauthn.audit_enabled", true)
	v.SetDefault("admin_webauthn.retention_limit", 6000)
	v.SetDefault("mab.enabled", false)
	v.SetDefault("mab.mode", "monitor")
	v.SetDefault("mab.fail_closed", true)
	v.SetDefault("mab.unknown_endpoint_policy", "deny")
	v.SetDefault("mab.default_role", "")
	v.SetDefault("mab.guest_role", "guest")
	v.SetDefault("mab.quarantine_role", "quarantine")
	v.SetDefault("mab.allowed_nas_port_types", []string{"ethernet", "wireless-802.11", "wireless80211"})
	v.SetDefault("mab.mac_formats", []string{"colon", "hyphen", "plain", "cisco-dot"})
	v.SetDefault("mab.password_policy", "accept_known_mac")
	v.SetDefault("mab.profiling_link_enabled", true)
	v.SetDefault("mab.endpoint_inventory_fallback", true)
	v.SetDefault("mab.revalidate_interval_seconds", 300)
	v.SetDefault("mab.cache_ttl_seconds", 300)
	v.SetDefault("mab.audit_enabled", true)
	v.SetDefault("mab.retention_limit", 6000)
	v.SetDefault("policy.runtime_shaping_enabled", true)
	v.SetDefault("policy.typed_engine_enabled", true)
	v.SetDefault("policy.mode", "monitor")
	v.SetDefault("policy.fail_closed", true)
	v.SetDefault("policy.audit_enabled", true)
	v.SetDefault("policy.allow_legacy_conditions", true)
	v.SetDefault("policy.require_typed_rules", false)
	v.SetDefault("policy.max_expression_depth", 8)
	v.SetDefault("policy.max_expression_nodes", 128)
	v.SetDefault("policy.max_list_values", 128)
	v.SetDefault("policy.evaluation_retention_limit", 10000)
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
		globalConfigMu.Lock()
		defer globalConfigMu.Unlock()
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
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	return globalConfig
}

func Path() string {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
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
	if c.Deployment.Hardware.StorageGB < 0 {
		return fmt.Errorf("deployment.hardware.storage_gb %d cannot be negative", c.Deployment.Hardware.StorageGB)
	}
	if c.Deployment.Hardware.WirelessPassthrough && EffectiveDeploymentForm(c.Deployment.Form) != "virtual" {
		return errors.New("deployment.hardware.wireless_passthrough is only valid for virtual deployments")
	}
	if err := validateSecretProviderConfig(c.Security.Secrets); err != nil {
		return err
	}
	if err := validateConfiguredSecretReferences(c); err != nil {
		return err
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

	if err := validateDatabaseConfig(c.Database); err != nil {
		return err
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
	if c.Telemetry.SupportBundleExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.support_bundle_exports.interval_minutes %d out of range", c.Telemetry.SupportBundleExports.IntervalMinutes)
	}
	if c.Telemetry.SupportBundleExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.support_bundle_exports.retention_count %d out of range", c.Telemetry.SupportBundleExports.RetentionCount)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.DiagnosticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.diagnostics_exports.format %q is invalid", c.Telemetry.DiagnosticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.AuditExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.audit_exports.format %q is invalid", c.Telemetry.AuditExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.SessionExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.session_exports.format %q is invalid", c.Telemetry.SessionExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.SessionAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.session_analytics_exports.format %q is invalid", c.Telemetry.SessionAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.VoucherAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.voucher_analytics_exports.format %q is invalid", c.Telemetry.VoucherAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.VoucherAgingAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.voucher_aging_analytics_exports.format %q is invalid", c.Telemetry.VoucherAgingAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.VoucherRedemptionAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.voucher_redemption_analytics_exports.format %q is invalid", c.Telemetry.VoucherRedemptionAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.VoucherExpiryAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.voucher_expiry_analytics_exports.format %q is invalid", c.Telemetry.VoucherExpiryAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestLifecycleExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_lifecycle_exports.format %q is invalid", c.Telemetry.GuestLifecycleExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestInviteAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_invite_analytics_exports.format %q is invalid", c.Telemetry.GuestInviteAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestConversionAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_conversion_analytics_exports.format %q is invalid", c.Telemetry.GuestConversionAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestRejectionAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_rejection_analytics_exports.format %q is invalid", c.Telemetry.GuestRejectionAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestDeliveryAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_delivery_analytics_exports.format %q is invalid", c.Telemetry.GuestDeliveryAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestDeliveryFailuresExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_delivery_failures_exports.format %q is invalid", c.Telemetry.GuestDeliveryFailuresExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.GuestSponsorAnalyticsExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.guest_sponsor_analytics_exports.format %q is invalid", c.Telemetry.GuestSponsorAnalyticsExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.IntegrationExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.integration_exports.format %q is invalid", c.Telemetry.IntegrationExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.HAExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.ha_exports.format %q is invalid", c.Telemetry.HAExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.NetworkExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.network_exports.format %q is invalid", c.Telemetry.NetworkExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.UpstreamAAAExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.upstream_aaa_exports.format %q is invalid", c.Telemetry.UpstreamAAAExports.Format)
	}
	switch strings.ToLower(strings.TrimSpace(c.Telemetry.UpgradeReadinessExports.Format)) {
	case "", "json", "csv", "both":
	default:
		return fmt.Errorf("telemetry.upgrade_readiness_exports.format %q is invalid", c.Telemetry.UpgradeReadinessExports.Format)
	}
	if c.Telemetry.DiagnosticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.diagnostics_exports.interval_minutes %d out of range", c.Telemetry.DiagnosticsExports.IntervalMinutes)
	}
	if c.Telemetry.AuditExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.audit_exports.interval_minutes %d out of range", c.Telemetry.AuditExports.IntervalMinutes)
	}
	if c.Telemetry.SessionExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.session_exports.interval_minutes %d out of range", c.Telemetry.SessionExports.IntervalMinutes)
	}
	if c.Telemetry.SessionAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.session_analytics_exports.interval_minutes %d out of range", c.Telemetry.SessionAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.VoucherAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.voucher_analytics_exports.interval_minutes %d out of range", c.Telemetry.VoucherAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.voucher_aging_analytics_exports.interval_minutes %d out of range", c.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.voucher_redemption_analytics_exports.interval_minutes %d out of range", c.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.voucher_expiry_analytics_exports.interval_minutes %d out of range", c.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.GuestLifecycleExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_lifecycle_exports.interval_minutes %d out of range", c.Telemetry.GuestLifecycleExports.IntervalMinutes)
	}
	if c.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_invite_analytics_exports.interval_minutes %d out of range", c.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_conversion_analytics_exports.interval_minutes %d out of range", c.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_rejection_analytics_exports.interval_minutes %d out of range", c.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_delivery_analytics_exports.interval_minutes %d out of range", c.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_delivery_failures_exports.interval_minutes %d out of range", c.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes)
	}
	if c.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.guest_sponsor_analytics_exports.interval_minutes %d out of range", c.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes)
	}
	if c.Telemetry.IntegrationExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.integration_exports.interval_minutes %d out of range", c.Telemetry.IntegrationExports.IntervalMinutes)
	}
	if c.Telemetry.HAExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.ha_exports.interval_minutes %d out of range", c.Telemetry.HAExports.IntervalMinutes)
	}
	if c.Telemetry.NetworkExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.network_exports.interval_minutes %d out of range", c.Telemetry.NetworkExports.IntervalMinutes)
	}
	if c.Telemetry.UpstreamAAAExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.upstream_aaa_exports.interval_minutes %d out of range", c.Telemetry.UpstreamAAAExports.IntervalMinutes)
	}
	if c.Telemetry.UpgradeReadinessExports.IntervalMinutes < 0 {
		return fmt.Errorf("telemetry.upgrade_readiness_exports.interval_minutes %d out of range", c.Telemetry.UpgradeReadinessExports.IntervalMinutes)
	}
	if c.Telemetry.DiagnosticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.diagnostics_exports.retention_count %d out of range", c.Telemetry.DiagnosticsExports.RetentionCount)
	}
	if c.Telemetry.AuditExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.audit_exports.retention_count %d out of range", c.Telemetry.AuditExports.RetentionCount)
	}
	if c.Telemetry.SessionExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.session_exports.retention_count %d out of range", c.Telemetry.SessionExports.RetentionCount)
	}
	if c.Telemetry.SessionAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.session_analytics_exports.retention_count %d out of range", c.Telemetry.SessionAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.VoucherAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.voucher_analytics_exports.retention_count %d out of range", c.Telemetry.VoucherAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.VoucherAgingAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.voucher_aging_analytics_exports.retention_count %d out of range", c.Telemetry.VoucherAgingAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.voucher_redemption_analytics_exports.retention_count %d out of range", c.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.voucher_expiry_analytics_exports.retention_count %d out of range", c.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.GuestLifecycleExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_lifecycle_exports.retention_count %d out of range", c.Telemetry.GuestLifecycleExports.RetentionCount)
	}
	if c.Telemetry.GuestInviteAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_invite_analytics_exports.retention_count %d out of range", c.Telemetry.GuestInviteAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.GuestConversionAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_conversion_analytics_exports.retention_count %d out of range", c.Telemetry.GuestConversionAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.GuestRejectionAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_rejection_analytics_exports.retention_count %d out of range", c.Telemetry.GuestRejectionAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_delivery_analytics_exports.retention_count %d out of range", c.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.GuestDeliveryFailuresExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_delivery_failures_exports.retention_count %d out of range", c.Telemetry.GuestDeliveryFailuresExports.RetentionCount)
	}
	if c.Telemetry.GuestSponsorAnalyticsExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.guest_sponsor_analytics_exports.retention_count %d out of range", c.Telemetry.GuestSponsorAnalyticsExports.RetentionCount)
	}
	if c.Telemetry.IntegrationExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.integration_exports.retention_count %d out of range", c.Telemetry.IntegrationExports.RetentionCount)
	}
	if c.Telemetry.HAExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.ha_exports.retention_count %d out of range", c.Telemetry.HAExports.RetentionCount)
	}
	if c.Telemetry.NetworkExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.network_exports.retention_count %d out of range", c.Telemetry.NetworkExports.RetentionCount)
	}
	if c.Telemetry.UpstreamAAAExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.upstream_aaa_exports.retention_count %d out of range", c.Telemetry.UpstreamAAAExports.RetentionCount)
	}
	if c.Telemetry.UpgradeReadinessExports.RetentionCount < 0 {
		return fmt.Errorf("telemetry.upgrade_readiness_exports.retention_count %d out of range", c.Telemetry.UpgradeReadinessExports.RetentionCount)
	}
	if c.Telemetry.SupportBundleExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.support_bundle_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.SupportBundleExports.Directory) == "" {
			return errors.New("telemetry.support_bundle_exports.enabled requires telemetry.support_bundle_exports.directory")
		}
		if c.Telemetry.SupportBundleExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.support_bundle_exports.enabled requires a positive telemetry.support_bundle_exports.interval_minutes")
		}
		if c.Telemetry.SupportBundleExports.RetentionCount <= 0 {
			return errors.New("telemetry.support_bundle_exports.enabled requires a positive telemetry.support_bundle_exports.retention_count")
		}
	}
	if c.Telemetry.DiagnosticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.diagnostics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.DiagnosticsExports.Directory) == "" {
			return errors.New("telemetry.diagnostics_exports.enabled requires telemetry.diagnostics_exports.directory")
		}
		if c.Telemetry.DiagnosticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.diagnostics_exports.enabled requires a positive telemetry.diagnostics_exports.interval_minutes")
		}
		if c.Telemetry.DiagnosticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.diagnostics_exports.enabled requires a positive telemetry.diagnostics_exports.retention_count")
		}
	}
	if c.Telemetry.AuditExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.audit_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.AuditExports.Directory) == "" {
			return errors.New("telemetry.audit_exports.enabled requires telemetry.audit_exports.directory")
		}
		if c.Telemetry.AuditExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.audit_exports.enabled requires a positive telemetry.audit_exports.interval_minutes")
		}
		if c.Telemetry.AuditExports.RetentionCount <= 0 {
			return errors.New("telemetry.audit_exports.enabled requires a positive telemetry.audit_exports.retention_count")
		}
	}
	if c.Telemetry.SessionExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.session_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.SessionExports.Directory) == "" {
			return errors.New("telemetry.session_exports.enabled requires telemetry.session_exports.directory")
		}
		if c.Telemetry.SessionExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.session_exports.enabled requires a positive telemetry.session_exports.interval_minutes")
		}
		if c.Telemetry.SessionExports.RetentionCount <= 0 {
			return errors.New("telemetry.session_exports.enabled requires a positive telemetry.session_exports.retention_count")
		}
	}
	if c.Telemetry.SessionAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.session_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.SessionAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.session_analytics_exports.enabled requires telemetry.session_analytics_exports.directory")
		}
		if c.Telemetry.SessionAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.session_analytics_exports.enabled requires a positive telemetry.session_analytics_exports.interval_minutes")
		}
		if c.Telemetry.SessionAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.session_analytics_exports.enabled requires a positive telemetry.session_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.VoucherAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.voucher_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.VoucherAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.voucher_analytics_exports.enabled requires telemetry.voucher_analytics_exports.directory")
		}
		if c.Telemetry.VoucherAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.voucher_analytics_exports.enabled requires a positive telemetry.voucher_analytics_exports.interval_minutes")
		}
		if c.Telemetry.VoucherAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.voucher_analytics_exports.enabled requires a positive telemetry.voucher_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.VoucherAgingAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.voucher_aging_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.VoucherAgingAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.voucher_aging_analytics_exports.enabled requires telemetry.voucher_aging_analytics_exports.directory")
		}
		if c.Telemetry.VoucherAgingAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.voucher_aging_analytics_exports.enabled requires a positive telemetry.voucher_aging_analytics_exports.interval_minutes")
		}
		if c.Telemetry.VoucherAgingAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.voucher_aging_analytics_exports.enabled requires a positive telemetry.voucher_aging_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.VoucherRedemptionAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.voucher_redemption_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.VoucherRedemptionAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.voucher_redemption_analytics_exports.enabled requires telemetry.voucher_redemption_analytics_exports.directory")
		}
		if c.Telemetry.VoucherRedemptionAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.voucher_redemption_analytics_exports.enabled requires a positive telemetry.voucher_redemption_analytics_exports.interval_minutes")
		}
		if c.Telemetry.VoucherRedemptionAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.voucher_redemption_analytics_exports.enabled requires a positive telemetry.voucher_redemption_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.VoucherExpiryAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.voucher_expiry_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.VoucherExpiryAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.voucher_expiry_analytics_exports.enabled requires telemetry.voucher_expiry_analytics_exports.directory")
		}
		if c.Telemetry.VoucherExpiryAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.voucher_expiry_analytics_exports.enabled requires a positive telemetry.voucher_expiry_analytics_exports.interval_minutes")
		}
		if c.Telemetry.VoucherExpiryAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.voucher_expiry_analytics_exports.enabled requires a positive telemetry.voucher_expiry_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.GuestLifecycleExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_lifecycle_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestLifecycleExports.Directory) == "" {
			return errors.New("telemetry.guest_lifecycle_exports.enabled requires telemetry.guest_lifecycle_exports.directory")
		}
		if c.Telemetry.GuestLifecycleExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_lifecycle_exports.enabled requires a positive telemetry.guest_lifecycle_exports.interval_minutes")
		}
		if c.Telemetry.GuestLifecycleExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_lifecycle_exports.enabled requires a positive telemetry.guest_lifecycle_exports.retention_count")
		}
	}
	if c.Telemetry.GuestInviteAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_invite_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestInviteAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.guest_invite_analytics_exports.enabled requires telemetry.guest_invite_analytics_exports.directory")
		}
		if c.Telemetry.GuestInviteAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_invite_analytics_exports.enabled requires a positive telemetry.guest_invite_analytics_exports.interval_minutes")
		}
		if c.Telemetry.GuestInviteAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_invite_analytics_exports.enabled requires a positive telemetry.guest_invite_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.GuestConversionAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_conversion_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestConversionAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.guest_conversion_analytics_exports.enabled requires telemetry.guest_conversion_analytics_exports.directory")
		}
		if c.Telemetry.GuestConversionAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_conversion_analytics_exports.enabled requires a positive telemetry.guest_conversion_analytics_exports.interval_minutes")
		}
		if c.Telemetry.GuestConversionAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_conversion_analytics_exports.enabled requires a positive telemetry.guest_conversion_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.GuestRejectionAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_rejection_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestRejectionAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.guest_rejection_analytics_exports.enabled requires telemetry.guest_rejection_analytics_exports.directory")
		}
		if c.Telemetry.GuestRejectionAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_rejection_analytics_exports.enabled requires a positive telemetry.guest_rejection_analytics_exports.interval_minutes")
		}
		if c.Telemetry.GuestRejectionAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_rejection_analytics_exports.enabled requires a positive telemetry.guest_rejection_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.GuestDeliveryAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_delivery_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestDeliveryAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.guest_delivery_analytics_exports.enabled requires telemetry.guest_delivery_analytics_exports.directory")
		}
		if c.Telemetry.GuestDeliveryAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_delivery_analytics_exports.enabled requires a positive telemetry.guest_delivery_analytics_exports.interval_minutes")
		}
		if c.Telemetry.GuestDeliveryAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_delivery_analytics_exports.enabled requires a positive telemetry.guest_delivery_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.GuestDeliveryFailuresExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_delivery_failures_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestDeliveryFailuresExports.Directory) == "" {
			return errors.New("telemetry.guest_delivery_failures_exports.enabled requires telemetry.guest_delivery_failures_exports.directory")
		}
		if c.Telemetry.GuestDeliveryFailuresExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_delivery_failures_exports.enabled requires a positive telemetry.guest_delivery_failures_exports.interval_minutes")
		}
		if c.Telemetry.GuestDeliveryFailuresExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_delivery_failures_exports.enabled requires a positive telemetry.guest_delivery_failures_exports.retention_count")
		}
	}
	if c.Telemetry.GuestSponsorAnalyticsExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.guest_sponsor_analytics_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.GuestSponsorAnalyticsExports.Directory) == "" {
			return errors.New("telemetry.guest_sponsor_analytics_exports.enabled requires telemetry.guest_sponsor_analytics_exports.directory")
		}
		if c.Telemetry.GuestSponsorAnalyticsExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.guest_sponsor_analytics_exports.enabled requires a positive telemetry.guest_sponsor_analytics_exports.interval_minutes")
		}
		if c.Telemetry.GuestSponsorAnalyticsExports.RetentionCount <= 0 {
			return errors.New("telemetry.guest_sponsor_analytics_exports.enabled requires a positive telemetry.guest_sponsor_analytics_exports.retention_count")
		}
	}
	if c.Telemetry.IntegrationExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.integration_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.IntegrationExports.Directory) == "" {
			return errors.New("telemetry.integration_exports.enabled requires telemetry.integration_exports.directory")
		}
		if c.Telemetry.IntegrationExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.integration_exports.enabled requires a positive telemetry.integration_exports.interval_minutes")
		}
		if c.Telemetry.IntegrationExports.RetentionCount <= 0 {
			return errors.New("telemetry.integration_exports.enabled requires a positive telemetry.integration_exports.retention_count")
		}
	}
	if c.Telemetry.HAExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.ha_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.HAExports.Directory) == "" {
			return errors.New("telemetry.ha_exports.enabled requires telemetry.ha_exports.directory")
		}
		if c.Telemetry.HAExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.ha_exports.enabled requires a positive telemetry.ha_exports.interval_minutes")
		}
		if c.Telemetry.HAExports.RetentionCount <= 0 {
			return errors.New("telemetry.ha_exports.enabled requires a positive telemetry.ha_exports.retention_count")
		}
	}
	if c.Telemetry.NetworkExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.network_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.NetworkExports.Directory) == "" {
			return errors.New("telemetry.network_exports.enabled requires telemetry.network_exports.directory")
		}
		if c.Telemetry.NetworkExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.network_exports.enabled requires a positive telemetry.network_exports.interval_minutes")
		}
		if c.Telemetry.NetworkExports.RetentionCount <= 0 {
			return errors.New("telemetry.network_exports.enabled requires a positive telemetry.network_exports.retention_count")
		}
	}
	if c.Telemetry.UpstreamAAAExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.upstream_aaa_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.UpstreamAAAExports.Directory) == "" {
			return errors.New("telemetry.upstream_aaa_exports.enabled requires telemetry.upstream_aaa_exports.directory")
		}
		if c.Telemetry.UpstreamAAAExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.upstream_aaa_exports.enabled requires a positive telemetry.upstream_aaa_exports.interval_minutes")
		}
		if c.Telemetry.UpstreamAAAExports.RetentionCount <= 0 {
			return errors.New("telemetry.upstream_aaa_exports.enabled requires a positive telemetry.upstream_aaa_exports.retention_count")
		}
	}
	if c.Telemetry.UpgradeReadinessExports.Enabled {
		if !c.Telemetry.Enabled {
			return errors.New("telemetry.upgrade_readiness_exports.enabled requires telemetry.enabled")
		}
		if strings.TrimSpace(c.Telemetry.UpgradeReadinessExports.Directory) == "" {
			return errors.New("telemetry.upgrade_readiness_exports.enabled requires telemetry.upgrade_readiness_exports.directory")
		}
		if c.Telemetry.UpgradeReadinessExports.IntervalMinutes <= 0 {
			return errors.New("telemetry.upgrade_readiness_exports.enabled requires a positive telemetry.upgrade_readiness_exports.interval_minutes")
		}
		if c.Telemetry.UpgradeReadinessExports.RetentionCount <= 0 {
			return errors.New("telemetry.upgrade_readiness_exports.enabled requires a positive telemetry.upgrade_readiness_exports.retention_count")
		}
	}
	profile := EffectiveDeploymentProfile(c.Deployment.Profile)
	switch strings.ToLower(strings.TrimSpace(c.Portal.GuestWorkflows.InviteDelivery)) {
	case "", "none", "email", "sms":
	default:
		return fmt.Errorf("portal.guest_workflows.invite_delivery %q is invalid", c.Portal.GuestWorkflows.InviteDelivery)
	}
	if err := validateIdentityFailover(c.Identity.Failover); err != nil {
		return err
	}
	if err := validateActiveDirectory(c.ActiveDirectory); err != nil {
		return err
	}
	if err := validateMFA(c.MFA); err != nil {
		return err
	}
	if err := validateAdminWebAuthn(c.AdminWebAuthn); err != nil {
		return err
	}
	if err := validateMAB(c.MAB); err != nil {
		return err
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
	switch strings.ToLower(strings.TrimSpace(c.Profiling.MDMProvider)) {
	case "", "generic", "workspace-one", "workspace-one-like", "intune", "jamf":
	default:
		return fmt.Errorf("profiling.mdm_provider %q is invalid", c.Profiling.MDMProvider)
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
	case "", "generic", "cisco", "aruba", "juniper-mist", "ruckus", "fortinet", "mikrotik", "unifi", "ubnt", "ubiquiti", "meraki", "openwifi", "open-wifi", "tip-openwifi":
	default:
		return fmt.Errorf("integrations.controller.platform %q is invalid", c.Integrations.Controller.Platform)
	}
	switch strings.ToLower(strings.TrimSpace(c.Integrations.Controller.SyncMode)) {
	case "", "monitor", "pull-config", "push-config", "coa-only":
	default:
		return fmt.Errorf("integrations.controller.sync_mode %q is invalid", c.Integrations.Controller.SyncMode)
	}
	if c.Integrations.Controller.Endpoint != "" {
		if err := requireHTTPURL("integrations.controller.endpoint", c.Integrations.Controller.Endpoint); err != nil {
			return err
		}
	}
	if c.Integrations.Controller.Enabled {
		controllerPlatform := strings.ToLower(strings.TrimSpace(c.Integrations.Controller.Platform))
		controllerSyncMode := strings.ToLower(strings.TrimSpace(c.Integrations.Controller.SyncMode))
		if profile == "lite" {
			return errors.New("integrations.controller.enabled is not supported on the lite deployment profile")
		}
		if !controllerConfigured(c) {
			if controllerPlatform == "cisco" || controllerPlatform == "ruckus" || controllerPlatform == "mikrotik" {
				return fmt.Errorf("integrations.controller.enabled with platform=%s requires endpoint, api_username_env, api_password_env, and sync_mode", controllerPlatform)
			}
			return errors.New("integrations.controller.enabled requires platform, endpoint, api_token_env, and sync_mode")
		}
		if controllerPlatform == "cisco" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for Cisco ISE ERS")
			}
		}
		if controllerPlatform == "aruba" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for Aruba Central")
			}
			if controllerHasEnterpriseSSIDs(c) && strings.TrimSpace(c.Integrations.Controller.RadiusProfile) == "" {
				return errors.New("integrations.controller.radius_profile is required for Aruba Central enterprise WLAN sync")
			}
		}
		if controllerPlatform == "juniper-mist" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for Juniper Mist")
			}
			if controllerHasEnterpriseSSIDs(c) && (strings.TrimSpace(c.Integrations.Controller.RadiusServer) == "" || strings.TrimSpace(c.Integrations.Controller.RadiusSecretEnv) == "") {
				return errors.New("integrations.controller.radius_server and radius_secret_env are required for Juniper Mist enterprise WLAN sync")
			}
		}
		if controllerPlatform == "ruckus" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for Ruckus SmartZone")
			}
			if controllerHasEnterpriseSSIDs(c) && strings.TrimSpace(c.Integrations.Controller.RadiusProfile) == "" {
				return errors.New("integrations.controller.radius_profile is required for Ruckus SmartZone enterprise WLAN sync")
			}
		}
		if controllerPlatform == "fortinet" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for FortiGate")
			}
			if controllerHasEnterpriseSSIDs(c) && strings.TrimSpace(c.Integrations.Controller.RadiusProfile) == "" {
				return errors.New("integrations.controller.radius_profile is required for FortiGate enterprise VAP sync")
			}
		}
		if controllerPlatform == "mikrotik" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for MikroTik RouterOS")
			}
			if controllerHasEnterpriseSSIDs(c) && (strings.TrimSpace(c.Integrations.Controller.RadiusServer) == "" || strings.TrimSpace(c.Integrations.Controller.RadiusSecretEnv) == "") {
				return errors.New("integrations.controller.radius_server and radius_secret_env are required for MikroTik enterprise WiFi sync")
			}
		}
		if controllerPlatform == "unifi" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for UniFi Network")
			}
			if controllerHasEnterpriseSSIDs(c) && strings.TrimSpace(c.Integrations.Controller.RadiusProfile) == "" {
				return errors.New("integrations.controller.radius_profile is required for UniFi enterprise WiFi sync")
			}
		}
		if controllerPlatform == "meraki" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for Cisco Meraki Dashboard")
			}
			if controllerHasEnterpriseSSIDs(c) && (strings.TrimSpace(c.Integrations.Controller.RadiusServer) == "" || strings.TrimSpace(c.Integrations.Controller.RadiusSecretEnv) == "") {
				return errors.New("integrations.controller.radius_server and radius_secret_env are required for Cisco Meraki enterprise SSID sync")
			}
		}
		if controllerPlatform == "openwifi" || controllerPlatform == "open-wifi" || controllerPlatform == "tip-openwifi" {
			parsed, _ := url.Parse(c.Integrations.Controller.Endpoint)
			if parsed == nil || parsed.Scheme != "https" {
				return errors.New("integrations.controller.endpoint must use https for TIP OpenWiFi Gateway")
			}
			if controllerHasEnterpriseSSIDs(c) && (strings.TrimSpace(c.Integrations.Controller.RadiusServer) == "" || strings.TrimSpace(c.Integrations.Controller.RadiusSecretEnv) == "") {
				return errors.New("integrations.controller.radius_server and radius_secret_env are required for TIP OpenWiFi enterprise SSID sync")
			}
		}
		if (controllerPlatform == "cisco" || controllerPlatform == "aruba" || controllerPlatform == "juniper-mist" || controllerPlatform == "ruckus" || controllerPlatform == "fortinet" || controllerPlatform == "mikrotik" || controllerPlatform == "unifi" || controllerPlatform == "meraki" || controllerPlatform == "openwifi" || controllerPlatform == "open-wifi" || controllerPlatform == "tip-openwifi") && controllerSyncMode == "coa-only" {
			return fmt.Errorf("integrations.controller.sync_mode %q is not supported by the %s native adapter", c.Integrations.Controller.SyncMode, controllerPlatform)
		}
		if controllerPlatformRequiresSite(c.Integrations.Controller.Platform) && strings.TrimSpace(c.Integrations.Controller.Site) == "" {
			return fmt.Errorf("integrations.controller.site is required for platform %q", strings.TrimSpace(c.Integrations.Controller.Platform))
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
	witnessURLs := normalizeWitnessURLs(c.HighAvailability.WitnessAPIURL, c.HighAvailability.WitnessURLs)
	if len(witnessURLs) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_api_url requires high_availability.enabled")
		}
		if !c.HighAvailability.SplitBrainProtectionEnabled {
			return errors.New("high_availability.witness_api_url requires high_availability.split_brain_protection_enabled")
		}
		for index, witnessURL := range witnessURLs {
			if err := requireHTTPURL(fmt.Sprintf("high_availability.witness_urls[%d]", index), witnessURL); err != nil {
				return err
			}
		}
		if c.HighAvailability.WitnessQuorum <= 0 {
			return fmt.Errorf("high_availability.witness_quorum %d must be at least 1", c.HighAvailability.WitnessQuorum)
		}
		if c.HighAvailability.WitnessQuorum > len(witnessURLs) {
			return fmt.Errorf("high_availability.witness_quorum %d cannot exceed configured witness count %d", c.HighAvailability.WitnessQuorum, len(witnessURLs))
		}
		if c.HighAvailability.WitnessWeightThreshold < 0 {
			return fmt.Errorf("high_availability.witness_weight_threshold %d cannot be negative", c.HighAvailability.WitnessWeightThreshold)
		}
		for witnessURL, weight := range c.HighAvailability.WitnessWeights {
			trimmedURL := strings.TrimSpace(witnessURL)
			if trimmedURL == "" {
				return errors.New("high_availability.witness_weights keys cannot be blank")
			}
			if !slices.Contains(witnessURLs, trimmedURL) {
				return fmt.Errorf("high_availability.witness_weights key %q does not match a configured witness URL", trimmedURL)
			}
			if weight <= 0 {
				return fmt.Errorf("high_availability.witness_weights[%q] %d must be at least 1", trimmedURL, weight)
			}
		}
		if c.HighAvailability.WitnessWeightThreshold > 0 {
			_, totalWeight := effectiveWitnessWeights(witnessURLs, c.HighAvailability.WitnessWeights)
			if c.HighAvailability.WitnessWeightThreshold > totalWeight {
				return fmt.Errorf("high_availability.witness_weight_threshold %d cannot exceed configured witness weight %d", c.HighAvailability.WitnessWeightThreshold, totalWeight)
			}
		}
		for witnessURL, group := range c.HighAvailability.WitnessGroups {
			trimmedURL := strings.TrimSpace(witnessURL)
			if trimmedURL == "" {
				return errors.New("high_availability.witness_groups keys cannot be blank")
			}
			if !slices.Contains(witnessURLs, trimmedURL) {
				return fmt.Errorf("high_availability.witness_groups key %q does not match a configured witness URL", trimmedURL)
			}
			if strings.TrimSpace(group) == "" {
				return fmt.Errorf("high_availability.witness_groups[%q] must not be blank", trimmedURL)
			}
		}
		_, distinctGroups := effectiveWitnessGroups(witnessURLs, c.HighAvailability.WitnessGroups)
		if c.HighAvailability.WitnessMinDistinctGroups > 0 {
			if c.HighAvailability.WitnessMinDistinctGroups > len(distinctGroups) {
				return fmt.Errorf("high_availability.witness_min_distinct_groups %d cannot exceed configured witness group count %d", c.HighAvailability.WitnessMinDistinctGroups, len(distinctGroups))
			}
		}
		for witnessURL, source := range c.HighAvailability.WitnessSources {
			trimmedURL := strings.TrimSpace(witnessURL)
			if trimmedURL == "" {
				return errors.New("high_availability.witness_sources keys cannot be blank")
			}
			if !slices.Contains(witnessURLs, trimmedURL) {
				return fmt.Errorf("high_availability.witness_sources key %q does not match a configured witness URL", trimmedURL)
			}
			if strings.TrimSpace(source) == "" {
				return fmt.Errorf("high_availability.witness_sources[%q] must not be blank", trimmedURL)
			}
		}
		sourceMap, distinctSources := effectiveWitnessSources(witnessURLs, c.HighAvailability.WitnessSources)
		_ = sourceMap
		for source, tier := range c.HighAvailability.WitnessSourceConfidence {
			trimmedSource := strings.TrimSpace(source)
			if trimmedSource == "" {
				return errors.New("high_availability.witness_source_confidence keys cannot be blank")
			}
			if !slices.Contains(distinctSources, trimmedSource) {
				return fmt.Errorf("high_availability.witness_source_confidence key %q does not match a configured witness source", trimmedSource)
			}
			if strings.TrimSpace(tier) == "" {
				return fmt.Errorf("high_availability.witness_source_confidence[%q] must not be blank", trimmedSource)
			}
		}
		confidenceBySource, distinctTiers := effectiveWitnessConfidenceTiers(distinctSources, c.HighAvailability.WitnessSourceConfidence)
		tierWitnessCounts := make(map[string]int, len(distinctTiers))
		tierWitnessWeights := make(map[string]int, len(distinctTiers))
		for _, witnessURL := range witnessURLs {
			source := sourceMap[strings.TrimSpace(witnessURL)]
			tier := strings.TrimSpace(confidenceBySource[source])
			if tier == "" {
				tier = "standard"
			}
			tierWitnessCounts[tier]++
			weight := 1
			if override, ok := c.HighAvailability.WitnessWeights[strings.TrimSpace(witnessURL)]; ok && override > 0 {
				weight = override
			}
			tierWitnessWeights[tier] += weight
		}
		tierWitnessGroups := make(map[string]map[string]struct{}, len(distinctTiers))
		tierWitnessSources := make(map[string]map[string]struct{}, len(distinctTiers))
		for _, witnessURL := range witnessURLs {
			trimmedURL := strings.TrimSpace(witnessURL)
			source := sourceMap[trimmedURL]
			tier := strings.TrimSpace(confidenceBySource[source])
			if tier == "" {
				tier = "standard"
			}
			group := trimmedURL
			if override, ok := c.HighAvailability.WitnessGroups[trimmedURL]; ok && strings.TrimSpace(override) != "" {
				group = strings.TrimSpace(override)
			}
			groups := tierWitnessGroups[tier]
			if groups == nil {
				groups = make(map[string]struct{})
				tierWitnessGroups[tier] = groups
			}
			groups[group] = struct{}{}
			sources := tierWitnessSources[tier]
			if sources == nil {
				sources = make(map[string]struct{})
				tierWitnessSources[tier] = sources
			}
			sources[source] = struct{}{}
		}
		for tier, approvals := range c.HighAvailability.WitnessMinApprovalsByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_min_approvals_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_min_approvals_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if approvals < 0 {
				return fmt.Errorf("high_availability.witness_min_approvals_by_tier[%q] %d cannot be negative", trimmedTier, approvals)
			}
			if approvals > tierWitnessCounts[trimmedTier] {
				return fmt.Errorf("high_availability.witness_min_approvals_by_tier[%q] %d cannot exceed configured witness count %d for that tier", trimmedTier, approvals, tierWitnessCounts[trimmedTier])
			}
		}
		for tier, minWeight := range c.HighAvailability.WitnessMinWeightByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_min_weight_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_min_weight_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if minWeight < 0 {
				return fmt.Errorf("high_availability.witness_min_weight_by_tier[%q] %d cannot be negative", trimmedTier, minWeight)
			}
			if minWeight > tierWitnessWeights[trimmedTier] {
				return fmt.Errorf("high_availability.witness_min_weight_by_tier[%q] %d cannot exceed configured witness weight %d for that tier", trimmedTier, minWeight, tierWitnessWeights[trimmedTier])
			}
		}
		for tier, minimum := range c.HighAvailability.WitnessMinDistinctGroupsByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_min_distinct_groups_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_min_distinct_groups_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if minimum < 0 {
				return fmt.Errorf("high_availability.witness_min_distinct_groups_by_tier[%q] %d cannot be negative", trimmedTier, minimum)
			}
			if minimum > len(tierWitnessGroups[trimmedTier]) {
				return fmt.Errorf("high_availability.witness_min_distinct_groups_by_tier[%q] %d cannot exceed configured witness group count %d for that tier", trimmedTier, minimum, len(tierWitnessGroups[trimmedTier]))
			}
		}
		for tier, minimum := range c.HighAvailability.WitnessMinDistinctSourcesByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_min_distinct_sources_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_min_distinct_sources_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if minimum < 0 {
				return fmt.Errorf("high_availability.witness_min_distinct_sources_by_tier[%q] %d cannot be negative", trimmedTier, minimum)
			}
			if minimum > len(tierWitnessSources[trimmedTier]) {
				return fmt.Errorf("high_availability.witness_min_distinct_sources_by_tier[%q] %d cannot exceed configured witness source count %d for that tier", trimmedTier, minimum, len(tierWitnessSources[trimmedTier]))
			}
		}
		for tier, sources := range c.HighAvailability.WitnessRequiredSourcesByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_required_sources_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_required_sources_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			for _, source := range sources {
				trimmedSource := strings.TrimSpace(source)
				if trimmedSource == "" {
					return fmt.Errorf("high_availability.witness_required_sources_by_tier[%q] entries must not be blank", trimmedTier)
				}
				if !slices.Contains(distinctSources, trimmedSource) {
					return fmt.Errorf("high_availability.witness_required_sources_by_tier[%q] entry %q does not match a configured witness source", trimmedTier, trimmedSource)
				}
			}
		}
		for tier, urls := range c.HighAvailability.WitnessRequiredURLsByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_required_urls_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_required_urls_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			for _, witnessURL := range urls {
				trimmedURL := strings.TrimSpace(witnessURL)
				if trimmedURL == "" {
					return fmt.Errorf("high_availability.witness_required_urls_by_tier[%q] entries must not be blank", trimmedTier)
				}
				if !slices.Contains(witnessURLs, trimmedURL) {
					return fmt.Errorf("high_availability.witness_required_urls_by_tier[%q] entry %q does not match a configured witness URL", trimmedTier, trimmedURL)
				}
			}
		}
		for tier, groups := range c.HighAvailability.WitnessRequiredGroupsByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_required_groups_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_required_groups_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			for _, group := range groups {
				trimmedGroup := strings.TrimSpace(group)
				if trimmedGroup == "" {
					return fmt.Errorf("high_availability.witness_required_groups_by_tier[%q] entries must not be blank", trimmedTier)
				}
				if !slices.Contains(distinctGroups, trimmedGroup) {
					return fmt.Errorf("high_availability.witness_required_groups_by_tier[%q] entry %q does not match a configured witness group", trimmedTier, trimmedGroup)
				}
			}
		}
		for tier, maxAge := range c.HighAvailability.WitnessMaxAgeByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_max_age_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_max_age_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if maxAge < 0 {
				return fmt.Errorf("high_availability.witness_max_age_by_tier[%q] %d cannot be negative", trimmedTier, maxAge)
			}
		}
		for tier, node := range c.HighAvailability.WitnessRequiredNodeByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_required_node_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_required_node_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if strings.TrimSpace(node) == "" {
				return fmt.Errorf("high_availability.witness_required_node_by_tier[%q] must not be blank", trimmedTier)
			}
		}
		for _, tier := range c.HighAvailability.WitnessSignatureRequiredTiers {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_signature_required_tiers entries must not be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_signature_required_tiers entry %q does not match a configured witness confidence tier", trimmedTier)
			}
		}
		for _, tier := range c.HighAvailability.WitnessReplayRequiredTiers {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_replay_required_tiers entries must not be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_replay_required_tiers entry %q does not match a configured witness confidence tier", trimmedTier)
			}
		}
		for tier, budget := range c.HighAvailability.WitnessFailureToleranceByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_failure_tolerance_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_failure_tolerance_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if budget < 0 {
				return fmt.Errorf("high_availability.witness_failure_tolerance_by_tier[%q] %d cannot be negative", trimmedTier, budget)
			}
		}
		for tier, budget := range c.HighAvailability.WitnessFailureWeightByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_failure_weight_tolerance_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_failure_weight_tolerance_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			if budget < 0 {
				return fmt.Errorf("high_availability.witness_failure_weight_tolerance_by_tier[%q] %d cannot be negative", trimmedTier, budget)
			}
		}
		for _, tier := range c.HighAvailability.WitnessBlockingTiers {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_blocking_tiers entries must not be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_blocking_tiers entry %q does not match a configured witness confidence tier", trimmedTier)
			}
		}
		if len(c.HighAvailability.WitnessRequiredGroups) > 0 {
			for _, group := range c.HighAvailability.WitnessRequiredGroups {
				trimmedGroup := strings.TrimSpace(group)
				if trimmedGroup == "" {
					return errors.New("high_availability.witness_required_groups entries must not be blank")
				}
				if !slices.Contains(distinctGroups, trimmedGroup) {
					return fmt.Errorf("high_availability.witness_required_groups entry %q does not match a configured witness group", trimmedGroup)
				}
			}
		}
		if len(c.HighAvailability.WitnessRequiredSources) > 0 {
			for _, source := range c.HighAvailability.WitnessRequiredSources {
				trimmedSource := strings.TrimSpace(source)
				if trimmedSource == "" {
					return errors.New("high_availability.witness_required_sources entries must not be blank")
				}
				if !slices.Contains(distinctSources, trimmedSource) {
					return fmt.Errorf("high_availability.witness_required_sources entry %q does not match a configured witness source", trimmedSource)
				}
			}
		}
		if len(c.HighAvailability.WitnessRequiredURLs) > 0 {
			for _, witnessURL := range c.HighAvailability.WitnessRequiredURLs {
				trimmedURL := strings.TrimSpace(witnessURL)
				if trimmedURL == "" {
					return errors.New("high_availability.witness_required_urls entries must not be blank")
				}
				if !slices.Contains(witnessURLs, trimmedURL) {
					return fmt.Errorf("high_availability.witness_required_urls entry %q does not match a configured witness URL", trimmedURL)
				}
			}
		}
		groupConfigured := c.HighAvailability.WitnessMinDistinctGroups > 0 || len(c.HighAvailability.WitnessRequiredGroups) > 0
		sourceConfigured := len(c.HighAvailability.WitnessRequiredSources) > 0
		urlConfigured := len(c.HighAvailability.WitnessRequiredURLs) > 0
		switch mode := normalizeWitnessPolicyMode(c.HighAvailability.WitnessPolicyMode); mode {
		case "all":
		case "any":
			if !groupConfigured && !sourceConfigured && !urlConfigured {
				return errors.New("high_availability.witness_policy_mode any requires witness_min_distinct_groups, witness_required_groups, witness_required_sources, or witness_required_urls")
			}
		case "group_only":
			if !groupConfigured {
				return errors.New("high_availability.witness_policy_mode group_only requires high_availability.witness_min_distinct_groups or high_availability.witness_required_groups")
			}
		case "source_only":
			if !sourceConfigured {
				return errors.New("high_availability.witness_policy_mode source_only requires high_availability.witness_required_sources")
			}
		case "url_only":
			if !urlConfigured {
				return errors.New("high_availability.witness_policy_mode url_only requires high_availability.witness_required_urls")
			}
		default:
			return fmt.Errorf("high_availability.witness_policy_mode %q must be one of all, any, group_only, source_only, or url_only", c.HighAvailability.WitnessPolicyMode)
		}
		tierGroupConfigured := make(map[string]bool, len(distinctTiers))
		tierSourceConfigured := make(map[string]bool, len(distinctTiers))
		for _, tier := range distinctTiers {
			tierGroupConfigured[tier] = c.HighAvailability.WitnessMinDistinctGroupsByTier[tier] > 0 || len(c.HighAvailability.WitnessRequiredGroupsByTier[tier]) > 0
			tierSourceConfigured[tier] = c.HighAvailability.WitnessMinDistinctSourcesByTier[tier] > 0 || len(c.HighAvailability.WitnessRequiredSourcesByTier[tier]) > 0 || len(c.HighAvailability.WitnessRequiredURLsByTier[tier]) > 0
		}
		for tier, mode := range c.HighAvailability.WitnessPolicyModeByTier {
			trimmedTier := strings.TrimSpace(tier)
			if trimmedTier == "" {
				return errors.New("high_availability.witness_policy_mode_by_tier keys cannot be blank")
			}
			if !slices.Contains(distinctTiers, trimmedTier) {
				return fmt.Errorf("high_availability.witness_policy_mode_by_tier key %q does not match a configured witness confidence tier", trimmedTier)
			}
			switch normalized := normalizeWitnessTierPolicyMode(mode); normalized {
			case "all":
			case "any":
				if !tierGroupConfigured[trimmedTier] && !tierSourceConfigured[trimmedTier] {
					return fmt.Errorf("high_availability.witness_policy_mode_by_tier[%q] any requires high_availability.witness_min_distinct_groups_by_tier, high_availability.witness_required_groups_by_tier, high_availability.witness_min_distinct_sources_by_tier, high_availability.witness_required_sources_by_tier, or high_availability.witness_required_urls_by_tier", trimmedTier)
				}
			case "group_only":
				if !tierGroupConfigured[trimmedTier] {
					return fmt.Errorf("high_availability.witness_policy_mode_by_tier[%q] group_only requires high_availability.witness_min_distinct_groups_by_tier or high_availability.witness_required_groups_by_tier", trimmedTier)
				}
			case "source_only":
				if !tierSourceConfigured[trimmedTier] {
					return fmt.Errorf("high_availability.witness_policy_mode_by_tier[%q] source_only requires high_availability.witness_min_distinct_sources_by_tier, high_availability.witness_required_sources_by_tier, or high_availability.witness_required_urls_by_tier", trimmedTier)
				}
			case "url_only":
				if len(c.HighAvailability.WitnessRequiredURLsByTier[trimmedTier]) == 0 {
					return fmt.Errorf("high_availability.witness_policy_mode_by_tier[%q] url_only requires high_availability.witness_required_urls_by_tier", trimmedTier)
				}
			default:
				return fmt.Errorf("high_availability.witness_policy_mode_by_tier[%q] %q must be one of all, any, group_only, source_only, or url_only", trimmedTier, mode)
			}
		}
		if c.HighAvailability.WitnessFailureTolerance < 0 {
			return fmt.Errorf("high_availability.witness_failure_tolerance %d cannot be negative", c.HighAvailability.WitnessFailureTolerance)
		}
		if c.HighAvailability.WitnessFailureTolerance > len(witnessURLs) {
			return fmt.Errorf("high_availability.witness_failure_tolerance %d cannot exceed configured witness count %d", c.HighAvailability.WitnessFailureTolerance, len(witnessURLs))
		}
		if c.HighAvailability.WitnessFailureWeightTolerance < 0 {
			return fmt.Errorf("high_availability.witness_failure_weight_tolerance %d cannot be negative", c.HighAvailability.WitnessFailureWeightTolerance)
		}
		if c.HighAvailability.WitnessFailureWeightTolerance > 0 {
			_, totalWeight := effectiveWitnessWeights(witnessURLs, c.HighAvailability.WitnessWeights)
			if c.HighAvailability.WitnessFailureWeightTolerance > totalWeight {
				return fmt.Errorf("high_availability.witness_failure_weight_tolerance %d cannot exceed configured witness weight %d", c.HighAvailability.WitnessFailureWeightTolerance, totalWeight)
			}
		}
	}
	if strings.TrimSpace(c.HighAvailability.WitnessTokenEnv) != "" {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_token_env requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_token_env requires high_availability.witness_api_url")
		}
	}
	if strings.TrimSpace(c.HighAvailability.WitnessSigningKeyEnv) != "" {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_signing_key_env requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_signing_key_env requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessGroups) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_groups requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_groups requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredGroups) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_groups requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_groups requires high_availability.witness_api_url")
		}
	}
	if c.HighAvailability.WitnessMinDistinctGroups < 0 {
		return fmt.Errorf("high_availability.witness_min_distinct_groups %d cannot be negative", c.HighAvailability.WitnessMinDistinctGroups)
	}
	if c.HighAvailability.WitnessMinDistinctGroups > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_min_distinct_groups requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_min_distinct_groups requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessSources) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_sources requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_sources requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredSources) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_sources requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_sources requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredURLs) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_urls requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_urls requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessSourceConfidence) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_source_confidence requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_source_confidence requires high_availability.witness_api_url")
		}
	}
	if strings.TrimSpace(c.HighAvailability.WitnessPolicyMode) != "" && normalizeWitnessPolicyMode(c.HighAvailability.WitnessPolicyMode) != "all" {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_policy_mode requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_policy_mode requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessPolicyModeByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_policy_mode_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_policy_mode_by_tier requires high_availability.witness_api_url")
		}
	}
	if c.HighAvailability.WitnessFailureTolerance > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_failure_tolerance requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_failure_tolerance requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessMinApprovalsByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_min_approvals_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_min_approvals_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessMinWeightByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_min_weight_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_min_weight_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessMinDistinctGroupsByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_min_distinct_groups_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_min_distinct_groups_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessMinDistinctSourcesByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_min_distinct_sources_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_min_distinct_sources_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredSourcesByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_sources_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_sources_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredURLsByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_urls_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_urls_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredGroupsByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_groups_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_groups_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessMaxAgeByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_max_age_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_max_age_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessRequiredNodeByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_node_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_node_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessSignatureRequiredTiers) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_signature_required_tiers requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_signature_required_tiers requires high_availability.witness_api_url")
		}
		if strings.TrimSpace(c.HighAvailability.WitnessSigningKeyEnv) == "" {
			return errors.New("high_availability.witness_signature_required_tiers requires high_availability.witness_signing_key_env")
		}
	}
	if len(c.HighAvailability.WitnessReplayRequiredTiers) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_replay_required_tiers requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_replay_required_tiers requires high_availability.witness_api_url")
		}
		if strings.TrimSpace(c.HighAvailability.WitnessSigningKeyEnv) == "" {
			return errors.New("high_availability.witness_replay_required_tiers requires high_availability.witness_signing_key_env")
		}
	}
	if len(c.HighAvailability.WitnessFailureToleranceByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_failure_tolerance_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_failure_tolerance_by_tier requires high_availability.witness_api_url")
		}
	}
	if c.HighAvailability.WitnessFailureWeightTolerance > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_failure_weight_tolerance requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_failure_weight_tolerance requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessFailureWeightByTier) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_failure_weight_tolerance_by_tier requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_failure_weight_tolerance_by_tier requires high_availability.witness_api_url")
		}
	}
	if len(c.HighAvailability.WitnessBlockingTiers) > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_blocking_tiers requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_blocking_tiers requires high_availability.witness_api_url")
		}
	}
	if c.HighAvailability.WitnessMaxAgeSeconds < 0 {
		return fmt.Errorf("high_availability.witness_max_age_seconds %d cannot be negative", c.HighAvailability.WitnessMaxAgeSeconds)
	}
	if c.HighAvailability.WitnessMaxAgeSeconds > 0 {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_max_age_seconds requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_max_age_seconds requires high_availability.witness_api_url")
		}
	}
	if strings.TrimSpace(c.HighAvailability.WitnessRequiredNode) != "" {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_required_node requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_required_node requires high_availability.witness_api_url")
		}
	}
	if c.HighAvailability.WitnessReplayProtectionEnabled {
		if !c.HighAvailability.Enabled {
			return errors.New("high_availability.witness_replay_protection_enabled requires high_availability.enabled")
		}
		if len(witnessURLs) == 0 {
			return errors.New("high_availability.witness_replay_protection_enabled requires high_availability.witness_api_url")
		}
		if strings.TrimSpace(c.HighAvailability.WitnessSigningKeyEnv) == "" {
			return errors.New("high_availability.witness_replay_protection_enabled requires high_availability.witness_signing_key_env")
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
	if err := validateRadiusDynamicClients(c.Radius.DynamicClients); err != nil {
		return err
	}
	if err := validateRadiusPacketHardening(c.Radius.PacketHardening); err != nil {
		return err
	}
	if err := validateRadSecConfig(c); err != nil {
		return err
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
			if !productconfigs.ValidVendorDictionaryAttributeType(attr.Type) {
				return fmt.Errorf("radius.vendor.attributes[%d].type %q is invalid", i, attr.Type)
			}
		}
	}
	if err := validateRadiusVendorIdentity(c.Radius.Vendor); err != nil {
		return err
	}
	dictionaryRelease := productconfigs.EffectiveDictionaryReleaseProfileID(c.Radius.Vendor.DictionaryRelease)
	if !productconfigs.ValidDictionaryReleaseProfileID(dictionaryRelease) {
		return fmt.Errorf("radius.vendor.dictionary_release %q is unknown", c.Radius.Vendor.DictionaryRelease)
	}
	seenVendorPacks := map[string]struct{}{}
	for i, pack := range c.Radius.Vendor.CompatibilityPacks {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(pack)
		if key == "" {
			return fmt.Errorf("radius.vendor.compatibility_packs[%d] cannot be empty", i)
		}
		if !productconfigs.ValidVendorCompatibilityPackKey(key) {
			return fmt.Errorf("radius.vendor.compatibility_packs[%d] %q is unknown", i, pack)
		}
		if _, exists := seenVendorPacks[key]; exists {
			return fmt.Errorf("radius.vendor.compatibility_packs[%d] %q duplicates an earlier pack", i, pack)
		}
		seenVendorPacks[key] = struct{}{}
	}
	if err := validateRadiusOpaquePassThrough(c.Radius.Vendor.OpaquePassThrough); err != nil {
		return err
	}
	seenVendorRoles := map[string]struct{}{}
	seenVendorRoleValues := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.RoleMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		if !productconfigs.VendorPackSupportsNumericRoleMapping(pack) {
			return fmt.Errorf("radius.vendor.role_mappings[%d].pack %q does not support numeric role mappings", i, mapping.Pack)
		}
		if role == "" {
			return fmt.Errorf("radius.vendor.role_mappings[%d].role cannot be empty", i)
		}
		if len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.role_mappings[%d].role is invalid", i)
		}
		if mapping.Value < 0 || uint64(mapping.Value) > uint64(^uint32(0)) {
			return fmt.Errorf("radius.vendor.role_mappings[%d].value %d is outside the uint32 range", i, mapping.Value)
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenVendorRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.role_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		valueKey := fmt.Sprintf("%s\x00%d", pack, mapping.Value)
		if _, exists := seenVendorRoleValues[valueKey]; exists {
			return fmt.Errorf("radius.vendor.role_mappings[%d] duplicates value %d for pack %q", i, mapping.Value, pack)
		}
		seenVendorRoles[roleKey] = struct{}{}
		seenVendorRoleValues[valueKey] = struct{}{}
	}
	seenExtendedVLANRoles := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.ExtendedVLANMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		if !productconfigs.VendorPackSupportsExtendedVLANMapping(pack) {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d].pack %q does not support extended VLAN mappings", i, mapping.Pack)
		}
		if role == "" {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d].role cannot be empty", i)
		}
		if len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d].role is invalid", i)
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenExtendedVLANRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		seenExtendedVLANRoles[roleKey] = struct{}{}

		vlanCount := len(mapping.TaggedVLANs)
		seenVLANs := map[int]struct{}{}
		if mapping.UntaggedVLAN != 0 {
			if mapping.UntaggedVLAN < 1 || mapping.UntaggedVLAN > 4094 {
				return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d].untagged_vlan %d is outside the VLAN range 1-4094", i, mapping.UntaggedVLAN)
			}
			seenVLANs[mapping.UntaggedVLAN] = struct{}{}
			vlanCount++
		}
		if vlanCount == 0 {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d] must include an untagged or tagged VLAN", i)
		}
		if vlanCount > 10 {
			return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d] cannot include more than 10 VLANs", i)
		}
		for taggedIndex, vlan := range mapping.TaggedVLANs {
			if vlan < 1 || vlan > 4094 {
				return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d].tagged_vlans[%d] %d is outside the VLAN range 1-4094", i, taggedIndex, vlan)
			}
			if _, exists := seenVLANs[vlan]; exists {
				return fmt.Errorf("radius.vendor.extended_vlan_mappings[%d] duplicates VLAN %d", i, vlan)
			}
			seenVLANs[vlan] = struct{}{}
		}
	}
	seenAVPairRoles := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.AVPairMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		if _, supported := productconfigs.VendorPackAVPairAttribute(pack); !supported {
			return fmt.Errorf("radius.vendor.avpair_mappings[%d].pack %q does not support AVPair mappings", i, mapping.Pack)
		}
		if role == "" {
			return fmt.Errorf("radius.vendor.avpair_mappings[%d].role cannot be empty", i)
		}
		if len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.avpair_mappings[%d].role is invalid", i)
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenAVPairRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.avpair_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		seenAVPairRoles[roleKey] = struct{}{}
		if len(mapping.Values) == 0 || len(mapping.Values) > 16 {
			return fmt.Errorf("radius.vendor.avpair_mappings[%d].values must contain between 1 and 16 entries", i)
		}
		seenValues := map[string]struct{}{}
		for valueIndex, value := range mapping.Values {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 240 || strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("radius.vendor.avpair_mappings[%d].values[%d] is invalid", i, valueIndex)
			}
			if unsupported := unsupportedAVPairTemplateToken(value); unsupported != "" {
				return fmt.Errorf("radius.vendor.avpair_mappings[%d].values[%d] uses unsupported template token %q", i, valueIndex, unsupported)
			}
			if _, exists := seenValues[value]; exists {
				return fmt.Errorf("radius.vendor.avpair_mappings[%d].values[%d] duplicates an earlier value", i, valueIndex)
			}
			seenValues[value] = struct{}{}
		}
	}
	seenPortalProfiles := map[string]struct{}{}
	seenPortalValues := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.PortalStatusMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		profile := strings.TrimSpace(mapping.PortalProfile)
		if !productconfigs.VendorPackSupportsPortalStatusMapping(pack) {
			return fmt.Errorf("radius.vendor.portal_status_mappings[%d].pack %q does not support portal status mappings", i, mapping.Pack)
		}
		if profile == "" || len(profile) > 1024 || strings.ContainsAny(profile, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.portal_status_mappings[%d].portal_profile is invalid", i)
		}
		if mapping.Value < 0 || uint64(mapping.Value) > uint64(^uint32(0)) {
			return fmt.Errorf("radius.vendor.portal_status_mappings[%d].value %d is outside the uint32 range", i, mapping.Value)
		}
		profileKey := pack + "\x00" + strings.ToLower(profile)
		if _, exists := seenPortalProfiles[profileKey]; exists {
			return fmt.Errorf("radius.vendor.portal_status_mappings[%d] duplicates portal profile %q for pack %q", i, profile, pack)
		}
		valueKey := fmt.Sprintf("%s\x00%d", pack, mapping.Value)
		if _, exists := seenPortalValues[valueKey]; exists {
			return fmt.Errorf("radius.vendor.portal_status_mappings[%d] duplicates value %d for pack %q", i, mapping.Value, pack)
		}
		seenPortalProfiles[profileKey] = struct{}{}
		seenPortalValues[valueKey] = struct{}{}
	}
	seenSessionActionRoles := map[string]struct{}{}
	seenSessionActionValues := map[string]string{}
	for i, mapping := range c.Radius.Vendor.SessionActionMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		action := strings.ToLower(strings.TrimSpace(mapping.Action))
		if !productconfigs.VendorPackSupportsSessionActionMapping(pack) {
			return fmt.Errorf("radius.vendor.session_action_mappings[%d].pack %q does not support session action mappings", i, mapping.Pack)
		}
		if role == "" || len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.session_action_mappings[%d].role is invalid", i)
		}
		switch action {
		case "allow", "reauth", "disconnect", "quarantine":
		default:
			return fmt.Errorf("radius.vendor.session_action_mappings[%d].action %q is invalid", i, mapping.Action)
		}
		if mapping.Value < 0 || uint64(mapping.Value) > uint64(^uint32(0)) {
			return fmt.Errorf("radius.vendor.session_action_mappings[%d].value %d is outside the uint32 range", i, mapping.Value)
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenSessionActionRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.session_action_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		valueKey := fmt.Sprintf("%s\x00%d", pack, mapping.Value)
		if existingAction, exists := seenSessionActionValues[valueKey]; exists && existingAction != action {
			return fmt.Errorf("radius.vendor.session_action_mappings[%d] maps value %d to both %q and %q for pack %q", i, mapping.Value, existingAction, action, pack)
		}
		seenSessionActionRoles[roleKey] = struct{}{}
		seenSessionActionValues[valueKey] = action
	}
	seenQuotaRoles := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.QuotaMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		if !productconfigs.VendorPackSupportsQuotaMapping(pack) {
			return fmt.Errorf("radius.vendor.quota_mappings[%d].pack %q does not support quota mappings", i, mapping.Pack)
		}
		if role == "" || len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.quota_mappings[%d].role is invalid", i)
		}
		if mapping.MaxTotalOctets < 1 || uint64(mapping.MaxTotalOctets) > uint64(^uint32(0)) {
			return fmt.Errorf("radius.vendor.quota_mappings[%d].max_total_octets %d is outside the uint32 range 1-4294967295", i, mapping.MaxTotalOctets)
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenQuotaRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.quota_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		seenQuotaRoles[roleKey] = struct{}{}
	}
	seenServiceNameRoles := map[string]struct{}{}
	for i, mapping := range c.Radius.Vendor.ServiceNameMappings {
		pack := productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack)
		role := strings.TrimSpace(mapping.Role)
		serviceName := strings.TrimSpace(mapping.ServiceName)
		if !productconfigs.VendorPackSupportsServiceNameMapping(pack) {
			return fmt.Errorf("radius.vendor.service_name_mappings[%d].pack %q does not support service name mappings", i, mapping.Pack)
		}
		if role == "" || len(role) > 253 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("radius.vendor.service_name_mappings[%d].role is invalid", i)
		}
		if serviceName == "" || len(serviceName) > 480 {
			return fmt.Errorf("radius.vendor.service_name_mappings[%d].service_name must contain between 1 and 480 decimal digits", i)
		}
		for _, digit := range serviceName {
			if digit < '0' || digit > '9' {
				return fmt.Errorf("radius.vendor.service_name_mappings[%d].service_name must contain only decimal digits", i)
			}
		}
		roleKey := pack + "\x00" + strings.ToLower(role)
		if _, exists := seenServiceNameRoles[roleKey]; exists {
			return fmt.Errorf("radius.vendor.service_name_mappings[%d] duplicates role %q for pack %q", i, role, pack)
		}
		seenServiceNameRoles[roleKey] = struct{}{}
	}
	seenVendorDictionaryPaths := map[string]struct{}{}
	for i, path := range c.Radius.Vendor.DictionaryPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			return fmt.Errorf("radius.vendor.dictionary_paths[%d] cannot be empty", i)
		}
		if strings.ContainsRune(path, 0) {
			return fmt.Errorf("radius.vendor.dictionary_paths[%d] contains an invalid NUL byte", i)
		}
		key := strings.ToLower(filepath.Clean(path))
		if _, exists := seenVendorDictionaryPaths[key]; exists {
			return fmt.Errorf("radius.vendor.dictionary_paths[%d] %q duplicates an earlier path", i, path)
		}
		seenVendorDictionaryPaths[key] = struct{}{}
	}
	if defaultEAPType := normalizeEAPMethod(c.Radius.EAP.DefaultType); defaultEAPType != "" && !validEAPMethod(defaultEAPType) {
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
	if c.Radius.EAP.CheckAllCRL && !c.Radius.EAP.CheckCRL {
		return errors.New("radius.eap.check_all_crl requires radius.eap.check_crl")
	}
	if c.Radius.EAP.CAPathReloadInterval < 0 {
		return fmt.Errorf("radius.eap.ca_path_reload_interval %d cannot be negative", c.Radius.EAP.CAPathReloadInterval)
	}
	if c.Radius.EAP.CheckCRL && c.Radius.EAP.CAPathReloadInterval < 1 {
		return errors.New("radius.eap.check_crl requires a positive radius.eap.ca_path_reload_interval")
	}
	if c.Radius.EAP.OCSP.TimeoutSeconds < 0 || c.Radius.EAP.OCSP.TimeoutSeconds > 60 {
		return fmt.Errorf("radius.eap.ocsp.timeout_seconds %d must be between 0 and 60", c.Radius.EAP.OCSP.TimeoutSeconds)
	}
	if c.Radius.EAP.OCSP.OverrideCertURL && !c.Radius.EAP.OCSP.Enabled {
		return errors.New("radius.eap.ocsp.override_cert_url requires radius.eap.ocsp.enabled")
	}
	if c.Radius.EAP.OCSP.OverrideCertURL && strings.TrimSpace(c.Radius.EAP.OCSP.URL) == "" {
		return errors.New("radius.eap.ocsp.override_cert_url requires radius.eap.ocsp.url")
	}
	if ocspURL := strings.TrimSpace(c.Radius.EAP.OCSP.URL); ocspURL != "" {
		if strings.ContainsAny(ocspURL, "\"\r\n") {
			return fmt.Errorf("radius.eap.ocsp.url %q contains invalid characters", c.Radius.EAP.OCSP.URL)
		}
		parsed, err := url.Parse(ocspURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("radius.eap.ocsp.url %q must be a valid http or https URL", c.Radius.EAP.OCSP.URL)
		}
	}
	if c.Onboarding.EAPTLSEnabled && !c.Radius.EAP.CheckCRL && !c.Radius.EAP.OCSP.Enabled {
		return errors.New("onboarding.eap_tls_enabled requires radius.eap.check_crl or radius.eap.ocsp.enabled")
	}
	if err := validateCertificateLifecycleConfig(c); err != nil {
		return err
	}
	if err := validateSupplicantLifecycleConfig(c); err != nil {
		return err
	}
	if err := validateRadiusEAPFramework(c.Radius.EAP); err != nil {
		return err
	}

	for i, cl := range c.Radius.Clients {
		if cl.IP == "" {
			return fmt.Errorf("radius.client[%d] missing ip", i)
		}
		transport := normalizeRadiusTransport(cl.Transport)
		if transport == "udp" && strings.TrimSpace(cl.Secret) == "" && strings.TrimSpace(cl.SecretRef) == "" {
			return fmt.Errorf("radius.client[%d] missing secret or secret_ref", i)
		}
		if err := validateRadiusClientTransport(i, cl, c.Radius.RadSec.Enabled); err != nil {
			return err
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

		if strings.TrimSpace(c.Radius.Upstream.Realm) == "" && len(c.Radius.Upstream.Routes) == 0 {
			return errors.New("radius.upstream.realm cannot be empty when upstream is enabled")
		}
		if strings.TrimSpace(c.Radius.Upstream.Realm) != "" && !validRadiusRealmName(c.Radius.Upstream.Realm) {
			return fmt.Errorf("radius.upstream.realm %q is invalid", c.Radius.Upstream.Realm)
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
			transport := normalizeRadiusTransport(server.Transport)
			if transport == "udp" && strings.TrimSpace(server.Secret) == "" && strings.TrimSpace(server.SecretRef) == "" {
				return fmt.Errorf("radius.upstream.server[%d] missing secret or secret_ref", i)
			}
			if server.AuthPort != 0 && (server.AuthPort < 1 || server.AuthPort > 65535) {
				return fmt.Errorf("radius.upstream.server[%d] auth_port %d out of range", i, server.AuthPort)
			}
			if server.AcctPort != 0 && (server.AcctPort < 1 || server.AcctPort > 65535) {
				return fmt.Errorf("radius.upstream.server[%d] acct_port %d out of range", i, server.AcctPort)
			}
			if err := validateRadSecPeer(i, server); err != nil {
				return err
			}
		}
		if err := validateRadiusProxyRoutes(c.Radius.Upstream, seenNames); err != nil {
			return err
		}
		if err := validateRadiusTransportPolicy(c.Radius.Upstream); err != nil {
			return err
		}
		if err := validateRadiusProxyPolicy(c.Radius.Upstream); err != nil {
			return err
		}
		if err := validateRadiusAccountingSpool(c.Radius.Upstream.AccountingSpool); err != nil {
			return err
		}
		if err := validateRadiusFallbackPolicy(c.Radius.Upstream.FallbackPolicy); err != nil {
			return err
		}
	}

	if err := validatePolicyEngineConfig(c.Policy); err != nil {
		return err
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
			if (ssid.AuthMode == "wpa2-enterprise" || ssid.AuthMode == "wpa3-enterprise") && strings.TrimSpace(c.Radius.Secret) == "" && strings.TrimSpace(c.Radius.SecretRef) == "" {
				return fmt.Errorf("wireless.ssids[%d] requires radius.secret or radius.secret_ref for %s", i, ssid.AuthMode)
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

func validateCertificateLifecycleConfig(c *Config) error {
	if c == nil {
		return nil
	}
	lifecycle := c.Onboarding.CertificateLifecycle
	mode := strings.ToLower(strings.TrimSpace(lifecycle.Mode))
	if mode == "" {
		mode = "monitor"
	}
	switch mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("onboarding.certificate_lifecycle.mode %q must be monitor or enforce", lifecycle.Mode)
	}
	rotation := strings.ToLower(strings.TrimSpace(lifecycle.IssuerRotationMode))
	if rotation == "" {
		rotation = "disabled"
	}
	switch rotation {
	case "disabled", "staged":
	default:
		return fmt.Errorf("onboarding.certificate_lifecycle.issuer_rotation_mode %q must be disabled or staged", lifecycle.IssuerRotationMode)
	}
	escrow := strings.ToLower(strings.TrimSpace(lifecycle.EscrowPolicy))
	if escrow == "" {
		escrow = "forbid"
	}
	switch escrow {
	case "forbid", "admin-approved", "allow":
	default:
		return fmt.Errorf("onboarding.certificate_lifecycle.escrow_policy %q must be forbid, admin-approved, or allow", lifecycle.EscrowPolicy)
	}
	if lifecycle.CertificateValidityDays < 0 || lifecycle.CertificateValidityDays > 825 {
		return fmt.Errorf("onboarding.certificate_lifecycle.certificate_validity_days must be between 0 and 825")
	}
	if lifecycle.MaxCertificateValidityDays < 0 || lifecycle.MaxCertificateValidityDays > 825 {
		return fmt.Errorf("onboarding.certificate_lifecycle.max_certificate_validity_days must be between 0 and 825")
	}
	if lifecycle.CertificateValidityDays > 0 && lifecycle.MaxCertificateValidityDays > 0 && lifecycle.CertificateValidityDays > lifecycle.MaxCertificateValidityDays {
		return fmt.Errorf("onboarding.certificate_lifecycle.certificate_validity_days cannot exceed max_certificate_validity_days")
	}
	if lifecycle.RenewalWindowDays < 0 || lifecycle.RenewalWindowDays > 365 {
		return fmt.Errorf("onboarding.certificate_lifecycle.renewal_window_days must be between 0 and 365")
	}
	if lifecycle.IssuerOverlapSeconds < 0 || lifecycle.IssuerOverlapSeconds > 31536000 {
		return fmt.Errorf("onboarding.certificate_lifecycle.issuer_overlap_seconds must be between 0 and 31536000")
	}
	if lifecycle.MinRSABits != 0 && (lifecycle.MinRSABits < 2048 || lifecycle.MinRSABits > 16384) {
		return fmt.Errorf("onboarding.certificate_lifecycle.min_rsa_bits must be between 2048 and 16384 when set")
	}
	if lifecycle.EventRetentionLimit != 0 && (lifecycle.EventRetentionLimit < 1 || lifecycle.EventRetentionLimit > 1000000) {
		return fmt.Errorf("onboarding.certificate_lifecycle.event_retention_limit must be between 1 and 1000000 when set")
	}
	if lifecycle.InventoryRetentionLimit != 0 && (lifecycle.InventoryRetentionLimit < 1 || lifecycle.InventoryRetentionLimit > 10000000) {
		return fmt.Errorf("onboarding.certificate_lifecycle.inventory_retention_limit must be between 1 and 10000000 when set")
	}
	if err := validateCertificateLifecycleNameList("onboarding.certificate_lifecycle.templates", lifecycle.Templates, false); err != nil {
		return err
	}
	if len(lifecycle.Templates) > 0 && strings.TrimSpace(lifecycle.DefaultTemplate) != "" && !certificateLifecycleListContains(lifecycle.Templates, lifecycle.DefaultTemplate) {
		return fmt.Errorf("onboarding.certificate_lifecycle.default_template %q is not in templates", lifecycle.DefaultTemplate)
	}
	if strings.TrimSpace(lifecycle.ActiveIssuer) != "" && !validCertificateLifecycleName(lifecycle.ActiveIssuer) {
		return fmt.Errorf("onboarding.certificate_lifecycle.active_issuer is invalid")
	}
	if strings.TrimSpace(lifecycle.StagedIssuer) != "" && !validCertificateLifecycleName(lifecycle.StagedIssuer) {
		return fmt.Errorf("onboarding.certificate_lifecycle.staged_issuer is invalid")
	}
	if rotation == "staged" {
		if strings.TrimSpace(lifecycle.StagedIssuer) == "" {
			return errors.New("onboarding.certificate_lifecycle.issuer_rotation_mode=staged requires staged_issuer")
		}
		if strings.EqualFold(strings.TrimSpace(lifecycle.ActiveIssuer), strings.TrimSpace(lifecycle.StagedIssuer)) {
			return errors.New("onboarding.certificate_lifecycle.staged_issuer must differ from active_issuer")
		}
		if lifecycle.IssuerOverlapSeconds == 0 {
			return errors.New("onboarding.certificate_lifecycle.issuer_rotation_mode=staged requires issuer_overlap_seconds")
		}
	}
	if err := validateCertificateLifecycleNameList("onboarding.certificate_lifecycle.allowed_key_types", lifecycle.AllowedKeyTypes, true); err != nil {
		return err
	}
	for i, value := range lifecycle.AllowedKeyTypes {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "", "rsa", "ecdsa", "ed25519":
		default:
			return fmt.Errorf("onboarding.certificate_lifecycle.allowed_key_types[%d] %q is invalid", i, value)
		}
	}
	if err := validateCertificateLifecycleNameList("onboarding.certificate_lifecycle.allowed_ecdsa_curves", lifecycle.AllowedECDSACurves, false); err != nil {
		return err
	}
	for i, value := range lifecycle.AllowedECDSACurves {
		switch strings.TrimSpace(value) {
		case "", "P-256", "P-384", "P-521":
		default:
			return fmt.Errorf("onboarding.certificate_lifecycle.allowed_ecdsa_curves[%d] %q is invalid", i, value)
		}
	}
	if lifecycle.AllowServerKeyGeneration && escrow == "forbid" {
		return errors.New("onboarding.certificate_lifecycle.allow_server_key_generation requires escrow_policy to be admin-approved or allow")
	}
	if strings.TrimSpace(lifecycle.OCSPResponderURL) != "" {
		if err := requireHTTPURL("onboarding.certificate_lifecycle.ocsp_responder_url", lifecycle.OCSPResponderURL); err != nil {
			return err
		}
	}
	if strings.ContainsRune(lifecycle.CRLPublishPath, 0) {
		return errors.New("onboarding.certificate_lifecycle.crl_publish_path contains an invalid NUL byte")
	}
	if lifecycle.Enabled {
		if EffectiveDeploymentProfile(c.Deployment.Profile) != "enterprise" {
			return errors.New("onboarding.certificate_lifecycle.enabled is only supported on the enterprise deployment profile")
		}
		if !c.Onboarding.CertificateEnrollmentEnabled {
			return errors.New("onboarding.certificate_lifecycle.enabled requires onboarding.certificate_enrollment_enabled")
		}
		if !c.Onboarding.EAPTLSEnabled {
			return errors.New("onboarding.certificate_lifecycle.enabled requires onboarding.eap_tls_enabled")
		}
		if !certificateAuthorityReady(c) {
			return errors.New("onboarding.certificate_lifecycle.enabled requires complete CA configuration")
		}
		if mode == "enforce" && lifecycle.FailClosed {
			if !lifecycle.RequireCSR && !lifecycle.AllowServerKeyGeneration {
				return errors.New("onboarding.certificate_lifecycle enforce fail-closed requires require_csr or allow_server_key_generation")
			}
			if !lifecycle.CRLEnabled && !lifecycle.OCSPEnabled && !c.Radius.EAP.CheckCRL && !c.Radius.EAP.OCSP.Enabled {
				return errors.New("onboarding.certificate_lifecycle enforce fail-closed requires CRL or OCSP")
			}
		}
		if !lifecycle.ESTEnabled && !lifecycle.SCEPEnabled && !lifecycle.BYODPortalEnabled {
			return errors.New("onboarding.certificate_lifecycle.enabled requires at least one enrollment entry point")
		}
	}
	return nil
}

func validateSupplicantLifecycleConfig(c *Config) error {
	if c == nil {
		return nil
	}
	lifecycle := c.Onboarding.SupplicantLifecycle
	mode := strings.ToLower(strings.TrimSpace(lifecycle.Mode))
	if mode == "" {
		mode = "monitor"
	}
	switch mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("onboarding.supplicant_lifecycle.mode %q must be monitor or enforce", lifecycle.Mode)
	}
	security := strings.ToLower(strings.TrimSpace(lifecycle.Security))
	if security == "" {
		security = "wpa2-enterprise"
	}
	switch security {
	case "wpa2-enterprise", "wpa3-enterprise":
	default:
		return fmt.Errorf("onboarding.supplicant_lifecycle.security %q must be wpa2-enterprise or wpa3-enterprise", lifecycle.Security)
	}
	if strings.TrimSpace(lifecycle.SSID) != "" && (len(lifecycle.SSID) > 32 || strings.ContainsAny(lifecycle.SSID, "\r\n\x00")) {
		return errors.New("onboarding.supplicant_lifecycle.ssid is invalid")
	}
	if err := validateCertificateLifecycleNameList("onboarding.supplicant_lifecycle.allowed_platforms", lifecycle.AllowedPlatforms, true); err != nil {
		return err
	}
	for i, platform := range lifecycle.AllowedPlatforms {
		switch strings.ToLower(strings.TrimSpace(platform)) {
		case "", "windows", "macos", "ios", "android", "linux":
		default:
			return fmt.Errorf("onboarding.supplicant_lifecycle.allowed_platforms[%d] %q is invalid", i, platform)
		}
	}
	if len(lifecycle.AllowedPlatforms) > 0 && strings.TrimSpace(lifecycle.DefaultPlatform) != "" && !certificateLifecycleListContains(lifecycle.AllowedPlatforms, lifecycle.DefaultPlatform) {
		return fmt.Errorf("onboarding.supplicant_lifecycle.default_platform %q is not in allowed_platforms", lifecycle.DefaultPlatform)
	}
	if err := validateCertificateLifecycleNameList("onboarding.supplicant_lifecycle.allowed_eap_methods", lifecycle.AllowedEAPMethods, true); err != nil {
		return err
	}
	for i, method := range lifecycle.AllowedEAPMethods {
		normalized := normalizeEAPMethod(method)
		switch normalized {
		case "tls", "peap", "ttls", "pwd", "fast", "teap":
		default:
			return fmt.Errorf("onboarding.supplicant_lifecycle.allowed_eap_methods[%d] %q is invalid", i, method)
		}
	}
	if len(lifecycle.AllowedEAPMethods) > 0 && strings.TrimSpace(lifecycle.DefaultEAPMethod) != "" && !certificateLifecycleListContains(lifecycle.AllowedEAPMethods, normalizeEAPMethod(lifecycle.DefaultEAPMethod)) {
		return fmt.Errorf("onboarding.supplicant_lifecycle.default_eap_method %q is not in allowed_eap_methods", lifecycle.DefaultEAPMethod)
	}
	if err := validateCertificateLifecycleNameList("onboarding.supplicant_lifecycle.allowed_inner_methods", lifecycle.AllowedInnerMethods, true); err != nil {
		return err
	}
	for i, method := range lifecycle.AllowedInnerMethods {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "", "mschapv2", "pap", "chap", "gtc", "tls":
		default:
			return fmt.Errorf("onboarding.supplicant_lifecycle.allowed_inner_methods[%d] %q is invalid", i, method)
		}
	}
	if len(lifecycle.AllowedInnerMethods) > 0 && strings.TrimSpace(lifecycle.DefaultInnerMethod) != "" && !certificateLifecycleListContains(lifecycle.AllowedInnerMethods, lifecycle.DefaultInnerMethod) {
		return fmt.Errorf("onboarding.supplicant_lifecycle.default_inner_method %q is not in allowed_inner_methods", lifecycle.DefaultInnerMethod)
	}
	if strings.TrimSpace(lifecycle.AnonymousIdentity) != "" && (len(lifecycle.AnonymousIdentity) > 253 || strings.ContainsAny(lifecycle.AnonymousIdentity, "\r\n\x00")) {
		return errors.New("onboarding.supplicant_lifecycle.anonymous_identity is invalid")
	}
	if strings.TrimSpace(lifecycle.DomainSuffix) != "" && !validDomainLabelList(lifecycle.DomainSuffix) {
		return errors.New("onboarding.supplicant_lifecycle.domain_suffix is invalid")
	}
	if err := validateSupplicantHostnameList("onboarding.supplicant_lifecycle.server_names", lifecycle.ServerNames); err != nil {
		return err
	}
	if err := validateSupplicantPinList("onboarding.supplicant_lifecycle.trust_anchor_pins", lifecycle.TrustAnchorPins); err != nil {
		return err
	}
	if err := validateCertificateLifecycleNameList("onboarding.supplicant_lifecycle.password_change_providers", lifecycle.PasswordChangeProviders, true); err != nil {
		return err
	}
	if err := validateCertificateLifecycleNameList("onboarding.supplicant_lifecycle.compatible_verifiers", lifecycle.CompatibleVerifiers, true); err != nil {
		return err
	}
	if lifecycle.PasswordChangeURL != "" {
		if err := requireHTTPURL("onboarding.supplicant_lifecycle.password_change_url", lifecycle.PasswordChangeURL); err != nil {
			return err
		}
	}
	if lifecycle.MaxPasswordAgeDays < 0 || lifecycle.MaxPasswordAgeDays > 3660 {
		return errors.New("onboarding.supplicant_lifecycle.max_password_age_days must be between 0 and 3660")
	}
	if lifecycle.ExpiryWarningDays < 0 || lifecycle.ExpiryWarningDays > 365 {
		return errors.New("onboarding.supplicant_lifecycle.expiry_warning_days must be between 0 and 365")
	}
	if lifecycle.GracePeriodDays < 0 || lifecycle.GracePeriodDays > 365 {
		return errors.New("onboarding.supplicant_lifecycle.grace_period_days must be between 0 and 365")
	}
	if lifecycle.MinPasswordLength < 0 || lifecycle.MinPasswordLength > 256 {
		return errors.New("onboarding.supplicant_lifecycle.min_password_length must be between 0 and 256")
	}
	if lifecycle.ProfileValidityDays != 0 && (lifecycle.ProfileValidityDays < 1 || lifecycle.ProfileValidityDays > 1095) {
		return errors.New("onboarding.supplicant_lifecycle.profile_validity_days must be between 1 and 1095 when set")
	}
	if lifecycle.DeliveryTokenTTLSeconds < 0 || lifecycle.DeliveryTokenTTLSeconds > 86400 {
		return errors.New("onboarding.supplicant_lifecycle.delivery_token_ttl_seconds must be between 0 and 86400")
	}
	if lifecycle.EventRetentionLimit != 0 && (lifecycle.EventRetentionLimit < 1 || lifecycle.EventRetentionLimit > 1000000) {
		return errors.New("onboarding.supplicant_lifecycle.event_retention_limit must be between 1 and 1000000 when set")
	}
	if lifecycle.ProfileRetentionLimit != 0 && (lifecycle.ProfileRetentionLimit < 1 || lifecycle.ProfileRetentionLimit > 10000000) {
		return errors.New("onboarding.supplicant_lifecycle.profile_retention_limit must be between 1 and 10000000 when set")
	}
	if strings.TrimSpace(lifecycle.ProfileSigningKeyRef) != "" && !validSecretRefShape(lifecycle.ProfileSigningKeyRef) {
		return errors.New("onboarding.supplicant_lifecycle.profile_signing_key_ref must use env:NAME or file:PATH")
	}
	if lifecycle.Enabled {
		if EffectiveDeploymentProfile(c.Deployment.Profile) != "enterprise" {
			return errors.New("onboarding.supplicant_lifecycle.enabled is only supported on the enterprise deployment profile")
		}
		if !c.Onboarding.PortalEnabled {
			return errors.New("onboarding.supplicant_lifecycle.enabled requires onboarding.portal_enabled")
		}
		if !c.Radius.EAP.Framework.Enabled {
			return errors.New("onboarding.supplicant_lifecycle.enabled requires radius.eap.framework.enabled")
		}
		if certificateLifecycleListContains(lifecycle.AllowedEAPMethods, "tls") && !c.Onboarding.CertificateLifecycle.Enabled {
			return errors.New("onboarding.supplicant_lifecycle TLS profiles require onboarding.certificate_lifecycle.enabled")
		}
		if lifecycle.RequireTrustAnchorPinning && len(lifecycle.TrustAnchorPins) == 0 {
			return errors.New("onboarding.supplicant_lifecycle.require_trust_anchor_pinning requires trust_anchor_pins")
		}
		if lifecycle.RequireTrustAnchorPinning && len(lifecycle.ServerNames) == 0 {
			return errors.New("onboarding.supplicant_lifecycle.require_trust_anchor_pinning requires server_names")
		}
		if lifecycle.AllowPasswordChange && len(lifecycle.PasswordChangeProviders) == 0 {
			return errors.New("onboarding.supplicant_lifecycle.allow_password_change requires password_change_providers")
		}
		if mode == "enforce" && lifecycle.FailClosed {
			if lifecycle.RequireTLSForDelivery == false {
				return errors.New("onboarding.supplicant_lifecycle enforce fail-closed requires require_tls_for_delivery")
			}
			if lifecycle.RequireSignedProfiles && strings.TrimSpace(lifecycle.ProfileSigningKeyRef) == "" {
				return errors.New("onboarding.supplicant_lifecycle enforce fail-closed requires profile_signing_key_ref")
			}
			if lifecycle.RequireVerifierCompatibility && len(lifecycle.CompatibleVerifiers) == 0 {
				return errors.New("onboarding.supplicant_lifecycle enforce fail-closed requires compatible_verifiers")
			}
			if lifecycle.RequireAnonymousIdentity && strings.TrimSpace(lifecycle.AnonymousIdentity) == "" {
				return errors.New("onboarding.supplicant_lifecycle enforce fail-closed requires anonymous_identity")
			}
		}
	}
	return nil
}

func validateSupplicantHostnameList(field string, values []string) error {
	seen := map[string]struct{}{}
	for i, value := range values {
		value = strings.TrimSpace(strings.TrimSuffix(value, "."))
		if value == "" {
			return fmt.Errorf("%s[%d] cannot be empty", field, i)
		}
		if !validDomainLabelList(value) {
			return fmt.Errorf("%s[%d] is invalid", field, i)
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier value", field, i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateSupplicantPinList(field string, values []string) error {
	seen := map[string]struct{}{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		lower := strings.ToLower(value)
		lower = strings.TrimPrefix(lower, "sha256:")
		if len(lower) != 64 {
			return fmt.Errorf("%s[%d] must be a SHA-256 hex fingerprint", field, i)
		}
		for _, r := range lower {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
				continue
			}
			return fmt.Errorf("%s[%d] must be a SHA-256 hex fingerprint", field, i)
		}
		if _, exists := seen[lower]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier value", field, i)
		}
		seen[lower] = struct{}{}
	}
	return nil
}

func validSecretRefShape(value string) bool {
	value = strings.TrimSpace(value)
	provider, target, ok := strings.Cut(value, ":")
	if !ok || strings.TrimSpace(provider) == "" || strings.TrimSpace(target) == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "env":
		for i, r := range target {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' {
				continue
			}
			if i > 0 && r >= '0' && r <= '9' {
				continue
			}
			return false
		}
		return true
	case "file":
		return !strings.ContainsAny(target, "\r\n\x00")
	default:
		return false
	}
}

func validateCertificateLifecycleNameList(field string, values []string, lower bool) error {
	seen := map[string]struct{}{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s[%d] cannot be empty", field, i)
		}
		if lower {
			value = strings.ToLower(value)
		}
		if !validCertificateLifecycleName(value) {
			return fmt.Errorf("%s[%d] is invalid", field, i)
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier value", field, i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validCertificateLifecycleName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '.', '_', '-', ':', '@':
			continue
		default:
			return false
		}
	}
	return true
}

func certificateLifecycleListContains(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
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
	controller := c.Integrations.Controller
	if strings.TrimSpace(controller.Platform) == "" || strings.TrimSpace(controller.Endpoint) == "" || strings.TrimSpace(controller.SyncMode) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(controller.Platform), "cisco") || strings.EqualFold(strings.TrimSpace(controller.Platform), "ruckus") || strings.EqualFold(strings.TrimSpace(controller.Platform), "mikrotik") {
		return strings.TrimSpace(controller.APIUsernameEnv) != "" && strings.TrimSpace(controller.APIPasswordEnv) != ""
	}
	return strings.TrimSpace(controller.APITokenEnv) != ""
}

func controllerPlatformRequiresSite(platform string) bool {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "", "generic":
		return false
	default:
		return true
	}
}

func controllerHasEnterpriseSSIDs(c *Config) bool {
	if c == nil {
		return false
	}
	for _, ssid := range c.Wireless.SSIDs {
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise", "wpa3-enterprise":
			return true
		}
	}
	return false
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

func validateSecretProviderConfig(cfg SecretProviderConfig) error {
	providers := cfg.Providers
	if len(providers) == 0 {
		providers = []string{"env", "file"}
	}
	seen := map[string]struct{}{}
	for i, provider := range providers {
		normalized := strings.ToLower(strings.TrimSpace(provider))
		switch normalized {
		case "env", "file":
		default:
			return fmt.Errorf("security.secrets.providers[%d] %q is not supported", i, provider)
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("security.secrets.providers[%d] %q duplicates an earlier provider", i, provider)
		}
		seen[normalized] = struct{}{}
	}
	if cfg.MaxSecretBytes < 0 {
		return fmt.Errorf("security.secrets.max_secret_bytes %d cannot be negative", cfg.MaxSecretBytes)
	}
	if cfg.MaxSecretBytes > 1024*1024 {
		return fmt.Errorf("security.secrets.max_secret_bytes %d exceeds 1048576", cfg.MaxSecretBytes)
	}
	if strings.ContainsAny(cfg.FileBaseDir, "\r\n\x00") {
		return errors.New("security.secrets.file_base_dir contains invalid characters")
	}
	return nil
}

func validateDatabaseConfig(cfg DatabaseConfig) error {
	backend := strings.ToLower(strings.TrimSpace(cfg.Backend))
	if backend == "" {
		backend = "sqlite"
	}
	switch backend {
	case "sqlite":
		if strings.TrimSpace(cfg.Path) == "" {
			return errors.New("database.path cannot be empty")
		}
		if strings.TrimSpace(cfg.DSN) != "" {
			return errors.New("database.dsn is only valid when database.backend is postgres")
		}
		if strings.TrimSpace(cfg.DSNRef) != "" {
			return errors.New("database.dsn_ref is only valid when database.backend is postgres")
		}
	case "postgres", "postgresql":
		if strings.TrimSpace(cfg.DSN) == "" && strings.TrimSpace(cfg.DSNRef) == "" {
			return errors.New("database.dsn_ref or database.dsn is required when database.backend is postgres")
		}
		if strings.TrimSpace(cfg.DSN) != "" && strings.TrimSpace(cfg.DSNRef) != "" {
			return errors.New("database.dsn and database.dsn_ref cannot both be set")
		}
		if strings.TrimSpace(cfg.DSN) != "" && !cfg.AllowInlinePostgreSQLDSN {
			return errors.New("database.dsn contains inline connection material; use database.dsn_ref or set database.allow_inline_postgresql_dsn for a controlled lab")
		}
		if strings.TrimSpace(cfg.DSNRef) != "" {
			if err := validateSecretRefField("database.dsn_ref", cfg.DSNRef); err != nil {
				return err
			}
		}
		sslMode := strings.ToLower(strings.TrimSpace(cfg.SSLMode))
		switch sslMode {
		case "", "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("database.sslmode %q is invalid", cfg.SSLMode)
		}
		if cfg.ProductionRequireTLS && !cfg.AllowUnsafePostgreSQLSSLMode {
			switch sslMode {
			case "require", "verify-ca", "verify-full":
			default:
				return fmt.Errorf("database.sslmode %q is not allowed when database.production_require_tls is true", cfg.SSLMode)
			}
		}
	default:
		return fmt.Errorf("database.backend %q is invalid", cfg.Backend)
	}
	if cfg.MaxOpenConns < 0 {
		return fmt.Errorf("database.max_open_conns %d cannot be negative", cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns < 0 {
		return fmt.Errorf("database.max_idle_conns %d cannot be negative", cfg.MaxIdleConns)
	}
	if cfg.MaxOpenConns > 0 && cfg.MaxIdleConns > cfg.MaxOpenConns {
		return errors.New("database.max_idle_conns cannot exceed database.max_open_conns")
	}
	if cfg.ConnMaxLifetimeSeconds < 0 {
		return fmt.Errorf("database.conn_max_lifetime_seconds %d cannot be negative", cfg.ConnMaxLifetimeSeconds)
	}
	if cfg.ConnMaxIdleTimeSeconds < 0 {
		return fmt.Errorf("database.conn_max_idle_time_seconds %d cannot be negative", cfg.ConnMaxIdleTimeSeconds)
	}
	if cfg.ConnectTimeoutSeconds < 0 {
		return fmt.Errorf("database.connect_timeout_seconds %d cannot be negative", cfg.ConnectTimeoutSeconds)
	}
	if cfg.StatementTimeoutMilliseconds < 0 {
		return fmt.Errorf("database.statement_timeout_milliseconds %d cannot be negative", cfg.StatementTimeoutMilliseconds)
	}
	if cfg.MigrationLockTimeoutSeconds < 0 {
		return fmt.Errorf("database.migration_lock_timeout_seconds %d cannot be negative", cfg.MigrationLockTimeoutSeconds)
	}
	return nil
}

func validateConfiguredSecretReferences(c *Config) error {
	if c == nil {
		return nil
	}
	if err := validateSecretPair("radius.secret", c.Radius.Secret, "radius.secret_ref", c.Radius.SecretRef); err != nil {
		return err
	}
	if ref := strings.TrimSpace(EffectiveMFAConfig(c.MFA).OTP.SealingKeyRef); ref != "" {
		if err := validateSecretRefField("mfa.otp.sealing_key_ref", ref); err != nil {
			return err
		}
	}
	if ref := strings.TrimSpace(c.Radius.DynamicClients.EnrollmentTokenRef); ref != "" {
		if err := validateSecretRefField("radius.dynamic_clients.enrollment_token_ref", ref); err != nil {
			return err
		}
	}
	for i, client := range c.Radius.Clients {
		if err := validateSecretPair(fmt.Sprintf("radius.clients[%d].secret", i), client.Secret, fmt.Sprintf("radius.clients[%d].secret_ref", i), client.SecretRef); err != nil {
			return err
		}
	}
	for i, server := range c.Radius.Upstream.Servers {
		if err := validateSecretPair(fmt.Sprintf("radius.upstream.servers[%d].secret", i), server.Secret, fmt.Sprintf("radius.upstream.servers[%d].secret_ref", i), server.SecretRef); err != nil {
			return err
		}
		if ref := strings.TrimSpace(server.RadSec.PSK.SecretRef); ref != "" {
			if err := validateSecretRefField(fmt.Sprintf("radius.upstream.servers[%d].radsec.psk.secret_ref", i), ref); err != nil {
				return err
			}
		}
		if ref := strings.TrimSpace(server.RadSec.PSK.NextSecretRef); ref != "" {
			if err := validateSecretRefField(fmt.Sprintf("radius.upstream.servers[%d].radsec.psk.next_secret_ref", i), ref); err != nil {
				return err
			}
		}
	}
	if err := validateSecretPair("active_directory.bind_password", c.ActiveDirectory.BindPassword, "active_directory.bind_password_ref", c.ActiveDirectory.BindPasswordRef); err != nil {
		return err
	}
	return validateSecretPair("ldap.bind_password", c.LDAP.BindPassword, "ldap.bind_password_ref", c.LDAP.BindPasswordRef)
}

func validateSecretPair(inlineField, inlineValue, refField, refValue string) error {
	inlineValue = strings.TrimSpace(inlineValue)
	refValue = strings.TrimSpace(refValue)
	if inlineValue != "" && refValue != "" {
		return fmt.Errorf("%s and %s cannot both be set", inlineField, refField)
	}
	if refValue == "" {
		return nil
	}
	return validateSecretRefField(refField, refValue)
}

func validateSecretRefField(fieldName, raw string) error {
	scheme, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok || strings.TrimSpace(scheme) == "" || strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must use env:NAME or file:NAME", fieldName)
	}
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "env":
		if !validSecretEnvName(value) {
			return fmt.Errorf("%s has invalid environment variable name %q", fieldName, value)
		}
	case "file":
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s has invalid file secret path", fieldName)
		}
	default:
		return fmt.Errorf("%s uses unsupported secret provider %q", fieldName, scheme)
	}
	return nil
}

func validSecretEnvName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
		if i == 0 && r >= '0' && r <= '9' {
			return false
		}
	}
	return true
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

func validRadiusRealmName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 {
		return false
	}
	upper := strings.ToUpper(value)
	if upper == "DEFAULT" || upper == "NULL" {
		return true
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
		if i == 0 && (r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validateRadiusProxyRoutes(upstream RadiusUpstreamConfig, serverNames map[string]struct{}) error {
	if len(upstream.Routes) == 0 {
		return nil
	}

	enabledRoutes := 0
	defaultRoutes := 0
	routeNames := make(map[string]struct{}, len(upstream.Routes))
	matchRealms := make(map[string]string)

	for i, route := range upstream.Routes {
		if !route.Enabled {
			continue
		}
		enabledRoutes++
		name := strings.TrimSpace(route.Name)
		if name == "" {
			return fmt.Errorf("radius.upstream.routes[%d] missing name", i)
		}
		if !validRadiusDictionaryName(name) {
			return fmt.Errorf("radius.upstream.routes[%d].name %q is invalid", i, route.Name)
		}
		if _, exists := routeNames[name]; exists {
			return fmt.Errorf("radius.upstream.routes[%d] duplicate name %q", i, name)
		}
		routeNames[name] = struct{}{}

		realm := strings.TrimSpace(route.Realm)
		if realm == "" {
			return fmt.Errorf("radius.upstream.routes[%d].realm cannot be empty", i)
		}
		if !validRadiusRealmName(realm) {
			return fmt.Errorf("radius.upstream.routes[%d].realm %q is invalid", i, route.Realm)
		}

		poolStrategy := strings.TrimSpace(route.PoolStrategy)
		if poolStrategy == "" {
			poolStrategy = upstream.PoolStrategy
		}
		switch poolStrategy {
		case "fail-over", "load-balance", "client-balance", "client-port-balance", "keyed-balance":
		default:
			return fmt.Errorf("radius.upstream.routes[%d].pool_strategy %q is invalid", i, route.PoolStrategy)
		}

		statusCheck := strings.TrimSpace(route.StatusCheck)
		if statusCheck == "" {
			statusCheck = upstream.StatusCheck
		}
		switch statusCheck {
		case "status-server", "none":
		default:
			return fmt.Errorf("radius.upstream.routes[%d].status_check %q is invalid", i, route.StatusCheck)
		}

		if len(route.Servers) == 0 {
			return fmt.Errorf("radius.upstream.routes[%d].servers requires at least one upstream server name", i)
		}
		seenRouteServers := make(map[string]struct{}, len(route.Servers))
		for serverIndex, serverName := range route.Servers {
			name := strings.TrimSpace(serverName)
			if name == "" {
				return fmt.Errorf("radius.upstream.routes[%d].servers[%d] cannot be empty", i, serverIndex)
			}
			if _, duplicate := seenRouteServers[name]; duplicate {
				return fmt.Errorf("radius.upstream.routes[%d].servers[%d] duplicate server %q", i, serverIndex, name)
			}
			seenRouteServers[name] = struct{}{}
			if _, exists := serverNames[name]; !exists {
				return fmt.Errorf("radius.upstream.routes[%d].servers[%d] references unknown upstream server %q", i, serverIndex, name)
			}
		}

		if route.Default {
			defaultRoutes++
			if defaultRoutes > 1 {
				return errors.New("radius.upstream.routes allows only one enabled default route")
			}
		}

		for _, matchRealm := range append([]string{realm}, route.MatchRealms...) {
			matchRealm = strings.TrimSpace(matchRealm)
			if matchRealm == "" {
				continue
			}
			if !validRadiusRealmName(matchRealm) {
				return fmt.Errorf("radius.upstream.routes[%d].match_realms contains invalid realm %q", i, matchRealm)
			}
			key := strings.ToLower(matchRealm)
			if owner, exists := matchRealms[key]; exists && owner != name {
				return fmt.Errorf("radius.upstream.routes[%d].match_realms realm %q is already claimed by route %q", i, matchRealm, owner)
			}
			matchRealms[key] = name
		}
	}

	if enabledRoutes == 0 {
		return errors.New("radius.upstream.routes requires at least one enabled route when configured")
	}
	return nil
}

func validatePolicyEngineConfig(policy PolicyConfig) error {
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" {
		mode = "monitor"
	}
	if mode != "monitor" && mode != "enforce" {
		return fmt.Errorf("policy.mode %q must be monitor or enforce", policy.Mode)
	}
	if policy.MaxExpressionDepth < 0 || policy.MaxExpressionDepth > 16 {
		return fmt.Errorf("policy.max_expression_depth must be between 1 and 16 when set")
	}
	if policy.MaxExpressionNodes < 0 || policy.MaxExpressionNodes > 1024 {
		return fmt.Errorf("policy.max_expression_nodes must be between 1 and 1024 when set")
	}
	if policy.MaxListValues < 0 || policy.MaxListValues > 1024 {
		return fmt.Errorf("policy.max_list_values must be between 1 and 1024 when set")
	}
	if policy.EvaluationRetentionLimit < 0 || policy.EvaluationRetentionLimit > 1000000 {
		return fmt.Errorf("policy.evaluation_retention_limit must be between 100 and 1000000 when set")
	}
	if policy.TypedEngineEnabled {
		if policy.MaxExpressionDepth == 0 || policy.MaxExpressionNodes == 0 || policy.MaxListValues == 0 {
			return errors.New("policy.typed_engine_enabled requires positive max_expression_depth, max_expression_nodes, and max_list_values")
		}
		if policy.AuditEnabled && policy.EvaluationRetentionLimit > 0 && policy.EvaluationRetentionLimit < 100 {
			return fmt.Errorf("policy.evaluation_retention_limit must be between 100 and 1000000")
		}
		if policy.RequireTypedRules && policy.AllowLegacyConditions {
			return errors.New("policy.require_typed_rules cannot be combined with policy.allow_legacy_conditions")
		}
	}
	return nil
}

func validateRadiusTransportPolicy(upstream RadiusUpstreamConfig) error {
	policy := upstream.TransportPolicy
	if !policy.Enabled && strings.TrimSpace(policy.Mode) == "" && strings.TrimSpace(policy.DefaultRequiredTransport) == "" &&
		!policy.FailClosed && !policy.AllowMixedTransports && len(policy.RoutePolicies) == 0 {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	if mode == "" {
		mode = "monitor"
	}
	switch mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("radius.upstream.transport_policy.mode %q must be monitor or enforce", policy.Mode)
	}
	required := strings.ToLower(strings.TrimSpace(policy.DefaultRequiredTransport))
	if required == "" {
		required = "any"
	}
	if !validUpstreamRequiredTransport(required) {
		return fmt.Errorf("radius.upstream.transport_policy.default_required_transport %q must be any, udp, or radsec", policy.DefaultRequiredTransport)
	}
	routeNames := map[string]struct{}{}
	if len(upstream.Routes) == 0 {
		routeNames["legacy-default"] = struct{}{}
	} else {
		for _, route := range upstream.Routes {
			if route.Enabled {
				routeNames[strings.TrimSpace(route.Name)] = struct{}{}
			}
		}
	}
	seen := map[string]struct{}{}
	for i, routePolicy := range policy.RoutePolicies {
		routeName := strings.TrimSpace(routePolicy.Route)
		if routeName == "" {
			return fmt.Errorf("radius.upstream.transport_policy.route_policies[%d].route cannot be empty", i)
		}
		if _, ok := routeNames[routeName]; !ok {
			return fmt.Errorf("radius.upstream.transport_policy.route_policies[%d].route %q does not match an enabled proxy route", i, routePolicy.Route)
		}
		key := strings.ToLower(routeName)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("radius.upstream.transport_policy.route_policies[%d] duplicates an earlier route policy", i)
		}
		seen[key] = struct{}{}
		requiredTransport := strings.ToLower(strings.TrimSpace(routePolicy.RequiredTransport))
		if requiredTransport == "" {
			requiredTransport = required
		}
		if !validUpstreamRequiredTransport(requiredTransport) {
			return fmt.Errorf("radius.upstream.transport_policy.route_policies[%d].required_transport %q must be any, udp, or radsec", i, routePolicy.RequiredTransport)
		}
		if strings.ContainsAny(routePolicy.Description, "\r\n\x00") || len(routePolicy.Description) > 240 {
			return fmt.Errorf("radius.upstream.transport_policy.route_policies[%d].description is invalid", i)
		}
	}
	return nil
}

func validUpstreamRequiredTransport(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "any", "udp", "radsec":
		return true
	default:
		return false
	}
}

func validateRadiusProxyPolicy(upstream RadiusUpstreamConfig) error {
	policy := upstream.ProxyPolicy
	if !policy.Enabled && len(policy.RoutePolicies) == 0 && strings.TrimSpace(policy.DefaultAction) == "" &&
		strings.TrimSpace(policy.LoopMarker) == "" && policy.MaxHops == 0 {
		return nil
	}
	defaultAction := strings.ToLower(strings.TrimSpace(policy.DefaultAction))
	if defaultAction == "" {
		defaultAction = "drop"
	}
	switch defaultAction {
	case "drop", "reject":
	default:
		return fmt.Errorf("radius.upstream.proxy_policy.default_action %q must be drop or reject", policy.DefaultAction)
	}
	marker := strings.TrimSpace(policy.LoopMarker)
	if marker == "" {
		marker = "aegisnas"
	}
	if !validProxyPolicyToken(marker) {
		return fmt.Errorf("radius.upstream.proxy_policy.loop_marker %q is invalid", policy.LoopMarker)
	}
	if policy.MaxHops < 0 || policy.MaxHops > 32 {
		return fmt.Errorf("radius.upstream.proxy_policy.max_hops must be between 1 and 32 when set")
	}

	routeNames := map[string]struct{}{}
	if len(upstream.Routes) == 0 {
		routeNames["legacy-default"] = struct{}{}
	} else {
		for _, route := range upstream.Routes {
			if route.Enabled {
				routeNames[strings.TrimSpace(route.Name)] = struct{}{}
			}
		}
	}
	seen := map[string]struct{}{}
	for i, routePolicy := range policy.RoutePolicies {
		routeName := strings.TrimSpace(routePolicy.Route)
		if routeName == "" {
			return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].route cannot be empty", i)
		}
		if _, ok := routeNames[routeName]; !ok {
			return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].route %q does not match an enabled proxy route", i, routePolicy.Route)
		}
		direction := strings.ToLower(strings.TrimSpace(routePolicy.Direction))
		if direction == "" {
			direction = "any"
		}
		switch direction {
		case "any", "proxy_request", "proxy_response":
		default:
			return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].direction %q is invalid", i, routePolicy.Direction)
		}
		key := strings.ToLower(routeName) + "\x00" + direction
		if _, exists := seen[key]; exists {
			return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d] duplicates an earlier route/direction policy", i)
		}
		seen[key] = struct{}{}
		if strings.ContainsAny(routePolicy.Description, "\r\n\x00") || len(routePolicy.Description) > 240 {
			return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].description is invalid", i)
		}
		for realmIndex, realm := range routePolicy.TrustedSourceRealms {
			if !validRadiusRealmName(realm) {
				return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].trusted_source_realms[%d] %q is invalid", i, realmIndex, realm)
			}
		}
		if err := validateProxyStandardAttributes(routePolicy.AllowStandard, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].allow_standard", i)); err != nil {
			return err
		}
		if err := validateProxyStandardAttributes(routePolicy.DenyStandard, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].deny_standard", i)); err != nil {
			return err
		}
		if err := validateProxyVendorIDs(routePolicy.AllowVendorIDs, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].allow_vendor_ids", i)); err != nil {
			return err
		}
		if err := validateProxyVendorIDs(routePolicy.DenyVendorIDs, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].deny_vendor_ids", i)); err != nil {
			return err
		}
		if err := validateProxyVendorSelectors(routePolicy.AllowVendorAttributes, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].allow_vendor_attributes", i)); err != nil {
			return err
		}
		if err := validateProxyVendorSelectors(routePolicy.DenyVendorAttributes, fmt.Sprintf("radius.upstream.proxy_policy.route_policies[%d].deny_vendor_attributes", i)); err != nil {
			return err
		}
		for rewriteIndex, rewrite := range routePolicy.RewriteRules {
			if err := validateProxyRewriteRule(rewrite); err != nil {
				return fmt.Errorf("radius.upstream.proxy_policy.route_policies[%d].rewrite_rules[%d]: %w", i, rewriteIndex, err)
			}
		}
	}
	return nil
}

func EffectiveRadiusAccountingSpoolConfig(raw RadiusAccountingSpoolConfig) RadiusAccountingSpoolConfig {
	effective := raw
	if effective.MaxQueueRecords == 0 {
		effective.MaxQueueRecords = 10000
	}
	if effective.MaxAttempts == 0 {
		effective.MaxAttempts = 10
	}
	if effective.InitialRetrySeconds == 0 {
		effective.InitialRetrySeconds = 30
	}
	if effective.MaxRetrySeconds == 0 {
		effective.MaxRetrySeconds = 3600
	}
	if effective.RecordTTLSeconds == 0 {
		effective.RecordTTLSeconds = 604800
	}
	if effective.ReplayIntervalSeconds == 0 {
		effective.ReplayIntervalSeconds = 60
	}
	if effective.BatchSize == 0 {
		effective.BatchSize = 100
	}
	if effective.LockSeconds == 0 {
		effective.LockSeconds = 120
	}
	if effective.SentRetentionSeconds == 0 {
		effective.SentRetentionSeconds = 604800
	}
	if effective.PoisonRetentionSeconds == 0 {
		effective.PoisonRetentionSeconds = 2592000
	}
	return effective
}

func validateRadiusAccountingSpool(raw RadiusAccountingSpoolConfig) error {
	values := map[string]int{
		"max_queue_records":        raw.MaxQueueRecords,
		"max_attempts":             raw.MaxAttempts,
		"initial_retry_seconds":    raw.InitialRetrySeconds,
		"max_retry_seconds":        raw.MaxRetrySeconds,
		"record_ttl_seconds":       raw.RecordTTLSeconds,
		"replay_interval_seconds":  raw.ReplayIntervalSeconds,
		"batch_size":               raw.BatchSize,
		"lock_seconds":             raw.LockSeconds,
		"sent_retention_seconds":   raw.SentRetentionSeconds,
		"poison_retention_seconds": raw.PoisonRetentionSeconds,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("radius.upstream.accounting_spool.%s %d cannot be negative", name, value)
		}
	}
	if !raw.Enabled {
		return nil
	}
	effective := EffectiveRadiusAccountingSpoolConfig(raw)
	if effective.MaxQueueRecords < 1 || effective.MaxQueueRecords > 1000000 {
		return fmt.Errorf("radius.upstream.accounting_spool.max_queue_records must be between 1 and 1000000")
	}
	if effective.MaxAttempts < 1 || effective.MaxAttempts > 1000 {
		return fmt.Errorf("radius.upstream.accounting_spool.max_attempts must be between 1 and 1000")
	}
	if effective.InitialRetrySeconds < 1 {
		return fmt.Errorf("radius.upstream.accounting_spool.initial_retry_seconds must be positive")
	}
	if effective.MaxRetrySeconds < effective.InitialRetrySeconds {
		return fmt.Errorf("radius.upstream.accounting_spool.max_retry_seconds must be greater than or equal to initial_retry_seconds")
	}
	if effective.RecordTTLSeconds < effective.MaxRetrySeconds {
		return fmt.Errorf("radius.upstream.accounting_spool.record_ttl_seconds must be greater than or equal to max_retry_seconds")
	}
	if effective.ReplayIntervalSeconds < 1 {
		return fmt.Errorf("radius.upstream.accounting_spool.replay_interval_seconds must be positive")
	}
	if effective.BatchSize < 1 || effective.BatchSize > effective.MaxQueueRecords {
		return fmt.Errorf("radius.upstream.accounting_spool.batch_size must be between 1 and max_queue_records")
	}
	if effective.LockSeconds < 1 {
		return fmt.Errorf("radius.upstream.accounting_spool.lock_seconds must be positive")
	}
	if effective.SentRetentionSeconds < 1 {
		return fmt.Errorf("radius.upstream.accounting_spool.sent_retention_seconds must be positive")
	}
	if effective.PoisonRetentionSeconds < 1 {
		return fmt.Errorf("radius.upstream.accounting_spool.poison_retention_seconds must be positive")
	}
	return nil
}

func EffectiveRadiusFallbackPolicyConfig(raw RadiusFallbackPolicyConfig) RadiusFallbackPolicyConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if effective.MaxOutageSeconds == 0 {
		effective.MaxOutageSeconds = 900
	}
	if effective.StalePolicySeconds == 0 {
		effective.StalePolicySeconds = 3600
	}
	if effective.RecoverySuccesses == 0 {
		effective.RecoverySuccesses = 2
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	return effective
}

func EffectiveIdentityFailoverConfig(raw IdentityFailoverConfig) IdentityFailoverConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if len(effective.SourceOrder) == 0 {
		effective.SourceOrder = []string{"local", "ldap-primary"}
	}
	if effective.MaxFailures == 0 {
		effective.MaxFailures = 3
	}
	if effective.CircuitOpenSeconds == 0 {
		effective.CircuitOpenSeconds = 300
	}
	if effective.StaleCacheSeconds == 0 {
		effective.StaleCacheSeconds = 3600
	}
	if strings.TrimSpace(effective.SplitResultPolicy) == "" {
		effective.SplitResultPolicy = "deny"
	}
	if effective.HealthCheckIntervalSeconds == 0 {
		effective.HealthCheckIntervalSeconds = 60
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	return effective
}

func validateIdentityFailover(raw IdentityFailoverConfig) error {
	values := map[string]int{
		"max_failures":                  raw.MaxFailures,
		"circuit_open_seconds":          raw.CircuitOpenSeconds,
		"stale_cache_seconds":           raw.StaleCacheSeconds,
		"health_check_interval_seconds": raw.HealthCheckIntervalSeconds,
		"retention_limit":               raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("identity.failover.%s %d cannot be negative", name, value)
		}
	}
	effective := EffectiveIdentityFailoverConfig(raw)
	switch strings.ToLower(strings.TrimSpace(effective.Mode)) {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("identity.failover.mode %q must be monitor or enforce", raw.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(effective.SplitResultPolicy)) {
	case "deny", "prefer_first", "prefer_success":
	default:
		return fmt.Errorf("identity.failover.split_result_policy %q must be deny, prefer_first, or prefer_success", raw.SplitResultPolicy)
	}
	seenSources := map[string]struct{}{}
	for i, source := range effective.SourceOrder {
		normalized := strings.ToLower(strings.TrimSpace(source))
		if normalized == "" {
			return fmt.Errorf("identity.failover.source_order[%d] cannot be empty", i)
		}
		if strings.ContainsAny(normalized, "\r\n\x00") {
			return fmt.Errorf("identity.failover.source_order[%d] is invalid", i)
		}
		if _, exists := seenSources[normalized]; exists {
			return fmt.Errorf("identity.failover.source_order[%d] %q duplicates an earlier source", i, source)
		}
		seenSources[normalized] = struct{}{}
	}
	if raw.Enabled {
		if effective.MaxFailures < 1 || effective.MaxFailures > 100 {
			return errors.New("identity.failover.max_failures must be between 1 and 100")
		}
		if effective.CircuitOpenSeconds < 5 || effective.CircuitOpenSeconds > 86400 {
			return errors.New("identity.failover.circuit_open_seconds must be between 5 and 86400")
		}
		if effective.StaleCacheSeconds < 60 || effective.StaleCacheSeconds > 2592000 {
			return errors.New("identity.failover.stale_cache_seconds must be between 60 and 2592000")
		}
		if effective.HealthCheckIntervalSeconds < 5 || effective.HealthCheckIntervalSeconds > 3600 {
			return errors.New("identity.failover.health_check_interval_seconds must be between 5 and 3600")
		}
		if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
			return errors.New("identity.failover.retention_limit must be between 100 and 1000000")
		}
	}
	return nil
}

func EffectiveActiveDirectoryConfig(raw ActiveDirectoryConfig) ActiveDirectoryConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if strings.TrimSpace(effective.AuthMethod) == "" {
		effective.AuthMethod = "ldap_bind"
	}
	if strings.TrimSpace(effective.UserFilter) == "" {
		effective.UserFilter = "(|(userPrincipalName=%p)(sAMAccountName=%u))"
	}
	if strings.TrimSpace(effective.GroupFilter) == "" {
		if effective.NestedGroups || !raw.Enabled {
			effective.GroupFilter = "(|(member=%D)(member:1.2.840.113556.1.4.1941:=%D))"
		} else {
			effective.GroupFilter = "(member=%D)"
		}
	}
	if effective.RequestTimeoutSeconds == 0 {
		effective.RequestTimeoutSeconds = 5
	}
	if effective.GroupCacheTTLSeconds == 0 {
		effective.GroupCacheTTLSeconds = 3600
	}
	if effective.HealthCheckIntervalSeconds == 0 {
		effective.HealthCheckIntervalSeconds = 60
	}
	if effective.ClockSkewSeconds == 0 {
		effective.ClockSkewSeconds = 300
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	if strings.TrimSpace(effective.Kerberos.KinitPath) == "" {
		effective.Kerberos.KinitPath = "kinit"
	}
	if strings.TrimSpace(effective.Kerberos.KDestroyPath) == "" {
		effective.Kerberos.KDestroyPath = "kdestroy"
	}
	if strings.TrimSpace(effective.Winbind.WbinfoPath) == "" {
		effective.Winbind.WbinfoPath = "wbinfo"
	}
	if strings.TrimSpace(effective.Winbind.NTLMAuthPath) == "" {
		effective.Winbind.NTLMAuthPath = "/usr/bin/ntlm_auth"
	}
	if effective.GroupRoleMappings == nil {
		effective.GroupRoleMappings = map[string]string{}
	}
	return effective
}

func validateActiveDirectory(raw ActiveDirectoryConfig) error {
	effective := EffectiveActiveDirectoryConfig(raw)
	switch strings.ToLower(strings.TrimSpace(effective.Mode)) {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("active_directory.mode %q must be monitor or enforce", raw.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(effective.AuthMethod)) {
	case "ldap_bind", "kerberos", "winbind_helper":
	default:
		return fmt.Errorf("active_directory.auth_method %q must be ldap_bind, kerberos, or winbind_helper", raw.AuthMethod)
	}
	values := map[string]int{
		"request_timeout_seconds":       raw.RequestTimeoutSeconds,
		"group_cache_ttl_seconds":       raw.GroupCacheTTLSeconds,
		"health_check_interval_seconds": raw.HealthCheckIntervalSeconds,
		"clock_skew_seconds":            raw.ClockSkewSeconds,
		"retention_limit":               raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("active_directory.%s %d cannot be negative", name, value)
		}
	}
	if !raw.Enabled {
		return validateActiveDirectoryTextFields(effective)
	}
	if strings.TrimSpace(effective.Domain) == "" {
		return errors.New("active_directory.enabled requires active_directory.domain")
	}
	if strings.TrimSpace(effective.Realm) == "" {
		return errors.New("active_directory.enabled requires active_directory.realm")
	}
	if strings.TrimSpace(effective.LDAPURL) == "" {
		return errors.New("active_directory.enabled requires active_directory.ldap_url")
	}
	if err := requireLDAPURL("active_directory.ldap_url", effective.LDAPURL, effective.RequireLDAPS); err != nil {
		return err
	}
	if strings.TrimSpace(effective.BaseDN) == "" {
		return errors.New("active_directory.enabled requires active_directory.base_dn")
	}
	if strings.TrimSpace(effective.BindDN) != "" && strings.TrimSpace(effective.BindPassword) == "" && strings.TrimSpace(effective.BindPasswordRef) == "" {
		return errors.New("active_directory.bind_dn requires bind_password or bind_password_ref")
	}
	if effective.RequestTimeoutSeconds < 1 || effective.RequestTimeoutSeconds > 60 {
		return errors.New("active_directory.request_timeout_seconds must be between 1 and 60")
	}
	if effective.GroupCacheTTLSeconds < 60 || effective.GroupCacheTTLSeconds > 2592000 {
		return errors.New("active_directory.group_cache_ttl_seconds must be between 60 and 2592000")
	}
	if effective.HealthCheckIntervalSeconds < 5 || effective.HealthCheckIntervalSeconds > 3600 {
		return errors.New("active_directory.health_check_interval_seconds must be between 5 and 3600")
	}
	if effective.ClockSkewSeconds < 30 || effective.ClockSkewSeconds > 3600 {
		return errors.New("active_directory.clock_skew_seconds must be between 30 and 3600")
	}
	if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
		return errors.New("active_directory.retention_limit must be between 100 and 1000000")
	}
	if strings.EqualFold(effective.AuthMethod, "kerberos") && !effective.Kerberos.Enabled {
		return errors.New("active_directory.auth_method kerberos requires active_directory.kerberos.enabled")
	}
	if strings.EqualFold(effective.AuthMethod, "winbind_helper") {
		if !effective.Winbind.Enabled {
			return errors.New("active_directory.auth_method winbind_helper requires active_directory.winbind.enabled")
		}
		if strings.TrimSpace(effective.Winbind.AuthHelperPath) == "" {
			return errors.New("active_directory.auth_method winbind_helper requires active_directory.winbind.auth_helper_path")
		}
	}
	return validateActiveDirectoryTextFields(effective)
}

func validateActiveDirectoryTextFields(effective ActiveDirectoryConfig) error {
	textFields := map[string]string{
		"active_directory.domain":                        effective.Domain,
		"active_directory.realm":                         effective.Realm,
		"active_directory.netbios_domain":                effective.NetBIOSDomain,
		"active_directory.base_dn":                       effective.BaseDN,
		"active_directory.bind_dn":                       effective.BindDN,
		"active_directory.user_filter":                   effective.UserFilter,
		"active_directory.group_filter":                  effective.GroupFilter,
		"active_directory.default_role":                  effective.DefaultRole,
		"active_directory.kerberos.kinit_path":           effective.Kerberos.KinitPath,
		"active_directory.kerberos.kdestroy_path":        effective.Kerberos.KDestroyPath,
		"active_directory.kerberos.krb5_config_path":     effective.Kerberos.Krb5ConfigPath,
		"active_directory.kerberos.keytab_path":          effective.Kerberos.KeytabPath,
		"active_directory.kerberos.service_principal":    effective.Kerberos.ServicePrincipal,
		"active_directory.kerberos.credential_cache_dir": effective.Kerberos.CredentialCacheDir,
		"active_directory.winbind.wbinfo_path":           effective.Winbind.WbinfoPath,
		"active_directory.winbind.ntlm_auth_path":        effective.Winbind.NTLMAuthPath,
		"active_directory.winbind.auth_helper_path":      effective.Winbind.AuthHelperPath,
	}
	for name, value := range textFields {
		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if !strings.Contains(effective.UserFilter, "%s") && !strings.Contains(effective.UserFilter, "%u") && !strings.Contains(effective.UserFilter, "%p") {
		return errors.New("active_directory.user_filter must contain %s, %u, or %p")
	}
	if strings.Count(effective.GroupFilter, "%D") == 0 && strings.Count(effective.GroupFilter, "%s") == 0 {
		return errors.New("active_directory.group_filter must contain %D or %s")
	}
	if err := validateSecretPair("active_directory.bind_password", effective.BindPassword, "active_directory.bind_password_ref", effective.BindPasswordRef); err != nil {
		return err
	}
	for group, role := range effective.GroupRoleMappings {
		group = strings.TrimSpace(group)
		role = strings.TrimSpace(role)
		if group == "" || len(group) > 256 || strings.ContainsAny(group, "\r\n\x00") {
			return errors.New("active_directory.group_role_mappings contains an invalid group")
		}
		if role == "" || len(role) > 128 || strings.ContainsAny(role, "\r\n\x00") {
			return errors.New("active_directory.group_role_mappings contains an invalid role")
		}
	}
	return nil
}

func requireLDAPURL(field, raw string, requireLDAPS bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%s must be an ldap:// or ldaps:// URL", field)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return fmt.Errorf("%s must use ldap:// or ldaps://", field)
	}
	if requireLDAPS && scheme != "ldaps" {
		return fmt.Errorf("%s must use ldaps:// when require_ldaps is true", field)
	}
	return nil
}

func EffectiveMFAConfig(raw MFAConfig) MFAConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if strings.TrimSpace(effective.OTP.Issuer) == "" {
		effective.OTP.Issuer = "AegisNAS"
	}
	if strings.TrimSpace(effective.OTP.Algorithm) == "" {
		effective.OTP.Algorithm = "SHA1"
	}
	if effective.OTP.Digits == 0 {
		effective.OTP.Digits = 6
	}
	if effective.OTP.PeriodSeconds == 0 {
		effective.OTP.PeriodSeconds = 30
	}
	if effective.OTP.WindowSteps == 0 {
		effective.OTP.WindowSteps = 1
	}
	if effective.OTP.MaxAttempts == 0 {
		effective.OTP.MaxAttempts = 5
	}
	if strings.TrimSpace(effective.OTP.SealingKeyRef) == "" {
		effective.OTP.SealingKeyRef = "env:AEGIS_MFA_SEALING_KEY"
	}
	if len(effective.OTP.StepUpRoles) == 0 {
		effective.OTP.StepUpRoles = []string{"admin", "super_admin", "ops_admin"}
	}
	if effective.RadiusChallenge.TTLSeconds == 0 {
		effective.RadiusChallenge.TTLSeconds = 300
	}
	if effective.RadiusChallenge.MaxPending == 0 {
		effective.RadiusChallenge.MaxPending = 10000
	}
	if strings.TrimSpace(effective.RadiusChallenge.Prompt) == "" {
		effective.RadiusChallenge.Prompt = "Enter one-time password"
	}
	if effective.RadiusChallenge.StateBytes == 0 {
		effective.RadiusChallenge.StateBytes = 32
	}
	if effective.Recovery.CodeCount == 0 {
		effective.Recovery.CodeCount = 10
	}
	if effective.Recovery.CodeBytes == 0 {
		effective.Recovery.CodeBytes = 16
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	return effective
}

func validateMFA(raw MFAConfig) error {
	effective := EffectiveMFAConfig(raw)
	switch strings.ToLower(strings.TrimSpace(effective.Mode)) {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("mfa.mode %q must be monitor or enforce", raw.Mode)
	}
	values := map[string]int{
		"otp.digits":                   raw.OTP.Digits,
		"otp.period_seconds":           raw.OTP.PeriodSeconds,
		"otp.window_steps":             raw.OTP.WindowSteps,
		"otp.max_attempts":             raw.OTP.MaxAttempts,
		"radius_challenge.ttl_seconds": raw.RadiusChallenge.TTLSeconds,
		"radius_challenge.max_pending": raw.RadiusChallenge.MaxPending,
		"radius_challenge.state_bytes": raw.RadiusChallenge.StateBytes,
		"recovery.code_count":          raw.Recovery.CodeCount,
		"recovery.code_bytes":          raw.Recovery.CodeBytes,
		"recovery.code_ttl_seconds":    raw.Recovery.CodeTTLSeconds,
		"retention_limit":              raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("mfa.%s %d cannot be negative", name, value)
		}
	}
	switch strings.ToUpper(strings.TrimSpace(effective.OTP.Algorithm)) {
	case "SHA1", "SHA256", "SHA512":
	default:
		return fmt.Errorf("mfa.otp.algorithm %q must be SHA1, SHA256, or SHA512", effective.OTP.Algorithm)
	}
	if effective.OTP.Digits != 6 && effective.OTP.Digits != 8 {
		return errors.New("mfa.otp.digits must be 6 or 8")
	}
	if effective.OTP.PeriodSeconds < 15 || effective.OTP.PeriodSeconds > 300 {
		return errors.New("mfa.otp.period_seconds must be between 15 and 300")
	}
	if effective.OTP.WindowSteps < 0 || effective.OTP.WindowSteps > 10 {
		return errors.New("mfa.otp.window_steps must be between 0 and 10")
	}
	if effective.OTP.MaxAttempts < 1 || effective.OTP.MaxAttempts > 20 {
		return errors.New("mfa.otp.max_attempts must be between 1 and 20")
	}
	if err := validateSecretRefField("mfa.otp.sealing_key_ref", effective.OTP.SealingKeyRef); err != nil {
		return err
	}
	if len(strings.TrimSpace(effective.OTP.Issuer)) > 64 || strings.ContainsAny(effective.OTP.Issuer, "\r\n\x00") {
		return errors.New("mfa.otp.issuer is invalid")
	}
	for i, role := range effective.OTP.StepUpRoles {
		if !validMFAToken(role) {
			return fmt.Errorf("mfa.otp.step_up_roles[%d] is invalid", i)
		}
	}
	for i, realm := range effective.OTP.StepUpRealms {
		realm = strings.TrimSpace(realm)
		if realm == "" {
			return fmt.Errorf("mfa.otp.step_up_realms[%d] cannot be empty", i)
		}
		if realm != "*" && !validRadiusRealmName(realm) {
			return fmt.Errorf("mfa.otp.step_up_realms[%d] %q is invalid", i, realm)
		}
	}
	if effective.RadiusChallenge.TTLSeconds < 30 || effective.RadiusChallenge.TTLSeconds > 3600 {
		return errors.New("mfa.radius_challenge.ttl_seconds must be between 30 and 3600")
	}
	if effective.RadiusChallenge.MaxPending < 1 || effective.RadiusChallenge.MaxPending > 1000000 {
		return errors.New("mfa.radius_challenge.max_pending must be between 1 and 1000000")
	}
	if effective.RadiusChallenge.StateBytes < 16 || effective.RadiusChallenge.StateBytes > 128 {
		return errors.New("mfa.radius_challenge.state_bytes must be between 16 and 128")
	}
	if len(strings.TrimSpace(effective.RadiusChallenge.Prompt)) > 160 || strings.ContainsAny(effective.RadiusChallenge.Prompt, "\r\n\x00") {
		return errors.New("mfa.radius_challenge.prompt is invalid")
	}
	if effective.Recovery.CodeCount < 1 || effective.Recovery.CodeCount > 50 {
		return errors.New("mfa.recovery.code_count must be between 1 and 50")
	}
	if effective.Recovery.CodeBytes < 8 || effective.Recovery.CodeBytes > 64 {
		return errors.New("mfa.recovery.code_bytes must be between 8 and 64")
	}
	if effective.Recovery.CodeTTLSeconds < 0 || effective.Recovery.CodeTTLSeconds > 31536000 {
		return errors.New("mfa.recovery.code_ttl_seconds must be between 0 and 31536000")
	}
	if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
		return errors.New("mfa.retention_limit must be between 100 and 1000000")
	}
	return nil
}

func EffectiveAdminWebAuthnConfig(raw AdminWebAuthnConfig) AdminWebAuthnConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if strings.TrimSpace(effective.RPName) == "" {
		effective.RPName = "AegisNAS Admin"
	}
	if effective.ChallengeTTLSeconds == 0 {
		effective.ChallengeTTLSeconds = 300
	}
	if effective.SessionTTLSeconds == 0 {
		effective.SessionTTLSeconds = 28800
	}
	if effective.MaxPending == 0 {
		effective.MaxPending = 10000
	}
	if strings.TrimSpace(effective.UserVerification) == "" {
		effective.UserVerification = "preferred"
	}
	if strings.TrimSpace(effective.Attestation) == "" {
		effective.Attestation = "none"
	}
	if strings.TrimSpace(effective.ResidentKey) == "" {
		effective.ResidentKey = "preferred"
	}
	if len(effective.RequireForRoles) == 0 {
		effective.RequireForRoles = []string{"super_admin", "ops_admin"}
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	return effective
}

func validateAdminWebAuthn(raw AdminWebAuthnConfig) error {
	effective := EffectiveAdminWebAuthnConfig(raw)
	switch strings.ToLower(strings.TrimSpace(effective.Mode)) {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("admin_webauthn.mode %q must be monitor or enforce", raw.Mode)
	}
	if len(strings.TrimSpace(effective.RPName)) > 64 || strings.ContainsAny(effective.RPName, "\r\n\x00") {
		return errors.New("admin_webauthn.rp_name is invalid")
	}
	rpID := strings.TrimSpace(effective.RPID)
	if rpID != "" && !validWebAuthnRPID(rpID) {
		return fmt.Errorf("admin_webauthn.rp_id %q is invalid", rpID)
	}
	seenOrigins := map[string]struct{}{}
	for i, origin := range effective.Origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			return fmt.Errorf("admin_webauthn.origins[%d] cannot be empty", i)
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("admin_webauthn.origins[%d] %q must be an origin without path, query, or fragment", i, origin)
		}
		if parsed.Scheme != "https" && !isLocalWebAuthnOrigin(parsed) {
			return fmt.Errorf("admin_webauthn.origins[%d] %q must use https outside localhost", i, origin)
		}
		key := strings.ToLower(origin)
		if _, ok := seenOrigins[key]; ok {
			return fmt.Errorf("admin_webauthn.origins[%d] duplicates another origin", i)
		}
		seenOrigins[key] = struct{}{}
	}
	values := map[string]int{
		"challenge_ttl_seconds": raw.ChallengeTTLSeconds,
		"session_ttl_seconds":   raw.SessionTTLSeconds,
		"max_pending":           raw.MaxPending,
		"retention_limit":       raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("admin_webauthn.%s %d cannot be negative", name, value)
		}
	}
	if effective.ChallengeTTLSeconds < 30 || effective.ChallengeTTLSeconds > 3600 {
		return errors.New("admin_webauthn.challenge_ttl_seconds must be between 30 and 3600")
	}
	if effective.SessionTTLSeconds < 300 || effective.SessionTTLSeconds > 86400 {
		return errors.New("admin_webauthn.session_ttl_seconds must be between 300 and 86400")
	}
	if effective.MaxPending < 1 || effective.MaxPending > 1000000 {
		return errors.New("admin_webauthn.max_pending must be between 1 and 1000000")
	}
	if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
		return errors.New("admin_webauthn.retention_limit must be between 100 and 1000000")
	}
	switch strings.ToLower(strings.TrimSpace(effective.UserVerification)) {
	case "required", "preferred", "discouraged":
	default:
		return fmt.Errorf("admin_webauthn.user_verification %q must be required, preferred, or discouraged", effective.UserVerification)
	}
	switch strings.ToLower(strings.TrimSpace(effective.Attestation)) {
	case "none", "direct", "enterprise":
	default:
		return fmt.Errorf("admin_webauthn.attestation %q must be none, direct, or enterprise", effective.Attestation)
	}
	switch strings.ToLower(strings.TrimSpace(effective.ResidentKey)) {
	case "required", "preferred", "discouraged":
	default:
		return fmt.Errorf("admin_webauthn.resident_key %q must be required, preferred, or discouraged", effective.ResidentKey)
	}
	for i, role := range effective.RequireForRoles {
		role = strings.TrimSpace(role)
		if !validMFAToken(role) {
			return fmt.Errorf("admin_webauthn.require_for_roles[%d] is invalid", i)
		}
	}
	return nil
}

func validWebAuthnRPID(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@\r\n\x00") {
		return false
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func isLocalWebAuthnOrigin(parsed *url.URL) bool {
	host := strings.ToLower(parsed.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func EffectiveMABConfig(raw MABConfig) MABConfig {
	effective := raw
	if strings.TrimSpace(effective.Mode) == "" {
		effective.Mode = "monitor"
	}
	if strings.TrimSpace(effective.UnknownEndpointPolicy) == "" {
		effective.UnknownEndpointPolicy = "deny"
	}
	if strings.TrimSpace(effective.GuestRole) == "" {
		effective.GuestRole = "guest"
	}
	if strings.TrimSpace(effective.QuarantineRole) == "" {
		effective.QuarantineRole = "quarantine"
	}
	if len(effective.AllowedNASPortTypes) == 0 {
		effective.AllowedNASPortTypes = []string{"ethernet", "wireless-802.11", "wireless80211"}
	}
	if len(effective.MACFormats) == 0 {
		effective.MACFormats = []string{"colon", "hyphen", "plain", "cisco-dot"}
	}
	if strings.TrimSpace(effective.PasswordPolicy) == "" {
		effective.PasswordPolicy = "accept_known_mac"
	}
	if effective.RevalidateIntervalSeconds == 0 {
		effective.RevalidateIntervalSeconds = 300
	}
	if effective.CacheTTLSeconds == 0 {
		effective.CacheTTLSeconds = 300
	}
	if effective.RetentionLimit == 0 {
		effective.RetentionLimit = 6000
	}
	return effective
}

func validateMAB(raw MABConfig) error {
	effective := EffectiveMABConfig(raw)
	switch strings.ToLower(strings.TrimSpace(effective.Mode)) {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("mab.mode %q must be monitor or enforce", raw.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(effective.UnknownEndpointPolicy)) {
	case "deny", "guest", "quarantine", "fail_open":
	default:
		return fmt.Errorf("mab.unknown_endpoint_policy %q must be deny, guest, quarantine, or fail_open", raw.UnknownEndpointPolicy)
	}
	switch strings.ToLower(strings.TrimSpace(effective.PasswordPolicy)) {
	case "accept_known_mac", "username_equals_password", "calling_station_id":
	default:
		return fmt.Errorf("mab.password_policy %q must be accept_known_mac, username_equals_password, or calling_station_id", raw.PasswordPolicy)
	}
	values := map[string]int{
		"revalidate_interval_seconds": raw.RevalidateIntervalSeconds,
		"cache_ttl_seconds":           raw.CacheTTLSeconds,
		"retention_limit":             raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("mab.%s %d cannot be negative", name, value)
		}
	}
	if effective.RevalidateIntervalSeconds < 30 || effective.RevalidateIntervalSeconds > 86400 {
		return errors.New("mab.revalidate_interval_seconds must be between 30 and 86400")
	}
	if effective.CacheTTLSeconds < 30 || effective.CacheTTLSeconds > 86400 {
		return errors.New("mab.cache_ttl_seconds must be between 30 and 86400")
	}
	if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
		return errors.New("mab.retention_limit must be between 100 and 1000000")
	}
	roleFields := map[string]string{
		"mab.default_role":    effective.DefaultRole,
		"mab.guest_role":      effective.GuestRole,
		"mab.quarantine_role": effective.QuarantineRole,
	}
	for field, role := range roleFields {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if len(role) > 128 || strings.ContainsAny(role, "\r\n\x00") {
			return fmt.Errorf("%s is invalid", field)
		}
	}
	if effective.Enabled {
		if strings.EqualFold(effective.UnknownEndpointPolicy, "guest") && strings.TrimSpace(effective.GuestRole) == "" {
			return errors.New("mab.unknown_endpoint_policy guest requires mab.guest_role")
		}
		if strings.EqualFold(effective.UnknownEndpointPolicy, "quarantine") && strings.TrimSpace(effective.QuarantineRole) == "" {
			return errors.New("mab.unknown_endpoint_policy quarantine requires mab.quarantine_role")
		}
	}
	seenPortTypes := map[string]struct{}{}
	for i, item := range effective.AllowedNASPortTypes {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			return fmt.Errorf("mab.allowed_nas_port_types[%d] cannot be empty", i)
		}
		if len(normalized) > 64 || strings.ContainsAny(normalized, "\r\n\x00") {
			return fmt.Errorf("mab.allowed_nas_port_types[%d] is invalid", i)
		}
		if _, exists := seenPortTypes[normalized]; exists {
			return fmt.Errorf("mab.allowed_nas_port_types[%d] %q duplicates an earlier value", i, item)
		}
		seenPortTypes[normalized] = struct{}{}
	}
	seenFormats := map[string]struct{}{}
	for i, item := range effective.MACFormats {
		normalized := strings.ToLower(strings.TrimSpace(item))
		switch normalized {
		case "colon", "hyphen", "plain", "cisco-dot":
		default:
			return fmt.Errorf("mab.mac_formats[%d] %q must be colon, hyphen, plain, or cisco-dot", i, item)
		}
		if _, exists := seenFormats[normalized]; exists {
			return fmt.Errorf("mab.mac_formats[%d] %q duplicates an earlier value", i, item)
		}
		seenFormats[normalized] = struct{}{}
	}
	return nil
}

func validMFAToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func validateRadiusFallbackPolicy(raw RadiusFallbackPolicyConfig) error {
	values := map[string]int{
		"max_outage_seconds":   raw.MaxOutageSeconds,
		"stale_policy_seconds": raw.StalePolicySeconds,
		"recovery_successes":   raw.RecoverySuccesses,
		"retention_limit":      raw.RetentionLimit,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("radius.upstream.fallback_policy.%s %d cannot be negative", name, value)
		}
	}
	effective := EffectiveRadiusFallbackPolicyConfig(raw)
	mode := strings.ToLower(strings.TrimSpace(effective.Mode))
	switch mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("radius.upstream.fallback_policy.mode %q must be monitor or enforce", raw.Mode)
	}
	if raw.Enabled {
		if effective.MaxOutageSeconds < 60 || effective.MaxOutageSeconds > 86400 {
			return fmt.Errorf("radius.upstream.fallback_policy.max_outage_seconds must be between 60 and 86400")
		}
		if effective.StalePolicySeconds < effective.MaxOutageSeconds {
			return fmt.Errorf("radius.upstream.fallback_policy.stale_policy_seconds must be greater than or equal to max_outage_seconds")
		}
		if effective.RecoverySuccesses < 1 || effective.RecoverySuccesses > 10 {
			return fmt.Errorf("radius.upstream.fallback_policy.recovery_successes must be between 1 and 10")
		}
		if effective.RetentionLimit < 100 || effective.RetentionLimit > 1000000 {
			return fmt.Errorf("radius.upstream.fallback_policy.retention_limit must be between 100 and 1000000")
		}
	}
	for i, value := range raw.AllowedUsers {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("radius.upstream.fallback_policy.allowed_users[%d] cannot be empty", i)
		}
	}
	for i, value := range raw.AllowedRealms {
		realm := strings.TrimSpace(value)
		if realm == "" {
			return fmt.Errorf("radius.upstream.fallback_policy.allowed_realms[%d] cannot be empty", i)
		}
		if realm != "*" && !validRadiusRealmName(realm) {
			return fmt.Errorf("radius.upstream.fallback_policy.allowed_realms[%d] %q is invalid", i, value)
		}
	}
	for i, value := range raw.AllowedRoles {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("radius.upstream.fallback_policy.allowed_roles[%d] cannot be empty", i)
		}
	}
	return nil
}

func EffectiveRadiusDynamicClientsConfig(raw RadiusDynamicClientsConfig) RadiusDynamicClientsConfig {
	effective := raw
	if effective.EnrollmentTTLSeconds == 0 {
		effective.EnrollmentTTLSeconds = 86400
	}
	if effective.MaxPending == 0 {
		effective.MaxPending = 256
	}
	if strings.TrimSpace(effective.DefaultNASType) == "" {
		effective.DefaultNASType = "other"
	}
	if strings.TrimSpace(effective.DefaultTransport) == "" {
		effective.DefaultTransport = "udp"
	}
	if strings.TrimSpace(effective.DefaultTemplate) == "" {
		effective.DefaultTemplate = "default"
	}
	return effective
}

func validateRadiusDynamicClients(raw RadiusDynamicClientsConfig) error {
	effective := EffectiveRadiusDynamicClientsConfig(raw)
	if raw.EnrollmentTTLSeconds < 0 {
		return fmt.Errorf("radius.dynamic_clients.enrollment_ttl_seconds cannot be negative")
	}
	if raw.MaxPending < 0 {
		return fmt.Errorf("radius.dynamic_clients.max_pending cannot be negative")
	}
	if effective.EnrollmentTTLSeconds < 60 || effective.EnrollmentTTLSeconds > 2592000 {
		return fmt.Errorf("radius.dynamic_clients.enrollment_ttl_seconds must be between 60 and 2592000")
	}
	if effective.MaxPending < 1 || effective.MaxPending > 100000 {
		return fmt.Errorf("radius.dynamic_clients.max_pending must be between 1 and 100000")
	}
	if !validRadiusClientToken(effective.DefaultNASType) {
		return fmt.Errorf("radius.dynamic_clients.default_nas_type %q is invalid", effective.DefaultNASType)
	}
	switch strings.ToLower(strings.TrimSpace(effective.DefaultTransport)) {
	case "udp", "radsec":
	default:
		return fmt.Errorf("radius.dynamic_clients.default_transport %q must be udp or radsec", effective.DefaultTransport)
	}
	if !validRadiusClientToken(effective.DefaultTemplate) {
		return fmt.Errorf("radius.dynamic_clients.default_template %q is invalid", effective.DefaultTemplate)
	}
	for i, cidr := range raw.DiscoveryAllowedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			return fmt.Errorf("radius.dynamic_clients.discovery_allowed_cidrs[%d] cannot be empty", i)
		}
		if net.ParseIP(cidr) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("radius.dynamic_clients.discovery_allowed_cidrs[%d] %q must be an IP address or CIDR", i, cidr)
		}
	}
	return nil
}

func validRadiusClientToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func validateProxyStandardAttributes(values []string, path string) error {
	seen := map[string]struct{}{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%s[%d] cannot be empty", path, i)
		}
		if _, err := strconv.Atoi(value); err == nil {
			number, _ := strconv.Atoi(value)
			if number < 1 || number > 255 {
				return fmt.Errorf("%s[%d] numeric type must be between 1 and 255", path, i)
			}
		} else if !validFreeRADIUSAttributeName(value) {
			return fmt.Errorf("%s[%d] %q is not a valid RADIUS attribute name or type", path, i, value)
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier attribute", path, i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateProxyVendorIDs(values []int, path string) error {
	seen := map[int]struct{}{}
	for i, value := range values {
		if value < 1 {
			return fmt.Errorf("%s[%d] must be positive", path, i)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier vendor ID", path, i)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateProxyVendorSelectors(values []RadiusProxyVendorAttributeSelector, path string) error {
	seen := map[string]struct{}{}
	for i, value := range values {
		if value.VendorID < 1 {
			return fmt.Errorf("%s[%d].vendor_id must be positive", path, i)
		}
		if value.Type < 1 {
			return fmt.Errorf("%s[%d].type must be positive", path, i)
		}
		if strings.TrimSpace(value.Name) != "" && !validFreeRADIUSAttributeName(value.Name) {
			return fmt.Errorf("%s[%d].name %q is invalid", path, i, value.Name)
		}
		if strings.ContainsAny(value.Description, "\r\n\x00") || len(value.Description) > 240 {
			return fmt.Errorf("%s[%d].description is invalid", path, i)
		}
		key := fmt.Sprintf("%d/%d", value.VendorID, value.Type)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%s[%d] duplicates an earlier vendor attribute", path, i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateProxyRewriteRule(rule RadiusProxyRewriteRuleConfig) error {
	attribute := strings.TrimSpace(rule.Attribute)
	if attribute == "" {
		attribute = "User-Name"
	}
	if !strings.EqualFold(attribute, "User-Name") && attribute != "1" {
		return fmt.Errorf("attribute must be User-Name")
	}
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	switch action {
	case "strip_realm_from_user_name":
		if strings.TrimSpace(rule.Replacement) != "" {
			return fmt.Errorf("strip_realm_from_user_name must not set replacement")
		}
	case "replace_realm":
		if !validRadiusRealmName(rule.MatchRealm) {
			return fmt.Errorf("replace_realm requires a valid match_realm")
		}
		if !validRadiusRealmName(rule.Replacement) {
			return fmt.Errorf("replace_realm requires a valid replacement realm")
		}
	default:
		return fmt.Errorf("action %q is invalid", rule.Action)
	}
	if strings.TrimSpace(rule.MatchRealm) != "" && !validRadiusRealmName(rule.MatchRealm) {
		return fmt.Errorf("match_realm %q is invalid", rule.MatchRealm)
	}
	if strings.ContainsAny(rule.Description, "\r\n\x00") || len(rule.Description) > 240 {
		return fmt.Errorf("description is invalid")
	}
	return nil
}

func validFreeRADIUSAttributeName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

func validProxyPolicyToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func validateRadiusVendorIdentity(vendor RadiusVendorConfig) error {
	if !vendor.Enabled && vendor.ID == 0 && strings.TrimSpace(vendor.IdentityMode) == "" &&
		strings.TrimSpace(vendor.AssignedOrganization) == "" && len(vendor.LegacyIDs) == 0 {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(vendor.IdentityMode))
	if mode == "" {
		if vendor.ID == productconfigs.AegisNASPlaceholderVendorID {
			mode = "lab"
		} else {
			mode = "unverified"
		}
	}
	switch mode {
	case "lab":
		if vendor.ID != productconfigs.AegisNASPlaceholderVendorID && vendor.ID != vendoridentity.DocumentationPEN {
			return fmt.Errorf("radius.vendor.identity_mode lab requires PEN %d or RFC 5612 documentation PEN %d", productconfigs.AegisNASPlaceholderVendorID, vendoridentity.DocumentationPEN)
		}
	case "unverified":
		if err := vendoridentity.ValidateProductionPEN(vendor.ID); err != nil {
			return fmt.Errorf("radius.vendor.id: %w", err)
		}
		if vendor.Enabled {
			return errors.New("radius.vendor.enabled requires identity_mode lab or a verified production identity")
		}
	case "production":
		evidence, err := RadiusVendorAssignmentEvidence(vendor)
		if err != nil {
			return err
		}
		if err := evidence.Validate(vendor.ID, vendor.AssignedOrganization); err != nil {
			return fmt.Errorf("radius.vendor production identity: %w", err)
		}
	default:
		return fmt.Errorf("radius.vendor.identity_mode %q must be lab, unverified, or production", vendor.IdentityMode)
	}

	seen := map[int]struct{}{vendor.ID: {}}
	for i, legacyID := range vendor.LegacyIDs {
		if legacyID < 1 || uint64(legacyID) >= uint64(^uint32(0)) {
			return fmt.Errorf("radius.vendor.legacy_ids[%d] %d is outside the RADIUS vendor ID range", i, legacyID)
		}
		if _, exists := seen[legacyID]; exists {
			return fmt.Errorf("radius.vendor.legacy_ids[%d] duplicates PEN %d", i, legacyID)
		}
		seen[legacyID] = struct{}{}
	}
	if len(vendor.LegacyIDs) > 0 {
		if strings.TrimSpace(vendor.LegacyAcceptUntil) == "" {
			return errors.New("radius.vendor.legacy_accept_until is required when legacy_ids are configured")
		}
		if _, err := time.Parse(time.RFC3339, vendor.LegacyAcceptUntil); err != nil {
			return fmt.Errorf("radius.vendor.legacy_accept_until must be RFC3339: %w", err)
		}
	} else if strings.TrimSpace(vendor.LegacyAcceptUntil) != "" {
		return errors.New("radius.vendor.legacy_accept_until requires at least one legacy_ids entry")
	}
	return nil
}

func RadiusVendorAssignmentEvidence(vendor RadiusVendorConfig) (vendoridentity.AssignmentEvidence, error) {
	verifiedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(vendor.AssignmentVerifiedAt))
	if err != nil {
		return vendoridentity.AssignmentEvidence{}, fmt.Errorf("radius.vendor.assignment_verified_at must be RFC3339: %w", err)
	}
	return vendoridentity.AssignmentEvidence{
		SchemaVersion:       vendoridentity.EvidenceSchemaVersion,
		PEN:                 uint32(vendor.ID),
		Organization:        strings.TrimSpace(vendor.AssignedOrganization),
		RegistryURL:         strings.TrimSpace(vendor.AssignmentRegistryURL),
		RegistryLastUpdated: strings.TrimSpace(vendor.RegistryLastUpdated),
		FetchedAt:           verifiedAt.UTC(),
		RegistrySHA256:      strings.TrimSpace(vendor.AssignmentRegistrySHA),
		RecordSHA256:        strings.TrimSpace(vendor.AssignmentRecordSHA),
	}, nil
}

func unsupportedAVPairTemplateToken(value string) string {
	allowed := map[string]struct{}{
		"role": {}, "acl_policy": {}, "inbound_acl": {}, "outbound_acl": {},
		"vlan": {}, "policy_tag": {}, "device_group": {}, "tenant": {},
	}
	for {
		start := strings.Index(value, "${")
		if start < 0 {
			return ""
		}
		endOffset := strings.IndexByte(value[start+2:], '}')
		if endOffset < 0 {
			return value[start:]
		}
		end := start + 2 + endOffset
		token := value[start+2 : end]
		if _, ok := allowed[token]; !ok {
			return value[start : end+1]
		}
		value = value[end+1:]
	}
}

func validateRadiusEAPFramework(eap RadiusEAPConfig) error {
	framework := eap.Framework
	if err := validateRadiusEAPTEAP(eap, framework); err != nil {
		return err
	}
	if err := validateRadiusEAPMachineUser(eap, framework); err != nil {
		return err
	}
	if err := validateRadiusEAPFAST(eap, framework); err != nil {
		return err
	}
	if err := validateRadiusEAPPWD(eap, framework); err != nil {
		return err
	}
	if err := validateRadiusEAPSIMAKA(eap, framework); err != nil {
		return err
	}
	if !framework.Enabled && !radiusEAPFrameworkConfigured(framework) {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(framework.Mode))
	switch mode {
	case "", "monitor", "enforce":
	default:
		return fmt.Errorf("radius.eap.framework.mode %q must be monitor or enforce", framework.Mode)
	}
	action := strings.ToLower(strings.TrimSpace(framework.UnsupportedMethodAction))
	switch action {
	case "", "reject", "nak", "monitor":
	default:
		return fmt.Errorf("radius.eap.framework.unsupported_method_action %q must be reject, nak, or monitor", framework.UnsupportedMethodAction)
	}
	if framework.EventRetentionLimit < 0 || framework.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.framework.event_retention_limit must be between 1 and 1000000 when set")
	}
	if framework.MaxConcurrentSessions < 0 || framework.MaxConcurrentSessions > 1000000 {
		return fmt.Errorf("radius.eap.framework.max_concurrent_sessions must be between 0 and 1000000")
	}
	if framework.MethodTimeoutSeconds < 0 || framework.MethodTimeoutSeconds > 3600 {
		return fmt.Errorf("radius.eap.framework.method_timeout_seconds must be between 1 and 3600 when set")
	}
	if framework.FragmentSize < 0 || framework.FragmentSize > 4096 {
		return fmt.Errorf("radius.eap.framework.fragment_size must be between 512 and 4096 when set")
	}
	if framework.FragmentSize > 0 && framework.FragmentSize < 512 {
		return fmt.Errorf("radius.eap.framework.fragment_size must be between 512 and 4096 when set")
	}

	rawAllowedMethods := framework.AllowedMethods
	if len(rawAllowedMethods) == 0 {
		rawAllowedMethods = []string{"peap", "ttls", "tls"}
	}
	allowedMethods, err := validateEAPMethodList("radius.eap.framework.allowed_methods", rawAllowedMethods, false)
	if err != nil {
		return err
	}
	rawAllowedInner := framework.AllowedInnerMethods
	if len(rawAllowedInner) == 0 {
		rawAllowedInner = []string{"mschapv2", "pap", "chap", "gtc", "tls"}
	}
	allowedInner, err := validateEAPInnerMethodList("radius.eap.framework.allowed_inner_methods", rawAllowedInner, true)
	if err != nil {
		return err
	}
	defaultType := normalizeEAPMethod(eap.DefaultType)
	if defaultType == "" {
		defaultType = "peap"
	}
	if _, ok := allowedMethods[defaultType]; framework.Enabled && !ok {
		return fmt.Errorf("radius.eap.default_type %q is not in radius.eap.framework.allowed_methods", eap.DefaultType)
	}
	peapInner := normalizeEAPInnerMethod(eap.PEAPInner)
	if peapInner == "" {
		peapInner = "mschapv2"
	}
	if _, ok := allowedInner[peapInner]; framework.Enabled && !ok {
		return fmt.Errorf("radius.eap.peap_inner %q is not in radius.eap.framework.allowed_inner_methods", eap.PEAPInner)
	}
	ttlsInner := normalizeEAPInnerMethod(eap.TTLSInner)
	if ttlsInner == "" {
		ttlsInner = "mschapv2"
	}
	if _, ok := allowedInner[ttlsInner]; framework.Enabled && !ok {
		return fmt.Errorf("radius.eap.ttls_inner %q is not in radius.eap.framework.allowed_inner_methods", eap.TTLSInner)
	}

	identitySources := map[string]RadiusEAPIdentitySource{}
	seenPriority := map[int]struct{}{}
	for i, source := range framework.IdentitySources {
		name := normalizeEAPIdentitySourceName(source.Name)
		if name == "" {
			return fmt.Errorf("radius.eap.framework.identity_sources[%d].name is required", i)
		}
		if !validEAPPolicyToken(name) {
			return fmt.Errorf("radius.eap.framework.identity_sources[%d].name %q is invalid", i, source.Name)
		}
		sourceType := strings.ToLower(strings.TrimSpace(source.Source))
		switch sourceType {
		case "local", "ldap", "active_directory", "identity_failover", "certificate", "upstream", "external":
		default:
			return fmt.Errorf("radius.eap.framework.identity_sources[%d].source %q is invalid", i, source.Source)
		}
		if _, exists := identitySources[name]; exists {
			return fmt.Errorf("radius.eap.framework.identity_sources[%d].name %q duplicates an earlier identity source", i, source.Name)
		}
		if _, exists := seenPriority[source.Priority]; source.Priority > 0 && exists {
			return fmt.Errorf("radius.eap.framework.identity_sources[%d].priority duplicates an earlier identity source", i)
		}
		seenPriority[source.Priority] = struct{}{}
		if _, err := validateEAPMethodList(fmt.Sprintf("radius.eap.framework.identity_sources[%d].methods", i), source.Methods, true); err != nil {
			return err
		}
		identitySources[name] = source
	}

	if framework.Enabled && framework.RequireIdentityBinding {
		outer := normalizeEAPIdentitySourceName(framework.DefaultOuterIdentitySource)
		inner := normalizeEAPIdentitySourceName(framework.DefaultInnerIdentitySource)
		if outer == "" {
			outer = "configured-default"
		}
		if inner == "" {
			inner = "identity-failover"
		}
		if outer != "configured-default" {
			if _, ok := identitySources[outer]; !ok {
				return fmt.Errorf("radius.eap.framework.default_outer_identity_source %q is not defined", framework.DefaultOuterIdentitySource)
			}
		}
		if _, ok := identitySources[inner]; !ok {
			return fmt.Errorf("radius.eap.framework.default_inner_identity_source %q is not defined", framework.DefaultInnerIdentitySource)
		}
	}

	seenMethods := map[string]struct{}{}
	for i, policy := range framework.MethodPolicies {
		method := normalizeEAPMethod(policy.Method)
		if method == "" {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].method is required", i)
		}
		if !validEAPMethod(method) {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].method %q is invalid", i, policy.Method)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].method %q duplicates an earlier policy", i, policy.Method)
		}
		seenMethods[method] = struct{}{}
		if framework.Enabled {
			if _, ok := allowedMethods[method]; !ok {
				return fmt.Errorf("radius.eap.framework.method_policies[%d].method %q is not in allowed_methods", i, policy.Method)
			}
		}
		policyInner, err := validateEAPInnerMethodList(fmt.Sprintf("radius.eap.framework.method_policies[%d].inner_methods", i), policy.InnerMethods, true)
		if err != nil {
			return err
		}
		for innerMethod := range policyInner {
			if _, ok := allowedInner[innerMethod]; framework.Enabled && !ok {
				return fmt.Errorf("radius.eap.framework.method_policies[%d].inner_methods contains %q which is not in allowed_inner_methods", i, innerMethod)
			}
		}
		identitySource := normalizeEAPIdentitySourceName(policy.IdentitySource)
		if framework.Enabled && framework.RequireIdentityBinding && identitySource == "" {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].identity_source is required when identity binding is required", i)
		}
		if identitySource != "" {
			if _, ok := identitySources[identitySource]; !ok {
				return fmt.Errorf("radius.eap.framework.method_policies[%d].identity_source %q is not defined", i, policy.IdentitySource)
			}
		}
		if policy.RequireCertificate && policy.AllowPasswordVerifier {
			return fmt.Errorf("radius.eap.framework.method_policies[%d] cannot require_certificate and allow_password_verifier together", i)
		}
		if policy.RequireRevocation && !policy.RequireCertificate {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].require_revocation requires require_certificate", i)
		}
		if policy.RequireRevocation && !eap.CheckCRL && !eap.OCSP.Enabled {
			return fmt.Errorf("radius.eap.framework.method_policies[%d].require_revocation requires radius.eap.check_crl or radius.eap.ocsp.enabled", i)
		}
		if err := validateEAPTLSVersionBounds(fmt.Sprintf("radius.eap.framework.method_policies[%d]", i), policy.MinTLSVersion, policy.MaxTLSVersion); err != nil {
			return err
		}
		for j, profile := range policy.VendorProfiles {
			if !validEAPPolicyToken(strings.ToLower(strings.TrimSpace(profile))) {
				return fmt.Errorf("radius.eap.framework.method_policies[%d].vendor_profiles[%d] is invalid", i, j)
			}
		}
	}

	seenProfiles := map[string]struct{}{}
	for i, profile := range framework.VendorCompatibilityProfiles {
		name := strings.ToLower(strings.TrimSpace(profile.Name))
		if name == "" || !validEAPPolicyToken(name) {
			return fmt.Errorf("radius.eap.framework.vendor_compatibility_profiles[%d].name is invalid", i)
		}
		if _, exists := seenProfiles[name]; exists {
			return fmt.Errorf("radius.eap.framework.vendor_compatibility_profiles[%d].name duplicates an earlier profile", i)
		}
		seenProfiles[name] = struct{}{}
		if _, err := validateEAPMethodList(fmt.Sprintf("radius.eap.framework.vendor_compatibility_profiles[%d].allowed_methods", i), profile.AllowedMethods, true); err != nil {
			return err
		}
		if _, err := validateEAPMethodList(fmt.Sprintf("radius.eap.framework.vendor_compatibility_profiles[%d].required_methods", i), profile.RequiredMethods, true); err != nil {
			return err
		}
		for j, nasType := range profile.NASTypes {
			if !validEAPPolicyToken(strings.ToLower(strings.TrimSpace(nasType))) {
				return fmt.Errorf("radius.eap.framework.vendor_compatibility_profiles[%d].nas_types[%d] is invalid", i, j)
			}
		}
		if strings.ContainsAny(profile.Notes, "\r\n\x00") || len(profile.Notes) > 512 {
			return fmt.Errorf("radius.eap.framework.vendor_compatibility_profiles[%d].notes is invalid", i)
		}
	}
	return nil
}

func validateRadiusEAPTEAP(eap RadiusEAPConfig, framework RadiusEAPFramework) error {
	teap := eap.TEAP
	if !teap.Enabled && !radiusEAPTEAPConfigured(teap) {
		return nil
	}
	defaultInner := normalizeEAPInnerMethod(teap.DefaultInnerMethod)
	if defaultInner == "" {
		defaultInner = "mschapv2"
	}
	if !validEAPInnerMethod(defaultInner) {
		return fmt.Errorf("radius.eap.teap.default_inner_method %q is invalid", teap.DefaultInnerMethod)
	}
	rawAllowedInner := framework.AllowedInnerMethods
	if len(rawAllowedInner) == 0 {
		rawAllowedInner = []string{"mschapv2", "pap", "chap", "gtc", "tls"}
	}
	allowedInner, err := validateEAPInnerMethodList("radius.eap.framework.allowed_inner_methods", rawAllowedInner, true)
	if err != nil {
		return err
	}
	if framework.Enabled {
		if _, ok := allowedInner[defaultInner]; !ok {
			return fmt.Errorf("radius.eap.teap.default_inner_method %q is not in radius.eap.framework.allowed_inner_methods", teap.DefaultInnerMethod)
		}
	}
	chainMode := strings.ToLower(strings.TrimSpace(teap.ChainMode))
	if chainMode == "" {
		chainMode = "machine_then_user"
	}
	switch chainMode {
	case "user_only", "machine_only", "machine_then_user", "either":
	default:
		return fmt.Errorf("radius.eap.teap.chain_mode %q must be user_only, machine_only, machine_then_user, or either", teap.ChainMode)
	}
	provisioning := strings.ToLower(strings.TrimSpace(teap.PACProvisioning))
	if provisioning == "" {
		provisioning = "authenticated"
	}
	switch provisioning {
	case "disabled", "authenticated", "optional":
	default:
		return fmt.Errorf("radius.eap.teap.pac_provisioning %q must be disabled, authenticated, or optional", teap.PACProvisioning)
	}
	if teap.RequirePAC && !teap.AllowPAC {
		return fmt.Errorf("radius.eap.teap.require_pac requires radius.eap.teap.allow_pac")
	}
	if teap.PACLifetimeSeconds < 0 || teap.PACLifetimeSeconds > 31536000 {
		return fmt.Errorf("radius.eap.teap.pac_lifetime_seconds must be between 0 and 31536000")
	}
	if teap.MaxChainSteps < 0 || teap.MaxChainSteps > 8 {
		return fmt.Errorf("radius.eap.teap.max_chain_steps must be between 1 and 8 when set")
	}
	if teap.MaxChainSteps > 0 && teap.MaxChainSteps < 1 {
		return fmt.Errorf("radius.eap.teap.max_chain_steps must be between 1 and 8 when set")
	}
	maxSteps := teap.MaxChainSteps
	if maxSteps == 0 {
		maxSteps = 2
	}
	if chainMode == "machine_then_user" && maxSteps < 2 {
		return fmt.Errorf("radius.eap.teap.max_chain_steps must be at least 2 for machine_then_user")
	}
	if teap.SessionTTLSeconds < 0 || teap.SessionTTLSeconds > 86400 {
		return fmt.Errorf("radius.eap.teap.session_ttl_seconds must be between 60 and 86400 when set")
	}
	if teap.SessionTTLSeconds > 0 && teap.SessionTTLSeconds < 60 {
		return fmt.Errorf("radius.eap.teap.session_ttl_seconds must be between 60 and 86400 when set")
	}
	if teap.EventRetentionLimit < 0 || teap.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.teap.event_retention_limit must be between 1 and 1000000 when set")
	}
	if !validEAPAuthorityID(teap.PACAuthorityID) {
		return fmt.Errorf("radius.eap.teap.pac_authority_id is invalid")
	}

	rawAllowedMethods := framework.AllowedMethods
	if len(rawAllowedMethods) == 0 {
		rawAllowedMethods = []string{"peap", "ttls", "tls"}
	}
	allowedMethods, err := validateEAPMethodList("radius.eap.framework.allowed_methods", rawAllowedMethods, false)
	if err != nil {
		return err
	}
	_, teapAllowed := allowedMethods["teap"]
	if teap.Enabled && framework.Enabled && teapAllowed {
		if !framework.RequireMessageAuthenticator {
			return fmt.Errorf("radius.eap.teap requires radius.eap.framework.require_message_authenticator when teap is allowed")
		}
		if !framework.RequireIdentityBinding {
			return fmt.Errorf("radius.eap.teap requires radius.eap.framework.require_identity_binding when teap is allowed")
		}
		mode := strings.ToLower(strings.TrimSpace(framework.Mode))
		if mode == "" {
			mode = "monitor"
		}
		if mode == "enforce" && framework.FailClosed && !teap.RequireCryptoBinding {
			return fmt.Errorf("radius.eap.teap.require_crypto_binding must be true in enforce fail-closed mode")
		}
	}
	return nil
}

func radiusEAPTEAPConfigured(teap RadiusEAPTEAPConfig) bool {
	return strings.TrimSpace(teap.DefaultInnerMethod) != "" ||
		strings.TrimSpace(teap.ChainMode) != "" ||
		teap.RequireCryptoBinding ||
		teap.RequireChannelBinding ||
		teap.RequireIdentityType ||
		teap.RequireMachineIdentity ||
		teap.RequireUserIdentity ||
		teap.AllowPAC ||
		teap.RequirePAC ||
		strings.TrimSpace(teap.PACProvisioning) != "" ||
		strings.TrimSpace(teap.PACAuthorityID) != "" ||
		teap.PACLifetimeSeconds != 0 ||
		teap.AllowEAPPayload ||
		teap.AllowBasicPasswordAuth ||
		teap.MaxChainSteps != 0 ||
		teap.SessionTTLSeconds != 0 ||
		teap.EventRetentionLimit != 0
}

func validateRadiusEAPMachineUser(eap RadiusEAPConfig, framework RadiusEAPFramework) error {
	machineUser := eap.MachineUser
	if !machineUser.Enabled && !radiusEAPMachineUserConfigured(machineUser) {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(machineUser.Mode))
	if mode == "" {
		mode = "monitor"
	}
	switch mode {
	case "monitor", "enforce":
	default:
		return fmt.Errorf("radius.eap.machine_user.mode %q must be monitor or enforce", machineUser.Mode)
	}
	correlationMode := strings.ToLower(strings.TrimSpace(machineUser.CorrelationMode))
	if correlationMode == "" {
		correlationMode = "machine_then_user"
	}
	switch correlationMode {
	case "machine_then_user", "same_session", "either", "machine_only", "user_only":
	default:
		return fmt.Errorf("radius.eap.machine_user.correlation_mode %q must be machine_then_user, same_session, either, machine_only, or user_only", machineUser.CorrelationMode)
	}
	if machineUser.MachineAuthTTLSeconds < 0 || machineUser.MachineAuthTTLSeconds > 604800 {
		return fmt.Errorf("radius.eap.machine_user.machine_auth_ttl_seconds must be between 60 and 604800 when set")
	}
	if machineUser.MachineAuthTTLSeconds > 0 && machineUser.MachineAuthTTLSeconds < 60 {
		return fmt.Errorf("radius.eap.machine_user.machine_auth_ttl_seconds must be between 60 and 604800 when set")
	}
	if machineUser.UserAuthTTLSeconds < 0 || machineUser.UserAuthTTLSeconds > 604800 {
		return fmt.Errorf("radius.eap.machine_user.user_auth_ttl_seconds must be between 60 and 604800 when set")
	}
	if machineUser.UserAuthTTLSeconds > 0 && machineUser.UserAuthTTLSeconds < 60 {
		return fmt.Errorf("radius.eap.machine_user.user_auth_ttl_seconds must be between 60 and 604800 when set")
	}
	if machineUser.TransitionWindowSeconds < 0 || machineUser.TransitionWindowSeconds > 86400 {
		return fmt.Errorf("radius.eap.machine_user.transition_window_seconds must be between 0 and 86400")
	}
	if _, err := validateEAPMethodList("radius.eap.machine_user.allowed_machine_methods", machineUser.AllowedMachineMethods, true); err != nil {
		return err
	}
	if _, err := validateEAPMethodList("radius.eap.machine_user.allowed_user_methods", machineUser.AllowedUserMethods, true); err != nil {
		return err
	}
	precedence := strings.ToLower(strings.TrimSpace(machineUser.IdentityPrecedence))
	if precedence == "" {
		precedence = "user_over_machine"
	}
	switch precedence {
	case "user_over_machine", "machine_over_user", "deny_conflict":
	default:
		return fmt.Errorf("radius.eap.machine_user.identity_precedence %q must be user_over_machine, machine_over_user, or deny_conflict", machineUser.IdentityPrecedence)
	}
	merge := strings.ToLower(strings.TrimSpace(machineUser.RoleMergeStrategy))
	if merge == "" {
		merge = "user_primary"
	}
	switch merge {
	case "user_primary", "machine_primary", "intersection", "deny_conflict":
	default:
		return fmt.Errorf("radius.eap.machine_user.role_merge_strategy %q must be user_primary, machine_primary, intersection, or deny_conflict", machineUser.RoleMergeStrategy)
	}
	conflictAction := strings.ToLower(strings.TrimSpace(machineUser.ConflictAction))
	if conflictAction == "" {
		conflictAction = "reject"
	}
	switch conflictAction {
	case "reject", "monitor", "quarantine":
	default:
		return fmt.Errorf("radius.eap.machine_user.conflict_action %q must be reject, monitor, or quarantine", machineUser.ConflictAction)
	}
	staleAction := strings.ToLower(strings.TrimSpace(machineUser.StaleMachineAction))
	if staleAction == "" {
		staleAction = "reject"
	}
	switch staleAction {
	case "reject", "monitor", "allow":
	default:
		return fmt.Errorf("radius.eap.machine_user.stale_machine_action %q must be reject, monitor, or allow", machineUser.StaleMachineAction)
	}
	for i, prefix := range machineUser.MachineIdentityPrefixes {
		if !validEAPIdentityPrefix(prefix) {
			return fmt.Errorf("radius.eap.machine_user.machine_identity_prefixes[%d] is invalid", i)
		}
	}
	for i, prefix := range machineUser.UserIdentityPrefixes {
		if !validEAPIdentityPrefix(prefix) {
			return fmt.Errorf("radius.eap.machine_user.user_identity_prefixes[%d] is invalid", i)
		}
	}
	if machineUser.MaxActiveCorrelations < 0 || machineUser.MaxActiveCorrelations > 10000000 {
		return fmt.Errorf("radius.eap.machine_user.max_active_correlations must be between 1 and 10000000 when set")
	}
	if machineUser.EventRetentionLimit < 0 || machineUser.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.machine_user.event_retention_limit must be between 1 and 1000000 when set")
	}
	if machineUser.Enabled && mode == "enforce" && machineUser.FailClosed {
		if !framework.Enabled {
			return fmt.Errorf("radius.eap.machine_user requires radius.eap.framework.enabled in enforce fail-closed mode")
		}
		rawAllowedMethods := framework.AllowedMethods
		if len(rawAllowedMethods) == 0 {
			rawAllowedMethods = []string{"peap", "ttls", "tls"}
		}
		if machineUser.RequireTEAP && (!eap.TEAP.Enabled || !containsEAPMethod(rawAllowedMethods, "teap")) {
			return fmt.Errorf("radius.eap.machine_user.require_teap requires TEAP to be enabled and listed in radius.eap.framework.allowed_methods")
		}
		if correlationMode == "machine_then_user" || correlationMode == "same_session" {
			if !machineUser.RequireMachineIdentity || !machineUser.RequireUserIdentity {
				return fmt.Errorf("radius.eap.machine_user requires machine and user identity in %s enforce fail-closed mode", correlationMode)
			}
		}
		if machineUser.RequireFreshMachineAuth && machineUser.MachineAuthTTLSeconds == 0 {
			return fmt.Errorf("radius.eap.machine_user.machine_auth_ttl_seconds must be set when fresh machine auth is required")
		}
		if correlationMode == "machine_then_user" && machineUser.TransitionWindowSeconds == 0 {
			return fmt.Errorf("radius.eap.machine_user.transition_window_seconds must be set for machine_then_user enforce fail-closed mode")
		}
		if machineUser.RequireMachineBeforeUser && correlationMode == "user_only" {
			return fmt.Errorf("radius.eap.machine_user.require_machine_before_user cannot be true with user_only correlation mode")
		}
		if !machineUser.RequireSameCallingStation && correlationMode != "user_only" && correlationMode != "machine_only" {
			return fmt.Errorf("radius.eap.machine_user.require_same_calling_station must be true in enforce fail-closed correlation mode")
		}
	}
	return nil
}

func radiusEAPMachineUserConfigured(machineUser RadiusEAPMachineUserConfig) bool {
	return strings.TrimSpace(machineUser.Mode) != "" ||
		strings.TrimSpace(machineUser.CorrelationMode) != "" ||
		machineUser.FailClosed ||
		machineUser.RequireTEAP ||
		machineUser.RequireMachineIdentity ||
		machineUser.RequireUserIdentity ||
		machineUser.RequireMachineBeforeUser ||
		machineUser.RequireSameCallingStation ||
		machineUser.RequireSameNAS ||
		machineUser.RequireFreshMachineAuth ||
		machineUser.MachineAuthTTLSeconds != 0 ||
		machineUser.UserAuthTTLSeconds != 0 ||
		machineUser.TransitionWindowSeconds != 0 ||
		len(machineUser.AllowedMachineMethods) > 0 ||
		len(machineUser.AllowedUserMethods) > 0 ||
		strings.TrimSpace(machineUser.IdentityPrecedence) != "" ||
		strings.TrimSpace(machineUser.RoleMergeStrategy) != "" ||
		strings.TrimSpace(machineUser.ConflictAction) != "" ||
		strings.TrimSpace(machineUser.StaleMachineAction) != "" ||
		len(machineUser.MachineIdentityPrefixes) > 0 ||
		len(machineUser.UserIdentityPrefixes) > 0 ||
		machineUser.MaxActiveCorrelations != 0 ||
		machineUser.AuditEnabled ||
		machineUser.EventRetentionLimit != 0
}

func containsEAPMethod(methods []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, method := range methods {
		if strings.ToLower(strings.TrimSpace(method)) == target {
			return true
		}
	}
	return false
}

func validEAPIdentityPrefix(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	return prefix != "" && len(prefix) <= 64 && !strings.ContainsAny(prefix, "\r\n\x00")
}

func validateRadiusEAPFAST(eap RadiusEAPConfig, framework RadiusEAPFramework) error {
	fast := eap.FAST
	if !fast.Enabled && !radiusEAPFASTConfigured(fast) {
		return nil
	}
	defaultInner := normalizeEAPInnerMethod(fast.DefaultInnerMethod)
	if defaultInner == "" {
		defaultInner = "mschapv2"
	}
	if !validEAPInnerMethod(defaultInner) {
		return fmt.Errorf("radius.eap.fast.default_inner_method %q is invalid", fast.DefaultInnerMethod)
	}
	rawAllowedInner := framework.AllowedInnerMethods
	if len(rawAllowedInner) == 0 {
		rawAllowedInner = []string{"mschapv2", "pap", "chap", "gtc", "tls"}
	}
	allowedInner, err := validateEAPInnerMethodList("radius.eap.framework.allowed_inner_methods", rawAllowedInner, true)
	if err != nil {
		return err
	}
	if framework.Enabled {
		if _, ok := allowedInner[defaultInner]; !ok {
			return fmt.Errorf("radius.eap.fast.default_inner_method %q is not in radius.eap.framework.allowed_inner_methods", fast.DefaultInnerMethod)
		}
	}
	provisioning := strings.ToLower(strings.TrimSpace(fast.PACProvisioning))
	if provisioning == "" {
		provisioning = "authenticated"
	}
	switch provisioning {
	case "disabled", "authenticated", "anonymous", "optional":
	default:
		return fmt.Errorf("radius.eap.fast.pac_provisioning %q must be disabled, authenticated, anonymous, or optional", fast.PACProvisioning)
	}
	if fast.RequirePAC && !fast.AllowPAC {
		return fmt.Errorf("radius.eap.fast.require_pac requires radius.eap.fast.allow_pac")
	}
	if fast.PACLifetimeSeconds < 0 || fast.PACLifetimeSeconds > 31536000 {
		return fmt.Errorf("radius.eap.fast.pac_lifetime_seconds must be between 0 and 31536000")
	}
	if fast.MaxProvisioningAttempts < 0 || fast.MaxProvisioningAttempts > 100 {
		return fmt.Errorf("radius.eap.fast.max_provisioning_attempts must be between 0 and 100")
	}
	if fast.SessionTTLSeconds < 0 || fast.SessionTTLSeconds > 86400 {
		return fmt.Errorf("radius.eap.fast.session_ttl_seconds must be between 60 and 86400 when set")
	}
	if fast.SessionTTLSeconds > 0 && fast.SessionTTLSeconds < 60 {
		return fmt.Errorf("radius.eap.fast.session_ttl_seconds must be between 60 and 86400 when set")
	}
	if fast.EventRetentionLimit < 0 || fast.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.fast.event_retention_limit must be between 1 and 1000000 when set")
	}
	if !validEAPAuthorityID(fast.PACAuthorityID) {
		return fmt.Errorf("radius.eap.fast.pac_authority_id is invalid")
	}
	if !validEAPSecretRefOrEmpty(fast.PACOpaqueKeyRef) {
		return fmt.Errorf("radius.eap.fast.pac_opaque_key_ref is invalid")
	}

	rawAllowedMethods := framework.AllowedMethods
	if len(rawAllowedMethods) == 0 {
		rawAllowedMethods = []string{"peap", "ttls", "tls"}
	}
	allowedMethods, err := validateEAPMethodList("radius.eap.framework.allowed_methods", rawAllowedMethods, false)
	if err != nil {
		return err
	}
	_, fastAllowed := allowedMethods["fast"]
	if fast.Enabled && framework.Enabled && fastAllowed {
		if !framework.RequireMessageAuthenticator {
			return fmt.Errorf("radius.eap.fast requires radius.eap.framework.require_message_authenticator when fast is allowed")
		}
		if !framework.RequireIdentityBinding {
			return fmt.Errorf("radius.eap.fast requires radius.eap.framework.require_identity_binding when fast is allowed")
		}
		mode := strings.ToLower(strings.TrimSpace(framework.Mode))
		if mode == "" {
			mode = "monitor"
		}
		if mode == "enforce" && framework.FailClosed {
			if !fast.RequireCryptoBinding {
				return fmt.Errorf("radius.eap.fast.require_crypto_binding must be true in enforce fail-closed mode")
			}
			if provisioning == "anonymous" && !fast.AllowAnonymousProvisioning {
				return fmt.Errorf("radius.eap.fast.pac_provisioning anonymous requires allow_anonymous_provisioning")
			}
		}
	}
	return nil
}

func validateRadiusEAPPWD(eap RadiusEAPConfig, framework RadiusEAPFramework) error {
	pwd := eap.PWD
	if !pwd.Enabled && !radiusEAPPWDConfigured(pwd) {
		return nil
	}
	group := pwd.Group
	if group == 0 {
		group = 19
	}
	if group < 1 || group > 65535 {
		return fmt.Errorf("radius.eap.pwd.group must be between 1 and 65535")
	}
	if pwd.RequireStrongGroup && !strongEAPPWDGroup(group) {
		return fmt.Errorf("radius.eap.pwd.group %d is not in the strong group allowlist", group)
	}
	if !validEAPAuthorityID(pwd.ServerID) {
		return fmt.Errorf("radius.eap.pwd.server_id is invalid")
	}
	source := normalizeEAPIdentitySourceName(pwd.PasswordSource)
	if source == "" {
		source = "identity-failover"
	}
	if !validEAPPolicyToken(source) {
		return fmt.Errorf("radius.eap.pwd.password_source is invalid")
	}
	if pwd.ReplayWindowSeconds < 0 || pwd.ReplayWindowSeconds > 3600 {
		return fmt.Errorf("radius.eap.pwd.replay_window_seconds must be between 0 and 3600")
	}
	if pwd.FragmentSize < 0 || pwd.FragmentSize > 4096 {
		return fmt.Errorf("radius.eap.pwd.fragment_size must be between 512 and 4096 when set")
	}
	if pwd.FragmentSize > 0 && pwd.FragmentSize < 512 {
		return fmt.Errorf("radius.eap.pwd.fragment_size must be between 512 and 4096 when set")
	}
	if pwd.EventRetentionLimit < 0 || pwd.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.pwd.event_retention_limit must be between 1 and 1000000 when set")
	}

	rawAllowedMethods := framework.AllowedMethods
	if len(rawAllowedMethods) == 0 {
		rawAllowedMethods = []string{"peap", "ttls", "tls"}
	}
	allowedMethods, err := validateEAPMethodList("radius.eap.framework.allowed_methods", rawAllowedMethods, false)
	if err != nil {
		return err
	}
	_, pwdAllowed := allowedMethods["pwd"]
	if pwd.Enabled && framework.Enabled && pwdAllowed {
		if !framework.RequireMessageAuthenticator {
			return fmt.Errorf("radius.eap.pwd requires radius.eap.framework.require_message_authenticator when pwd is allowed")
		}
		if !framework.RequireIdentityBinding {
			return fmt.Errorf("radius.eap.pwd requires radius.eap.framework.require_identity_binding when pwd is allowed")
		}
		mode := strings.ToLower(strings.TrimSpace(framework.Mode))
		if mode == "" {
			mode = "monitor"
		}
		if mode == "enforce" && framework.FailClosed {
			if !pwd.RequireIdentity {
				return fmt.Errorf("radius.eap.pwd.require_identity must be true in enforce fail-closed mode")
			}
			if !pwd.RequirePasswordProof {
				return fmt.Errorf("radius.eap.pwd.require_password_proof must be true in enforce fail-closed mode")
			}
			if !pwd.AllowLocalVerifier {
				return fmt.Errorf("radius.eap.pwd.allow_local_verifier must be true until an external verifier is configured")
			}
		}
	}
	return nil
}

func validateRadiusEAPSIMAKA(eap RadiusEAPConfig, framework RadiusEAPFramework) error {
	simaka := eap.SIMAKA
	if !simaka.Enabled && !radiusEAPSIMAKAConfigured(simaka) {
		return nil
	}
	methods := simaka.Methods
	if len(methods) == 0 {
		methods = []string{"sim", "aka", "aka-prime"}
	}
	seenMethods := map[string]struct{}{}
	for i, raw := range methods {
		method := normalizeEAPMethod(raw)
		switch method {
		case "sim", "aka", "aka-prime":
		default:
			return fmt.Errorf("radius.eap.sim_aka.methods[%d] %q must be sim, aka, or aka-prime", i, raw)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("radius.eap.sim_aka.methods[%d] %q duplicates an earlier method", i, raw)
		}
		seenMethods[method] = struct{}{}
	}
	provider := strings.ToLower(strings.TrimSpace(simaka.VectorProvider))
	if provider == "" {
		provider = "external-http"
	}
	switch provider {
	case "external-http", "hss-http", "udm-http", "static-file", "identity-failover":
	default:
		return fmt.Errorf("radius.eap.sim_aka.vector_provider %q must be external-http, hss-http, udm-http, static-file, or identity-failover", simaka.VectorProvider)
	}
	if !validEAPSecretRefOrEmpty(simaka.VectorProviderRef) {
		return fmt.Errorf("radius.eap.sim_aka.vector_provider_ref must be an external reference such as env:NAME or file:/path")
	}
	if simaka.PseudonymTTLSeconds < 0 || simaka.PseudonymTTLSeconds > 31536000 {
		return fmt.Errorf("radius.eap.sim_aka.pseudonym_ttl_seconds must be between 0 and 31536000")
	}
	if simaka.ReauthTTLSeconds < 0 || simaka.ReauthTTLSeconds > 31536000 {
		return fmt.Errorf("radius.eap.sim_aka.reauth_ttl_seconds must be between 0 and 31536000")
	}
	if simaka.MaxVectorAgeSeconds < 0 || simaka.MaxVectorAgeSeconds > 86400 {
		return fmt.Errorf("radius.eap.sim_aka.max_vector_age_seconds must be between 1 and 86400 when set")
	}
	if simaka.MaxVectorAgeSeconds > 0 && simaka.MaxVectorAgeSeconds < 1 {
		return fmt.Errorf("radius.eap.sim_aka.max_vector_age_seconds must be between 1 and 86400 when set")
	}
	if simaka.MinTriplets < 0 || simaka.MinTriplets > 16 {
		return fmt.Errorf("radius.eap.sim_aka.min_triplets must be between 1 and 16 when set")
	}
	if simaka.MinQuintuplets < 0 || simaka.MinQuintuplets > 16 {
		return fmt.Errorf("radius.eap.sim_aka.min_quintuplets must be between 1 and 16 when set")
	}
	if simaka.ResyncWindowSeconds < 0 || simaka.ResyncWindowSeconds > 3600 {
		return fmt.Errorf("radius.eap.sim_aka.resync_window_seconds must be between 0 and 3600")
	}
	if !validEAPSIMAKANetworkName(simaka.NetworkName) {
		return fmt.Errorf("radius.eap.sim_aka.network_name is invalid")
	}
	if simaka.EventRetentionLimit < 0 || simaka.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.eap.sim_aka.event_retention_limit must be between 1 and 1000000 when set")
	}

	rawAllowedMethods := framework.AllowedMethods
	if len(rawAllowedMethods) == 0 {
		rawAllowedMethods = []string{"peap", "ttls", "tls"}
	}
	allowedMethods, err := validateEAPMethodList("radius.eap.framework.allowed_methods", rawAllowedMethods, false)
	if err != nil {
		return err
	}
	simAllowed := false
	for method := range seenMethods {
		if _, ok := allowedMethods[method]; ok {
			simAllowed = true
			break
		}
	}
	if simaka.Enabled && framework.Enabled && simAllowed {
		if !framework.RequireMessageAuthenticator {
			return fmt.Errorf("radius.eap.sim_aka requires radius.eap.framework.require_message_authenticator when mobile methods are allowed")
		}
		if !framework.RequireIdentityBinding {
			return fmt.Errorf("radius.eap.sim_aka requires radius.eap.framework.require_identity_binding when mobile methods are allowed")
		}
		mode := strings.ToLower(strings.TrimSpace(framework.Mode))
		if mode == "" {
			mode = "monitor"
		}
		if mode == "enforce" && framework.FailClosed {
			if !simaka.RequireIdentity {
				return fmt.Errorf("radius.eap.sim_aka.require_identity must be true in enforce fail-closed mode")
			}
			if !simaka.RequirePermanentIdentity && !simaka.AllowPseudonymIdentity {
				return fmt.Errorf("radius.eap.sim_aka requires permanent or pseudonym identity support in enforce fail-closed mode")
			}
			if strings.TrimSpace(simaka.VectorProviderRef) == "" {
				return fmt.Errorf("radius.eap.sim_aka.vector_provider_ref is required when SIM/AKA methods are allowed in enforce fail-closed mode")
			}
			if !simaka.RequireFreshVectors {
				return fmt.Errorf("radius.eap.sim_aka.require_fresh_vectors must be true in enforce fail-closed mode")
			}
			maxAge := simaka.MaxVectorAgeSeconds
			if maxAge == 0 {
				maxAge = 300
			}
			if maxAge > 3600 {
				return fmt.Errorf("radius.eap.sim_aka.max_vector_age_seconds must be 3600 or less in enforce fail-closed mode")
			}
			if _, ok := allowedMethods["sim"]; ok {
				minTriplets := simaka.MinTriplets
				if minTriplets == 0 {
					minTriplets = 2
				}
				if minTriplets < 2 {
					return fmt.Errorf("radius.eap.sim_aka.min_triplets must be at least 2 when EAP-SIM is allowed")
				}
			}
			if _, ok := allowedMethods["aka"]; ok {
				minQuintuplets := simaka.MinQuintuplets
				if minQuintuplets == 0 {
					minQuintuplets = 1
				}
				if minQuintuplets < 1 {
					return fmt.Errorf("radius.eap.sim_aka.min_quintuplets must be at least 1 when EAP-AKA is allowed")
				}
			}
			if _, ok := allowedMethods["aka-prime"]; ok {
				if !simaka.RequireNetworkName {
					return fmt.Errorf("radius.eap.sim_aka.require_network_name must be true when EAP-AKA-prime is allowed")
				}
				if strings.TrimSpace(simaka.NetworkName) == "" {
					return fmt.Errorf("radius.eap.sim_aka.network_name is required when EAP-AKA-prime is allowed")
				}
				if !simaka.RequireKDF {
					return fmt.Errorf("radius.eap.sim_aka.require_kdf must be true when EAP-AKA-prime is allowed")
				}
			}
		}
	}
	return nil
}

func radiusEAPFASTConfigured(fast RadiusEAPFASTConfig) bool {
	return strings.TrimSpace(fast.DefaultInnerMethod) != "" ||
		fast.RequireCryptoBinding ||
		fast.AllowPAC ||
		fast.RequirePAC ||
		strings.TrimSpace(fast.PACProvisioning) != "" ||
		strings.TrimSpace(fast.PACAuthorityID) != "" ||
		fast.PACLifetimeSeconds != 0 ||
		strings.TrimSpace(fast.PACOpaqueKeyRef) != "" ||
		fast.AllowAnonymousProvisioning ||
		fast.AllowEAPPayload ||
		fast.MaxProvisioningAttempts != 0 ||
		fast.SessionTTLSeconds != 0 ||
		fast.EventRetentionLimit != 0
}

func radiusEAPPWDConfigured(pwd RadiusEAPPWDConfig) bool {
	return pwd.Group != 0 ||
		strings.TrimSpace(pwd.ServerID) != "" ||
		pwd.RequireStrongGroup ||
		strings.TrimSpace(pwd.PasswordSource) != "" ||
		pwd.AllowLocalVerifier ||
		pwd.RequireIdentity ||
		pwd.RequirePasswordProof ||
		pwd.ReplayWindowSeconds != 0 ||
		pwd.FragmentSize != 0 ||
		pwd.EventRetentionLimit != 0
}

func radiusEAPSIMAKAConfigured(simaka RadiusEAPSIMAKAConfig) bool {
	return len(simaka.Methods) > 0 ||
		simaka.RequireIdentity ||
		simaka.RequirePermanentIdentity ||
		simaka.AllowPseudonymIdentity ||
		simaka.RequirePseudonymReauth ||
		simaka.PseudonymTTLSeconds != 0 ||
		simaka.ReauthTTLSeconds != 0 ||
		strings.TrimSpace(simaka.VectorProvider) != "" ||
		strings.TrimSpace(simaka.VectorProviderRef) != "" ||
		simaka.RequireFreshVectors ||
		simaka.MaxVectorAgeSeconds != 0 ||
		simaka.MinTriplets != 0 ||
		simaka.MinQuintuplets != 0 ||
		simaka.AllowResynchronization ||
		simaka.ResyncWindowSeconds != 0 ||
		simaka.RequireNetworkName ||
		strings.TrimSpace(simaka.NetworkName) != "" ||
		simaka.RequireKDF ||
		simaka.FailOnProviderUnavailable ||
		simaka.EventRetentionLimit != 0
}

func radiusEAPFrameworkConfigured(framework RadiusEAPFramework) bool {
	return strings.TrimSpace(framework.Mode) != "" ||
		framework.FailClosed ||
		len(framework.AllowedMethods) > 0 ||
		len(framework.AllowedInnerMethods) > 0 ||
		strings.TrimSpace(framework.DefaultOuterIdentitySource) != "" ||
		strings.TrimSpace(framework.DefaultInnerIdentitySource) != "" ||
		len(framework.MethodPolicies) > 0 ||
		strings.TrimSpace(framework.UnsupportedMethodAction) != "" ||
		framework.RequireMessageAuthenticator ||
		framework.RequireIdentityBinding ||
		framework.TelemetryEnabled ||
		framework.EventRetentionLimit != 0 ||
		framework.MaxConcurrentSessions != 0 ||
		framework.MethodTimeoutSeconds != 0 ||
		framework.FragmentSize != 0 ||
		framework.NakUnknownTypes ||
		len(framework.IdentitySources) > 0 ||
		len(framework.VendorCompatibilityProfiles) > 0
}

func validateEAPMethodList(path string, methods []string, allowEmpty bool) (map[string]struct{}, error) {
	seen := map[string]struct{}{}
	if len(methods) == 0 && !allowEmpty {
		return seen, fmt.Errorf("%s must include at least one method", path)
	}
	for i, raw := range methods {
		method := normalizeEAPMethod(raw)
		if method == "" {
			return seen, fmt.Errorf("%s[%d] cannot be empty", path, i)
		}
		if !validEAPMethod(method) {
			return seen, fmt.Errorf("%s[%d] %q is invalid", path, i, raw)
		}
		if _, exists := seen[method]; exists {
			return seen, fmt.Errorf("%s[%d] %q duplicates an earlier method", path, i, raw)
		}
		seen[method] = struct{}{}
	}
	return seen, nil
}

func validateEAPInnerMethodList(path string, methods []string, allowEmpty bool) (map[string]struct{}, error) {
	seen := map[string]struct{}{}
	if len(methods) == 0 && !allowEmpty {
		return seen, fmt.Errorf("%s must include at least one inner method", path)
	}
	for i, raw := range methods {
		method := normalizeEAPInnerMethod(raw)
		if method == "" {
			return seen, fmt.Errorf("%s[%d] cannot be empty", path, i)
		}
		if !validEAPInnerMethod(method) {
			return seen, fmt.Errorf("%s[%d] %q is invalid", path, i, raw)
		}
		if _, exists := seen[method]; exists {
			return seen, fmt.Errorf("%s[%d] %q duplicates an earlier inner method", path, i, raw)
		}
		seen[method] = struct{}{}
	}
	return seen, nil
}

func validateEAPTLSVersionBounds(path, minVersion, maxVersion string) error {
	if minVersion == "" && maxVersion == "" {
		return nil
	}
	min := strings.TrimSpace(minVersion)
	max := strings.TrimSpace(maxVersion)
	switch min {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("%s.min_tls_version %q is invalid", path, minVersion)
	}
	switch max {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("%s.max_tls_version %q is invalid", path, maxVersion)
	}
	if min == "1.3" && max == "1.2" {
		return fmt.Errorf("%s.min_tls_version cannot be greater than max_tls_version", path)
	}
	return nil
}

func normalizeEAPMethod(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "eap-tls":
		return "tls"
	case "eap-ttls":
		return "ttls"
	case "eap-peap":
		return "peap"
	case "eap-fast":
		return "fast"
	case "eap-pwd":
		return "pwd"
	case "eap-sim":
		return "sim"
	case "eap-aka":
		return "aka"
	case "eap-aka-prime", "eap-aka'":
		return "aka-prime"
	default:
		return value
	}
}

func normalizeEAPInnerMethod(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "mschap", "mschap-v2", "ms-chap-v2":
		return "mschapv2"
	case "eap-tls":
		return "tls"
	default:
		return value
	}
}

func normalizeEAPIdentitySourceName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validEAPMethod(method string) bool {
	switch method {
	case "peap", "ttls", "tls", "teap", "fast", "pwd", "sim", "aka", "aka-prime", "md5", "leap", "gtc":
		return true
	default:
		return false
	}
}

func validEAPInnerMethod(method string) bool {
	switch method {
	case "mschapv2", "pap", "chap", "gtc", "tls", "md5":
		return true
	default:
		return false
	}
}

func validEAPPolicyToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '-', '_', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func validEAPAuthorityID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validEAPSecretRefOrEmpty(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return strings.Contains(value, ":")
}

func validEAPSIMAKANetworkName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) > 253 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '-', '_':
			continue
		default:
			return false
		}
	}
	return true
}

func strongEAPPWDGroup(group int) bool {
	switch group {
	case 19, 20, 21, 25, 26:
		return true
	default:
		return false
	}
}

func validateRadiusOpaquePassThrough(cfg RadiusOpaquePassThroughConfig) error {
	if cfg.MaxAttributesPerPacket < 0 || cfg.MaxAttributesPerPacket > 128 {
		return fmt.Errorf("radius.vendor.opaque_pass_through.max_attributes_per_packet must be between 1 and 128 when set")
	}
	if cfg.MaxAttributeBytes < 0 || cfg.MaxAttributeBytes > 249 {
		return fmt.Errorf("radius.vendor.opaque_pass_through.max_attribute_bytes must be between 1 and 249 when set")
	}
	if cfg.MaxTotalBytesPerPacket < 0 || cfg.MaxTotalBytesPerPacket > 4096 {
		return fmt.Errorf("radius.vendor.opaque_pass_through.max_total_bytes_per_packet must be between 1 and 4096 when set")
	}
	effectiveMaxAttr := cfg.MaxAttributeBytes
	if effectiveMaxAttr == 0 {
		effectiveMaxAttr = 249
	}
	effectiveMaxTotal := cfg.MaxTotalBytesPerPacket
	if effectiveMaxTotal == 0 {
		effectiveMaxTotal = 2048
	}
	if effectiveMaxTotal < effectiveMaxAttr {
		return errors.New("radius.vendor.opaque_pass_through.max_total_bytes_per_packet must be greater than or equal to max_attribute_bytes")
	}
	seen := map[string]struct{}{}
	for i, rule := range cfg.Rules {
		direction := strings.ToLower(strings.TrimSpace(rule.Direction))
		if direction == "" {
			direction = "any"
		}
		if !validOpaquePassThroughDirection(direction) {
			return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].direction %q is invalid", i, rule.Direction)
		}
		kind := strings.ToLower(strings.TrimSpace(rule.Kind))
		if kind == "vsa" {
			kind = "vendor_attribute"
		}
		if !validOpaquePassThroughKind(kind) {
			return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].kind %q is invalid", i, rule.Kind)
		}
		if rule.MaxAttributeBytes < 0 || rule.MaxAttributeBytes > effectiveMaxAttr {
			return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].max_attribute_bytes must be between 0 and the policy max", i)
		}
		if strings.ContainsAny(rule.Description, "\r\n\x00") || len(rule.Description) > 240 {
			return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].description is invalid", i)
		}
		switch kind {
		case "standard":
			if rule.VendorID != 0 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].vendor_id must be empty for standard rules", i)
			}
			if rule.Type < 1 || rule.Type > 255 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].type must be between 1 and 255 for standard rules", i)
			}
			if name, denied := deniedOpaqueStandardRadiusType(rule.Type); denied {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].type %d (%s) cannot be passed opaquely", i, rule.Type, name)
			}
		case "vendor":
			if rule.VendorID < 1 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].vendor_id is required for vendor rules", i)
			}
			if rule.Type != 0 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].type must be empty for vendor rules", i)
			}
		case "vendor_attribute":
			if rule.VendorID < 1 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].vendor_id is required for vendor_attribute rules", i)
			}
			if rule.Type < 1 {
				return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d].type is required for vendor_attribute rules", i)
			}
		}
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", direction, kind, rule.VendorID, rule.Type)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("radius.vendor.opaque_pass_through.rules[%d] duplicates an earlier rule", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateRadiusPacketHardening(cfg RadiusPacketHardeningConfig) error {
	mode := strings.ToLower(strings.TrimSpace(cfg.RequireMessageAuthenticator))
	switch mode {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("radius.packet_hardening.require_message_authenticator %q must be auto, always, or never", cfg.RequireMessageAuthenticator)
	}
	if cfg.MaxPacketBytes < 0 || cfg.MaxPacketBytes > 4096 {
		return fmt.Errorf("radius.packet_hardening.max_packet_bytes must be between 1 and 4096 when set")
	}
	if cfg.MaxPacketBytes > 0 && cfg.MaxPacketBytes < 20 {
		return fmt.Errorf("radius.packet_hardening.max_packet_bytes must be at least 20")
	}
	if cfg.MaxAttributesPerPacket < 0 || cfg.MaxAttributesPerPacket > 256 {
		return fmt.Errorf("radius.packet_hardening.max_attributes_per_packet must be between 1 and 256 when set")
	}
	if cfg.MaxProxyStateAttributes < 0 || cfg.MaxProxyStateAttributes > 32 {
		return fmt.Errorf("radius.packet_hardening.max_proxy_state_attributes must be between 0 and 32")
	}
	if cfg.MaxProxyStateBytes < 0 || cfg.MaxProxyStateBytes > 4096 {
		return fmt.Errorf("radius.packet_hardening.max_proxy_state_bytes must be between 1 and 4096 when set")
	}
	if cfg.ReplayWindowSeconds < 0 || cfg.ReplayWindowSeconds > 3600 {
		return fmt.Errorf("radius.packet_hardening.replay_window_seconds must be between 1 and 3600 when set")
	}
	if cfg.ReplayCacheMaxEntries < 0 || cfg.ReplayCacheMaxEntries > 1000000 {
		return fmt.Errorf("radius.packet_hardening.replay_cache_max_entries must be between 1 and 1000000 when set")
	}
	if cfg.PerClientRateLimitPerSecond < 0 || cfg.PerClientRateLimitPerSecond > 100000 {
		return fmt.Errorf("radius.packet_hardening.per_client_rate_limit_per_second must be between 1 and 100000 when set")
	}
	if cfg.PerClientBurst < 0 || cfg.PerClientBurst > 1000000 {
		return fmt.Errorf("radius.packet_hardening.per_client_burst must be between 1 and 1000000 when set")
	}
	if cfg.EventRetentionLimit < 0 || cfg.EventRetentionLimit > 1000000 {
		return fmt.Errorf("radius.packet_hardening.event_retention_limit must be between 1 and 1000000 when set")
	}
	for i, cidr := range cfg.TrustedProxyCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			return fmt.Errorf("radius.packet_hardening.trusted_proxy_cidrs[%d] cannot be empty", i)
		}
		if net.ParseIP(cidr) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("radius.packet_hardening.trusted_proxy_cidrs[%d] %q must be an IP address or CIDR", i, cidr)
		}
	}
	return nil
}

func validOpaquePassThroughDirection(value string) bool {
	switch value {
	case "any", "inbound_request", "outbound_reply", "accounting_request", "accounting_response",
		"coa_request", "coa_response", "disconnect_request", "disconnect_response", "proxy_request", "proxy_response":
		return true
	default:
		return false
	}
}

func validOpaquePassThroughKind(value string) bool {
	switch value {
	case "standard", "vendor", "vendor_attribute":
		return true
	default:
		return false
	}
}

func deniedOpaqueStandardRadiusType(typ int) (string, bool) {
	switch typ {
	case 2:
		return "User-Password", true
	case 3:
		return "CHAP-Password", true
	case 26:
		return "Vendor-Specific", true
	case 60:
		return "CHAP-Challenge", true
	case 69:
		return "Tunnel-Password", true
	case 79:
		return "EAP-Message", true
	case 80:
		return "Message-Authenticator", true
	default:
		return "", false
	}
}
