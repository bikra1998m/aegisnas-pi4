package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const AddressPolicyCompilerVersion = 1

type AddressPolicyCompileRequest struct {
	Role                string   `json:"role"`
	SessionID           string   `json:"session_id,omitempty"`
	AcctSessionID       string   `json:"acct_session_id,omitempty"`
	CallingStationID    string   `json:"calling_station_id,omitempty"`
	NASIdentifier       string   `json:"nas_identifier,omitempty"`
	NASIPAddress        string   `json:"nas_ip_address,omitempty"`
	Owner               string   `json:"owner,omitempty"`
	LifecycleAction     string   `json:"lifecycle_action,omitempty"`
	IPv4Address         string   `json:"ipv4_address,omitempty"`
	IPv4Pool            string   `json:"ipv4_pool,omitempty"`
	IPv6Address         string   `json:"ipv6_address,omitempty"`
	IPv6Pool            string   `json:"ipv6_pool,omitempty"`
	IPv6Prefix          string   `json:"ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix string   `json:"delegated_ipv6_prefix,omitempty"`
	DelegatedIPv6Pool   string   `json:"delegated_ipv6_pool,omitempty"`
	RAPrefix            string   `json:"ra_prefix,omitempty"`
	RAPrefixPool        string   `json:"ra_prefix_pool,omitempty"`
	DHCPv6Mode          string   `json:"dhcpv6_mode,omitempty"`
	RAMode              string   `json:"ra_mode,omitempty"`
	PackKeys            []string `json:"pack_keys,omitempty"`
}

type AddressPolicyDecompileRequest struct {
	PackKey    string                   `json:"pack_key,omitempty"`
	Attributes []AddressPolicyAttribute `json:"attributes"`
	Role       string                   `json:"role,omitempty"`
	SessionID  string                   `json:"session_id,omitempty"`
}

type AddressPolicyCompileResult struct {
	CompilerVersion int                       `json:"compiler_version"`
	Status          string                    `json:"status"`
	Message         string                    `json:"message"`
	Decision        AddressPolicyDecision     `json:"decision"`
	Attributes      []AddressPolicyAttribute  `json:"attributes"`
	Summary         AddressPolicySummary      `json:"summary"`
	Diagnostics     []AddressPolicyDiagnostic `json:"diagnostics"`
	Fingerprint     string                    `json:"fingerprint"`
	RFCs            []string                  `json:"rfcs"`
}

type AddressPolicyDecompileResult = AddressPolicyCompileResult

type AddressPolicyDecision struct {
	Role                     string   `json:"role,omitempty"`
	SessionID                string   `json:"session_id,omitempty"`
	AcctSessionID            string   `json:"acct_session_id,omitempty"`
	PolicyMatched            bool     `json:"policy_matched"`
	PolicySource             string   `json:"policy_source"`
	LifecycleAction          string   `json:"lifecycle_action"`
	Owner                    string   `json:"owner,omitempty"`
	Revision                 string   `json:"revision,omitempty"`
	OwnershipKey             string   `json:"ownership_key,omitempty"`
	SelectionKey             string   `json:"selection_key,omitempty"`
	IPv4Address              string   `json:"ipv4_address,omitempty"`
	IPv4Pool                 string   `json:"ipv4_pool,omitempty"`
	IPv4Gateway              string   `json:"ipv4_gateway,omitempty"`
	IPv4Netmask              string   `json:"ipv4_netmask,omitempty"`
	IPv6Address              string   `json:"ipv6_address,omitempty"`
	IPv6Pool                 string   `json:"ipv6_pool,omitempty"`
	IPv6Prefix               string   `json:"ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix      string   `json:"delegated_ipv6_prefix,omitempty"`
	DelegatedIPv6Pool        string   `json:"delegated_ipv6_pool,omitempty"`
	RAPrefix                 string   `json:"ra_prefix,omitempty"`
	RAPrefixPool             string   `json:"ra_prefix_pool,omitempty"`
	DHCPv6Mode               string   `json:"dhcpv6_mode,omitempty"`
	RAMode                   string   `json:"ra_mode,omitempty"`
	DHCPv6Managed            bool     `json:"dhcpv6_managed"`
	DHCPv6OtherConfig        bool     `json:"dhcpv6_other_config"`
	PrefixDelegation         bool     `json:"prefix_delegation"`
	RAManagedFlag            bool     `json:"ra_managed_flag"`
	RAOtherConfigFlag        bool     `json:"ra_other_config_flag"`
	RouterPreference         string   `json:"router_preference,omitempty"`
	ValidLifetimeSeconds     int      `json:"valid_lifetime_seconds,omitempty"`
	PreferredLifetimeSeconds int      `json:"preferred_lifetime_seconds,omitempty"`
	DNSServers               []string `json:"dns_servers,omitempty"`
	DomainSearch             []string `json:"domain_search,omitempty"`
	VendorPacks              []string `json:"vendor_packs,omitempty"`
	Withdraw                 bool     `json:"withdraw"`
}

type AddressPolicyAttribute struct {
	PackKey string `json:"pack_key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Quoted  bool   `json:"quoted"`
	Purpose string `json:"purpose"`
}

type AddressPolicySummary struct {
	PolicyCount          int `json:"policy_count"`
	PoolCount            int `json:"pool_count"`
	AssignmentCount      int `json:"assignment_count"`
	IPv4AssignmentCount  int `json:"ipv4_assignment_count"`
	IPv6AssignmentCount  int `json:"ipv6_assignment_count"`
	DelegatedPrefixCount int `json:"delegated_prefix_count"`
	RAPrefixCount        int `json:"ra_prefix_count"`
	WithdrawCount        int `json:"withdraw_count"`
	AttributeCount       int `json:"attribute_count"`
	DiagnosticCount      int `json:"diagnostic_count"`
}

type AddressPolicyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
	PackKey  string `json:"pack_key,omitempty"`
	Pool     string `json:"pool,omitempty"`
	Value    string `json:"value,omitempty"`
}

type AddressPolicyReport struct {
	CompilerVersion int                              `json:"compiler_version"`
	Enabled         bool                             `json:"enabled"`
	FailClosed      bool                             `json:"fail_closed"`
	MaxAssignments  int                              `json:"max_assignments"`
	DefaultOwner    string                           `json:"default_owner"`
	ConflictMode    string                           `json:"conflict_mode"`
	StopWithdrawal  bool                             `json:"stop_withdrawal"`
	DHCPv6          config.RadiusDHCPv6PolicyConfig  `json:"dhcpv6"`
	RA              config.RadiusRAPolicyConfig      `json:"ra"`
	Summary         AddressPolicyCatalogSummary      `json:"summary"`
	Capabilities    []AddressPolicyCapability        `json:"capabilities"`
	Pools           []config.RadiusAddressPoolConfig `json:"pools"`
	Policies        []config.RadiusAddressRolePolicy `json:"policies"`
	RFCs            []string                         `json:"rfcs"`
}

type AddressPolicyCatalogSummary struct {
	PolicyCount          int `json:"policy_count"`
	PoolCount            int `json:"pool_count"`
	IPv4PoolCount        int `json:"ipv4_pool_count"`
	IPv6PoolCount        int `json:"ipv6_pool_count"`
	DelegatedPolicyCount int `json:"delegated_policy_count"`
	RAPolicyCount        int `json:"ra_policy_count"`
}

type AddressPolicyCapability struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Status     string   `json:"status"`
	Attributes []string `json:"attributes"`
	Vendors    []string `json:"vendors"`
	Notes      string   `json:"notes,omitempty"`
}

func BuildAddressPolicyReport(cfg *config.Config) AddressPolicyReport {
	policy := config.RadiusAddressPolicyConfig{}
	if cfg != nil {
		policy = cfg.Radius.AddressPolicy
	}
	report := AddressPolicyReport{
		CompilerVersion: AddressPolicyCompilerVersion,
		Enabled:         policy.Enabled,
		FailClosed:      policy.FailClosed,
		MaxAssignments:  effectiveAddressPolicyMaxAssignments(policy),
		DefaultOwner:    effectiveAddressPolicyOwner(policy.DefaultOwner),
		ConflictMode:    effectiveAddressPolicyConflictMode(policy.ConflictMode),
		StopWithdrawal:  policy.StopWithdrawal,
		DHCPv6:          policy.DHCPv6,
		RA:              policy.RA,
		Pools:           append([]config.RadiusAddressPoolConfig(nil), policy.Pools...),
		Policies:        append([]config.RadiusAddressRolePolicy(nil), policy.RolePolicies...),
		RFCs:            addressPolicyRFCs(),
		Capabilities: []AddressPolicyCapability{
			{Key: "ipv4_framed_address", Label: "IPv4 Framed Address And Pool", Status: "implemented", Attributes: []string{"Framed-IP-Address", "Framed-IP-Netmask", "Framed-Pool", "AegisNAS-Framed-IP-Address", "AegisNAS-IPv4-Pool"}, Vendors: []string{"Cisco", "Juniper ERX", "Huawei", "MikroTik", "BNG/BRAS", "standards-based"}},
			{Key: "ipv6_framed_address", Label: "IPv6 Framed Address And Pool", Status: "implemented", Attributes: []string{"Framed-IPv6-Address", "Framed-IPv6-Prefix", "Framed-IPv6-Pool", "AegisNAS-Framed-IPv6-Address", "AegisNAS-Framed-IPv6-Prefix"}, Vendors: []string{"Cisco", "Juniper ERX", "Huawei", "Nokia", "standards-based"}},
			{Key: "delegated_ipv6_prefix", Label: "Delegated IPv6 Prefix", Status: "implemented", Attributes: []string{"Delegated-IPv6-Prefix", "AegisNAS-Delegated-IPv6-Prefix", "Mikrotik-Delegated-IPv6-Pool", "Huawei-Delegated-IPv6-Prefix-Pool"}, Vendors: []string{"MikroTik", "Huawei", "Juniper ERX", "Nokia", "BNG/BRAS"}},
			{Key: "dhcpv6_ra_metadata", Label: "DHCPv6 And RA Metadata", Status: "implemented", Attributes: []string{"AegisNAS-DHCPv6-Mode", "AegisNAS-RA-Mode", "AegisNAS-RA-Prefix"}, Vendors: []string{"DHCPv6/RA capable NAS", "BNG/BRAS"}, Notes: "Native DHCPv6/RA packet emission remains release certification evidence per target adapter."},
			{Key: "address_ownership", Label: "Address Ownership Lifecycle", Status: "implemented", Attributes: []string{"AegisNAS-Address-Policy", "AegisNAS-Address-Owner", "AegisNAS-Address-Revision"}, Vendors: []string{"all RADIUS dynamic authorization capable NAS"}, Notes: "Software records revisioned ownership and withdraws on accounting Stop when enabled."},
		},
	}
	report.Summary.PolicyCount = len(policy.RolePolicies)
	report.Summary.PoolCount = len(policy.Pools)
	for _, pool := range policy.Pools {
		switch normalizedAddressPolicyFamily(pool.Family, pool.CIDR) {
		case "ipv4":
			report.Summary.IPv4PoolCount++
		case "ipv6":
			report.Summary.IPv6PoolCount++
		}
	}
	for _, rolePolicy := range policy.RolePolicies {
		if strings.TrimSpace(rolePolicy.DelegatedIPv6Pool) != "" || strings.TrimSpace(rolePolicy.DelegatedIPv6Prefix) != "" {
			report.Summary.DelegatedPolicyCount++
		}
		if strings.TrimSpace(rolePolicy.RAPrefixPool) != "" || strings.TrimSpace(rolePolicy.RAPrefix) != "" {
			report.Summary.RAPolicyCount++
		}
	}
	return report
}

func CompileAddressPolicy(cfg *config.Config, req AddressPolicyCompileRequest) AddressPolicyCompileResult {
	result := AddressPolicyCompileResult{
		CompilerVersion: AddressPolicyCompilerVersion,
		Status:          "ready",
		RFCs:            addressPolicyRFCs(),
	}
	if cfg == nil {
		result.Status = "blocked"
		result.Message = "configuration is required"
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "missing_config", Message: result.Message})
		finalizeAddressPolicyResult(&result)
		return result
	}
	policy := cfg.Radius.AddressPolicy
	result.Summary.PolicyCount = len(policy.RolePolicies)
	result.Summary.PoolCount = len(policy.Pools)
	if !policy.Enabled {
		result.Status = "blocked"
		result.Message = "address policy compiler is disabled"
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "disabled", Message: result.Message, Field: "radius.address_policy.enabled"})
		finalizeAddressPolicyResult(&result)
		return result
	}

	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "default"
	}
	result.Decision.Role = role
	result.Decision.SessionID = strings.TrimSpace(req.SessionID)
	result.Decision.AcctSessionID = strings.TrimSpace(req.AcctSessionID)
	result.Decision.LifecycleAction = normalizeAddressPolicyLifecycleAction(req.LifecycleAction)
	result.Decision.Owner = firstReplyValue(strings.TrimSpace(req.Owner), effectiveAddressPolicyOwner(policy.DefaultOwner))
	result.Decision.PolicySource = "request"
	result.Decision.SelectionKey = addressPolicySelectionKey(req, role)
	result.Decision.DHCPv6Managed = policy.DHCPv6.ManagedAddress
	result.Decision.DHCPv6OtherConfig = policy.DHCPv6.OtherConfig
	result.Decision.PrefixDelegation = policy.DHCPv6.PrefixDelegation
	result.Decision.RAManagedFlag = policy.RA.ManagedFlag
	result.Decision.RAOtherConfigFlag = policy.RA.OtherConfigFlag
	result.Decision.RouterPreference = effectiveAddressPolicyRouterPreference(policy.RA.DefaultRouterPreference)
	result.Decision.ValidLifetimeSeconds = firstPositiveInt(policy.RA.ValidLifetimeSeconds, policy.DHCPv6.ValidLifetimeSeconds)
	result.Decision.PreferredLifetimeSeconds = firstPositiveInt(policy.RA.PreferredLifetimeSeconds, policy.DHCPv6.PreferredLifetimeSeconds)
	result.Decision.DNSServers = normalizeAddressPolicyList(append(append([]string{}, policy.DHCPv6.DNSServers...), policy.RA.RDNSS...))
	result.Decision.DomainSearch = normalizeAddressPolicyList(append(append([]string{}, policy.DHCPv6.DomainSearch...), policy.RA.DNSSL...))

	pools := addressPolicyPoolsByName(policy.Pools)
	if rolePolicy, matched := addressPolicyForRole(policy.RolePolicies, role); matched {
		result.Decision.PolicyMatched = true
		result.Decision.PolicySource = "radius.address_policy.role_policies"
		result.Decision.Owner = firstReplyValue(strings.TrimSpace(rolePolicy.Owner), result.Decision.Owner)
		result.Decision.VendorPacks = normalizeAddressPolicyPackKeys(rolePolicy.VendorPacks)
		applyAddressPolicyRoleIntent(&result, rolePolicy)
	}
	applyAddressPolicyRequestIntent(&result, req, effectiveAddressPolicyConflictMode(policy.ConflictMode))
	resolveAddressPolicyPools(&result, policy, pools)
	applyAddressPolicyLifecycle(&result, policy)
	validateCompiledAddressDecision(&result, policy)
	result.Decision.Revision = addressPolicyRevision(result.Decision)
	result.Decision.OwnershipKey = addressPolicyOwnershipKey(result.Decision)
	result.Attributes = BuildAddressPolicyAttributes(result.Decision, effectiveAddressPolicyPackKeys(req.PackKeys, result.Decision.VendorPacks, cfg.Radius.Vendor.CompatibilityPacks))
	finalizeAddressPolicyResult(&result)
	return result
}

func DecompileAddressPolicyAttributes(req AddressPolicyDecompileRequest) AddressPolicyDecompileResult {
	result := AddressPolicyCompileResult{
		CompilerVersion: AddressPolicyCompilerVersion,
		Status:          "decompiled",
		RFCs:            addressPolicyRFCs(),
		Attributes:      append([]AddressPolicyAttribute(nil), req.Attributes...),
	}
	packKey := productconfigs.NormalizeVendorCompatibilityPackKey(req.PackKey)
	if packKey == "" {
		packKey = productconfigs.VendorPackStandard
	}
	result.Decision.Role = strings.TrimSpace(req.Role)
	result.Decision.SessionID = strings.TrimSpace(req.SessionID)
	result.Decision.PolicySource = "decompile"
	result.Decision.LifecycleAction = "authorize"
	result.Decision.Owner = "aegisnas"
	result.Decision.VendorPacks = []string{packKey}

	for index, attr := range req.Attributes {
		name := strings.ToLower(strings.TrimSpace(attr.Name))
		value := strings.TrimSpace(strings.Trim(attr.Value, `"`))
		if name == "" || value == "" {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "empty_attribute", Message: "empty address attribute was ignored", Field: fmt.Sprintf("attributes[%d]", index), PackKey: packKey})
			continue
		}
		switch name {
		case "framed-ip-address", "aegisnas-framed-ip-address":
			result.Decision.IPv4Address = normalizeAddressPolicyIPValue(&result, value, "ipv4", attr.Name)
		case "framed-ip-netmask":
			result.Decision.IPv4Netmask = value
		case "framed-pool", "aegisnas-ipv4-pool":
			result.Decision.IPv4Pool = value
		case "framed-ipv6-address", "aegisnas-framed-ipv6-address":
			result.Decision.IPv6Address = normalizeAddressPolicyIPValue(&result, value, "ipv6", attr.Name)
		case "framed-ipv6-prefix", "aegisnas-framed-ipv6-prefix":
			result.Decision.IPv6Prefix = normalizeAddressPolicyPrefixValue(&result, value, attr.Name)
		case "delegated-ipv6-prefix", "aegisnas-delegated-ipv6-prefix":
			result.Decision.DelegatedIPv6Prefix = normalizeAddressPolicyPrefixValue(&result, value, attr.Name)
		case "framed-ipv6-pool", "aegisnas-ipv6-pool":
			result.Decision.IPv6Pool = value
		case "aegisnas-delegated-ipv6-pool":
			result.Decision.DelegatedIPv6Pool = value
		case "aegisnas-ra-prefix-pool":
			result.Decision.RAPrefixPool = value
		case "aegisnas-ra-prefix":
			result.Decision.RAPrefix = normalizeAddressPolicyPrefixValue(&result, value, attr.Name)
		case "aegisnas-address-policy":
			result.Decision.LifecycleAction = normalizeAddressPolicyLifecycleAction(value)
		case "aegisnas-address-owner":
			result.Decision.Owner = value
		case "aegisnas-address-revision":
			result.Decision.Revision = value
		case "aegisnas-dhcpv6-mode":
			result.Decision.DHCPv6Mode = normalizeAddressPolicyDHCPv6Mode(value)
		case "aegisnas-ra-mode":
			result.Decision.RAMode = normalizeAddressPolicyRAMode(value)
		case "cisco-avpair", "juniper-av-pair", "huawei-avpair", "h3c-av-pair", "nokia-avpair":
			decompileVendorAddressAVPair(&result, value, attr.Name)
		case "juniper-ip-pool-name", "huawei-framed-pool":
			result.Decision.IPv4Pool = value
		case "mikrotik-delegated-ipv6-pool", "huawei-delegated-ipv6-prefix-pool":
			result.Decision.DelegatedIPv6Pool = value
		case "huawei-framed-ipv6-address":
			result.Decision.IPv6Address = normalizeAddressPolicyIPValue(&result, value, "ipv6", attr.Name)
		}
	}
	if result.Decision.LifecycleAction == "" {
		result.Decision.LifecycleAction = "authorize"
	}
	if result.Decision.Owner == "" {
		result.Decision.Owner = "aegisnas"
	}
	validateCompiledAddressDecision(&result, config.RadiusAddressPolicyConfig{Enabled: true, MaxAssignments: 4096, DefaultOwner: "aegisnas", ConflictMode: "warn"})
	if result.Decision.Revision == "" {
		result.Decision.Revision = addressPolicyRevision(result.Decision)
	}
	result.Decision.OwnershipKey = addressPolicyOwnershipKey(result.Decision)
	result.Message = fmt.Sprintf("address policy decompiled %d attribute(s)", len(req.Attributes))
	finalizeAddressPolicyResult(&result)
	return result
}

func BuildAddressPolicyAttributes(decision AddressPolicyDecision, packKeys []string) []AddressPolicyAttribute {
	packKeys = normalizeAddressPolicyPackKeys(packKeys)
	if len(packKeys) == 0 {
		packKeys = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
	}
	attrs := make([]AddressPolicyAttribute, 0, 16)
	appendAttr := func(pack, name, value, purpose string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		attrs = append(attrs, AddressPolicyAttribute{PackKey: pack, Name: name, Value: value, Quoted: quoted, Purpose: purpose})
	}
	withdraw := decision.Withdraw || decision.LifecycleAction == "withdraw" || decision.LifecycleAction == "accounting-stop"
	for _, pack := range packKeys {
		switch pack {
		case productconfigs.VendorPackStandard:
			if withdraw {
				continue
			}
			appendAttr(pack, "Framed-IP-Address", decision.IPv4Address, "ipv4_address", false)
			appendAttr(pack, "Framed-IP-Netmask", decision.IPv4Netmask, "ipv4_netmask", false)
			appendAttr(pack, "Framed-Pool", decision.IPv4Pool, "ipv4_pool", true)
			appendAttr(pack, "Framed-IPv6-Address", decision.IPv6Address, "ipv6_address", false)
			appendAttr(pack, "Framed-IPv6-Prefix", decision.IPv6Prefix, "ipv6_prefix", false)
			appendAttr(pack, "Delegated-IPv6-Prefix", decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix", false)
			appendAttr(pack, "Framed-IPv6-Pool", firstReplyValue(decision.IPv6Pool, decision.DelegatedIPv6Pool), "ipv6_pool", true)
		case productconfigs.VendorPackAegisNAS:
			appendAttr(pack, "AegisNAS-Address-Policy", decision.LifecycleAction, "policy", true)
			appendAttr(pack, "AegisNAS-Address-Owner", decision.Owner, "owner", true)
			appendAttr(pack, "AegisNAS-Address-Revision", firstReplyValue(decision.Revision, addressPolicyRevision(decision)), "revision", true)
			appendAttr(pack, "AegisNAS-DHCPv6-Mode", decision.DHCPv6Mode, "dhcpv6_mode", true)
			appendAttr(pack, "AegisNAS-RA-Mode", decision.RAMode, "ra_mode", true)
			if withdraw {
				continue
			}
			appendAttr(pack, "AegisNAS-IPv4-Pool", decision.IPv4Pool, "ipv4_pool", true)
			appendAttr(pack, "AegisNAS-IPv6-Pool", decision.IPv6Pool, "ipv6_pool", true)
			appendAttr(pack, "AegisNAS-Delegated-IPv6-Pool", decision.DelegatedIPv6Pool, "delegated_ipv6_pool", true)
			appendAttr(pack, "AegisNAS-RA-Prefix-Pool", decision.RAPrefixPool, "ra_prefix_pool", true)
			appendAttr(pack, "AegisNAS-Framed-IP-Address", decision.IPv4Address, "ipv4_address", true)
			appendAttr(pack, "AegisNAS-Framed-IPv6-Address", decision.IPv6Address, "ipv6_address", true)
			appendAttr(pack, "AegisNAS-Framed-IPv6-Prefix", decision.IPv6Prefix, "ipv6_prefix", true)
			appendAttr(pack, "AegisNAS-Delegated-IPv6-Prefix", decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix", true)
			appendAttr(pack, "AegisNAS-RA-Prefix", decision.RAPrefix, "ra_prefix", true)
		case productconfigs.VendorPackMikroTik:
			if withdraw {
				continue
			}
			appendAttr(pack, "Mikrotik-Delegated-IPv6-Pool", decision.DelegatedIPv6Pool, "delegated_ipv6_pool", true)
		case productconfigs.VendorPackJuniper:
			if withdraw {
				appendAttr(pack, "Juniper-AV-Pair", "address-policy=withdraw", "policy", true)
				continue
			}
			appendAttr(pack, "Juniper-Ip-Pool-Name", decision.IPv4Pool, "ipv4_pool", true)
			appendAddressAVPairAttributes(pack, "Juniper-AV-Pair", decision, appendAttr)
		case productconfigs.VendorPackCisco:
			appendAddressAVPairAttributes(pack, "Cisco-AVPair", decision, appendAttr)
		case productconfigs.VendorPackHuawei:
			if withdraw {
				appendAttr(pack, "Huawei-AVpair", "address-policy=withdraw", "policy", true)
				continue
			}
			appendAttr(pack, "Huawei-Framed-Pool", decision.IPv4Pool, "ipv4_pool", true)
			appendAttr(pack, "Huawei-Framed-IPv6-Address", decision.IPv6Address, "ipv6_address", false)
			appendAttr(pack, "Huawei-Delegated-IPv6-Prefix-Pool", decision.DelegatedIPv6Pool, "delegated_ipv6_pool", true)
			appendAddressAVPairAttributes(pack, "Huawei-AVpair", decision, appendAttr)
		case productconfigs.VendorPackH3C:
			appendAddressAVPairAttributes(pack, "H3C-Av-Pair", decision, appendAttr)
		case productconfigs.VendorPackNokia:
			appendAddressAVPairAttributes(pack, "Nokia-AVPair", decision, appendAttr)
		}
	}
	return attrs
}

func ApplyAddressPolicyToReplyAttributes(attrs *ReplyAttributes, result AddressPolicyCompileResult) {
	if attrs == nil || result.Status == "blocked" {
		return
	}
	decision := result.Decision
	attrs.AddressOwner = decision.Owner
	attrs.AddressRevision = firstReplyValue(decision.Revision, addressPolicyRevision(decision))
	attrs.AddressPolicyMode = decision.LifecycleAction
	attrs.AddressPolicyFingerprint = result.Fingerprint
	attrs.FramedIPAddress = decision.IPv4Address
	attrs.FramedIPNetmask = decision.IPv4Netmask
	attrs.FramedPool = decision.IPv4Pool
	attrs.FramedIPv6Address = decision.IPv6Address
	attrs.FramedIPv6Prefix = decision.IPv6Prefix
	attrs.DelegatedIPv6Prefix = decision.DelegatedIPv6Prefix
	attrs.FramedIPv6Pool = firstReplyValue(decision.IPv6Pool, decision.DelegatedIPv6Pool)
	attrs.RAPrefix = decision.RAPrefix
	attrs.DHCPv6Mode = decision.DHCPv6Mode
	attrs.RAMode = decision.RAMode
}

func ApplyConfiguredAddressPolicyToReplyAttributes(cfg *config.Config, attrs *ReplyAttributes, req AddressPolicyCompileRequest) (AddressPolicyCompileResult, bool) {
	if cfg == nil || attrs == nil || !cfg.Radius.AddressPolicy.Enabled {
		return AddressPolicyCompileResult{}, false
	}
	if strings.TrimSpace(req.Role) == "" {
		req.Role = replyRole(attrs)
	}
	result := CompileAddressPolicy(cfg, req)
	if result.Status == "blocked" || result.Decision.Withdraw {
		return result, false
	}
	if !result.Decision.PolicyMatched && !addressPolicyRequestHasIntent(req) {
		return result, false
	}
	ApplyAddressPolicyToReplyAttributes(attrs, result)
	return result, true
}

func applyAddressPolicyRoleIntent(result *AddressPolicyCompileResult, rolePolicy config.RadiusAddressRolePolicy) {
	decision := &result.Decision
	decision.IPv4Address = strings.TrimSpace(rolePolicy.IPv4Address)
	decision.IPv4Pool = strings.TrimSpace(rolePolicy.IPv4Pool)
	decision.IPv6Address = strings.TrimSpace(rolePolicy.IPv6Address)
	decision.IPv6Pool = strings.TrimSpace(rolePolicy.IPv6Pool)
	decision.IPv6Prefix = strings.TrimSpace(rolePolicy.IPv6Prefix)
	decision.DelegatedIPv6Prefix = strings.TrimSpace(rolePolicy.DelegatedIPv6Prefix)
	decision.DelegatedIPv6Pool = strings.TrimSpace(rolePolicy.DelegatedIPv6Pool)
	decision.RAPrefix = strings.TrimSpace(rolePolicy.RAPrefix)
	decision.RAPrefixPool = strings.TrimSpace(rolePolicy.RAPrefixPool)
	decision.DHCPv6Mode = normalizeAddressPolicyDHCPv6Mode(rolePolicy.DHCPv6Mode)
	decision.RAMode = normalizeAddressPolicyRAMode(rolePolicy.RAMode)
}

func applyAddressPolicyRequestIntent(result *AddressPolicyCompileResult, req AddressPolicyCompileRequest, conflictMode string) {
	merge := func(field string, current *string, candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if *current == "" || strings.EqualFold(*current, candidate) {
			*current = candidate
			return
		}
		switch conflictMode {
		case "prefer-request":
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "address_conflict_replaced", Message: "request address intent replaced role intent", Field: field, Value: candidate})
			*current = candidate
		case "prefer-role":
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "address_conflict_ignored", Message: "request address intent conflicted with role intent and was ignored", Field: field, Value: candidate})
		case "warn":
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "address_conflict", Message: "request address intent conflicts with role intent", Field: field, Value: candidate})
		default:
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "address_conflict", Message: "request address intent conflicts with role intent", Field: field, Value: candidate})
		}
	}
	merge("ipv4_address", &result.Decision.IPv4Address, req.IPv4Address)
	merge("ipv4_pool", &result.Decision.IPv4Pool, req.IPv4Pool)
	merge("ipv6_address", &result.Decision.IPv6Address, req.IPv6Address)
	merge("ipv6_pool", &result.Decision.IPv6Pool, req.IPv6Pool)
	merge("ipv6_prefix", &result.Decision.IPv6Prefix, req.IPv6Prefix)
	merge("delegated_ipv6_prefix", &result.Decision.DelegatedIPv6Prefix, req.DelegatedIPv6Prefix)
	merge("delegated_ipv6_pool", &result.Decision.DelegatedIPv6Pool, req.DelegatedIPv6Pool)
	merge("ra_prefix", &result.Decision.RAPrefix, req.RAPrefix)
	merge("ra_prefix_pool", &result.Decision.RAPrefixPool, req.RAPrefixPool)
	merge("dhcpv6_mode", &result.Decision.DHCPv6Mode, normalizeAddressPolicyDHCPv6Mode(req.DHCPv6Mode))
	merge("ra_mode", &result.Decision.RAMode, normalizeAddressPolicyRAMode(req.RAMode))
}

func resolveAddressPolicyPools(result *AddressPolicyCompileResult, policy config.RadiusAddressPolicyConfig, pools map[string]config.RadiusAddressPoolConfig) {
	if result == nil {
		return
	}
	resolveIPv4Pool(result, pools)
	resolveIPv6Pool(result, pools)
	resolveDelegatedPrefixPool(result, pools)
	resolveRAPrefixPool(result, pools)
	if result.Decision.DHCPv6Mode == "" {
		result.Decision.DHCPv6Mode = effectiveAddressPolicyDHCPv6Mode(policy, result.Decision)
	}
	if result.Decision.RAMode == "" {
		result.Decision.RAMode = effectiveAddressPolicyRAMode(policy, result.Decision)
	}
	result.Decision.DNSServers = normalizeAddressPolicyList(result.Decision.DNSServers)
	result.Decision.DomainSearch = normalizeAddressPolicyList(result.Decision.DomainSearch)
}

func resolveIPv4Pool(result *AddressPolicyCompileResult, pools map[string]config.RadiusAddressPoolConfig) {
	poolName := strings.TrimSpace(result.Decision.IPv4Pool)
	if poolName == "" {
		if result.Decision.IPv4Address != "" {
			result.Decision.IPv4Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv4Address, "ipv4", "ipv4_address")
		}
		return
	}
	pool, ok := pools[strings.ToLower(poolName)]
	if !ok {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_missing", Message: "IPv4 pool is not configured", Field: "ipv4_pool", Pool: poolName})
		return
	}
	if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) != "ipv4" {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_family_mismatch", Message: "IPv4 pool reference points to a non-IPv4 pool", Field: "ipv4_pool", Pool: poolName})
		return
	}
	if result.Decision.IPv4Address == "" {
		addr, err := selectAddressFromPool(pool, result.Decision.SelectionKey)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_select_failed", Message: err.Error(), Field: "ipv4_pool", Pool: poolName})
		} else {
			result.Decision.IPv4Address = addr
		}
	} else {
		result.Decision.IPv4Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv4Address, "ipv4", "ipv4_address")
	}
	result.Decision.IPv4Gateway = strings.TrimSpace(pool.Gateway)
	result.Decision.IPv4Netmask = ipv4NetmaskForCIDR(pool.CIDR)
	mergePoolMetadata(&result.Decision, pool)
}

func resolveIPv6Pool(result *AddressPolicyCompileResult, pools map[string]config.RadiusAddressPoolConfig) {
	poolName := strings.TrimSpace(result.Decision.IPv6Pool)
	if poolName == "" {
		if result.Decision.IPv6Address != "" {
			result.Decision.IPv6Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv6Address, "ipv6", "ipv6_address")
		}
		if result.Decision.IPv6Prefix != "" {
			result.Decision.IPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.IPv6Prefix, "ipv6_prefix")
		}
		return
	}
	pool, ok := pools[strings.ToLower(poolName)]
	if !ok {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_missing", Message: "IPv6 pool is not configured", Field: "ipv6_pool", Pool: poolName})
		return
	}
	if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) != "ipv6" {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_family_mismatch", Message: "IPv6 pool reference points to a non-IPv6 pool", Field: "ipv6_pool", Pool: poolName})
		return
	}
	if result.Decision.IPv6Address == "" && addressPoolProvidesAddresses(pool) {
		addr, err := selectAddressFromPool(pool, result.Decision.SelectionKey)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_select_failed", Message: err.Error(), Field: "ipv6_pool", Pool: poolName})
		} else {
			result.Decision.IPv6Address = addr
		}
	} else if result.Decision.IPv6Address != "" {
		result.Decision.IPv6Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv6Address, "ipv6", "ipv6_address")
	}
	if result.Decision.IPv6Prefix == "" && addressPoolProvidesPrefixes(pool) {
		prefix, err := selectPrefixFromPool(pool, effectiveAddressPolicyPrefixLength(pool, 64), result.Decision.SelectionKey+"|framed-prefix")
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "prefix_select_failed", Message: err.Error(), Field: "ipv6_pool", Pool: poolName})
		} else {
			result.Decision.IPv6Prefix = prefix
		}
	} else if result.Decision.IPv6Prefix != "" {
		result.Decision.IPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.IPv6Prefix, "ipv6_prefix")
	}
	mergePoolMetadata(&result.Decision, pool)
}

func resolveDelegatedPrefixPool(result *AddressPolicyCompileResult, pools map[string]config.RadiusAddressPoolConfig) {
	poolName := strings.TrimSpace(result.Decision.DelegatedIPv6Pool)
	if poolName == "" {
		if result.Decision.DelegatedIPv6Prefix != "" {
			result.Decision.DelegatedIPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix")
			result.Decision.PrefixDelegation = true
		}
		return
	}
	pool, ok := pools[strings.ToLower(poolName)]
	if !ok {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_missing", Message: "delegated IPv6 pool is not configured", Field: "delegated_ipv6_pool", Pool: poolName})
		return
	}
	if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) != "ipv6" {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_family_mismatch", Message: "delegated pool reference points to a non-IPv6 pool", Field: "delegated_ipv6_pool", Pool: poolName})
		return
	}
	if result.Decision.DelegatedIPv6Prefix == "" {
		prefix, err := selectPrefixFromPool(pool, effectiveDelegatedPrefixLength(pool), result.Decision.SelectionKey+"|delegated-prefix")
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "prefix_select_failed", Message: err.Error(), Field: "delegated_ipv6_pool", Pool: poolName})
		} else {
			result.Decision.DelegatedIPv6Prefix = prefix
		}
	} else {
		result.Decision.DelegatedIPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix")
	}
	result.Decision.PrefixDelegation = true
	mergePoolMetadata(&result.Decision, pool)
}

func resolveRAPrefixPool(result *AddressPolicyCompileResult, pools map[string]config.RadiusAddressPoolConfig) {
	poolName := strings.TrimSpace(result.Decision.RAPrefixPool)
	if poolName == "" {
		if result.Decision.RAPrefix != "" {
			result.Decision.RAPrefix = normalizeAddressPolicyPrefixValue(result, result.Decision.RAPrefix, "ra_prefix")
		}
		return
	}
	pool, ok := pools[strings.ToLower(poolName)]
	if !ok {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_missing", Message: "RA prefix pool is not configured", Field: "ra_prefix_pool", Pool: poolName})
		return
	}
	if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) != "ipv6" {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "pool_family_mismatch", Message: "RA prefix pool reference points to a non-IPv6 pool", Field: "ra_prefix_pool", Pool: poolName})
		return
	}
	if result.Decision.RAPrefix == "" {
		prefix, err := selectPrefixFromPool(pool, effectiveAddressPolicyPrefixLength(pool, 64), result.Decision.SelectionKey+"|ra-prefix")
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "prefix_select_failed", Message: err.Error(), Field: "ra_prefix_pool", Pool: poolName})
		} else {
			result.Decision.RAPrefix = prefix
		}
	} else {
		result.Decision.RAPrefix = normalizeAddressPolicyPrefixValue(result, result.Decision.RAPrefix, "ra_prefix")
	}
	mergePoolMetadata(&result.Decision, pool)
}

func mergePoolMetadata(decision *AddressPolicyDecision, pool config.RadiusAddressPoolConfig) {
	if decision == nil {
		return
	}
	if pool.ValidLifetimeSeconds > 0 {
		decision.ValidLifetimeSeconds = pool.ValidLifetimeSeconds
	}
	if pool.PreferredLifetimeSeconds > 0 {
		decision.PreferredLifetimeSeconds = pool.PreferredLifetimeSeconds
	}
	decision.DNSServers = normalizeAddressPolicyList(append(decision.DNSServers, pool.DNSServers...))
	decision.DomainSearch = normalizeAddressPolicyList(append(decision.DomainSearch, pool.DomainSearch...))
}

func applyAddressPolicyLifecycle(result *AddressPolicyCompileResult, policy config.RadiusAddressPolicyConfig) {
	if result == nil {
		return
	}
	switch result.Decision.LifecycleAction {
	case "withdraw", "accounting-stop":
		if result.Decision.LifecycleAction == "accounting-stop" && !policy.StopWithdrawal {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "stop_withdrawal_disabled", Message: "accounting Stop address withdrawal is disabled by policy"})
			return
		}
		result.Decision.Withdraw = true
	}
}

func validateCompiledAddressDecision(result *AddressPolicyCompileResult, policy config.RadiusAddressPolicyConfig) {
	if result == nil {
		return
	}
	addError := func(code, message, field, value string) {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: code, Message: message, Field: field, Value: value})
	}
	if strings.TrimSpace(result.Decision.Owner) == "" {
		addError("missing_owner", "address policy did not resolve an owner", "owner", "")
	}
	if result.Decision.IPv4Address != "" {
		result.Decision.IPv4Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv4Address, "ipv4", "ipv4_address")
	}
	if result.Decision.IPv6Address != "" {
		result.Decision.IPv6Address = normalizeAddressPolicyIPValue(result, result.Decision.IPv6Address, "ipv6", "ipv6_address")
	}
	if result.Decision.IPv6Prefix != "" {
		result.Decision.IPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.IPv6Prefix, "ipv6_prefix")
	}
	if result.Decision.DelegatedIPv6Prefix != "" {
		result.Decision.DelegatedIPv6Prefix = normalizeAddressPolicyPrefixValue(result, result.Decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix")
	}
	if result.Decision.RAPrefix != "" {
		result.Decision.RAPrefix = normalizeAddressPolicyPrefixValue(result, result.Decision.RAPrefix, "ra_prefix")
		if prefix, err := netip.ParsePrefix(result.Decision.RAPrefix); err == nil && prefix.Bits() != 64 {
			result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "warning", Code: "ra_prefix_not_64", Message: "RA/SLAAC prefixes are normally /64; certify non-/64 behavior with the target NAS", Field: "ra_prefix", Value: result.Decision.RAPrefix})
		}
	}
	total := addressPolicyAssignmentCount(result.Decision)
	if total > effectiveAddressPolicyMaxAssignments(policy) {
		addError("too_many_assignments", fmt.Sprintf("assignment count exceeds limit %d", effectiveAddressPolicyMaxAssignments(policy)), "assignments", "")
	}
	if total == 0 && result.Decision.PolicyMatched && policy.FailClosed {
		addError("missing_assignment", "matched address policy has no address, pool, RA, or delegated-prefix intent and fail_closed is enabled", "assignments", "")
	}
	if result.Decision.DelegatedIPv6Prefix != "" {
		result.Decision.PrefixDelegation = true
	}
}

func finalizeAddressPolicyResult(result *AddressPolicyCompileResult) {
	if result == nil {
		return
	}
	if result.Status == "ready" && len(result.Diagnostics) > 0 {
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "error" {
				result.Status = "blocked"
				break
			}
			if diagnostic.Severity == "warning" {
				result.Status = "degraded"
			}
		}
	}
	if result.Status == "ready" {
		result.Status = "compiled"
	}
	result.Summary.IPv4AssignmentCount = boolCount(result.Decision.IPv4Address != "" || result.Decision.IPv4Pool != "")
	result.Summary.IPv6AssignmentCount = boolCount(result.Decision.IPv6Address != "") + boolCount(result.Decision.IPv6Prefix != "" || result.Decision.IPv6Pool != "")
	result.Summary.DelegatedPrefixCount = boolCount(result.Decision.DelegatedIPv6Prefix != "" || result.Decision.DelegatedIPv6Pool != "")
	result.Summary.RAPrefixCount = boolCount(result.Decision.RAPrefix != "" || result.Decision.RAPrefixPool != "")
	result.Summary.AssignmentCount = addressPolicyAssignmentCount(result.Decision)
	if result.Decision.Withdraw {
		result.Summary.WithdrawCount = result.Summary.AssignmentCount
	}
	result.Summary.AttributeCount = len(result.Attributes)
	result.Summary.DiagnosticCount = len(result.Diagnostics)
	if strings.TrimSpace(result.Message) == "" {
		result.Message = fmt.Sprintf("address policy compiled %d assignment(s) for role %s", result.Summary.AssignmentCount, firstReplyValue(result.Decision.Role, "default"))
	}
	payload := struct {
		Version    int                      `json:"version"`
		Status     string                   `json:"status"`
		Decision   AddressPolicyDecision    `json:"decision"`
		Attributes []AddressPolicyAttribute `json:"attributes"`
	}{
		Version:    result.CompilerVersion,
		Status:     result.Status,
		Decision:   result.Decision,
		Attributes: result.Attributes,
	}
	result.Fingerprint = "sha256:" + sha256AddressPolicyJSON(payload)
}

func decompileVendorAddressAVPair(result *AddressPolicyCompileResult, value, field string) {
	normalized := strings.TrimSpace(strings.Trim(value, `"`))
	lower := strings.ToLower(normalized)
	rawValue := func(prefix string) string {
		return strings.TrimSpace(normalized[len(prefix):])
	}
	switch {
	case strings.HasPrefix(lower, "address-policy="):
		result.Decision.LifecycleAction = normalizeAddressPolicyLifecycleAction(rawValue("address-policy="))
	case strings.HasPrefix(lower, "address-owner="):
		result.Decision.Owner = rawValue("address-owner=")
	case strings.HasPrefix(lower, "ipv4-pool="), strings.HasPrefix(lower, "ip:addr-pool="):
		result.Decision.IPv4Pool = strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:])
	case strings.HasPrefix(lower, "ipv6-pool="), strings.HasPrefix(lower, "ipv6:addr-pool="):
		result.Decision.IPv6Pool = strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:])
	case strings.HasPrefix(lower, "framed-ip-address="):
		result.Decision.IPv4Address = normalizeAddressPolicyIPValue(result, rawValue("framed-ip-address="), "ipv4", field)
	case strings.HasPrefix(lower, "framed-ipv6-address="):
		result.Decision.IPv6Address = normalizeAddressPolicyIPValue(result, rawValue("framed-ipv6-address="), "ipv6", field)
	case strings.HasPrefix(lower, "framed-ipv6-prefix="), strings.HasPrefix(lower, "ipv6:prefix="):
		result.Decision.IPv6Prefix = normalizeAddressPolicyPrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "delegated-ipv6-prefix="), strings.HasPrefix(lower, "ipv6:delegated-prefix="):
		result.Decision.DelegatedIPv6Prefix = normalizeAddressPolicyPrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "delegated-ipv6-pool="), strings.HasPrefix(lower, "ipv6:delegated-pool="):
		result.Decision.DelegatedIPv6Pool = strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:])
	case strings.HasPrefix(lower, "ra-prefix="), strings.HasPrefix(lower, "ipv6:ra-prefix="):
		result.Decision.RAPrefix = normalizeAddressPolicyPrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "ra-prefix-pool="):
		result.Decision.RAPrefixPool = rawValue("ra-prefix-pool=")
	case strings.HasPrefix(lower, "dhcpv6-mode="):
		result.Decision.DHCPv6Mode = normalizeAddressPolicyDHCPv6Mode(rawValue("dhcpv6-mode="))
	case strings.HasPrefix(lower, "ra-mode="):
		result.Decision.RAMode = normalizeAddressPolicyRAMode(rawValue("ra-mode="))
	}
}

func appendAddressAVPairAttributes(pack, attrName string, decision AddressPolicyDecision, appendAttr func(string, string, string, string, bool)) {
	appendAttr(pack, attrName, "address-owner="+decision.Owner, "owner", true)
	appendAttr(pack, attrName, "address-revision="+firstReplyValue(decision.Revision, addressPolicyRevision(decision)), "revision", true)
	if decision.Withdraw {
		appendAttr(pack, attrName, "address-policy=withdraw", "policy", true)
		return
	}
	appendAttr(pack, attrName, "ipv4-pool="+decision.IPv4Pool, "ipv4_pool", true)
	appendAttr(pack, attrName, "framed-ip-address="+decision.IPv4Address, "ipv4_address", true)
	appendAttr(pack, attrName, "ipv6-pool="+decision.IPv6Pool, "ipv6_pool", true)
	appendAttr(pack, attrName, "framed-ipv6-address="+decision.IPv6Address, "ipv6_address", true)
	appendAttr(pack, attrName, "framed-ipv6-prefix="+decision.IPv6Prefix, "ipv6_prefix", true)
	appendAttr(pack, attrName, "delegated-ipv6-pool="+decision.DelegatedIPv6Pool, "delegated_ipv6_pool", true)
	appendAttr(pack, attrName, "delegated-ipv6-prefix="+decision.DelegatedIPv6Prefix, "delegated_ipv6_prefix", true)
	appendAttr(pack, attrName, "ra-prefix-pool="+decision.RAPrefixPool, "ra_prefix_pool", true)
	appendAttr(pack, attrName, "ra-prefix="+decision.RAPrefix, "ra_prefix", true)
	appendAttr(pack, attrName, "dhcpv6-mode="+decision.DHCPv6Mode, "dhcpv6_mode", true)
	appendAttr(pack, attrName, "ra-mode="+decision.RAMode, "ra_mode", true)
}

func selectAddressFromPool(pool config.RadiusAddressPoolConfig, selectionKey string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool.CIDR))
	if err != nil {
		return "", err
	}
	prefix = prefix.Masked()
	start, end, err := addressPoolRange(prefix, pool.Start, pool.End)
	if err != nil {
		return "", err
	}
	span := new(big.Int).Sub(end, start)
	span.Add(span, big.NewInt(1))
	if span.Sign() <= 0 {
		return "", fmt.Errorf("pool %s has no usable addresses", pool.Name)
	}
	offset := new(big.Int).Mod(hashAddressPolicyBig(selectionKey+"|"+pool.Name+"|address"), span)
	selected := new(big.Int).Add(start, offset)
	addr, err := bigToAddressPolicyAddr(selected, prefix.Addr().Is4())
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func selectPrefixFromPool(pool config.RadiusAddressPoolConfig, targetBits int, selectionKey string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool.CIDR))
	if err != nil {
		return "", err
	}
	prefix = prefix.Masked()
	addrBits := 128
	if prefix.Addr().Is4() {
		addrBits = 32
	}
	if targetBits <= 0 {
		targetBits = prefix.Bits()
	}
	if targetBits < prefix.Bits() || targetBits > addrBits {
		return "", fmt.Errorf("target prefix length %d is outside pool %s", targetBits, prefix.String())
	}
	slotBits := targetBits - prefix.Bits()
	slotCount := new(big.Int).Lsh(big.NewInt(1), uint(slotBits))
	index := new(big.Int).Mod(hashAddressPolicyBig(selectionKey+"|"+pool.Name+"|prefix"), slotCount)
	prefixSize := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-targetBits))
	offset := new(big.Int).Mul(index, prefixSize)
	base, _ := addressPolicyAddrToBig(prefix.Addr())
	selected := new(big.Int).Add(base, offset)
	addr, err := bigToAddressPolicyAddr(selected, prefix.Addr().Is4())
	if err != nil {
		return "", err
	}
	return netip.PrefixFrom(addr, targetBits).Masked().String(), nil
}

func addressPoolRange(prefix netip.Prefix, rawStart, rawEnd string) (*big.Int, *big.Int, error) {
	start, _ := addressPolicyAddrToBig(prefix.Addr())
	addrBits := 128
	if prefix.Addr().Is4() {
		addrBits = 32
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-prefix.Bits()))
	end := new(big.Int).Add(start, new(big.Int).Sub(size, big.NewInt(1)))
	if prefix.Addr().Is4() && size.Cmp(big.NewInt(2)) > 0 {
		start = new(big.Int).Add(start, big.NewInt(1))
		end = new(big.Int).Sub(end, big.NewInt(1))
	}
	if strings.TrimSpace(rawStart) != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(rawStart))
		if err != nil {
			return nil, nil, err
		}
		start, _ = addressPolicyAddrToBig(addr)
	}
	if strings.TrimSpace(rawEnd) != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(rawEnd))
		if err != nil {
			return nil, nil, err
		}
		end, _ = addressPolicyAddrToBig(addr)
	}
	if start.Cmp(end) > 0 {
		return nil, nil, fmt.Errorf("pool start is after end")
	}
	return start, end, nil
}

func normalizeAddressPolicyIPValue(result *AddressPolicyCompileResult, value, family, field string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "invalid_address", Message: err.Error(), Field: field, Value: value})
		return ""
	}
	if family == "ipv4" && !addr.Is4() {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "address_family_mismatch", Message: "address must be IPv4", Field: field, Value: value})
		return ""
	}
	if family == "ipv6" && !addr.Is6() {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "address_family_mismatch", Message: "address must be IPv6", Field: field, Value: value})
		return ""
	}
	return addr.String()
}

func normalizeAddressPolicyPrefixValue(result *AddressPolicyCompileResult, value, field string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "invalid_prefix", Message: err.Error(), Field: field, Value: value})
		return ""
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() {
		result.Diagnostics = append(result.Diagnostics, AddressPolicyDiagnostic{Severity: "error", Code: "prefix_family_mismatch", Message: "prefix must be IPv6", Field: field, Value: value})
		return ""
	}
	return prefix.String()
}

func addressPolicyPoolsByName(pools []config.RadiusAddressPoolConfig) map[string]config.RadiusAddressPoolConfig {
	out := map[string]config.RadiusAddressPoolConfig{}
	for _, pool := range pools {
		name := strings.TrimSpace(pool.Name)
		if name == "" {
			continue
		}
		out[strings.ToLower(name)] = pool
	}
	return out
}

func addressPolicyForRole(policies []config.RadiusAddressRolePolicy, role string) (config.RadiusAddressRolePolicy, bool) {
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.Role), strings.TrimSpace(role)) {
			return policy, true
		}
	}
	return config.RadiusAddressRolePolicy{}, false
}

func effectiveAddressPolicyMaxAssignments(policy config.RadiusAddressPolicyConfig) int {
	if policy.MaxAssignments <= 0 {
		return 128
	}
	return policy.MaxAssignments
}

func effectiveAddressPolicyOwner(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "aegisnas"
	}
	return value
}

func effectiveAddressPolicyConflictMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prefer-role", "prefer-request", "warn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "block"
	}
}

func normalizeAddressPolicyLifecycleAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "coa-update", "reauth", "withdraw", "accounting-stop":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "authorize"
	}
}

func normalizeAddressPolicyDHCPv6Mode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "disabled", "stateless", "stateful", "prefix-delegation", "stateful-pd":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeAddressPolicyRAMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "disabled", "slaac", "managed", "other-config":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func effectiveAddressPolicyDHCPv6Mode(policy config.RadiusAddressPolicyConfig, decision AddressPolicyDecision) string {
	if !policy.DHCPv6.Enabled {
		return "disabled"
	}
	switch {
	case decision.DelegatedIPv6Prefix != "" && decision.IPv6Address != "":
		return "stateful-pd"
	case decision.DelegatedIPv6Prefix != "":
		return "prefix-delegation"
	case decision.IPv6Address != "":
		return "stateful"
	default:
		return "stateless"
	}
}

func effectiveAddressPolicyRAMode(policy config.RadiusAddressPolicyConfig, decision AddressPolicyDecision) string {
	if !policy.RA.Enabled {
		return "disabled"
	}
	switch {
	case decision.RAPrefix != "" && decision.RAManagedFlag:
		return "managed"
	case decision.RAPrefix != "":
		return "slaac"
	default:
		return "other-config"
	}
}

func effectiveAddressPolicyRouterPreference(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "high":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "medium"
	}
}

func effectiveAddressPolicyPackKeys(requested, rolePacks, configured []string) []string {
	if len(requested) > 0 {
		return normalizeAddressPolicyPackKeys(requested)
	}
	if len(rolePacks) > 0 {
		return normalizeAddressPolicyPackKeys(rolePacks)
	}
	if len(configured) > 0 {
		return normalizeAddressPolicyPackKeys(configured)
	}
	return []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
}

func normalizeAddressPolicyPackKeys(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func normalizedAddressPolicyFamily(family, cidr string) string {
	family = strings.ToLower(strings.TrimSpace(family))
	switch family {
	case "ipv4", "4":
		return "ipv4"
	case "ipv6", "6":
		return "ipv6"
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return ""
	}
	if prefix.Addr().Is4() {
		return "ipv4"
	}
	if prefix.Addr().Is6() {
		return "ipv6"
	}
	return ""
}

func addressPoolProvidesAddresses(pool config.RadiusAddressPoolConfig) bool {
	switch strings.ToLower(strings.TrimSpace(pool.Mode)) {
	case "", "address", "mixed":
		return true
	default:
		return false
	}
}

func addressPoolProvidesPrefixes(pool config.RadiusAddressPoolConfig) bool {
	switch strings.ToLower(strings.TrimSpace(pool.Mode)) {
	case "prefix", "ra-prefix", "mixed":
		return true
	default:
		return pool.PrefixLength > 0
	}
}

func effectiveAddressPolicyPrefixLength(pool config.RadiusAddressPoolConfig, fallback int) int {
	if pool.PrefixLength > 0 {
		return pool.PrefixLength
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool.CIDR))
	if err != nil {
		return fallback
	}
	if fallback < prefix.Bits() {
		return prefix.Bits()
	}
	return fallback
}

func effectiveDelegatedPrefixLength(pool config.RadiusAddressPoolConfig) int {
	if pool.DelegatedPrefixLength > 0 {
		return pool.DelegatedPrefixLength
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool.CIDR))
	if err != nil {
		return 64
	}
	switch {
	case prefix.Bits() <= 56:
		return 56
	case prefix.Bits() <= 64:
		return 64
	default:
		return prefix.Bits()
	}
}

func addressPolicySelectionKey(req AddressPolicyCompileRequest, role string) string {
	return firstReplyValue(strings.TrimSpace(req.SessionID), strings.TrimSpace(req.AcctSessionID), strings.TrimSpace(req.CallingStationID), strings.TrimSpace(req.NASIdentifier), role)
}

func addressPolicyRequestHasIntent(req AddressPolicyCompileRequest) bool {
	for _, value := range []string{
		req.IPv4Address, req.IPv4Pool, req.IPv6Address, req.IPv6Pool, req.IPv6Prefix,
		req.DelegatedIPv6Prefix, req.DelegatedIPv6Pool, req.RAPrefix, req.RAPrefixPool,
		req.DHCPv6Mode, req.RAMode,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func addressPolicyAssignmentCount(decision AddressPolicyDecision) int {
	total := 0
	for _, value := range []string{
		decision.IPv4Address, decision.IPv4Pool, decision.IPv6Address, decision.IPv6Pool,
		decision.IPv6Prefix, decision.DelegatedIPv6Prefix, decision.DelegatedIPv6Pool,
		decision.RAPrefix, decision.RAPrefixPool,
	} {
		if strings.TrimSpace(value) != "" {
			total++
		}
	}
	return total
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func normalizeAddressPolicyList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func addressPolicyRevision(decision AddressPolicyDecision) string {
	payload := struct {
		Role                string `json:"role"`
		Owner               string `json:"owner"`
		Action              string `json:"action"`
		IPv4Address         string `json:"ipv4_address,omitempty"`
		IPv4Pool            string `json:"ipv4_pool,omitempty"`
		IPv6Address         string `json:"ipv6_address,omitempty"`
		IPv6Pool            string `json:"ipv6_pool,omitempty"`
		IPv6Prefix          string `json:"ipv6_prefix,omitempty"`
		DelegatedIPv6Prefix string `json:"delegated_ipv6_prefix,omitempty"`
		DelegatedIPv6Pool   string `json:"delegated_ipv6_pool,omitempty"`
		RAPrefix            string `json:"ra_prefix,omitempty"`
		RAPrefixPool        string `json:"ra_prefix_pool,omitempty"`
	}{
		Role:                decision.Role,
		Owner:               decision.Owner,
		Action:              decision.LifecycleAction,
		IPv4Address:         decision.IPv4Address,
		IPv4Pool:            decision.IPv4Pool,
		IPv6Address:         decision.IPv6Address,
		IPv6Pool:            decision.IPv6Pool,
		IPv6Prefix:          decision.IPv6Prefix,
		DelegatedIPv6Prefix: decision.DelegatedIPv6Prefix,
		DelegatedIPv6Pool:   decision.DelegatedIPv6Pool,
		RAPrefix:            decision.RAPrefix,
		RAPrefixPool:        decision.RAPrefixPool,
	}
	sum := sha256AddressPolicyJSON(payload)
	if len(sum) > 16 {
		return sum[:16]
	}
	return sum
}

func addressPolicyOwnershipKey(decision AddressPolicyDecision) string {
	key := strings.Join([]string{
		firstReplyValue(decision.SessionID, decision.AcctSessionID, decision.SelectionKey, decision.Role),
		decision.Owner,
		decision.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return "address-owner-" + hex.EncodeToString(sum[:12])
}

func addressPolicyAddrToBig(addr netip.Addr) (*big.Int, int) {
	if addr.Is4() {
		raw := addr.As4()
		return new(big.Int).SetBytes(raw[:]), 32
	}
	raw := addr.As16()
	return new(big.Int).SetBytes(raw[:]), 128
}

func bigToAddressPolicyAddr(value *big.Int, ipv4 bool) (netip.Addr, error) {
	if value == nil || value.Sign() < 0 {
		return netip.Addr{}, fmt.Errorf("invalid address value")
	}
	if ipv4 {
		raw := value.FillBytes(make([]byte, 4))
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), nil
	}
	raw := value.FillBytes(make([]byte, 16))
	return netip.AddrFrom16([16]byte{
		raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	}), nil
}

func hashAddressPolicyBig(seed string) *big.Int {
	sum := sha256.Sum256([]byte(seed))
	return new(big.Int).SetBytes(sum[:])
}

func ipv4NetmaskForCIDR(cidr string) string {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		return ""
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	if len(mask) != 4 {
		return ""
	}
	return net.IPv4(mask[0], mask[1], mask[2], mask[3]).String()
}

func addressPolicyRFCs() []string {
	return []string{"RFC 2865", "RFC 3162", "RFC 3315", "RFC 3633", "RFC 4861", "RFC 4862", "RFC 5176", "RFC 6911", "RFC 8415"}
}

func sha256AddressPolicyJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
