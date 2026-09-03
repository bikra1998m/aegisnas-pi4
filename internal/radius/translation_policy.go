package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const TranslationPolicyCompilerVersion = 1

type TranslationPolicyCompileRequest struct {
	Role                  string   `json:"role"`
	SessionID             string   `json:"session_id,omitempty"`
	AcctSessionID         string   `json:"acct_session_id,omitempty"`
	CallingStationID      string   `json:"calling_station_id,omitempty"`
	NASIdentifier         string   `json:"nas_identifier,omitempty"`
	NASIPAddress          string   `json:"nas_ip_address,omitempty"`
	Owner                 string   `json:"owner,omitempty"`
	LifecycleAction       string   `json:"lifecycle_action,omitempty"`
	TranslationMode       string   `json:"translation_mode,omitempty"`
	PublicPool            string   `json:"public_pool,omitempty"`
	PublicIPv4            string   `json:"public_ipv4,omitempty"`
	PrivateIPv4Prefix     string   `json:"private_ipv4_prefix,omitempty"`
	SubscriberIPv6Prefix  string   `json:"subscriber_ipv6_prefix,omitempty"`
	NAT64Prefix           string   `json:"nat64_prefix,omitempty"`
	PortBlockStart        int      `json:"port_block_start,omitempty"`
	PortBlockEnd          int      `json:"port_block_end,omitempty"`
	PortBlockSize         int      `json:"port_block_size,omitempty"`
	LoggingProfile        string   `json:"logging_profile,omitempty"`
	AccountingKey         string   `json:"accounting_key,omitempty"`
	QuotaCorrelation      bool     `json:"quota_correlation,omitempty"`
	AccountingCorrelation bool     `json:"accounting_correlation,omitempty"`
	PackKeys              []string `json:"pack_keys,omitempty"`
}

type TranslationPolicyDecompileRequest struct {
	PackKey    string                       `json:"pack_key,omitempty"`
	Attributes []TranslationPolicyAttribute `json:"attributes"`
	Role       string                       `json:"role,omitempty"`
	SessionID  string                       `json:"session_id,omitempty"`
}

type TranslationPolicyCompileResult struct {
	CompilerVersion int                           `json:"compiler_version"`
	Status          string                        `json:"status"`
	Message         string                        `json:"message"`
	Decision        TranslationPolicyDecision     `json:"decision"`
	Attributes      []TranslationPolicyAttribute  `json:"attributes"`
	Summary         TranslationPolicySummary      `json:"summary"`
	Diagnostics     []TranslationPolicyDiagnostic `json:"diagnostics"`
	Fingerprint     string                        `json:"fingerprint"`
	RFCs            []string                      `json:"rfcs"`
}

type TranslationPolicyDecompileResult = TranslationPolicyCompileResult

type TranslationPolicyDecision struct {
	Role                  string   `json:"role,omitempty"`
	SessionID             string   `json:"session_id,omitempty"`
	AcctSessionID         string   `json:"acct_session_id,omitempty"`
	PolicyMatched         bool     `json:"policy_matched"`
	PolicySource          string   `json:"policy_source"`
	LifecycleAction       string   `json:"lifecycle_action"`
	Owner                 string   `json:"owner,omitempty"`
	Revision              string   `json:"revision,omitempty"`
	OwnershipKey          string   `json:"ownership_key,omitempty"`
	SelectionKey          string   `json:"selection_key,omitempty"`
	AllocationMode        string   `json:"allocation_mode,omitempty"`
	TranslationMode       string   `json:"translation_mode,omitempty"`
	PublicPool            string   `json:"public_pool,omitempty"`
	PublicIPv4            string   `json:"public_ipv4,omitempty"`
	PrivateIPv4Prefix     string   `json:"private_ipv4_prefix,omitempty"`
	SubscriberIPv6Prefix  string   `json:"subscriber_ipv6_prefix,omitempty"`
	NAT64Prefix           string   `json:"nat64_prefix,omitempty"`
	PortBlockStart        int      `json:"port_block_start,omitempty"`
	PortBlockEnd          int      `json:"port_block_end,omitempty"`
	PortBlockSize         int      `json:"port_block_size,omitempty"`
	LoggingProfile        string   `json:"logging_profile,omitempty"`
	AccountingKey         string   `json:"accounting_key,omitempty"`
	QuotaCorrelation      bool     `json:"quota_correlation"`
	AccountingCorrelation bool     `json:"accounting_correlation"`
	VendorPacks           []string `json:"vendor_packs,omitempty"`
	Withdraw              bool     `json:"withdraw"`
}

type TranslationPolicyAttribute struct {
	PackKey string `json:"pack_key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Quoted  bool   `json:"quoted"`
	Purpose string `json:"purpose"`
}

type TranslationPolicySummary struct {
	PolicyCount        int `json:"policy_count"`
	PoolCount          int `json:"pool_count"`
	MappingCount       int `json:"mapping_count"`
	CGNATCount         int `json:"cgnat_count"`
	NAT64Count         int `json:"nat64_count"`
	PortBlockCount     int `json:"port_block_count"`
	WithdrawCount      int `json:"withdraw_count"`
	AttributeCount     int `json:"attribute_count"`
	DiagnosticCount    int `json:"diagnostic_count"`
	LoggingCount       int `json:"logging_count"`
	AccountingKeyCount int `json:"accounting_key_count"`
}

type TranslationPolicyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
	PackKey  string `json:"pack_key,omitempty"`
	Pool     string `json:"pool,omitempty"`
	Value    string `json:"value,omitempty"`
}

type TranslationPolicyReport struct {
	CompilerVersion       int                                  `json:"compiler_version"`
	Enabled               bool                                 `json:"enabled"`
	FailClosed            bool                                 `json:"fail_closed"`
	MaxMappings           int                                  `json:"max_mappings"`
	DefaultOwner          string                               `json:"default_owner"`
	ConflictMode          string                               `json:"conflict_mode"`
	StopWithdrawal        bool                                 `json:"stop_withdrawal"`
	AllocationMode        string                               `json:"allocation_mode"`
	DefaultPortBlockSize  int                                  `json:"default_port_block_size"`
	MinPort               int                                  `json:"min_port"`
	MaxPort               int                                  `json:"max_port"`
	DefaultNAT64Prefix    string                               `json:"default_nat64_prefix"`
	LoggingRequired       bool                                 `json:"logging_required"`
	AccountingCorrelation bool                                 `json:"accounting_correlation"`
	Summary               TranslationPolicyCatalogSummary      `json:"summary"`
	Capabilities          []TranslationPolicyCapability        `json:"capabilities"`
	Pools                 []config.RadiusTranslationPoolConfig `json:"pools"`
	Policies              []config.RadiusTranslationRolePolicy `json:"policies"`
	RFCs                  []string                             `json:"rfcs"`
}

type TranslationPolicyCatalogSummary struct {
	PolicyCount       int `json:"policy_count"`
	PoolCount         int `json:"pool_count"`
	PublicIPv4Pools   int `json:"public_ipv4_pools"`
	CGNATPolicies     int `json:"cgnat_policies"`
	NAT64Policies     int `json:"nat64_policies"`
	PortBlockPolicies int `json:"port_block_policies"`
}

type TranslationPolicyCapability struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Status     string   `json:"status"`
	Attributes []string `json:"attributes"`
	Vendors    []string `json:"vendors"`
	Notes      string   `json:"notes,omitempty"`
}

func BuildTranslationPolicyReport(cfg *config.Config) TranslationPolicyReport {
	policy := config.RadiusTranslationPolicyConfig{}
	if cfg != nil {
		policy = cfg.Radius.TranslationPolicy
	}
	report := TranslationPolicyReport{
		CompilerVersion:       TranslationPolicyCompilerVersion,
		Enabled:               policy.Enabled,
		FailClosed:            policy.FailClosed,
		MaxMappings:           effectiveTranslationPolicyMaxMappings(policy),
		DefaultOwner:          effectiveTranslationPolicyOwner(policy.DefaultOwner),
		ConflictMode:          effectiveTranslationPolicyConflictMode(policy.ConflictMode),
		StopWithdrawal:        policy.StopWithdrawal,
		AllocationMode:        effectiveTranslationAllocationMode(policy.AllocationMode),
		DefaultPortBlockSize:  effectiveTranslationPortBlockSize(policy.DefaultPortBlockSize),
		MinPort:               effectiveTranslationMinPort(policy.MinPort),
		MaxPort:               effectiveTranslationMaxPort(policy.MaxPort),
		DefaultNAT64Prefix:    firstReplyValue(strings.TrimSpace(policy.DefaultNAT64Prefix), "64:ff9b::/96"),
		LoggingRequired:       policy.LoggingRequired,
		AccountingCorrelation: policy.AccountingCorrelation,
		Pools:                 append([]config.RadiusTranslationPoolConfig(nil), policy.Pools...),
		Policies:              append([]config.RadiusTranslationRolePolicy(nil), policy.RolePolicies...),
		RFCs:                  translationPolicyRFCs(),
		Capabilities: []TranslationPolicyCapability{
			{Key: "deterministic_cgnat", Label: "Deterministic CGNAT Mapping", Status: "implemented", Attributes: []string{"AegisNAS-Translation-Public-IPv4-Address", "AegisNAS-Translation-Port-Block-Start", "AegisNAS-Translation-Port-Block-End", "Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "H3C-Av-Pair", "Nokia-AVPair", "SN-NAT-IP-Address"}, Vendors: []string{"Cisco", "Juniper ERX/Junos", "Huawei", "H3C", "Nokia", "Starent/Cisco ASR"}, Notes: "Native dataplane installation remains release certification evidence per target adapter."},
			{Key: "nat64_prefix", Label: "NAT64 Prefix Intent", Status: "implemented", Attributes: []string{"AegisNAS-Translation-NAT64-Prefix", "Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "Nokia-AVPair"}, Vendors: []string{"BNG/BRAS", "Cisco", "Juniper", "Huawei", "Nokia"}},
			{Key: "port_blocks", Label: "Deterministic Port Blocks", Status: "implemented", Attributes: []string{"AegisNAS-Translation-Port-Block-Start", "AegisNAS-Translation-Port-Block-End", "AegisNAS-Translation-Port-Block-Size"}, Vendors: []string{"CGNAT/BNG platforms"}},
			{Key: "logging_accounting", Label: "Translation Logging And Accounting Correlation", Status: "implemented", Attributes: []string{"AegisNAS-Translation-Logging-Profile", "AegisNAS-Translation-Accounting-Key"}, Vendors: []string{"ISP/BNG platforms"}, Notes: "Lawful logging and retention policy require site-specific external approval."},
			{Key: "ownership_lifecycle", Label: "HA-Safe Ownership Lifecycle", Status: "implemented", Attributes: []string{"AegisNAS-Translation-Policy", "AegisNAS-Translation-Owner", "AegisNAS-Translation-Revision"}, Vendors: []string{"all dynamic authorization capable NAS"}},
		},
	}
	report.Summary.PolicyCount = len(policy.RolePolicies)
	report.Summary.PoolCount = len(policy.Pools)
	for _, pool := range policy.Pools {
		if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) == "ipv4" {
			report.Summary.PublicIPv4Pools++
		}
	}
	for _, rolePolicy := range policy.RolePolicies {
		mode := normalizeTranslationMode(rolePolicy.TranslationMode)
		if mode == "" {
			mode = "cgnat"
		}
		if translationModeNeedsPublicIPv4(mode) {
			report.Summary.CGNATPolicies++
		}
		if translationModeNeedsNAT64Prefix(mode) {
			report.Summary.NAT64Policies++
		}
		if rolePolicy.PortBlockStart > 0 || rolePolicy.PortBlockEnd > 0 || rolePolicy.PortBlockSize > 0 {
			report.Summary.PortBlockPolicies++
		}
	}
	return report
}

func CompileTranslationPolicy(cfg *config.Config, req TranslationPolicyCompileRequest) TranslationPolicyCompileResult {
	result := TranslationPolicyCompileResult{
		CompilerVersion: TranslationPolicyCompilerVersion,
		Status:          "ready",
		RFCs:            translationPolicyRFCs(),
	}
	if cfg == nil {
		result.Status = "blocked"
		result.Message = "configuration is required"
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "missing_config", Message: result.Message})
		finalizeTranslationPolicyResult(&result)
		return result
	}
	policy := cfg.Radius.TranslationPolicy
	result.Summary.PolicyCount = len(policy.RolePolicies)
	result.Summary.PoolCount = len(policy.Pools)
	if !policy.Enabled {
		result.Status = "blocked"
		result.Message = "translation policy compiler is disabled"
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "disabled", Message: result.Message, Field: "radius.translation_policy.enabled"})
		finalizeTranslationPolicyResult(&result)
		return result
	}

	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "default"
	}
	result.Decision.Role = role
	result.Decision.SessionID = strings.TrimSpace(req.SessionID)
	result.Decision.AcctSessionID = strings.TrimSpace(req.AcctSessionID)
	result.Decision.LifecycleAction = normalizeTranslationPolicyLifecycleAction(req.LifecycleAction)
	result.Decision.Owner = firstReplyValue(strings.TrimSpace(req.Owner), effectiveTranslationPolicyOwner(policy.DefaultOwner))
	result.Decision.PolicySource = "request"
	result.Decision.SelectionKey = translationPolicySelectionKey(req, role)
	result.Decision.AllocationMode = effectiveTranslationAllocationMode(policy.AllocationMode)
	result.Decision.TranslationMode = firstReplyValue(normalizeTranslationMode(req.TranslationMode), "cgnat")
	result.Decision.PortBlockSize = firstPositiveInt(req.PortBlockSize, effectiveTranslationPortBlockSize(policy.DefaultPortBlockSize))
	result.Decision.LoggingProfile = strings.TrimSpace(req.LoggingProfile)
	result.Decision.AccountingKey = strings.TrimSpace(req.AccountingKey)
	result.Decision.QuotaCorrelation = req.QuotaCorrelation
	result.Decision.AccountingCorrelation = policy.AccountingCorrelation || req.AccountingCorrelation

	pools := translationPolicyPoolsByName(policy.Pools)
	if rolePolicy, matched := translationPolicyForRole(policy.RolePolicies, role); matched {
		result.Decision.PolicyMatched = true
		result.Decision.PolicySource = "radius.translation_policy.role_policies"
		result.Decision.Owner = firstReplyValue(strings.TrimSpace(rolePolicy.Owner), result.Decision.Owner)
		result.Decision.VendorPacks = normalizeAddressPolicyPackKeys(rolePolicy.VendorPacks)
		applyTranslationPolicyRoleIntent(&result, rolePolicy)
	}
	applyTranslationPolicyRequestIntent(&result, req, effectiveTranslationPolicyConflictMode(policy.ConflictMode))
	resolveTranslationPolicyPoolsAndPorts(&result, policy, pools)
	if policy.LoggingRequired && result.Decision.LoggingProfile == "" && !result.Decision.Withdraw {
		result.Decision.LoggingProfile = "aegisnas-cgnat"
	}
	if result.Decision.AccountingCorrelation && result.Decision.AccountingKey == "" && !result.Decision.Withdraw {
		result.Decision.AccountingKey = translationPolicyAccountingKey(result.Decision)
	}
	applyTranslationPolicyLifecycle(&result, policy)
	validateCompiledTranslationDecision(&result, policy)
	result.Decision.Revision = translationPolicyRevision(result.Decision)
	result.Decision.OwnershipKey = translationPolicyOwnershipKey(result.Decision)
	result.Attributes = BuildTranslationPolicyAttributes(result.Decision, effectiveAddressPolicyPackKeys(req.PackKeys, result.Decision.VendorPacks, cfg.Radius.Vendor.CompatibilityPacks))
	finalizeTranslationPolicyResult(&result)
	return result
}

func DecompileTranslationPolicyAttributes(req TranslationPolicyDecompileRequest) TranslationPolicyDecompileResult {
	result := TranslationPolicyCompileResult{
		CompilerVersion: TranslationPolicyCompilerVersion,
		Status:          "decompiled",
		RFCs:            translationPolicyRFCs(),
		Attributes:      append([]TranslationPolicyAttribute(nil), req.Attributes...),
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
	result.Decision.TranslationMode = "cgnat"
	result.Decision.AllocationMode = "deterministic"
	result.Decision.VendorPacks = []string{packKey}

	for index, attr := range req.Attributes {
		name := strings.ToLower(strings.TrimSpace(attr.Name))
		value := strings.TrimSpace(strings.Trim(attr.Value, `"`))
		if name == "" || value == "" {
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "empty_attribute", Message: "empty translation attribute was ignored", Field: fmt.Sprintf("attributes[%d]", index), PackKey: packKey})
			continue
		}
		switch name {
		case "aegisnas-translation-policy":
			result.Decision.LifecycleAction = normalizeTranslationPolicyLifecycleAction(value)
		case "aegisnas-translation-owner":
			result.Decision.Owner = value
		case "aegisnas-translation-revision":
			result.Decision.Revision = value
		case "aegisnas-translation-mode":
			result.Decision.TranslationMode = normalizeTranslationMode(value)
		case "aegisnas-translation-public-ipv4-pool":
			result.Decision.PublicPool = value
		case "aegisnas-translation-public-ipv4-address", "sn-nat-ip-address":
			result.Decision.PublicIPv4 = normalizeTranslationIPv4Value(&result, value, attr.Name)
		case "aegisnas-translation-private-ipv4-prefix":
			result.Decision.PrivateIPv4Prefix = normalizeTranslationPrefixValue(&result, value, "ipv4", attr.Name)
		case "aegisnas-translation-subscriber-ipv6-prefix":
			result.Decision.SubscriberIPv6Prefix = normalizeTranslationPrefixValue(&result, value, "ipv6", attr.Name)
		case "aegisnas-translation-nat64-prefix":
			result.Decision.NAT64Prefix = normalizeTranslationNAT64PrefixValue(&result, value, attr.Name)
		case "aegisnas-translation-port-block-start":
			result.Decision.PortBlockStart = parseTranslationInt(&result, value, attr.Name)
		case "aegisnas-translation-port-block-end":
			result.Decision.PortBlockEnd = parseTranslationInt(&result, value, attr.Name)
		case "aegisnas-translation-port-block-size":
			result.Decision.PortBlockSize = parseTranslationInt(&result, value, attr.Name)
		case "aegisnas-translation-logging-profile":
			result.Decision.LoggingProfile = value
		case "aegisnas-translation-accounting-key":
			result.Decision.AccountingKey = value
			result.Decision.AccountingCorrelation = true
		case "cisco-avpair", "juniper-av-pair", "huawei-avpair", "h3c-av-pair", "nokia-avpair":
			decompileVendorTranslationAVPair(&result, value, attr.Name)
		case "erx-address-pool-name":
			result.Decision.PublicPool = value
		}
	}
	if result.Decision.LifecycleAction == "" {
		result.Decision.LifecycleAction = "authorize"
	}
	if result.Decision.Owner == "" {
		result.Decision.Owner = "aegisnas"
	}
	if result.Decision.TranslationMode == "" {
		result.Decision.TranslationMode = "cgnat"
	}
	applyTranslationPolicyLifecycle(&result, config.RadiusTranslationPolicyConfig{Enabled: true, StopWithdrawal: true})
	validateCompiledTranslationDecision(&result, config.RadiusTranslationPolicyConfig{Enabled: true, MaxMappings: 4096, DefaultOwner: "aegisnas", ConflictMode: "warn", MinPort: 1, MaxPort: 65535, DefaultPortBlockSize: 0})
	if result.Decision.Revision == "" {
		result.Decision.Revision = translationPolicyRevision(result.Decision)
	}
	result.Decision.OwnershipKey = translationPolicyOwnershipKey(result.Decision)
	result.Message = fmt.Sprintf("translation policy decompiled %d attribute(s)", len(req.Attributes))
	finalizeTranslationPolicyResult(&result)
	return result
}

func BuildTranslationPolicyAttributes(decision TranslationPolicyDecision, packKeys []string) []TranslationPolicyAttribute {
	packKeys = normalizeAddressPolicyPackKeys(packKeys)
	if len(packKeys) == 0 {
		packKeys = []string{productconfigs.VendorPackAegisNAS}
	}
	attrs := make([]TranslationPolicyAttribute, 0, 24)
	appendAttr := func(pack, name, value, purpose string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		attrs = append(attrs, TranslationPolicyAttribute{PackKey: pack, Name: name, Value: value, Quoted: quoted, Purpose: purpose})
	}
	appendIntAttr := func(pack, name string, value int, purpose string) {
		if value <= 0 {
			return
		}
		appendAttr(pack, name, strconv.Itoa(value), purpose, false)
	}
	withdraw := decision.Withdraw || decision.LifecycleAction == "withdraw" || decision.LifecycleAction == "accounting-stop"
	for _, pack := range packKeys {
		switch pack {
		case productconfigs.VendorPackAegisNAS:
			appendAttr(pack, "AegisNAS-Translation-Policy", decision.LifecycleAction, "policy", true)
			appendAttr(pack, "AegisNAS-Translation-Owner", decision.Owner, "owner", true)
			appendAttr(pack, "AegisNAS-Translation-Revision", firstReplyValue(decision.Revision, translationPolicyRevision(decision)), "revision", true)
			appendAttr(pack, "AegisNAS-Translation-Mode", decision.TranslationMode, "translation_mode", true)
			if withdraw {
				continue
			}
			appendAttr(pack, "AegisNAS-Translation-Public-IPv4-Pool", decision.PublicPool, "public_pool", true)
			appendAttr(pack, "AegisNAS-Translation-Public-IPv4-Address", decision.PublicIPv4, "public_ipv4", true)
			appendAttr(pack, "AegisNAS-Translation-Private-IPv4-Prefix", decision.PrivateIPv4Prefix, "private_ipv4_prefix", true)
			appendAttr(pack, "AegisNAS-Translation-Subscriber-IPv6-Prefix", decision.SubscriberIPv6Prefix, "subscriber_ipv6_prefix", true)
			appendAttr(pack, "AegisNAS-Translation-NAT64-Prefix", decision.NAT64Prefix, "nat64_prefix", true)
			appendIntAttr(pack, "AegisNAS-Translation-Port-Block-Start", decision.PortBlockStart, "port_block_start")
			appendIntAttr(pack, "AegisNAS-Translation-Port-Block-End", decision.PortBlockEnd, "port_block_end")
			appendIntAttr(pack, "AegisNAS-Translation-Port-Block-Size", decision.PortBlockSize, "port_block_size")
			appendAttr(pack, "AegisNAS-Translation-Logging-Profile", decision.LoggingProfile, "logging_profile", true)
			appendAttr(pack, "AegisNAS-Translation-Accounting-Key", decision.AccountingKey, "accounting_key", true)
		case productconfigs.VendorPackCisco:
			appendTranslationAVPairAttributes(pack, "Cisco-AVPair", decision, appendAttr)
		case productconfigs.VendorPackJuniper:
			appendTranslationAVPairAttributes(pack, "Juniper-AV-Pair", decision, appendAttr)
		case productconfigs.VendorPackHuawei:
			if !withdraw {
				appendAttr(pack, "Huawei-NAT-Public-Address", decision.PublicIPv4, "public_ipv4", false)
				appendAttr(pack, "Huawei-NAT-Policy-Name", decision.TranslationMode, "translation_mode", true)
				appendIntAttr(pack, "Huawei-NAT-Start-Port", decision.PortBlockStart, "port_block_start")
				appendIntAttr(pack, "Huawei-NAT-End-Port", decision.PortBlockEnd, "port_block_end")
				appendIntAttr(pack, "Huawei-NAT-Port-Range-Update", decision.PortBlockSize, "port_block_size")
			}
			appendTranslationAVPairAttributes(pack, "Huawei-AVpair", decision, appendAttr)
		case productconfigs.VendorPackH3C:
			if !withdraw {
				appendAttr(pack, "H3C-NAT-IP-Address", decision.PublicIPv4, "public_ipv4", false)
				appendIntAttr(pack, "H3C-NAT-Start-Port", decision.PortBlockStart, "port_block_start")
				appendIntAttr(pack, "H3C-NAT-End-Port", decision.PortBlockEnd, "port_block_end")
			}
			appendTranslationAVPairAttributes(pack, "H3C-Av-Pair", decision, appendAttr)
		case productconfigs.VendorPackNokia:
			appendTranslationAVPairAttributes(pack, "Nokia-AVPair", decision, appendAttr)
		case productconfigs.VendorPackStarent:
			if withdraw {
				continue
			}
			appendAttr(pack, "SN-NAT-IP-Address", decision.PublicIPv4, "public_ipv4", false)
			appendAttr(pack, "SN-IP-Pool-Name", decision.PublicPool, "public_pool", true)
		case productconfigs.VendorPackERX:
			if withdraw {
				continue
			}
			appendAttr(pack, "ERX-Address-Pool-Name", decision.PublicPool, "public_pool", true)
		case productconfigs.VendorPackRuckus:
			if withdraw {
				continue
			}
			appendAttr(pack, "Ruckus-Nat-Pool-Name", decision.PublicPool, "public_pool", true)
		}
	}
	return attrs
}

func ApplyTranslationPolicyToReplyAttributes(attrs *ReplyAttributes, result TranslationPolicyCompileResult) {
	if attrs == nil || result.Status == "blocked" {
		return
	}
	decision := result.Decision
	attrs.TranslationOwner = decision.Owner
	attrs.TranslationRevision = firstReplyValue(decision.Revision, translationPolicyRevision(decision))
	attrs.TranslationPolicyMode = decision.LifecycleAction
	attrs.TranslationPolicyFingerprint = result.Fingerprint
	attrs.TranslationMode = decision.TranslationMode
	attrs.TranslationPublicPool = decision.PublicPool
	attrs.TranslationPublicIPv4 = decision.PublicIPv4
	attrs.TranslationPrivateIPv4Prefix = decision.PrivateIPv4Prefix
	attrs.TranslationSubscriberIPv6Prefix = decision.SubscriberIPv6Prefix
	attrs.TranslationNAT64Prefix = decision.NAT64Prefix
	attrs.TranslationPortBlockStart = decision.PortBlockStart
	attrs.TranslationPortBlockEnd = decision.PortBlockEnd
	attrs.TranslationPortBlockSize = decision.PortBlockSize
	attrs.TranslationLoggingProfile = decision.LoggingProfile
	attrs.TranslationAccountingKey = decision.AccountingKey
	attrs.TranslationQuotaCorrelation = decision.QuotaCorrelation
	attrs.TranslationAccountingCorrelation = decision.AccountingCorrelation
}

func ApplyConfiguredTranslationPolicyToReplyAttributes(cfg *config.Config, attrs *ReplyAttributes, req TranslationPolicyCompileRequest) (TranslationPolicyCompileResult, bool) {
	if cfg == nil || attrs == nil || !cfg.Radius.TranslationPolicy.Enabled {
		return TranslationPolicyCompileResult{}, false
	}
	if strings.TrimSpace(req.Role) == "" {
		req.Role = replyRole(attrs)
	}
	result := CompileTranslationPolicy(cfg, req)
	if result.Status == "blocked" || result.Decision.Withdraw {
		return result, false
	}
	if !result.Decision.PolicyMatched && !translationPolicyRequestHasIntent(req) {
		return result, false
	}
	ApplyTranslationPolicyToReplyAttributes(attrs, result)
	return result, true
}

func applyTranslationPolicyRoleIntent(result *TranslationPolicyCompileResult, rolePolicy config.RadiusTranslationRolePolicy) {
	decision := &result.Decision
	if mode := normalizeTranslationMode(rolePolicy.TranslationMode); mode != "" && mode != "inherit" {
		decision.TranslationMode = mode
	}
	decision.PublicPool = strings.TrimSpace(rolePolicy.PublicPool)
	decision.PublicIPv4 = strings.TrimSpace(rolePolicy.PublicIPv4)
	decision.PrivateIPv4Prefix = strings.TrimSpace(rolePolicy.PrivateIPv4Prefix)
	decision.SubscriberIPv6Prefix = strings.TrimSpace(rolePolicy.SubscriberIPv6Prefix)
	decision.NAT64Prefix = strings.TrimSpace(rolePolicy.NAT64Prefix)
	decision.PortBlockStart = rolePolicy.PortBlockStart
	decision.PortBlockEnd = rolePolicy.PortBlockEnd
	if rolePolicy.PortBlockSize > 0 {
		decision.PortBlockSize = rolePolicy.PortBlockSize
	}
	decision.LoggingProfile = strings.TrimSpace(rolePolicy.LoggingProfile)
	decision.AccountingKey = strings.TrimSpace(rolePolicy.AccountingKey)
	decision.QuotaCorrelation = rolePolicy.QuotaCorrelation
	decision.AccountingCorrelation = decision.AccountingCorrelation || rolePolicy.AccountingCorrelation
}

func applyTranslationPolicyRequestIntent(result *TranslationPolicyCompileResult, req TranslationPolicyCompileRequest, conflictMode string) {
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
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict_replaced", Message: "request translation intent replaced role intent", Field: field, Value: candidate})
			*current = candidate
		case "prefer-role":
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict_ignored", Message: "request translation intent conflicted with role intent and was ignored", Field: field, Value: candidate})
		case "warn":
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict", Message: "request translation intent conflicts with role intent", Field: field, Value: candidate})
		default:
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "translation_conflict", Message: "request translation intent conflicts with role intent", Field: field, Value: candidate})
		}
	}
	mergeInt := func(field string, current *int, candidate int) {
		if candidate <= 0 {
			return
		}
		if *current <= 0 || *current == candidate {
			*current = candidate
			return
		}
		text := strconv.Itoa(candidate)
		switch conflictMode {
		case "prefer-request":
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict_replaced", Message: "request translation intent replaced role intent", Field: field, Value: text})
			*current = candidate
		case "prefer-role":
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict_ignored", Message: "request translation intent conflicted with role intent and was ignored", Field: field, Value: text})
		case "warn":
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "translation_conflict", Message: "request translation intent conflicts with role intent", Field: field, Value: text})
		default:
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "translation_conflict", Message: "request translation intent conflicts with role intent", Field: field, Value: text})
		}
	}
	merge("translation_mode", &result.Decision.TranslationMode, normalizeTranslationMode(req.TranslationMode))
	merge("public_pool", &result.Decision.PublicPool, req.PublicPool)
	merge("public_ipv4", &result.Decision.PublicIPv4, req.PublicIPv4)
	merge("private_ipv4_prefix", &result.Decision.PrivateIPv4Prefix, req.PrivateIPv4Prefix)
	merge("subscriber_ipv6_prefix", &result.Decision.SubscriberIPv6Prefix, req.SubscriberIPv6Prefix)
	merge("nat64_prefix", &result.Decision.NAT64Prefix, req.NAT64Prefix)
	mergeInt("port_block_start", &result.Decision.PortBlockStart, req.PortBlockStart)
	mergeInt("port_block_end", &result.Decision.PortBlockEnd, req.PortBlockEnd)
	mergeInt("port_block_size", &result.Decision.PortBlockSize, req.PortBlockSize)
	merge("logging_profile", &result.Decision.LoggingProfile, req.LoggingProfile)
	merge("accounting_key", &result.Decision.AccountingKey, req.AccountingKey)
	if req.QuotaCorrelation {
		result.Decision.QuotaCorrelation = true
	}
	if req.AccountingCorrelation {
		result.Decision.AccountingCorrelation = true
	}
}

func resolveTranslationPolicyPoolsAndPorts(result *TranslationPolicyCompileResult, policy config.RadiusTranslationPolicyConfig, pools map[string]config.RadiusTranslationPoolConfig) {
	if result == nil {
		return
	}
	mode := normalizeTranslationMode(result.Decision.TranslationMode)
	if mode == "" {
		mode = "cgnat"
	}
	result.Decision.TranslationMode = mode
	if translationModeNeedsNAT64Prefix(mode) && result.Decision.NAT64Prefix == "" {
		result.Decision.NAT64Prefix = firstReplyValue(strings.TrimSpace(policy.DefaultNAT64Prefix), "64:ff9b::/96")
	}
	poolName := strings.TrimSpace(result.Decision.PublicPool)
	var pool config.RadiusTranslationPoolConfig
	var hasPool bool
	if poolName != "" {
		pool, hasPool = pools[strings.ToLower(poolName)]
		if !hasPool {
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "pool_missing", Message: "public translation pool is not configured", Field: "public_pool", Pool: poolName})
		} else if normalizedAddressPolicyFamily(pool.Family, pool.CIDR) != "ipv4" {
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "pool_family_mismatch", Message: "public translation pool must be IPv4", Field: "public_pool", Pool: poolName})
		} else if result.Decision.PublicIPv4 == "" && translationModeNeedsPublicIPv4(mode) {
			addr, err := selectTranslationPublicIPv4(pool, result.Decision.SelectionKey)
			if err != nil {
				result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "pool_select_failed", Message: err.Error(), Field: "public_pool", Pool: poolName})
			} else {
				result.Decision.PublicIPv4 = addr
			}
		}
	}
	if result.Decision.PublicIPv4 != "" {
		result.Decision.PublicIPv4 = normalizeTranslationIPv4Value(result, result.Decision.PublicIPv4, "public_ipv4")
	}
	result.Decision.PrivateIPv4Prefix = normalizeTranslationPrefixValue(result, result.Decision.PrivateIPv4Prefix, "ipv4", "private_ipv4_prefix")
	result.Decision.SubscriberIPv6Prefix = normalizeTranslationPrefixValue(result, result.Decision.SubscriberIPv6Prefix, "ipv6", "subscriber_ipv6_prefix")
	result.Decision.NAT64Prefix = normalizeTranslationNAT64PrefixValue(result, result.Decision.NAT64Prefix, "nat64_prefix")
	resolveTranslationPortBlock(result, policy, pool, hasPool)
}

func resolveTranslationPortBlock(result *TranslationPolicyCompileResult, policy config.RadiusTranslationPolicyConfig, pool config.RadiusTranslationPoolConfig, hasPool bool) {
	minPort := effectiveTranslationMinPort(policy.MinPort)
	maxPort := effectiveTranslationMaxPort(policy.MaxPort)
	blockSize := firstPositiveInt(result.Decision.PortBlockSize, effectiveTranslationPortBlockSize(policy.DefaultPortBlockSize))
	if hasPool {
		if pool.PortStart > 0 {
			minPort = pool.PortStart
		}
		if pool.PortEnd > 0 {
			maxPort = pool.PortEnd
		}
		if pool.PortBlockSize > 0 {
			blockSize = pool.PortBlockSize
		}
	}
	if blockSize <= 0 {
		blockSize = maxPort - minPort + 1
	}
	result.Decision.PortBlockSize = blockSize
	if result.Decision.PortBlockStart > 0 && result.Decision.PortBlockEnd > 0 {
		return
	}
	if !translationModeNeedsPortBlock(result.Decision.TranslationMode) {
		return
	}
	if result.Decision.PortBlockStart > 0 && result.Decision.PortBlockEnd == 0 {
		result.Decision.PortBlockEnd = result.Decision.PortBlockStart + blockSize - 1
		return
	}
	if result.Decision.PortBlockEnd > 0 && result.Decision.PortBlockStart == 0 {
		result.Decision.PortBlockStart = result.Decision.PortBlockEnd - blockSize + 1
		return
	}
	start, end, err := selectTranslationPortBlock(minPort, maxPort, blockSize, result.Decision.SelectionKey)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "port_block_select_failed", Message: err.Error(), Field: "port_block"})
		return
	}
	result.Decision.PortBlockStart = start
	result.Decision.PortBlockEnd = end
}

func applyTranslationPolicyLifecycle(result *TranslationPolicyCompileResult, policy config.RadiusTranslationPolicyConfig) {
	if result == nil {
		return
	}
	switch result.Decision.LifecycleAction {
	case "withdraw", "accounting-stop":
		if result.Decision.LifecycleAction == "accounting-stop" && !policy.StopWithdrawal {
			result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "warning", Code: "stop_withdrawal_disabled", Message: "accounting Stop translation withdrawal is disabled by policy"})
			return
		}
		result.Decision.Withdraw = true
	}
}

func validateCompiledTranslationDecision(result *TranslationPolicyCompileResult, policy config.RadiusTranslationPolicyConfig) {
	if result == nil {
		return
	}
	addError := func(code, message, field, value string) {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: code, Message: message, Field: field, Value: value})
	}
	if strings.TrimSpace(result.Decision.Owner) == "" {
		addError("missing_owner", "translation policy did not resolve an owner", "owner", "")
	}
	if result.Decision.Withdraw {
		return
	}
	mode := normalizeTranslationMode(result.Decision.TranslationMode)
	if mode == "" {
		addError("invalid_translation_mode", "translation mode is invalid", "translation_mode", result.Decision.TranslationMode)
		return
	}
	result.Decision.TranslationMode = mode
	if translationModeNeedsPublicIPv4(mode) && strings.TrimSpace(result.Decision.PublicIPv4) == "" {
		addError("missing_public_ipv4", "translation mode requires a public IPv4 address or public pool", "public_ipv4", "")
	}
	if translationModeNeedsNAT64Prefix(mode) && strings.TrimSpace(result.Decision.NAT64Prefix) == "" {
		addError("missing_nat64_prefix", "translation mode requires a NAT64 prefix", "nat64_prefix", "")
	}
	if translationModeNeedsPortBlock(mode) {
		if result.Decision.PortBlockStart <= 0 || result.Decision.PortBlockEnd <= 0 {
			addError("missing_port_block", "translation mode requires a deterministic port block", "port_block", "")
		} else if result.Decision.PortBlockStart > result.Decision.PortBlockEnd {
			addError("invalid_port_block", "port block start cannot exceed end", "port_block", fmt.Sprintf("%d-%d", result.Decision.PortBlockStart, result.Decision.PortBlockEnd))
		} else if result.Decision.PortBlockStart < 1 || result.Decision.PortBlockEnd > 65535 {
			addError("invalid_port_block", "port block must be within TCP/UDP port range 1..65535", "port_block", fmt.Sprintf("%d-%d", result.Decision.PortBlockStart, result.Decision.PortBlockEnd))
		}
		if result.Decision.PortBlockSize <= 0 {
			result.Decision.PortBlockSize = result.Decision.PortBlockEnd - result.Decision.PortBlockStart + 1
		}
	}
	if policy.LoggingRequired && strings.TrimSpace(result.Decision.LoggingProfile) == "" && strings.TrimSpace(result.Decision.AccountingKey) == "" {
		addError("missing_logging_profile", "translation logging is required but no logging profile or accounting key was resolved", "logging_profile", "")
	}
	total := translationPolicyMappingCount(result.Decision)
	if total > effectiveTranslationPolicyMaxMappings(policy) {
		addError("too_many_mappings", fmt.Sprintf("translation mapping count exceeds limit %d", effectiveTranslationPolicyMaxMappings(policy)), "mappings", "")
	}
	if total == 0 && result.Decision.PolicyMatched && policy.FailClosed {
		addError("missing_mapping", "matched translation policy has no public address, NAT64 prefix, port block, or subscriber prefix intent and fail_closed is enabled", "mappings", "")
	}
}

func finalizeTranslationPolicyResult(result *TranslationPolicyCompileResult) {
	if result == nil {
		return
	}
	if result.Status == "ready" && len(result.Diagnostics) > 0 {
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "error" {
				result.Status = "blocked"
				break
			}
		}
		if result.Status == "ready" {
			result.Status = "degraded"
		}
	}
	if result.Status == "ready" {
		result.Status = "compiled"
	}
	result.Summary.MappingCount = translationPolicyMappingCount(result.Decision)
	result.Summary.CGNATCount = boolCount(translationModeNeedsPublicIPv4(result.Decision.TranslationMode) && result.Decision.PublicIPv4 != "")
	result.Summary.NAT64Count = boolCount(result.Decision.NAT64Prefix != "")
	result.Summary.PortBlockCount = boolCount(result.Decision.PortBlockStart > 0 && result.Decision.PortBlockEnd > 0)
	result.Summary.WithdrawCount = boolCount(result.Decision.Withdraw)
	result.Summary.AttributeCount = len(result.Attributes)
	result.Summary.DiagnosticCount = len(result.Diagnostics)
	result.Summary.LoggingCount = boolCount(result.Decision.LoggingProfile != "")
	result.Summary.AccountingKeyCount = boolCount(result.Decision.AccountingKey != "")
	if strings.TrimSpace(result.Message) == "" {
		result.Message = fmt.Sprintf("translation policy compiled %d mapping(s) for role %s", result.Summary.MappingCount, firstReplyValue(result.Decision.Role, "default"))
	}
	payload := struct {
		Version    int                          `json:"version"`
		Status     string                       `json:"status"`
		Decision   TranslationPolicyDecision    `json:"decision"`
		Attributes []TranslationPolicyAttribute `json:"attributes"`
	}{
		Version:    result.CompilerVersion,
		Status:     result.Status,
		Decision:   result.Decision,
		Attributes: result.Attributes,
	}
	result.Fingerprint = "sha256:" + sha256TranslationPolicyJSON(payload)
}

func appendTranslationAVPairAttributes(pack, attrName string, decision TranslationPolicyDecision, appendAttr func(string, string, string, string, bool)) {
	appendAttr(pack, attrName, "translation-owner="+decision.Owner, "owner", true)
	appendAttr(pack, attrName, "translation-revision="+firstReplyValue(decision.Revision, translationPolicyRevision(decision)), "revision", true)
	if decision.Withdraw {
		appendAttr(pack, attrName, "translation-policy=withdraw", "policy", true)
		return
	}
	appendAttr(pack, attrName, "translation-mode="+decision.TranslationMode, "translation_mode", true)
	appendAttr(pack, attrName, "translation-public-pool="+decision.PublicPool, "public_pool", true)
	appendAttr(pack, attrName, "translation-public-ipv4="+decision.PublicIPv4, "public_ipv4", true)
	appendAttr(pack, attrName, "translation-private-ipv4-prefix="+decision.PrivateIPv4Prefix, "private_ipv4_prefix", true)
	appendAttr(pack, attrName, "translation-subscriber-ipv6-prefix="+decision.SubscriberIPv6Prefix, "subscriber_ipv6_prefix", true)
	appendAttr(pack, attrName, "translation-nat64-prefix="+decision.NAT64Prefix, "nat64_prefix", true)
	if decision.PortBlockStart > 0 && decision.PortBlockEnd > 0 {
		appendAttr(pack, attrName, fmt.Sprintf("translation-port-block=%d-%d", decision.PortBlockStart, decision.PortBlockEnd), "port_block", true)
	}
	if decision.PortBlockSize > 0 {
		appendAttr(pack, attrName, "translation-port-block-size="+strconv.Itoa(decision.PortBlockSize), "port_block_size", true)
	}
	appendAttr(pack, attrName, "translation-log-profile="+decision.LoggingProfile, "logging_profile", true)
	appendAttr(pack, attrName, "translation-accounting-key="+decision.AccountingKey, "accounting_key", true)
	if decision.QuotaCorrelation {
		appendAttr(pack, attrName, "translation-quota-correlation=1", "quota_correlation", true)
	}
	if decision.AccountingCorrelation {
		appendAttr(pack, attrName, "translation-accounting-correlation=1", "accounting_correlation", true)
	}
}

func decompileVendorTranslationAVPair(result *TranslationPolicyCompileResult, value, field string) {
	normalized := strings.TrimSpace(strings.Trim(value, `"`))
	lower := strings.ToLower(normalized)
	rawValue := func(prefix string) string {
		return strings.TrimSpace(normalized[len(prefix):])
	}
	switch {
	case strings.HasPrefix(lower, "translation-policy="):
		result.Decision.LifecycleAction = normalizeTranslationPolicyLifecycleAction(rawValue("translation-policy="))
	case strings.HasPrefix(lower, "translation-owner="):
		result.Decision.Owner = rawValue("translation-owner=")
	case strings.HasPrefix(lower, "translation-revision="):
		result.Decision.Revision = rawValue("translation-revision=")
	case strings.HasPrefix(lower, "translation-mode="), strings.HasPrefix(lower, "nat-mode="):
		result.Decision.TranslationMode = normalizeTranslationMode(strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]))
	case strings.HasPrefix(lower, "translation-public-pool="), strings.HasPrefix(lower, "nat-pool="):
		result.Decision.PublicPool = strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:])
	case strings.HasPrefix(lower, "translation-public-ipv4="), strings.HasPrefix(lower, "public-ip="), strings.HasPrefix(lower, "nat-ip="):
		result.Decision.PublicIPv4 = normalizeTranslationIPv4Value(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "translation-private-ipv4-prefix="), strings.HasPrefix(lower, "private-prefix="):
		result.Decision.PrivateIPv4Prefix = normalizeTranslationPrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), "ipv4", field)
	case strings.HasPrefix(lower, "translation-subscriber-ipv6-prefix="), strings.HasPrefix(lower, "subscriber-ipv6-prefix="):
		result.Decision.SubscriberIPv6Prefix = normalizeTranslationPrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), "ipv6", field)
	case strings.HasPrefix(lower, "translation-nat64-prefix="), strings.HasPrefix(lower, "nat64-prefix="):
		result.Decision.NAT64Prefix = normalizeTranslationNAT64PrefixValue(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "translation-port-block="), strings.HasPrefix(lower, "port-block="):
		parseTranslationPortRange(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "translation-port-block-size="), strings.HasPrefix(lower, "port-block-size="):
		result.Decision.PortBlockSize = parseTranslationInt(result, strings.TrimSpace(normalized[strings.Index(normalized, "=")+1:]), field)
	case strings.HasPrefix(lower, "translation-log-profile="):
		result.Decision.LoggingProfile = rawValue("translation-log-profile=")
	case strings.HasPrefix(lower, "translation-accounting-key="):
		result.Decision.AccountingKey = rawValue("translation-accounting-key=")
		result.Decision.AccountingCorrelation = true
	case strings.HasPrefix(lower, "translation-quota-correlation=1"):
		result.Decision.QuotaCorrelation = true
	case strings.HasPrefix(lower, "translation-accounting-correlation=1"):
		result.Decision.AccountingCorrelation = true
	}
}

func selectTranslationPublicIPv4(pool config.RadiusTranslationPoolConfig, selectionKey string) (string, error) {
	return selectAddressFromPool(config.RadiusAddressPoolConfig{
		Name:   pool.Name,
		Family: pool.Family,
		CIDR:   pool.CIDR,
		Start:  pool.Start,
		End:    pool.End,
		Mode:   "address",
	}, selectionKey)
}

func selectTranslationPortBlock(minPort, maxPort, blockSize int, selectionKey string) (int, int, error) {
	if minPort < 1 || maxPort > 65535 || minPort > maxPort {
		return 0, 0, fmt.Errorf("invalid port range %d-%d", minPort, maxPort)
	}
	if blockSize <= 0 || blockSize > maxPort-minPort+1 {
		return 0, 0, fmt.Errorf("invalid port block size %d for range %d-%d", blockSize, minPort, maxPort)
	}
	slots := (maxPort - minPort + 1) / blockSize
	if slots <= 0 {
		return 0, 0, fmt.Errorf("port range %d-%d has no full block of size %d", minPort, maxPort, blockSize)
	}
	index := new(big.Int).Mod(hashAddressPolicyBig(selectionKey+"|translation-port-block"), big.NewInt(int64(slots))).Int64()
	start := minPort + int(index)*blockSize
	return start, start + blockSize - 1, nil
}

func translationPolicyPoolsByName(pools []config.RadiusTranslationPoolConfig) map[string]config.RadiusTranslationPoolConfig {
	out := map[string]config.RadiusTranslationPoolConfig{}
	for _, pool := range pools {
		name := strings.TrimSpace(pool.Name)
		if name == "" {
			continue
		}
		out[strings.ToLower(name)] = pool
	}
	return out
}

func translationPolicyForRole(policies []config.RadiusTranslationRolePolicy, role string) (config.RadiusTranslationRolePolicy, bool) {
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.Role), strings.TrimSpace(role)) {
			return policy, true
		}
	}
	return config.RadiusTranslationRolePolicy{}, false
}

func effectiveTranslationPolicyMaxMappings(policy config.RadiusTranslationPolicyConfig) int {
	if policy.MaxMappings <= 0 {
		return 256
	}
	return policy.MaxMappings
}

func effectiveTranslationPolicyOwner(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "aegisnas"
	}
	return value
}

func effectiveTranslationPolicyConflictMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prefer-role", "prefer-request", "warn":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "block"
	}
}

func effectiveTranslationAllocationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sticky", "dynamic":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "deterministic"
	}
}

func effectiveTranslationPortBlockSize(value int) int {
	if value <= 0 {
		return 512
	}
	return value
}

func effectiveTranslationMinPort(value int) int {
	if value <= 0 {
		return 1024
	}
	return value
}

func effectiveTranslationMaxPort(value int) int {
	if value <= 0 {
		return 65535
	}
	return value
}

func normalizeTranslationPolicyLifecycleAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "coa-update", "reauth", "withdraw", "accounting-stop":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "authorize"
	}
}

func normalizeTranslationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cgnat", "nat44", "nat64", "dual-stack", "ds-lite", "map-t":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func translationModeNeedsPublicIPv4(mode string) bool {
	switch normalizeTranslationMode(mode) {
	case "cgnat", "nat44", "dual-stack", "ds-lite", "map-t":
		return true
	default:
		return false
	}
}

func translationModeNeedsNAT64Prefix(mode string) bool {
	switch normalizeTranslationMode(mode) {
	case "nat64", "dual-stack":
		return true
	default:
		return false
	}
}

func translationModeNeedsPortBlock(mode string) bool {
	switch normalizeTranslationMode(mode) {
	case "cgnat", "nat44", "dual-stack", "ds-lite", "map-t":
		return true
	default:
		return false
	}
}

func translationPolicySelectionKey(req TranslationPolicyCompileRequest, role string) string {
	return firstReplyValue(strings.TrimSpace(req.SessionID), strings.TrimSpace(req.AcctSessionID), strings.TrimSpace(req.CallingStationID), strings.TrimSpace(req.NASIdentifier), strings.TrimSpace(req.NASIPAddress), role)
}

func translationPolicyRequestHasIntent(req TranslationPolicyCompileRequest) bool {
	for _, value := range []string{
		req.TranslationMode, req.PublicPool, req.PublicIPv4, req.PrivateIPv4Prefix,
		req.SubscriberIPv6Prefix, req.NAT64Prefix, req.LoggingProfile, req.AccountingKey,
	} {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return req.PortBlockStart > 0 || req.PortBlockEnd > 0 || req.PortBlockSize > 0 || req.QuotaCorrelation || req.AccountingCorrelation
}

func translationPolicyMappingCount(decision TranslationPolicyDecision) int {
	total := 0
	for _, value := range []string{
		decision.PublicPool, decision.PublicIPv4, decision.PrivateIPv4Prefix,
		decision.SubscriberIPv6Prefix, decision.NAT64Prefix,
	} {
		if strings.TrimSpace(value) != "" {
			total++
		}
	}
	if decision.PortBlockStart > 0 && decision.PortBlockEnd > 0 {
		total++
	}
	return total
}

func normalizeTranslationIPv4Value(result *TranslationPolicyCompileResult, value, field string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_public_ipv4", Message: err.Error(), Field: field, Value: value})
		return ""
	}
	if !addr.Is4() {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "address_family_mismatch", Message: "translation public address must be IPv4", Field: field, Value: value})
		return ""
	}
	return addr.String()
}

func normalizeTranslationPrefixValue(result *TranslationPolicyCompileResult, value, family, field string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_prefix", Message: err.Error(), Field: field, Value: value})
		return ""
	}
	prefix = prefix.Masked()
	if family == "ipv4" && !prefix.Addr().Is4() {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "prefix_family_mismatch", Message: "prefix must be IPv4", Field: field, Value: value})
		return ""
	}
	if family == "ipv6" && !prefix.Addr().Is6() {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "prefix_family_mismatch", Message: "prefix must be IPv6", Field: field, Value: value})
		return ""
	}
	return prefix.String()
}

func normalizeTranslationNAT64PrefixValue(result *TranslationPolicyCompileResult, value, field string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_nat64_prefix", Message: err.Error(), Field: field, Value: value})
		return ""
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "nat64_prefix_family_mismatch", Message: "NAT64 prefix must be IPv6", Field: field, Value: value})
		return ""
	}
	switch prefix.Bits() {
	case 32, 40, 48, 56, 64, 96:
		return prefix.String()
	default:
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_nat64_prefix_length", Message: "NAT64 prefix must use RFC 6052 length /32, /40, /48, /56, /64, or /96", Field: field, Value: value})
		return ""
	}
}

func parseTranslationInt(result *TranslationPolicyCompileResult, value, field string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_integer", Message: err.Error(), Field: field, Value: value})
		return 0
	}
	return parsed
}

func parseTranslationPortRange(result *TranslationPolicyCompileResult, value, field string) {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		result.Diagnostics = append(result.Diagnostics, TranslationPolicyDiagnostic{Severity: "error", Code: "invalid_port_block", Message: "port block must use start-end format", Field: field, Value: value})
		return
	}
	result.Decision.PortBlockStart = parseTranslationInt(result, parts[0], field)
	result.Decision.PortBlockEnd = parseTranslationInt(result, parts[1], field)
	if result.Decision.PortBlockStart > 0 && result.Decision.PortBlockEnd >= result.Decision.PortBlockStart {
		result.Decision.PortBlockSize = result.Decision.PortBlockEnd - result.Decision.PortBlockStart + 1
	}
}

func translationPolicyRevision(decision TranslationPolicyDecision) string {
	payload := struct {
		Role                 string `json:"role"`
		Owner                string `json:"owner"`
		Action               string `json:"action"`
		Mode                 string `json:"mode"`
		PublicPool           string `json:"public_pool,omitempty"`
		PublicIPv4           string `json:"public_ipv4,omitempty"`
		PrivateIPv4Prefix    string `json:"private_ipv4_prefix,omitempty"`
		SubscriberIPv6Prefix string `json:"subscriber_ipv6_prefix,omitempty"`
		NAT64Prefix          string `json:"nat64_prefix,omitempty"`
		PortBlockStart       int    `json:"port_block_start,omitempty"`
		PortBlockEnd         int    `json:"port_block_end,omitempty"`
		PortBlockSize        int    `json:"port_block_size,omitempty"`
	}{
		Role:                 decision.Role,
		Owner:                decision.Owner,
		Action:               decision.LifecycleAction,
		Mode:                 decision.TranslationMode,
		PublicPool:           decision.PublicPool,
		PublicIPv4:           decision.PublicIPv4,
		PrivateIPv4Prefix:    decision.PrivateIPv4Prefix,
		SubscriberIPv6Prefix: decision.SubscriberIPv6Prefix,
		NAT64Prefix:          decision.NAT64Prefix,
		PortBlockStart:       decision.PortBlockStart,
		PortBlockEnd:         decision.PortBlockEnd,
		PortBlockSize:        decision.PortBlockSize,
	}
	sum := sha256AddressPolicyJSON(payload)
	if len(sum) > 16 {
		return sum[:16]
	}
	return sum
}

func translationPolicyOwnershipKey(decision TranslationPolicyDecision) string {
	key := strings.Join([]string{
		firstReplyValue(decision.SessionID, decision.AcctSessionID, decision.SelectionKey, decision.Role),
		decision.Owner,
		decision.Revision,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return "translation-owner-" + hex.EncodeToString(sum[:12])
}

func translationPolicyAccountingKey(decision TranslationPolicyDecision) string {
	key := strings.Join([]string{
		firstReplyValue(decision.SessionID, decision.AcctSessionID, decision.SelectionKey, decision.Role),
		decision.PublicIPv4,
		strconv.Itoa(decision.PortBlockStart),
		strconv.Itoa(decision.PortBlockEnd),
		decision.NAT64Prefix,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return "trans-acct-" + hex.EncodeToString(sum[:10])
}

func translationPolicyRFCs() []string {
	return []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6052", "RFC 6145", "RFC 6146", "RFC 6888", "RFC 7422", "RFC 8219"}
}

func sha256TranslationPolicyJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
