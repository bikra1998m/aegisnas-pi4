package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const VLANPolicyCompilerVersion = 1

const (
	egressVLANIDTagged   = 0x31
	egressVLANIDUntagged = 0x32
)

type VLANPolicyCompileRequest struct {
	Role             string   `json:"role"`
	VLAN             int      `json:"vlan,omitempty"`
	CallingStationID string   `json:"calling_station_id,omitempty"`
	NASIdentifier    string   `json:"nas_identifier,omitempty"`
	AuthFailed       bool     `json:"auth_failed,omitempty"`
	Quarantined      bool     `json:"quarantined,omitempty"`
	PackKeys         []string `json:"pack_keys,omitempty"`
}

type VLANPolicyDecompileRequest struct {
	PackKey    string                `json:"pack_key,omitempty"`
	Attributes []VLANPolicyAttribute `json:"attributes"`
	Role       string                `json:"role,omitempty"`
}

type VLANPolicyCompileResult struct {
	CompilerVersion int                    `json:"compiler_version"`
	Status          string                 `json:"status"`
	Message         string                 `json:"message"`
	Decision        VLANPolicyDecision     `json:"decision"`
	Attributes      []VLANPolicyAttribute  `json:"attributes"`
	Summary         VLANPolicySummary      `json:"summary"`
	Diagnostics     []VLANPolicyDiagnostic `json:"diagnostics"`
	Fingerprint     string                 `json:"fingerprint"`
	RFCs            []string               `json:"rfcs"`
}

type VLANPolicyDecompileResult = VLANPolicyCompileResult

type VLANPolicyDecision struct {
	Role           string   `json:"role,omitempty"`
	PolicyMatched  bool     `json:"policy_matched"`
	PolicySource   string   `json:"policy_source"`
	AssignmentMode string   `json:"assignment_mode"`
	EffectiveVLAN  int      `json:"effective_vlan,omitempty"`
	DataVLAN       int      `json:"data_vlan,omitempty"`
	VoiceVLAN      int      `json:"voice_vlan,omitempty"`
	TaggedVLANs    []int    `json:"tagged_vlans,omitempty"`
	PoolName       string   `json:"pool_name,omitempty"`
	PoolStrategy   string   `json:"pool_strategy,omitempty"`
	PoolVLANs      []int    `json:"pool_vlans,omitempty"`
	FallbackVLAN   int      `json:"fallback_vlan,omitempty"`
	AuthFailVLAN   int      `json:"auth_fail_vlan,omitempty"`
	AuthFailed     bool     `json:"auth_failed,omitempty"`
	Quarantined    bool     `json:"quarantined,omitempty"`
	QinQEnabled    bool     `json:"qinq_enabled"`
	QinQMode       string   `json:"qinq_mode,omitempty"`
	QinQOuterVLAN  int      `json:"qinq_outer_vlan,omitempty"`
	QinQInnerVLAN  int      `json:"qinq_inner_vlan,omitempty"`
	VendorPacks    []string `json:"vendor_packs,omitempty"`
	SelectionKey   string   `json:"selection_key,omitempty"`
}

type VLANPolicyAttribute struct {
	PackKey string `json:"pack_key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Quoted  bool   `json:"quoted"`
	Purpose string `json:"purpose"`
}

type VLANPolicySummary struct {
	PolicyCount         int `json:"policy_count"`
	PoolCount           int `json:"pool_count"`
	PoolVLANCount       int `json:"pool_vlan_count"`
	EffectiveVLAN       int `json:"effective_vlan"`
	DataVLAN            int `json:"data_vlan"`
	VoiceVLAN           int `json:"voice_vlan"`
	TaggedVLANCount     int `json:"tagged_vlan_count"`
	QinQAssignmentCount int `json:"qinq_assignment_count"`
	FallbackAssignment  int `json:"fallback_assignment"`
	AuthFailAssignment  int `json:"auth_fail_assignment"`
	AttributeCount      int `json:"attribute_count"`
	DiagnosticCount     int `json:"diagnostic_count"`
}

type VLANPolicyDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"`
	PackKey  string `json:"pack_key,omitempty"`
	VLAN     int    `json:"vlan,omitempty"`
}

type VLANPolicyReport struct {
	CompilerVersion int                           `json:"compiler_version"`
	Enabled         bool                          `json:"enabled"`
	FailClosed      bool                          `json:"fail_closed"`
	MaxTaggedVLANs  int                           `json:"max_tagged_vlans"`
	Summary         VLANPolicyCatalogSummary      `json:"summary"`
	Capabilities    []VLANPolicyCapability        `json:"capabilities"`
	Policies        []config.RadiusVLANRolePolicy `json:"policies"`
	Pools           []config.RadiusVLANPoolConfig `json:"pools"`
	RFCs            []string                      `json:"rfcs"`
}

type VLANPolicyCatalogSummary struct {
	PolicyCount      int `json:"policy_count"`
	PoolCount        int `json:"pool_count"`
	PoolVLANCount    int `json:"pool_vlan_count"`
	VoicePolicyCount int `json:"voice_policy_count"`
	QinQPolicyCount  int `json:"qinq_policy_count"`
	FallbackCount    int `json:"fallback_count"`
	AuthFailCount    int `json:"auth_fail_count"`
}

type VLANPolicyCapability struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Status     string   `json:"status"`
	Attributes []string `json:"attributes"`
	Vendors    []string `json:"vendors"`
	Notes      string   `json:"notes,omitempty"`
}

func BuildVLANPolicyReport(cfg *config.Config) VLANPolicyReport {
	policy := config.RadiusVLANPolicyConfig{}
	if cfg != nil {
		policy = cfg.Radius.VLANPolicy
	}
	report := VLANPolicyReport{
		CompilerVersion: VLANPolicyCompilerVersion,
		Enabled:         policy.Enabled,
		FailClosed:      policy.FailClosed,
		MaxTaggedVLANs:  effectiveMaxTaggedVLANs(policy),
		Policies:        append([]config.RadiusVLANRolePolicy(nil), policy.RolePolicies...),
		Pools:           append([]config.RadiusVLANPoolConfig(nil), policy.Pools...),
		RFCs:            vlanPolicyRFCs(),
		Capabilities: []VLANPolicyCapability{
			{Key: "data_vlan", Label: "Data VLAN", Status: "implemented", Attributes: []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "AegisNAS-Data-VLAN"}, Vendors: []string{"standards-based", "all VLAN-capable NAS"}},
			{Key: "tagged_voice_vlan", Label: "Tagged Voice VLAN", Status: "implemented", Attributes: []string{"Egress-VLANID", "AegisNAS-Voice-VLAN"}, Vendors: []string{"HP", "Cisco", "Extreme", "Juniper", "Huawei", "standards-based"}, Notes: "Device behavior requires release certification by firmware."},
			{Key: "extra_tagged_vlans", Label: "Extra Tagged VLANs", Status: "implemented", Attributes: []string{"Egress-VLANID", "AegisNAS-Tagged-VLAN"}, Vendors: []string{"HP", "Extreme", "carrier access", "standards-based"}},
			{Key: "qinq", Label: "QinQ Intent", Status: "implemented", Attributes: []string{"AegisNAS-QinQ-Outer-VLAN", "AegisNAS-QinQ-Inner-VLAN"}, Vendors: []string{"carrier access", "Juniper", "Huawei", "Cisco", "Nokia"}, Notes: "Portable RADIUS output is product VSA and evidence; native device encodings require vendor certification."},
			{Key: "vlan_pool", Label: "VLAN Pool Selection", Status: "implemented", Attributes: []string{"Tunnel-Private-Group-Id", "AegisNAS-VLAN-Pool"}, Vendors: []string{"all VLAN-capable NAS"}},
			{Key: "fallback", Label: "Fallback And Auth-Fail VLAN", Status: "implemented", Attributes: []string{"Tunnel-Private-Group-Id", "AegisNAS-Fallback-VLAN", "AegisNAS-Auth-Fail-VLAN"}, Vendors: []string{"Cisco", "Aruba", "HP", "Extreme", "Juniper", "Huawei", "standards-based"}},
		},
	}
	report.Summary.PolicyCount = len(policy.RolePolicies)
	report.Summary.PoolCount = len(policy.Pools)
	for _, pool := range policy.Pools {
		report.Summary.PoolVLANCount += len(pool.VLANs)
	}
	for _, rolePolicy := range policy.RolePolicies {
		if rolePolicy.VoiceVLAN > 0 {
			report.Summary.VoicePolicyCount++
		}
		if rolePolicy.QinQ.Enabled {
			report.Summary.QinQPolicyCount++
		}
		if rolePolicy.FallbackVLAN > 0 {
			report.Summary.FallbackCount++
		}
		if rolePolicy.AuthFailVLAN > 0 {
			report.Summary.AuthFailCount++
		}
	}
	return report
}

func CompileVLANPolicy(cfg *config.Config, req VLANPolicyCompileRequest) VLANPolicyCompileResult {
	result := VLANPolicyCompileResult{
		CompilerVersion: VLANPolicyCompilerVersion,
		Status:          "ready",
		RFCs:            vlanPolicyRFCs(),
	}
	if cfg == nil {
		result.Status = "blocked"
		result.Message = "configuration is required"
		result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: "missing_config", Message: result.Message})
		finalizeVLANPolicyResult(&result)
		return result
	}
	policy := cfg.Radius.VLANPolicy
	result.Summary.PolicyCount = len(policy.RolePolicies)
	result.Summary.PoolCount = len(policy.Pools)
	for _, pool := range policy.Pools {
		result.Summary.PoolVLANCount += len(pool.VLANs)
	}
	if !policy.Enabled {
		result.Status = "blocked"
		result.Message = "VLAN policy compiler is disabled"
		result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: "disabled", Message: result.Message, Field: "radius.vlan_policy.enabled"})
		finalizeVLANPolicyResult(&result)
		return result
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "default"
	}
	result.Decision.Role = role
	result.Decision.AuthFailed = req.AuthFailed
	result.Decision.Quarantined = req.Quarantined
	pools := vlanPolicyPoolsByName(policy.Pools)
	rolePolicy, matched := vlanPolicyForRole(policy.RolePolicies, role)
	if matched {
		result.Decision.PolicyMatched = true
		result.Decision.PolicySource = "radius.vlan_policy.role_policies"
		result.Decision.VendorPacks = normalizeVLANPolicyPackKeys(rolePolicy.VendorPacks)
		result.Decision.FallbackVLAN = firstPositiveInt(rolePolicy.FallbackVLAN, policy.DefaultFallbackVLAN)
		result.Decision.AuthFailVLAN = firstPositiveInt(rolePolicy.AuthFailVLAN, policy.DefaultAuthFailVLAN)
		result.Decision.VoiceVLAN = rolePolicy.VoiceVLAN
		result.Decision.TaggedVLANs = normalizeVLANList(rolePolicy.TaggedVLANs)
		result.Decision.PoolName = strings.TrimSpace(rolePolicy.Pool)
		if result.Decision.PoolName != "" {
			if pool, ok := pools[strings.ToLower(result.Decision.PoolName)]; ok {
				result.Decision.PoolVLANs = normalizeVLANList(pool.VLANs)
				result.Decision.PoolStrategy = firstReplyValue(strings.ToLower(strings.TrimSpace(pool.Strategy)), "hash-calling-station")
				selected, selectionKey := selectVLANFromPool(pool, req, role)
				result.Decision.SelectionKey = selectionKey
				result.Decision.DataVLAN = selected
				result.Decision.EffectiveVLAN = selected
			}
		}
		if result.Decision.EffectiveVLAN == 0 {
			result.Decision.DataVLAN = firstPositiveInt(rolePolicy.DataVLAN, req.VLAN)
			result.Decision.EffectiveVLAN = result.Decision.DataVLAN
		}
		if rolePolicy.QinQ.Enabled {
			result.Decision.QinQEnabled = true
			result.Decision.QinQMode = firstReplyValue(strings.ToLower(strings.TrimSpace(rolePolicy.QinQ.Mode)), "provider-bridge")
			result.Decision.QinQOuterVLAN = rolePolicy.QinQ.OuterVLAN
			result.Decision.QinQInnerVLAN = firstPositiveInt(rolePolicy.QinQ.InnerVLAN, result.Decision.EffectiveVLAN)
		}
	} else {
		result.Decision.PolicySource = "request"
		result.Decision.FallbackVLAN = policy.DefaultFallbackVLAN
		result.Decision.AuthFailVLAN = policy.DefaultAuthFailVLAN
		result.Decision.DataVLAN = req.VLAN
		result.Decision.EffectiveVLAN = req.VLAN
		result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "warning", Code: "role_policy_missing", Message: "no VLAN policy matched the role; request VLAN and defaults were used", Field: "role"})
	}

	if req.AuthFailed && result.Decision.AuthFailVLAN > 0 {
		result.Decision.AssignmentMode = "auth-fail"
		result.Decision.EffectiveVLAN = result.Decision.AuthFailVLAN
		result.Decision.DataVLAN = result.Decision.AuthFailVLAN
		result.Summary.AuthFailAssignment = result.Decision.AuthFailVLAN
	} else if result.Decision.EffectiveVLAN == 0 && result.Decision.FallbackVLAN > 0 {
		result.Decision.AssignmentMode = "fallback"
		result.Decision.EffectiveVLAN = result.Decision.FallbackVLAN
		result.Decision.DataVLAN = result.Decision.FallbackVLAN
		result.Summary.FallbackAssignment = result.Decision.FallbackVLAN
	} else if result.Decision.PoolName != "" && result.Decision.EffectiveVLAN > 0 {
		result.Decision.AssignmentMode = "pool"
	} else if result.Decision.QinQEnabled {
		result.Decision.AssignmentMode = "qinq"
	} else if result.Decision.VoiceVLAN > 0 || len(result.Decision.TaggedVLANs) > 0 {
		result.Decision.AssignmentMode = "voice-data"
	} else {
		result.Decision.AssignmentMode = "access"
	}

	validateCompiledVLANDecision(&result, policy)
	result.Attributes = BuildVLANPolicyAttributes(result.Decision, effectiveVLANPolicyPackKeys(req.PackKeys, result.Decision.VendorPacks, cfg.Radius.Vendor.CompatibilityPacks))
	finalizeVLANPolicyResult(&result)
	return result
}

func DecompileVLANPolicyAttributes(req VLANPolicyDecompileRequest) VLANPolicyDecompileResult {
	result := VLANPolicyCompileResult{
		CompilerVersion: VLANPolicyCompilerVersion,
		Status:          "decompiled",
		RFCs:            vlanPolicyRFCs(),
		Attributes:      append([]VLANPolicyAttribute(nil), req.Attributes...),
	}
	packKey := productconfigs.NormalizeVendorCompatibilityPackKey(req.PackKey)
	if packKey == "" {
		packKey = productconfigs.VendorPackStandard
	}
	result.Decision.Role = strings.TrimSpace(req.Role)
	result.Decision.PolicySource = "decompile"
	result.Decision.AssignmentMode = "access"
	result.Decision.VendorPacks = []string{packKey}

	for index, attr := range req.Attributes {
		name := strings.ToLower(strings.TrimSpace(attr.Name))
		value := strings.TrimSpace(attr.Value)
		if name == "" || value == "" {
			result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "warning", Code: "empty_attribute", Message: "empty VLAN attribute was ignored", Field: fmt.Sprintf("attributes[%d]", index), PackKey: packKey})
			continue
		}
		switch name {
		case "tunnel-private-group-id", "aegisnas-vlan", "aegisnas-data-vlan", "aruba-user-vlan", "ruckus-vlan-id", "cambium-epmp-data-vlan-id", "extreme-user-vlan", "nomadix-net-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if !ok || !validRuntimeVLAN(vlan) {
				result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: "invalid_data_vlan", Message: "data VLAN attribute has an invalid VLAN ID", Field: attr.Name, PackKey: packKey})
				continue
			}
			result.Decision.DataVLAN = vlan
			result.Decision.EffectiveVLAN = vlan
		case "egress-vlanid":
			vlan, tagged, ok := DecodeEgressVLANID(value)
			if !ok {
				result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: "invalid_egress_vlanid", Message: "Egress-VLANID has an invalid VLAN encoding", Field: attr.Name, PackKey: packKey})
				continue
			}
			if tagged {
				result.Decision.TaggedVLANs = appendUniqueVLANs(result.Decision.TaggedVLANs, 0, vlan)
			} else {
				result.Decision.DataVLAN = vlan
				result.Decision.EffectiveVLAN = vlan
			}
		case "aegisnas-voice-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.VoiceVLAN = vlan
			}
		case "aegisnas-tagged-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.TaggedVLANs = appendUniqueVLANs(result.Decision.TaggedVLANs, 0, vlan)
			}
		case "aegisnas-qinq-outer-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.QinQEnabled = true
				result.Decision.QinQOuterVLAN = vlan
			}
		case "aegisnas-qinq-inner-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.QinQEnabled = true
				result.Decision.QinQInnerVLAN = vlan
			}
		case "aegisnas-vlan-pool":
			result.Decision.PoolName = value
		case "aegisnas-fallback-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.FallbackVLAN = vlan
			}
		case "aegisnas-auth-fail-vlan":
			vlan, ok := parseVLANPolicyInt(value)
			if ok && validRuntimeVLAN(vlan) {
				result.Decision.AuthFailVLAN = vlan
			}
		case "aegisnas-vlan-policy":
			result.Decision.AssignmentMode = strings.ToLower(value)
		case "extreme-netlogin-extended-vlan":
			untagged, hasUntagged, tagged, ok := parseExtremeExtendedVLAN(value)
			if !ok {
				result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: "invalid_extreme_extended_vlan", Message: "Extreme extended VLAN attribute could not be parsed", Field: attr.Name, PackKey: packKey})
				continue
			}
			if hasUntagged {
				result.Decision.DataVLAN = untagged
				result.Decision.EffectiveVLAN = untagged
			}
			result.Decision.TaggedVLANs = appendUniqueVLANs(result.Decision.TaggedVLANs, 0, tagged...)
		}
	}

	if result.Decision.VoiceVLAN > 0 {
		result.Decision.TaggedVLANs = removeVLANFromList(result.Decision.TaggedVLANs, result.Decision.VoiceVLAN)
	}
	result.Decision.TaggedVLANs = normalizeVLANList(result.Decision.TaggedVLANs)
	if result.Decision.AssignmentMode == "" || result.Decision.AssignmentMode == "access" {
		switch {
		case result.Decision.QinQEnabled:
			result.Decision.AssignmentMode = "qinq"
		case result.Decision.PoolName != "":
			result.Decision.AssignmentMode = "pool"
		case result.Decision.VoiceVLAN > 0 || len(result.Decision.TaggedVLANs) > 0:
			result.Decision.AssignmentMode = "voice-data"
		default:
			result.Decision.AssignmentMode = "access"
		}
	}
	validateCompiledVLANDecision(&result, config.RadiusVLANPolicyConfig{Enabled: true, MaxTaggedVLANs: 64})
	if len(result.Diagnostics) > 0 {
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "error" {
				result.Status = "blocked"
				break
			}
			if result.Status != "blocked" && diagnostic.Severity == "warning" {
				result.Status = "degraded"
			}
		}
	}
	result.Message = fmt.Sprintf("VLAN policy decompiled %d attribute(s)", len(req.Attributes))
	finalizeVLANPolicyResult(&result)
	return result
}

func BuildVLANPolicyAttributes(decision VLANPolicyDecision, packKeys []string) []VLANPolicyAttribute {
	packKeys = normalizeVLANPolicyPackKeys(packKeys)
	if len(packKeys) == 0 {
		packKeys = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
	}
	attrs := make([]VLANPolicyAttribute, 0, 16)
	appendAttr := func(pack, name, value, purpose string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		attrs = append(attrs, VLANPolicyAttribute{PackKey: pack, Name: name, Value: value, Quoted: quoted, Purpose: purpose})
	}
	for _, pack := range packKeys {
		switch pack {
		case productconfigs.VendorPackStandard:
			if decision.EffectiveVLAN > 0 {
				appendAttr(pack, "Tunnel-Type", "VLAN", "data_vlan", false)
				appendAttr(pack, "Tunnel-Medium-Type", "IEEE-802", "data_vlan", false)
				appendAttr(pack, "Tunnel-Private-Group-Id", strconv.Itoa(decision.EffectiveVLAN), "data_vlan", true)
			}
			for _, vlan := range appendUniqueVLANs(nil, decision.VoiceVLAN, decision.TaggedVLANs...) {
				appendAttr(pack, "Egress-VLANID", strconv.FormatUint(uint64(EncodeEgressVLANID(vlan, true)), 10), "tagged_vlan", false)
			}
		case productconfigs.VendorPackAegisNAS:
			appendAttr(pack, "AegisNAS-VLAN-Policy", decision.AssignmentMode, "policy", true)
			if decision.EffectiveVLAN > 0 {
				appendAttr(pack, "AegisNAS-Data-VLAN", strconv.Itoa(decision.EffectiveVLAN), "data_vlan", false)
			}
			if decision.VoiceVLAN > 0 {
				appendAttr(pack, "AegisNAS-Voice-VLAN", strconv.Itoa(decision.VoiceVLAN), "voice_vlan", false)
			}
			for _, vlan := range decision.TaggedVLANs {
				appendAttr(pack, "AegisNAS-Tagged-VLAN", strconv.Itoa(vlan), "tagged_vlan", false)
			}
			if decision.QinQEnabled {
				appendAttr(pack, "AegisNAS-QinQ-Outer-VLAN", strconv.Itoa(decision.QinQOuterVLAN), "qinq", false)
				appendAttr(pack, "AegisNAS-QinQ-Inner-VLAN", strconv.Itoa(decision.QinQInnerVLAN), "qinq", false)
			}
			appendAttr(pack, "AegisNAS-VLAN-Pool", decision.PoolName, "pool", true)
			if decision.FallbackVLAN > 0 {
				appendAttr(pack, "AegisNAS-Fallback-VLAN", strconv.Itoa(decision.FallbackVLAN), "fallback", false)
			}
			if decision.AuthFailVLAN > 0 {
				appendAttr(pack, "AegisNAS-Auth-Fail-VLAN", strconv.Itoa(decision.AuthFailVLAN), "auth_fail", false)
			}
		case productconfigs.VendorPackExtreme:
			value := extremeVLANPolicyValue(decision)
			appendAttr(pack, "Extreme-Netlogin-Extended-Vlan", value, "extended_vlan", true)
		case productconfigs.VendorPackHP:
			if decision.EffectiveVLAN > 0 {
				appendAttr(pack, "Egress-VLANID", strconv.FormatUint(uint64(EncodeEgressVLANID(decision.EffectiveVLAN, false)), 10), "data_vlan", false)
			}
			for _, vlan := range appendUniqueVLANs(nil, decision.VoiceVLAN, decision.TaggedVLANs...) {
				appendAttr(pack, "Egress-VLANID", strconv.FormatUint(uint64(EncodeEgressVLANID(vlan, true)), 10), "tagged_vlan", false)
			}
		}
	}
	return attrs
}

func EncodeEgressVLANID(vlan int, tagged bool) uint32 {
	if vlan < 1 || vlan > 4094 {
		return 0
	}
	tag := uint32(egressVLANIDUntagged)
	if tagged {
		tag = egressVLANIDTagged
	}
	return (tag << 24) | uint32(vlan&0x0fff)
}

func DecodeEgressVLANID(value string) (int, bool, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return 0, false, false
	}
	parsed, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return 0, false, false
	}
	if parsed >= 1 && parsed <= 4094 {
		return int(parsed), false, true
	}
	tag := byte(parsed >> 24)
	vlan := int(parsed & 0x0fff)
	if !validRuntimeVLAN(vlan) {
		return 0, false, false
	}
	switch tag {
	case egressVLANIDTagged:
		return vlan, true, true
	case egressVLANIDUntagged:
		return vlan, false, true
	default:
		return 0, false, false
	}
}

func ApplyVLANPolicyToReplyAttributes(attrs *ReplyAttributes, result VLANPolicyCompileResult) {
	if attrs == nil || result.Status == "blocked" {
		return
	}
	decision := result.Decision
	if decision.EffectiveVLAN > 0 {
		attrs.VLAN = decision.EffectiveVLAN
		attrs.TunnelType = "VLAN"
		attrs.TunnelMediumType = "IEEE-802"
		attrs.TunnelPrivateGroupID = strconv.Itoa(decision.EffectiveVLAN)
	}
	attrs.DataVLAN = decision.DataVLAN
	attrs.VoiceVLAN = decision.VoiceVLAN
	attrs.TaggedVLANs = append([]int(nil), decision.TaggedVLANs...)
	attrs.QinQOuterVLAN = decision.QinQOuterVLAN
	attrs.QinQInnerVLAN = decision.QinQInnerVLAN
	attrs.VLANPool = decision.PoolName
	attrs.FallbackVLAN = decision.FallbackVLAN
	attrs.AuthFailVLAN = decision.AuthFailVLAN
	attrs.VLANPolicyMode = decision.AssignmentMode
	attrs.VLANPolicyFingerprint = result.Fingerprint
}

func ApplyConfiguredVLANPolicyToReplyAttributes(cfg *config.Config, attrs *ReplyAttributes, req VLANPolicyCompileRequest) (VLANPolicyCompileResult, bool) {
	if cfg == nil || attrs == nil || !cfg.Radius.VLANPolicy.Enabled {
		return VLANPolicyCompileResult{}, false
	}
	if strings.TrimSpace(req.Role) == "" {
		req.Role = replyRole(attrs)
	}
	if req.VLAN == 0 {
		req.VLAN = replyVLAN(attrs)
	}
	result := CompileVLANPolicy(cfg, req)
	if result.Status == "blocked" {
		return result, false
	}
	switch result.Decision.AssignmentMode {
	case "fallback", "auth-fail":
		ApplyVLANPolicyToReplyAttributes(attrs, result)
		return result, true
	}
	if !result.Decision.PolicyMatched {
		return result, false
	}
	ApplyVLANPolicyToReplyAttributes(attrs, result)
	return result, true
}

func finalizeVLANPolicyResult(result *VLANPolicyCompileResult) {
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
	result.Summary.EffectiveVLAN = result.Decision.EffectiveVLAN
	result.Summary.DataVLAN = result.Decision.DataVLAN
	result.Summary.VoiceVLAN = result.Decision.VoiceVLAN
	result.Summary.TaggedVLANCount = len(result.Decision.TaggedVLANs)
	if result.Decision.QinQEnabled {
		result.Summary.QinQAssignmentCount = 1
	}
	result.Summary.AttributeCount = len(result.Attributes)
	result.Summary.DiagnosticCount = len(result.Diagnostics)
	if strings.TrimSpace(result.Message) == "" {
		result.Message = fmt.Sprintf("VLAN policy compiled %d attribute(s) for role %s", len(result.Attributes), firstReplyValue(result.Decision.Role, "default"))
	}
	payload := struct {
		Version    int                   `json:"version"`
		Status     string                `json:"status"`
		Decision   VLANPolicyDecision    `json:"decision"`
		Attributes []VLANPolicyAttribute `json:"attributes"`
	}{
		Version:    result.CompilerVersion,
		Status:     result.Status,
		Decision:   result.Decision,
		Attributes: result.Attributes,
	}
	result.Fingerprint = "sha256:" + sha256VLANPolicyJSON(payload)
}

func validateCompiledVLANDecision(result *VLANPolicyCompileResult, policy config.RadiusVLANPolicyConfig) {
	if result == nil {
		return
	}
	addError := func(code, message, field string, vlan int) {
		result.Diagnostics = append(result.Diagnostics, VLANPolicyDiagnostic{Severity: "error", Code: code, Message: message, Field: field, VLAN: vlan})
	}
	if result.Decision.EffectiveVLAN != 0 && !validRuntimeVLAN(result.Decision.EffectiveVLAN) {
		addError("invalid_effective_vlan", "effective VLAN is outside the range 1-4094", "effective_vlan", result.Decision.EffectiveVLAN)
	}
	if result.Decision.VoiceVLAN != 0 && !validRuntimeVLAN(result.Decision.VoiceVLAN) {
		addError("invalid_voice_vlan", "voice VLAN is outside the range 1-4094", "voice_vlan", result.Decision.VoiceVLAN)
	}
	maxTagged := effectiveMaxTaggedVLANs(policy)
	if len(result.Decision.TaggedVLANs) > maxTagged {
		addError("too_many_tagged_vlans", fmt.Sprintf("tagged VLAN count exceeds limit %d", maxTagged), "tagged_vlans", 0)
	}
	seen := map[int]string{}
	for _, binding := range []struct {
		vlan  int
		field string
	}{
		{result.Decision.EffectiveVLAN, "effective_vlan"},
		{result.Decision.VoiceVLAN, "voice_vlan"},
	} {
		if binding.vlan == 0 {
			continue
		}
		if previous := seen[binding.vlan]; previous != "" {
			addError("duplicate_vlan_assignment", fmt.Sprintf("VLAN %d appears in both %s and %s", binding.vlan, previous, binding.field), binding.field, binding.vlan)
		}
		seen[binding.vlan] = binding.field
	}
	for _, vlan := range result.Decision.TaggedVLANs {
		if !validRuntimeVLAN(vlan) {
			addError("invalid_tagged_vlan", "tagged VLAN is outside the range 1-4094", "tagged_vlans", vlan)
			continue
		}
		if previous := seen[vlan]; previous != "" {
			addError("duplicate_vlan_assignment", fmt.Sprintf("VLAN %d appears in both %s and tagged_vlans", vlan, previous), "tagged_vlans", vlan)
		}
		seen[vlan] = "tagged_vlans"
	}
	if result.Decision.QinQEnabled {
		if !validRuntimeVLAN(result.Decision.QinQOuterVLAN) {
			addError("invalid_qinq_outer_vlan", "QinQ outer VLAN is outside the range 1-4094", "qinq.outer_vlan", result.Decision.QinQOuterVLAN)
		}
		if !validRuntimeVLAN(result.Decision.QinQInnerVLAN) {
			addError("invalid_qinq_inner_vlan", "QinQ inner VLAN is outside the range 1-4094", "qinq.inner_vlan", result.Decision.QinQInnerVLAN)
		}
		if result.Decision.QinQOuterVLAN == result.Decision.QinQInnerVLAN {
			addError("duplicate_qinq_vlan", "QinQ inner and outer VLANs must differ", "qinq", result.Decision.QinQOuterVLAN)
		}
	}
	if result.Decision.EffectiveVLAN == 0 && policy.FailClosed {
		addError("missing_vlan", "no effective VLAN was selected and fail_closed is enabled", "effective_vlan", 0)
	}
}

func vlanPolicyForRole(policies []config.RadiusVLANRolePolicy, role string) (config.RadiusVLANRolePolicy, bool) {
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.Role), strings.TrimSpace(role)) {
			return policy, true
		}
	}
	return config.RadiusVLANRolePolicy{}, false
}

func vlanPolicyPoolsByName(pools []config.RadiusVLANPoolConfig) map[string]config.RadiusVLANPoolConfig {
	out := map[string]config.RadiusVLANPoolConfig{}
	for _, pool := range pools {
		name := strings.ToLower(strings.TrimSpace(pool.Name))
		if name != "" {
			out[name] = pool
		}
	}
	return out
}

func selectVLANFromPool(pool config.RadiusVLANPoolConfig, req VLANPolicyCompileRequest, role string) (int, string) {
	vlans := normalizeVLANList(pool.VLANs)
	if len(vlans) == 0 {
		return 0, ""
	}
	strategy := strings.ToLower(strings.TrimSpace(pool.Strategy))
	switch strategy {
	case "first":
		return vlans[0], "first"
	case "hash-nas":
		key := firstReplyValue(strings.TrimSpace(req.NASIdentifier), role)
		h := fnv.New32a()
		_, _ = h.Write([]byte(key))
		return vlans[int(h.Sum32())%len(vlans)], key
	case "hash-role":
		key := firstReplyValue(role, strings.TrimSpace(req.CallingStationID), pool.Name)
		h := fnv.New32a()
		_, _ = h.Write([]byte(key))
		return vlans[int(h.Sum32())%len(vlans)], key
	case "hash-calling-station", "":
		key := vlanPoolSelectionKey(req, role)
		h := fnv.New32a()
		_, _ = h.Write([]byte(firstReplyValue(key, role, pool.Name)))
		return vlans[int(h.Sum32())%len(vlans)], key
	default:
		return vlans[0], "first"
	}
}

func vlanPoolSelectionKey(req VLANPolicyCompileRequest, role string) string {
	return firstReplyValue(strings.TrimSpace(req.CallingStationID), strings.TrimSpace(req.NASIdentifier), role)
}

func effectiveMaxTaggedVLANs(policy config.RadiusVLANPolicyConfig) int {
	if policy.MaxTaggedVLANs <= 0 {
		return 10
	}
	return policy.MaxTaggedVLANs
}

func effectiveVLANPolicyPackKeys(requested, rolePacks, configured []string) []string {
	if len(requested) > 0 {
		return normalizeVLANPolicyPackKeys(requested)
	}
	if len(rolePacks) > 0 {
		return normalizeVLANPolicyPackKeys(rolePacks)
	}
	if len(configured) > 0 {
		return normalizeVLANPolicyPackKeys(configured)
	}
	return []string{productconfigs.VendorPackStandard, productconfigs.VendorPackAegisNAS}
}

func normalizeVLANPolicyPackKeys(values []string) []string {
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

func normalizeVLANList(values []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(values))
	for _, vlan := range values {
		if !validRuntimeVLAN(vlan) {
			continue
		}
		if _, exists := seen[vlan]; exists {
			continue
		}
		seen[vlan] = struct{}{}
		out = append(out, vlan)
	}
	sort.Ints(out)
	return out
}

func appendUniqueVLANs(base []int, first int, values ...int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(base)+len(values)+1)
	for _, vlan := range base {
		if validRuntimeVLAN(vlan) {
			seen[vlan] = struct{}{}
			out = append(out, vlan)
		}
	}
	if validRuntimeVLAN(first) {
		seen[first] = struct{}{}
		out = append(out, first)
	}
	for _, vlan := range values {
		if !validRuntimeVLAN(vlan) {
			continue
		}
		if _, exists := seen[vlan]; exists {
			continue
		}
		seen[vlan] = struct{}{}
		out = append(out, vlan)
	}
	sort.Ints(out)
	return out
}

func removeVLANFromList(values []int, denied int) []int {
	if denied == 0 {
		return values
	}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value != denied {
			out = append(out, value)
		}
	}
	return out
}

func extremeVLANPolicyValue(decision VLANPolicyDecision) string {
	parts := make([]string, 0, len(decision.TaggedVLANs)+2)
	if decision.EffectiveVLAN > 0 {
		parts = append(parts, fmt.Sprintf("U%d", decision.EffectiveVLAN))
	}
	for _, vlan := range appendUniqueVLANs(nil, decision.VoiceVLAN, decision.TaggedVLANs...) {
		parts = append(parts, fmt.Sprintf("T%d", vlan))
	}
	return strings.Join(parts, ";")
}

func validRuntimeVLAN(vlan int) bool {
	return vlan >= 1 && vlan <= 4094
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func parseVLANPolicyInt(value string) (int, bool) {
	parsed, err := strconv.Atoi(strings.TrimSpace(strings.Trim(value, `"`)))
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func vlanPolicyRFCs() []string {
	return []string{"RFC 2865", "RFC 2868", "RFC 3580", "RFC 4675", "RFC 5176"}
}

func sha256VLANPolicyJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(fmt.Sprint(value))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
