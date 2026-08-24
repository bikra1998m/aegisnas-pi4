package radius

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const CiscoAVPairMaxValueLength = 240

type CiscoAVPairKind string

const (
	CiscoAVPairKindUnknown       CiscoAVPairKind = "unknown"
	CiscoAVPairKindDynamicACL    CiscoAVPairKind = "dynamic_acl"
	CiscoAVPairKindRoute         CiscoAVPairKind = "route"
	CiscoAVPairKindVRF           CiscoAVPairKind = "vrf"
	CiscoAVPairKindAddressPool   CiscoAVPairKind = "address_pool"
	CiscoAVPairKindTrustSecSGT   CiscoAVPairKind = "trustsec_sgt"
	CiscoAVPairKindVPN           CiscoAVPairKind = "vpn_policy"
	CiscoAVPairKindVoice         CiscoAVPairKind = "voice_policy"
	CiscoAVPairKindCommandAuth   CiscoAVPairKind = "command_authorization"
	CiscoAVPairKindPosture       CiscoAVPairKind = "posture"
	CiscoAVPairKindTranslation   CiscoAVPairKind = "translation"
	CiscoAVPairKindCharging      CiscoAVPairKind = "charging"
	CiscoAVPairKindSubscriberSvc CiscoAVPairKind = "subscriber_service"
)

type CiscoAVPair struct {
	Raw       string          `json:"raw"`
	Namespace string          `json:"namespace,omitempty"`
	Name      string          `json:"name"`
	Operator  string          `json:"operator"`
	Value     string          `json:"value"`
	Sequence  int             `json:"sequence,omitempty"`
	Direction string          `json:"direction,omitempty"`
	Kind      CiscoAVPairKind `json:"kind"`
	Semantic  string          `json:"semantic,omitempty"`
}

type CiscoAVPairIntent struct {
	ACLRules             []ACLRule
	SecurityGroupTag     int
	SecurityGroupName    string
	VPNGroupPolicy       string
	VPNTunnelGroup       string
	VPNSplitTunnelList   string
	VoiceTrafficClass    string
	ShellPrivilegeLevel  int
	ShellRoles           []string
	PostureStatus        string
	AuditSessionID       string
	IPv4Routes           []string
	IPv6Routes           []string
	VRF                  string
	IPv4Pool             string
	IPv6Pool             string
	DelegatedIPv6Prefix  string
	TranslationPolicy    string
	TranslationPublicIP  string
	TranslationPortBlock string
	ChargingProfile      string
	Custom               []string
}

func ParseCiscoAVPair(raw string) (CiscoAVPair, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair is empty")
	}
	if len(trimmed) > CiscoAVPairMaxValueLength {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair exceeds %d bytes", CiscoAVPairMaxValueLength)
	}
	if containsControlRune(trimmed) {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair contains control characters")
	}
	idx := strings.Index(trimmed, "=")
	if idx <= 0 || idx == len(trimmed)-1 {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair must use name=value form")
	}
	left := strings.TrimSpace(trimmed[:idx])
	value := strings.TrimSpace(trimmed[idx+1:])
	if left == "" || value == "" {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair requires non-empty name and value")
	}
	pair := CiscoAVPair{Raw: trimmed, Operator: "=", Value: value}
	if colon := strings.Index(left, ":"); colon >= 0 {
		pair.Namespace = strings.ToLower(strings.TrimSpace(left[:colon]))
		left = strings.TrimSpace(left[colon+1:])
	}
	if hash := strings.LastIndex(left, "#"); hash >= 0 {
		seq, err := strconv.Atoi(strings.TrimSpace(left[hash+1:]))
		if err != nil || seq < 1 || seq > 4096 {
			return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair sequence is invalid")
		}
		pair.Sequence = seq
		left = strings.TrimSpace(left[:hash])
	}
	pair.Name = strings.ToLower(left)
	if !validCiscoAVPairToken(pair.Namespace) || !validCiscoAVPairToken(pair.Name) {
		return CiscoAVPair{}, fmt.Errorf("Cisco-AVPair contains an invalid namespace or name")
	}
	pair.Kind, pair.Semantic, pair.Direction = classifyCiscoAVPair(pair)
	return pair, nil
}

func ParseCiscoAVPairs(values []string) ([]CiscoAVPair, []string) {
	pairs := make([]CiscoAVPair, 0, len(values))
	diagnostics := []string{}
	for _, value := range values {
		pair, err := ParseCiscoAVPair(value)
		if err != nil {
			diagnostics = append(diagnostics, err.Error())
			continue
		}
		pairs = append(pairs, pair)
	}
	return pairs, diagnostics
}

func BuildCiscoAVPairsForIntent(intent CiscoAVPairIntent) ([]string, error) {
	values := make([]string, 0, 16)
	seen := map[string]struct{}{}
	appendValue := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if _, exists := seen[value]; exists {
			return nil
		}
		if _, err := ParseCiscoAVPair(value); err != nil {
			return err
		}
		seen[value] = struct{}{}
		values = append(values, value)
		return nil
	}
	for _, value := range renderCiscoAVPairACLRules(intent.ACLRules) {
		if err := appendValue(value); err != nil {
			return nil, err
		}
	}
	if intent.SecurityGroupTag > 0 {
		if intent.SecurityGroupTag > 65535 {
			return nil, fmt.Errorf("Cisco TrustSec SGT must be between 1 and 65535")
		}
		if err := appendValue("cts:security-group-tag=" + strconv.Itoa(intent.SecurityGroupTag)); err != nil {
			return nil, err
		}
	}
	if intent.SecurityGroupName != "" {
		if err := appendValue("cts:security-group-name=" + sanitizeCiscoAVPairValue(intent.SecurityGroupName)); err != nil {
			return nil, err
		}
	}
	if intent.VPNGroupPolicy != "" {
		if err := appendValue("vpn:group-policy=" + sanitizeCiscoAVPairValue(intent.VPNGroupPolicy)); err != nil {
			return nil, err
		}
	}
	if intent.VPNTunnelGroup != "" {
		if err := appendValue("vpn:tunnel-group=" + sanitizeCiscoAVPairValue(intent.VPNTunnelGroup)); err != nil {
			return nil, err
		}
	}
	if intent.VPNSplitTunnelList != "" {
		if err := appendValue("vpn:split-tunnel-list=" + sanitizeCiscoAVPairValue(intent.VPNSplitTunnelList)); err != nil {
			return nil, err
		}
	}
	if intent.VoiceTrafficClass != "" {
		if err := appendValue("device-traffic-class=" + sanitizeCiscoAVPairValue(intent.VoiceTrafficClass)); err != nil {
			return nil, err
		}
	}
	if intent.ShellPrivilegeLevel > 0 {
		if intent.ShellPrivilegeLevel > 15 {
			return nil, fmt.Errorf("Cisco shell privilege level must be between 1 and 15")
		}
		if err := appendValue("shell:priv-lvl=" + strconv.Itoa(intent.ShellPrivilegeLevel)); err != nil {
			return nil, err
		}
	}
	if len(intent.ShellRoles) > 0 {
		if err := appendValue("shell:roles=" + sanitizeCiscoAVPairValue(strings.Join(intent.ShellRoles, ","))); err != nil {
			return nil, err
		}
	}
	if intent.PostureStatus != "" {
		if err := appendValue("posture:status=" + sanitizeCiscoAVPairValue(intent.PostureStatus)); err != nil {
			return nil, err
		}
	}
	if intent.AuditSessionID != "" {
		if err := appendValue("audit-session-id=" + sanitizeCiscoAVPairValue(intent.AuditSessionID)); err != nil {
			return nil, err
		}
	}
	for _, route := range intent.IPv4Routes {
		if err := appendValue("ip:route=" + sanitizeCiscoAVPairValue(route)); err != nil {
			return nil, err
		}
	}
	for _, route := range intent.IPv6Routes {
		if err := appendValue("ipv6:route=" + sanitizeCiscoAVPairValue(route)); err != nil {
			return nil, err
		}
	}
	if intent.VRF != "" {
		if err := appendValue("ip:vrf-id=" + sanitizeCiscoAVPairValue(intent.VRF)); err != nil {
			return nil, err
		}
	}
	if intent.IPv4Pool != "" {
		if err := appendValue("ip:addr-pool=" + sanitizeCiscoAVPairValue(intent.IPv4Pool)); err != nil {
			return nil, err
		}
	}
	if intent.IPv6Pool != "" {
		if err := appendValue("ipv6:addr-pool=" + sanitizeCiscoAVPairValue(intent.IPv6Pool)); err != nil {
			return nil, err
		}
	}
	if intent.DelegatedIPv6Prefix != "" {
		if err := appendValue("ipv6:delegated-prefix=" + sanitizeCiscoAVPairValue(intent.DelegatedIPv6Prefix)); err != nil {
			return nil, err
		}
	}
	if intent.TranslationPolicy != "" {
		if err := appendValue("translation-policy=" + sanitizeCiscoAVPairValue(intent.TranslationPolicy)); err != nil {
			return nil, err
		}
	}
	if intent.TranslationPublicIP != "" {
		if err := appendValue("translation-public-ipv4=" + sanitizeCiscoAVPairValue(intent.TranslationPublicIP)); err != nil {
			return nil, err
		}
	}
	if intent.TranslationPortBlock != "" {
		if err := appendValue("translation-port-block=" + sanitizeCiscoAVPairValue(intent.TranslationPortBlock)); err != nil {
			return nil, err
		}
	}
	if intent.ChargingProfile != "" {
		if err := appendValue("subscriber:charging-profile=" + sanitizeCiscoAVPairValue(intent.ChargingProfile)); err != nil {
			return nil, err
		}
	}
	for _, custom := range intent.Custom {
		if err := appendValue(custom); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func applyCiscoAVPairString(result *BrokerAuthResult, raw string) {
	appendUniqueVendorAVPair(result, raw)
	pair, err := ParseCiscoAVPair(raw)
	if err != nil {
		return
	}
	ApplyCiscoAVPairToBrokerResult(result, pair)
}

func ApplyCiscoAVPairToBrokerResult(result *BrokerAuthResult, pair CiscoAVPair) {
	if result == nil {
		return
	}
	switch pair.Kind {
	case CiscoAVPairKindDynamicACL:
		if pair.Direction == "out" {
			setStringIfEmpty(&result.VendorOutboundACL, pair.Value)
		} else {
			setStringIfEmpty(&result.VendorInboundACL, pair.Value)
		}
	case CiscoAVPairKindRoute:
		if pair.Namespace == "ipv6" {
			result.VendorFramedIPv6Routes = appendUniqueVendorString(result.VendorFramedIPv6Routes, pair.Value, 32)
		} else {
			result.VendorFramedRoutes = appendUniqueVendorString(result.VendorFramedRoutes, pair.Value, 32)
		}
	case CiscoAVPairKindVRF:
		setStringIfEmpty(&result.VendorVRF, pair.Value)
	case CiscoAVPairKindAddressPool:
		applyCiscoAddressPool(result, pair)
	case CiscoAVPairKindTrustSecSGT:
		setStringIfEmpty(&result.VendorPolicyTag, "sgt:"+pair.Value)
	case CiscoAVPairKindVPN:
		setStringIfEmpty(&result.VendorPolicyTag, "vpn:"+pair.Value)
	case CiscoAVPairKindVoice:
		setStringIfEmpty(&result.VendorDeviceGroup, "voice")
		setStringIfEmpty(&result.VendorPolicyTag, "voice:"+pair.Value)
	case CiscoAVPairKindCommandAuth:
		if pair.Namespace == "shell" && pair.Name == "roles" {
			setStringIfEmpty(&result.VendorRole, pair.Value)
		} else {
			setStringIfEmpty(&result.VendorPolicyTag, "shell:"+pair.Name+"="+pair.Value)
		}
	case CiscoAVPairKindPosture:
		setStringIfEmpty(&result.VendorDevicePosture, pair.Value)
	case CiscoAVPairKindTranslation:
		applyCiscoTranslation(result, pair)
	case CiscoAVPairKindCharging:
		setStringIfEmpty(&result.VendorPolicyTag, "charging:"+pair.Value)
	case CiscoAVPairKindSubscriberSvc:
		setStringIfEmpty(&result.VendorSessionAction, pair.Value)
	}
}

func classifyCiscoAVPair(pair CiscoAVPair) (CiscoAVPairKind, string, string) {
	name := pair.Name
	namespace := pair.Namespace
	switch {
	case namespace == "ip" && (name == "inacl" || name == "outacl"):
		direction := "in"
		if name == "outacl" {
			direction = "out"
		}
		return CiscoAVPairKindDynamicACL, productconfigs.VendorSemanticDynamicACL, direction
	case name == "route":
		return CiscoAVPairKindRoute, productconfigs.VendorSemanticRoute, ""
	case strings.Contains(name, "vrf"):
		return CiscoAVPairKindVRF, productconfigs.VendorSemanticVRF, ""
	case strings.Contains(name, "pool") || strings.Contains(name, "prefix") || strings.Contains(name, "framed-ip"):
		return CiscoAVPairKindAddressPool, productconfigs.VendorSemanticAddressPool, ""
	case namespace == "cts" || name == "sgt" || strings.Contains(name, "security-group"):
		return CiscoAVPairKindTrustSecSGT, productconfigs.VendorSemanticPolicyTag, ""
	case namespace == "vpn" || namespace == "webvpn" || namespace == "ipsec" || strings.Contains(name, "vpn") || strings.Contains(name, "tunnel-group"):
		return CiscoAVPairKindVPN, productconfigs.VendorSemanticPolicyTag, ""
	case namespace == "voice" || name == "device-traffic-class" || strings.Contains(name, "voice"):
		return CiscoAVPairKindVoice, productconfigs.VendorSemanticDeviceGroup, ""
	case namespace == "shell" || strings.HasPrefix(name, "cmd") || name == "priv-lvl":
		return CiscoAVPairKindCommandAuth, productconfigs.VendorSemanticRole, ""
	case namespace == "posture" || strings.Contains(name, "posture") || name == "audit-session-id":
		return CiscoAVPairKindPosture, productconfigs.VendorSemanticDevicePosture, ""
	case strings.Contains(name, "translation") || strings.Contains(name, "nat64"):
		return CiscoAVPairKindTranslation, productconfigs.VendorSemanticTranslationPolicy, ""
	case strings.Contains(name, "charging") || strings.Contains(name, "credit") || strings.Contains(name, "prepaid"):
		return CiscoAVPairKindCharging, productconfigs.VendorSemanticAccountingCounters, ""
	case namespace == "subscriber" || strings.Contains(name, "subscriber") || strings.Contains(name, "service"):
		return CiscoAVPairKindSubscriberSvc, productconfigs.VendorSemanticSessionAction, ""
	default:
		return CiscoAVPairKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func applyCiscoAddressPool(result *BrokerAuthResult, pair CiscoAVPair) {
	switch {
	case strings.Contains(pair.Name, "delegated"):
		setStringIfEmpty(&result.VendorDelegatedIPv6Prefix, pair.Value)
	case pair.Namespace == "ipv6" || strings.Contains(pair.Name, "ipv6"):
		setStringIfEmpty(&result.VendorIPv6Pool, pair.Value)
	default:
		setStringIfEmpty(&result.VendorIPv4Pool, pair.Value)
	}
}

func applyCiscoTranslation(result *BrokerAuthResult, pair CiscoAVPair) {
	switch {
	case strings.Contains(pair.Name, "public-ipv4"):
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, pair.Value)
	case strings.Contains(pair.Name, "port-block"):
		parts := strings.SplitN(pair.Value, "-", 2)
		if len(parts) == 2 {
			if start, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && start > 0 {
				result.VendorTranslationPortBlockStart = start
				result.HasVendorTranslationPortBlockStart = true
			}
			if end, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && end > 0 {
				result.VendorTranslationPortBlockEnd = end
				result.HasVendorTranslationPortBlockEnd = true
			}
		}
	case strings.Contains(pair.Name, "nat64"):
		setStringIfEmpty(&result.VendorTranslationNAT64Prefix, pair.Value)
	default:
		setStringIfEmpty(&result.VendorTranslationPolicy, pair.Value)
	}
}

func sanitizeCiscoAVPairValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > CiscoAVPairMaxValueLength {
		value = value[:CiscoAVPairMaxValueLength]
	}
	return value
}

func validCiscoAVPairToken(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func containsControlRune(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
