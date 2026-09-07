package radius

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const SwitchingVendorMaxValueLength = 240

type SwitchingVendorAttributeKind string

const (
	SwitchingVendorKindUnknown      SwitchingVendorAttributeKind = "unknown"
	SwitchingVendorKindRole         SwitchingVendorAttributeKind = "role_policy"
	SwitchingVendorKindCommandAuth  SwitchingVendorAttributeKind = "command_authorization"
	SwitchingVendorKindVLAN         SwitchingVendorAttributeKind = "vlan_policy"
	SwitchingVendorKindACL          SwitchingVendorAttributeKind = "acl_policy"
	SwitchingVendorKindPortal       SwitchingVendorAttributeKind = "guest_portal"
	SwitchingVendorKindQoS          SwitchingVendorAttributeKind = "qos_policy"
	SwitchingVendorKindSession      SwitchingVendorAttributeKind = "session_action"
	SwitchingVendorKindDevice       SwitchingVendorAttributeKind = "device_context"
	SwitchingVendorKindPosture      SwitchingVendorAttributeKind = "posture"
	SwitchingVendorKindTenant       SwitchingVendorAttributeKind = "tenant"
	SwitchingVendorKindVRF          SwitchingVendorAttributeKind = "vrf"
	SwitchingVendorKindIPv4Address  SwitchingVendorAttributeKind = "ipv4_address"
	SwitchingVendorKindAccounting   SwitchingVendorAttributeKind = "accounting_context"
	SwitchingVendorKindAdminContact SwitchingVendorAttributeKind = "admin_contact"
)

type SwitchingVendorAttribute struct {
	Raw       string                       `json:"raw"`
	Vendor    string                       `json:"vendor"`
	Attribute string                       `json:"attribute"`
	Namespace string                       `json:"namespace,omitempty"`
	Name      string                       `json:"name,omitempty"`
	Operator  string                       `json:"operator,omitempty"`
	Value     string                       `json:"value"`
	Kind      SwitchingVendorAttributeKind `json:"kind"`
	Semantic  string                       `json:"semantic"`
	Direction string                       `json:"direction,omitempty"`
}

func NormalizeSwitchingVendorAttribute(vendor, attribute, raw string) (SwitchingVendorAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return SwitchingVendorAttribute{}, fmt.Errorf("switching vendor attribute name is required")
	}
	if value == "" {
		return SwitchingVendorAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > SwitchingVendorMaxValueLength {
		return SwitchingVendorAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, SwitchingVendorMaxValueLength)
	}
	if containsControlRune(value) {
		return SwitchingVendorAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isSwitchingVendorAVPairAttribute(attribute) {
		return parseSwitchingVendorAVPair(vendor, attribute, value)
	}
	kind, semantic, direction := classifySwitchingVendorRuntime(attribute, "")
	return SwitchingVendorAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func parseSwitchingVendorAVPair(vendor, attribute, raw string) (SwitchingVendorAttribute, error) {
	name, namespace, op, value := splitRuckusICXToken(raw)
	if name == "" || value == "" {
		return SwitchingVendorAttribute{}, fmt.Errorf("%s must use name=value or name:value form", attribute)
	}
	if !validCiscoAVPairToken(namespace) || !validCiscoAVPairToken(name) {
		return SwitchingVendorAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	tokenKey := name
	if namespace != "" {
		tokenKey = namespace + ":" + name
	}
	kind, semantic, direction := classifySwitchingVendorRuntime(attribute, tokenKey)
	return SwitchingVendorAttribute{
		Raw:       raw,
		Vendor:    vendor,
		Attribute: attribute,
		Namespace: namespace,
		Name:      name,
		Operator:  op,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func applySwitchingVendorAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeSwitchingVendorAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplySwitchingVendorAttributeToBrokerResult(result, token)
	return true
}

func ApplySwitchingVendorAttributeToBrokerResult(result *BrokerAuthResult, token SwitchingVendorAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case SwitchingVendorKindRole:
		setStringIfEmpty(&result.VendorRole, switchingVendorRoleValue(token))
	case SwitchingVendorKindCommandAuth:
		setStringIfEmpty(&result.VendorPolicyTag, "command:"+token.Value)
	case SwitchingVendorKindVLAN:
		if vlan, err := strconv.Atoi(strings.TrimSpace(token.Value)); err == nil && vlan >= 1 && vlan <= 4094 {
			if !result.HasVendorVLAN {
				result.VendorVLAN = vlan
				result.HasVendorVLAN = true
			}
			return
		}
		setStringIfEmpty(&result.VendorVLANPool, token.Value)
	case SwitchingVendorKindACL:
		if token.Direction == "out" || containsAnySwitchingVendorToken(token.Attribute, "out", "egress") || containsAnySwitchingVendorToken(token.Name, "outacl", "egress") {
			setStringIfEmpty(&result.VendorOutboundACL, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case SwitchingVendorKindPortal:
		setStringIfEmpty(&result.VendorPortalProfile, switchingVendorPortalValue(token))
	case SwitchingVendorKindQoS:
		setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
	case SwitchingVendorKindSession:
		setStringIfEmpty(&result.VendorSessionAction, switchingVendorSessionAction(token))
	case SwitchingVendorKindDevice:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case SwitchingVendorKindPosture:
		posture := switchingVendorEvidenceValue(token)
		setStringIfEmpty(&result.VendorDevicePosture, posture)
		appendUniqueVendorAVPair(result, posture)
	case SwitchingVendorKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case SwitchingVendorKindVRF:
		setStringIfEmpty(&result.VendorVRF, token.Value)
	case SwitchingVendorKindIPv4Address:
		ip := net.ParseIP(strings.TrimSpace(token.Value))
		if ip == nil || ip.To4() == nil {
			appendUniqueVendorAVPair(result, token.Raw)
			return
		}
		setStringIfEmpty(&result.VendorFramedIPAddress, ip.To4().String())
	case SwitchingVendorKindAccounting:
		setStringIfEmpty(&result.VendorAccountingIdentity, switchingVendorEvidenceValue(token))
	case SwitchingVendorKindAdminContact:
		setStringIfEmpty(&result.VendorAccountingIdentity, switchingVendorEvidenceValue(token))
	default:
		appendUniqueVendorAVPair(result, token.Raw)
	}
}

func classifySwitchingVendorRuntime(attribute, tokenName string) (SwitchingVendorAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnySwitchingVendorToken(name, "access-list", "acl", "filter", "pool-access", "aor-list"):
		direction := "in"
		if containsAnySwitchingVendorToken(name, "outacl", "egress", "output") {
			direction = "out"
		}
		semantic := productconfigs.VendorSemanticACL
		if isSwitchingVendorAVPairAttribute(attribute) {
			semantic = productconfigs.VendorSemanticDynamicACL
		}
		return SwitchingVendorKindACL, semantic, direction
	case containsAnySwitchingVendorToken(name, "vm-vr", "vr-name", "vrf", "virtual-router"):
		return SwitchingVendorKindVRF, productconfigs.VendorSemanticVRF, ""
	case containsAnySwitchingVendorToken(name, "vlan", "segment"):
		return SwitchingVendorKindVLAN, productconfigs.VendorSemanticVLAN, ""
	case containsAnySwitchingVendorToken(name, "url", "portal", "webauth"):
		return SwitchingVendorKindPortal, productconfigs.VendorSemanticPortalProfile, ""
	case containsAnySwitchingVendorToken(name, "blockmac", "block-mac", "unblockmac", "unblock-mac", "portflap", "port-flap", "coa", "reauth", "disconnect"):
		return SwitchingVendorKindSession, productconfigs.VendorSemanticCoAReauth, ""
	case containsAnySwitchingVendorToken(name, "qos", "priority", "bandwidth", "traffic-class"):
		return SwitchingVendorKindQoS, productconfigs.VendorSemanticBandwidthProfile, ""
	case containsAnySwitchingVendorToken(name, "command", "cli", "shell"):
		return SwitchingVendorKindCommandAuth, productconfigs.VendorSemanticRole, ""
	case containsAnySwitchingVendorToken(name, "priv", "role", "group", "access-level", "account-type", "cvp-role", "auth-role"):
		return SwitchingVendorKindRole, productconfigs.VendorSemanticRole, ""
	case containsAnySwitchingVendorToken(name, "ip-host", "ip-addr", "ipv4"):
		return SwitchingVendorKindIPv4Address, productconfigs.VendorSemanticIPv4Address, ""
	case containsAnySwitchingVendorToken(name, "tenant", "location", "site", "domain", "repl-site"):
		return SwitchingVendorKindTenant, productconfigs.VendorSemanticTenant, ""
	case containsAnySwitchingVendorToken(name, "encryption", "802.1x", "mac-authent", "valid-lookup", "profiling"):
		return SwitchingVendorKindPosture, productconfigs.VendorSemanticDevicePosture, ""
	case containsAnySwitchingVendorToken(name, "ssid", "mobility", "product", "interface", "vm-name", "vpp"):
		return SwitchingVendorKindDevice, productconfigs.VendorSemanticDeviceGroup, ""
	case containsAnySwitchingVendorToken(name, "full-name", "email", "phone", "mobile"):
		return SwitchingVendorKindAdminContact, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnySwitchingVendorToken(name, "connect", "startup", "poll", "expiry", "warn", "timestamp"):
		return SwitchingVendorKindAccounting, productconfigs.VendorSemanticAccountingIdentity, ""
	default:
		return SwitchingVendorKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func appendSwitchingVendorReplyAttributes(attrs *ReplyAttributes, packKey string, vendor config.RadiusVendorConfig, appendItem func(string, string, bool)) {
	if attrs == nil {
		return
	}
	switch productconfigs.NormalizeVendorCompatibilityPackKey(packKey) {
	case productconfigs.VendorPack3Com:
		appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "3Com-User-Access-Level")
		if vlan := replyVLAN(attrs); vlan > 0 {
			appendItem("3Com-VLAN-Name", strconv.Itoa(vlan), true)
		} else {
			appendItem("3Com-VLAN-Name", attrs.VLANPool, true)
		}
		appendItem("3Com-Mobility-Profile", attrs.DeviceGroup, true)
		appendItem("3Com-SSID", attrs.DeviceGroup, true)
		appendItem("3Com-Encryption-Type", firstReplyValue(attrs.PolicyTag, attrs.FilterID), true)
		appendURLItem(attrs, appendItem, "3Com-URL", attrs.PortalProfile)
		appendItem("3Com-Ip-Host-Addr", attrs.FramedIPAddress, true)
	case productconfigs.VendorPackArista:
		appendItem("Arista-User-Role", replyRole(attrs), true)
		appendItem("Arista-CVP-Role", replyRole(attrs), true)
		appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "Arista-User-Priv-Level")
		appendItem("Arista-Command", attrs.PolicyTag, true)
		if strings.TrimSpace(attrs.PortalProfile) != "" {
			appendItem("Arista-Captive-Portal", attrs.PortalProfile, true)
			appendItem("Arista-WebAuth", "1", false)
		}
		if vlan := replyVLAN(attrs); vlan > 0 {
			appendItem("Arista-Segment-Id", strconv.Itoa(vlan), true)
		}
		appendItem("Arista-Interface-Profile", attrs.DeviceGroup, true)
		appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
	case productconfigs.VendorPackBrocade:
		appendItem("Brocade-Auth-Role", replyRole(attrs), true)
		appendBrocadeAVPairs(attrs, vendor.AVPairMappings, appendItem)
		if attrs.SessionTimeout > 0 {
			appendItem("Brocade-Passwd-ExpiryDate", strconv.Itoa(attrs.SessionTimeout), true)
		}
		if attrs.IdleTimeout > 0 {
			appendItem("Brocade-Passwd-WarnPeriod", strconv.Itoa(attrs.IdleTimeout), true)
		}
	case productconfigs.VendorPackDellEMC:
		appendItem("DellEMC-Group-Name", replyRole(attrs), true)
		appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
	case productconfigs.VendorPackEquallogic:
		appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "Equallogic-EQL-Admin-Privilege")
		appendItem("Equallogic-Admin-Account-Type", replyRole(attrs), true)
		appendItem("Equallogic-Admin-Pool-Access", firstReplyValue(attrs.ACLPolicyName, attrs.InboundACL, attrs.OutboundACL), true)
		appendItem("Equallogic-Admin-Repl-Site-Access", attrs.Tenant, true)
		if attrs.IdleTimeout > 0 {
			appendItem("Equallogic-Poll-Interval", strconv.Itoa(attrs.IdleTimeout), false)
		}
	case productconfigs.VendorPackForce10:
		if !appendVendorAVPairItemsWithResult(attrs, packKey, vendor.AVPairMappings, appendItem) {
			appendItem("Force10-AVPair", firstReplyValue(attrs.PolicyTag, attrs.ACLPolicyName, attrs.InboundACL), true)
		}
	}
}

func appendBrocadeAVPairs(attrs *ReplyAttributes, mappings []config.RadiusVendorAVPairMapping, appendItem func(string, string, bool)) {
	values := expandSwitchingVendorAVPairTemplates(attrs, productconfigs.VendorPackBrocade, mappings)
	if len(values) == 0 {
		values = append(values, firstReplyValue(attrs.PolicyTag, attrs.ACLPolicyName, attrs.InboundACL, attrs.OutboundACL))
	}
	for idx, value := range values {
		if idx >= 4 {
			return
		}
		appendItem(fmt.Sprintf("Brocade-AVPairs%d", idx+1), value, true)
	}
}

func appendVendorAVPairItemsWithResult(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorAVPairMapping, appendItem func(string, string, bool)) bool {
	values := expandSwitchingVendorAVPairTemplates(attrs, packKey, mappings)
	attribute, supported := productconfigs.VendorPackAVPairAttribute(packKey)
	if !supported {
		return false
	}
	for _, value := range values {
		appendItem(attribute, value, true)
	}
	return len(values) > 0
}

func expandSwitchingVendorAVPairTemplates(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorAVPairMapping) []string {
	if attrs == nil {
		return nil
	}
	role := replyRole(attrs)
	out := []string{}
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != productconfigs.NormalizeVendorCompatibilityPackKey(packKey) || !strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			continue
		}
		for _, value := range mapping.Values {
			expanded := expandVendorAVPairTemplate(value, attrs)
			if expanded == "" || len(expanded) > SwitchingVendorMaxValueLength || strings.ContainsAny(expanded, "\r\n\x00") {
				continue
			}
			out = append(out, expanded)
		}
		break
	}
	return out
}

func switchingVendorRoleValue(token SwitchingVendorAttribute) string {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	if value == "" {
		return ""
	}
	if _, err := strconv.Atoi(value); err == nil {
		switch {
		case containsAnySwitchingVendorToken(name, "access-level"):
			return "access-level:" + value
		case containsAnySwitchingVendorToken(name, "account-type"):
			return "account-type:" + value
		case containsAnySwitchingVendorToken(name, "priv"):
			return "privilege:" + value
		}
	}
	return value
}

func switchingVendorPortalValue(token SwitchingVendorAttribute) string {
	value := strings.TrimSpace(token.Value)
	if strings.EqualFold(strings.TrimSpace(token.Attribute), "Arista-WebAuth") {
		switch strings.ToLower(value) {
		case "1", "true", "yes", "on":
			return "webauth:enabled"
		case "0", "false", "no", "off":
			return "webauth:disabled"
		}
	}
	return value
}

func switchingVendorSessionAction(token SwitchingVendorAttribute) string {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	switch {
	case containsAnySwitchingVendorToken(name, "unblockmac", "unblock-mac"):
		return "unblock-mac:" + value
	case containsAnySwitchingVendorToken(name, "blockmac", "block-mac"):
		return "block-mac:" + value
	case containsAnySwitchingVendorToken(name, "portflap", "port-flap"):
		return "port-flap:" + value
	case containsAnySwitchingVendorToken(name, "disconnect") || strings.Contains(strings.ToLower(value), "disconnect"):
		return "disconnect:" + value
	case containsAnySwitchingVendorToken(name, "reauth") || strings.Contains(strings.ToLower(value), "reauth"):
		return "reauth:" + value
	case containsAnySwitchingVendorToken(name, "coa"):
		return "coa:" + value
	default:
		return value
	}
}

func switchingVendorEvidenceValue(token SwitchingVendorAttribute) string {
	if token.Name != "" {
		if token.Namespace != "" {
			return token.Namespace + ":" + token.Name + token.Operator + token.Value
		}
		return token.Name + token.Operator + token.Value
	}
	return strings.TrimSpace(token.Attribute) + "=" + strings.TrimSpace(token.Value)
}

func isSwitchingVendorAVPairAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return strings.Contains(name, "avpair") || strings.Contains(name, "avpairs")
}

func isSwitchingPackKey(packKey string) bool {
	switch productconfigs.NormalizeVendorCompatibilityPackKey(packKey) {
	case productconfigs.VendorPack3Com,
		productconfigs.VendorPackArista,
		productconfigs.VendorPackBrocade,
		productconfigs.VendorPackDellEMC,
		productconfigs.VendorPackEquallogic,
		productconfigs.VendorPackExtreme,
		productconfigs.VendorPackForce10,
		productconfigs.VendorPackFoundry:
		return true
	default:
		return false
	}
}

func containsAnySwitchingVendorToken(value string, tokens ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, token := range tokens {
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" && strings.Contains(value, token) {
			return true
		}
	}
	return false
}
