package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const ArubaFamilyMaxValueLength = 240

type ArubaFamilyAttributeKind string

const (
	ArubaFamilyKindUnknown        ArubaFamilyAttributeKind = "unknown"
	ArubaFamilyKindRole           ArubaFamilyAttributeKind = "role_policy"
	ArubaFamilyKindVLAN           ArubaFamilyAttributeKind = "vlan_policy"
	ArubaFamilyKindACL            ArubaFamilyAttributeKind = "acl_policy"
	ArubaFamilyKindPortal         ArubaFamilyAttributeKind = "guest_portal"
	ArubaFamilyKindDevice         ArubaFamilyAttributeKind = "device_context"
	ArubaFamilyKindPosture        ArubaFamilyAttributeKind = "posture"
	ArubaFamilyKindTenant         ArubaFamilyAttributeKind = "tenant"
	ArubaFamilyKindAirGroup       ArubaFamilyAttributeKind = "airgroup_policy"
	ArubaFamilyKindKeyLifecycle   ArubaFamilyAttributeKind = "key_lifecycle"
	ArubaFamilyKindUBT            ArubaFamilyAttributeKind = "user_based_tunneling"
	ArubaFamilyKindQoS            ArubaFamilyAttributeKind = "qos_policy"
	ArubaFamilyKindCommandAuth    ArubaFamilyAttributeKind = "command_authorization"
	ArubaFamilyKindCoA            ArubaFamilyAttributeKind = "dynamic_authorization"
	ArubaFamilyKindQuarantine     ArubaFamilyAttributeKind = "quarantine"
	ArubaFamilyKindServiceProfile ArubaFamilyAttributeKind = "service_profile"
)

type ArubaFamilyAttribute struct {
	Raw       string                   `json:"raw"`
	Vendor    string                   `json:"vendor"`
	Attribute string                   `json:"attribute"`
	Name      string                   `json:"name,omitempty"`
	Operator  string                   `json:"operator,omitempty"`
	Value     string                   `json:"value"`
	Kind      ArubaFamilyAttributeKind `json:"kind"`
	Semantic  string                   `json:"semantic"`
	Redacted  bool                     `json:"redacted"`
}

func NormalizeArubaFamilyAttribute(vendor, attribute, raw string) (ArubaFamilyAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return ArubaFamilyAttribute{}, fmt.Errorf("Aruba-family attribute name is required")
	}
	if value == "" {
		return ArubaFamilyAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > ArubaFamilyMaxValueLength {
		return ArubaFamilyAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, ArubaFamilyMaxValueLength)
	}
	if containsControlRune(value) {
		return ArubaFamilyAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isArubaFamilySecretRuntimeAttribute(attribute) {
		kind, semantic := classifyArubaFamilyRuntime(attribute, "")
		return ArubaFamilyAttribute{
			Raw:       attribute + "=<redacted>",
			Vendor:    vendor,
			Attribute: attribute,
			Value:     "<redacted>",
			Kind:      kind,
			Semantic:  semantic,
			Redacted:  true,
		}, nil
	}
	if isArubaFamilyAVPairAttribute(attribute) {
		return parseArubaFamilyAVPair(vendor, attribute, value)
	}
	kind, semantic := classifyArubaFamilyRuntime(attribute, "")
	return ArubaFamilyAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
	}, nil
}

func parseArubaFamilyAVPair(vendor, attribute, raw string) (ArubaFamilyAttribute, error) {
	name, op, value := splitArubaFamilyToken(raw)
	if name == "" || value == "" {
		return ArubaFamilyAttribute{}, fmt.Errorf("%s must use name=value or name:value form", attribute)
	}
	if !validArubaFamilyToken(name) {
		return ArubaFamilyAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	kind, semantic := classifyArubaFamilyRuntime(attribute, name)
	return ArubaFamilyAttribute{
		Raw:       raw,
		Vendor:    vendor,
		Attribute: attribute,
		Name:      name,
		Operator:  op,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
	}, nil
}

func splitArubaFamilyToken(raw string) (string, string, string) {
	for _, op := range []string{"=", ":"} {
		if idx := strings.Index(raw, op); idx > 0 {
			name := strings.TrimSpace(raw[:idx])
			value := strings.TrimSpace(raw[idx+len(op):])
			return name, op, value
		}
	}
	return "", "", ""
}

func BuildArubaFamilyPolicyTokens(values []string) ([]string, []string) {
	out := make([]string, 0, len(values))
	errors := []string{}
	for _, value := range values {
		token, err := NormalizeArubaFamilyAttribute("aruba-family", "Aruba-AVPair", value)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if token.Redacted {
			out = append(out, token.Raw)
			continue
		}
		out = append(out, token.Name+token.Operator+token.Value)
	}
	return out, errors
}

func appendArubaFamilyReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if attrs == nil {
		return
	}
	switch packKey {
	case productconfigs.VendorPackAruba:
		appendItem("Aruba-CPPM-Role", firstReplyValue(attrs.ArubaCPPMRole, attrs.Role), true)
		appendItem("Aruba-Admin-Role", attrs.ArubaAdminRole, true)
		appendItem("Aruba-Named-User-Vlan", attrs.ArubaNamedUserVLAN, true)
		appendItem("Aruba-AP-Group", firstReplyValue(attrs.ArubaAPGroup, attrs.DeviceGroup), true)
		appendItem("Aruba-User-Group", firstReplyValue(attrs.ArubaUserGroup, attrs.DeviceGroup), true)
		appendItem("Aruba-Device-Type", attrs.ArubaDeviceType, true)
		appendItem("Aruba-Mdps-Device-Name", attrs.ArubaMDPSDeviceName, true)
		appendItem("Aruba-Mdps-Device-Profile", attrs.ArubaMDPSDeviceProfile, true)
		appendItem("Aruba-AirGroup-User-Name", attrs.ArubaAirGroupUserName, true)
		appendItem("Aruba-AirGroup-Shared-User", attrs.ArubaAirGroupSharedUser, true)
		appendItem("Aruba-AirGroup-Shared-Role", attrs.ArubaAirGroupSharedRole, true)
		appendItem("Aruba-AirGroup-Shared-Group", attrs.ArubaAirGroupSharedGroup, true)
		appendItem("Aruba-MPSK-Key-Name", attrs.ArubaMPSKKeyName, true)
		appendIntegerStringItem(attrs.ArubaDPPServiceType, appendItem, "Aruba-DPP-Service-Type")
		appendItem("Aruba-UBT-Gateway-Role", attrs.ArubaUBTGatewayRole, true)
		appendItem("Aruba-Gateway-Zone", attrs.ArubaGatewayZone, true)
		appendIntegerStringItem(attrs.ArubaQoSTrustMode, appendItem, "Aruba-QoS-Trust-Mode")
		appendIntegerStringItem(attrs.ArubaPoEPriority, appendItem, "Aruba-PoE-Priority")
		appendIntegerStringItem(attrs.ArubaDeviceTrafficClass, appendItem, "Aruba-Device-Traffic-Class")
		appendURLItem(attrs, appendItem, "Aruba-Captive-Portal-URL", attrs.PortalProfile)
		for _, value := range renderNASFilterRules(attrs.ACLRules) {
			appendItem("Aruba-NAS-Filter-Rule", value, true)
		}
		appendArubaFamilyAVPairs(attrs.ArubaAVPairs, appendItem, "Aruba-AVPair")
	case productconfigs.VendorPackHP:
		appendIntegerStringItem(attrs.HPPrivilegeLevel, appendItem, "HP-Privilege-Level")
		appendItem("HP-CPPM-Secondary-Role", attrs.HPCPPMSecondaryRole, true)
		appendItem("HP-Cos", attrs.HPCos, true)
		appendItem("HP-Bonjour-Inbound-Profile", attrs.HPBonjourInboundProfile, true)
		appendItem("HP-Bonjour-Outbound-Profile", attrs.HPBonjourOutboundProfile, true)
		appendItem("HP-URI-String", attrs.HPURIString, true)
		appendItem("HP-URI-Access", attrs.HPURIAccess, true)
		appendItem("HP-Command-String", attrs.HPCommandString, true)
		appendIntegerStringItem(attrs.HPNasRulesIPv6, appendItem, "HP-Nas-Rules-IPv6")
		appendItem("HP-Egress-VLAN-Name", attrs.HPEgressVLANName, true)
	case productconfigs.VendorPackAerohive:
		appendItem("Extreme-User-Language", attrs.AerohiveUserLanguage, true)
		appendIntegerStringItem(attrs.AerohiveIDMMessage, appendItem, "Extreme-IDM-Message")
		appendIntegerStringItem(attrs.AerohiveClientMonitorProblem, appendItem, "Extreme-Client-Monitor-Problem")
		appendIntegerStringItem(attrs.AerohiveAuthSource, appendItem, "Extreme-Auth-Source")
		appendArubaFamilyAVPairs(attrs.AerohiveAVPairs, appendItem, "Extreme-AVPair")
	case productconfigs.VendorPackColubris:
		appendArubaFamilyAVPairs(attrs.ColubrisAVPairs, appendItem, "AVPair")
	}
}

func appendArubaFamilyAVPairs(values []string, appendItem func(string, string, bool), attribute string) {
	for _, value := range values {
		token, err := NormalizeArubaFamilyAttribute("aruba-family", attribute, value)
		if err != nil {
			continue
		}
		if token.Redacted {
			appendItem(attribute, token.Raw, true)
			continue
		}
		if token.Name != "" {
			appendItem(attribute, token.Name+token.Operator+token.Value, true)
			continue
		}
		appendItem(attribute, token.Value, true)
	}
}

func appendIntegerStringItem(value int, appendItem func(string, string, bool), attribute string) {
	if value > 0 {
		appendItem(attribute, strconv.Itoa(value), false)
	}
}

func applyArubaFamilyAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeArubaFamilyAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyArubaFamilyAttributeToBrokerResult(result, token)
	return true
}

func ApplyArubaFamilyAttributeToBrokerResult(result *BrokerAuthResult, token ArubaFamilyAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case ArubaFamilyKindRole:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case ArubaFamilyKindVLAN:
		if vlan, err := strconv.Atoi(token.Value); err == nil && vlan >= 1 && vlan <= 4094 {
			if !result.HasVendorVLAN {
				result.VendorVLAN = vlan
				result.HasVendorVLAN = true
			}
			return
		}
		setStringIfEmpty(&result.VendorVLANPool, token.Value)
	case ArubaFamilyKindACL:
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case ArubaFamilyKindPortal:
		setStringIfEmpty(&result.VendorPortalProfile, token.Value)
	case ArubaFamilyKindDevice:
		if strings.Contains(strings.ToLower(token.Attribute), "group") || strings.Contains(strings.ToLower(token.Name), "group") {
			setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case ArubaFamilyKindPosture:
		setStringIfEmpty(&result.VendorDevicePosture, token.Value)
	case ArubaFamilyKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case ArubaFamilyKindAirGroup, ArubaFamilyKindKeyLifecycle, ArubaFamilyKindServiceProfile:
		if token.Redacted {
			appendUniqueVendorAVPair(result, token.Raw)
			return
		}
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
	case ArubaFamilyKindUBT:
		setStringIfEmpty(&result.VendorVRF, token.Value)
	case ArubaFamilyKindQoS:
		setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
	case ArubaFamilyKindCommandAuth:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case ArubaFamilyKindCoA:
		setStringIfEmpty(&result.VendorSessionAction, arubaFamilyActionValue(token.Value))
	case ArubaFamilyKindQuarantine:
		if enabled, ok := arubaFamilyBool(token.Value); ok && !result.HasVendorQuarantine {
			result.VendorQuarantine = enabled
			result.HasVendorQuarantine = true
		}
	default:
		appendUniqueVendorAVPair(result, token.Raw)
	}
}

func classifyArubaFamilyRuntime(attribute, tokenName string) (ArubaFamilyAttributeKind, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnyArubaRuntimeToken(name, "gateway-zone", "location-id"):
		return ArubaFamilyKindTenant, productconfigs.VendorSemanticTenant
	case containsAnyArubaRuntimeToken(name, "user-role", "cppm-role", "admin-role", "privilege-level", "profile-attribute", "secondary-role"):
		return ArubaFamilyKindRole, productconfigs.VendorSemanticRole
	case containsAnyArubaRuntimeToken(name, "vlan", "ubt", "gateway-zone", "gateway-role"):
		return ArubaFamilyKindVLAN, productconfigs.VendorSemanticVLAN
	case containsAnyArubaRuntimeToken(name, "filter", "acl", "rule", "ip-filter"):
		return ArubaFamilyKindACL, productconfigs.VendorSemanticACL
	case containsAnyArubaRuntimeToken(name, "portal", "redirect"):
		return ArubaFamilyKindPortal, productconfigs.VendorSemanticPortalProfile
	case containsAnyArubaRuntimeToken(name, "device-type", "client-monitor", "problem"):
		return ArubaFamilyKindPosture, productconfigs.VendorSemanticDevicePosture
	case containsAnyArubaRuntimeToken(name, "mdps", "device", "ap-", "essid", "location", "port-identifier", "mac-address", "vc-groups"):
		return ArubaFamilyKindDevice, productconfigs.VendorSemanticAccountingIdentity
	case containsAnyArubaRuntimeToken(name, "airgroup", "bonjour"):
		return ArubaFamilyKindAirGroup, productconfigs.VendorSemanticPolicyTag
	case containsAnyArubaRuntimeToken(name, "mpsk", "dpp", "ppsk", "pmk", "credential", "auth-source"):
		return ArubaFamilyKindKeyLifecycle, productconfigs.VendorSemanticCertificateOnboarding
	case containsAnyArubaRuntimeToken(name, "qos", "poe", "traffic-class", "cos", "bandwidth"):
		return ArubaFamilyKindQoS, productconfigs.VendorSemanticBandwidthProfile
	case containsAnyArubaRuntimeToken(name, "command", "admin-path", "management", "uri"):
		return ArubaFamilyKindCommandAuth, productconfigs.VendorSemanticRole
	case containsAnyArubaRuntimeToken(name, "bounce", "reauth", "disconnect", "auth-surv"):
		return ArubaFamilyKindCoA, productconfigs.VendorSemanticCoAReauth
	case containsAnyArubaRuntimeToken(name, "intercept", "quarantine"):
		return ArubaFamilyKindQuarantine, productconfigs.VendorSemanticQuarantine
	default:
		return ArubaFamilyKindUnknown, productconfigs.VendorSemanticPolicyTag
	}
}

func isArubaFamilyAVPairAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "aruba-avpair", "extreme-avpair", "avpair":
		return true
	default:
		return false
	}
}

func isArubaFamilySecretRuntimeAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "aruba-mpsk-passphrase", "aruba-dpp-passphrase", "aruba-as-credential-hash", "aruba-dpp-bootstrapping-key-sha256",
		"aruba-dpp-bootstrapping-net-access-key-sha256", "aruba-dpp-bootstrapping-key-b64", "extreme-ppsk-request", "extreme-ppsk-pmk":
		return true
	default:
		return false
	}
}

func arubaFamilyBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "enabled", "enable", "intercept":
		return true, true
	case "0", "false", "no", "disabled", "disable", "none":
		return false, true
	default:
		return false, false
	}
}

func arubaFamilyActionValue(value string) string {
	if enabled, ok := arubaFamilyBool(value); ok {
		if enabled {
			return "reauth"
		}
		return "none"
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func validArubaFamilyToken(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func containsAnyArubaRuntimeToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
