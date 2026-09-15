package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const FortinetPaloAltoMaxValueLength = 240

type FortinetPaloAltoAttributeKind string

const (
	FortinetPaloAltoKindUnknown     FortinetPaloAltoAttributeKind = "unknown"
	FortinetPaloAltoKindRole        FortinetPaloAltoAttributeKind = "role_policy"
	FortinetPaloAltoKindTenant      FortinetPaloAltoAttributeKind = "tenant_vrf"
	FortinetPaloAltoKindPolicy      FortinetPaloAltoAttributeKind = "security_policy"
	FortinetPaloAltoKindWebFilter   FortinetPaloAltoAttributeKind = "web_filter"
	FortinetPaloAltoKindAppControl  FortinetPaloAltoAttributeKind = "application_control"
	FortinetPaloAltoKindChallenge   FortinetPaloAltoAttributeKind = "challenge_or_token"
	FortinetPaloAltoKindVPN         FortinetPaloAltoAttributeKind = "vpn_context"
	FortinetPaloAltoKindPosture     FortinetPaloAltoAttributeKind = "posture"
	FortinetPaloAltoKindAccounting  FortinetPaloAltoAttributeKind = "accounting_identity"
	FortinetPaloAltoKindWLAN        FortinetPaloAltoAttributeKind = "wlan_context"
	FortinetPaloAltoKindInterface   FortinetPaloAltoAttributeKind = "interface_context"
	FortinetPaloAltoKindIPv4Address FortinetPaloAltoAttributeKind = "ipv4_address"
	FortinetPaloAltoKindIPv6Address FortinetPaloAltoAttributeKind = "ipv6_address"
	FortinetPaloAltoKindDynamicACL  FortinetPaloAltoAttributeKind = "dynamic_acl"
	FortinetPaloAltoKindRoute       FortinetPaloAltoAttributeKind = "route"
	FortinetPaloAltoKindSecret      FortinetPaloAltoAttributeKind = "secret_redaction"
)

type FortinetPaloAltoAttribute struct {
	Raw       string                        `json:"raw"`
	Vendor    string                        `json:"vendor"`
	Attribute string                        `json:"attribute"`
	Namespace string                        `json:"namespace,omitempty"`
	Name      string                        `json:"name,omitempty"`
	Operator  string                        `json:"operator,omitempty"`
	Value     string                        `json:"value"`
	Kind      FortinetPaloAltoAttributeKind `json:"kind"`
	Semantic  string                        `json:"semantic"`
	Direction string                        `json:"direction,omitempty"`
	Redacted  bool                          `json:"redacted"`
}

func NormalizeFortinetPaloAltoAttribute(vendor, attribute, raw string) (FortinetPaloAltoAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("Fortinet/Palo Alto attribute name is required")
	}
	if value == "" {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > FortinetPaloAltoMaxValueLength {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, FortinetPaloAltoMaxValueLength)
	}
	if isFortinetPaloAltoSecretRuntimeAttribute(attribute) {
		kind, semantic, direction := classifyFortinetPaloAltoRuntime(attribute, "")
		return FortinetPaloAltoAttribute{
			Raw:       attribute + "=<redacted>",
			Vendor:    vendor,
			Attribute: attribute,
			Value:     "<redacted>",
			Kind:      kind,
			Semantic:  semantic,
			Direction: direction,
			Redacted:  true,
		}, nil
	}
	if containsControlRune(value) {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isFortinetPaloAltoAVPairAttribute(attribute) {
		return parseFortinetPaloAltoAVPair(vendor, attribute, value)
	}
	kind, semantic, direction := classifyFortinetPaloAltoRuntime(attribute, "")
	return FortinetPaloAltoAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func parseFortinetPaloAltoAVPair(vendor, attribute, raw string) (FortinetPaloAltoAttribute, error) {
	name, namespace, op, value := splitFortinetPaloAltoToken(raw)
	if name == "" || value == "" {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("%s must use name=value or name:value form", attribute)
	}
	if !validCiscoAVPairToken(namespace) || !validCiscoAVPairToken(name) {
		return FortinetPaloAltoAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	tokenKey := name
	if namespace != "" {
		tokenKey = namespace + ":" + name
	}
	kind, semantic, direction := classifyFortinetPaloAltoRuntime(attribute, tokenKey)
	return FortinetPaloAltoAttribute{
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

func splitFortinetPaloAltoToken(raw string) (name, namespace, op, value string) {
	for _, candidate := range []string{"=", ":"} {
		if idx := strings.Index(raw, candidate); idx > 0 {
			left := strings.TrimSpace(raw[:idx])
			value = strings.TrimSpace(raw[idx+len(candidate):])
			op = candidate
			if colon := strings.Index(left, ":"); colon > 0 {
				namespace = strings.ToLower(strings.TrimSpace(left[:colon]))
				left = strings.TrimSpace(left[colon+1:])
			}
			name = strings.ToLower(left)
			return name, namespace, op, value
		}
	}
	return "", "", "", ""
}

func BuildFortinetPaloAltoPolicyTokens(values []string) ([]string, []string) {
	out := make([]string, 0, len(values))
	errors := []string{}
	for _, value := range values {
		token, err := NormalizeFortinetPaloAltoAttribute("fortinet-paloalto", "Fortinet-FortiWAN-AVPair", value)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if token.Namespace != "" {
			out = append(out, token.Namespace+":"+token.Name+token.Operator+token.Value)
			continue
		}
		out = append(out, token.Name+token.Operator+token.Value)
	}
	return out, errors
}

func appendFortinetPaloAltoReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if attrs == nil {
		return
	}
	switch packKey {
	case productconfigs.VendorPackFortinet:
		appendItem("Fortinet-Group-Name", replyRole(attrs), true)
		appendItem("Fortinet-Client-IP-Address", firstReplyValue(attrs.FortinetClientIPAddress, attrs.FramedIPAddress), false)
		appendItem("Fortinet-Vdom-Name", firstReplyValue(attrs.FortinetVDOMName, attrs.Tenant, attrs.VRF), true)
		appendItem("Fortinet-Client-IPv6-Address", firstReplyValue(attrs.FortinetClientIPv6Address, attrs.FramedIPv6Address), false)
		appendItem("Fortinet-Interface-Name", firstReplyValue(attrs.FortinetInterfaceName, attrs.DeviceGroup), true)
		appendItem("Fortinet-Access-Profile", firstReplyValue(attrs.FortinetAccessProfile, attrs.PolicyTag, attrs.FilterID, attrs.ACLPolicyName), true)
		appendItem("Fortinet-SSID", attrs.FortinetSSID, true)
		appendItem("Fortinet-AP-Name", firstReplyValue(attrs.FortinetAPName, attrs.DeviceGroup), true)
		appendItem("Fortinet-FAC-Auth-Status", attrs.FortinetFACAuthStatus, true)
		appendItem("Fortinet-FAC-Challenge-Code", attrs.FortinetFACChallengeCode, true)
		appendItem("Fortinet-Webfilter-Category-Allow", attrs.FortinetWebfilterCategoryAllow, false)
		appendItem("Fortinet-Webfilter-Category-Block", attrs.FortinetWebfilterCategoryBlock, false)
		appendItem("Fortinet-Webfilter-Category-Monitor", attrs.FortinetWebfilterCategoryMonitor, false)
		appendItem("Fortinet-AppCtrl-Category-Allow", attrs.FortinetAppCtrlCategoryAllow, false)
		appendItem("Fortinet-AppCtrl-Category-Block", attrs.FortinetAppCtrlCategoryBlock, false)
		appendItem("Fortinet-AppCtrl-Risk-Allow", attrs.FortinetAppCtrlRiskAllow, false)
		appendItem("Fortinet-AppCtrl-Risk-Block", attrs.FortinetAppCtrlRiskBlock, false)
		appendItem("Fortinet-FDD-Access-Profile", attrs.FortinetFDDAccessProfile, true)
		appendItem("Fortinet-FDD-Trusted-Hosts", attrs.FortinetFDDTrustedHosts, true)
		appendItem("Fortinet-FDD-SPP-Name", attrs.FortinetFDDSPPName, true)
		appendItem("Fortinet-FDD-Is-System-Admin", attrs.FortinetFDDIsSystemAdmin, true)
		appendItem("Fortinet-FDD-Is-SPP-Admin", attrs.FortinetFDDIsSPPAdmin, true)
		appendItem("Fortinet-FDD-SPP-Policy-Group", attrs.FortinetFDDSPPPolicyGroup, true)
		appendItem("Fortinet-FDD-Allow-API-Access", attrs.FortinetFDDAllowAPIAccess, true)
		appendItem("Fortinet-Fpc-User-Role", firstReplyValue(attrs.FortinetFPCUserRole, attrs.Role), true)
		appendItem("Fortinet-Tenant-Identification", firstReplyValue(attrs.FortinetTenantIdentification, attrs.Tenant), true)
		appendFortinetPaloAltoAVPairs(attrs.FortinetFortiWANAVPairs, appendItem, "Fortinet-FortiWAN-AVPair")
		appendFortinetPaloAltoAVPairs(attrs.FortinetHostPortAVPairs, appendItem, "Fortinet-Host-Port-AVPair")
	case productconfigs.VendorPackPaloAlto:
		appendItem("PaloAlto-Admin-Role", replyRole(attrs), true)
		appendItem("PaloAlto-Admin-Access-Domain", attrs.Tenant, true)
		appendItem("PaloAlto-Panorama-Admin-Role", firstReplyValue(attrs.PaloAltoPanoramaAdminRole, attrs.Role), true)
		appendItem("PaloAlto-Panorama-Admin-Access-Domain", firstReplyValue(attrs.PaloAltoPanoramaAdminAccessDomain, attrs.Tenant), true)
		appendItem("PaloAlto-User-Group", firstReplyValue(attrs.DeviceGroup, attrs.Role), true)
		appendItem("PaloAlto-User-Domain", firstReplyValue(attrs.PaloAltoUserDomain, attrs.Tenant), true)
		appendItem("PaloAlto-Client-Source-IP", firstReplyValue(attrs.PaloAltoClientSourceIP, attrs.FramedIPAddress), false)
		appendItem("PaloAlto-Client-OS", attrs.PaloAltoClientOS, true)
		appendItem("PaloAlto-Client-Hostname", attrs.PaloAltoClientHostname, true)
		appendItem("PaloAlto-GlobalProtect-Client-Version", attrs.PaloAltoGlobalProtectClientVersion, true)
	}
}

func appendFortinetPaloAltoAVPairs(values []string, appendItem func(string, string, bool), attribute string) {
	for _, value := range values {
		token, err := NormalizeFortinetPaloAltoAttribute("fortinet-paloalto", attribute, value)
		if err != nil {
			continue
		}
		if token.Namespace != "" {
			appendItem(attribute, token.Namespace+":"+token.Name+token.Operator+token.Value, true)
			continue
		}
		if token.Name != "" {
			appendItem(attribute, token.Name+token.Operator+token.Value, true)
			continue
		}
		appendItem(attribute, token.Value, true)
	}
}

func applyFortinetPaloAltoAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeFortinetPaloAltoAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyFortinetPaloAltoAttributeToBrokerResult(result, token)
	return true
}

func ApplyFortinetPaloAltoAttributeToBrokerResult(result *BrokerAuthResult, token FortinetPaloAltoAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case FortinetPaloAltoKindRole:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case FortinetPaloAltoKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
		if containsAnyFortinetPaloAltoRuntimeToken(token.Attribute, "vdom", "access-domain", "user-domain") {
			setStringIfEmpty(&result.VendorVRF, token.Value)
		}
	case FortinetPaloAltoKindPolicy, FortinetPaloAltoKindWebFilter:
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
	case FortinetPaloAltoKindAppControl:
		if containsAnyFortinetPaloAltoRuntimeToken(token.Attribute, "risk") {
			setStringIfEmpty(&result.VendorDevicePosture, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
	case FortinetPaloAltoKindChallenge, FortinetPaloAltoKindSecret:
		appendUniqueVendorAVPair(result, token.Raw)
	case FortinetPaloAltoKindVPN, FortinetPaloAltoKindPosture:
		setStringIfEmpty(&result.VendorDevicePosture, token.Value)
	case FortinetPaloAltoKindAccounting:
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case FortinetPaloAltoKindWLAN, FortinetPaloAltoKindInterface:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case FortinetPaloAltoKindIPv4Address:
		setStringIfEmpty(&result.VendorFramedIPAddress, token.Value)
	case FortinetPaloAltoKindIPv6Address:
		setStringIfEmpty(&result.VendorFramedIPv6Address, token.Value)
	case FortinetPaloAltoKindDynamicACL, FortinetPaloAltoKindRoute:
		applyFortinetPaloAltoAVPairToken(result, token)
	default:
		if token.Name != "" {
			appendUniqueVendorAVPair(result, token.Raw)
		}
	}
}

func applyFortinetPaloAltoAVPairToken(result *BrokerAuthResult, token FortinetPaloAltoAttribute) {
	name := strings.ToLower(strings.TrimSpace(token.Namespace + " " + token.Name + " " + token.Attribute))
	switch {
	case containsAnyFortinetPaloAltoRuntimeToken(name, "outacl", "egress", "output"):
		setStringIfEmpty(&result.VendorOutboundACL, token.Value)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "acl", "filter", "trusted-host"):
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "route"):
		result.VendorFramedRoutes = appendUniqueVendorString(result.VendorFramedRoutes, token.Value, 32)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "vrf", "vdom"):
		setStringIfEmpty(&result.VendorVRF, token.Value)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "tenant", "domain"):
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "role", "group"):
		setStringIfEmpty(&result.VendorRole, token.Value)
	case containsAnyFortinetPaloAltoRuntimeToken(name, "pool"):
		setStringIfEmpty(&result.VendorIPv4Pool, token.Value)
	default:
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
		appendUniqueVendorAVPair(result, token.Raw)
	}
}

func classifyFortinetPaloAltoRuntime(attribute, tokenName string) (FortinetPaloAltoAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnyFortinetPaloAltoRuntimeToken(name, "fac-token", "fac-challenge"):
		return FortinetPaloAltoKindSecret, productconfigs.VendorSemanticCertificateOnboarding, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "admin-role", "panorama-admin-role", "group-name", "user-role", "is-system-admin", "is-spp-admin"):
		return FortinetPaloAltoKindRole, productconfigs.VendorSemanticRole, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "access-domain", "user-domain", "vdom", "tenant"):
		return FortinetPaloAltoKindTenant, productconfigs.VendorSemanticTenant, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "outacl", "inacl", "acl", "filter", "trusted-host", "host-port-avpair"):
		direction := "in"
		if containsAnyFortinetPaloAltoRuntimeToken(name, "outacl", "egress", "output") {
			direction = "out"
		}
		return FortinetPaloAltoKindDynamicACL, productconfigs.VendorSemanticDynamicACL, direction
	case containsAnyFortinetPaloAltoRuntimeToken(name, "route"):
		return FortinetPaloAltoKindRoute, productconfigs.VendorSemanticRoute, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "webfilter"):
		return FortinetPaloAltoKindWebFilter, productconfigs.VendorSemanticPolicyTag, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "appctrl"):
		semantic := productconfigs.VendorSemanticPolicyTag
		if containsAnyFortinetPaloAltoRuntimeToken(name, "risk") {
			semantic = productconfigs.VendorSemanticDevicePosture
		}
		return FortinetPaloAltoKindAppControl, semantic, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "access-profile", "spp-name", "spp-policy-group", "allow-api-access", "policy", "profile"):
		return FortinetPaloAltoKindPolicy, productconfigs.VendorSemanticPolicyTag, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "globalprotect"):
		return FortinetPaloAltoKindVPN, productconfigs.VendorSemanticDevicePosture, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "client-os", "auth-status"):
		return FortinetPaloAltoKindPosture, productconfigs.VendorSemanticDevicePosture, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "client-hostname", "wirelesscontroller-device-mac", "wirelesscontroller-wtp-id", "assoc-time"):
		return FortinetPaloAltoKindAccounting, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "user-group", "device-group", "ssid", "ap-name"):
		return FortinetPaloAltoKindWLAN, productconfigs.VendorSemanticDeviceGroup, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "interface"):
		return FortinetPaloAltoKindInterface, productconfigs.VendorSemanticDeviceGroup, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "client-source-ip", "client-ip-address"):
		return FortinetPaloAltoKindIPv4Address, productconfigs.VendorSemanticIPv4Address, ""
	case containsAnyFortinetPaloAltoRuntimeToken(name, "client-ipv6-address"):
		return FortinetPaloAltoKindIPv6Address, productconfigs.VendorSemanticIPv6Address, ""
	default:
		return FortinetPaloAltoKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func isFortinetPaloAltoAVPairAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "fortinet-fortiwan-avpair", "fortinet-host-port-avpair":
		return true
	default:
		return false
	}
}

func isFortinetPaloAltoSecretRuntimeAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyFortinetPaloAltoRuntimeToken(name, "fac-token", "fac-challenge")
}

func containsAnyFortinetPaloAltoRuntimeToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func fortinetPaloAltoBoolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func fortinetPaloAltoUnixTimeString(value int64) string {
	if value <= 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}
