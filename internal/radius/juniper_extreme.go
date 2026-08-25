package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const JuniperExtremeMaxValueLength = 240

type JuniperExtremeAttributeKind string

const (
	JuniperExtremeKindUnknown       JuniperExtremeAttributeKind = "unknown"
	JuniperExtremeKindRole          JuniperExtremeAttributeKind = "role_policy"
	JuniperExtremeKindCommandAuth   JuniperExtremeAttributeKind = "command_authorization"
	JuniperExtremeKindVLAN          JuniperExtremeAttributeKind = "vlan_policy"
	JuniperExtremeKindACL           JuniperExtremeAttributeKind = "acl_policy"
	JuniperExtremeKindPortal        JuniperExtremeAttributeKind = "guest_portal"
	JuniperExtremeKindVRF           JuniperExtremeAttributeKind = "vrf"
	JuniperExtremeKindRoute         JuniperExtremeAttributeKind = "route"
	JuniperExtremeKindAddressPool   JuniperExtremeAttributeKind = "address_pool"
	JuniperExtremeKindQoS           JuniperExtremeAttributeKind = "qos_policy"
	JuniperExtremeKindAccounting    JuniperExtremeAttributeKind = "accounting_context"
	JuniperExtremeKindDevice        JuniperExtremeAttributeKind = "device_context"
	JuniperExtremeKindTenant        JuniperExtremeAttributeKind = "tenant"
	JuniperExtremeKindSessionAction JuniperExtremeAttributeKind = "session_action"
	JuniperExtremeKindCoA           JuniperExtremeAttributeKind = "dynamic_authorization"
	JuniperExtremeKindTranslation   JuniperExtremeAttributeKind = "translation"
	JuniperExtremeKindSecret        JuniperExtremeAttributeKind = "secret_redaction"
)

type JuniperExtremeAttribute struct {
	Raw       string                      `json:"raw"`
	Vendor    string                      `json:"vendor"`
	Attribute string                      `json:"attribute"`
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name,omitempty"`
	Operator  string                      `json:"operator,omitempty"`
	Value     string                      `json:"value"`
	Kind      JuniperExtremeAttributeKind `json:"kind"`
	Semantic  string                      `json:"semantic"`
	Direction string                      `json:"direction,omitempty"`
	Redacted  bool                        `json:"redacted"`
}

func NormalizeJuniperExtremeAttribute(vendor, attribute, raw string) (JuniperExtremeAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return JuniperExtremeAttribute{}, fmt.Errorf("Juniper/Extreme attribute name is required")
	}
	if value == "" {
		return JuniperExtremeAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > JuniperExtremeMaxValueLength {
		return JuniperExtremeAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, JuniperExtremeMaxValueLength)
	}
	if containsControlRune(value) {
		return JuniperExtremeAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isJuniperExtremeSecretRuntimeAttribute(attribute) {
		return JuniperExtremeAttribute{
			Raw:       attribute + "=<redacted>",
			Vendor:    vendor,
			Attribute: attribute,
			Value:     "<redacted>",
			Kind:      JuniperExtremeKindSecret,
			Semantic:  productconfigs.VendorSemanticPolicyTag,
			Redacted:  true,
		}, nil
	}
	if isJuniperExtremeAVPairAttribute(attribute) {
		return parseJuniperExtremeAVPair(vendor, attribute, value)
	}
	kind, semantic, direction := classifyJuniperExtremeRuntime(attribute, "")
	return JuniperExtremeAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func parseJuniperExtremeAVPair(vendor, attribute, raw string) (JuniperExtremeAttribute, error) {
	name, namespace, op, value := splitJuniperExtremeToken(raw)
	if name == "" || value == "" {
		return JuniperExtremeAttribute{}, fmt.Errorf("%s must use name=value or name:value form", attribute)
	}
	if !validCiscoAVPairToken(namespace) || !validCiscoAVPairToken(name) {
		return JuniperExtremeAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	tokenKey := name
	if namespace != "" {
		tokenKey = namespace + ":" + name
	}
	kind, semantic, direction := classifyJuniperExtremeRuntime(attribute, tokenKey)
	return JuniperExtremeAttribute{
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

func splitJuniperExtremeToken(raw string) (name, namespace, op, value string) {
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

func BuildJuniperExtremePolicyTokens(values []string) ([]string, []string) {
	out := make([]string, 0, len(values))
	errors := []string{}
	for _, value := range values {
		token, err := NormalizeJuniperExtremeAttribute("juniper-extreme", "Juniper-AV-Pair", value)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if token.Redacted {
			out = append(out, token.Raw)
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

func appendJuniperExtremeReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if attrs == nil {
		return
	}
	switch packKey {
	case productconfigs.VendorPackJuniper:
		appendItem("Juniper-Allow-Commands", attrs.JuniperAllowCommands, true)
		appendItem("Juniper-Deny-Commands", attrs.JuniperDenyCommands, true)
		appendItem("Juniper-User-Permissions", attrs.JuniperUserPermissions, true)
		appendItem("Juniper-VoIP-Vlan", attrs.JuniperVoIPVLAN, true)
		appendItem("Juniper-CoS-Traffic-Control-Profile", firstReplyValue(attrs.JuniperCoSTrafficControlProfile, attrs.BandwidthProfile), true)
		appendItem("Juniper-Policer-Parameter", attrs.JuniperPolicerParameter, true)
		appendJuniperExtremeAVPairs(attrs.JuniperAVPairs, appendItem, "Juniper-AV-Pair")
	case productconfigs.VendorPackExtreme:
		appendIntegerStringItem(attrs.ExtremeCLIAuthorization, appendItem, "Extreme-CLI-Authorization")
		appendItem("Extreme-Shell-Command", attrs.ExtremeShellCommand, true)
		appendItem("Extreme-Netlogin-Url-Desc", attrs.ExtremeNetloginURLDesc, true)
		appendItem("Extreme-User-Location", firstReplyValue(attrs.ExtremeUserLocation, attrs.Tenant), true)
		appendItem("Extreme-VM-Name", attrs.ExtremeVMName, true)
		appendItem("Extreme-VM-VPP-Name", attrs.ExtremeVMVPPName, true)
		appendItem("Extreme-VM-IP-Addr", attrs.ExtremeVMIPAddr, true)
		appendIntegerStringItem(attrs.ExtremeVMVLANID, appendItem, "Extreme-VM-VLAN-ID")
		appendItem("Extreme-VM-VR-Name", firstReplyValue(attrs.ExtremeVMVRName, attrs.VRF), true)
	case productconfigs.VendorPackERX:
		appendItem("ERX-Virtual-Router-Name", firstReplyValue(attrs.ERXVirtualRouterName, attrs.VRF), true)
		appendItem("ERX-Address-Pool-Name", firstReplyValue(attrs.ERXAddressPoolName, attrs.FramedPool, attrs.TranslationPublicPool), true)
		appendItem("ERX-Redirect-VR-Name", attrs.ERXRedirectVRName, true)
		appendItem("ERX-Qos-Profile-Name", firstReplyValue(attrs.ERXQoSProfileName, attrs.BandwidthProfile), true)
		appendItem("ERX-Pppoe-Url", attrs.ERXPppoeURL, true)
		appendItem("ERX-Service-Bundle", attrs.ERXServiceBundle, true)
		appendItem("ERX-Service-Activate", attrs.ERXServiceActivate, true)
		appendItem("ERX-Service-Deactivate", attrs.ERXServiceDeactivate, true)
		appendIntegerStringItem(attrs.ERXServiceTimeout, appendItem, "ERX-Service-Timeout")
		appendItem("ERX-Client-Profile-Name", firstReplyValue(attrs.ERXClientProfileName, attrs.DeviceGroup), true)
		appendItem("ERX-APN-Name", firstReplyValue(attrs.ERXAPNName, attrs.Tenant), true)
		appendItem("ERX-Cos-Shaping-Rate", attrs.ERXCosShapingRate, true)
		appendItem("ERX-Input-Interface-Filter", firstReplyValue(attrs.ERXInputInterfaceFilter, attrs.InboundACL, attrs.ACLPolicyName), true)
		appendItem("ERX-Output-Interface-Filter", firstReplyValue(attrs.ERXOutputInterfaceFilter, attrs.OutboundACL, attrs.ACLPolicyName), true)
		appendItem("ERX-IPv6-Delegated-Pool-Name", firstReplyValue(attrs.ERXIPv6DelegatedPoolName, attrs.FramedIPv6Pool), true)
		appendIntegerStringItem(attrs.ERXBulkCoATransactionID, appendItem, "ERX-Bulk-CoA-Transaction-Id")
		appendIntegerStringItem(attrs.ERXBulkCoAIdentifier, appendItem, "ERX-Bulk-CoA-Identifier")
		appendItem("ERX-Adv-Pcef-Rule-Name", attrs.ERXAdvPcefRuleName, true)
	}
}

func appendJuniperExtremeAVPairs(values []string, appendItem func(string, string, bool), attribute string) {
	for _, value := range values {
		token, err := NormalizeJuniperExtremeAttribute("juniper-extreme", attribute, value)
		if err != nil {
			continue
		}
		if token.Redacted {
			appendItem(attribute, token.Raw, true)
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

func applyJuniperExtremeAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeJuniperExtremeAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyJuniperExtremeAttributeToBrokerResult(result, token)
	return true
}

func ApplyJuniperExtremeAttributeToBrokerResult(result *BrokerAuthResult, token JuniperExtremeAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case JuniperExtremeKindRole, JuniperExtremeKindCommandAuth:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case JuniperExtremeKindVLAN:
		if vlan, err := strconv.Atoi(token.Value); err == nil && vlan >= 1 && vlan <= 4094 {
			if !result.HasVendorVLAN {
				result.VendorVLAN = vlan
				result.HasVendorVLAN = true
			}
			return
		}
		setStringIfEmpty(&result.VendorVLANPool, token.Value)
	case JuniperExtremeKindACL:
		if token.Direction == "out" || containsAnyJuniperRuntimeToken(token.Attribute, "egress", "output") || containsAnyJuniperRuntimeToken(token.Name, "outacl", "egress", "output") {
			setStringIfEmpty(&result.VendorOutboundACL, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case JuniperExtremeKindPortal:
		setStringIfEmpty(&result.VendorPortalProfile, token.Value)
	case JuniperExtremeKindVRF:
		setStringIfEmpty(&result.VendorVRF, token.Value)
	case JuniperExtremeKindRoute:
		if token.Namespace == "ipv6" || containsAnyJuniperRuntimeToken(token.Attribute, "ipv6") || containsAnyJuniperRuntimeToken(token.Name, "ipv6") {
			result.VendorFramedIPv6Routes = appendUniqueVendorString(result.VendorFramedIPv6Routes, token.Value, 32)
			return
		}
		result.VendorFramedRoutes = appendUniqueVendorString(result.VendorFramedRoutes, token.Value, 32)
	case JuniperExtremeKindAddressPool:
		applyJuniperExtremeAddressPool(result, token)
	case JuniperExtremeKindQoS:
		applyJuniperExtremeQoS(result, token)
	case JuniperExtremeKindAccounting, JuniperExtremeKindDevice:
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case JuniperExtremeKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case JuniperExtremeKindSessionAction:
		setStringIfEmpty(&result.VendorSessionAction, token.Value)
	case JuniperExtremeKindCoA:
		if strings.Contains(strings.ToLower(token.Semantic), "disconnect") || containsAnyJuniperRuntimeToken(token.Attribute, "disconnect") {
			setStringIfEmpty(&result.VendorSessionAction, "disconnect:"+token.Value)
			return
		}
		setStringIfEmpty(&result.VendorSessionAction, "reauth:"+token.Value)
	case JuniperExtremeKindTranslation:
		applyJuniperExtremeTranslation(result, token)
	case JuniperExtremeKindSecret:
		appendUniqueVendorAVPair(result, token.Raw)
	default:
		if token.Name != "" {
			appendUniqueVendorAVPair(result, token.Raw)
		}
	}
}

func classifyJuniperExtremeRuntime(attribute, tokenName string) (JuniperExtremeAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnyJuniperRuntimeToken(name, "password", "mobile-ip-key", "secret"):
		return JuniperExtremeKindSecret, productconfigs.VendorSemanticPolicyTag, ""
	case containsAnyJuniperRuntimeToken(name, "translation", "nat64", "port-block", "public-ipv4"):
		return JuniperExtremeKindTranslation, productconfigs.VendorSemanticTranslationPolicy, ""
	case containsAnyJuniperRuntimeToken(name, "inacl", "firewall", "switching-filter", "filter", "acl", "pcef-rule"):
		direction := "in"
		if containsAnyJuniperRuntimeToken(name, "outacl", "egress", "output") {
			direction = "out"
		}
		semantic := productconfigs.VendorSemanticACL
		if isJuniperExtremeAVPairAttribute(attribute) {
			semantic = productconfigs.VendorSemanticDynamicACL
		}
		return JuniperExtremeKindACL, semantic, direction
	case containsAnyJuniperRuntimeToken(name, "vrf", "virtual-router", "vrouter", "vr-name"):
		return JuniperExtremeKindVRF, productconfigs.VendorSemanticVRF, ""
	case containsAnyJuniperRuntimeToken(name, "route", "routing-services"):
		return JuniperExtremeKindRoute, productconfigs.VendorSemanticRoute, ""
	case containsAnyJuniperRuntimeToken(name, "delegated-prefix", "delegated-pool", "ndra-pool", "addr-pool", "address-pool", "ip-pool", "pool-name"):
		return JuniperExtremeKindAddressPool, productconfigs.VendorSemanticAddressPool, ""
	case containsAnyJuniperRuntimeToken(name, "vlan"):
		return JuniperExtremeKindVLAN, productconfigs.VendorSemanticVLAN, ""
	case containsAnyJuniperRuntimeToken(name, "portal", "redirect", "url"):
		return JuniperExtremeKindPortal, productconfigs.VendorSemanticPortalProfile, ""
	case containsAnyJuniperRuntimeToken(name, "qos", "cos", "policer", "rate", "bandwidth", "connect-speed", "throughput"):
		return JuniperExtremeKindQoS, productconfigs.VendorSemanticBandwidthProfile, ""
	case containsAnyJuniperRuntimeToken(name, "service-activate", "service-deactivate", "update-service"):
		return JuniperExtremeKindSessionAction, productconfigs.VendorSemanticSessionAction, ""
	case containsAnyJuniperRuntimeToken(name, "bulk-coa", "disconnect", "re-authentication"):
		semantic := productconfigs.VendorSemanticCoAReauth
		if strings.Contains(name, "disconnect") {
			semantic = productconfigs.VendorSemanticCoADisconnect
		}
		return JuniperExtremeKindCoA, semantic, ""
	case containsAnyJuniperRuntimeToken(name, "allow-commands", "deny-commands", "allow-configuration", "deny-configuration", "shell-command", "interactive-command", "permissions", "cli"):
		return JuniperExtremeKindCommandAuth, productconfigs.VendorSemanticRole, ""
	case containsAnyJuniperRuntimeToken(name, "local-user", "security-profile"):
		return JuniperExtremeKindRole, productconfigs.VendorSemanticRole, ""
	case containsAnyJuniperRuntimeToken(name, "location", "apn"):
		return JuniperExtremeKindTenant, productconfigs.VendorSemanticTenant, ""
	case containsAnyJuniperRuntimeToken(name, "group", "profile", "vm-name", "interface", "dhcp-mac", "radius-client", "ppp-username", "service-session"):
		return JuniperExtremeKindDevice, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnyJuniperRuntimeToken(name, "acct", "gigawords", "input-octets", "output-octets", "request-reason"):
		return JuniperExtremeKindAccounting, productconfigs.VendorSemanticAccountingCounters, ""
	default:
		return JuniperExtremeKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func applyJuniperExtremeAddressPool(result *BrokerAuthResult, token JuniperExtremeAttribute) {
	switch {
	case containsAnyJuniperRuntimeToken(token.Attribute, "delegated") || containsAnyJuniperRuntimeToken(token.Name, "delegated"):
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, token.Value)
	case containsAnyJuniperRuntimeToken(token.Attribute, "ipv6", "ndra") || containsAnyJuniperRuntimeToken(token.Name, "ipv6", "ndra"):
		setStringIfEmpty(&result.VendorIPv6Pool, token.Value)
	case containsAnyJuniperRuntimeToken(token.Attribute, "address-pool") || containsAnyJuniperRuntimeToken(token.Name, "public-pool"):
		setStringIfEmpty(&result.VendorIPv4Pool, token.Value)
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Pool, token.Value)
	default:
		setStringIfEmpty(&result.VendorIPv4Pool, token.Value)
	}
}

func applyJuniperExtremeQoS(result *BrokerAuthResult, token JuniperExtremeAttribute) {
	if value, err := strconv.Atoi(token.Value); err == nil && value > 0 {
		switch {
		case containsAnyJuniperRuntimeToken(token.Attribute, "-up", "upstream", "tx") || containsAnyJuniperRuntimeToken(token.Name, "up", "upstream", "tx"):
			if result.WISPrBandwidthMaxUp == 0 {
				result.WISPrBandwidthMaxUp = value
			}
			return
		case containsAnyJuniperRuntimeToken(token.Attribute, "-dn", "downstream", "rx") || containsAnyJuniperRuntimeToken(token.Name, "dn", "downstream", "rx"):
			if result.WISPrBandwidthMaxDown == 0 {
				result.WISPrBandwidthMaxDown = value
			}
			return
		}
	}
	setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
}

func applyJuniperExtremeTranslation(result *BrokerAuthResult, token JuniperExtremeAttribute) {
	switch {
	case containsAnyJuniperRuntimeToken(token.Name, "public-ipv4") || containsAnyJuniperRuntimeToken(token.Attribute, "public-ipv4"):
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, token.Value)
	case containsAnyJuniperRuntimeToken(token.Name, "port-block") || containsAnyJuniperRuntimeToken(token.Attribute, "port-block"):
		parts := strings.SplitN(token.Value, "-", 2)
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
	case containsAnyJuniperRuntimeToken(token.Name, "nat64") || containsAnyJuniperRuntimeToken(token.Attribute, "nat64"):
		setStringIfEmpty(&result.VendorTranslationNAT64Prefix, token.Value)
	default:
		setStringIfEmpty(&result.VendorTranslationPolicy, token.Value)
	}
}

func isJuniperExtremeAVPairAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "juniper-av-pair":
		return true
	default:
		return false
	}
}

func isJuniperExtremeSecretRuntimeAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "erx-tunnel-password", "erx-ppp-password", "erx-mobile-ip-key":
		return true
	default:
		return false
	}
}

func containsAnyJuniperRuntimeToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
