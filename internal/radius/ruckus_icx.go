package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const RuckusICXMaxValueLength = 240

type RuckusICXAttributeKind string

const (
	RuckusICXKindUnknown        RuckusICXAttributeKind = "unknown"
	RuckusICXKindRole           RuckusICXAttributeKind = "role_policy"
	RuckusICXKindCommandAuth    RuckusICXAttributeKind = "command_authorization"
	RuckusICXKindVLAN           RuckusICXAttributeKind = "vlan_policy"
	RuckusICXKindACL            RuckusICXAttributeKind = "acl_policy"
	RuckusICXKindPortal         RuckusICXAttributeKind = "guest_portal"
	RuckusICXKindGuest          RuckusICXAttributeKind = "guest_lifecycle"
	RuckusICXKindQoS            RuckusICXAttributeKind = "qos_policy"
	RuckusICXKindQuota          RuckusICXAttributeKind = "quota_policy"
	RuckusICXKindAccounting     RuckusICXAttributeKind = "accounting_context"
	RuckusICXKindDevice         RuckusICXAttributeKind = "device_context"
	RuckusICXKindPosture        RuckusICXAttributeKind = "posture"
	RuckusICXKindTenant         RuckusICXAttributeKind = "tenant"
	RuckusICXKindAddressPool    RuckusICXAttributeKind = "address_pool"
	RuckusICXKindIPv4Address    RuckusICXAttributeKind = "ipv4_address"
	RuckusICXKindMobile         RuckusICXAttributeKind = "mobile_core"
	RuckusICXKindCoA            RuckusICXAttributeKind = "dynamic_authorization"
	RuckusICXKindController     RuckusICXAttributeKind = "controller_context"
	RuckusICXKindSessionTimeout RuckusICXAttributeKind = "session_timeout"
	RuckusICXKindSecret         RuckusICXAttributeKind = "secret_redaction"
)

type RuckusICXAttribute struct {
	Raw       string                 `json:"raw"`
	Vendor    string                 `json:"vendor"`
	Attribute string                 `json:"attribute"`
	Namespace string                 `json:"namespace,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Operator  string                 `json:"operator,omitempty"`
	Value     string                 `json:"value"`
	Kind      RuckusICXAttributeKind `json:"kind"`
	Semantic  string                 `json:"semantic"`
	Direction string                 `json:"direction,omitempty"`
	Redacted  bool                   `json:"redacted"`
}

func NormalizeRuckusICXAttribute(vendor, attribute, raw string) (RuckusICXAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return RuckusICXAttribute{}, fmt.Errorf("Ruckus/ICX attribute name is required")
	}
	if value == "" {
		return RuckusICXAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > RuckusICXMaxValueLength {
		return RuckusICXAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, RuckusICXMaxValueLength)
	}
	if isRuckusICXSecretRuntimeAttribute(attribute) {
		kind, semantic, direction := classifyRuckusICXRuntime(attribute, "")
		return RuckusICXAttribute{
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
		return RuckusICXAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isRuckusICXAVPairAttribute(attribute) {
		return parseRuckusICXAVPair(vendor, attribute, value)
	}
	kind, semantic, direction := classifyRuckusICXRuntime(attribute, "")
	return RuckusICXAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func parseRuckusICXAVPair(vendor, attribute, raw string) (RuckusICXAttribute, error) {
	name, namespace, op, value := splitRuckusICXToken(raw)
	if name == "" || value == "" {
		return RuckusICXAttribute{}, fmt.Errorf("%s must use name=value or name:value form", attribute)
	}
	if !validCiscoAVPairToken(namespace) || !validCiscoAVPairToken(name) {
		return RuckusICXAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	tokenKey := name
	if namespace != "" {
		tokenKey = namespace + ":" + name
	}
	kind, semantic, direction := classifyRuckusICXRuntime(attribute, tokenKey)
	return RuckusICXAttribute{
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

func splitRuckusICXToken(raw string) (name, namespace, op, value string) {
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

func BuildRuckusICXPolicyTokens(values []string) ([]string, []string) {
	out := make([]string, 0, len(values))
	errors := []string{}
	for _, value := range values {
		token, err := NormalizeRuckusICXAttribute("ruckus-icx", "Ruckus-FlexAuth-AVP", value)
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

func appendRuckusICXReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if attrs == nil {
		return
	}
	switch packKey {
	case productconfigs.VendorPackRuckus:
		appendItem("Ruckus-User-Groups", replyRole(attrs), true)
		if vlan := replyVLAN(attrs); vlan > 0 {
			appendItem("Ruckus-VLAN-ID", fmt.Sprintf("%d", vlan), false)
		}
		appendItem("Ruckus-Policy-Name", firstReplyValue(attrs.PolicyTag, attrs.FilterID, attrs.ACLPolicyName), true)
		appendItem("Ruckus-Wispr-Redirect-Policy", firstReplyValue(attrs.PortalProfile, attrs.FilterID), true)
		appendItem("Ruckus-Zone-Name", attrs.DeviceGroup, true)
		appendItem("Ruckus-Wlan-Name", firstReplyValue(attrs.RuckusWLANName, attrs.DeviceGroup), true)
		appendItem("Ruckus-Vlan-Pool", attrs.VLANPool, true)
		appendItem("Ruckus-Vlan-Name", firstReplyValue(attrs.RuckusVLANName, attrs.VLANPool), true)
		appendIntegerStringItem(attrs.RuckusStaExpiration, appendItem, "Ruckus-Sta-Expiration")
		appendIntegerStringItem(attrs.RuckusGracePeriod, appendItem, "Ruckus-Grace-Period")
		appendIntegerStringItem(attrs.RuckusMaxDLULQuota, appendItem, "Ruckus-Max-DL-UL-Quota")
		appendItem("Ruckus-Traffic-Class-Attribute-Ids", firstReplyValue(attrs.RuckusTrafficClassAttributeIDs, attrs.BandwidthProfile), true)
		appendItem("Ruckus-Nat-Pool-Name", firstReplyValue(attrs.TranslationPublicPool, attrs.FramedPool), true)
		appendItem("Ruckus-CP-Token", attrs.RuckusCPToken, true)
		appendItem("Ruckus-Cluster-Name", attrs.RuckusClusterName, true)
		appendItem("Ruckus-Auth-Server-Id", attrs.RuckusAuthServerID, true)
		appendItem("Ruckus-SCI-Role", firstReplyValue(attrs.RuckusSCIRole, attrs.Role), true)
		appendItem("Ruckus-SCI-Resource-Group", firstReplyValue(attrs.RuckusSCIResourceGroup, attrs.DeviceGroup), true)
		appendRuckusICXAVPairs(attrs.RuckusFlexAuthAVPs, appendItem, "Ruckus-FlexAuth-AVP")
	case productconfigs.VendorPackFoundry:
		appendIntegerStringItem(attrs.FoundryPrivilegeLevel, appendItem, "Foundry-Privilege-Level")
		appendIntegerStringItem(attrs.FoundryINMPrivilege, appendItem, "Foundry-INM-Privilege")
		appendIntegerStringItem(attrs.FoundryCommandExceptionFlag, appendItem, "Foundry-Command-Exception-Flag")
		appendItem("Foundry-Command-String", attrs.FoundryCommandString, true)
		appendItem("Foundry-Access-List", firstReplyValue(attrs.FoundryAccessList, attrs.InboundACL, attrs.ACLPolicyName), true)
		appendIntegerStringItem(attrs.FoundryMACAuthentNeeds8021X, appendItem, "Foundry-MAC-Authent-needs-802.1x")
		appendIntegerStringItem(attrs.Foundry8021XValidLookup, appendItem, "Foundry-802.1x-Valid-Lookup")
		appendIntegerStringItem(attrs.FoundryMACBasedVLANQoS, appendItem, "Foundry-MAC-Based-Vlan-QoS")
		appendItem("Foundry-INM-Role-Aor-List", firstReplyValue(attrs.FoundryINMRoleAORList, attrs.Role), true)
		appendItem("Foundry-COA-Command", attrs.FoundryCOACommand, true)
		appendItem("Foundry-SI-Context-Role", firstReplyValue(attrs.FoundrySIContextRole, attrs.Role), true)
		appendItem("Foundry-SI-Role-Template", attrs.FoundrySIRoleTemplate, true)
		appendItem("Foundry-Voice-Phone-Config", attrs.FoundryVoicePhoneConfig, true)
	}
}

func appendRuckusICXAVPairs(values []string, appendItem func(string, string, bool), attribute string) {
	for _, value := range values {
		token, err := NormalizeRuckusICXAttribute("ruckus-icx", attribute, value)
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

func applyRuckusICXAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeRuckusICXAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyRuckusICXAttributeToBrokerResult(result, token)
	return true
}

func ApplyRuckusICXAttributeToBrokerResult(result *BrokerAuthResult, token RuckusICXAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case RuckusICXKindRole:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case RuckusICXKindCommandAuth:
		if result.VendorRole == "" && ruckusICXLooksLikeRoleAttribute(token.Attribute, token.Name) {
			setStringIfEmpty(&result.VendorRole, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorPolicyTag, "command:"+token.Value)
	case RuckusICXKindVLAN:
		if vlan, err := strconv.Atoi(token.Value); err == nil && vlan >= 1 && vlan <= 4094 {
			if !result.HasVendorVLAN {
				result.VendorVLAN = vlan
				result.HasVendorVLAN = true
			}
			return
		}
		setStringIfEmpty(&result.VendorVLANPool, token.Value)
	case RuckusICXKindACL:
		if token.Direction == "out" || containsAnyRuckusRuntimeToken(token.Attribute, "out", "egress") || containsAnyRuckusRuntimeToken(token.Name, "outacl", "egress") {
			setStringIfEmpty(&result.VendorOutboundACL, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case RuckusICXKindPortal, RuckusICXKindGuest:
		setStringIfEmpty(&result.VendorPortalProfile, token.Value)
	case RuckusICXKindQoS:
		setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
	case RuckusICXKindQuota:
		if value, err := strconv.ParseUint(strings.TrimSpace(token.Value), 10, 64); err == nil && value > 0 {
			result.VendorMaxTotalOctets = value
			result.HasVendorMaxTotalOctets = true
			return
		}
		setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
	case RuckusICXKindAccounting:
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case RuckusICXKindDevice:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case RuckusICXKindPosture:
		setStringIfEmpty(&result.VendorDevicePosture, token.Value)
	case RuckusICXKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case RuckusICXKindAddressPool:
		setStringIfEmpty(&result.VendorIPv4Pool, token.Value)
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Pool, token.Value)
	case RuckusICXKindIPv4Address:
		setStringIfEmpty(&result.VendorFramedIPAddress, token.Value)
	case RuckusICXKindMobile:
		if containsAnyRuckusRuntimeToken(token.Attribute, "apn") || containsAnyRuckusRuntimeToken(token.Name, "apn") {
			setStringIfEmpty(&result.VendorTenant, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case RuckusICXKindCoA:
		action := strings.ToLower(strings.TrimSpace(token.Value))
		if action == "" {
			return
		}
		if strings.Contains(action, "disconnect") {
			setStringIfEmpty(&result.VendorSessionAction, "disconnect:"+token.Value)
			return
		}
		if strings.Contains(action, "reauth") || strings.Contains(action, "coa") {
			setStringIfEmpty(&result.VendorSessionAction, "reauth:"+token.Value)
			return
		}
		setStringIfEmpty(&result.VendorSessionAction, token.Value)
	case RuckusICXKindController:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case RuckusICXKindSessionTimeout:
		if value, err := strconv.Atoi(token.Value); err == nil && value > 0 && !result.HasVendorSessionTimeout {
			result.VendorSessionTimeout = value
			result.HasVendorSessionTimeout = true
		}
	case RuckusICXKindSecret:
		appendUniqueVendorAVPair(result, token.Raw)
	default:
		if token.Name != "" {
			appendUniqueVendorAVPair(result, token.Raw)
		}
	}
}

func classifyRuckusICXRuntime(attribute, tokenName string) (RuckusICXAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnyRuckusRuntimeToken(name, "dpsk", "eapol-key-frame", "triplets", "imsi", "msisdn", "charging-charac", "pdp-type", "dynamic-address-flag", "chch-selection-mode", "sgsn-number", "area-code", "cell-identifier", "read-preference"):
		return RuckusICXKindSecret, productconfigs.VendorSemanticPolicyTag, ""
	case containsAnyRuckusRuntimeToken(name, "access-list", "acl", "filter"):
		direction := "in"
		if containsAnyRuckusRuntimeToken(name, "outacl", "egress", "output") {
			direction = "out"
		}
		semantic := productconfigs.VendorSemanticACL
		if isRuckusICXAVPairAttribute(attribute) {
			semantic = productconfigs.VendorSemanticDynamicACL
		}
		return RuckusICXKindACL, semantic, direction
	case containsAnyRuckusRuntimeToken(name, "vlan-qos"):
		return RuckusICXKindVLAN, productconfigs.VendorSemanticVLAN, ""
	case containsAnyRuckusRuntimeToken(name, "vlan"):
		return RuckusICXKindVLAN, productconfigs.VendorSemanticVLAN, ""
	case containsAnyRuckusRuntimeToken(name, "wispr", "portal", "redirect"):
		return RuckusICXKindPortal, productconfigs.VendorSemanticPortalProfile, ""
	case containsAnyRuckusRuntimeToken(name, "cp-token"):
		return RuckusICXKindGuest, productconfigs.VendorSemanticGuestLifecycle, ""
	case containsAnyRuckusRuntimeToken(name, "max-dl-ul-quota", "tc-quota", "quota"):
		return RuckusICXKindQuota, productconfigs.VendorSemanticDataQuota, ""
	case containsAnyRuckusRuntimeToken(name, "qos", "traffic-class", "tc-name", "mac-based-vlan-qos"):
		return RuckusICXKindQoS, productconfigs.VendorSemanticBandwidthProfile, ""
	case containsAnyRuckusRuntimeToken(name, "client-local-ip", "aaa-ip"):
		return RuckusICXKindIPv4Address, productconfigs.VendorSemanticIPv4Address, ""
	case containsAnyRuckusRuntimeToken(name, "nat-pool"):
		return RuckusICXKindAddressPool, productconfigs.VendorSemanticAddressPool, ""
	case containsAnyRuckusRuntimeToken(name, "gn-user-name", "apn", "sgsn", "cdr", "cell", "area"):
		return RuckusICXKindMobile, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnyRuckusRuntimeToken(name, "acct", "input-octets", "output-octets", "accounting-status", "session-type", "start-time"):
		return RuckusICXKindAccounting, productconfigs.VendorSemanticAccountingCounters, ""
	case containsAnyRuckusRuntimeToken(name, "client-os", "client-device", "802.1x", "mac-authent"):
		return RuckusICXKindPosture, productconfigs.VendorSemanticDevicePosture, ""
	case containsAnyRuckusRuntimeToken(name, "domain", "location"):
		return RuckusICXKindTenant, productconfigs.VendorSemanticTenant, ""
	case containsAnyRuckusRuntimeToken(name, "client-host", "gn-user-name"):
		return RuckusICXKindAccounting, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnyRuckusRuntimeToken(name, "zone", "cluster", "blade", "aaa-id", "auth-server", "utp", "ssid", "wlan", "bssid", "roamed", "eth-profile", "sta-rssi", "sta-uuid", "sta-inner", "sci-resource"):
		return RuckusICXKindDevice, productconfigs.VendorSemanticDeviceGroup, ""
	case containsAnyRuckusRuntimeToken(name, "grace-period", "expiration"):
		return RuckusICXKindSessionTimeout, productconfigs.VendorSemanticSessionTimeout, ""
	case containsAnyRuckusRuntimeToken(name, "coa"):
		return RuckusICXKindCoA, productconfigs.VendorSemanticCoAReauth, ""
	case containsAnyRuckusRuntimeToken(name, "command", "privilege", "inm-privilege"):
		return RuckusICXKindCommandAuth, productconfigs.VendorSemanticRole, ""
	case containsAnyRuckusRuntimeToken(name, "user-groups", "user-group", "policy-name", "sci-role", "role-template", "context-role", "aor-list", "role"):
		return RuckusICXKindRole, productconfigs.VendorSemanticRole, ""
	case containsAnyRuckusRuntimeToken(name, "voice"):
		return RuckusICXKindDevice, productconfigs.VendorSemanticPolicyTag, ""
	default:
		return RuckusICXKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func ruckusICXLooksLikeRoleAttribute(attribute, tokenName string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	return containsAnyRuckusRuntimeToken(name, "privilege", "role", "user-groups")
}

func isRuckusICXAVPairAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "ruckus-flexauth-avp":
		return true
	default:
		return false
	}
}

func isRuckusICXSecretRuntimeAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyRuckusRuntimeToken(name,
		"dpsk", "eapol-key-frame", "triplets", "imsi", "msisdn",
		"charging-charac", "pdp-type", "dynamic-address-flag",
		"chch-selection-mode", "sgsn-number", "area-code", "cell-identifier",
		"read-preference",
	)
}

func containsAnyRuckusRuntimeToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
