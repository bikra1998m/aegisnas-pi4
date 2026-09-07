package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const NokiaALUMaxValueLength = 240

type NokiaALUAttributeKind string

const (
	NokiaALUKindUnknown               NokiaALUAttributeKind = "unknown"
	NokiaALUKindRole                  NokiaALUAttributeKind = "role_policy"
	NokiaALUKindQoS                   NokiaALUAttributeKind = "qos_policy"
	NokiaALUKindVLAN                  NokiaALUAttributeKind = "vlan_policy"
	NokiaALUKindACL                   NokiaALUAttributeKind = "acl_policy"
	NokiaALUKindRoute                 NokiaALUAttributeKind = "route_policy"
	NokiaALUKindVRF                   NokiaALUAttributeKind = "vrf"
	NokiaALUKindIPv4Address           NokiaALUAttributeKind = "ipv4_address"
	NokiaALUKindIPv6Address           NokiaALUAttributeKind = "ipv6_address"
	NokiaALUKindAddressPool           NokiaALUAttributeKind = "address_pool"
	NokiaALUKindDelegatedIPv6Pool     NokiaALUAttributeKind = "delegated_ipv6_pool"
	NokiaALUKindRAPrefixPool          NokiaALUAttributeKind = "ra_prefix_pool"
	NokiaALUKindTranslation           NokiaALUAttributeKind = "translation_policy"
	NokiaALUKindTranslationPublicIPv4 NokiaALUAttributeKind = "translation_public_ipv4"
	NokiaALUKindTranslationPortBlock  NokiaALUAttributeKind = "translation_port_block"
	NokiaALUKindNAT64Prefix           NokiaALUAttributeKind = "nat64_prefix"
	NokiaALUKindPortal                NokiaALUAttributeKind = "portal"
	NokiaALUKindAccounting            NokiaALUAttributeKind = "accounting"
	NokiaALUKindDevice                NokiaALUAttributeKind = "device_context"
	NokiaALUKindTenant                NokiaALUAttributeKind = "tenant_location"
	NokiaALUKindPosture               NokiaALUAttributeKind = "posture"
	NokiaALUKindSessionAction         NokiaALUAttributeKind = "session_action"
	NokiaALUKindSecret                NokiaALUAttributeKind = "secret_redaction"
	NokiaALUKindPolicyTag             NokiaALUAttributeKind = "policy_tag"
)

type NokiaALUAttribute struct {
	Raw       string                `json:"raw"`
	Vendor    string                `json:"vendor"`
	Attribute string                `json:"attribute"`
	Namespace string                `json:"namespace,omitempty"`
	Name      string                `json:"name,omitempty"`
	Operator  string                `json:"operator,omitempty"`
	Value     string                `json:"value"`
	Kind      NokiaALUAttributeKind `json:"kind"`
	Semantic  string                `json:"semantic"`
	Direction string                `json:"direction,omitempty"`
	Redacted  bool                  `json:"redacted"`
}

func NormalizeNokiaALUAttribute(vendor, attribute, raw string) (NokiaALUAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return NokiaALUAttribute{}, fmt.Errorf("Nokia/ALU attribute name is required")
	}
	if value == "" {
		return NokiaALUAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > NokiaALUMaxValueLength {
		return NokiaALUAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, NokiaALUMaxValueLength)
	}
	if isNokiaALUSecretRuntimeAttribute(attribute) {
		kind, semantic, direction := classifyNokiaALURuntime(attribute, "")
		return NokiaALUAttribute{
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
		return NokiaALUAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	if isNokiaALUAVPairAttribute(attribute) {
		return parseNokiaALUAVPair(vendor, attribute, value)
	}
	kind, semantic, direction := classifyNokiaALURuntime(attribute, "")
	return NokiaALUAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func parseNokiaALUAVPair(vendor, attribute, raw string) (NokiaALUAttribute, error) {
	name, namespace, op, value := splitNokiaALUToken(raw)
	if name == "" || value == "" {
		return NokiaALUAttribute{}, fmt.Errorf("%s must use name=value or namespace:name=value form", attribute)
	}
	if !validCiscoAVPairToken(namespace) || !validCiscoAVPairToken(name) {
		return NokiaALUAttribute{}, fmt.Errorf("%s contains an invalid policy token", attribute)
	}
	tokenKey := name
	if namespace != "" {
		tokenKey = namespace + ":" + name
	}
	kind, semantic, direction := classifyNokiaALURuntime(attribute, tokenKey)
	return NokiaALUAttribute{
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

func splitNokiaALUToken(raw string) (name, namespace, op, value string) {
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

func applyNokiaALUAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeNokiaALUAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyNokiaALUAttributeToBrokerResult(result, token)
	return true
}

func ApplyNokiaALUAttributeToBrokerResult(result *BrokerAuthResult, token NokiaALUAttribute) {
	if result == nil {
		return
	}
	if token.Name != "" && applyNokiaALUAVPairToken(result, token) {
		return
	}
	switch token.Kind {
	case NokiaALUKindSecret:
		appendUniqueVendorAVPair(result, token.Raw)
	case NokiaALUKindRole:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case NokiaALUKindQoS:
		applyNokiaALUQoS(result, token)
	case NokiaALUKindVLAN:
		applyNokiaALUVLAN(result, token.Value)
	case NokiaALUKindACL:
		if token.Direction == "out" || containsAnyNokiaALURuntimeToken(token.Attribute, "out", "egress", "output") || containsAnyNokiaALURuntimeToken(token.Name, "outacl", "egress") {
			setStringIfEmpty(&result.VendorOutboundACL, token.Value)
			return
		}
		setStringIfEmpty(&result.VendorInboundACL, token.Value)
	case NokiaALUKindRoute:
		applyNokiaALURoute(result, token)
	case NokiaALUKindVRF:
		setStringIfEmpty(&result.VendorVRF, token.Value)
	case NokiaALUKindIPv4Address:
		applyNokiaALUIPv4(result, token)
	case NokiaALUKindIPv6Address:
		applyNokiaALUIPv6(result, token)
	case NokiaALUKindAddressPool:
		applyNokiaALUAddressPool(result, token)
	case NokiaALUKindDelegatedIPv6Pool:
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, token.Value)
	case NokiaALUKindRAPrefixPool:
		setStringIfEmpty(&result.VendorRAPrefixPool, token.Value)
	case NokiaALUKindTranslation:
		setStringIfEmpty(&result.VendorTranslationPolicy, token.Value)
	case NokiaALUKindTranslationPublicIPv4:
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, token.Value)
	case NokiaALUKindTranslationPortBlock:
		applyNokiaALUPortRange(result, token.Value)
	case NokiaALUKindNAT64Prefix:
		setStringIfEmpty(&result.VendorTranslationNAT64Prefix, token.Value)
	case NokiaALUKindPortal:
		setStringIfEmpty(&result.VendorPortalProfile, token.Value)
	case NokiaALUKindAccounting:
		setStringIfEmpty(&result.VendorAccountingIdentity, token.Value)
	case NokiaALUKindDevice:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case NokiaALUKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case NokiaALUKindPosture:
		setStringIfEmpty(&result.VendorDevicePosture, token.Value)
	case NokiaALUKindSessionAction:
		setStringIfEmpty(&result.VendorSessionAction, normalizeNokiaALUSessionAction(token.Value, token.Attribute, token.Name))
	case NokiaALUKindPolicyTag:
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
	default:
		if token.Name != "" {
			appendUniqueVendorAVPair(result, token.Raw)
			return
		}
		setStringIfEmpty(&result.VendorPolicyTag, token.Value)
	}
}

func applyNokiaALUAVPairToken(result *BrokerAuthResult, token NokiaALUAttribute) bool {
	name := strings.ToLower(strings.TrimSpace(token.Name))
	namespace := strings.ToLower(strings.TrimSpace(token.Namespace))
	fullName := strings.TrimSpace(namespace + ":" + name)
	if namespace == "" {
		fullName = name
	}
	value := strings.TrimSpace(token.Value)
	switch {
	case fullName == "vrf" || fullName == "routing-instance" || fullName == "ip:vrf-id":
		setStringIfEmpty(&result.VendorVRF, value)
	case fullName == "route-owner":
		setStringIfEmpty(&result.VendorRouteOwner, value)
	case fullName == "route-revision":
		setStringIfEmpty(&result.VendorRouteRevision, value)
	case fullName == "route-policy":
		setStringIfEmpty(&result.VendorRoutePolicy, value)
	case fullName == "framed-route" || fullName == "ip:route":
		result.VendorFramedRoutes = appendUniqueVendorString(result.VendorFramedRoutes, value, 32)
	case fullName == "framed-ipv6-route" || fullName == "ipv6:route":
		result.VendorFramedIPv6Routes = appendUniqueVendorString(result.VendorFramedIPv6Routes, value, 32)
	case fullName == "address-pool" || fullName == "framed-pool" || fullName == "ip:addr-pool":
		setStringIfEmpty(&result.VendorIPv4Pool, value)
	case fullName == "nat-pool" || fullName == "translation-public-pool":
		setStringIfEmpty(&result.VendorIPv4Pool, value)
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Pool, value)
	case fullName == "ipv6-pool":
		setStringIfEmpty(&result.VendorIPv6Pool, value)
	case fullName == "delegated-prefix" || fullName == "ipv6:delegated-prefix":
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, value)
	case fullName == "ra-prefix-pool":
		setStringIfEmpty(&result.VendorRAPrefixPool, value)
	case fullName == "translation-policy":
		setStringIfEmpty(&result.VendorTranslationPolicy, value)
	case fullName == "translation-owner":
		setStringIfEmpty(&result.VendorTranslationOwner, value)
	case fullName == "translation-revision":
		setStringIfEmpty(&result.VendorTranslationRevision, value)
	case fullName == "translation-mode" || fullName == "nat-mode":
		setStringIfEmpty(&result.VendorTranslationMode, value)
	case fullName == "translation-public-ipv4" || fullName == "public-ip" || fullName == "nat-ip":
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, value)
	case fullName == "translation-private-ipv4-prefix" || fullName == "private-prefix":
		setStringIfEmpty(&result.VendorTranslationPrivateIPv4Prefix, value)
	case fullName == "translation-subscriber-ipv6-prefix" || fullName == "subscriber-ipv6-prefix":
		setStringIfEmpty(&result.VendorTranslationSubscriberIPv6Prefix, value)
	case fullName == "translation-nat64-prefix" || fullName == "nat64-prefix":
		setStringIfEmpty(&result.VendorTranslationNAT64Prefix, value)
	case fullName == "translation-port-block" || fullName == "port-block":
		applyNokiaALUPortRange(result, value)
	case fullName == "translation-port-block-size" || fullName == "port-block-size":
		applyNokiaALUPortRange(result, value)
	case fullName == "translation-log-profile":
		setStringIfEmpty(&result.VendorTranslationLoggingProfile, value)
	case fullName == "translation-accounting-key":
		setStringIfEmpty(&result.VendorTranslationAccountingKey, value)
	case fullName == "acl" || strings.Contains(fullName, "filter"):
		setStringIfEmpty(&result.VendorInboundACL, value)
	case fullName == "outacl" || strings.Contains(fullName, "egress"):
		setStringIfEmpty(&result.VendorOutboundACL, value)
	case fullName == "role" || fullName == "profile" || fullName == "service-profile" || fullName == "subscriber-profile":
		setStringIfEmpty(&result.VendorRole, value)
	case fullName == "qos" || fullName == "sla-profile" || fullName == "bandwidth-profile":
		setStringIfEmpty(&result.VendorBandwidthProfile, value)
	case fullName == "tenant" || fullName == "location" || fullName == "home-network":
		setStringIfEmpty(&result.VendorTenant, value)
	case fullName == "device-group" || fullName == "nas-port" || fullName == "client":
		setStringIfEmpty(&result.VendorDeviceGroup, value)
	case fullName == "subscriber-id" || fullName == "accounting-identity" || fullName == "charging-profile":
		setStringIfEmpty(&result.VendorAccountingIdentity, value)
	case fullName == "policy" || fullName == "service":
		setStringIfEmpty(&result.VendorPolicyTag, value)
	default:
		return false
	}
	return true
}

func classifyNokiaALURuntime(attribute, tokenName string) (NokiaALUAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute + " " + tokenName))
	switch {
	case containsAnyNokiaALURuntimeToken(name, "password", "auth-key", "auth_key", "keychain", "key-", "nonce", "triplet", "quintet", "aka-rand", "aka-auts", "tunnel-challenge", "femto-public-key-hash"):
		return NokiaALUKindSecret, productconfigs.VendorSemanticCertificateOnboarding, ""
	case containsAnyNokiaALURuntimeToken(name, "outacl", "egress", "output-filter"):
		return NokiaALUKindACL, productconfigs.VendorSemanticDynamicACL, "out"
	case containsAnyNokiaALURuntimeToken(name, "access-rule", "nas-filter", "data-filter", "subscriber-filter", "filter", "acl"):
		return NokiaALUKindACL, productconfigs.VendorSemanticDynamicACL, "in"
	case containsAnyNokiaALURuntimeToken(name, "wlan-ssid-vlan", "vlan"):
		return NokiaALUKindVLAN, productconfigs.VendorSemanticVLAN, ""
	case containsAnyNokiaALURuntimeToken(name, "vrouter", "vrf"):
		return NokiaALUKindVRF, productconfigs.VendorSemanticVRF, ""
	case containsAnyNokiaALURuntimeToken(name, "bgp-policy", "bgp-export-policy", "bgp-import-policy", "route-policy", "framed-route", "framed-ipv6-route", "ip:route", "ipv6:route"):
		return NokiaALUKindRoute, productconfigs.VendorSemanticRoute, ""
	case containsAnyNokiaALURuntimeToken(name, "access-loop-rate-down"):
		return NokiaALUKindQoS, productconfigs.VendorSemanticDownloadBandwidth, ""
	case containsAnyNokiaALURuntimeToken(name, "access-loop-rate-up"):
		return NokiaALUKindQoS, productconfigs.VendorSemanticUploadBandwidth, ""
	case containsAnyNokiaALURuntimeToken(name, "qos", "sla-prof", "traffic-profile", "td-profile", "tos", "subscriber-qos", "qoa"):
		return NokiaALUKindQoS, productconfigs.VendorSemanticBandwidthProfile, ""
	case containsAnyNokiaALURuntimeToken(name, "nat64-prefix"):
		return NokiaALUKindNAT64Prefix, productconfigs.VendorSemanticNAT64Prefix, ""
	case containsAnyNokiaALURuntimeToken(name, "nat-port-range", "translation-port-block", "port-block", "port-range"):
		return NokiaALUKindTranslationPortBlock, productconfigs.VendorSemanticTranslationPortBlock, ""
	case containsAnyNokiaALURuntimeToken(name, "nat-outside-ip", "public-ip", "translation-public-ipv4", "nat-ip"):
		return NokiaALUKindTranslationPublicIPv4, productconfigs.VendorSemanticTranslationPublicIPv4, ""
	case containsAnyNokiaALURuntimeToken(name, "dnat", "nat-outside-serv", "nat-policy", "translation-policy", "translation-mode"):
		return NokiaALUKindTranslation, productconfigs.VendorSemanticTranslationPolicy, ""
	case containsAnyNokiaALURuntimeToken(name, "delegated-ipv6-pool", "delegated-prefix", "ipv6:delegated-prefix"):
		return NokiaALUKindDelegatedIPv6Pool, productconfigs.VendorSemanticDelegatedIPv6Prefix, ""
	case containsAnyNokiaALURuntimeToken(name, "slaac-ipv6-pool", "ra-prefix-pool"):
		return NokiaALUKindRAPrefixPool, productconfigs.VendorSemanticRouterAdvertisement, ""
	case containsAnyNokiaALURuntimeToken(name, "ipv6-address", "ipv6-primary-dns", "ipv6-secondary-dns", "dhcp6", "to-client-dhcp6", "to-server-dhcp6", "preferred-lifetime", "valid-lifetime"):
		return NokiaALUKindIPv6Address, productconfigs.VendorSemanticIPv6Address, ""
	case containsAnyNokiaALURuntimeToken(name, "primary-dns", "secondary-dns", "default-router", "nas-ip-address", "ppp-address", "client-primary-dns", "client-secondary-dns", "address-"):
		return NokiaALUKindIPv4Address, productconfigs.VendorSemanticIPv4Address, ""
	case containsAnyNokiaALURuntimeToken(name, "pool-definition", "assign-ip-pool", "address-pool", "framed-pool", "ip:addr-pool", "pool"):
		return NokiaALUKindAddressPool, productconfigs.VendorSemanticAddressPool, ""
	case containsAnyNokiaALURuntimeToken(name, "portal", "redirect", "http"):
		return NokiaALUKindPortal, productconfigs.VendorSemanticPortalProfile, ""
	case containsAnyNokiaALURuntimeToken(name, "force-renew", "force-nak", "remove-override", "trigger-acct-interim"):
		return NokiaALUKindSessionAction, productconfigs.VendorSemanticCoAReauth, ""
	case containsAnyNokiaALURuntimeToken(name, "acct", "account", "octets", "pkts", "packets", "statmode", "interim", "delta-session", "charging", "credit-control", "ocs-id"):
		return NokiaALUKindAccounting, productconfigs.VendorSemanticAccountingCounters, ""
	case containsAnyNokiaALURuntimeToken(name, "subsc-id", "subscriber-id", "service-id", "service-username", "service-name", "session-access-method", "session-charging-type", "sap-session", "pppoe", "dhcp", "ancp", "lease", "dsl", "xdsl", "apn", "msisdn"):
		return NokiaALUKindAccounting, productconfigs.VendorSemanticAccountingIdentity, ""
	case containsAnyNokiaALURuntimeToken(name, "home-network", "tenant", "location", "civic", "geospatial", "domain"):
		return NokiaALUKindTenant, productconfigs.VendorSemanticTenant, ""
	case containsAnyNokiaALURuntimeToken(name, "client", "hardware", "mac", "nas-port", "program", "version", "interface", "transport", "maintenance", "provisioning", "modem", "slot", "shelf"):
		return NokiaALUKindDevice, productconfigs.VendorSemanticDeviceGroup, ""
	case containsAnyNokiaALURuntimeToken(name, "ipsec", "li-", "lawful", "security", "tl1", "source-ip-check", "auth-type", "require-auth", "trec"):
		return NokiaALUKindPosture, productconfigs.VendorSemanticDevicePosture, ""
	case containsAnyNokiaALURuntimeToken(name, "voice", "called-station"):
		return NokiaALUKindPolicyTag, productconfigs.VendorSemanticPolicyTag, ""
	case containsAnyNokiaALURuntimeToken(name, "subsc-prof", "service-profile", "authentication-policy", "app-prof", "msap-policy", "upnp-sub-override-policy", "timetra-profile", "user-profile"):
		return NokiaALUKindRole, productconfigs.VendorSemanticRole, ""
	case containsAnyNokiaALURuntimeToken(name, "av-pair", "avpair", "policy", "service"):
		return NokiaALUKindPolicyTag, productconfigs.VendorSemanticPolicyTag, ""
	default:
		return NokiaALUKindUnknown, productconfigs.VendorSemanticPolicyTag, ""
	}
}

func applyNokiaALUQoS(result *BrokerAuthResult, token NokiaALUAttribute) {
	value := strings.TrimSpace(token.Value)
	if token.Semantic == productconfigs.VendorSemanticDownloadBandwidth {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && result.WISPrBandwidthMaxDown == 0 {
			result.WISPrBandwidthMaxDown = parsed
			return
		}
	}
	if token.Semantic == productconfigs.VendorSemanticUploadBandwidth {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && result.WISPrBandwidthMaxUp == 0 {
			result.WISPrBandwidthMaxUp = parsed
			return
		}
	}
	setStringIfEmpty(&result.VendorBandwidthProfile, value)
}

func applyNokiaALUVLAN(result *BrokerAuthResult, value string) {
	value = strings.TrimSpace(value)
	if vlan, err := strconv.Atoi(value); err == nil && vlan >= 1 && vlan <= 4094 {
		if !result.HasVendorVLAN {
			result.VendorVLAN = vlan
			result.HasVendorVLAN = true
		}
		return
	}
	setStringIfEmpty(&result.VendorVLANPool, value)
}

func applyNokiaALURoute(result *BrokerAuthResult, token NokiaALUAttribute) {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	switch {
	case strings.Contains(name, "framed-ipv6-route") || strings.Contains(name, "ipv6:route"):
		result.VendorFramedIPv6Routes = appendUniqueVendorString(result.VendorFramedIPv6Routes, value, 32)
	case strings.Contains(name, "framed-route") || strings.Contains(name, "ip:route"):
		result.VendorFramedRoutes = appendUniqueVendorString(result.VendorFramedRoutes, value, 32)
	default:
		setStringIfEmpty(&result.VendorRoutePolicy, value)
	}
}

func applyNokiaALUIPv4(result *BrokerAuthResult, token NokiaALUAttribute) {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	switch {
	case strings.Contains(name, "nat") || strings.Contains(name, "public") || strings.Contains(name, "outside"):
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, value)
	case strings.Contains(name, "ppp-address") || strings.Contains(name, "framed") || strings.Contains(name, "address-"):
		setStringIfEmpty(&result.VendorFramedIPAddress, value)
	case strings.Contains(name, "pool"):
		setStringIfEmpty(&result.VendorIPv4Pool, value)
	default:
		setStringIfEmpty(&result.VendorAccountingIdentity, value)
	}
}

func applyNokiaALUIPv6(result *BrokerAuthResult, token NokiaALUAttribute) {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	switch {
	case strings.Contains(name, "delegated"):
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, value)
	case strings.Contains(name, "pool"):
		setStringIfEmpty(&result.VendorIPv6Pool, value)
	case strings.Contains(name, "prefix"):
		setStringIfEmpty(&result.VendorFramedIPv6Prefix, value)
	default:
		setStringIfEmpty(&result.VendorFramedIPv6Address, value)
	}
}

func applyNokiaALUAddressPool(result *BrokerAuthResult, token NokiaALUAttribute) {
	value := strings.TrimSpace(token.Value)
	name := strings.ToLower(strings.TrimSpace(token.Attribute + " " + token.Name))
	switch {
	case strings.Contains(name, "delegated"):
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, value)
	case strings.Contains(name, "ipv6"):
		setStringIfEmpty(&result.VendorIPv6Pool, value)
	default:
		setStringIfEmpty(&result.VendorIPv4Pool, value)
		if strings.Contains(name, "nat") || strings.Contains(name, "translation") {
			setStringIfEmpty(&result.VendorTranslationPublicIPv4Pool, value)
		}
	}
}

func applyNokiaALUPortRange(result *BrokerAuthResult, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	parts := strings.SplitN(value, "-", 2)
	if len(parts) == 2 {
		if start, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && start > 0 && !result.HasVendorTranslationPortBlockStart {
			result.VendorTranslationPortBlockStart = start
			result.HasVendorTranslationPortBlockStart = true
		}
		if end, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && end > 0 && !result.HasVendorTranslationPortBlockEnd {
			result.VendorTranslationPortBlockEnd = end
			result.HasVendorTranslationPortBlockEnd = true
		}
		return
	}
	if size, err := strconv.Atoi(value); err == nil && size > 0 && !result.HasVendorTranslationPortBlockSize {
		result.VendorTranslationPortBlockSize = size
		result.HasVendorTranslationPortBlockSize = true
	}
}

func normalizeNokiaALUSessionAction(value, attribute, name string) string {
	lower := strings.ToLower(strings.TrimSpace(attribute + " " + name + " " + value))
	switch {
	case strings.Contains(lower, "force-nak"), strings.Contains(lower, "disconnect"):
		return "disconnect:" + strings.TrimSpace(value)
	case strings.Contains(lower, "force-renew"), strings.Contains(lower, "reauth"), strings.Contains(lower, "trigger-acct-interim"):
		return "reauth:" + strings.TrimSpace(value)
	default:
		return strings.TrimSpace(value)
	}
}

func isNokiaALUPackKey(packKey string) bool {
	switch productconfigs.NormalizeVendorCompatibilityPackKey(packKey) {
	case productconfigs.VendorPackNokia, productconfigs.VendorPackAlcatel, productconfigs.VendorPackAlcatelESAM, productconfigs.VendorPackALUSR, productconfigs.VendorPackALUAAA:
		return true
	default:
		return false
	}
}

func isNokiaALUAVPairRuntimeMapping(mapping inboundVendorMapping) bool {
	return isNokiaALUPackKey(mapping.PackKey) && isNokiaALUAVPairAttribute(mapping.Attribute)
}

func isNokiaALUAVPairAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return name == "nokia-avpair" || name == "alu-aaa-av-pair" || strings.Contains(name, "avpair") || strings.Contains(name, "av-pair")
}

func isNokiaALUSecretRuntimeAttribute(attribute string) bool {
	return containsAnyNokiaALURuntimeToken(attribute,
		"password", "auth-key", "auth_key", "keychain", "key-",
		"nonce", "triplet", "quintet", "aka-rand", "aka-auts",
		"tunnel-challenge", "femto-public-key-hash",
	)
}

func containsAnyNokiaALURuntimeToken(value string, tokens ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
