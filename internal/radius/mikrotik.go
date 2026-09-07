package radius

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const MikroTikMaxValueLength = 240

type MikroTikAttributeKind string

const (
	MikroTikKindUnknown       MikroTikAttributeKind = "unknown"
	MikroTikKindRate          MikroTikAttributeKind = "rate_policy"
	MikroTikKindQuota         MikroTikAttributeKind = "quota_policy"
	MikroTikKindRole          MikroTikAttributeKind = "role_profile"
	MikroTikKindACL           MikroTikAttributeKind = "acl_profile"
	MikroTikKindIPv4Address   MikroTikAttributeKind = "ipv4_address"
	MikroTikKindIPv6Pool      MikroTikAttributeKind = "ipv6_delegated_pool"
	MikroTikKindPortal        MikroTikAttributeKind = "portal"
	MikroTikKindGuest         MikroTikAttributeKind = "guest_lifecycle"
	MikroTikKindTenant        MikroTikAttributeKind = "tenant"
	MikroTikKindPolicyTag     MikroTikAttributeKind = "policy_tag"
	MikroTikKindDeviceGroup   MikroTikAttributeKind = "device_group"
	MikroTikKindDevicePosture MikroTikAttributeKind = "device_posture"
	MikroTikKindVLANPolicy    MikroTikAttributeKind = "vlan_policy"
	MikroTikKindSecret        MikroTikAttributeKind = "secret_redaction"
)

type MikroTikAttribute struct {
	Raw       string                `json:"raw"`
	Vendor    string                `json:"vendor"`
	Attribute string                `json:"attribute"`
	Value     string                `json:"value"`
	Kind      MikroTikAttributeKind `json:"kind"`
	Semantic  string                `json:"semantic"`
	Direction string                `json:"direction,omitempty"`
	Redacted  bool                  `json:"redacted"`
}

func NormalizeMikroTikAttribute(vendor, attribute, raw string) (MikroTikAttribute, error) {
	vendor = strings.TrimSpace(vendor)
	attribute = strings.TrimSpace(attribute)
	value := strings.TrimSpace(raw)
	if attribute == "" {
		return MikroTikAttribute{}, fmt.Errorf("MikroTik attribute name is required")
	}
	if value == "" {
		return MikroTikAttribute{}, fmt.Errorf("%s value is empty", attribute)
	}
	if len(value) > MikroTikMaxValueLength {
		return MikroTikAttribute{}, fmt.Errorf("%s exceeds %d bytes", attribute, MikroTikMaxValueLength)
	}
	kind, semantic, direction := classifyMikroTikAttribute(attribute)
	if isMikroTikSensitiveAttribute(attribute) {
		return MikroTikAttribute{
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
		return MikroTikAttribute{}, fmt.Errorf("%s contains control characters", attribute)
	}
	return MikroTikAttribute{
		Raw:       attribute + "=" + value,
		Vendor:    vendor,
		Attribute: attribute,
		Value:     value,
		Kind:      kind,
		Semantic:  semantic,
		Direction: direction,
	}, nil
}

func applyMikroTikAttributeString(result *BrokerAuthResult, vendor, attribute, raw string) bool {
	token, err := NormalizeMikroTikAttribute(vendor, attribute, raw)
	if err != nil {
		return false
	}
	ApplyMikroTikAttributeToBrokerResult(result, token)
	return true
}

func ApplyMikroTikAttributeToBrokerResult(result *BrokerAuthResult, token MikroTikAttribute) {
	if result == nil {
		return
	}
	switch token.Kind {
	case MikroTikKindSecret:
		appendUniqueVendorAVPair(result, token.Raw)
	case MikroTikKindRate:
		setStringIfEmpty(&result.MikrotikRateLimit, token.Value)
		setStringIfEmpty(&result.VendorBandwidthProfile, token.Value)
		if intent, err := DecompileMikroTikRateLimit(token.Value); err == nil {
			if result.WISPrBandwidthMaxDown == 0 {
				result.WISPrBandwidthMaxDown = intent.DownloadRateKbps
			}
			if result.WISPrBandwidthMaxUp == 0 {
				result.WISPrBandwidthMaxUp = intent.UploadRateKbps
			}
		}
	case MikroTikKindQuota:
		applyMikroTikQuota(result, token.Attribute, token.Value)
	case MikroTikKindRole:
		setStringIfEmpty(&result.VendorRole, token.Value)
	case MikroTikKindACL:
		applyMikroTikACL(result, token.Attribute, token.Value)
	case MikroTikKindIPv4Address:
		applyMikroTikIPv4(result, token.Value)
	case MikroTikKindIPv6Pool:
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, token.Value)
	case MikroTikKindPortal:
		setStringIfEmpty(&result.VendorPortalProfile, token.Value)
	case MikroTikKindGuest:
		appendUniqueVendorAVPair(result, "Mikrotik-Advertise-Interval="+token.Value)
	case MikroTikKindTenant:
		setStringIfEmpty(&result.VendorTenant, token.Value)
	case MikroTikKindPolicyTag:
		applyMikroTikPolicyTag(result, token.Attribute, token.Value)
	case MikroTikKindDeviceGroup:
		setStringIfEmpty(&result.VendorDeviceGroup, token.Value)
	case MikroTikKindDevicePosture:
		posture := normalizeMikroTikDevicePosture(token.Attribute, token.Value)
		setStringIfEmpty(&result.VendorDevicePosture, posture)
		appendUniqueVendorAVPair(result, posture)
	case MikroTikKindVLANPolicy:
		policy := normalizeMikroTikVLANPolicy(token.Value)
		setStringIfEmpty(&result.VendorVLANPolicy, policy)
		appendUniqueVendorAVPair(result, policy)
	default:
		appendUniqueVendorAVPair(result, token.Raw)
	}
}

func classifyMikroTikAttribute(attribute string) (MikroTikAttributeKind, string, string) {
	name := strings.ToLower(strings.TrimSpace(attribute))
	switch {
	case isMikroTikSensitiveAttribute(attribute):
		return MikroTikKindSecret, productconfigs.VendorSemanticCertificateOnboarding, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Rate-Limit"):
		return MikroTikKindRate, productconfigs.VendorSemanticBandwidthProfile, "inbound"
	case strings.Contains(name, "recv-limit") || strings.Contains(name, "xmit-limit") || strings.Contains(name, "total-limit"):
		return MikroTikKindQuota, productconfigs.VendorSemanticDataQuota, "accounting"
	case strings.EqualFold(attribute, "Mikrotik-Group"):
		return MikroTikKindRole, productconfigs.VendorSemanticRole, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Address-List") || strings.EqualFold(attribute, "Mikrotik-Switching-Filter"):
		return MikroTikKindACL, productconfigs.VendorSemanticDynamicACL, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Host-IP"):
		return MikroTikKindIPv4Address, productconfigs.VendorSemanticIPv4Address, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Delegated-IPv6-Pool"):
		return MikroTikKindIPv6Pool, productconfigs.VendorSemanticDelegatedIPv6Prefix, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Advertise-URL"):
		return MikroTikKindPortal, productconfigs.VendorSemanticPortalProfile, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Advertise-Interval"):
		return MikroTikKindGuest, productconfigs.VendorSemanticGuestLifecycle, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Realm"):
		return MikroTikKindTenant, productconfigs.VendorSemanticTenant, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Comment"):
		return MikroTikKindDeviceGroup, productconfigs.VendorSemanticDeviceGroup, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Wireless-VLANIDtype") || strings.EqualFold(attribute, "Mikrotik-Wireless-VLANID-Type"):
		return MikroTikKindVLANPolicy, productconfigs.VendorSemanticVLAN, "inbound"
	case strings.EqualFold(attribute, "Mikrotik-Mark-Id") || strings.HasPrefix(name, "mikrotik-dhcp-option"):
		return MikroTikKindPolicyTag, productconfigs.VendorSemanticPolicyTag, "inbound"
	case strings.HasPrefix(name, "mikrotik-wireless-"):
		return MikroTikKindDevicePosture, productconfigs.VendorSemanticDevicePosture, "inbound"
	default:
		return MikroTikKindUnknown, productconfigs.VendorSemanticPolicyTag, "inbound"
	}
}

func applyMikroTikQuota(result *BrokerAuthResult, attribute, value string) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || parsed == 0 {
		appendUniqueVendorAVPair(result, strings.TrimSpace(attribute)+"="+strings.TrimSpace(value))
		return
	}
	name := strings.ToLower(strings.TrimSpace(attribute))
	switch {
	case strings.EqualFold(attribute, "Mikrotik-Total-Limit"):
		result.VendorMaxTotalOctets += parsed
		result.HasVendorMaxTotalOctets = true
	case strings.EqualFold(attribute, "Mikrotik-Total-Limit-Gigawords"):
		result.VendorMaxTotalOctets += parsed << 32
		result.HasVendorMaxTotalOctets = true
	case strings.Contains(name, "recv-limit") || strings.Contains(name, "xmit-limit"):
		appendUniqueVendorAVPair(result, strings.TrimSpace(attribute)+"="+strconv.FormatUint(parsed, 10))
	default:
		appendUniqueVendorAVPair(result, strings.TrimSpace(attribute)+"="+strconv.FormatUint(parsed, 10))
	}
}

func applyMikroTikACL(result *BrokerAuthResult, attribute, value string) {
	switch {
	case strings.EqualFold(attribute, "Mikrotik-Switching-Filter"):
		setStringIfEmpty(&result.VendorOutboundACL, value)
	default:
		setStringIfEmpty(&result.VendorInboundACL, value)
	}
}

func applyMikroTikIPv4(result *BrokerAuthResult, value string) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.To4() == nil {
		appendUniqueVendorAVPair(result, "Mikrotik-Host-IP="+strings.TrimSpace(value))
		return
	}
	setStringIfEmpty(&result.VendorFramedIPAddress, ip.To4().String())
}

func applyMikroTikPolicyTag(result *BrokerAuthResult, attribute, value string) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(attribute)), "mikrotik-dhcp-option") {
		if strings.EqualFold(attribute, "Mikrotik-DHCP-Option-Set") {
			setStringIfEmpty(&result.VendorPolicyTag, value)
		}
		appendUniqueVendorAVPair(result, strings.TrimSpace(attribute)+"="+strings.TrimSpace(value))
		return
	}
	setStringIfEmpty(&result.VendorPolicyTag, value)
}

func normalizeMikroTikDevicePosture(attribute, value string) string {
	attribute = strings.TrimSpace(attribute)
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Forward"):
		return "wireless-forward=" + mikroTikBoolLabel(value)
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Skip-Dot1x"):
		return "wireless-skip-dot1x=" + mikroTikBoolLabel(value)
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Enc-Algo"):
		return "wireless-enc-algo=" + value
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Minsignal"):
		return "wireless-minsignal=" + value
	case strings.EqualFold(attribute, "Mikrotik-Wireless-Maxsignal"):
		return "wireless-maxsignal=" + value
	default:
		return attribute + "=" + value
	}
}

func normalizeMikroTikVLANPolicy(value string) string {
	switch strings.TrimSpace(value) {
	case "0":
		return "routeros-vlan-id-type=use-service-tag"
	case "1":
		return "routeros-vlan-id-type=use-customer-tag"
	default:
		return "routeros-vlan-id-type=" + strings.TrimSpace(value)
	}
}

func mikroTikBoolLabel(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "1", "true", "yes", "on":
		return "enabled"
	case "0", "false", "no", "off":
		return "disabled"
	default:
		return strings.TrimSpace(value)
	}
}

func isMikroTikPackKey(packKey string) bool {
	return productconfigs.NormalizeVendorCompatibilityPackKey(packKey) == productconfigs.VendorPackMikroTik
}

func isMikroTikSensitiveAttribute(attribute string) bool {
	return strings.EqualFold(attribute, "Mikrotik-Wireless-Enc-Key") ||
		strings.EqualFold(attribute, "Mikrotik-Wireless-PSK") ||
		strings.EqualFold(attribute, "Mikrotik-Wireless-MPKey")
}
