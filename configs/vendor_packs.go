package configs

import "strings"

const (
	VendorPackStandard    = "standard"
	VendorPackAegisNAS    = "aegisnas"
	VendorPackMikroTik    = "mikrotik"
	VendorPackWISPr       = "wispr"
	VendorPackCisco       = "cisco"
	VendorPackAruba       = "aruba"
	VendorPackRuckus      = "ruckus"
	VendorPackFoundry     = "foundry"
	VendorPackFortinet    = "fortinet"
	VendorPackUBNT        = "ubnt"
	VendorPackCambium     = "cambium"
	VendorPackMeraki      = "meraki"
	VendorPackExtreme     = "extreme"
	VendorPackJuniper     = "juniper"
	VendorPackERX         = "erx"
	VendorPackHuawei      = "huawei"
	VendorPackH3C         = "h3c"
	VendorPackPaloAlto    = "paloalto"
	VendorPackTPLink      = "tplink"
	VendorPackAerohive    = "aerohive"
	VendorPackAirespace   = "airespace"
	VendorPackHP          = "hp"
	VendorPackNomadix     = "nomadix"
	VendorPackChilliSpot  = "chillispot"
	VendorPackDLink       = "dlink"
	VendorPackSonicWall   = "sonicwall"
	VendorPackArista      = "arista"
	VendorPackPica8       = "pica8"
	VendorPackZTE         = "zte"
	VendorPackNokia       = "nokia"
	VendorPackAlcatel     = "alcatel"
	VendorPackAlcatelESAM = "alcatel-esam"
	VendorPackALUSR       = "alu-sr"
	VendorPackALUAAA      = "alu-aaa"
	VendorPackStarent     = "starent"
	VendorPackMeru        = "meru"
	VendorPackColubris    = "colubris"
	VendorPackOpenWiFi    = "openwifi"
	VendorPackMist        = "mist"
)

type VendorCompatibilityPack struct {
	Key              string                       `json:"key"`
	Label            string                       `json:"label"`
	VendorName       string                       `json:"vendor_name,omitempty"`
	VendorID         int                          `json:"vendor_id,omitempty"`
	DefaultEnabled   bool                         `json:"default_enabled"`
	HardwareProfiles []string                     `json:"hardware_profiles"`
	Attributes       []VendorPackAttributeMapping `json:"attributes"`
	FeatureTemplates []VendorPackFeatureTemplate  `json:"feature_templates,omitempty"`
	Notes            []string                     `json:"notes,omitempty"`
}

type VendorPackAttributeMapping struct {
	Semantic           string `json:"semantic"`
	Attribute          string `json:"attribute"`
	Direction          string `json:"direction"`
	ValueType          string `json:"value_type"`
	CompatibilityState string `json:"compatibility_state"`
}

type VendorPackFeatureTemplate struct {
	Feature            string   `json:"feature"`
	Direction          string   `json:"direction"`
	ValueType          string   `json:"value_type"`
	CompatibilityState string   `json:"compatibility_state"`
	Attributes         []string `json:"attributes"`
}

func DefaultVendorCompatibilityPackKeys() []string {
	return []string{VendorPackStandard, VendorPackMikroTik, VendorPackWISPr}
}

func AegisNASVendorCompatibilityPacks() []VendorCompatibilityPack {
	allProfiles := []string{"lite", "branch", "enterprise", "custom"}
	branchEnterprise := []string{"branch", "enterprise", "custom"}
	enterprise := []string{"enterprise", "custom"}
	productIdentity := AegisNASVendorIdentity()

	return withVendorPackFeatureTemplates([]VendorCompatibilityPack{
		{
			Key:              VendorPackStandard,
			Label:            "Standards-Based RADIUS",
			DefaultEnabled:   true,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Filter-Id", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Tunnel-Type", Direction: "outbound_reply", ValueType: "enum", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Tunnel-Medium-Type", Direction: "outbound_reply", ValueType: "enum", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Tunnel-Private-Group-Id", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Egress-VLANID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionTimeout, Attribute: "Session-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIdleTimeout, Attribute: "Idle-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "NAS-Filter-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Framed-Route", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Framed-IPv6-Route", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Framed-IP-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Framed-IP-Netmask", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Framed-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "Framed-IPv6-Address", Direction: "outbound_reply", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "Framed-IPv6-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Framed-IPv6-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Delegated-IPv6-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackAegisNAS,
			Label:            "AegisNAS Product VSA",
			VendorName:       productIdentity.Name,
			VendorID:         productIdentity.ID,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "AegisNAS-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "AegisNAS-Bandwidth-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticQuarantine, Attribute: "AegisNAS-Quarantine", Direction: "outbound_reply", ValueType: "boolean", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "AegisNAS-Policy-Tag", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionTimeout, Attribute: "AegisNAS-Session-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIdleTimeout, Attribute: "AegisNAS-Idle-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "AegisNAS-Portal-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "AegisNAS-Device-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "AegisNAS-Tenant", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "AegisNAS-ACL-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "AegisNAS-ACL-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-Data-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-Voice-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-Tagged-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-QinQ-Outer-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-QinQ-Inner-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-VLAN-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-Fallback-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-Auth-Fail-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "AegisNAS-VLAN-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "AegisNAS-Route-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "AegisNAS-VRF", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "AegisNAS-Route-Owner", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "AegisNAS-Route-Revision", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "AegisNAS-Framed-Route", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "AegisNAS-Framed-IPv6-Route", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-Address-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-Address-Owner", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-Address-Revision", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-IPv4-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-IPv6-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "AegisNAS-Delegated-IPv6-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRouterAdvertisement, Attribute: "AegisNAS-RA-Prefix-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "AegisNAS-Framed-IP-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "AegisNAS-Framed-IPv6-Address", Direction: "outbound_reply", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "AegisNAS-Framed-IPv6-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "AegisNAS-Delegated-IPv6-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRouterAdvertisement, Attribute: "AegisNAS-RA-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDHCPv6, Attribute: "AegisNAS-DHCPv6-Mode", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRouterAdvertisement, Attribute: "AegisNAS-RA-Mode", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Owner", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Revision", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Mode", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "AegisNAS-Translation-Public-IPv4-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "AegisNAS-Translation-Public-IPv4-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Private-IPv4-Prefix", Direction: "outbound_reply", ValueType: "ipv4prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "AegisNAS-Translation-Subscriber-IPv6-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "AegisNAS-Translation-NAT64-Prefix", Direction: "outbound_reply", ValueType: "ipv6prefix", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "AegisNAS-Translation-Port-Block-Start", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "AegisNAS-Translation-Port-Block-End", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "AegisNAS-Translation-Port-Block-Size", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationLogging, Attribute: "AegisNAS-Translation-Logging-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationLogging, Attribute: "AegisNAS-Translation-Accounting-Key", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: productIdentity.Warnings,
		},
		{
			Key:              VendorPackMikroTik,
			Label:            "MikroTik RouterOS",
			VendorName:       "Mikrotik",
			VendorID:         14988,
			DefaultEnabled:   true,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Recv-Limit", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Xmit-Limit", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Mikrotik-Group", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Forward", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Skip-Dot1x", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Enc-Algo", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Mikrotik-Wireless-Enc-Key", Direction: "inbound,outbound_reply", ValueType: "secret", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Mikrotik-Rate-Limit", Direction: "inbound,outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Mikrotik-Realm", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Mikrotik-Host-IP", Direction: "inbound,outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mikrotik-Mark-Id", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Mikrotik-Advertise-URL", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticGuestLifecycle, Attribute: "Mikrotik-Advertise-Interval", Direction: "inbound,outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Recv-Limit-Gigawords", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Xmit-Limit-Gigawords", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Mikrotik-Wireless-PSK", Direction: "inbound,outbound_reply", ValueType: "secret", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Total-Limit", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Mikrotik-Total-Limit-Gigawords", Direction: "inbound,outbound_reply,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Mikrotik-Address-List", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Mikrotik-Wireless-MPKey", Direction: "inbound,outbound_reply", ValueType: "secret", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Comment", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Mikrotik-Delegated-IPv6-Pool", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mikrotik-DHCP-Option-Set", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mikrotik-DHCP-Option-Param-STR1", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mikrotik-DHCP-Option-ParamSTR2", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mikrotik-DHCP-Option-Param-STR2", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Mikrotik-Wireless-VLANID", Direction: "inbound,outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Mikrotik-Wireless-VLANIDtype", Direction: "inbound,outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Mikrotik-Wireless-VLANID-Type", Direction: "inbound,outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Minsignal", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Mikrotik-Wireless-Maxsignal", Direction: "inbound,outbound_reply,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Mikrotik-Switching-Filter", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0070 software-certifies every pinned MikroTik dictionary row as native semantic mapping, ACL profile reference, typed evidence, or redacted wireless secret evidence; RouterOS/CAPsMAN device behavior remains release-certified externally."},
		},
		{
			Key:              VendorPackWISPr,
			Label:            "WISPr Bandwidth Hints",
			VendorName:       "WISPr",
			VendorID:         14122,
			DefaultEnabled:   true,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "WISPr-Bandwidth-Max-Down", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "WISPr-Bandwidth-Max-Up", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackCisco,
			Label:            "Cisco",
			VendorName:       "Cisco",
			VendorID:         9,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticACL, Attribute: "Cisco-In-ACL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Cisco-Out-ACL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDHCPv6, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRouterAdvertisement, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
			},
			Notes: []string{"Cisco dynamic ACL rendering emits one Cisco-AVPair per ACL rule using ip:inacl/ip:outacl numbering."},
		},
		{
			Key:              VendorPackAruba,
			Label:            "Aruba",
			VendorName:       "Aruba",
			VendorID:         14823,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Aruba-User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Aruba-CPPM-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Aruba-Admin-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Aruba-User-Vlan", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Aruba-Named-User-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Aruba-NAS-Filter-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Aruba-ACL-Server-Query-Info", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Aruba-Captive-Portal-URL", Direction: "outbound_reply", ValueType: "url", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Aruba-AP-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Aruba-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Aruba-Device-Type", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Aruba-Mdps-Device-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Aruba-Mdps-Device-Profile", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Aruba-AirGroup-Shared-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Aruba-MPSK-Key-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Aruba-DPP-Service-Type", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Aruba-UBT-Gateway-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Aruba-Gateway-Zone", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Aruba-QoS-Trust-Mode", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Aruba-PoE-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCoAReauth, Attribute: "Aruba-Port-Bounce-Host", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Secret-bearing Aruba MPSK and DPP values are redacted in software evidence; real key onboarding remains release certification."},
		},
		{
			Key:              VendorPackRuckus,
			Label:            "Ruckus SmartZone / ZoneDirector",
			VendorName:       "Ruckus",
			VendorID:         25053,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Ruckus-User-Groups", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Ruckus-VLAN-ID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-SSID", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-Wlan-Id", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Ruckus-Location", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionTimeout, Attribute: "Ruckus-Grace-Period", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionTimeout, Attribute: "Ruckus-Sta-Expiration", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Ruckus-FlexAuth-AVP", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Ruckus-IMSI", Direction: "accounting", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Ruckus-APN-NI", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Ruckus-QoS", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Ruckus-Gn-User-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Ruckus-Policy-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Ruckus-Client-Local-IP", Direction: "accounting", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Ruckus-Wispr-Redirect-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-Zone-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-Wlan-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Ruckus-Client-Host-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Ruckus-Client-Os-Type", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Ruckus-Client-Os-Class", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Ruckus-Vlan-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Ruckus-DPSK", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticGuestLifecycle, Attribute: "Ruckus-CP-Token", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Ruckus-Max-DL-UL-Quota", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Ruckus-Traffic-Class-Attribute-Ids", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Ruckus-Nat-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Ruckus-TC-Acct-Ctrs", Direction: "accounting", ValueType: "tlv", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-Cluster-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Ruckus-Domain-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Ruckus-Client-Device-Type", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Ruckus-Vlan-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Ruckus-SCI-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Ruckus-SCI-Resource-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"Ruckus DPSK, mobile-core identifiers, and TLV counter families are software-certified as typed evidence with redaction where needed; real SmartZone, ZoneDirector, Unleashed, and Ruckus One behavior remains release certification."},
		},
		{
			Key:              VendorPackFoundry,
			Label:            "Ruckus ICX / Foundry",
			VendorName:       "Foundry",
			VendorID:         1991,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Foundry-Privilege-Level", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-Command-String", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-Command-Exception-Flag", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-INM-Privilege", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Foundry-Access-List", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Foundry-MAC-Authent-needs-802.1x", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Foundry-802.1x-Valid-Lookup", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Foundry-MAC-Based-Vlan-QoS", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-INM-Role-Aor-List", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCoAReauth, Attribute: "Foundry-COA-Command", Direction: "coa", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-SI-Context-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Foundry-SI-Role-Template", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Foundry-Voice-Phone-Config", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"Foundry dictionary rows represent the ICX switch policy surface. Duplicate VSA numbers are treated as multi-semantic wire interpretations and require model/firmware release evidence."},
		},
		{
			Key:              VendorPackFortinet,
			Label:            "Fortinet",
			VendorName:       "Fortinet",
			VendorID:         12356,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Fortinet-Group-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Fortinet-Client-IP-Address", Direction: "accounting", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Fortinet-Vdom-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Fortinet-Vdom-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "Fortinet-Client-IPv6-Address", Direction: "accounting", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Fortinet-Interface-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Access-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Fortinet-SSID", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Fortinet-AP-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Fortinet-FAC-Auth-Status", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Fortinet-FAC-Token-ID", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Fortinet-FAC-Challenge-Code", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Webfilter-Category-Allow", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Webfilter-Category-Block", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Webfilter-Category-Monitor", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-AppCtrl-Category-Allow", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-AppCtrl-Category-Block", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Fortinet-AppCtrl-Risk-Allow", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Fortinet-AppCtrl-Risk-Block", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Fortinet-WirelessController-Device-MAC", Direction: "accounting", ValueType: "ether", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Fortinet-WirelessController-WTP-ID", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Fortinet-WirelessController-Assoc-Time", Direction: "accounting", ValueType: "date", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Fortinet-FortiWAN-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Fortinet-FortiWAN-AVPair", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-FortiWAN-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-FDD-Access-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Fortinet-FDD-Trusted-Hosts", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-FDD-SPP-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Fortinet-FDD-Is-System-Admin", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Fortinet-FDD-Is-SPP-Admin", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-FDD-SPP-Policy-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-FDD-Allow-API-Access", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Fortinet-Fpc-User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Fortinet-Tenant-Identification", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Fortinet-Host-Port-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Host-Port-AVPair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
			},
			Notes: []string{"Fortinet security pack covers FortiGate/FortiWiFi, FortiAuthenticator, FortiNAC, FortiAP/FortiSwitch controller context, FortiDeceptor FDD, and FortiWAN typed RADIUS evidence. Hardware behavior remains release certification."},
		},
		{
			Key:              VendorPackUBNT,
			Label:            "Ubiquiti / UniFi",
			VendorName:       "UBNT",
			VendorID:         41112,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "UBNT-Data-Rate-DL", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "UBNT-Data-Rate-DL", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "UBNT-Data-Rate-UL", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "UBNT-Data-Rate-UL", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
			},
			Notes: []string{"UniFi/UBNT rate attributes are parsed and rendered from AegisNAS kbps values as bits per second. FreeRADIUS 3.2.8 does not include a Ubiquiti namespace, so these rows remain AegisNAS runtime compatibility extensions until NAS-0073 external dictionary intake is complete."},
		},
		{
			Key:              VendorPackCambium,
			Label:            "Cambium",
			VendorName:       "Cambium",
			VendorID:         17713,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Cambium-Acct-Class-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-Data-VLAN-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-Management-VLAN-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Cambium-ePMP-Max-Burst-Uplink-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Cambium-ePMP-Max-Burst-Downlink-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Cambium-Auth-Role", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Cambium-ePMP-UserLevel", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Cambium-ePMP-SM-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-VLAN-Membersip-Set", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Cambium-ePMP-Management-VLAN-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Cambium-ePMP-Data-VLAN-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-Separate-Management-VLAN-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Cambium-ePMP-Separate-Management-VLAN-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-Multicast-VLAN-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-VLAN-Mapping", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Input-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Input-Packets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Output-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Output-Packets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Authorize-Bytes-Left", Direction: "inbound", ValueType: "integer64", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Cambium-Authorize-Class-Name", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Authorize-Classes", Direction: "inbound", ValueType: "tlv", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Up", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Down", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Up-Gigwords", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Down-Gigwords", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Total", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "Cambium-Traffic-Quota-Limit-Total-Gigwords", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-VLAN-Pool-Id", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Traffic-Classes-Acct", Direction: "accounting", ValueType: "tlv", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticQuarantine, Attribute: "Cambium-Walled-Garden-State", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Cambium role/user-level replies are numeric and need a site role-to-number template before automatic rendering. cnMaestro, ePMP/PMP, traffic-class TLV, and hardware CoA behavior remains release-certified externally."},
		},
		{
			Key:              VendorPackMeraki,
			Label:            "Cisco Meraki",
			VendorName:       "Meraki",
			VendorID:         29671,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Meraki-Device-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Meraki-Network-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Meraki-Ap-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Meraki-Ap-Tags", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticControllerPolicySync, Attribute: "controller.policy_sync", Direction: "controller_api", ValueType: "sync", CompatibilityState: "implemented"},
			},
			Notes: []string{"Meraki's FreeRADIUS dictionary is mostly contextual/accounting; standards-based replies remain the RADIUS enforcement path, while the native Dashboard API adapter reconciles existing wireless SSID slots by exact name."},
		},
		{
			Key:              VendorPackExtreme,
			Label:            "Extreme Networks",
			VendorName:       "Extreme",
			VendorID:         1916,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Extreme-CLI-Authorization", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Extreme-Shell-Command", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Extreme-Security-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan-Tag", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Extreme-Netlogin-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Extreme-Netlogin-Url-Desc", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Extended-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Extreme-User-Location", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Extreme-VM-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Extreme-VM-VPP-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Extreme-VM-IP-Addr", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-VM-VLAN-ID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Extreme-VM-VR-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"Extreme extended VLAN output validates untagged and tagged VLAN grammar before rendering; VM and VR context values are software-visible and externally certified by platform firmware."},
		},
		{
			Key:              VendorPackJuniper,
			Label:            "Juniper",
			VendorName:       "Juniper",
			VendorID:         2636,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Juniper-Local-User-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Juniper-Allow-Commands", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Juniper-Deny-Commands", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Juniper-User-Permissions", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Juniper-Firewall-filter-name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Juniper-Switching-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Juniper-VoIP-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Juniper-CWA-Redirect", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Juniper-CoS-Traffic-Control-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Juniper-Policer-Parameter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Juniper-Ip-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Juniper-Acct-Request-Reason", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Juniper-AV-Pair templates preserve unknown values as bounded evidence and promote known firewall, route, VRF, pool, translation, and service tokens into neutral policy fields."},
		},
		{
			Key:              VendorPackERX,
			Label:            "Juniper ERX / E-Series",
			VendorName:       "ERX",
			VendorID:         4874,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticAddressPool, Attribute: "ERX-Address-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "ERX-Address-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "ERX-Virtual-Router-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "ERX-Redirect-VR-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "ERX-Qos-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "ERX-Pppoe-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "ERX-Service-Bundle", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionAction, Attribute: "ERX-Service-Activate", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionAction, Attribute: "ERX-Service-Deactivate", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionTimeout, Attribute: "ERX-Service-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "ERX-Client-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "ERX-APN-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "ERX-Cos-Shaping-Rate", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "ERX-Input-Interface-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "ERX-Output-Interface-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "ERX-IPv6-Delegated-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "ERX-Adv-Pcef-Rule-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCoAReauth, Attribute: "ERX-Bulk-CoA-Transaction-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCoAReauth, Attribute: "ERX-Bulk-CoA-Identifier", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"ERX dictionaries expose broadband subscriber, BNG routing, QoS, service activation, and bulk CoA fields; software normalizes safe intent and stores bounded evidence, while line-card behavior remains release certification."},
		},
		{
			Key:              VendorPackHuawei,
			Label:            "Huawei",
			VendorName:       "Huawei",
			VendorID:         2011,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Huawei-User-Class", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-User-Class", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Exec-Privilege", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Command", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Command-Mode", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Access-Service", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Service-Scheme", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Huawei-Service-Info", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Qos-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Qos-Profile-Name", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Down-QOS-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Queue-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Huawei-Output-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Huawei-Output-Average-Rate", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Huawei-Output-Peak-Information-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Huawei-Input-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Huawei-Input-Average-Rate", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Huawei-Input-Peak-Information-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Huawei-Data-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Huawei-Data-Filter", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Huawei-Redirect-ACL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Huawei-HTTP-Redirect-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Huawei-PortalURL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Huawei-Web-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Huawei-AVpair", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Huawei-Framed-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Huawei-Framed-Pool-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "Huawei-Framed-IPv6-Address", Direction: "outbound_reply", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Huawei-Delegated-IPv6-Prefix-Pool", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Huawei-NAT-Public-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "Huawei-NAT-Policy-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Huawei-NAT-Port-Forwarding", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Huawei-NAT-Start-Port", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Huawei-NAT-End-Port", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Huawei-NAT-Port-Range-Update", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Huawei-VPN-Instance", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Huawei-Domain-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Huawei-Acct-IPv6-Input-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Huawei-Acct-IPv6-Input-Gigawords", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Huawei-Tariff-Input-Octets", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Huawei-Multicast-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Huawei-AP-Information", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Huawei-User-Password", Direction: "inbound", ValueType: "redacted", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Huawei-DPSK-Info", Direction: "inbound", ValueType: "redacted", CompatibilityState: "implemented"},
			},
			Notes: []string{"Huawei rate attributes are rendered from AegisNAS kbps values; validate unit expectations on the target controller, switch, BRAS, or BNG before publishing hardware-certified claims.", "NAS-0068 software-certifies every pinned Huawei dictionary row as native semantic mapping, typed pass-through evidence, or redacted authentication evidence."},
		},
		{
			Key:              VendorPackH3C,
			Label:            "H3C / Comware",
			VendorName:       "H3C",
			VendorID:         25506,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "H3C-User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "H3C-User-Role", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "H3C-Exec-Privilege", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "H3C-Command", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "H3C-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "H3C-User-Group", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "H3C-Output-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "H3C-Output-Average-Rate", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "H3C-Output-Peak-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "H3C-Input-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "H3C-Input-Average-Rate", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "H3C-Input-Peak-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "H3C-Up-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "H3C-Down-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "H3C-Ita-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "H3C-Portal-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "H3C-WEB-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "H3C-Av-Pair", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "H3C-NAT-IP-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "H3C-NAT-IP-Address", Direction: "inbound", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "H3C-NAT-Start-Port", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "H3C-NAT-End-Port", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "H3C-VPN-Instance", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "H3C-Client-Primary-DNS", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "H3C-Subscriber-ID", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "H3C-Subscriber-Profile", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "H3C-IPv4-Multicast-Receive-Group", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "H3C-IPv6-Multicast-Receive-Group", Direction: "outbound_reply", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "H3C-Acct-IPv6-Input-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "H3C-Backup-NAS-IP", Direction: "accounting", ValueType: "ipaddr", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0068 software-certifies every pinned H3C/Comware row as native semantic mapping or typed evidence; real Comware, iMC, BRAS, and BNG behavior remains release-certified externally."},
		},
		{
			Key:              VendorPackPaloAlto,
			Label:            "Palo Alto Networks",
			VendorName:       "PaloAlto",
			VendorID:         25461,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "PaloAlto-Admin-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "PaloAlto-Admin-Access-Domain", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "PaloAlto-Panorama-Admin-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "PaloAlto-Panorama-Admin-Access-Domain", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "PaloAlto-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "PaloAlto-User-Domain", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "PaloAlto-Client-Source-IP", Direction: "accounting", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "PaloAlto-Client-Hostname", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "PaloAlto-Client-OS", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "PaloAlto-GlobalProtect-Client-Version", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"Palo Alto attributes are primarily PAN-OS/Panorama administration, User-ID context, and GlobalProtect posture rather than wireless AP enforcement. Real firewall/VPN behavior remains release certification."},
		},
		{
			Key:              VendorPackTPLink,
			Label:            "TP-Link Omada",
			VendorName:       "TPLink",
			VendorID:         11863,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "TPLink-Recv-limit", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "TPLink-Recv-limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "TPLink-Xmit-limit", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "TPLink-Xmit-limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "TPLink-Authentication-FindKey", Direction: "inbound", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "TPLink-Authentication-FoundKey", Direction: "inbound", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "TPLink-User-Command", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "TPLink-Omada", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "TPLink-Omada", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "TPLink-Site", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "TPLink-Site", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Redirect-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Redirect-Url", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Portal-Access-Status", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Portal-Access-Status", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"TP-Link rate naming is device-oriented; validate receive/transmit direction on the target Omada controller before production use. Portal access status values require a reversible operator-certified profile mapping because the dictionary does not define portable integer labels. Authentication key octets are redacted evidence, never cleartext policy inputs."},
		},
		{
			Key:              VendorPackAerohive,
			Label:            "Aerohive / ExtremeCloud IQ",
			VendorName:       "Aerohive",
			VendorID:         26928,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-User-Vlan", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Extreme-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Extreme-IDM-Redirect-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Extreme-User-Profile-Attribute", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Extreme-Client-Monitor-Problem", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Extreme-IDM-Message", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Extreme-User-Language", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCertificateOnboarding, Attribute: "Extreme-Auth-Source", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Aerohive dictionaries use Extreme-prefixed attributes under the Aerohive vendor namespace; numeric user profile IDs need a site template before role rendering. Client monitor problem codes are retained as their decimal dictionary value for posture processing. PPSK/PMK material is redacted in software evidence; real client onboarding remains release certification."},
		},
		{
			Key:              VendorPackAirespace,
			Label:            "Cisco Airespace / WLC",
			VendorName:       "Airespace",
			VendorID:         14179,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Guest-Role-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "ACL-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Data-Bandwidth-Average-Contract", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Data-Bandwidth-Average-Contract-Upstream", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Wlan-Id", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Airespace bandwidth contracts should be validated against the target Cisco WLC generation before production use."},
		},
		{
			Key:              VendorPackHP,
			Label:            "HP / ArubaOS-Switch",
			VendorName:       "HP",
			VendorID:         11,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "HP-Privilege-Level", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "HP-Command-String", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "CPPM-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "HP-CPPM-Secondary-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Access-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Captive-Portal-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Bandwidth-Max-Ingress", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Bandwidth-Max-Egress", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "HP-Cos", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Ip-Filter-Raw", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "HP-Nas-Rules-IPv6", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Egress-VLANID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "HP-Egress-VLAN-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "HP-Bonjour-Inbound-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "HP-Bonjour-Outbound-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticCoAReauth, Attribute: "HP-Port-Bounce-Host", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"HP/ArubaOS-Switch VLAN encoding can be deployment-specific; keep standards-based tunnel VLANs enabled until switch-side validation is complete."},
		},
		{
			Key:              VendorPackNomadix,
			Label:            "Nomadix",
			VendorName:       "Nomadix",
			VendorID:         3309,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Nomadix-Bw-Up", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Nomadix-Bw-Down", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Nomadix-URL-Redirection", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Nomadix-Net-VLAN", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Nomadix-Qos-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticSessionAction, Attribute: "Nomadix-EndofSession", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Nomadix EndofSession integer meanings are firmware-specific and require an operator-certified reversible role/action mapping."},
		},
		{
			Key:              VendorPackChilliSpot,
			Label:            "ChilliSpot / CoovaChilli",
			VendorName:       "ChilliSpot",
			VendorID:         14559,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "ChilliSpot-Bandwidth-Max-Up", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "ChilliSpot-Bandwidth-Max-Down", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "ChilliSpot-Config", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "ChilliSpot-UAM-Allowed", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDataQuota, Attribute: "ChilliSpot-Max-Total-Octets", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"ChilliSpot quota values are combined input and output authorization limits and are configured per local role."},
		},
		{
			Key:              VendorPackDLink,
			Label:            "D-Link",
			VendorName:       "Dlink",
			VendorID:         171,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Dlink-User-Level", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Dlink-User-Level", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Dlink-Ingress-Bandwidth-Assignment", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Dlink-Ingress-Bandwidth-Assignment", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Dlink-Egress-Bandwidth-Assignment", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Dlink-Egress-Bandwidth-Assignment", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Dlink-1p-Priority", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Dlink-1p-Priority", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Dlink-VLAN-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Dlink-VLAN-Name", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Dlink-VLAN-ID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Dlink-VLAN-ID", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Dlink-ACL-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Dlink-ACL-Profile", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Dlink-ACL-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Dlink-ACL-Rule", Direction: "inbound", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Dlink-ACL-Script", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Dlink-ACL-Script", Direction: "inbound", ValueType: "policy", CompatibilityState: "implemented"},
			},
			Notes: []string{"D-Link role, bandwidth, priority, VLAN, and ACL rows are software-normalized. D-Link switch, AP, Nuclias, ACL script, and firmware behavior remains release-certified externally."},
		},
		{
			Key:              VendorPackSonicWall,
			Label:            "SonicWall",
			VendorName:       "SonicWall",
			VendorID:         8741,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "User-Privilege", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackArista,
			Label:            "Arista",
			VendorName:       "Arista",
			VendorID:         30065,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Arista-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Captive-Portal", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Segment-Id", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Interface-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "Device-Profiling", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackPica8,
			Label:            "Pica8",
			VendorName:       "Pica8",
			VendorID:         35098,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDynamicACL, Attribute: "IP-Downloadable-ACL-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "IP-Downloadable-ACL-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Redirect-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackZTE,
			Label:            "ZTE",
			VendorName:       "ZTE",
			VendorID:         3902,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QoS-Profile-Down", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QoS-Profile-Down", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QOS-Profile-Up", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QOS-Profile-Up", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QoS-Profile-Down-v6", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QoS-Profile-Up-v6", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QoS-Type", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Priority-Level", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Rate-Ctrl-SCR-Down", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Rate-Ctrl-SCR-Down", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Rate-Ctrl-SCR-Down-v6", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "ZTE_Rate-Bust-DPIR", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Rate-Ctrl-SCR-Up", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Rate-Ctrl-SCR-Up", Direction: "inbound", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Rate-Ctrl-SCR-Up-v6", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "ZTE_Rate-Bust-UPIR", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "PPPOE-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "PPPOE-URL", Direction: "inbound", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "PPPOE-MOTM", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "SW-Privilege", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "SW-Privilege", Direction: "inbound", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "IGMP-Service-Profile-Num", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mcast-Send", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mcast-Receive", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Mcast-MaxGroups", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Tunnel-Max-Sessions", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Tunnel-Cmd-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Client-DNS-Pri", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "Client-DNS-Sec", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "Access-Domain", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "VPN-ID", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0068 software-certifies every pinned ZTE dictionary row as native semantic mapping or typed evidence; PPPoE, tunnel, multicast, and BNG behavior remains release-certified externally."},
		},
		{
			Key:              VendorPackNokia,
			Label:            "Nokia SR OS",
			VendorName:       "Nokia",
			VendorID:         94,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Nokia-User-Profile", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Nokia-Service-Name", Direction: "inbound,outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "route", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPolicy, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticNAT64Prefix, Attribute: "Nokia-AVPair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0069 software-certifies every pinned Nokia dictionary row as native semantic mapping or typed evidence; Service-Name decimal digits use swapped-nibble BCD with an F pad nibble for odd lengths."},
		},
		{
			Key:              VendorPackAlcatel,
			Label:            "Alcatel AAT Access",
			VendorName:       "Alcatel",
			VendorID:         3041,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticIPv4Address, Attribute: "AAT-Client-Primary-DNS", Direction: "inbound,outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "AAT-PPP-Address", Direction: "inbound,outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVRF, Attribute: "AAT-Vrouter-Name", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "AAT-Qos", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "AAT-ATM-Traffic-Profile", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "AAT-Filter", Direction: "inbound,outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "AAT-Data-Filter", Direction: "inbound,outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "AAT-Require-Auth", Direction: "inbound,accounting", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0069 software-certifies legacy Alcatel AAT PPP, DNS, WINS, vrouter, QoS, ATM/FR, filter, and mobile/home-agent rows as bounded vendor evidence."},
		},
		{
			Key:              VendorPackAlcatelESAM,
			Label:            "Alcatel ESAM",
			VendorName:       "Alcatel-ESAM",
			VendorID:         637,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticVRF, Attribute: "A-ESAM-VRF-Name", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "A-ESAM-Vlan-Id", Direction: "inbound,outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "A-ESAM-QOS-Profile-Name", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "A-ESAM-QOS-Params", Direction: "inbound,outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "A-AL-DHCP", Direction: "inbound,accounting", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "A-AL-PPPoE", Direction: "inbound,accounting", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "A-AL-QoS", Direction: "inbound,outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "A-AL-Security", Direction: "inbound,accounting", ValueType: "octets", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0069 covers ESAM high-number access-node, TL1, VLAN, VRF, DHCP, PPPoE, QoS, xDSL, and security rows as typed dictionary evidence; high-number wire interop remains release-certified."},
		},
		{
			Key:              VendorPackALUSR,
			Label:            "Alcatel-Lucent SR OS",
			VendorName:       "Alcatel-Lucent-Service-Router",
			VendorID:         6527,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Timetra-Profile", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Alc-Subsc-ID-Str", Direction: "inbound,accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Alc-Subsc-Prof-Str", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Alc-SLA-Prof-Str", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Alc-MSAP-Policy", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRoute, Attribute: "Alc-BGP-Policy", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv6Address, Attribute: "Alc-Ipv6-Address", Direction: "inbound,outbound_reply", ValueType: "ipv6addr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDelegatedIPv6Prefix, Attribute: "Alc-Delegated-IPv6-Pool", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPortBlock, Attribute: "Alc-Nat-Port-Range", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "Alc-Nat-Outside-Ip-Addr", Direction: "inbound,outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Alc-Access-Loop-Rate-Down", Direction: "inbound,outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Alc-Portal-Url", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Alc-Wlan-SSID-VLAN", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Alc-Nas-Filter-Rule-Shared", Direction: "inbound,outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Alc-Trigger-Acct-Interim", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0069 software-certifies the pinned Timetra/Alc SR OS dictionary for subscriber/SAP/MSAP service, SLA/QoS, route, NAT, IPv6, portal, WLAN, security, and accounting semantics."},
		},
		{
			Key:              VendorPackALUAAA,
			Label:            "ALU-AAA",
			VendorName:       "ALU-AAA",
			VendorID:         831,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDynamicACL, Attribute: "ALU-AAA-Access-Rule", Direction: "inbound,outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "ALU-AAA-AV-Pair", Direction: "inbound,outbound_reply", ValueType: "record", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "ALU-AAA-Service-Profile", Direction: "inbound,outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIPv4Address, Attribute: "ALU-AAA-NAS-IP-Address", Direction: "inbound,accounting", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "ALU-AAA-NAS-Port", Direction: "inbound,accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "ALU-AAA-Delta-Session", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "ALU-AAA-Civic-Location", Direction: "inbound,accounting", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "ALU-AAA-Geospatial-Location", Direction: "inbound,accounting", ValueType: "octets", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "ALU-AAA-Called-Station-Id", Direction: "inbound,accounting", ValueType: "string", CompatibilityState: "implemented"},
			},
			Notes: []string{"NAS-0069 software-certifies ALU-AAA access-rule, AV-Pair, service-profile, mobile-auth, femto, location, voice, event, and counter rows; GSM/AKA/femto key material is redacted."},
		},
		{
			Key:              VendorPackStarent,
			Label:            "Starent / Cisco ASR Mobile Core",
			VendorName:       "Starent",
			VendorID:         8164,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticTranslationPublicIPv4, Attribute: "SN-NAT-IP-Address", Direction: "outbound_reply", ValueType: "ipaddr", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAddressPool, Attribute: "SN-IP-Pool-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "SN-Prepaid-Total-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "planned"},
			},
			Notes: []string{"Starent exposes SN-NAT-IP-Address for NAT public address selection; deterministic port-block and NAT64 metadata use AegisNAS product VSAs unless a target-specific adapter is certified."},
		},
		{
			Key:              VendorPackMeru,
			Label:            "Meru",
			VendorName:       "Meru",
			VendorID:         15983,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "Access-Point-Name", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Access-Point-Id", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"Meru's public dictionary is mostly AP identity context; access enforcement should stay standards-based until a richer controller template is available."},
		},
		{
			Key:              VendorPackColubris,
			Label:            "Colubris / HP MSM",
			VendorName:       "Colubris",
			VendorID:         8744,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticPolicyTag, Attribute: "AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
				{Semantic: VendorSemanticQuarantine, Attribute: "Intercept", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackOpenWiFi,
			Label:            "OpenWiFi",
			VendorName:       "OpenWiFi",
			VendorID:         58888,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "OpenWiFi-AP-MAC-Address", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticControllerPolicySync, Attribute: "controller.policy_sync", Direction: "controller_api", ValueType: "sync", CompatibilityState: "implemented"},
			},
			Notes: []string{"OpenWiFi enforcement uses standards-based RADIUS replies; the native Gateway adapter reconciles existing same-name enterprise SSIDs in per-device uCentral configurations selected by AP serial number or venue UUID."},
		},
		{
			Key:              VendorPackMist,
			Label:            "Juniper Mist",
			VendorName:       "Juniper",
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticControllerPolicySync, Attribute: "controller.policy_sync", Direction: "controller_api", ValueType: "sync", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticControllerHealth, Attribute: "controller.sync_health", Direction: "controller_api", ValueType: "record", CompatibilityState: "implemented"},
			},
			Notes: []string{"Mist compatibility is controller-API oriented; RADIUS reply rendering stays standards-based until site policy templates are configured."},
		},
	})
}

func VendorCompatibilityPackByKey(key string) (VendorCompatibilityPack, bool) {
	key = NormalizeVendorCompatibilityPackKey(key)
	for _, pack := range AegisNASVendorCompatibilityPacks() {
		if NormalizeVendorCompatibilityPackKey(pack.Key) == key {
			return pack, true
		}
	}
	return VendorCompatibilityPack{}, false
}

func VendorPackSupportsNumericRoleMapping(key string) bool {
	switch NormalizeVendorCompatibilityPackKey(key) {
	case VendorPackCambium, VendorPackAerohive, VendorPackDLink, VendorPackSonicWall, VendorPackZTE, VendorPackFoundry:
		return true
	default:
		return false
	}
}

func VendorPackSupportsExtendedVLANMapping(key string) bool {
	return NormalizeVendorCompatibilityPackKey(key) == VendorPackExtreme
}

func VendorPackAVPairAttribute(key string) (string, bool) {
	switch NormalizeVendorCompatibilityPackKey(key) {
	case VendorPackNokia:
		return "Nokia-AVPair", true
	case VendorPackRuckus:
		return "Ruckus-FlexAuth-AVP", true
	case VendorPackJuniper:
		return "Juniper-AV-Pair", true
	case VendorPackHuawei:
		return "Huawei-AVpair", true
	case VendorPackH3C:
		return "H3C-Av-Pair", true
	case VendorPackArista:
		return "Arista-AVPair", true
	case VendorPackFortinet:
		return "Fortinet-FortiWAN-AVPair", true
	case VendorPackALUAAA:
		return "ALU-AAA-AV-Pair", true
	default:
		return "", false
	}
}

func VendorPackSupportsPortalStatusMapping(key string) bool {
	return NormalizeVendorCompatibilityPackKey(key) == VendorPackTPLink
}

func VendorPackSupportsSessionActionMapping(key string) bool {
	return NormalizeVendorCompatibilityPackKey(key) == VendorPackNomadix
}

func VendorPackSupportsQuotaMapping(key string) bool {
	switch NormalizeVendorCompatibilityPackKey(key) {
	case VendorPackCambium, VendorPackChilliSpot, VendorPackRuckus, VendorPackMikroTik:
		return true
	default:
		return false
	}
}

func VendorPackSupportsServiceNameMapping(key string) bool {
	return NormalizeVendorCompatibilityPackKey(key) == VendorPackNokia
}

func NormalizeVendorCompatibilityPackKey(key string) string {
	return NormalizeDictionaryPackAlias(DefaultDictionaryReleaseProfileID, key)
}

func ValidVendorCompatibilityPackKey(key string) bool {
	_, ok := VendorCompatibilityPackByKey(key)
	return ok
}

func withVendorPackFeatureTemplates(packs []VendorCompatibilityPack) []VendorCompatibilityPack {
	for i := range packs {
		if len(packs[i].FeatureTemplates) == 0 {
			packs[i].FeatureTemplates = buildVendorPackFeatureTemplates(packs[i].Attributes)
		}
	}
	return packs
}

func buildVendorPackFeatureTemplates(mappings []VendorPackAttributeMapping) []VendorPackFeatureTemplate {
	indexes := map[string]int{}
	templates := make([]VendorPackFeatureTemplate, 0, len(mappings))
	for _, mapping := range mappings {
		feature := strings.TrimSpace(mapping.Semantic)
		if feature == "" {
			continue
		}
		key := feature + "\x00" + strings.TrimSpace(mapping.Direction)
		idx, ok := indexes[key]
		if !ok {
			templates = append(templates, VendorPackFeatureTemplate{
				Feature:            feature,
				Direction:          strings.TrimSpace(mapping.Direction),
				ValueType:          strings.TrimSpace(mapping.ValueType),
				CompatibilityState: strings.TrimSpace(mapping.CompatibilityState),
			})
			idx = len(templates) - 1
			indexes[key] = idx
		}
		templates[idx].Attributes = append(templates[idx].Attributes, strings.TrimSpace(mapping.Attribute))
		templates[idx].CompatibilityState = mergeVendorPackTemplateState(templates[idx].CompatibilityState, mapping.CompatibilityState)
		if templates[idx].ValueType == "" {
			templates[idx].ValueType = strings.TrimSpace(mapping.ValueType)
		}
	}
	return templates
}

func mergeVendorPackTemplateState(current, next string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	next = strings.ToLower(strings.TrimSpace(next))
	switch {
	case current == "":
		return next
	case next == "" || current == next:
		return current
	case current == "partial" || next == "partial":
		return "partial"
	case current == "implemented" && next == "planned":
		return "partial"
	case current == "planned" && next == "implemented":
		return "partial"
	default:
		return next
	}
}
