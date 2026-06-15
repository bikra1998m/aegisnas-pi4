package configs

import "strings"

const (
	VendorPackStandard = "standard"
	VendorPackAegisNAS = "aegisnas"
	VendorPackMikroTik = "mikrotik"
	VendorPackWISPr    = "wispr"
	VendorPackCisco    = "cisco"
	VendorPackAruba    = "aruba"
	VendorPackRuckus   = "ruckus"
	VendorPackFortinet = "fortinet"
	VendorPackUBNT     = "ubnt"
	VendorPackCambium  = "cambium"
	VendorPackMeraki   = "meraki"
	VendorPackExtreme  = "extreme"
	VendorPackJuniper  = "juniper"
	VendorPackHuawei   = "huawei"
	VendorPackH3C      = "h3c"
	VendorPackPaloAlto = "paloalto"
	VendorPackTPLink   = "tplink"
	VendorPackMist     = "mist"
)

type VendorCompatibilityPack struct {
	Key              string                       `json:"key"`
	Label            string                       `json:"label"`
	VendorName       string                       `json:"vendor_name,omitempty"`
	VendorID         int                          `json:"vendor_id,omitempty"`
	DefaultEnabled   bool                         `json:"default_enabled"`
	HardwareProfiles []string                     `json:"hardware_profiles"`
	Attributes       []VendorPackAttributeMapping `json:"attributes"`
	Notes            []string                     `json:"notes,omitempty"`
}

type VendorPackAttributeMapping struct {
	Semantic           string `json:"semantic"`
	Attribute          string `json:"attribute"`
	Direction          string `json:"direction"`
	ValueType          string `json:"value_type"`
	CompatibilityState string `json:"compatibility_state"`
}

func DefaultVendorCompatibilityPackKeys() []string {
	return []string{VendorPackStandard, VendorPackMikroTik, VendorPackWISPr}
}

func AegisNASVendorCompatibilityPacks() []VendorCompatibilityPack {
	allProfiles := []string{"lite", "branch", "enterprise", "custom"}
	branchEnterprise := []string{"branch", "enterprise", "custom"}
	enterprise := []string{"enterprise", "custom"}

	return []VendorCompatibilityPack{
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
				{Semantic: VendorSemanticSessionTimeout, Attribute: "Session-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIdleTimeout, Attribute: "Idle-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackAegisNAS,
			Label:            "AegisNAS Product VSA",
			VendorName:       "AegisNAS",
			VendorID:         55555,
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
			},
			Notes: []string{"Replace vendor ID 55555 with an assigned Private Enterprise Number before production use."},
		},
		{
			Key:              VendorPackMikroTik,
			Label:            "MikroTik RouterOS",
			VendorName:       "Mikrotik",
			VendorID:         14988,
			DefaultEnabled:   true,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Mikrotik-Rate-Limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
			},
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
				{Semantic: VendorSemanticDynamicACL, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
			},
			Notes: []string{"Cisco downloadable ACL and controller-specific AVPair semantics require site-specific templates."},
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
				{Semantic: VendorSemanticVLAN, Attribute: "Aruba-User-Vlan", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Aruba-NAS-Filter-Rule", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
			},
		},
		{
			Key:              VendorPackRuckus,
			Label:            "Ruckus",
			VendorName:       "Ruckus",
			VendorID:         25053,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Ruckus-User-Groups", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Ruckus-VLAN-ID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
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
				{Semantic: VendorSemanticPolicyTag, Attribute: "Fortinet-Access-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackUBNT,
			Label:            "Ubiquiti / UniFi",
			VendorName:       "UBNT",
			VendorID:         41112,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "UBNT-Data-Rate-DL", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "UBNT-Data-Rate-UL", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
			},
			Notes: []string{"UniFi/UBNT rate attributes are rendered from AegisNAS kbps values as bits per second."},
		},
		{
			Key:              VendorPackCambium,
			Label:            "Cambium",
			VendorName:       "Cambium",
			VendorID:         17713,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticVLAN, Attribute: "Cambium-ePMP-Data-VLAN-Id", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Cambium-ePMP-Max-Burst-Uplink-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Cambium-ePMP-Max-Burst-Downlink-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "Cambium-Auth-Role", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "planned"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Input-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Output-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Cambium-Walled-Garden-State", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "planned"},
			},
			Notes: []string{"Cambium role/user-level replies are numeric and need a site role-to-number template before automatic rendering."},
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
				{Semantic: VendorSemanticDevicePosture, Attribute: "Meraki-Ap-Tags", Direction: "accounting", ValueType: "string", CompatibilityState: "planned"},
				{Semantic: VendorSemanticControllerPolicySync, Attribute: "controller.policy_sync", Direction: "controller_api", ValueType: "sync", CompatibilityState: "planned"},
			},
			Notes: []string{"Meraki's FreeRADIUS dictionary is mostly contextual/accounting; group-policy enforcement should use standards-based replies or controller templates."},
		},
		{
			Key:              VendorPackExtreme,
			Label:            "Extreme Networks",
			VendorName:       "Extreme",
			VendorID:         1916,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Extreme-Security-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan-Tag", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Extreme-Netlogin-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Extreme-Netlogin-Extended-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
			},
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
				{Semantic: VendorSemanticACL, Attribute: "Juniper-Firewall-filter-name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Juniper-Switching-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Juniper-CWA-Redirect", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Juniper-Acct-Request-Reason", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
			},
		},
		{
			Key:              VendorPackHuawei,
			Label:            "Huawei",
			VendorName:       "Huawei",
			VendorID:         2011,
			DefaultEnabled:   false,
			HardwareProfiles: branchEnterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Huawei-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Qos-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Huawei-Output-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Huawei-Input-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Huawei-Data-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Huawei-HTTP-Redirect-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
			},
			Notes: []string{"Huawei rate attributes are rendered from AegisNAS kbps values; validate unit expectations on the target controller or switch."},
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
				{Semantic: VendorSemanticDeviceGroup, Attribute: "H3C-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "H3C-Output-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "H3C-Input-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "H3C-Ita-Policy", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "H3C-Portal-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "planned"},
			},
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
				{Semantic: VendorSemanticDeviceGroup, Attribute: "PaloAlto-User-Group", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "PaloAlto-Admin-Access-Domain", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "PaloAlto-Client-Hostname", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDevicePosture, Attribute: "PaloAlto-Client-OS", Direction: "accounting", ValueType: "string", CompatibilityState: "planned"},
			},
			Notes: []string{"Palo Alto attributes are primarily firewall/VPN administration and GlobalProtect context rather than wireless AP enforcement."},
		},
		{
			Key:              VendorPackTPLink,
			Label:            "TP-Link Omada",
			VendorName:       "TPLink",
			VendorID:         11863,
			DefaultEnabled:   false,
			HardwareProfiles: allProfiles,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "TPLink-Recv-limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "TPLink-Xmit-limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "TPLink-Omada", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticTenant, Attribute: "TPLink-Site", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Redirect-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Portal-Access-Status", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "planned"},
			},
			Notes: []string{"TP-Link rate naming is device-oriented; validate receive/transmit direction on the target Omada controller before production use."},
		},
		{
			Key:              VendorPackMist,
			Label:            "Juniper Mist",
			VendorName:       "Juniper",
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticControllerPolicySync, Attribute: "controller.policy_sync", Direction: "controller_api", ValueType: "sync", CompatibilityState: "planned"},
				{Semantic: VendorSemanticControllerHealth, Attribute: "controller.sync_health", Direction: "controller_api", ValueType: "record", CompatibilityState: "planned"},
			},
			Notes: []string{"Mist compatibility is controller-API oriented; RADIUS reply rendering stays standards-based until site policy templates are configured."},
		},
	}
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

func NormalizeVendorCompatibilityPackKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "aegis", "aegisnas-vsa", "product":
		return VendorPackAegisNAS
	case "mikrotik", "routeros":
		return VendorPackMikroTik
	case "wisp", "wispr":
		return VendorPackWISPr
	case "ubiquiti", "unifi", "ubnt":
		return VendorPackUBNT
	case "canopy", "epmp":
		return VendorPackCambium
	case "cisco-meraki":
		return VendorPackMeraki
	case "extremenetworks", "extreme-networks":
		return VendorPackExtreme
	case "junos":
		return VendorPackJuniper
	case "huawei-3com", "comware":
		return VendorPackH3C
	case "palo-alto", "palo_alto", "pan":
		return VendorPackPaloAlto
	case "tp-link", "tp_link", "omada":
		return VendorPackTPLink
	case "juniper-mist":
		return VendorPackMist
	default:
		return key
	}
}

func ValidVendorCompatibilityPackKey(key string) bool {
	_, ok := VendorCompatibilityPackByKey(key)
	return ok
}
