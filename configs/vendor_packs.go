package configs

import "strings"

const (
	VendorPackStandard   = "standard"
	VendorPackAegisNAS   = "aegisnas"
	VendorPackMikroTik   = "mikrotik"
	VendorPackWISPr      = "wispr"
	VendorPackCisco      = "cisco"
	VendorPackAruba      = "aruba"
	VendorPackRuckus     = "ruckus"
	VendorPackFortinet   = "fortinet"
	VendorPackUBNT       = "ubnt"
	VendorPackCambium    = "cambium"
	VendorPackMeraki     = "meraki"
	VendorPackExtreme    = "extreme"
	VendorPackJuniper    = "juniper"
	VendorPackHuawei     = "huawei"
	VendorPackH3C        = "h3c"
	VendorPackPaloAlto   = "paloalto"
	VendorPackTPLink     = "tplink"
	VendorPackAerohive   = "aerohive"
	VendorPackAirespace  = "airespace"
	VendorPackHP         = "hp"
	VendorPackNomadix    = "nomadix"
	VendorPackChilliSpot = "chillispot"
	VendorPackDLink      = "dlink"
	VendorPackSonicWall  = "sonicwall"
	VendorPackArista     = "arista"
	VendorPackPica8      = "pica8"
	VendorPackZTE        = "zte"
	VendorPackNokia      = "nokia"
	VendorPackMeru       = "meru"
	VendorPackColubris   = "colubris"
	VendorPackOpenWiFi   = "openwifi"
	VendorPackMist       = "mist"
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
				{Semantic: VendorSemanticSessionTimeout, Attribute: "Session-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticIdleTimeout, Attribute: "Idle-Timeout", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "NAS-Filter-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Mikrotik-Rate-Limit", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Mikrotik-Address-List", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticDynamicACL, Attribute: "Cisco-AVPair", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticVLAN, Attribute: "Aruba-User-Vlan", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Aruba-NAS-Filter-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticRole, Attribute: "Cambium-Auth-Role", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Input-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticAccountingCounters, Attribute: "Cambium-Acct-Output-Octets", Direction: "accounting", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticQuarantine, Attribute: "Cambium-Walled-Garden-State", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticRole, Attribute: "Extreme-Security-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Vlan-Tag", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Extreme-Netlogin-Url", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Extreme-Netlogin-Extended-Vlan", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticDynamicACL, Attribute: "Juniper-AV-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticRole, Attribute: "Huawei-User-Class", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "Huawei-Qos-Profile-Name", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Huawei-Output-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Huawei-Input-Average-Rate", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "Huawei-Data-Filter", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Huawei-HTTP-Redirect-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Huawei-AVpair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticDynamicACL, Attribute: "H3C-Av-Pair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticDevicePosture, Attribute: "PaloAlto-Client-OS", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticPortalProfile, Attribute: "TPLink-Portal-Access-Status", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"TP-Link rate naming is device-oriented; validate receive/transmit direction on the target Omada controller before production use. Portal access status values require a reversible operator-certified profile mapping because the dictionary does not define portable integer labels."},
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
			},
			Notes: []string{"Aerohive dictionaries use Extreme-prefixed attributes under the Aerohive vendor namespace; numeric user profile IDs need a site template before role rendering. Client monitor problem codes are retained as their decimal dictionary value for posture processing."},
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
				{Semantic: VendorSemanticRole, Attribute: "User-Role", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Access-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "Captive-Portal-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Bandwidth-Max-Ingress", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Bandwidth-Max-Egress", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "Ip-Filter-Raw", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "Egress-VLANID", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
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
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Ingress-Bandwidth-Assignment", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Egress-Bandwidth-Assignment", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticVLAN, Attribute: "VLAN-ID", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticACL, Attribute: "ACL-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDynamicACL, Attribute: "ACL-Rule", Direction: "outbound_reply", ValueType: "policy", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "User-Level", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
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
				{Semantic: VendorSemanticBandwidthProfile, Attribute: "QOS-Profile-Up", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDownloadBandwidth, Attribute: "Rate-Ctrl-SCR-Down", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticUploadBandwidth, Attribute: "Rate-Ctrl-SCR-Up", Direction: "outbound_reply", ValueType: "rate", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPortalProfile, Attribute: "PPPOE-URL", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticRole, Attribute: "SW-Privilege", Direction: "outbound_reply", ValueType: "integer", CompatibilityState: "implemented"},
			},
			Notes: []string{"ZTE broadband attributes are useful for access gateway mode; wireless enforcement should be validated against the deployed controller or BNG profile."},
		},
		{
			Key:              VendorPackNokia,
			Label:            "Nokia",
			VendorName:       "Nokia",
			VendorID:         94,
			DefaultEnabled:   false,
			HardwareProfiles: enterprise,
			Attributes: []VendorPackAttributeMapping{
				{Semantic: VendorSemanticRole, Attribute: "Nokia-User-Profile", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticPolicyTag, Attribute: "Nokia-AVPair", Direction: "outbound_reply", ValueType: "string", CompatibilityState: "implemented"},
				{Semantic: VendorSemanticDeviceGroup, Attribute: "Nokia-Service-Name", Direction: "outbound_reply", ValueType: "octets", CompatibilityState: "implemented"},
			},
			Notes: []string{"Nokia Service-Name decimal digits are encoded as swapped-nibble BCD with an F pad nibble for odd lengths."},
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
				{Semantic: VendorSemanticAccountingIdentity, Attribute: "AP-MAC-Address", Direction: "accounting", ValueType: "string", CompatibilityState: "implemented"},
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
	case VendorPackCambium, VendorPackAerohive, VendorPackDLink, VendorPackSonicWall, VendorPackZTE:
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
	case VendorPackJuniper:
		return "Juniper-AV-Pair", true
	case VendorPackHuawei:
		return "Huawei-AVpair", true
	case VendorPackH3C:
		return "H3C-Av-Pair", true
	case VendorPackArista:
		return "Arista-AVPair", true
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
	return NormalizeVendorCompatibilityPackKey(key) == VendorPackChilliSpot
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
