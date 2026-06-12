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
			Key:              "mist",
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
	default:
		return key
	}
}

func ValidVendorCompatibilityPackKey(key string) bool {
	_, ok := VendorCompatibilityPackByKey(key)
	return ok
}
