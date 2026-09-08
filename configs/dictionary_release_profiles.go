package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	DictionaryReleaseProfileSchemaVersion = 1
	DefaultDictionaryReleaseProfileID     = "freeradius-3.2.8"
)

type DictionaryReleaseProfile struct {
	SchemaVersion           int                         `json:"schema_version"`
	ID                      string                      `json:"id"`
	Name                    string                      `json:"name"`
	Source                  string                      `json:"source"`
	Release                 string                      `json:"release"`
	Status                  string                      `json:"status"`
	Default                 bool                        `json:"default"`
	RFCs                    []string                    `json:"rfcs"`
	RegistrySchemaVersion   int                         `json:"registry_schema_version"`
	RegistrySourceSHA256    string                      `json:"registry_source_sha256"`
	SourceFileCount         int                         `json:"source_file_count"`
	SourceAttributeCount    int                         `json:"source_attribute_count"`
	EffectiveAttributeCount int                         `json:"effective_attribute_count"`
	VendorCount             int                         `json:"vendor_count"`
	MappedAttributeCount    int                         `json:"mapped_attribute_count"`
	RuntimeDecoderCount     int                         `json:"runtime_decoder_count"`
	VendorAliasCount        int                         `json:"vendor_alias_count"`
	AttributeAliasCount     int                         `json:"attribute_alias_count"`
	FirmwareProfileCount    int                         `json:"firmware_profile_count"`
	VendorAliases           []DictionaryVendorAlias     `json:"vendor_aliases"`
	AttributeAliases        []DictionaryAttributeAlias  `json:"attribute_aliases"`
	FirmwareProfiles        []DictionaryFirmwareProfile `json:"firmware_profiles"`
	Notes                   []string                    `json:"notes,omitempty"`
}

type DictionaryVendorAlias struct {
	Alias            string   `json:"alias"`
	CanonicalVendor  string   `json:"canonical_vendor"`
	CanonicalPackKey string   `json:"canonical_pack_key,omitempty"`
	PEN              uint32   `json:"pen,omitempty"`
	Scope            string   `json:"scope"`
	Source           string   `json:"source"`
	Notes            []string `json:"notes,omitempty"`
}

type DictionaryAttributeAlias struct {
	Vendor             string   `json:"vendor"`
	Alias              string   `json:"alias"`
	CanonicalAttribute string   `json:"canonical_attribute"`
	PEN                uint32   `json:"pen,omitempty"`
	Number             uint32   `json:"number,omitempty"`
	WireKey            string   `json:"wire_key,omitempty"`
	Scope              string   `json:"scope"`
	Source             string   `json:"source"`
	Notes              []string `json:"notes,omitempty"`
}

type DictionaryFirmwareProfile struct {
	Key              string   `json:"key"`
	Vendor           string   `json:"vendor"`
	PackKey          string   `json:"pack_key"`
	PEN              uint32   `json:"pen,omitempty"`
	ProductFamily    string   `json:"product_family"`
	FirmwareScope    string   `json:"firmware_scope"`
	HardwareProfiles []string `json:"hardware_profiles"`
	SupportState     string   `json:"support_state"`
	EvidenceState    string   `json:"evidence_state"`
	AttributeScope   []string `json:"attribute_scope"`
	Notes            []string `json:"notes,omitempty"`
}

type dictionaryReleaseContract struct {
	profile DictionaryReleaseProfile
}

var defaultDictionaryReleaseContract = dictionaryReleaseContract{profile: DictionaryReleaseProfile{
	SchemaVersion:           DictionaryReleaseProfileSchemaVersion,
	ID:                      DefaultDictionaryReleaseProfileID,
	Name:                    "FreeRADIUS 3.2.8 vendor dictionary profile",
	Source:                  "FreeRADIUS dictionary corpus",
	Release:                 FreeRADIUSRegistryRelease,
	Status:                  "active",
	Default:                 true,
	RFCs:                    []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6614", "RFC 9813"},
	RegistrySchemaVersion:   AttributeRegistrySchemaVersion,
	SourceFileCount:         FreeRADIUSRegistryFileCount,
	SourceAttributeCount:    7654,
	EffectiveAttributeCount: 7661,
	VendorCount:             196,
	MappedAttributeCount:    2254,
	RuntimeDecoderCount:     2071,
	VendorAliases: []DictionaryVendorAlias{
		vendorAlias("aegis", AegisNASVendorName, VendorPackAegisNAS, AegisNASPlaceholderVendorID, "product dictionary"),
		vendorAlias("aegisnas-vsa", AegisNASVendorName, VendorPackAegisNAS, AegisNASPlaceholderVendorID, "product dictionary"),
		vendorAlias("product", AegisNASVendorName, VendorPackAegisNAS, AegisNASPlaceholderVendorID, "product dictionary"),
		vendorAlias("mikrotik", "Mikrotik", VendorPackMikroTik, 14988, "vendor dictionary"),
		vendorAlias("routeros", "Mikrotik", VendorPackMikroTik, 14988, "product firmware"),
		vendorAlias("wisp", "WISPr", VendorPackWISPr, 14122, "vendor dictionary"),
		vendorAlias("wispr", "WISPr", VendorPackWISPr, 14122, "vendor dictionary"),
		vendorAlias("ubiquiti", "Ubiquiti", VendorPackUBNT, 41112, "vendor dictionary"),
		vendorAlias("unifi", "Ubiquiti", VendorPackUBNT, 41112, "controller family"),
		vendorAlias("ubnt", "Ubiquiti", VendorPackUBNT, 41112, "vendor dictionary"),
		vendorAlias("canopy", "Cambium", VendorPackCambium, 17713, "product firmware"),
		vendorAlias("epmp", "Cambium", VendorPackCambium, 17713, "product firmware"),
		vendorAlias("cnmaestro", "Cambium", VendorPackCambium, 17713, "controller family"),
		vendorAlias("pmp", "Cambium", VendorPackCambium, 17713, "product firmware"),
		vendorAlias("cisco-meraki", "Meraki", VendorPackMeraki, 29671, "controller family"),
		vendorAlias("cisco-wlc", "Airespace", VendorPackAirespace, 14179, "controller family"),
		vendorAlias("wlc", "Airespace", VendorPackAirespace, 14179, "controller family"),
		vendorAlias("extremenetworks", "Extreme", VendorPackExtreme, 1916, "vendor dictionary"),
		vendorAlias("extreme-networks", "Extreme", VendorPackExtreme, 1916, "vendor dictionary"),
		vendorAlias("junos", "Juniper", VendorPackJuniper, 2636, "product firmware"),
		vendorAlias("juniper-erx", "ERX", VendorPackERX, 4874, "product firmware"),
		vendorAlias("e-series", "ERX", VendorPackERX, 4874, "product firmware"),
		vendorAlias("huawei-3com", "H3C", VendorPackH3C, 25506, "vendor lineage"),
		vendorAlias("comware", "H3C", VendorPackH3C, 25506, "product firmware"),
		vendorAlias("palo-alto", "PaloAlto", VendorPackPaloAlto, 25461, "vendor spelling"),
		vendorAlias("palo_alto", "PaloAlto", VendorPackPaloAlto, 25461, "vendor spelling"),
		vendorAlias("pan", "PaloAlto", VendorPackPaloAlto, 25461, "product family"),
		vendorAlias("tp-link", "TPLink", VendorPackTPLink, 11863, "vendor spelling"),
		vendorAlias("tp_link", "TPLink", VendorPackTPLink, 11863, "vendor spelling"),
		vendorAlias("omada", "TPLink", VendorPackTPLink, 11863, "controller family"),
		vendorAlias("extremecloud", "Aerohive", VendorPackAerohive, 26928, "cloud controller"),
		vendorAlias("extremecloudiq", "Aerohive", VendorPackAerohive, 26928, "cloud controller"),
		vendorAlias("extreme-cloud-iq", "Aerohive", VendorPackAerohive, 26928, "cloud controller"),
		vendorAlias("hive", "Aerohive", VendorPackAerohive, 26928, "vendor lineage"),
		vendorAlias("hivemanager", "Aerohive", VendorPackAerohive, 26928, "controller family"),
		vendorAlias("hewlett-packard", "HP", VendorPackHP, 11, "vendor spelling"),
		vendorAlias("arubaos-switch", "HP", VendorPackHP, 11, "product firmware"),
		vendorAlias("procurve", "HP", VendorPackHP, 11, "product firmware"),
		vendorAlias("coovachilli", "ChilliSpot", VendorPackChilliSpot, 14559, "project lineage"),
		vendorAlias("coova-chilli", "ChilliSpot", VendorPackChilliSpot, 14559, "project lineage"),
		vendorAlias("chilli", "ChilliSpot", VendorPackChilliSpot, 14559, "project shorthand"),
		vendorAlias("d-link", "DLink", VendorPackDLink, 171, "vendor spelling"),
		vendorAlias("d_link", "DLink", VendorPackDLink, 171, "vendor spelling"),
		vendorAlias("dlink", "DLink", VendorPackDLink, 171, "vendor spelling"),
		vendorAlias("nuclias", "DLink", VendorPackDLink, 171, "controller family"),
		vendorAlias("sonic-wall", "SonicWall", VendorPackSonicWall, 8741, "vendor spelling"),
		vendorAlias("3com", "3com", VendorPack3Com, 43, "vendor dictionary"),
		vendorAlias("threecom", "3com", VendorPack3Com, 43, "vendor spelling"),
		vendorAlias("arista", "Arista", VendorPackArista, 30065, "vendor dictionary"),
		vendorAlias("arista-eos", "Arista", VendorPackArista, 30065, "product firmware"),
		vendorAlias("eos", "Arista", VendorPackArista, 30065, "product firmware"),
		vendorAlias("brocade", "Brocade", VendorPackBrocade, 1588, "vendor dictionary"),
		vendorAlias("dell", "DellEMC", VendorPackDellEMC, 674, "vendor family"),
		vendorAlias("dell-emc", "DellEMC", VendorPackDellEMC, 674, "vendor spelling"),
		vendorAlias("dellemc", "DellEMC", VendorPackDellEMC, 674, "vendor dictionary"),
		vendorAlias("equallogic", "Equallogic", VendorPackEquallogic, 12740, "vendor dictionary"),
		vendorAlias("equal-logic", "Equallogic", VendorPackEquallogic, 12740, "vendor spelling"),
		vendorAlias("force10", "Force10", VendorPackForce10, 6027, "vendor dictionary"),
		vendorAlias("ftos", "Force10", VendorPackForce10, 6027, "product firmware"),
		vendorAlias("foundry", "Foundry", VendorPackFoundry, 1991, "vendor dictionary"),
		vendorAlias("fastiron", "Foundry", VendorPackFoundry, 1991, "product firmware"),
		vendorAlias("pica", "Pica8", VendorPackPica8, 35098, "vendor shorthand"),
		vendorAlias("alcatel", "Alcatel", VendorPackAlcatel, 3041, "vendor dictionary"),
		vendorAlias("alcatel-aat", "Alcatel", VendorPackAlcatel, 3041, "product firmware"),
		vendorAlias("alcatel-esam", "Alcatel-ESAM", VendorPackAlcatelESAM, 637, "product firmware"),
		vendorAlias("esam", "Alcatel-ESAM", VendorPackAlcatelESAM, 637, "product firmware"),
		vendorAlias("alcatel-lucent", "Alcatel-Lucent-Service-Router", VendorPackALUSR, 6527, "vendor lineage"),
		vendorAlias("alu", "Alcatel-Lucent-Service-Router", VendorPackALUSR, 6527, "vendor lineage"),
		vendorAlias("alu-sr", "Alcatel-Lucent-Service-Router", VendorPackALUSR, 6527, "product firmware"),
		vendorAlias("timetra", "Alcatel-Lucent-Service-Router", VendorPackALUSR, 6527, "product firmware"),
		vendorAlias("alu-aaa", "ALU-AAA", VendorPackALUAAA, 831, "vendor dictionary"),
		vendorAlias("nokia-sr", "Nokia", VendorPackNokia, 94, "product firmware"),
		vendorAlias("nokia-sros", "Nokia", VendorPackNokia, 94, "product firmware"),
		vendorAlias("staros", "Starent", VendorPackStarent, 8164, "product firmware"),
		vendorAlias("cisco-asr", "Starent", VendorPackStarent, 8164, "product firmware"),
		vendorAlias("cisco-asr5000", "Starent", VendorPackStarent, 8164, "product firmware"),
		vendorAlias("hp-msm", "Colubris", VendorPackColubris, 8744, "product firmware"),
		vendorAlias("open-wifi", "OpenWiFi", VendorPackOpenWiFi, 58888, "project spelling"),
		vendorAlias("tip-openwifi", "OpenWiFi", VendorPackOpenWiFi, 58888, "project spelling"),
		vendorAlias("juniper-mist", "Mist", VendorPackMist, 28139, "controller family"),
	},
	AttributeAliases: []DictionaryAttributeAlias{
		attributeAlias("Cisco", "Cisco-AV-Pair", "Cisco-AVPair", 9, 1, "vendor spelling"),
		attributeAlias("Ubiquiti", "Ubiquiti-Data-Rate-DL", "UBNT-Data-Rate-DL", 41112, 1, "vendor spelling"),
		attributeAlias("Ubiquiti", "Ubiquiti-Data-Rate-UL", "UBNT-Data-Rate-UL", 41112, 3, "vendor spelling"),
		attributeAlias("Huawei", "Huawei-AVPair", "Huawei-AVpair", 2011, 188, "vendor spelling"),
		attributeAlias("Huawei", "Huawei-AV-Pair", "Huawei-AVpair", 2011, 188, "vendor spelling"),
		attributeAlias("H3C", "H3C-AVPair", "H3C-Av-Pair", 25506, 210, "vendor spelling"),
		attributeAlias("H3C", "H3C-AV-Pair", "H3C-Av-Pair", 25506, 210, "vendor spelling"),
		attributeAlias("TPLink", "TP-Link-Redirect-Url", "TPLink-Redirect-Url", 11863, 8, "vendor spelling"),
		attributeAlias("TPLink", "TP-Link-Portal-Access-Status", "TPLink-Portal-Access-Status", 11863, 9, "vendor spelling"),
		attributeAlias("Airespace", "Cisco-WLC-ACL-Name", "ACL-Name", 14179, 6, "controller alias"),
	},
	FirmwareProfiles: []DictionaryFirmwareProfile{
		firmwareProfile("mikrotik-routeros", "Mikrotik", VendorPackMikroTik, 14988, "RouterOS", "RouterOS 6.x and 7.x dictionary-compatible RADIUS attributes", []string{"lite", "branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Mikrotik-Rate-Limit", "Mikrotik-Group", "Mikrotik-Address-List", "Mikrotik-Switching-Filter", "Mikrotik-Total-Limit", "Mikrotik-Total-Limit-Gigawords", "Mikrotik-Advertise-URL", "Mikrotik-Host-IP", "Mikrotik-Delegated-IPv6-Pool", "Mikrotik-Wireless-VLANID", "Mikrotik-DHCP-Option-Set"}),
		firmwareProfile("ubiquiti-unifi-network", "Ubiquiti", VendorPackUBNT, 41112, "UniFi Network", "UniFi Network controllers and AP firmware that accept UBNT rate VSAs", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"UBNT-Data-Rate-DL", "UBNT-Data-Rate-UL"}),
		firmwareProfile("aruba-aos-controller", "Aruba", VendorPackAruba, 14823, "ArubaOS / Mobility Controller", "AOS controller and AP firmware accepting role, VLAN, and filter rule VSAs", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Aruba-User-Role", "Aruba-User-Vlan", "Aruba-NAS-Filter-Rule"}),
		firmwareProfile("cisco-ios-xe", "Cisco", VendorPackCisco, 9, "Cisco IOS/IOS-XE", "Switch and WLC firmware accepting Cisco ACL and AVPair reply attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Cisco-In-ACL", "Cisco-Out-ACL", "Cisco-AVPair"}),
		firmwareProfile("juniper-junos", "Juniper", VendorPackJuniper, 2636, "Junos", "Junos switching and access platforms using Juniper local role, filter, and AVPair attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Juniper-Local-User-Name", "Juniper-Firewall-filter-name", "Juniper-AV-Pair"}),
		firmwareProfile("juniper-erx", "ERX", VendorPackERX, 4874, "Juniper ERX / E-Series", "ERX and E-Series BNG dictionaries using address-pool selectors for subscriber translation policy", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"ERX-Address-Pool-Name"}),
		firmwareProfile("huawei-h3c-comware", "H3C", VendorPackH3C, 25506, "Comware", "H3C/Huawei-3Com Comware platforms with H3C user-role, rate, portal, and AVPair attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"H3C-User-Role", "H3C-Input-Average-Rate", "H3C-Av-Pair"}),
		firmwareProfile("cambium-cnmaestro", "Cambium", VendorPackCambium, 17713, "cnMaestro", "Cambium cnMaestro, enterprise Wi-Fi, ePMP, and PMP firmware using role, VLAN, quota, QoS, walled-garden, and traffic-class attributes", []string{"lite", "branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Cambium-Auth-Role", "Cambium-ePMP-Data-VLAN-Id", "Cambium-Traffic-Quota-Limit-Total", "Cambium-Walled-Garden-State"}),
		firmwareProfile("tplink-omada", "TPLink", VendorPackTPLink, 11863, "Omada", "Omada controller, AP, switch, and gateway firmware using TPLink bandwidth, site, Omada group, portal, redirect, and authentication-key attributes", []string{"lite", "branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"TPLink-Recv-limit", "TPLink-Xmit-limit", "TPLink-Site", "TPLink-Omada", "TPLink-Portal-Access-Status"}),
		firmwareProfile("dlink-nuclias", "DLink", VendorPackDLink, 171, "Nuclias / D-Link switching", "D-Link access switch, AP, and Nuclias firmware using user level, bandwidth, priority, VLAN, ACL profile, ACL rule, and ACL script attributes", []string{"lite", "branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Dlink-User-Level", "Dlink-VLAN-ID", "Dlink-ACL-Profile", "Dlink-ACL-Rule"}),
		firmwareProfile("3com-switching", "3com", VendorPack3Com, 43, "3Com switching and WLAN access", "3Com dictionary-compatible switching and wireless access firmware using access level, VLAN name, mobility, SSID, portal URL, encryption, host IP, and session telemetry", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"3Com-User-Access-Level", "3Com-VLAN-Name", "3Com-SSID", "3Com-URL", "3Com-Ip-Host-Addr"}),
		firmwareProfile("arista-eos-switching", "Arista", VendorPackArista, 30065, "Arista EOS", "EOS and CloudVision dictionary-compatible access, role, command, WebAuth, captive portal, MAC remediation, and fabric-segment attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Arista-AVPair", "Arista-User-Role", "Arista-CVP-Role", "Arista-Command", "Arista-Captive-Portal"}),
		firmwareProfile("brocade-switching", "Brocade", VendorPackBrocade, 1588, "Brocade switching", "Brocade dictionary-compatible switch administration and policy attributes using auth role, AVPairs, and password lifecycle hints", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Brocade-Auth-Role", "Brocade-AVPairs1", "Brocade-AVPairs2", "Brocade-Passwd-ExpiryDate"}),
		firmwareProfile("dellemc-powerswitch", "DellEMC", VendorPackDellEMC, 674, "Dell EMC PowerSwitch", "Dell EMC dictionary-compatible switching platforms using group-name and AVpair policy attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"DellEMC-Group-Name", "DellEMC-AVpair"}),
		firmwareProfile("equallogic-admin", "Equallogic", VendorPackEquallogic, 12740, "Dell EqualLogic", "EqualLogic administrative access dictionary attributes using admin contact, privilege, pool access, replication-site, account-type, and poll interval context", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Equallogic-EQL-Admin-Privilege", "Equallogic-Admin-Pool-Access", "Equallogic-Admin-Repl-Site-Access"}),
		firmwareProfile("force10-ftos-switching", "Force10", VendorPackForce10, 6027, "Dell Force10 / FTOS", "Force10 dictionary-compatible switching platforms using AVPair policy tokens", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Force10-AVPair"}),
		firmwareProfile("foundry-fastiron-switching", "Foundry", VendorPackFoundry, 1991, "Foundry / ICX FastIron", "Foundry and Ruckus ICX dictionary-compatible switch policy, command authorization, ACL, 802.1X, VLAN/QoS, CoA, and voice attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Foundry-Privilege-Level", "Foundry-Command-String", "Foundry-Access-List", "Foundry-COA-Command"}),
		firmwareProfile("extreme-switching-netlogin", "Extreme", VendorPackExtreme, 1916, "Extreme switching NetLogin", "Extreme dictionary-compatible NetLogin, CLI authorization, VLAN, captive portal, security profile, VM, and virtual-router attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Extreme-CLI-Authorization", "Extreme-Netlogin-Vlan", "Extreme-Netlogin-Extended-Vlan", "Extreme-Security-Profile"}),
		firmwareProfile("nokia-sros", "Nokia", VendorPackNokia, 94, "SR OS", "Nokia SR OS attributes requiring AVPair policy normalization and BCD service-name handling", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Nokia-AVPair", "Nokia-User-Profile", "Nokia-Service-Name"}),
		firmwareProfile("alcatel-aat", "Alcatel", VendorPackAlcatel, 3041, "AAT access", "Legacy Alcatel access and PPP dictionaries using DNS, vrouter, QoS, filter, WINS, and home-agent attributes", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"AAT-PPP-Address", "AAT-Vrouter-Name", "AAT-Qos", "AAT-Filter"}),
		firmwareProfile("alcatel-esam", "Alcatel-ESAM", VendorPackAlcatelESAM, 637, "ESAM access node", "Alcatel ESAM DSL/GPON access-node dictionaries carrying VLAN, VRF, TL1, DHCP, PPPoE, QoS, xDSL, and security evidence", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"A-ESAM-VRF-Name", "A-ESAM-Vlan-Id", "A-AL-DHCP", "A-AL-PPPoE"}),
		firmwareProfile("alu-service-router", "Alcatel-Lucent-Service-Router", VendorPackALUSR, 6527, "SR OS / Timetra", "Alcatel-Lucent SR OS and Timetra service-router dictionaries using subscriber, SAP/MSAP, SLA, IPv6, NAT, portal, BGP, and accounting attributes", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"Timetra-Profile", "Alc-Subsc-ID-Str", "Alc-SLA-Prof-Str", "Alc-Nat-Port-Range", "Alc-Nas-Filter-Rule-Shared"}),
		firmwareProfile("alu-aaa", "ALU-AAA", VendorPackALUAAA, 831, "ALU-AAA", "ALU-AAA dictionaries carrying access rules, AV-Pairs, service profiles, mobile-auth evidence, location, voice, and event state", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"ALU-AAA-Access-Rule", "ALU-AAA-AV-Pair", "ALU-AAA-Service-Profile", "ALU-AAA-Delta-Session"}),
		firmwareProfile("starent-staros", "Starent", VendorPackStarent, 8164, "StarOS / Cisco ASR mobile core", "Starent and Cisco ASR mobile-core dictionaries exposing SN-NAT-IP-Address and subscriber pool selectors", []string{"enterprise", "custom"}, "software-ready", "external-certification-required", []string{"SN-NAT-IP-Address", "SN-IP-Pool-Name"}),
		firmwareProfile("openwifi-tip", "OpenWiFi", VendorPackOpenWiFi, 58888, "TIP OpenWiFi", "TIP OpenWiFi controller integrations and AP identity attributes", []string{"branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"OpenWiFi-AP-MAC-Address", "controller.policy_sync"}),
		firmwareProfile("long-tail-freeradius-namespaces", "Long-Tail FreeRADIUS Corpus", VendorPackLongTail, 0, "Long-tail vendor namespaces", "NAS-0072 typed namespace program covering the remaining in-corpus vendors assigned to the long-tail roadmap wave", []string{"lite", "branch", "enterprise", "custom"}, "software-ready", "external-certification-required", []string{"1,126 NAS-0072 registry-backed VSA rows"}),
	},
	Notes: []string{
		"Profile activation is build-time and immutable for this release; external evidence state is tracked separately from dictionary metadata.",
		"Firmware profile support_state means AegisNAS has deterministic software mappings. It does not certify a physical AP, switch, firewall, or controller release.",
	},
}}

func vendorAlias(alias, canonicalVendor, packKey string, pen uint32, scope string) DictionaryVendorAlias {
	return DictionaryVendorAlias{Alias: alias, CanonicalVendor: canonicalVendor, CanonicalPackKey: packKey, PEN: pen, Scope: scope, Source: DefaultDictionaryReleaseProfileID}
}

func attributeAlias(vendor, alias, canonical string, pen, number uint32, scope string) DictionaryAttributeAlias {
	return DictionaryAttributeAlias{Vendor: vendor, Alias: alias, CanonicalAttribute: canonical, PEN: pen, Number: number, WireKey: fmt.Sprintf("vsa:%d:%d", pen, number), Scope: scope, Source: DefaultDictionaryReleaseProfileID}
}

func firmwareProfile(key, vendor, packKey string, pen uint32, family, scope string, hardwareProfiles []string, supportState, evidenceState string, attrs []string) DictionaryFirmwareProfile {
	return DictionaryFirmwareProfile{Key: key, Vendor: vendor, PackKey: packKey, PEN: pen, ProductFamily: family, FirmwareScope: scope, HardwareProfiles: append([]string(nil), hardwareProfiles...), SupportState: supportState, EvidenceState: evidenceState, AttributeScope: append([]string(nil), attrs...)}
}

func BuiltInDictionaryReleaseProfiles() []DictionaryReleaseProfile {
	profile := defaultDictionaryReleaseBaseProfile()
	if registry, err := BuiltInAttributeRegistry(); err == nil {
		profile.RegistrySchemaVersion = registry.SchemaVersion
		profile.RegistrySourceSHA256 = registry.SourceSHA256
		profile.SourceFileCount = registry.SourceFileCount
		profile.SourceAttributeCount = registry.SourceAttributeCount
		profile.EffectiveAttributeCount = registry.AttributeCount
		profile.VendorCount = registry.VendorCount
		profile.MappedAttributeCount = registry.MappedCount
		profile.RuntimeDecoderCount = len(registry.RuntimeMappings())
	}
	return []DictionaryReleaseProfile{profile}
}

func DefaultDictionaryReleaseProfile() DictionaryReleaseProfile {
	return BuiltInDictionaryReleaseProfiles()[0]
}

func DictionaryReleaseProfileByID(id string) (DictionaryReleaseProfile, bool) {
	id = EffectiveDictionaryReleaseProfileID(id)
	for _, profile := range BuiltInDictionaryReleaseProfiles() {
		if strings.EqualFold(profile.ID, id) {
			return profile, true
		}
	}
	return DictionaryReleaseProfile{}, false
}

func EffectiveDictionaryReleaseProfileID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return DefaultDictionaryReleaseProfileID
	}
	return strings.ToLower(id)
}

func ValidDictionaryReleaseProfileID(id string) bool {
	_, ok := DictionaryReleaseProfileByID(id)
	return ok
}

func NormalizeDictionaryVendorName(profileID, vendor string) string {
	vendor = strings.TrimSpace(vendor)
	if vendor == "" {
		return ""
	}
	profile := dictionaryReleaseBaseProfileByID(profileID)
	key := normalizedDictionaryReleaseKey(vendor)
	for _, alias := range profile.VendorAliases {
		if normalizedDictionaryReleaseKey(alias.Alias) == key || normalizedDictionaryReleaseKey(alias.CanonicalVendor) == key {
			return alias.CanonicalVendor
		}
	}
	return vendor
}

func NormalizeDictionaryAttributeName(profileID, vendor, attribute string) string {
	attribute = strings.TrimSpace(attribute)
	if attribute == "" {
		return ""
	}
	profile := dictionaryReleaseBaseProfileByID(profileID)
	canonicalVendor := NormalizeDictionaryVendorName(profileID, vendor)
	attributeKey := normalizedDictionaryReleaseKey(attribute)
	trimmedAttributeKey := normalizedDictionaryReleaseKey(trimDictionaryAttributePrefix(attribute, vendor))
	canonicalVendorKey := normalizedDictionaryReleaseKey(canonicalVendor)
	for _, alias := range profile.AttributeAliases {
		if canonicalVendorKey != "" && normalizedDictionaryReleaseKey(alias.Vendor) != canonicalVendorKey {
			continue
		}
		aliasKey := normalizedDictionaryReleaseKey(alias.Alias)
		canonicalKey := normalizedDictionaryReleaseKey(alias.CanonicalAttribute)
		if aliasKey == attributeKey || aliasKey == trimmedAttributeKey || canonicalKey == attributeKey || canonicalKey == trimmedAttributeKey {
			return alias.CanonicalAttribute
		}
	}
	return attribute
}

func NormalizeDictionaryPackAlias(profileID, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return ""
	}
	switch normalizedDictionaryReleaseKey(key) {
	case "long-tail", "longtail", "long-tail-namespace", "long-tail-namespaces", "typed-long-tail", "typed-longtail", "nas-0072":
		return VendorPackLongTail
	}
	profile := dictionaryReleaseBaseProfileByID(profileID)
	for _, alias := range profile.VendorAliases {
		if normalizedDictionaryReleaseKey(alias.Alias) == key || normalizedDictionaryReleaseKey(alias.CanonicalVendor) == key {
			return alias.CanonicalPackKey
		}
	}
	return key
}

func DictionaryFirmwareProfilesForPack(profileID, packKey string) []DictionaryFirmwareProfile {
	profile := dictionaryReleaseBaseProfileByID(profileID)
	packKey = NormalizeDictionaryPackAlias(profileID, packKey)
	out := []DictionaryFirmwareProfile{}
	for _, firmware := range profile.FirmwareProfiles {
		if NormalizeDictionaryPackAlias(profileID, firmware.PackKey) == packKey {
			out = append(out, firmware)
		}
	}
	return out
}

func ValidateDictionaryReleaseProfile(profile DictionaryReleaseProfile, registry *AttributeRegistry, packs []VendorCompatibilityPack) error {
	if strings.TrimSpace(profile.ID) == "" {
		return fmt.Errorf("dictionary release profile id is required")
	}
	if registry == nil {
		return fmt.Errorf("attribute registry is required")
	}
	if !strings.EqualFold(profile.Release, registry.SourceRelease) {
		return fmt.Errorf("release profile %s targets FreeRADIUS %s but registry is %s", profile.ID, profile.Release, registry.SourceRelease)
	}
	if profile.RegistrySchemaVersion != registry.SchemaVersion || profile.SourceFileCount != registry.SourceFileCount || profile.SourceAttributeCount != registry.SourceAttributeCount || profile.EffectiveAttributeCount != registry.AttributeCount {
		return fmt.Errorf("release profile %s does not match registry counts", profile.ID)
	}
	if strings.TrimSpace(profile.RegistrySourceSHA256) != "" && !strings.EqualFold(profile.RegistrySourceSHA256, registry.SourceSHA256) {
		return fmt.Errorf("release profile %s source hash does not match registry", profile.ID)
	}
	if err := validateDictionaryVendorAliases(profile); err != nil {
		return err
	}
	if err := validateDictionaryAttributeAliases(profile, registry); err != nil {
		return err
	}
	if err := validateDictionaryFirmwareProfiles(profile, packs); err != nil {
		return err
	}
	return nil
}

var cachedDefaultDictionaryReleaseBaseProfile = buildDefaultDictionaryReleaseBaseProfile()

func defaultDictionaryReleaseBaseProfile() DictionaryReleaseProfile {
	return cloneDictionaryReleaseProfile(cachedDefaultDictionaryReleaseBaseProfile)
}

func cloneDictionaryReleaseProfile(profile DictionaryReleaseProfile) DictionaryReleaseProfile {
	profile.RFCs = append([]string(nil), profile.RFCs...)
	profile.VendorAliases = append([]DictionaryVendorAlias(nil), profile.VendorAliases...)
	for idx := range profile.VendorAliases {
		profile.VendorAliases[idx].Notes = append([]string(nil), profile.VendorAliases[idx].Notes...)
	}
	profile.AttributeAliases = append([]DictionaryAttributeAlias(nil), profile.AttributeAliases...)
	for idx := range profile.AttributeAliases {
		profile.AttributeAliases[idx].Notes = append([]string(nil), profile.AttributeAliases[idx].Notes...)
	}
	profile.FirmwareProfiles = append([]DictionaryFirmwareProfile(nil), profile.FirmwareProfiles...)
	for idx := range profile.FirmwareProfiles {
		profile.FirmwareProfiles[idx].HardwareProfiles = append([]string(nil), profile.FirmwareProfiles[idx].HardwareProfiles...)
		profile.FirmwareProfiles[idx].AttributeScope = append([]string(nil), profile.FirmwareProfiles[idx].AttributeScope...)
		profile.FirmwareProfiles[idx].Notes = append([]string(nil), profile.FirmwareProfiles[idx].Notes...)
	}
	profile.Notes = append([]string(nil), profile.Notes...)
	return profile
}

func buildDefaultDictionaryReleaseBaseProfile() DictionaryReleaseProfile {
	profile := defaultDictionaryReleaseContract.profile
	profile.RFCs = append([]string(nil), profile.RFCs...)
	profile.VendorAliases = append([]DictionaryVendorAlias(nil), profile.VendorAliases...)
	profile.AttributeAliases = append([]DictionaryAttributeAlias(nil), profile.AttributeAliases...)
	profile.FirmwareProfiles = append([]DictionaryFirmwareProfile(nil), profile.FirmwareProfiles...)
	profile.Notes = append([]string(nil), profile.Notes...)
	profile.VendorAliasCount = len(profile.VendorAliases)
	profile.AttributeAliasCount = len(profile.AttributeAliases)
	profile.FirmwareProfileCount = len(profile.FirmwareProfiles)
	sort.Slice(profile.VendorAliases, func(i, j int) bool {
		return strings.ToLower(profile.VendorAliases[i].Alias) < strings.ToLower(profile.VendorAliases[j].Alias)
	})
	sort.Slice(profile.AttributeAliases, func(i, j int) bool {
		left := strings.ToLower(profile.AttributeAliases[i].Vendor + "\x00" + profile.AttributeAliases[i].Alias)
		right := strings.ToLower(profile.AttributeAliases[j].Vendor + "\x00" + profile.AttributeAliases[j].Alias)
		return left < right
	})
	sort.Slice(profile.FirmwareProfiles, func(i, j int) bool {
		return strings.ToLower(profile.FirmwareProfiles[i].Key) < strings.ToLower(profile.FirmwareProfiles[j].Key)
	})
	return profile
}

func dictionaryReleaseBaseProfileByID(id string) DictionaryReleaseProfile {
	if EffectiveDictionaryReleaseProfileID(id) == DefaultDictionaryReleaseProfileID {
		return cachedDefaultDictionaryReleaseBaseProfile
	}
	return cachedDefaultDictionaryReleaseBaseProfile
}

func normalizedDictionaryReleaseKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, " ", "-")
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return value
}

func trimDictionaryAttributePrefix(attribute, vendor string) string {
	attribute = strings.TrimSpace(attribute)
	vendor = NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, vendor)
	vendorKey := normalizedDictionaryReleaseKey(vendor)
	attrKey := normalizedDictionaryReleaseKey(attribute)
	if vendorKey != "" && strings.HasPrefix(attrKey, vendorKey+"-") {
		return attribute[len(vendor)+1:]
	}
	if prefix, suffix, ok := strings.Cut(attribute, "."); ok && normalizedDictionaryReleaseKey(prefix) == vendorKey {
		return suffix
	}
	return attribute
}

func validateDictionaryVendorAliases(profile DictionaryReleaseProfile) error {
	seen := map[string]string{}
	for _, alias := range profile.VendorAliases {
		key := normalizedDictionaryReleaseKey(alias.Alias)
		if key == "" || strings.TrimSpace(alias.CanonicalVendor) == "" {
			return fmt.Errorf("dictionary release profile %s contains an invalid vendor alias", profile.ID)
		}
		if existing, exists := seen[key]; exists && existing != alias.CanonicalVendor {
			return fmt.Errorf("dictionary release profile %s aliases %q to both %q and %q", profile.ID, alias.Alias, existing, alias.CanonicalVendor)
		}
		seen[key] = alias.CanonicalVendor
	}
	return nil
}

func validateDictionaryAttributeAliases(profile DictionaryReleaseProfile, registry *AttributeRegistry) error {
	for _, alias := range profile.AttributeAliases {
		if strings.TrimSpace(alias.Vendor) == "" || strings.TrimSpace(alias.Alias) == "" || strings.TrimSpace(alias.CanonicalAttribute) == "" {
			return fmt.Errorf("dictionary release profile %s contains an invalid attribute alias", profile.ID)
		}
		if _, ok := registry.LookupName(alias.Vendor, alias.CanonicalAttribute); !ok {
			return fmt.Errorf("dictionary release profile %s attribute alias %s/%s points to an unknown registry entry", profile.ID, alias.Vendor, alias.CanonicalAttribute)
		}
	}
	return nil
}

func validateDictionaryFirmwareProfiles(profile DictionaryReleaseProfile, packs []VendorCompatibilityPack) error {
	packByKey := map[string]VendorCompatibilityPack{}
	for _, pack := range packs {
		packByKey[NormalizeDictionaryPackAlias(profile.ID, pack.Key)] = pack
	}
	seen := map[string]struct{}{}
	for _, firmware := range profile.FirmwareProfiles {
		key := strings.ToLower(strings.TrimSpace(firmware.Key))
		if key == "" {
			return fmt.Errorf("dictionary release profile %s contains an empty firmware profile key", profile.ID)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("dictionary release profile %s duplicates firmware profile %q", profile.ID, firmware.Key)
		}
		seen[key] = struct{}{}
		packKey := NormalizeDictionaryPackAlias(profile.ID, firmware.PackKey)
		pack, ok := packByKey[packKey]
		if !ok {
			return fmt.Errorf("dictionary release profile %s firmware profile %q references unknown pack %q", profile.ID, firmware.Key, firmware.PackKey)
		}
		if pack.VendorID > 0 && firmware.PEN != 0 && pack.VendorID != int(firmware.PEN) {
			return fmt.Errorf("dictionary release profile %s firmware profile %q PEN %d conflicts with pack PEN %d", profile.ID, firmware.Key, firmware.PEN, pack.VendorID)
		}
		if len(firmware.HardwareProfiles) == 0 || strings.TrimSpace(firmware.ProductFamily) == "" || strings.TrimSpace(firmware.FirmwareScope) == "" {
			return fmt.Errorf("dictionary release profile %s firmware profile %q is incomplete", profile.ID, firmware.Key)
		}
	}
	return nil
}
