package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	AegisNASVendorAttrRole             byte = 1
	AegisNASVendorAttrBandwidthProfile byte = 2
	AegisNASVendorAttrVLAN             byte = 3
	AegisNASVendorAttrQuarantine       byte = 4
	AegisNASVendorAttrPolicyTag        byte = 5
	AegisNASVendorAttrSessionTimeout   byte = 6
	AegisNASVendorAttrIdleTimeout      byte = 7
	AegisNASVendorAttrSessionAction    byte = 8
	AegisNASVendorAttrPortalProfile    byte = 9
	AegisNASVendorAttrDeviceGroup      byte = 10
	AegisNASVendorAttrTenant           byte = 11
	AegisNASVendorAttrACLName          byte = 12
	AegisNASVendorAttrACLRule          byte = 13
)

type inboundVendorValueKind string

const (
	inboundVendorString       inboundVendorValueKind = "string"
	inboundVendorVLAN         inboundVendorValueKind = "vlan"
	inboundVendorRateKbps     inboundVendorValueKind = "rate_kbps"
	inboundVendorRateBps      inboundVendorValueKind = "rate_bps"
	inboundVendorBool         inboundVendorValueKind = "bool"
	inboundVendorIntText      inboundVendorValueKind = "integer_text"
	inboundVendorMappedRole   inboundVendorValueKind = "mapped_role"
	inboundVendorExtendedVLAN inboundVendorValueKind = "extended_vlan"
	inboundVendorAVPairs      inboundVendorValueKind = "avpairs"
	inboundVendorMappedPortal inboundVendorValueKind = "mapped_portal_status"
	inboundVendorMappedAction inboundVendorValueKind = "mapped_session_action"
	inboundVendorQuota        inboundVendorValueKind = "data_quota"
)

type inboundVendorMapping struct {
	PackKey   string
	VendorID  uint32
	Type      byte
	Attribute string
	Semantic  string
	Kind      inboundVendorValueKind
}

var inboundVendorMappings = []inboundVendorMapping{
	{PackKey: productconfigs.VendorPackCisco, VendorID: 9, Type: 57, Attribute: "Cisco-In-ACL", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackCisco, VendorID: 9, Type: 58, Attribute: "Cisco-Out-ACL", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackCisco, VendorID: 9, Type: 1, Attribute: "Cisco-AVPair", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 1, Attribute: "Aruba-User-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 2, Attribute: "Aruba-User-Vlan", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 10, Attribute: "Aruba-AP-Group", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 12, Attribute: "Aruba-Device-Type", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 19, Attribute: "Aruba-Mdps-Device-Name", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 36, Attribute: "Aruba-User-Group", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 43, Attribute: "Aruba-Captive-Portal-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAruba, VendorID: 14823, Type: 51, Attribute: "Aruba-NAS-Filter-Rule", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 1, Attribute: "Ruckus-User-Groups", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 9, Attribute: "Ruckus-VLAN-ID", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 132, Attribute: "Ruckus-Wispr-Redirect-Policy", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 134, Attribute: "Ruckus-Zone-Name", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 138, Attribute: "Ruckus-Client-Host-Name", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 139, Attribute: "Ruckus-Client-Os-Type", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 140, Attribute: "Ruckus-Client-Os-Class", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 155, Attribute: "Ruckus-Domain-Name", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackRuckus, VendorID: 25053, Type: 156, Attribute: "Ruckus-Client-Device-Type", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackFortinet, VendorID: 12356, Type: 1, Attribute: "Fortinet-Group-Name", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackFortinet, VendorID: 12356, Type: 6, Attribute: "Fortinet-Access-Profile", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackFortinet, VendorID: 12356, Type: 8, Attribute: "Fortinet-AP-Name", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackFortinet, VendorID: 12356, Type: 24, Attribute: "Fortinet-WirelessController-WTP-ID", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackFortinet, VendorID: 12356, Type: 41, Attribute: "Fortinet-Tenant-Identification", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackUBNT, VendorID: 41112, Type: 1, Attribute: "UBNT-Data-Rate-DL", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateBps},
	{PackKey: productconfigs.VendorPackUBNT, VendorID: 41112, Type: 3, Attribute: "UBNT-Data-Rate-UL", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateBps},

	{PackKey: productconfigs.VendorPackCambium, VendorID: 17713, Type: 21, Attribute: "Cambium-ePMP-Data-VLAN-Id", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackCambium, VendorID: 17713, Type: 1, Attribute: "Cambium-Auth-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorMappedRole},
	{PackKey: productconfigs.VendorPackCambium, VendorID: 17713, Type: 26, Attribute: "Cambium-ePMP-Max-Burst-Uplink-Rate", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackCambium, VendorID: 17713, Type: 27, Attribute: "Cambium-ePMP-Max-Burst-Downlink-Rate", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackCambium, VendorID: 17713, Type: 160, Attribute: "Cambium-Walled-Garden-State", Semantic: productconfigs.VendorSemanticQuarantine, Kind: inboundVendorBool},

	{PackKey: productconfigs.VendorPackMeraki, VendorID: 29671, Type: 1, Attribute: "Meraki-Device-Name", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackMeraki, VendorID: 29671, Type: 2, Attribute: "Meraki-Network-Name", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackMeraki, VendorID: 29671, Type: 3, Attribute: "Meraki-Ap-Name", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackMeraki, VendorID: 29671, Type: 4, Attribute: "Meraki-Ap-Tags", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackExtreme, VendorID: 1916, Type: 203, Attribute: "Extreme-Netlogin-Vlan", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackExtreme, VendorID: 1916, Type: 204, Attribute: "Extreme-Netlogin-Url", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackExtreme, VendorID: 1916, Type: 209, Attribute: "Extreme-Netlogin-Vlan-Tag", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackExtreme, VendorID: 1916, Type: 211, Attribute: "Extreme-Netlogin-Extended-Vlan", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorExtendedVLAN},
	{PackKey: productconfigs.VendorPackExtreme, VendorID: 1916, Type: 212, Attribute: "Extreme-Security-Profile", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 1, Attribute: "Juniper-Local-User-Name", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 44, Attribute: "Juniper-Firewall-filter-name", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 46, Attribute: "Juniper-Local-Group-Name", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 48, Attribute: "Juniper-Switching-Filter", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 50, Attribute: "Juniper-CWA-Redirect", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackJuniper, VendorID: 2636, Type: 52, Attribute: "Juniper-AV-Pair", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorAVPairs},

	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 5, Attribute: "Huawei-Output-Average-Rate", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 2, Attribute: "Huawei-Input-Average-Rate", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 31, Attribute: "Huawei-Qos-Profile-Name", Semantic: productconfigs.VendorSemanticBandwidthProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 66, Attribute: "Huawei-User-Class", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 82, Attribute: "Huawei-Data-Filter", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 140, Attribute: "Huawei-HTTP-Redirect-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 182, Attribute: "Huawei-Down-QOS-Profile-Name", Semantic: productconfigs.VendorSemanticBandwidthProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHuawei, VendorID: 2011, Type: 188, Attribute: "Huawei-AVpair", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorAVPairs},

	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 5, Attribute: "H3C-Output-Average-Rate", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 2, Attribute: "H3C-Input-Average-Rate", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 27, Attribute: "H3C-Portal-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 140, Attribute: "H3C-User-Group", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 155, Attribute: "H3C-User-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 216, Attribute: "H3C-Ita-Policy", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackH3C, VendorID: 25506, Type: 210, Attribute: "H3C-Av-Pair", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorAVPairs},

	{PackKey: productconfigs.VendorPackPaloAlto, VendorID: 25461, Type: 1, Attribute: "PaloAlto-Admin-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPaloAlto, VendorID: 25461, Type: 2, Attribute: "PaloAlto-Admin-Access-Domain", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPaloAlto, VendorID: 25461, Type: 5, Attribute: "PaloAlto-User-Group", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPaloAlto, VendorID: 25461, Type: 8, Attribute: "PaloAlto-Client-OS", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPaloAlto, VendorID: 25461, Type: 9, Attribute: "PaloAlto-Client-Hostname", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 1, Attribute: "TPLink-Recv-limit", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 2, Attribute: "TPLink-Xmit-limit", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 6, Attribute: "TPLink-Site", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 7, Attribute: "TPLink-Omada", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 8, Attribute: "TPLink-Redirect-Url", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackTPLink, VendorID: 11863, Type: 9, Attribute: "TPLink-Portal-Access-Status", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorMappedPortal},

	{PackKey: productconfigs.VendorPackAerohive, VendorID: 26928, Type: 1, Attribute: "Extreme-User-Vlan", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackAerohive, VendorID: 26928, Type: 6, Attribute: "Extreme-User-Profile-Attribute", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorMappedRole},
	{PackKey: productconfigs.VendorPackAerohive, VendorID: 26928, Type: 8, Attribute: "Extreme-AVPair", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAerohive, VendorID: 26928, Type: 210, Attribute: "Extreme-Client-Monitor-Problem", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorIntText},
	{PackKey: productconfigs.VendorPackAerohive, VendorID: 26928, Type: 211, Attribute: "Extreme-IDM-Redirect-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackAirespace, VendorID: 14179, Type: 1, Attribute: "Wlan-Id", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorIntText},
	{PackKey: productconfigs.VendorPackAirespace, VendorID: 14179, Type: 6, Attribute: "ACL-Name", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAirespace, VendorID: 14179, Type: 7, Attribute: "Data-Bandwidth-Average-Contract", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackAirespace, VendorID: 14179, Type: 11, Attribute: "Guest-Role-Name", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackAirespace, VendorID: 14179, Type: 13, Attribute: "Data-Bandwidth-Average-Contract-Upstream", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},

	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 24, Attribute: "Captive-Portal-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 25, Attribute: "User-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 27, Attribute: "CPPM-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 46, Attribute: "Bandwidth-Max-Ingress", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 48, Attribute: "Bandwidth-Max-Egress", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 61, Attribute: "Ip-Filter-Raw", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 62, Attribute: "Access-Profile", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackHP, VendorID: 11, Type: 64, Attribute: "Egress-VLANID", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},

	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 1, Attribute: "Nomadix-Bw-Up", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 2, Attribute: "Nomadix-Bw-Down", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 3, Attribute: "Nomadix-URL-Redirection", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 9, Attribute: "Nomadix-EndofSession", Semantic: productconfigs.VendorSemanticSessionAction, Kind: inboundVendorMappedAction},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 11, Attribute: "Nomadix-Net-VLAN", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 14, Attribute: "Nomadix-Qos-Policy", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackNomadix, VendorID: 3309, Type: 27, Attribute: "Nomadix-Bw-Class-Name", Semantic: productconfigs.VendorSemanticBandwidthProfile, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackChilliSpot, VendorID: 14559, Type: 3, Attribute: "ChilliSpot-Max-Total-Octets", Semantic: productconfigs.VendorSemanticDataQuota, Kind: inboundVendorQuota},
	{PackKey: productconfigs.VendorPackChilliSpot, VendorID: 14559, Type: 4, Attribute: "ChilliSpot-Bandwidth-Max-Up", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackChilliSpot, VendorID: 14559, Type: 5, Attribute: "ChilliSpot-Bandwidth-Max-Down", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackChilliSpot, VendorID: 14559, Type: 6, Attribute: "ChilliSpot-Config", Semantic: productconfigs.VendorSemanticPolicyTag, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackChilliSpot, VendorID: 14559, Type: 100, Attribute: "ChilliSpot-UAM-Allowed", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 2, Attribute: "Ingress-Bandwidth-Assignment", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 1, Attribute: "User-Level", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorMappedRole},
	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 3, Attribute: "Egress-Bandwidth-Assignment", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 11, Attribute: "VLAN-ID", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 12, Attribute: "ACL-Profile", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackDLink, VendorID: 171, Type: 13, Attribute: "ACL-Rule", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackSonicWall, VendorID: 8741, Type: 3, Attribute: "User-Group", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackSonicWall, VendorID: 8741, Type: 1, Attribute: "User-Privilege", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorMappedRole},

	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 3, Attribute: "User-Role", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 10, Attribute: "Captive-Portal", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 11, Attribute: "Segment-Id", Semantic: productconfigs.VendorSemanticVLAN, Kind: inboundVendorVLAN},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 17, Attribute: "Device-Profiling", Semantic: productconfigs.VendorSemanticDevicePosture, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 20, Attribute: "Tenant-Id", Semantic: productconfigs.VendorSemanticTenant, Kind: inboundVendorIntText},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 21, Attribute: "Interface-Profile", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackArista, VendorID: 30065, Type: 1, Attribute: "Arista-AVPair", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorAVPairs},

	{PackKey: productconfigs.VendorPackPica8, VendorID: 35098, Type: 2, Attribute: "IP-Downloadable-ACL-Rule", Semantic: productconfigs.VendorSemanticDynamicACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPica8, VendorID: 35098, Type: 3, Attribute: "IP-Downloadable-ACL-Name", Semantic: productconfigs.VendorSemanticACL, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackPica8, VendorID: 35098, Type: 4, Attribute: "Redirect-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 27, Attribute: "PPPOE-URL", Semantic: productconfigs.VendorSemanticPortalProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 104, Attribute: "SW-Privilege", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorMappedRole},
	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 82, Attribute: "QoS-Profile-Down", Semantic: productconfigs.VendorSemanticBandwidthProfile, Kind: inboundVendorString},
	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 83, Attribute: "Rate-Ctrl-SCR-Down", Semantic: productconfigs.VendorSemanticDownloadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 89, Attribute: "Rate-Ctrl-SCR-Up", Semantic: productconfigs.VendorSemanticUploadBandwidth, Kind: inboundVendorRateKbps},
	{PackKey: productconfigs.VendorPackZTE, VendorID: 3902, Type: 94, Attribute: "QOS-Profile-Up", Semantic: productconfigs.VendorSemanticBandwidthProfile, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackNokia, VendorID: 94, Type: 2, Attribute: "User-Profile", Semantic: productconfigs.VendorSemanticRole, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackMeru, VendorID: 15983, Type: 1, Attribute: "Access-Point-Id", Semantic: productconfigs.VendorSemanticDeviceGroup, Kind: inboundVendorIntText},
	{PackKey: productconfigs.VendorPackMeru, VendorID: 15983, Type: 2, Attribute: "Access-Point-Name", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},

	{PackKey: productconfigs.VendorPackColubris, VendorID: 8744, Type: 1, Attribute: "Intercept", Semantic: productconfigs.VendorSemanticQuarantine, Kind: inboundVendorBool},

	{PackKey: productconfigs.VendorPackOpenWiFi, VendorID: 58888, Type: 1, Attribute: "AP-MAC-Address", Semantic: productconfigs.VendorSemanticAccountingIdentity, Kind: inboundVendorString},
}

// EffectiveVendorAttributes returns the built-in AegisNAS VSA dictionary plus
// any operator-provided additions or overrides.
func EffectiveVendorAttributes(vendor config.RadiusVendorConfig) []config.RadiusVendorAttribute {
	productAttrs := productVendorAttributes()
	attrs := make([]config.RadiusVendorAttribute, 0, len(productAttrs)+len(vendor.Attributes))
	byName := make(map[string]int)
	byNumber := make(map[int]int)
	rebuildIndexes := func() {
		clear(byName)
		clear(byNumber)
		for i, attr := range attrs {
			byName[strings.ToLower(attr.Name)] = i
			byNumber[attr.Number] = i
		}
	}
	removeAt := func(idx int) {
		if idx < 0 || idx >= len(attrs) {
			return
		}
		attrs = append(attrs[:idx], attrs[idx+1:]...)
		rebuildIndexes()
	}

	upsert := func(attr config.RadiusVendorAttribute) {
		normalized, ok := normalizeVendorAttribute(attr)
		if !ok {
			return
		}
		nameKey := strings.ToLower(normalized.Name)
		if idx, exists := byName[nameKey]; exists {
			if numberIdx, numberExists := byNumber[normalized.Number]; numberExists && numberIdx != idx {
				removeAt(numberIdx)
				if numberIdx < idx {
					idx--
				}
			}
			attrs[idx] = normalized
			rebuildIndexes()
			return
		}
		if idx, exists := byNumber[normalized.Number]; exists {
			attrs[idx] = normalized
			rebuildIndexes()
			return
		}
		attrs = append(attrs, normalized)
		rebuildIndexes()
	}

	for _, attr := range productAttrs {
		upsert(attr)
	}
	for _, attr := range vendor.Attributes {
		upsert(attr)
	}
	return attrs
}

func productVendorAttributes() []config.RadiusVendorAttribute {
	dict := productconfigs.AegisNASVendorDictionary()
	attrs := make([]config.RadiusVendorAttribute, 0, len(dict.Attributes))
	for _, attr := range dict.Attributes {
		attrs = append(attrs, config.RadiusVendorAttribute{
			Name:   attr.Name,
			Number: attr.Number,
			Type:   attr.Type,
		})
	}
	return attrs
}

func normalizeVendorAttribute(attr config.RadiusVendorAttribute) (config.RadiusVendorAttribute, bool) {
	attr.Name = strings.TrimSpace(attr.Name)
	attr.Type = strings.ToLower(strings.TrimSpace(attr.Type))
	if attr.Type == "" {
		attr.Type = "string"
	}
	if attr.Name == "" || attr.Number < 1 || attr.Number > 255 {
		return config.RadiusVendorAttribute{}, false
	}
	return attr, true
}

func ParseBrokerPacketWithConfig(packet *layehradius.Packet, cfg *config.Config) *BrokerAuthResult {
	result := ParseBrokerPacket(packet)
	if cfg != nil {
		ApplyVendorAttributes(result, packet, cfg.Radius.Vendor)
	}
	return result
}

func ApplyVendorAttributes(result *BrokerAuthResult, packet *layehradius.Packet, vendor config.RadiusVendorConfig) {
	if result == nil || packet == nil || !vendor.Enabled {
		return
	}

	if vendor.ID >= 1 {
		attrs := EffectiveVendorAttributes(vendor)
		vendorID := uint32(vendor.ID)

		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrRole)); ok {
			result.VendorRole = value
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrBandwidthProfile)); ok {
			result.VendorBandwidthProfile = value
		}
		if value, ok := lookupVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrVLAN)); ok {
			result.VendorVLAN = int(value)
			result.HasVendorVLAN = true
		}
		if value, ok := lookupVendorBool(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrQuarantine)); ok {
			result.VendorQuarantine = value
			result.HasVendorQuarantine = true
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrPolicyTag)); ok {
			result.VendorPolicyTag = value
		}
		if value, ok := lookupVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrSessionTimeout)); ok {
			result.VendorSessionTimeout = int(value)
			result.HasVendorSessionTimeout = true
		}
		if value, ok := lookupVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrIdleTimeout)); ok {
			result.VendorIdleTimeout = int(value)
			result.HasVendorIdleTimeout = true
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrSessionAction)); ok {
			result.VendorSessionAction = value
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrPortalProfile)); ok {
			result.VendorPortalProfile = value
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrDeviceGroup)); ok {
			result.VendorDeviceGroup = value
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrTenant)); ok {
			result.VendorTenant = value
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrACLName)); ok {
			setStringIfEmpty(&result.VendorInboundACL, value)
		}
		if value, ok := lookupVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrACLRule)); ok {
			setStringIfEmpty(&result.VendorInboundACL, value)
		}
	}

	applyVendorCompatibilityAttributes(result, packet, vendor)
}

func AddVendorAccountingAttributes(packet *layehradius.Packet, vendor config.RadiusVendorConfig, rec *AccountingRecord) error {
	if packet == nil || rec == nil || !vendor.Enabled || vendor.ID < 1 {
		return nil
	}

	attrs := EffectiveVendorAttributes(vendor)
	vendorID := uint32(vendor.ID)
	if rec.Role != "" {
		if err := addVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrRole), rec.Role); err != nil {
			return err
		}
	}
	if rec.BandwidthProfile != "" {
		if err := addVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrBandwidthProfile), rec.BandwidthProfile); err != nil {
			return err
		}
	}
	if rec.VLAN > 0 {
		if err := addVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrVLAN), uint32(rec.VLAN)); err != nil {
			return err
		}
	}
	if rec.FilterID != "" {
		if err := addVendorString(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrPolicyTag), rec.FilterID); err != nil {
			return err
		}
	}
	if rec.SessionTimeout > 0 {
		if err := addVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrSessionTimeout), uint32(rec.SessionTimeout)); err != nil {
			return err
		}
	}
	if rec.IdleTimeout > 0 {
		if err := addVendorInteger(packet, vendorID, vendorAttributeNumber(attrs, AegisNASVendorAttrIdleTimeout), uint32(rec.IdleTimeout)); err != nil {
			return err
		}
	}
	return nil
}

func applyVendorCompatibilityAttributes(result *BrokerAuthResult, packet *layehradius.Packet, vendor config.RadiusVendorConfig) {
	activePacks := map[string]struct{}{}
	for _, key := range normalizeReplyPackKeys(vendor.CompatibilityPacks) {
		activePacks[key] = struct{}{}
	}
	for _, mapping := range inboundVendorMappings {
		if _, ok := activePacks[mapping.PackKey]; !ok {
			continue
		}
		applyInboundVendorMapping(result, packet, mapping, vendor)
	}
}

func applyInboundVendorMapping(result *BrokerAuthResult, packet *layehradius.Packet, mapping inboundVendorMapping, vendor config.RadiusVendorConfig) {
	switch mapping.Kind {
	case inboundVendorString:
		value, ok := lookupVendorString(packet, mapping.VendorID, mapping.Type)
		if !ok {
			return
		}
		applyInboundVendorString(result, mapping, value)
	case inboundVendorVLAN:
		value, ok := lookupVendorVLAN(packet, mapping.VendorID, mapping.Type)
		if !ok || value <= 0 {
			return
		}
		if !result.HasVendorVLAN {
			result.VendorVLAN = value
			result.HasVendorVLAN = true
		}
	case inboundVendorRateKbps:
		value, ok := lookupVendorRate(packet, mapping.VendorID, mapping.Type, 1)
		if ok {
			applyInboundVendorRate(result, mapping.Semantic, value)
		}
	case inboundVendorRateBps:
		value, ok := lookupVendorRate(packet, mapping.VendorID, mapping.Type, 1000)
		if ok {
			applyInboundVendorRate(result, mapping.Semantic, value)
		}
	case inboundVendorBool:
		value, ok := lookupVendorBool(packet, mapping.VendorID, mapping.Type)
		if ok && !result.HasVendorQuarantine {
			result.VendorQuarantine = value
			result.HasVendorQuarantine = true
		}
	case inboundVendorIntText:
		value, ok := lookupVendorInteger(packet, mapping.VendorID, mapping.Type)
		if ok {
			applyInboundVendorString(result, mapping, strconv.Itoa(int(value)))
		}
	case inboundVendorMappedRole:
		value, ok := lookupVendorInteger(packet, mapping.VendorID, mapping.Type)
		if !ok {
			return
		}
		if role, found := numericVendorRoleName(vendor.RoleMappings, mapping.PackKey, value); found {
			setStringIfEmpty(&result.VendorRole, role)
		}
	case inboundVendorExtendedVLAN:
		value, ok := lookupVendorString(packet, mapping.VendorID, mapping.Type)
		if !ok {
			return
		}
		untagged, hasUntagged, tagged, ok := parseExtremeExtendedVLAN(value)
		if !ok {
			return
		}
		if hasUntagged {
			result.VendorVLAN = untagged
			result.HasVendorVLAN = true
		}
		result.VendorTaggedVLANs = append([]int(nil), tagged...)
	case inboundVendorAVPairs:
		for _, value := range lookupVendorStrings(packet, mapping.VendorID, mapping.Type) {
			appendUniqueVendorAVPair(result, value)
		}
	case inboundVendorMappedPortal:
		value, ok := lookupVendorInteger(packet, mapping.VendorID, mapping.Type)
		if !ok {
			return
		}
		if profile, found := numericVendorPortalProfile(vendor.PortalStatusMappings, mapping.PackKey, value); found {
			setStringIfEmpty(&result.VendorPortalProfile, profile)
		}
	case inboundVendorMappedAction:
		value, ok := lookupVendorInteger(packet, mapping.VendorID, mapping.Type)
		if !ok {
			return
		}
		if action, found := numericVendorSessionAction(vendor.SessionActionMappings, mapping.PackKey, value); found {
			setStringIfEmpty(&result.VendorSessionAction, action)
		}
	case inboundVendorQuota:
		value, ok := lookupVendorInteger(packet, mapping.VendorID, mapping.Type)
		if ok && value > 0 {
			result.VendorMaxTotalOctets = uint64(value)
			result.HasVendorMaxTotalOctets = true
		}
	}
}

func numericVendorSessionAction(mappings []config.RadiusVendorSessionActionMapping, packKey string, value uint32) (string, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != packKey || mapping.Value < 0 || uint64(mapping.Value) != uint64(value) {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(mapping.Action))
		if action != "" {
			return action, true
		}
	}
	return "", false
}

func numericVendorPortalProfile(mappings []config.RadiusVendorPortalStatusMapping, packKey string, value uint32) (string, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != packKey || mapping.Value < 0 || uint64(mapping.Value) != uint64(value) {
			continue
		}
		profile := strings.TrimSpace(mapping.PortalProfile)
		if profile != "" {
			return profile, true
		}
	}
	return "", false
}

func appendUniqueVendorAVPair(result *BrokerAuthResult, value string) {
	value = strings.TrimSpace(value)
	if result == nil || value == "" || len(value) > 240 || len(result.VendorAVPairs) >= 16 {
		return
	}
	for _, existing := range result.VendorAVPairs {
		if existing == value {
			return
		}
	}
	result.VendorAVPairs = append(result.VendorAVPairs, value)
}

func parseExtremeExtendedVLAN(value string) (int, bool, []int, bool) {
	parts := strings.Split(strings.TrimSpace(value), ";")
	seen := map[int]struct{}{}
	tagged := make([]int, 0, len(parts))
	untagged := 0
	hasUntagged := false
	assignmentCount := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		assignmentCount++
		if assignmentCount > 10 || len(part) < 2 {
			return 0, false, nil, false
		}
		kind := part[0]
		if kind != 'U' && kind != 'u' && kind != 'T' && kind != 't' {
			return 0, false, nil, false
		}
		vlan, err := strconv.Atoi(part[1:])
		if err != nil || vlan < 1 || vlan > 4094 {
			return 0, false, nil, false
		}
		if _, exists := seen[vlan]; exists {
			return 0, false, nil, false
		}
		seen[vlan] = struct{}{}
		if kind == 'U' || kind == 'u' {
			if hasUntagged {
				return 0, false, nil, false
			}
			untagged = vlan
			hasUntagged = true
			continue
		}
		tagged = append(tagged, vlan)
	}
	if assignmentCount == 0 {
		return 0, false, nil, false
	}
	return untagged, hasUntagged, tagged, true
}

func numericVendorRoleName(mappings []config.RadiusVendorRoleMapping, packKey string, value uint32) (string, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != packKey || mapping.Value < 0 || uint64(mapping.Value) != uint64(value) {
			continue
		}
		role := strings.TrimSpace(mapping.Role)
		if role != "" {
			return role, true
		}
	}
	return "", false
}

func applyInboundVendorString(result *BrokerAuthResult, mapping inboundVendorMapping, value string) {
	switch mapping.Semantic {
	case productconfigs.VendorSemanticRole:
		setStringIfEmpty(&result.VendorRole, value)
	case productconfigs.VendorSemanticBandwidthProfile:
		setStringIfEmpty(&result.VendorBandwidthProfile, value)
	case productconfigs.VendorSemanticPolicyTag:
		setStringIfEmpty(&result.VendorPolicyTag, value)
	case productconfigs.VendorSemanticPortalProfile:
		setStringIfEmpty(&result.VendorPortalProfile, value)
	case productconfigs.VendorSemanticDeviceGroup:
		setStringIfEmpty(&result.VendorDeviceGroup, value)
	case productconfigs.VendorSemanticTenant:
		setStringIfEmpty(&result.VendorTenant, value)
	case productconfigs.VendorSemanticDevicePosture:
		setStringIfEmpty(&result.VendorDevicePosture, value)
	case productconfigs.VendorSemanticAccountingIdentity:
		setStringIfEmpty(&result.VendorAccountingIdentity, value)
	case productconfigs.VendorSemanticACL:
		applyInboundVendorACL(result, mapping.Attribute, value)
	case productconfigs.VendorSemanticDynamicACL:
		setStringIfEmpty(&result.VendorInboundACL, value)
	}
}

func applyInboundVendorACL(result *BrokerAuthResult, attribute, value string) {
	normalized := strings.ToLower(attribute)
	switch {
	case strings.Contains(normalized, "out"):
		setStringIfEmpty(&result.VendorOutboundACL, value)
	default:
		setStringIfEmpty(&result.VendorInboundACL, value)
	}
}

func applyInboundVendorRate(result *BrokerAuthResult, semantic string, value int) {
	if value <= 0 {
		return
	}
	switch semantic {
	case productconfigs.VendorSemanticDownloadBandwidth:
		if result.WISPrBandwidthMaxDown == 0 {
			result.WISPrBandwidthMaxDown = value
		}
	case productconfigs.VendorSemanticUploadBandwidth:
		if result.WISPrBandwidthMaxUp == 0 {
			result.WISPrBandwidthMaxUp = value
		}
	}
}

func setStringIfEmpty(dst *string, value string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.TrimSpace(*dst) != "" {
		return
	}
	*dst = value
}

func vendorAttributeNumber(attrs []config.RadiusVendorAttribute, productNumber byte) byte {
	name := productVendorAttributeName(productNumber)
	for _, attr := range attrs {
		if strings.EqualFold(strings.TrimSpace(attr.Name), name) && attr.Number >= 1 && attr.Number <= 255 {
			return byte(attr.Number)
		}
	}
	return productNumber
}

func productVendorAttributeName(number byte) string {
	for _, attr := range productVendorAttributes() {
		if attr.Number == int(number) {
			return attr.Name
		}
	}
	return ""
}

func lookupVendorString(packet *layehradius.Packet, vendorID uint32, typ byte) (string, bool) {
	attr, ok := lookupVendorAttribute(packet, vendorID, typ)
	if !ok {
		return "", false
	}
	value := strings.TrimSpace(layehradius.String(attr))
	return value, value != ""
}

func lookupVendorStrings(packet *layehradius.Packet, vendorID uint32, typ byte) []string {
	if packet == nil {
		return nil
	}
	values := make([]string, 0, 2)
	for _, avp := range packet.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		gotVendorID, vsa, err := layehradius.VendorSpecific(avp.Attribute)
		if err != nil || gotVendorID != vendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaType, vsaLen := vsa[0], int(vsa[1])
			if vsaLen > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaType == typ {
				values = append(values, string(vsa[2:vsaLen]))
			}
			vsa = vsa[vsaLen:]
		}
	}
	return values
}

func lookupVendorInteger(packet *layehradius.Packet, vendorID uint32, typ byte) (uint32, bool) {
	value, ok := lookupVendorUnsigned(packet, vendorID, typ)
	if !ok || value > uint64(^uint32(0)) {
		return 0, false
	}
	return uint32(value), true
}

func lookupVendorVLAN(packet *layehradius.Packet, vendorID uint32, typ byte) (int, bool) {
	if value, ok := lookupVendorInteger(packet, vendorID, typ); ok {
		return int(value), true
	}
	text, ok := lookupVendorString(packet, vendorID, typ)
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, false
	}
	return value, true
}

func lookupVendorRate(packet *layehradius.Packet, vendorID uint32, typ byte, scale int) (int, bool) {
	value, ok := lookupVendorUnsigned(packet, vendorID, typ)
	if !ok {
		return 0, false
	}
	if scale > 1 {
		value = value / uint64(scale)
	}
	maxInt := uint64(^uint(0) >> 1)
	if value == 0 || value > maxInt {
		return 0, false
	}
	return int(value), true
}

func lookupVendorUnsigned(packet *layehradius.Packet, vendorID uint32, typ byte) (uint64, bool) {
	attr, ok := lookupVendorAttribute(packet, vendorID, typ)
	if !ok {
		return 0, false
	}
	switch len(attr) {
	case 4:
		return uint64(binary.BigEndian.Uint32(attr)), true
	case 8:
		return binary.BigEndian.Uint64(attr), true
	default:
		value, err := layehradius.Integer(attr)
		return uint64(value), err == nil
	}
}

func lookupVendorBool(packet *layehradius.Packet, vendorID uint32, typ byte) (bool, bool) {
	if value, ok := lookupVendorInteger(packet, vendorID, typ); ok {
		return value != 0, true
	}
	text, ok := lookupVendorString(packet, vendorID, typ)
	if !ok {
		return false, false
	}
	switch strings.ToLower(text) {
	case "1", "true", "yes", "on", "quarantine":
		return true, true
	case "0", "false", "no", "off", "allow":
		return false, true
	default:
		return false, false
	}
}

func lookupVendorAttribute(packet *layehradius.Packet, vendorID uint32, typ byte) (layehradius.Attribute, bool) {
	for _, avp := range packet.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		gotVendorID, vsa, err := layehradius.VendorSpecific(avp.Attribute)
		if err != nil || gotVendorID != vendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaType, vsaLen := vsa[0], int(vsa[1])
			if vsaLen > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaType == typ {
				attr := make(layehradius.Attribute, vsaLen-2)
				copy(attr, vsa[2:vsaLen])
				return attr, true
			}
			vsa = vsa[vsaLen:]
		}
	}
	return nil, false
}

func addVendorString(packet *layehradius.Packet, vendorID uint32, typ byte, value string) error {
	attr, err := layehradius.NewString(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	return addVendorAttribute(packet, vendorID, typ, attr)
}

func addVendorInteger(packet *layehradius.Packet, vendorID uint32, typ byte, value uint32) error {
	return addVendorAttribute(packet, vendorID, typ, layehradius.NewInteger(value))
}

func addVendorInteger64(packet *layehradius.Packet, vendorID uint32, typ byte, value uint64) error {
	attr := make(layehradius.Attribute, 8)
	binary.BigEndian.PutUint64(attr, value)
	return addVendorAttribute(packet, vendorID, typ, attr)
}

func addVendorAttribute(packet *layehradius.Packet, vendorID uint32, typ byte, attr layehradius.Attribute) error {
	if len(attr) > 253 {
		return fmt.Errorf("vendor attribute %d too long", typ)
	}
	vendorAttr := make(layehradius.Attribute, 2+len(attr))
	vendorAttr[0] = typ
	vendorAttr[1] = byte(len(vendorAttr))
	copy(vendorAttr[2:], attr)
	vsa, err := layehradius.NewVendorSpecific(vendorID, vendorAttr)
	if err != nil {
		return err
	}
	packet.Add(rfc2865.VendorSpecific_Type, vsa)
	return nil
}
