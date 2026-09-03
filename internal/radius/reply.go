package radius

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
)

// ReplyAttributes contains RADIUS reply attributes for a user.
type ReplyAttributes struct {
	Role                               string
	BandwidthProfile                   string
	FilterID                           string
	PolicyTag                          string
	SessionTimeout                     int
	IdleTimeout                        int
	VLAN                               int
	TunnelType                         string // "VLAN"
	TunnelMediumType                   string // "IEEE-802"
	TunnelPrivateGroupID               string // VLAN ID as string
	DataVLAN                           int
	VoiceVLAN                          int
	TaggedVLANs                        []int
	QinQOuterVLAN                      int
	QinQInnerVLAN                      int
	VLANPool                           string
	FallbackVLAN                       int
	AuthFailVLAN                       int
	VLANPolicyMode                     string
	VLANPolicyFingerprint              string
	VRF                                string
	RouteOwner                         string
	RouteRevision                      string
	RoutePolicyMode                    string
	RoutePolicyFingerprint             string
	FramedRoutes                       []string
	FramedIPv6Routes                   []string
	AddressOwner                       string
	AddressRevision                    string
	AddressPolicyMode                  string
	AddressPolicyFingerprint           string
	FramedIPAddress                    string
	FramedIPNetmask                    string
	FramedPool                         string
	FramedIPv6Address                  string
	FramedIPv6Prefix                   string
	DelegatedIPv6Prefix                string
	FramedIPv6Pool                     string
	RAPrefix                           string
	DHCPv6Mode                         string
	RAMode                             string
	TranslationOwner                   string
	TranslationRevision                string
	TranslationPolicyMode              string
	TranslationPolicyFingerprint       string
	TranslationMode                    string
	TranslationPublicPool              string
	TranslationPublicIPv4              string
	TranslationPrivateIPv4Prefix       string
	TranslationSubscriberIPv6Prefix    string
	TranslationNAT64Prefix             string
	TranslationPortBlockStart          int
	TranslationPortBlockEnd            int
	TranslationPortBlockSize           int
	TranslationLoggingProfile          string
	TranslationAccountingKey           string
	TranslationQuotaCorrelation        bool
	TranslationAccountingCorrelation   bool
	MikrotikRateLimit                  string // MikroTik specific, but widely used
	WISPrBandwidthMaxDown              int
	WISPrBandwidthMaxUp                int
	HasQuarantine                      bool
	Quarantine                         bool
	PortalProfile                      string
	DeviceGroup                        string
	Tenant                             string
	ACLPolicyName                      string
	InboundACL                         string
	OutboundACL                        string
	ACLRules                           []ACLRule
	ServiceChain                       []policy.ServiceIntent
	CiscoSecurityGroupTag              int
	CiscoSecurityGroupName             string
	CiscoVPNGroupPolicy                string
	CiscoVPNTunnelGroup                string
	CiscoVPNSplitTunnelList            string
	CiscoVoiceTrafficClass             string
	CiscoShellPrivilegeLevel           int
	CiscoShellRoles                    []string
	CiscoPostureStatus                 string
	CiscoAuditSessionID                string
	CiscoChargingProfile               string
	CiscoAVPairs                       []string
	ArubaAdminRole                     string
	ArubaCPPMRole                      string
	ArubaNamedUserVLAN                 string
	ArubaAPGroup                       string
	ArubaUserGroup                     string
	ArubaDeviceType                    string
	ArubaMDPSDeviceName                string
	ArubaMDPSDeviceProfile             string
	ArubaAirGroupUserName              string
	ArubaAirGroupSharedUser            string
	ArubaAirGroupSharedRole            string
	ArubaAirGroupSharedGroup           string
	ArubaMPSKKeyName                   string
	ArubaDPPServiceType                int
	ArubaUBTGatewayRole                string
	ArubaGatewayZone                   string
	ArubaQoSTrustMode                  int
	ArubaPoEPriority                   int
	ArubaDeviceTrafficClass            int
	ArubaAVPairs                       []string
	HPPrivilegeLevel                   int
	HPCPPMSecondaryRole                string
	HPCos                              string
	HPBonjourInboundProfile            string
	HPBonjourOutboundProfile           string
	HPURIString                        string
	HPURIAccess                        string
	HPCommandString                    string
	HPNasRulesIPv6                     int
	HPEgressVLANName                   string
	AerohiveUserLanguage               string
	AerohiveIDMMessage                 int
	AerohiveClientMonitorProblem       int
	AerohiveAuthSource                 int
	AerohiveAVPairs                    []string
	ColubrisAVPairs                    []string
	JuniperAllowCommands               string
	JuniperDenyCommands                string
	JuniperUserPermissions             string
	JuniperVoIPVLAN                    string
	JuniperCoSTrafficControlProfile    string
	JuniperPolicerParameter            string
	JuniperAVPairs                     []string
	ExtremeCLIAuthorization            int
	ExtremeShellCommand                string
	ExtremeNetloginURLDesc             string
	ExtremeUserLocation                string
	ExtremeVMName                      string
	ExtremeVMVPPName                   string
	ExtremeVMIPAddr                    string
	ExtremeVMVLANID                    int
	ExtremeVMVRName                    string
	ERXVirtualRouterName               string
	ERXAddressPoolName                 string
	ERXRedirectVRName                  string
	ERXQoSProfileName                  string
	ERXPppoeURL                        string
	ERXServiceBundle                   string
	ERXServiceActivate                 string
	ERXServiceDeactivate               string
	ERXServiceTimeout                  int
	ERXClientProfileName               string
	ERXAPNName                         string
	ERXCosShapingRate                  string
	ERXInputInterfaceFilter            string
	ERXOutputInterfaceFilter           string
	ERXIPv6DelegatedPoolName           string
	ERXBulkCoATransactionID            int
	ERXBulkCoAIdentifier               int
	ERXAdvPcefRuleName                 string
	RuckusWLANName                     string
	RuckusVLANName                     string
	RuckusGracePeriod                  int
	RuckusStaExpiration                int
	RuckusTrafficClassAttributeIDs     string
	RuckusCPToken                      string
	RuckusClusterName                  string
	RuckusAuthServerID                 string
	RuckusFlexAuthAVPs                 []string
	RuckusMaxDLULQuota                 int
	RuckusSCIRole                      string
	RuckusSCIResourceGroup             string
	FoundryPrivilegeLevel              int
	FoundryINMPrivilege                int
	FoundryCommandExceptionFlag        int
	FoundryCommandString               string
	FoundryAccessList                  string
	FoundryMACAuthentNeeds8021X        int
	Foundry8021XValidLookup            int
	FoundryMACBasedVLANQoS             int
	FoundryINMRoleAORList              string
	FoundryCOACommand                  string
	FoundrySIContextRole               string
	FoundrySIRoleTemplate              string
	FoundryVoicePhoneConfig            string
	FortinetClientIPAddress            string
	FortinetClientIPv6Address          string
	FortinetVDOMName                   string
	FortinetInterfaceName              string
	FortinetAccessProfile              string
	FortinetSSID                       string
	FortinetAPName                     string
	FortinetFACAuthStatus              string
	FortinetFACChallengeCode           string
	FortinetWebfilterCategoryAllow     string
	FortinetWebfilterCategoryBlock     string
	FortinetWebfilterCategoryMonitor   string
	FortinetAppCtrlCategoryAllow       string
	FortinetAppCtrlCategoryBlock       string
	FortinetAppCtrlRiskAllow           string
	FortinetAppCtrlRiskBlock           string
	FortinetFortiWANAVPairs            []string
	FortinetFDDAccessProfile           string
	FortinetFDDTrustedHosts            string
	FortinetFDDSPPName                 string
	FortinetFDDIsSystemAdmin           string
	FortinetFDDIsSPPAdmin              string
	FortinetFDDSPPPolicyGroup          string
	FortinetFDDAllowAPIAccess          string
	FortinetFPCUserRole                string
	FortinetTenantIdentification       string
	FortinetHostPortAVPairs            []string
	PaloAltoPanoramaAdminRole          string
	PaloAltoPanoramaAdminAccessDomain  string
	PaloAltoUserDomain                 string
	PaloAltoClientSourceIP             string
	PaloAltoClientOS                   string
	PaloAltoClientHostname             string
	PaloAltoGlobalProtectClientVersion string
}

type ReplyAttributeItem struct {
	Name   string
	Value  string
	Quoted bool
}

// GetReplyAttributes retrieves attributes based on user role.
func GetReplyAttributes(username, role string) (*ReplyAttributes, error) {
	if db.DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var (
		vlan          sql.NullInt32
		bwProfile     sql.NullString
		sessionTO     sql.NullInt32
		idleTO        sql.NullInt32
		portalProfile sql.NullString
		aclPolicyName sql.NullString
	)

	err := db.DB.QueryRow(`SELECT vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name
		FROM roles WHERE name = ?`, role).Scan(&vlan, &bwProfile, &sessionTO, &idleTO, &portalProfile, &aclPolicyName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role %s not found", role)
		}
		return nil, err
	}

	attrs := &ReplyAttributes{Role: strings.TrimSpace(role)}
	if vlan.Valid {
		attrs.VLAN = int(vlan.Int32)
		attrs.TunnelType = "VLAN"
		attrs.TunnelMediumType = "IEEE-802"
		attrs.TunnelPrivateGroupID = fmt.Sprintf("%d", vlan.Int32)
	}
	if sessionTO.Valid {
		attrs.SessionTimeout = int(sessionTO.Int32)
	}
	if idleTO.Valid {
		attrs.IdleTimeout = int(idleTO.Int32)
	}
	if portalProfile.Valid {
		attrs.PortalProfile = strings.TrimSpace(portalProfile.String)
	}
	if bwProfile.Valid {
		attrs.BandwidthProfile = strings.TrimSpace(bwProfile.String)
		// Retrieve bandwidth profile details
		var down, up int
		err = db.DB.QueryRow(`SELECT download_rate_kbps, upload_rate_kbps FROM bandwidth_profiles WHERE name = ?`,
			bwProfile.String).Scan(&down, &up)
		if err == nil {
			attrs.MikrotikRateLimit = FormatMikroTikRateLimit(down, up)
			attrs.WISPrBandwidthMaxDown = down
			attrs.WISPrBandwidthMaxUp = up
		}
	}
	if aclPolicyName.Valid && strings.TrimSpace(aclPolicyName.String) != "" {
		loaded, err := ApplyStoredACLPolicy(attrs, aclPolicyName.String)
		if err != nil {
			return nil, err
		}
		if !loaded {
			return nil, fmt.Errorf("ACL policy %s assigned to role %s is missing or disabled", aclPolicyName.String, role)
		}
	}
	return attrs, nil
}

// RenderReplyAttributes generates the FreeRADIUS reply items.
func RenderReplyAttributes(attrs *ReplyAttributes) string {
	return RenderReplyAttributesForPacks(attrs, productconfigs.DefaultVendorCompatibilityPackKeys())
}

func RenderReplyAttributesForPacks(attrs *ReplyAttributes, packKeys []string) string {
	items := BuildReplyAttributeItems(attrs, packKeys)
	return renderReplyAttributeItems(items)
}

func renderReplyAttributeItems(items []ReplyAttributeItem) string {
	var sb strings.Builder
	for _, item := range items {
		if item.Quoted {
			sb.WriteString(fmt.Sprintf("\t%s = \"%s\"\n", item.Name, escapeReplyValue(item.Value)))
			continue
		}
		sb.WriteString(fmt.Sprintf("\t%s = %s\n", item.Name, item.Value))
	}
	return sb.String()
}

func RenderReplyAttributesForVendorConfig(attrs *ReplyAttributes, vendor config.RadiusVendorConfig) string {
	return RenderReplyAttributesForVendorConfigAndPacks(attrs, vendor.CompatibilityPacks, vendor)
}

func BuildReplyAttributeItems(attrs *ReplyAttributes, packKeys []string) []ReplyAttributeItem {
	return buildReplyAttributeItems(attrs, packKeys, config.RadiusVendorConfig{})
}

func BuildReplyAttributeItemsForVendorConfig(attrs *ReplyAttributes, packKeys []string, vendor config.RadiusVendorConfig) []ReplyAttributeItem {
	return buildReplyAttributeItems(attrs, packKeys, vendor)
}

func RenderReplyAttributesForVendorConfigAndPacks(attrs *ReplyAttributes, packKeys []string, vendor config.RadiusVendorConfig) string {
	return renderReplyAttributeItems(BuildReplyAttributeItemsForVendorConfig(attrs, packKeys, vendor))
}

func buildReplyAttributeItems(attrs *ReplyAttributes, packKeys []string, vendor config.RadiusVendorConfig) []ReplyAttributeItem {
	if attrs == nil {
		return nil
	}
	packKeys = normalizeReplyPackKeys(packKeys)
	items := make([]ReplyAttributeItem, 0, 16)
	seen := map[string]struct{}{}
	appendItem := func(name, value string, quoted bool) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		key := name + "\x00" + value
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		items = append(items, ReplyAttributeItem{Name: name, Value: value, Quoted: quoted})
	}
	for _, packKey := range packKeys {
		appendACLCompilerReplyAttributes(attrs, packKey, appendItem)
		switch packKey {
		case productconfigs.VendorPackStandard:
			appendStandardReplyAttributes(attrs, appendItem)
		case productconfigs.VendorPackAegisNAS:
			appendAegisNASReplyAttributes(attrs, appendItem)
		case productconfigs.VendorPackMikroTik:
			appendItem("Mikrotik-Rate-Limit", attrs.MikrotikRateLimit, true)
			appendItem("Mikrotik-Address-List", attrs.ACLPolicyName, true)
		case productconfigs.VendorPackWISPr:
			if attrs.WISPrBandwidthMaxDown > 0 {
				appendItem("WISPr-Bandwidth-Max-Down", FormatRateKbps(attrs.WISPrBandwidthMaxDown), false)
			}
			if attrs.WISPrBandwidthMaxUp > 0 {
				appendItem("WISPr-Bandwidth-Max-Up", FormatRateKbps(attrs.WISPrBandwidthMaxUp), false)
			}
		case productconfigs.VendorPackCisco:
			appendCiscoFamilyReplyAttributes(attrs, appendItem)
		case productconfigs.VendorPackAruba:
			appendItem("Aruba-User-Role", replyRole(attrs), true)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Aruba-User-Vlan", fmt.Sprintf("%d", vlan), false)
			}
			appendArubaFamilyReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackRuckus:
			appendRuckusICXReplyAttributes(attrs, packKey, appendItem)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
			appendQuotaItem(attrs, packKey, vendor.QuotaMappings, appendItem, "Ruckus-Max-DL-UL-Quota")
		case productconfigs.VendorPackFoundry:
			appendRuckusICXReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackFortinet:
			appendFortinetPaloAltoReplyAttributes(attrs, packKey, appendItem)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
		case productconfigs.VendorPackUBNT:
			if attrs.WISPrBandwidthMaxDown > 0 {
				appendItem("UBNT-Data-Rate-DL", FormatRateBpsFromKbps(attrs.WISPrBandwidthMaxDown), false)
			}
			if attrs.WISPrBandwidthMaxUp > 0 {
				appendItem("UBNT-Data-Rate-UL", FormatRateBpsFromKbps(attrs.WISPrBandwidthMaxUp), false)
			}
		case productconfigs.VendorPackCambium:
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Cambium-ePMP-Data-VLAN-Id", fmt.Sprintf("%d", vlan), false)
			}
			appendRateKbpsItem(attrs, appendItem, "Cambium-ePMP-Max-Burst-Downlink-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Cambium-ePMP-Max-Burst-Uplink-Rate", attrs.WISPrBandwidthMaxUp)
			appendQuotaItem(attrs, packKey, vendor.QuotaMappings, appendItem, "Cambium-Traffic-Quota-Limit-Total")
			appendBooleanIntegerItem(attrs.HasQuarantine, attrs.Quarantine, appendItem, "Cambium-Walled-Garden-State")
			appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "Cambium-Auth-Role")
		case productconfigs.VendorPackExtreme:
			appendItem("Extreme-Security-Profile", replyRole(attrs), true)
			if hasVLANPolicyReplyAttributes(attrs) {
				// NAS-0054 policy output is appended below as an extended VLAN assignment.
			} else if extendedVLAN, ok := extremeExtendedVLANValue(vendor.ExtendedVLANMappings, replyRole(attrs)); ok {
				appendItem("Extreme-Netlogin-Extended-Vlan", extendedVLAN, true)
			} else if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Extreme-Netlogin-Vlan", fmt.Sprintf("%d", vlan), true)
				appendItem("Extreme-Netlogin-Vlan-Tag", fmt.Sprintf("%d", vlan), false)
			}
			appendURLItem(attrs, appendItem, "Extreme-Netlogin-Url", attrs.PortalProfile)
			appendJuniperExtremeReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackJuniper:
			appendItem("Juniper-Local-User-Name", replyRole(attrs), true)
			appendItem("Juniper-Firewall-filter-name", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendItem("Juniper-Switching-Filter", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendURLItem(attrs, appendItem, "Juniper-CWA-Redirect", attrs.PortalProfile)
			appendJuniperExtremeReplyAttributes(attrs, packKey, appendItem)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
		case productconfigs.VendorPackERX:
			appendJuniperExtremeReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackHuawei:
			appendItem("Huawei-User-Class", replyRole(attrs), true)
			appendItem("Huawei-Qos-Profile-Name", attrs.BandwidthProfile, true)
			appendItem("Huawei-Down-QOS-Profile-Name", attrs.BandwidthProfile, true)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Output-Average-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Output-Peak-Information-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Input-Average-Rate", attrs.WISPrBandwidthMaxUp)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Input-Peak-Information-Rate", attrs.WISPrBandwidthMaxUp)
			appendItem("Huawei-Data-Filter", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendURLItem(attrs, appendItem, "Huawei-HTTP-Redirect-URL", attrs.PortalProfile)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
		case productconfigs.VendorPackH3C:
			appendItem("H3C-User-Role", replyRole(attrs), true)
			appendItem("H3C-User-Group", firstReplyValue(attrs.DeviceGroup, attrs.Role), true)
			appendRateKbpsItem(attrs, appendItem, "H3C-Output-Average-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "H3C-Output-Peak-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "H3C-Input-Average-Rate", attrs.WISPrBandwidthMaxUp)
			appendRateKbpsItem(attrs, appendItem, "H3C-Input-Peak-Rate", attrs.WISPrBandwidthMaxUp)
			appendItem("H3C-Ita-Policy", firstReplyValue(attrs.PolicyTag, attrs.FilterID), true)
			appendURLItem(attrs, appendItem, "H3C-Portal-URL", attrs.PortalProfile)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
		case productconfigs.VendorPackPaloAlto:
			appendFortinetPaloAltoReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackTPLink:
			appendRateKbpsItem(attrs, appendItem, "TPLink-Xmit-limit", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "TPLink-Recv-limit", attrs.WISPrBandwidthMaxUp)
			appendItem("TPLink-Omada", attrs.DeviceGroup, true)
			appendItem("TPLink-Site", attrs.Tenant, true)
			appendURLItem(attrs, appendItem, "TPLink-Redirect-Url", attrs.PortalProfile)
			appendNumericPortalStatusItem(attrs, packKey, vendor.PortalStatusMappings, appendItem, "TPLink-Portal-Access-Status")
		case productconfigs.VendorPackAerohive:
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Extreme-User-Vlan", fmt.Sprintf("%d", vlan), false)
			}
			appendItem("Extreme-AVPair", firstReplyValue(attrs.PolicyTag, attrs.ACLPolicyName, attrs.FilterID), true)
			appendURLItem(attrs, appendItem, "Extreme-IDM-Redirect-URL", attrs.PortalProfile)
			appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "Extreme-User-Profile-Attribute")
			appendArubaFamilyReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackAirespace:
			appendItem("Guest-Role-Name", replyRole(attrs), true)
			appendItem("ACL-Name", firstReplyValue(attrs.ACLPolicyName, attrs.InboundACL, attrs.OutboundACL), true)
			appendRateKbpsItem(attrs, appendItem, "Data-Bandwidth-Average-Contract", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Data-Bandwidth-Average-Contract-Upstream", attrs.WISPrBandwidthMaxUp)
		case productconfigs.VendorPackHP:
			appendItem("User-Role", replyRole(attrs), true)
			appendItem("Access-Profile", firstReplyValue(attrs.PolicyTag, attrs.FilterID, attrs.ACLPolicyName), true)
			appendURLItem(attrs, appendItem, "Captive-Portal-URL", attrs.PortalProfile)
			appendRateKbpsItem(attrs, appendItem, "Bandwidth-Max-Egress", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Bandwidth-Max-Ingress", attrs.WISPrBandwidthMaxUp)
			if vlan := replyVLAN(attrs); vlan > 0 && !hasVLANPolicyReplyAttributes(attrs) {
				appendItem("Egress-VLANID", fmt.Sprintf("%d", vlan), false)
			}
			appendArubaFamilyReplyAttributes(attrs, packKey, appendItem)
		case productconfigs.VendorPackNomadix:
			appendRateKbpsItem(attrs, appendItem, "Nomadix-Bw-Down", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Nomadix-Bw-Up", attrs.WISPrBandwidthMaxUp)
			appendURLItem(attrs, appendItem, "Nomadix-URL-Redirection", attrs.PortalProfile)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Nomadix-Net-VLAN", fmt.Sprintf("%d", vlan), false)
			}
			appendItem("Nomadix-Qos-Policy", firstReplyValue(attrs.PolicyTag, attrs.BandwidthProfile, attrs.FilterID), true)
			appendNumericSessionActionItem(attrs, packKey, vendor.SessionActionMappings, appendItem, "Nomadix-EndofSession")
		case productconfigs.VendorPackChilliSpot:
			appendRateKbpsItem(attrs, appendItem, "ChilliSpot-Bandwidth-Max-Down", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "ChilliSpot-Bandwidth-Max-Up", attrs.WISPrBandwidthMaxUp)
			appendItem("ChilliSpot-Config", firstReplyValue(attrs.PolicyTag, attrs.FilterID), true)
			appendItem("ChilliSpot-UAM-Allowed", attrs.PortalProfile, true)
			appendQuotaItem(attrs, packKey, vendor.QuotaMappings, appendItem, "ChilliSpot-Max-Total-Octets")
		case productconfigs.VendorPackDLink:
			appendRateKbpsItem(attrs, appendItem, "Dlink-Egress-Bandwidth-Assignment", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Dlink-Ingress-Bandwidth-Assignment", attrs.WISPrBandwidthMaxUp)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Dlink-VLAN-ID", fmt.Sprintf("%d", vlan), true)
			}
			appendItem("Dlink-ACL-Profile", firstReplyValue(attrs.ACLPolicyName, attrs.InboundACL, attrs.OutboundACL), true)
			appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "Dlink-User-Level")
		case productconfigs.VendorPackSonicWall:
			appendItem("User-Group", replyRole(attrs), true)
			appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "User-Privilege")
		case productconfigs.VendorPackArista:
			appendItem("User-Role", replyRole(attrs), true)
			appendURLItem(attrs, appendItem, "Captive-Portal", attrs.PortalProfile)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Segment-Id", fmt.Sprintf("%d", vlan), true)
			}
			appendItem("Interface-Profile", attrs.DeviceGroup, true)
			appendVendorAVPairItems(attrs, packKey, vendor.AVPairMappings, appendItem)
		case productconfigs.VendorPackPica8:
			appendURLItem(attrs, appendItem, "Redirect-URL", attrs.PortalProfile)
			appendItem("AVPair", attrs.PolicyTag, true)
		case productconfigs.VendorPackZTE:
			appendItem("QoS-Profile-Down", attrs.BandwidthProfile, true)
			appendItem("QOS-Profile-Up", attrs.BandwidthProfile, true)
			appendItem("QoS-Profile-Down-v6", attrs.BandwidthProfile, true)
			appendItem("QoS-Profile-Up-v6", attrs.BandwidthProfile, true)
			appendRateKbpsItem(attrs, appendItem, "Rate-Ctrl-SCR-Down", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Rate-Ctrl-SCR-Down-v6", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Rate-Ctrl-SCR-Up", attrs.WISPrBandwidthMaxUp)
			appendRateKbpsItem(attrs, appendItem, "Rate-Ctrl-SCR-Up-v6", attrs.WISPrBandwidthMaxUp)
			appendURLItem(attrs, appendItem, "PPPOE-URL", attrs.PortalProfile)
			appendNumericRoleItem(attrs, packKey, vendor.RoleMappings, appendItem, "SW-Privilege")
		case productconfigs.VendorPackNokia:
			appendItem("Nokia-User-Profile", replyRole(attrs), true)
			appendItem("Nokia-AVPair", attrs.PolicyTag, true)
			appendNokiaServiceNameItem(attrs, packKey, vendor.ServiceNameMappings, appendItem)
		case productconfigs.VendorPackColubris:
			appendItem("AVPair", firstReplyValue(attrs.PolicyTag, attrs.ACLPolicyName, attrs.FilterID), true)
			appendBooleanIntegerItem(attrs.HasQuarantine, attrs.Quarantine, appendItem, "Intercept")
			appendArubaFamilyReplyAttributes(attrs, packKey, appendItem)
		}
		appendVLANPolicyReplyAttributes(attrs, packKey, appendItem)
		appendRoutePolicyReplyAttributes(attrs, packKey, appendItem)
		appendAddressPolicyReplyAttributes(attrs, packKey, appendItem)
		appendTranslationPolicyReplyAttributes(attrs, packKey, appendItem)
	}
	return items
}

func appendCiscoFamilyReplyAttributes(attrs *ReplyAttributes, appendItem func(string, string, bool)) {
	values, err := BuildCiscoAVPairsForIntent(CiscoAVPairIntent{
		SecurityGroupTag:    attrs.CiscoSecurityGroupTag,
		SecurityGroupName:   attrs.CiscoSecurityGroupName,
		VPNGroupPolicy:      attrs.CiscoVPNGroupPolicy,
		VPNTunnelGroup:      attrs.CiscoVPNTunnelGroup,
		VPNSplitTunnelList:  attrs.CiscoVPNSplitTunnelList,
		VoiceTrafficClass:   attrs.CiscoVoiceTrafficClass,
		ShellPrivilegeLevel: attrs.CiscoShellPrivilegeLevel,
		ShellRoles:          attrs.CiscoShellRoles,
		PostureStatus:       attrs.CiscoPostureStatus,
		AuditSessionID:      attrs.CiscoAuditSessionID,
		ChargingProfile:     attrs.CiscoChargingProfile,
		Custom:              attrs.CiscoAVPairs,
	})
	if err != nil {
		return
	}
	for _, value := range values {
		appendItem("Cisco-AVPair", value, true)
	}
}

func appendVLANPolicyReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if !hasVLANPolicyReplyAttributes(attrs) {
		return
	}
	decision := vlanPolicyDecisionFromReplyAttributes(attrs)
	for _, item := range BuildVLANPolicyAttributes(decision, []string{packKey}) {
		appendItem(item.Name, item.Value, item.Quoted)
	}
}

func hasVLANPolicyReplyAttributes(attrs *ReplyAttributes) bool {
	if attrs == nil {
		return false
	}
	return attrs.DataVLAN > 0 ||
		attrs.VoiceVLAN > 0 ||
		len(attrs.TaggedVLANs) > 0 ||
		attrs.QinQOuterVLAN > 0 ||
		attrs.QinQInnerVLAN > 0 ||
		strings.TrimSpace(attrs.VLANPool) != "" ||
		attrs.FallbackVLAN > 0 ||
		attrs.AuthFailVLAN > 0 ||
		strings.TrimSpace(attrs.VLANPolicyMode) != "" ||
		strings.TrimSpace(attrs.VLANPolicyFingerprint) != ""
}

func vlanPolicyDecisionFromReplyAttributes(attrs *ReplyAttributes) VLANPolicyDecision {
	if attrs == nil {
		return VLANPolicyDecision{}
	}
	dataVLAN := firstPositiveInt(attrs.DataVLAN, replyVLAN(attrs))
	mode := strings.ToLower(strings.TrimSpace(attrs.VLANPolicyMode))
	if mode == "" {
		switch {
		case attrs.QinQOuterVLAN > 0 || attrs.QinQInnerVLAN > 0:
			mode = "qinq"
		case strings.TrimSpace(attrs.VLANPool) != "":
			mode = "pool"
		case attrs.VoiceVLAN > 0 || len(attrs.TaggedVLANs) > 0:
			mode = "voice-data"
		default:
			mode = "access"
		}
	}
	return VLANPolicyDecision{
		Role:           replyRole(attrs),
		PolicySource:   "reply_attributes",
		AssignmentMode: mode,
		EffectiveVLAN:  firstPositiveInt(replyVLAN(attrs), dataVLAN),
		DataVLAN:       dataVLAN,
		VoiceVLAN:      attrs.VoiceVLAN,
		TaggedVLANs:    normalizeVLANList(attrs.TaggedVLANs),
		PoolName:       strings.TrimSpace(attrs.VLANPool),
		FallbackVLAN:   attrs.FallbackVLAN,
		AuthFailVLAN:   attrs.AuthFailVLAN,
		QinQEnabled:    attrs.QinQOuterVLAN > 0 || attrs.QinQInnerVLAN > 0,
		QinQMode:       "provider-bridge",
		QinQOuterVLAN:  attrs.QinQOuterVLAN,
		QinQInnerVLAN:  attrs.QinQInnerVLAN,
	}
}

func appendRoutePolicyReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if !hasRoutePolicyReplyAttributes(attrs) {
		return
	}
	decision := routePolicyDecisionFromReplyAttributes(attrs)
	for _, item := range BuildRoutePolicyAttributes(decision, []string{packKey}) {
		appendItem(item.Name, item.Value, item.Quoted)
	}
}

func hasRoutePolicyReplyAttributes(attrs *ReplyAttributes) bool {
	if attrs == nil {
		return false
	}
	return strings.TrimSpace(attrs.VRF) != "" ||
		strings.TrimSpace(attrs.RouteOwner) != "" ||
		strings.TrimSpace(attrs.RouteRevision) != "" ||
		strings.TrimSpace(attrs.RoutePolicyMode) != "" ||
		strings.TrimSpace(attrs.RoutePolicyFingerprint) != "" ||
		len(attrs.FramedRoutes) > 0 ||
		len(attrs.FramedIPv6Routes) > 0
}

func routePolicyDecisionFromReplyAttributes(attrs *ReplyAttributes) RoutePolicyDecision {
	if attrs == nil {
		return RoutePolicyDecision{}
	}
	decision := RoutePolicyDecision{
		Role:            replyRole(attrs),
		PolicySource:    "reply_attributes",
		LifecycleAction: firstReplyValue(strings.ToLower(strings.TrimSpace(attrs.RoutePolicyMode)), "authorize"),
		VRF:             firstReplyValue(strings.TrimSpace(attrs.VRF), "default"),
		Owner:           firstReplyValue(strings.TrimSpace(attrs.RouteOwner), "aegisnas"),
		Revision:        strings.TrimSpace(attrs.RouteRevision),
	}
	for _, value := range attrs.FramedRoutes {
		route, diagnostics := parseFramedRouteValue(value, "ipv4", "framed_routes")
		if len(diagnostics) == 0 && route.Destination != "" {
			route.Source = "reply_attributes"
			route.Install = true
			decision.IPv4Routes = append(decision.IPv4Routes, route)
		}
	}
	for _, value := range attrs.FramedIPv6Routes {
		route, diagnostics := parseFramedRouteValue(value, "ipv6", "framed_ipv6_routes")
		if len(diagnostics) == 0 && route.Destination != "" {
			route.Source = "reply_attributes"
			route.Install = true
			decision.IPv6Routes = append(decision.IPv6Routes, route)
		}
	}
	if decision.Revision == "" {
		decision.Revision = routePolicyRevision(decision)
	}
	decision.OwnershipKey = routePolicyOwnershipKey(decision)
	return decision
}

func appendAddressPolicyReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if !hasAddressPolicyReplyAttributes(attrs) {
		return
	}
	decision := addressPolicyDecisionFromReplyAttributes(attrs)
	for _, item := range BuildAddressPolicyAttributes(decision, []string{packKey}) {
		appendItem(item.Name, item.Value, item.Quoted)
	}
}

func hasAddressPolicyReplyAttributes(attrs *ReplyAttributes) bool {
	if attrs == nil {
		return false
	}
	return strings.TrimSpace(attrs.AddressOwner) != "" ||
		strings.TrimSpace(attrs.AddressRevision) != "" ||
		strings.TrimSpace(attrs.AddressPolicyMode) != "" ||
		strings.TrimSpace(attrs.AddressPolicyFingerprint) != "" ||
		strings.TrimSpace(attrs.FramedIPAddress) != "" ||
		strings.TrimSpace(attrs.FramedIPNetmask) != "" ||
		strings.TrimSpace(attrs.FramedPool) != "" ||
		strings.TrimSpace(attrs.FramedIPv6Address) != "" ||
		strings.TrimSpace(attrs.FramedIPv6Prefix) != "" ||
		strings.TrimSpace(attrs.DelegatedIPv6Prefix) != "" ||
		strings.TrimSpace(attrs.FramedIPv6Pool) != "" ||
		strings.TrimSpace(attrs.RAPrefix) != "" ||
		strings.TrimSpace(attrs.DHCPv6Mode) != "" ||
		strings.TrimSpace(attrs.RAMode) != ""
}

func addressPolicyDecisionFromReplyAttributes(attrs *ReplyAttributes) AddressPolicyDecision {
	if attrs == nil {
		return AddressPolicyDecision{}
	}
	decision := AddressPolicyDecision{
		Role:                replyRole(attrs),
		PolicySource:        "reply_attributes",
		LifecycleAction:     firstReplyValue(strings.ToLower(strings.TrimSpace(attrs.AddressPolicyMode)), "authorize"),
		Owner:               firstReplyValue(strings.TrimSpace(attrs.AddressOwner), "aegisnas"),
		Revision:            strings.TrimSpace(attrs.AddressRevision),
		IPv4Address:         strings.TrimSpace(attrs.FramedIPAddress),
		IPv4Pool:            strings.TrimSpace(attrs.FramedPool),
		IPv4Netmask:         strings.TrimSpace(attrs.FramedIPNetmask),
		IPv6Address:         strings.TrimSpace(attrs.FramedIPv6Address),
		IPv6Prefix:          strings.TrimSpace(attrs.FramedIPv6Prefix),
		DelegatedIPv6Prefix: strings.TrimSpace(attrs.DelegatedIPv6Prefix),
		IPv6Pool:            strings.TrimSpace(attrs.FramedIPv6Pool),
		RAPrefix:            strings.TrimSpace(attrs.RAPrefix),
		DHCPv6Mode:          normalizeAddressPolicyDHCPv6Mode(attrs.DHCPv6Mode),
		RAMode:              normalizeAddressPolicyRAMode(attrs.RAMode),
	}
	if decision.Revision == "" {
		decision.Revision = addressPolicyRevision(decision)
	}
	decision.OwnershipKey = addressPolicyOwnershipKey(decision)
	return decision
}

func appendTranslationPolicyReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	if !hasTranslationPolicyReplyAttributes(attrs) {
		return
	}
	decision := translationPolicyDecisionFromReplyAttributes(attrs)
	for _, item := range BuildTranslationPolicyAttributes(decision, []string{packKey}) {
		appendItem(item.Name, item.Value, item.Quoted)
	}
}

func hasTranslationPolicyReplyAttributes(attrs *ReplyAttributes) bool {
	if attrs == nil {
		return false
	}
	return strings.TrimSpace(attrs.TranslationOwner) != "" ||
		strings.TrimSpace(attrs.TranslationRevision) != "" ||
		strings.TrimSpace(attrs.TranslationPolicyMode) != "" ||
		strings.TrimSpace(attrs.TranslationPolicyFingerprint) != "" ||
		strings.TrimSpace(attrs.TranslationMode) != "" ||
		strings.TrimSpace(attrs.TranslationPublicPool) != "" ||
		strings.TrimSpace(attrs.TranslationPublicIPv4) != "" ||
		strings.TrimSpace(attrs.TranslationPrivateIPv4Prefix) != "" ||
		strings.TrimSpace(attrs.TranslationSubscriberIPv6Prefix) != "" ||
		strings.TrimSpace(attrs.TranslationNAT64Prefix) != "" ||
		attrs.TranslationPortBlockStart > 0 ||
		attrs.TranslationPortBlockEnd > 0 ||
		attrs.TranslationPortBlockSize > 0 ||
		strings.TrimSpace(attrs.TranslationLoggingProfile) != "" ||
		strings.TrimSpace(attrs.TranslationAccountingKey) != "" ||
		attrs.TranslationQuotaCorrelation ||
		attrs.TranslationAccountingCorrelation
}

func translationPolicyDecisionFromReplyAttributes(attrs *ReplyAttributes) TranslationPolicyDecision {
	if attrs == nil {
		return TranslationPolicyDecision{}
	}
	decision := TranslationPolicyDecision{
		Role:                  replyRole(attrs),
		PolicySource:          "reply_attributes",
		LifecycleAction:       firstReplyValue(strings.ToLower(strings.TrimSpace(attrs.TranslationPolicyMode)), "authorize"),
		Owner:                 firstReplyValue(strings.TrimSpace(attrs.TranslationOwner), "aegisnas"),
		Revision:              strings.TrimSpace(attrs.TranslationRevision),
		TranslationMode:       firstReplyValue(normalizeTranslationMode(attrs.TranslationMode), "cgnat"),
		PublicPool:            strings.TrimSpace(attrs.TranslationPublicPool),
		PublicIPv4:            strings.TrimSpace(attrs.TranslationPublicIPv4),
		PrivateIPv4Prefix:     strings.TrimSpace(attrs.TranslationPrivateIPv4Prefix),
		SubscriberIPv6Prefix:  strings.TrimSpace(attrs.TranslationSubscriberIPv6Prefix),
		NAT64Prefix:           strings.TrimSpace(attrs.TranslationNAT64Prefix),
		PortBlockStart:        attrs.TranslationPortBlockStart,
		PortBlockEnd:          attrs.TranslationPortBlockEnd,
		PortBlockSize:         attrs.TranslationPortBlockSize,
		LoggingProfile:        strings.TrimSpace(attrs.TranslationLoggingProfile),
		AccountingKey:         strings.TrimSpace(attrs.TranslationAccountingKey),
		QuotaCorrelation:      attrs.TranslationQuotaCorrelation,
		AccountingCorrelation: attrs.TranslationAccountingCorrelation,
	}
	if decision.Revision == "" {
		decision.Revision = translationPolicyRevision(decision)
	}
	decision.OwnershipKey = translationPolicyOwnershipKey(decision)
	return decision
}

func appendACLCompilerReplyAttributes(attrs *ReplyAttributes, packKey string, appendItem func(string, string, bool)) {
	def := aclCompilerDefinitionForPack(packKey)
	if def.LineAttribute == "" {
		return
	}
	if attrs == nil || (strings.TrimSpace(attrs.ACLPolicyName) == "" && strings.TrimSpace(attrs.InboundACL) == "" && strings.TrimSpace(attrs.OutboundACL) == "" && len(attrs.ACLRules) == 0) {
		return
	}
	result, err := CompileACLPolicyForPack(ACLCompilerRequest{
		PolicyName:  attrs.ACLPolicyName,
		InboundACL:  attrs.InboundACL,
		OutboundACL: attrs.OutboundACL,
		Rules:       attrs.ACLRules,
	}, packKey)
	if err != nil || result.Status == aclCompilerStatusBlocked || result.Status == aclCompilerStatusUnsupported {
		return
	}
	for _, item := range result.Attributes {
		appendItem(item.Name, item.Value, item.Quoted)
	}
}

func appendStandardReplyAttributes(attrs *ReplyAttributes, appendItem func(string, string, bool)) {
	if attrs.SessionTimeout > 0 {
		appendItem("Session-Timeout", fmt.Sprintf("%d", attrs.SessionTimeout), false)
	}
	if attrs.IdleTimeout > 0 {
		appendItem("Idle-Timeout", fmt.Sprintf("%d", attrs.IdleTimeout), false)
	}
	if attrs.FilterID != "" {
		appendItem("Filter-Id", attrs.FilterID, true)
	} else if attrs.Role != "" {
		appendItem("Filter-Id", attrs.Role, true)
	}
	if vlan := replyVLAN(attrs); vlan > 0 && !hasVLANPolicyReplyAttributes(attrs) {
		tunnelType := firstReplyValue(attrs.TunnelType, "VLAN")
		tunnelMedium := firstReplyValue(attrs.TunnelMediumType, "IEEE-802")
		appendItem("Tunnel-Type", tunnelType, false)
		appendItem("Tunnel-Medium-Type", tunnelMedium, false)
		appendItem("Tunnel-Private-Group-Id", fmt.Sprintf("%d", vlan), true)
	}
}

func appendAegisNASReplyAttributes(attrs *ReplyAttributes, appendItem func(string, string, bool)) {
	appendItem("AegisNAS-Role", replyRole(attrs), true)
	appendItem("AegisNAS-Bandwidth-Profile", attrs.BandwidthProfile, true)
	if vlan := replyVLAN(attrs); vlan > 0 && !hasVLANPolicyReplyAttributes(attrs) {
		appendItem("AegisNAS-VLAN", fmt.Sprintf("%d", vlan), false)
	}
	if attrs.HasQuarantine {
		if attrs.Quarantine {
			appendItem("AegisNAS-Quarantine", "1", false)
		} else {
			appendItem("AegisNAS-Quarantine", "0", false)
		}
	}
	appendItem("AegisNAS-Policy-Tag", firstReplyValue(attrs.PolicyTag, attrs.FilterID), true)
	if attrs.SessionTimeout > 0 {
		appendItem("AegisNAS-Session-Timeout", fmt.Sprintf("%d", attrs.SessionTimeout), false)
	}
	if attrs.IdleTimeout > 0 {
		appendItem("AegisNAS-Idle-Timeout", fmt.Sprintf("%d", attrs.IdleTimeout), false)
	}
	appendItem("AegisNAS-Portal-Profile", attrs.PortalProfile, true)
	appendItem("AegisNAS-Device-Group", attrs.DeviceGroup, true)
	appendItem("AegisNAS-Tenant", attrs.Tenant, true)
	if summary := renderAegisNASServiceChain(attrs.ServiceChain); summary != "" {
		appendItem("AegisNAS-Service-Chain", summary, true)
	}
	for _, service := range policy.NormalizeServiceChain(attrs.ServiceChain) {
		appendItem("AegisNAS-Service-Name", service.Key, true)
	}
}

func ApplyServiceChainReplyAttributes(attrs *ReplyAttributes, services []policy.ServiceIntent) {
	if attrs == nil {
		return
	}
	attrs.ServiceChain = policy.NormalizeServiceChain(services)
}

func renderAegisNASServiceChain(chain []policy.ServiceIntent) string {
	services := policy.NormalizeServiceChain(chain)
	if len(services) == 0 {
		return ""
	}
	parts := make([]string, 0, len(services))
	for _, service := range services {
		key := strings.TrimSpace(service.Key)
		if key == "" {
			continue
		}
		segment := key
		if service.Type != "" {
			segment += ":" + service.Type
		}
		if service.Action != "" && service.Action != "activate" {
			segment += ":" + service.Action
		}
		if service.Optional {
			segment += ":optional"
		}
		candidate := strings.Join(append(parts, segment), ";")
		if len(candidate) > 240 {
			remaining := len(services) - len(parts)
			if remaining > 0 {
				overflow := fmt.Sprintf("+%d", remaining)
				if len(strings.Join(append(parts, overflow), ";")) <= 240 {
					parts = append(parts, overflow)
				}
			}
			break
		}
		parts = append(parts, segment)
	}
	return strings.Join(parts, ";")
}

func normalizeReplyPackKeys(packKeys []string) []string {
	if len(packKeys) == 0 {
		packKeys = productconfigs.DefaultVendorCompatibilityPackKeys()
	}
	out := make([]string, 0, len(packKeys))
	seen := map[string]struct{}{}
	for _, packKey := range packKeys {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func replyRole(attrs *ReplyAttributes) string {
	return firstReplyValue(attrs.Role, attrs.FilterID)
}

func replyVLAN(attrs *ReplyAttributes) int {
	if attrs.VLAN > 0 {
		return attrs.VLAN
	}
	if attrs.TunnelPrivateGroupID == "" {
		return 0
	}
	var vlan int
	if _, err := fmt.Sscanf(strings.TrimSpace(attrs.TunnelPrivateGroupID), "%d", &vlan); err != nil {
		return 0
	}
	return vlan
}

func firstReplyValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func appendRateKbpsItem(attrs *ReplyAttributes, appendItem func(string, string, bool), name string, value int) {
	if attrs == nil || value <= 0 {
		return
	}
	appendItem(name, FormatRateKbps(value), false)
}

func appendURLItem(_ *ReplyAttributes, appendItem func(string, string, bool), name, value string) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "http://") && !strings.HasPrefix(strings.ToLower(value), "https://") {
		return
	}
	appendItem(name, value, true)
}

func appendBooleanIntegerItem(present, value bool, appendItem func(string, string, bool), name string) {
	if !present {
		return
	}
	if value {
		appendItem(name, "1", false)
		return
	}
	appendItem(name, "0", false)
}

func appendNumericRoleItem(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorRoleMapping, appendItem func(string, string, bool), attribute string) {
	if attrs == nil {
		return
	}
	value, ok := numericVendorRoleValue(mappings, packKey, replyRole(attrs))
	if !ok {
		return
	}
	appendItem(attribute, fmt.Sprintf("%d", value), false)
}

func numericVendorRoleValue(mappings []config.RadiusVendorRoleMapping, packKey, role string) (int, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	role = strings.TrimSpace(role)
	if role == "" {
		return 0, false
	}
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != packKey || !strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			continue
		}
		return mapping.Value, true
	}
	return 0, false
}

func appendNumericPortalStatusItem(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorPortalStatusMapping, appendItem func(string, string, bool), attribute string) {
	if attrs == nil {
		return
	}
	value, ok := numericVendorPortalStatusValue(mappings, packKey, attrs.PortalProfile)
	if !ok {
		return
	}
	appendItem(attribute, strconv.Itoa(value), false)
}

func numericVendorPortalStatusValue(mappings []config.RadiusVendorPortalStatusMapping, packKey, profile string) (int, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return 0, false
	}
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) == packKey && strings.EqualFold(strings.TrimSpace(mapping.PortalProfile), profile) {
			return mapping.Value, true
		}
	}
	return 0, false
}

func appendNumericSessionActionItem(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorSessionActionMapping, appendItem func(string, string, bool), attribute string) {
	if attrs == nil {
		return
	}
	value, ok := numericVendorSessionActionValue(mappings, packKey, replyRole(attrs))
	if !ok {
		return
	}
	appendItem(attribute, strconv.Itoa(value), false)
}

func numericVendorSessionActionValue(mappings []config.RadiusVendorSessionActionMapping, packKey, role string) (int, bool) {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	role = strings.TrimSpace(role)
	if role == "" {
		return 0, false
	}
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) == packKey && strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			return mapping.Value, true
		}
	}
	return 0, false
}

func appendQuotaItem(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorQuotaMapping, appendItem func(string, string, bool), attribute string) {
	if attrs == nil {
		return
	}
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	role := replyRole(attrs)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) == packKey && strings.EqualFold(strings.TrimSpace(mapping.Role), role) && mapping.MaxTotalOctets > 0 {
			appendItem(attribute, strconv.FormatInt(mapping.MaxTotalOctets, 10), false)
			return
		}
	}
}

func appendNokiaServiceNameItem(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorServiceNameMapping, appendItem func(string, string, bool)) {
	if attrs == nil || productconfigs.NormalizeVendorCompatibilityPackKey(packKey) != productconfigs.VendorPackNokia {
		return
	}
	role := replyRole(attrs)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != productconfigs.VendorPackNokia || !strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			continue
		}
		encoded, ok := encodeNokiaBCD(mapping.ServiceName)
		if ok {
			appendItem("Nokia-Service-Name", "0x"+hex.EncodeToString(encoded), false)
		}
		return
	}
}

func encodeNokiaBCD(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 480 {
		return nil, false
	}
	encoded := make([]byte, (len(value)+1)/2)
	for i := 0; i < len(value); i += 2 {
		if value[i] < '0' || value[i] > '9' {
			return nil, false
		}
		low := value[i] - '0'
		high := byte(0x0f)
		if i+1 < len(value) {
			if value[i+1] < '0' || value[i+1] > '9' {
				return nil, false
			}
			high = value[i+1] - '0'
		}
		encoded[i/2] = high<<4 | low
	}
	return encoded, true
}

func extremeExtendedVLANValue(mappings []config.RadiusVendorExtendedVLANMapping, role string) (string, bool) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "", false
	}
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != productconfigs.VendorPackExtreme || !strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			continue
		}
		parts := make([]string, 0, len(mapping.TaggedVLANs)+1)
		if mapping.UntaggedVLAN > 0 {
			parts = append(parts, fmt.Sprintf("U%d", mapping.UntaggedVLAN))
		}
		for _, vlan := range mapping.TaggedVLANs {
			parts = append(parts, fmt.Sprintf("T%d", vlan))
		}
		if len(parts) > 0 {
			return strings.Join(parts, ";"), true
		}
	}
	return "", false
}

func appendVendorAVPairItems(attrs *ReplyAttributes, packKey string, mappings []config.RadiusVendorAVPairMapping, appendItem func(string, string, bool)) {
	attribute, supported := productconfigs.VendorPackAVPairAttribute(packKey)
	if !supported || attrs == nil {
		return
	}
	role := replyRole(attrs)
	for _, mapping := range mappings {
		if productconfigs.NormalizeVendorCompatibilityPackKey(mapping.Pack) != productconfigs.NormalizeVendorCompatibilityPackKey(packKey) || !strings.EqualFold(strings.TrimSpace(mapping.Role), role) {
			continue
		}
		for _, value := range mapping.Values {
			expanded := expandVendorAVPairTemplate(value, attrs)
			if expanded == "" || len(expanded) > 240 || strings.ContainsAny(expanded, "\r\n\x00") {
				continue
			}
			appendItem(attribute, expanded, true)
		}
		return
	}
}

func expandVendorAVPairTemplate(value string, attrs *ReplyAttributes) string {
	if attrs == nil {
		return strings.TrimSpace(value)
	}
	return strings.NewReplacer(
		"${role}", replyRole(attrs),
		"${acl_policy}", strings.TrimSpace(attrs.ACLPolicyName),
		"${inbound_acl}", strings.TrimSpace(attrs.InboundACL),
		"${outbound_acl}", strings.TrimSpace(attrs.OutboundACL),
		"${vlan}", strconv.Itoa(replyVLAN(attrs)),
		"${policy_tag}", strings.TrimSpace(attrs.PolicyTag),
		"${device_group}", strings.TrimSpace(attrs.DeviceGroup),
		"${tenant}", strings.TrimSpace(attrs.Tenant),
	).Replace(strings.TrimSpace(value))
}

func escapeReplyValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
