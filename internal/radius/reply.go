package radius

import (
	"database/sql"
	"fmt"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// ReplyAttributes contains RADIUS reply attributes for a user.
type ReplyAttributes struct {
	Role                  string
	BandwidthProfile      string
	FilterID              string
	PolicyTag             string
	SessionTimeout        int
	IdleTimeout           int
	VLAN                  int
	TunnelType            string // "VLAN"
	TunnelMediumType      string // "IEEE-802"
	TunnelPrivateGroupID  string // VLAN ID as string
	MikrotikRateLimit     string // MikroTik specific, but widely used
	WISPrBandwidthMaxDown int
	WISPrBandwidthMaxUp   int
	HasQuarantine         bool
	Quarantine            bool
	PortalProfile         string
	DeviceGroup           string
	Tenant                string
	ACLPolicyName         string
	InboundACL            string
	OutboundACL           string
	ACLRules              []ACLRule
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
		vlan      sql.NullInt32
		bwProfile sql.NullString
		sessionTO sql.NullInt32
		idleTO    sql.NullInt32
	)

	err := db.DB.QueryRow(`SELECT vlan, bandwidth_profile, session_timeout, idle_timeout
		FROM roles WHERE name = ?`, role).Scan(&vlan, &bwProfile, &sessionTO, &idleTO)
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
	if bwProfile.Valid {
		attrs.BandwidthProfile = strings.TrimSpace(bwProfile.String)
		// Retrieve bandwidth profile details
		var down, up int
		err = db.DB.QueryRow(`SELECT download_rate_kbps, upload_rate_kbps FROM bandwidth_profiles WHERE name = ?`,
			bwProfile.String).Scan(&down, &up)
		if err == nil {
			attrs.MikrotikRateLimit = fmt.Sprintf("%dk/%dk", down, up)
			attrs.WISPrBandwidthMaxDown = down
			attrs.WISPrBandwidthMaxUp = up
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
	return RenderReplyAttributesForPacks(attrs, vendor.CompatibilityPacks)
}

func BuildReplyAttributeItems(attrs *ReplyAttributes, packKeys []string) []ReplyAttributeItem {
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
				appendItem("WISPr-Bandwidth-Max-Down", fmt.Sprintf("%d", attrs.WISPrBandwidthMaxDown), false)
			}
			if attrs.WISPrBandwidthMaxUp > 0 {
				appendItem("WISPr-Bandwidth-Max-Up", fmt.Sprintf("%d", attrs.WISPrBandwidthMaxUp), false)
			}
		case productconfigs.VendorPackCisco:
			appendItem("Cisco-In-ACL", attrs.InboundACL, true)
			appendItem("Cisco-Out-ACL", attrs.OutboundACL, true)
			for _, value := range renderCiscoAVPairACLRules(attrs.ACLRules) {
				appendItem("Cisco-AVPair", value, true)
			}
		case productconfigs.VendorPackAruba:
			appendItem("Aruba-User-Role", replyRole(attrs), true)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Aruba-User-Vlan", fmt.Sprintf("%d", vlan), false)
			}
			for _, value := range renderNASFilterRules(attrs.ACLRules) {
				appendItem("Aruba-NAS-Filter-Rule", value, true)
			}
		case productconfigs.VendorPackRuckus:
			appendItem("Ruckus-User-Groups", replyRole(attrs), true)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Ruckus-VLAN-ID", fmt.Sprintf("%d", vlan), false)
			}
		case productconfigs.VendorPackFortinet:
			appendItem("Fortinet-Group-Name", replyRole(attrs), true)
			appendItem("Fortinet-Access-Profile", firstReplyValue(attrs.PolicyTag, attrs.FilterID, attrs.ACLPolicyName), true)
		case productconfigs.VendorPackUBNT:
			if attrs.WISPrBandwidthMaxDown > 0 {
				appendItem("UBNT-Data-Rate-DL", fmt.Sprintf("%d", attrs.WISPrBandwidthMaxDown*1000), false)
			}
			if attrs.WISPrBandwidthMaxUp > 0 {
				appendItem("UBNT-Data-Rate-UL", fmt.Sprintf("%d", attrs.WISPrBandwidthMaxUp*1000), false)
			}
		case productconfigs.VendorPackCambium:
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Cambium-ePMP-Data-VLAN-Id", fmt.Sprintf("%d", vlan), false)
			}
			appendRateKbpsItem(attrs, appendItem, "Cambium-ePMP-Max-Burst-Downlink-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Cambium-ePMP-Max-Burst-Uplink-Rate", attrs.WISPrBandwidthMaxUp)
		case productconfigs.VendorPackExtreme:
			appendItem("Extreme-Security-Profile", replyRole(attrs), true)
			if vlan := replyVLAN(attrs); vlan > 0 {
				appendItem("Extreme-Netlogin-Vlan", fmt.Sprintf("%d", vlan), true)
				appendItem("Extreme-Netlogin-Vlan-Tag", fmt.Sprintf("%d", vlan), false)
			}
			appendURLItem(attrs, appendItem, "Extreme-Netlogin-Url", attrs.PortalProfile)
		case productconfigs.VendorPackJuniper:
			appendItem("Juniper-Local-User-Name", replyRole(attrs), true)
			appendItem("Juniper-Firewall-filter-name", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendItem("Juniper-Switching-Filter", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendURLItem(attrs, appendItem, "Juniper-CWA-Redirect", attrs.PortalProfile)
		case productconfigs.VendorPackHuawei:
			appendItem("Huawei-User-Class", replyRole(attrs), true)
			appendItem("Huawei-Qos-Profile-Name", attrs.BandwidthProfile, true)
			appendItem("Huawei-Down-QOS-Profile-Name", attrs.BandwidthProfile, true)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Output-Average-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "Huawei-Input-Average-Rate", attrs.WISPrBandwidthMaxUp)
			appendItem("Huawei-Data-Filter", firstReplyValue(attrs.InboundACL, attrs.OutboundACL, attrs.ACLPolicyName), true)
			appendURLItem(attrs, appendItem, "Huawei-HTTP-Redirect-URL", attrs.PortalProfile)
		case productconfigs.VendorPackH3C:
			appendItem("H3C-User-Role", replyRole(attrs), true)
			appendItem("H3C-User-Group", firstReplyValue(attrs.DeviceGroup, attrs.Role), true)
			appendRateKbpsItem(attrs, appendItem, "H3C-Output-Average-Rate", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "H3C-Input-Average-Rate", attrs.WISPrBandwidthMaxUp)
			appendItem("H3C-Ita-Policy", firstReplyValue(attrs.PolicyTag, attrs.FilterID), true)
			appendURLItem(attrs, appendItem, "H3C-Portal-URL", attrs.PortalProfile)
		case productconfigs.VendorPackPaloAlto:
			appendItem("PaloAlto-Admin-Role", replyRole(attrs), true)
			appendItem("PaloAlto-User-Group", firstReplyValue(attrs.DeviceGroup, attrs.Role), true)
			appendItem("PaloAlto-Admin-Access-Domain", attrs.Tenant, true)
		case productconfigs.VendorPackTPLink:
			appendRateKbpsItem(attrs, appendItem, "TPLink-Xmit-limit", attrs.WISPrBandwidthMaxDown)
			appendRateKbpsItem(attrs, appendItem, "TPLink-Recv-limit", attrs.WISPrBandwidthMaxUp)
			appendItem("TPLink-Omada", attrs.DeviceGroup, true)
			appendItem("TPLink-Site", attrs.Tenant, true)
			appendURLItem(attrs, appendItem, "TPLink-Redirect-Url", attrs.PortalProfile)
		}
	}
	return items
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
	}
	if vlan := replyVLAN(attrs); vlan > 0 {
		tunnelType := firstReplyValue(attrs.TunnelType, "VLAN")
		tunnelMedium := firstReplyValue(attrs.TunnelMediumType, "IEEE-802")
		appendItem("Tunnel-Type", tunnelType, false)
		appendItem("Tunnel-Medium-Type", tunnelMedium, false)
		appendItem("Tunnel-Private-Group-Id", fmt.Sprintf("%d", vlan), true)
	}
	for _, value := range renderNASFilterRules(attrs.ACLRules) {
		appendItem("NAS-Filter-Rule", value, true)
	}
}

func appendAegisNASReplyAttributes(attrs *ReplyAttributes, appendItem func(string, string, bool)) {
	appendItem("AegisNAS-Role", replyRole(attrs), true)
	appendItem("AegisNAS-Bandwidth-Profile", attrs.BandwidthProfile, true)
	if vlan := replyVLAN(attrs); vlan > 0 {
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
	appendItem("AegisNAS-ACL-Name", attrs.ACLPolicyName, true)
	for _, value := range renderNASFilterRules(attrs.ACLRules) {
		appendItem("AegisNAS-ACL-Rule", value, true)
	}
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
	appendItem(name, fmt.Sprintf("%d", value), false)
}

func appendURLItem(_ *ReplyAttributes, appendItem func(string, string, bool), name, value string) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "http://") && !strings.HasPrefix(strings.ToLower(value), "https://") {
		return
	}
	appendItem(name, value, true)
}

func escapeReplyValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
