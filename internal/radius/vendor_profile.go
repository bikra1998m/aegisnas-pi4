package radius

import (
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// NormalizeClientNASType returns a safe FreeRADIUS nastype/profile token.
func NormalizeClientNASType(nasType string) string {
	raw := strings.TrimSpace(nasType)
	if raw == "" {
		return "other"
	}

	key := productconfigs.NormalizeVendorCompatibilityPackKey(raw)
	if productconfigs.ValidVendorCompatibilityPackKey(key) {
		return key
	}

	key = strings.ToLower(raw)
	if validClientProfileToken(key) {
		return key
	}
	return "other"
}

func ReplyCompatibilityPacksForClient(vendor config.RadiusVendorConfig, client config.RadiusClient) []string {
	return ReplyCompatibilityPacksForNASType(vendor, client.NASType)
}

func ReplyCompatibilityPacksForNASType(vendor config.RadiusVendorConfig, nasType string) []string {
	configured := normalizeReplyPackKeys(vendor.CompatibilityPacks)
	profile := NormalizeClientNASType(nasType)
	if profile == "other" {
		return configured
	}
	if !productconfigs.ValidVendorCompatibilityPackKey(profile) {
		return configured
	}

	selected := []string{productconfigs.VendorPackStandard}
	if profile != productconfigs.VendorPackStandard {
		selected = append(selected, profile)
	}
	for _, key := range []string{productconfigs.VendorPackAegisNAS, productconfigs.VendorPackWISPr} {
		if key == profile {
			continue
		}
		if replyPackContains(configured, key) {
			selected = append(selected, key)
		}
	}
	return normalizeReplyPackKeys(selected)
}

func RenderReplyAttributesForClient(attrs *ReplyAttributes, vendor config.RadiusVendorConfig, client config.RadiusClient) string {
	return RenderReplyAttributesForPacks(attrs, ReplyCompatibilityPacksForClient(vendor, client))
}

func replyPackContains(packs []string, key string) bool {
	key = productconfigs.NormalizeVendorCompatibilityPackKey(key)
	for _, pack := range packs {
		if pack == key {
			return true
		}
	}
	return false
}

func validClientProfileToken(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}
