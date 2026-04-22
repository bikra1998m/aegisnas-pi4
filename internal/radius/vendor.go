package radius

import (
	"fmt"
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
)

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
	if result == nil || packet == nil || !vendor.Enabled || vendor.ID < 1 {
		return
	}

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

func lookupVendorInteger(packet *layehradius.Packet, vendorID uint32, typ byte) (uint32, bool) {
	attr, ok := lookupVendorAttribute(packet, vendorID, typ)
	if !ok {
		return 0, false
	}
	value, err := layehradius.Integer(attr)
	return value, err == nil
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
