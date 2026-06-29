package radius

import (
	"fmt"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func RecordVendorAuthTransportFailure(cfg *config.Config, message string) {
	recordVendorPackOutcome(cfg, "global", func(key string) db.VendorObservabilityDelta {
		return db.VendorObservabilityDelta{
			VendorKey:        key,
			AuthFailureDelta: 1,
			Message:          message,
		}
	})
}

func RecordVendorAuthResult(cfg *config.Config, result *BrokerAuthResult, packet *layehradius.Packet) {
	if cfg == nil || result == nil {
		return
	}
	responseCode := ""
	if packet != nil {
		responseCode = packet.Code.String()
	}
	recordVendorPackOutcome(cfg, "global", func(key string) db.VendorObservabilityDelta {
		delta := db.VendorObservabilityDelta{
			VendorKey: key,
			Message:   fmt.Sprintf("auth response %s", responseCode),
		}
		if result.Accepted {
			delta.AuthSuccessDelta = 1
		} else {
			delta.AuthFailureDelta = 1
		}
		return delta
	})
	recordKnownParsedResultAttributes(result)
	RecordVendorPacketObservability(cfg, packet, "global", "auth response")
}

func RecordVendorDynamicAuth(cfg *config.Config, packet *layehradius.Packet, action string, success bool, message string) {
	if cfg == nil {
		return
	}
	recordVendorPackOutcome(cfg, "global", func(key string) db.VendorObservabilityDelta {
		delta := db.VendorObservabilityDelta{
			VendorKey: key,
			Message:   message,
		}
		switch action {
		case "disconnect":
			if success {
				delta.DisconnectSuccessDelta = 1
			} else {
				delta.DisconnectFailureDelta = 1
			}
		default:
			if success {
				delta.CoASuccessDelta = 1
			} else {
				delta.CoAFailureDelta = 1
			}
		}
		return delta
	})
	RecordVendorPacketObservability(cfg, packet, "global", message)
}

func RecordVendorPacketObservability(cfg *config.Config, packet *layehradius.Packet, nasType, message string) {
	if cfg == nil || packet == nil {
		return
	}
	inspector := newVendorPacketInspector(cfg.Radius.Vendor)
	for _, avp := range packet.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		vendorID, vsa, err := layehradius.VendorSpecific(avp.Attribute)
		if err != nil {
			_ = db.RecordVendorObservability(db.VendorObservabilityDelta{
				VendorKey:            "unknown-vendor",
				NASType:              nasType,
				VSAParseFailureDelta: 1,
				Message:              message,
			})
			continue
		}
		inspector.recordVendorSpecificAttributes(vendorID, vsa, nasType, message)
	}
}

type vendorPacketInspector struct {
	knownTypesByVendorAndPack map[uint32]map[string]map[byte]struct{}
	knownPacksByVendor        map[uint32][]string
	productVendorID           uint32
	productTypes              map[byte]struct{}
}

func newVendorPacketInspector(vendor config.RadiusVendorConfig) vendorPacketInspector {
	inspector := vendorPacketInspector{
		knownTypesByVendorAndPack: map[uint32]map[string]map[byte]struct{}{},
		knownPacksByVendor:        map[uint32][]string{},
		productTypes:              map[byte]struct{}{},
	}
	active := activeVendorPackSet(vendor)
	for _, mapping := range inboundVendorMappings {
		if _, ok := active[mapping.PackKey]; !ok {
			continue
		}
		if inspector.knownTypesByVendorAndPack[mapping.VendorID] == nil {
			inspector.knownTypesByVendorAndPack[mapping.VendorID] = map[string]map[byte]struct{}{}
		}
		if inspector.knownTypesByVendorAndPack[mapping.VendorID][mapping.PackKey] == nil {
			inspector.knownTypesByVendorAndPack[mapping.VendorID][mapping.PackKey] = map[byte]struct{}{}
			inspector.knownPacksByVendor[mapping.VendorID] = append(inspector.knownPacksByVendor[mapping.VendorID], mapping.PackKey)
		}
		inspector.knownTypesByVendorAndPack[mapping.VendorID][mapping.PackKey][mapping.Type] = struct{}{}
	}
	if vendor.Enabled && vendor.ID > 0 {
		inspector.productVendorID = uint32(vendor.ID)
		for _, attr := range EffectiveVendorAttributes(vendor) {
			if attr.Number >= 1 && attr.Number <= 255 {
				inspector.productTypes[byte(attr.Number)] = struct{}{}
			}
		}
	}
	return inspector
}

func (i vendorPacketInspector) recordVendorSpecificAttributes(vendorID uint32, vsa layehradius.Attribute, nasType, message string) {
	if i.productVendorID > 0 && vendorID == i.productVendorID {
		i.recordProductAttributes(vsa, nasType, message)
		return
	}

	packs := i.knownPacksByVendor[vendorID]
	if len(packs) == 0 {
		_ = db.RecordVendorObservability(db.VendorObservabilityDelta{
			VendorKey:                 fmt.Sprintf("vendor-%d", vendorID),
			NASType:                   nasType,
			UnsupportedAttributeDelta: 1,
			Message:                   message,
		})
		return
	}
	for len(vsa) > 0 {
		if len(vsa) < 2 {
			i.recordParseFailure(packs, nasType, message)
			return
		}
		vsaType, vsaLen := vsa[0], int(vsa[1])
		if vsaLen < 2 || vsaLen > len(vsa) {
			i.recordParseFailure(packs, nasType, message)
			return
		}
		for _, pack := range packs {
			if _, ok := i.knownTypesByVendorAndPack[vendorID][pack][vsaType]; ok {
				_ = db.RecordVendorObservability(db.VendorObservabilityDelta{
					VendorKey:      pack,
					NASType:        nasType,
					VSAParsedDelta: 1,
					Message:        message,
				})
			} else {
				_ = db.RecordVendorObservability(db.VendorObservabilityDelta{
					VendorKey:                 pack,
					NASType:                   nasType,
					UnsupportedAttributeDelta: 1,
					Message:                   message,
				})
			}
		}
		vsa = vsa[vsaLen:]
	}
}

func (i vendorPacketInspector) recordProductAttributes(vsa layehradius.Attribute, nasType, message string) {
	for len(vsa) > 0 {
		if len(vsa) < 2 {
			_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackAegisNAS, NASType: nasType, VSAParseFailureDelta: 1, Message: message})
			return
		}
		vsaType, vsaLen := vsa[0], int(vsa[1])
		if vsaLen < 2 || vsaLen > len(vsa) {
			_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackAegisNAS, NASType: nasType, VSAParseFailureDelta: 1, Message: message})
			return
		}
		if _, ok := i.productTypes[vsaType]; ok {
			_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackAegisNAS, NASType: nasType, VSAParsedDelta: 1, Message: message})
		} else {
			_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackAegisNAS, NASType: nasType, UnsupportedAttributeDelta: 1, Message: message})
		}
		vsa = vsa[vsaLen:]
	}
}

func (i vendorPacketInspector) recordParseFailure(packs []string, nasType, message string) {
	for _, pack := range packs {
		_ = db.RecordVendorObservability(db.VendorObservabilityDelta{
			VendorKey:            pack,
			NASType:              nasType,
			VSAParseFailureDelta: 1,
			Message:              message,
		})
	}
}

func recordKnownParsedResultAttributes(result *BrokerAuthResult) {
	if result == nil {
		return
	}
	if result.MikrotikRateLimit != "" {
		_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackMikroTik, VSAParsedDelta: 1, Message: "auth response parsed MikroTik rate limit"})
	}
	if result.WISPrBandwidthMaxDown > 0 || result.WISPrBandwidthMaxUp > 0 {
		_ = db.RecordVendorObservability(db.VendorObservabilityDelta{VendorKey: productconfigs.VendorPackWISPr, VSAParsedDelta: 1, Message: "auth response parsed WISPr bandwidth"})
	}
}

func recordVendorPackOutcome(cfg *config.Config, nasType string, build func(string) db.VendorObservabilityDelta) {
	if cfg == nil {
		return
	}
	for _, key := range activeVendorPackKeys(cfg.Radius.Vendor) {
		delta := build(key)
		delta.VendorKey = key
		delta.NASType = nasType
		_ = db.RecordVendorObservability(delta)
	}
}

func activeVendorPackKeys(vendor config.RadiusVendorConfig) []string {
	keys := normalizeReplyPackKeys(vendor.CompatibilityPacks)
	if len(keys) == 0 {
		keys = []string{productconfigs.VendorPackStandard}
	}
	return keys
}

func activeVendorPackSet(vendor config.RadiusVendorConfig) map[string]struct{} {
	set := map[string]struct{}{}
	for _, key := range activeVendorPackKeys(vendor) {
		set[key] = struct{}{}
	}
	return set
}
