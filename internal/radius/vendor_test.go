package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

func TestApplyVendorAttributesParsesAegisNASVSAs(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrRole, "guest-premium"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrBandwidthProfile, "50m-down-20m-up"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrVLAN, 20))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrQuarantine, 1))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), AegisNASVendorAttrPolicyTag, "premium"))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrSessionTimeout, 3600))
	require.NoError(t, addVendorInteger(packet, uint32(vendor.ID), AegisNASVendorAttrIdleTimeout, 600))

	result := ParseBrokerPacket(packet)
	ApplyVendorAttributes(result, packet, vendor)

	assert.Equal(t, "guest-premium", result.VendorRole)
	assert.Equal(t, "50m-down-20m-up", result.VendorBandwidthProfile)
	assert.Equal(t, "premium", result.VendorPolicyTag)
	assert.True(t, result.HasVendorVLAN)
	assert.Equal(t, 20, result.VendorVLAN)
	assert.True(t, result.HasVendorQuarantine)
	assert.True(t, result.VendorQuarantine)
	assert.True(t, result.HasVendorSessionTimeout)
	assert.Equal(t, 3600, result.VendorSessionTimeout)
	assert.True(t, result.HasVendorIdleTimeout)
	assert.Equal(t, 600, result.VendorIdleTimeout)
}

func TestVendorAttributeOverrideByName(t *testing.T) {
	productRole := productconfigs.AegisNASVendorDictionary().Attributes[0]
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
		Attributes: []config.RadiusVendorAttribute{
			{Name: productRole.Name, Number: 20, Type: productRole.Type},
		},
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, uint32(vendor.ID), 20, "admin"))

	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, "admin", result.VendorRole)
	attrs := EffectiveVendorAttributes(vendor)
	assert.Equal(t, byte(20), vendorAttributeNumber(attrs, AegisNASVendorAttrRole))
}

func TestAddVendorAccountingAttributes(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true,
		Name:    "AegisNAS",
		ID:      55555,
	}
	packet := layehradius.New(layehradius.CodeAccountingRequest, []byte("secret"))
	rec := &AccountingRecord{
		Role:             "guest-premium",
		BandwidthProfile: "50m-down-20m-up",
		FilterID:         "premium",
		VLAN:             20,
		SessionTimeout:   3600,
		IdleTimeout:      600,
	}

	require.NoError(t, AddVendorAccountingAttributes(packet, vendor, rec))
	result := ParseBrokerPacketWithConfig(packet, &config.Config{Radius: config.RadiusConfig{Vendor: vendor}})

	assert.Equal(t, rec.Role, result.VendorRole)
	assert.Equal(t, rec.BandwidthProfile, result.VendorBandwidthProfile)
	assert.Equal(t, rec.FilterID, result.VendorPolicyTag)
	assert.Equal(t, rec.VLAN, result.VendorVLAN)
	assert.Equal(t, rec.SessionTimeout, result.VendorSessionTimeout)
	assert.Equal(t, rec.IdleTimeout, result.VendorIdleTimeout)
}

func TestResolveSessionPolicyUsesVendorAttributes(t *testing.T) {
	oldDB := db.DB
	db.DB = nil
	defer func() { db.DB = oldDB }()

	policy, err := ResolveSessionPolicy("guest-basic", &BrokerAuthResult{
		VendorRole:              "guest-premium",
		VendorBandwidthProfile:  "50m-down-20m-up",
		VendorPolicyTag:         "premium",
		VendorVLAN:              20,
		HasVendorVLAN:           true,
		VendorSessionTimeout:    3600,
		HasVendorSessionTimeout: true,
		VendorIdleTimeout:       600,
		HasVendorIdleTimeout:    true,
	})
	require.NoError(t, err)

	assert.Equal(t, "guest-premium", policy.Role)
	assert.Equal(t, "50m-down-20m-up", policy.BandwidthProfile)
	assert.Equal(t, "premium", policy.FilterID)
	assert.Equal(t, 20, policy.VLAN)
	assert.Equal(t, 3600, policy.SessionTimeout)
	assert.Equal(t, 600, policy.IdleTimeout)
}
