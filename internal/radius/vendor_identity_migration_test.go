package radius

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
)

func TestProductVendorMigrationAcceptsLegacyInboundUntilDeadline(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true, Name: "AegisNAS", ID: 424242, IdentityMode: "production",
		LegacyIDs: []int{55555}, LegacyAcceptUntil: "2026-07-09T10:00:00Z",
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 55555, AegisNASVendorAttrRole, "legacy-role"))
	require.NoError(t, addVendorInteger(packet, 55555, AegisNASVendorAttrVLAN, 20))
	result := &BrokerAuthResult{}
	attrs := EffectiveVendorAttributes(vendor)
	for _, id := range ProductVendorInboundIDsAt(vendor, time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)) {
		applyProductVendorID(result, packet, attrs, id)
	}
	assert.Equal(t, "legacy-role", result.VendorRole)
	assert.Equal(t, 20, result.VendorVLAN)
	assert.True(t, result.HasVendorVLAN)
}

func TestProductVendorMigrationPrefersCurrentPENAndExpiresLegacy(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true, ID: 424242, LegacyIDs: []int{55555}, LegacyAcceptUntil: "2026-07-09T10:00:00Z",
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 424242, AegisNASVendorAttrRole, "current-role"))
	require.NoError(t, addVendorString(packet, 55555, AegisNASVendorAttrRole, "legacy-role"))
	result := &BrokerAuthResult{}
	attrs := EffectiveVendorAttributes(vendor)
	for _, id := range ProductVendorInboundIDsAt(vendor, time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)) {
		applyProductVendorID(result, packet, attrs, id)
	}
	assert.Equal(t, "current-role", result.VendorRole)
	assert.Equal(t, []uint32{424242}, ProductVendorInboundIDsAt(vendor, time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)))
}

func TestProductVendorMigrationEmitsOnlyCurrentPEN(t *testing.T) {
	vendor := config.RadiusVendorConfig{
		Enabled: true, ID: 424242, LegacyIDs: []int{55555}, LegacyAcceptUntil: "2099-01-01T00:00:00Z",
	}
	packet := layehradius.New(layehradius.CodeAccountingRequest, []byte("secret"))
	require.NoError(t, AddVendorAccountingAttributes(packet, vendor, &AccountingRecord{Role: "current-role"}))
	_, currentFound := lookupVendorString(packet, 424242, AegisNASVendorAttrRole)
	_, legacyFound := lookupVendorString(packet, 55555, AegisNASVendorAttrRole)
	assert.True(t, currentFound)
	assert.False(t, legacyFound)
}
