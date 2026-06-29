package radius

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

func TestRecordVendorAuthResultCountsParsedAndUnsupportedVSAs(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "radius-vendor-observability-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Vendor: vendorConfigForPacks(productconfigs.VendorPackAruba),
		},
	}
	packet := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, addVendorString(packet, 14823, 1, "guest"))
	require.NoError(t, addVendorString(packet, 14823, 99, "not-mapped"))

	result := ParseBrokerPacketWithConfig(packet, cfg)
	result.Accepted = true
	RecordVendorAuthResult(cfg, result, packet)

	records, err := db.ListVendorObservability(10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, productconfigs.VendorPackAruba, records[0].VendorKey)
	assert.Equal(t, 1, records[0].AuthSuccessCount)
	assert.Equal(t, 1, records[0].VSAParsedCount)
	assert.Equal(t, 1, records[0].UnsupportedAttributeCount)
	assert.Less(t, records[0].CompatibilityScore, 100)
}
