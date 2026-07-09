package configs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltInAttributeRegistryContract(t *testing.T) {
	registry, err := BuiltInAttributeRegistry()
	require.NoError(t, err)
	require.NotNil(t, registry)

	assert.Equal(t, AttributeRegistrySchemaVersion, registry.SchemaVersion)
	assert.Equal(t, DefaultDictionaryReleaseProfileID, registry.ReleaseProfileID)
	assert.Equal(t, "3.2.8", registry.SourceRelease)
	assert.Equal(t, 246, registry.SourceFileCount)
	assert.Equal(t, 196, registry.VendorCount)
	assert.Equal(t, 7654, registry.SourceAttributeCount)
	assert.Equal(t, 7661, registry.AttributeCount)
	assert.Equal(t, 148, registry.MappedCount)
	assert.Len(t, registry.SourceSHA256, 64)
	assert.Len(t, registry.RuntimeMappings(), 134)
}

func TestAttributeRegistryIndexesAndRuntimeCodecs(t *testing.T) {
	registry := MustBuiltInAttributeRegistry()

	cisco, ok := registry.LookupName("Cisco", "Cisco-AVPair")
	require.True(t, ok)
	assert.Equal(t, uint32(9), cisco.PEN)
	assert.Equal(t, uint32(1), cisco.Number)
	assert.Equal(t, "string", cisco.DecodeKind)
	assert.Contains(t, cisco.Directions, "inbound")

	aliases := registry.LookupWire(26928, 1)
	require.Len(t, aliases, 2)
	assert.Equal(t, "vsa:26928:1", aliases[0].WireKey)

	ubnt, ok := registry.LookupName("Ubiquiti", "UBNT-Data-Rate-DL")
	require.True(t, ok)
	assert.Equal(t, "aegisnas-runtime", ubnt.Source)
	assert.Equal(t, "aegisnas-runtime", ubnt.SemanticProvenance)
	assert.Equal(t, "rate_bps", ubnt.DecodeKind)
	assert.Equal(t, 1000, ubnt.DecodeScale)

	nokia, ok := registry.LookupName("Nokia", "Nokia-Service-Name")
	require.True(t, ok)
	assert.Equal(t, "nokia_bcd", nokia.DecodeKind)

	wimax, ok := registry.LookupName("WiMAX", "WiMAX-Termination-Action")
	require.True(t, ok)
	assert.Equal(t, []uint32{37, 12}, wimax.OIDPath)
	assert.True(t, wimax.WireCodec.Grouped)
	assert.True(t, wimax.WireCodec.Repeated)
	assert.Equal(t, 1, wimax.WireCodec.TypeOctets)
	assert.Equal(t, 1, wimax.WireCodec.LengthOctets)
}

func TestAttributeRegistryValidatesRendererPackContract(t *testing.T) {
	registry := MustBuiltInAttributeRegistry()
	require.NoError(t, registry.ValidateCompatibilityPacks(AegisNASVendorCompatibilityPacks()))

	broken := AegisNASVendorCompatibilityPacks()
	for idx := range broken {
		if broken[idx].Key == VendorPackAruba {
			broken[idx].Attributes[0].Semantic = VendorSemanticTenant
			break
		}
	}
	require.ErrorContains(t, registry.ValidateCompatibilityPacks(broken), "conflicts with registry semantic")
}

func TestParseAttributeRegistryCSVRejectsInvalidContracts(t *testing.T) {
	_, err := ParseAttributeRegistryCSV([]byte("wrong,header\n"))
	require.Error(t, err)

	header := "Vendor,PEN,Attribute,Number,OID,Type,EnumeratedValues,CapabilityFamily,Status,Pack,Semantic,Direction,Functionality\n"
	duplicate := header + strings.Join([]string{
		"Acme,424242,Acme-Role,1,,string,,Authorization,partial,acme,access.role,inbound,role",
		"Acme,424242,Acme-Role,1,,string,,Authorization,partial,acme,access.role,inbound,role",
	}, "\n") + "\n"
	_, err = ParseAttributeRegistryCSV([]byte(duplicate))
	require.ErrorContains(t, err, "duplicates Acme/Acme-Role")

	invalidType := header + "Acme,424242,Acme-Role,1,,javascript,,Authorization,partial,acme,access.role,inbound,role\n"
	_, err = ParseAttributeRegistryCSV([]byte(invalidType))
	require.ErrorContains(t, err, "valid wire type")
}

func FuzzParseAttributeRegistryCSV(f *testing.F) {
	f.Add([]byte("Vendor,PEN,Attribute,Number,OID,Type,EnumeratedValues,CapabilityFamily,Status,Pack,Semantic,Direction,Functionality\nAcme,424242,Acme-Role,1,,string,,Authorization,partial,acme,access.role,inbound,role\n"))
	f.Add([]byte("not,a,registry\n"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseAttributeRegistryCSV(payload)
	})
}

func BenchmarkAttributeRegistryLookupWire(b *testing.B) {
	registry := MustBuiltInAttributeRegistry()
	b.ReportAllocs()
	for b.Loop() {
		entries := registry.LookupWire(14823, 1)
		if len(entries) == 0 {
			b.Fatal("Aruba-User-Role is absent")
		}
	}
}
