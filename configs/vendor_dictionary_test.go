package configs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAegisNASVendorDictionary(t *testing.T) {
	dict := AegisNASVendorDictionary()

	assert.Equal(t, "AegisNAS", dict.Name)
	assert.Equal(t, 55555, dict.ID)
	require.Len(t, dict.Attributes, 11)
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Role", Number: 1, Type: "string"}, dict.Attributes[0])
	assert.Equal(t, VendorDictionaryAttribute{Name: "AegisNAS-Tenant", Number: 11, Type: "string"}, dict.Attributes[10])
}
