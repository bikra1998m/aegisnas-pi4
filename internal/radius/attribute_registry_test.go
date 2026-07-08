package radius

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratedAttributeRegistryPreservesInboundPacketContract(t *testing.T) {
	generated := map[string]struct{}{}
	for _, mapping := range inboundVendorMappings {
		generated[inboundMappingContractKey(mapping)] = struct{}{}
	}

	for _, legacy := range inboundPacketCompatibilityContract {
		key := inboundMappingContractKey(legacy)
		if _, ok := generated[key]; !ok {
			assert.Fail(t, "generated registry lost an inbound packet mapping", key)
		}
	}
}

func inboundMappingContractKey(mapping inboundVendorMapping) string {
	return fmt.Sprintf("%s/%d/%d/%s/%s", mapping.PackKey, mapping.VendorID, mapping.Type, mapping.Semantic, mapping.Kind)
}
