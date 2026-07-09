package radius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestOpaquePassThroughPreservesAllowedUnknownVendorAttribute(t *testing.T) {
	request := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, AddVendorAttributeWithSpec(request, VendorAttributeSpec{VendorID: 424242, Type: 77}, layehradius.Attribute("opaque-token")))

	policy := DefaultOpaquePassThroughPolicy()
	policy.Rules = []OpaquePassThroughRule{
		{Direction: OpaquePassThroughDirectionProxyResponse, Kind: OpaquePassThroughKindVendorAttribute, VendorID: 424242, Type: 77},
	}

	result := CollectOpaqueAttributes(request, OpaquePassThroughDirectionProxyResponse, policy, nil)
	require.Empty(t, result.Errors)
	require.Len(t, result.Accepted, 1)
	assert.Empty(t, result.Dropped)
	assert.Equal(t, uint32(424242), result.Accepted[0].VendorID)
	assert.Equal(t, uint32(77), result.Accepted[0].VendorType)
	assert.Equal(t, OpaqueRegistryStateUnregistered, result.Accepted[0].RegistryState)
	assert.NotEmpty(t, result.Accepted[0].RawSHA256)

	response := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, ApplyOpaqueAttributes(response, result.Accepted, policy))
	value, ok := LookupVendorAttributeValue(response, 424242, 77)
	require.True(t, ok)
	assert.Equal(t, "opaque-token", string(value))
}

func TestOpaquePassThroughDropsByDefaultAndAllowsSafeStandardType(t *testing.T) {
	request := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	request.Add(layehradius.Type(25), layehradius.Attribute("upstream-class"))

	defaultResult := CollectOpaqueAttributes(request, OpaquePassThroughDirectionProxyResponse, DefaultOpaquePassThroughPolicy(), nil)
	require.Len(t, defaultResult.Dropped, 1)
	assert.Equal(t, "default_drop", defaultResult.Dropped[0].Reason)

	policy := DefaultOpaquePassThroughPolicy()
	policy.Rules = []OpaquePassThroughRule{{Direction: OpaquePassThroughDirectionAny, Kind: OpaquePassThroughKindStandard, Type: 25}}
	result := CollectOpaqueAttributes(request, OpaquePassThroughDirectionProxyResponse, policy, nil)
	require.Empty(t, result.Errors)
	require.Len(t, result.Accepted, 1)
	assert.Equal(t, uint32(25), result.Accepted[0].Type)

	response := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, ApplyOpaqueAttributes(response, result.Accepted, policy))
	require.Len(t, response.Attributes, 1)
	assert.Equal(t, layehradius.Type(25), response.Attributes[0].Type)
	assert.Equal(t, "upstream-class", string(response.Attributes[0].Attribute))
}

func TestOpaquePassThroughRejectsSensitiveStandardRules(t *testing.T) {
	policy := DefaultOpaquePassThroughPolicy()
	policy.Rules = []OpaquePassThroughRule{{Direction: OpaquePassThroughDirectionAny, Kind: OpaquePassThroughKindStandard, Type: 2}}
	require.ErrorContains(t, policy.Validate(), "User-Password")
}

func TestOpaquePassThroughRejectsMalformedAndBoundedVendorPayloads(t *testing.T) {
	request := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	malformed, err := layehradius.NewVendorSpecific(424242, layehradius.Attribute{77, 9, 'x'})
	require.NoError(t, err)
	request.Add(rfc2865.VendorSpecific_Type, malformed)

	policy := DefaultOpaquePassThroughPolicy()
	policy.Rules = []OpaquePassThroughRule{{Direction: OpaquePassThroughDirectionProxyResponse, Kind: OpaquePassThroughKindVendor, VendorID: 424242}}
	result := CollectOpaqueAttributes(request, OpaquePassThroughDirectionProxyResponse, policy, nil)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors[0], "exceeds remaining")
	assert.Empty(t, result.Accepted)

	bounded := layehradius.New(layehradius.CodeAccessAccept, []byte("secret"))
	require.NoError(t, AddVendorAttributeWithSpec(bounded, VendorAttributeSpec{VendorID: 424242, Type: 77}, layehradius.Attribute("oversized")))
	policy.Rules = []OpaquePassThroughRule{{Direction: OpaquePassThroughDirectionProxyResponse, Kind: OpaquePassThroughKindVendorAttribute, VendorID: 424242, Type: 77, MaxAttributeBytes: 4}}
	result = CollectOpaqueAttributes(bounded, OpaquePassThroughDirectionProxyResponse, policy, nil)
	require.Len(t, result.Dropped, 1)
	assert.Contains(t, result.Dropped[0].Reason, "attribute_too_large")
}

func TestOpaquePassThroughReportExposesConservativeDefaults(t *testing.T) {
	report := BuildOpaquePassThroughReport(nil, nil)
	assert.Equal(t, OpaquePassThroughSchemaVersion, report.SchemaVersion)
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.Policy.Enabled)
	assert.True(t, report.Summary.DefaultActionDrop)
	assert.Equal(t, "drop", report.Policy.DefaultAction)
	assert.Greater(t, report.Summary.SourceAttributeCount, 7000)
	assert.NotEmpty(t, report.SensitiveTypes)
}
