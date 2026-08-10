package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACLCompilerEventHistorySummary(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	require.NoError(t, Migrate())
	defer Close()

	compiledID, err := RecordACLCompilerEvent(ACLCompilerEventInput{
		Operation:           "compile",
		Status:              "compiled",
		PackKey:             "cisco",
		PolicyName:          "guest-internet",
		ASTFingerprint:      "sha256:ast",
		ArtifactFingerprint: "sha256:artifact",
		ArtifactCount:       3,
		RuleCount:           2,
		Lossless:            true,
		Actor:               "ops",
	})
	require.NoError(t, err)
	require.NotEmpty(t, compiledID)

	profileID, err := RecordACLCompilerEvent(ACLCompilerEventInput{
		Operation:     "decompile",
		Status:        "profile_reference",
		PackKey:       "mikrotik",
		PolicyName:    "guest-internet",
		ArtifactCount: 1,
		RuleCount:     0,
		Lossless:      false,
	})
	require.NoError(t, err)
	require.NotEmpty(t, profileID)
	assert.NotEqual(t, compiledID, profileID)

	events, err := ListACLCompilerEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "mikrotik", events[0].PackKey)
	assert.Equal(t, "profile_reference", events[0].Status)
	assert.Equal(t, "[]", events[0].DiagnosticsJSON)
	assert.Equal(t, "{}", events[0].DetailsJSON)

	summary, err := GetACLCompilerEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 1, summary.CompileEvents)
	assert.Equal(t, 1, summary.DecompileEvents)
	assert.Equal(t, 1, summary.CompiledCount)
	assert.Equal(t, 1, summary.ProfileReferenceCount)
	assert.Equal(t, 1, summary.LosslessCount)
	assert.Equal(t, 4, summary.ArtifactCount)
}
