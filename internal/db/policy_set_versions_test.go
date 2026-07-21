package db

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySetVersionLifecycle(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "policy-set-versions-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())
	require.NoError(t, Init(tmpfile.Name()))
	t.Cleanup(func() { _ = Close() })
	require.NoError(t, Migrate())

	contentJSON := `{"schema_version":1,"key":"default","name":"Default","enabled":true,"rules":[{"name":"allow-employees","priority":100,"enabled":true,"match_conditions":{"field":"groups","op":"contains","value":"employees"},"action":"allow"}]}`
	created, err := CreatePolicySetVersion(context.Background(), CreatePolicySetVersionRequest{
		SetKey:           "default",
		Description:      "employee policy",
		ContentJSON:      contentJSON,
		ContentSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicySHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RuleCount:        1,
		MaxDepth:         1,
		ApprovalRequired: true,
		MinApprovals:     1,
		CreatedBy:        "maker",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, created.Version)
	assert.Equal(t, PolicySetStatusDraft, created.Status)

	submitted, err := SubmitPolicySetVersion(context.Background(), created.ID, "maker")
	require.NoError(t, err)
	assert.Equal(t, PolicySetStatusPendingApproval, submitted.Status)

	_, err = ApprovePolicySetVersion(context.Background(), created.ID, "maker", "self", 1, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "maker-checker")

	approved, err := ApprovePolicySetVersion(context.Background(), created.ID, "checker", "ok", 1, true)
	require.NoError(t, err)
	assert.Equal(t, PolicySetStatusApproved, approved.Status)
	assert.Equal(t, 1, approved.ApprovalCount)

	tx, err := DB.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = MarkPolicySetVersionActiveTx(tx, created.ID, "admin", "activate")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	active, err := GetActivePolicySetVersion("default")
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, created.ID, active.ID)
	assert.Equal(t, PolicySetStatusActive, active.Status)

	require.NoError(t, RecordPolicySetSimulation(PolicySetSimulation{
		VersionID:        created.ID,
		EvaluationID:     "eval-1",
		PolicySHA256:     active.PolicySHA256,
		RequestHash:      "request-1",
		Decision:         "allow",
		Allowed:          true,
		MatchedRuleCount: 1,
		TraceNodeCount:   1,
		ResultJSON:       `{"ok":true}`,
	}))
	summary, err := SummarizePolicySetVersions()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalVersions)
	assert.Equal(t, 1, summary.ActiveCount)
	assert.Equal(t, 1, summary.SimulationCount)

	events, err := ListPolicySetActivationEvents(10)
	require.NoError(t, err)
	require.NotEmpty(t, events)
}
