package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantIsolationProfileResourceAndEventPersistence(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "tenant-isolation-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())
	require.NoError(t, Init(tmpfile.Name()))
	t.Cleanup(func() { _ = Close() })
	require.NoError(t, Migrate())

	profile, err := UpsertTenantProfile(TenantProfile{
		TenantKey:           "Tenant-A",
		DisplayName:         "Tenant A",
		DataResidencyRegion: "us-east",
		QuotaJSON:           `{"max_sessions":1000}`,
		ControllerScopeJSON: `{"sites":["branch-1"]}`,
		BillingAccountRef:   "acct-123",
		CreatedBy:           "ops",
		UpdatedBy:           "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", profile.TenantKey)
	assert.Equal(t, "active", profile.Status)
	assert.Equal(t, "tenant-a/secret", profile.SecretNamespace)
	assert.Equal(t, "tenant-a/ca", profile.CANamespace)
	assert.True(t, TenantProfileExists("TENANT-A"))

	binding, err := UpsertTenantResourceBinding(TenantResourceBinding{
		Tenant:       "tenant-a",
		ResourceType: "Policy_Set",
		ResourceID:   "default:tenant-a",
		EvidenceJSON: `{"source":"test"}`,
		CreatedBy:    "ops",
		UpdatedBy:    "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", binding.Tenant)
	assert.Equal(t, "policy_set", binding.ResourceType)
	assert.Equal(t, "tenant", binding.OwnerKind)
	assert.Equal(t, "active", binding.Status)

	require.NoError(t, RecordTenantIsolationEvent(TenantIsolationEvent{
		Tenant:         "tenant-a",
		ResourceType:   "policy_set",
		ResourceID:     "default:tenant-a",
		Action:         "activate",
		Decision:       "allow",
		Reason:         "test activation",
		Actor:          "ops",
		RequestTenants: []string{"tenant-a", "Tenant-A"},
		DetailsJSON:    `{"version":1}`,
	}, 100))

	events, err := ListTenantIsolationEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, []string{"tenant-a"}, events[0].RequestTenants)
	assert.Equal(t, "allow", events[0].Decision)

	summary, err := SummarizeTenantIsolation()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TenantCount)
	assert.Equal(t, 1, summary.ActiveTenantCount)
	assert.Equal(t, 1, summary.ResourceBindingCount)
	assert.Equal(t, 1, summary.IsolationEventCount)
}

func TestTenantIsolationRejectsInvalidInputs(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "tenant-isolation-invalid-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())
	require.NoError(t, Init(tmpfile.Name()))
	t.Cleanup(func() { _ = Close() })
	require.NoError(t, Migrate())

	_, err = UpsertTenantProfile(TenantProfile{TenantKey: "bad tenant"})
	require.ErrorContains(t, err, "tenant_key")

	_, err = UpsertTenantResourceBinding(TenantResourceBinding{Tenant: "", ResourceType: "policy_set", ResourceID: "default"})
	require.ErrorContains(t, err, "tenant is required")

	_, err = UpsertTenantResourceBinding(TenantResourceBinding{Tenant: "tenant-a", ResourceType: "policy_set", ResourceID: "default", OwnerKind: "foreign"})
	require.ErrorContains(t, err, "owner_kind")
}
