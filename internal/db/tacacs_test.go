package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTACACSCommandSetAndEvidenceLifecycle(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "tacacs-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	defer os.Remove(dbPath)

	require.NoError(t, Init(dbPath))
	defer Close()
	require.NoError(t, Migrate())

	set, err := UpsertTACACSCommandSet(TACACSCommandSetRecord{
		Name:            "ops-show",
		Enabled:         true,
		DefaultAction:   "deny",
		Permit:          []string{"show *"},
		Roles:           []string{"ops"},
		PrivilegeLevels: []int{5, 15},
		Vendors:         []string{"Cisco"},
		Source:          "api",
		CreatedBy:       "tester",
		UpdatedBy:       "tester",
	})
	require.NoError(t, err)
	assert.Equal(t, "ops-show", set.Name)
	assert.Equal(t, []string{"cisco"}, set.Vendors)
	assert.NotEmpty(t, set.ContentHash)

	require.NoError(t, RecordTACACSAuthorizationEvent(TACACSAuthorizationEvent{
		EventID:           "authz-1",
		SessionID:         123,
		UsernameHash:      "alice",
		Role:              "ops",
		ClientName:        "sw1",
		ClientIP:          "192.0.2.10",
		Vendor:            "cisco",
		Service:           "shell",
		Command:           "show version",
		PrivilegeLevel:    5,
		Decision:          "permit",
		MatchedCommandSet: "ops-show",
		Args:              []string{"cmd=show", "cmd-arg=version"},
		RequestJSON:       `{"command":"show version"}`,
		ResponseJSON:      `{"status":"permit"}`,
	}, 100))
	require.NoError(t, RecordTACACSAccountingRecord(TACACSAccountingRecord{
		SessionID:      123,
		TaskID:         "task-1",
		UsernameHash:   "alice",
		Role:           "ops",
		ClientName:     "sw1",
		ClientIP:       "192.0.2.10",
		Command:        "show version",
		PrivilegeLevel: 5,
		Flags:          1,
		Args:           []string{"task_id=task-1", "cmd=show", "cmd-arg=version"},
		RequestJSON:    `{"task_id":"task-1"}`,
	}, 100))

	summary, err := SummarizeTACACS(100)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.CommandSetCount)
	assert.Equal(t, 1, summary.AuthorizationEvents)
	assert.Equal(t, 1, summary.PermitCount)
	assert.Equal(t, 1, summary.AccountingRecords)

	authz, err := ListTACACSAuthorizationEvents(10)
	require.NoError(t, err)
	require.Len(t, authz, 1)
	assert.NotEqual(t, "alice", authz[0].UsernameHash)
	assert.Equal(t, HashCommand("show version"), authz[0].CommandHash)
}
