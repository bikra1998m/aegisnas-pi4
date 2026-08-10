package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNASSessionOwnershipSyncsActiveSessionsAndCapabilities(t *testing.T) {
	require.NoError(t, Init(":memory:"))
	DB.SetMaxOpenConns(1)
	defer Close()
	require.NoError(t, Migrate())

	capabilitiesJSON := `{
		"dynamic_authorization": {
			"coa": true,
			"disconnect": true,
			"vendor_actions": true,
			"transport": {"udp": true, "radsec": false, "proxy": false}
		},
		"policy": {"filter_id": true, "vlan": true, "acl": true}
	}`
	_, err := DB.Exec(`INSERT INTO radius_clients (
		shortname, ipaddr, secret, nas_type, enabled, transport, capabilities_json
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"branch-ap", "192.0.2.10", "shared-secret", "cisco", true, "udp", capabilitiesJSON)
	require.NoError(t, err)

	_, err = DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, nas_identifier, radius_session_id, start_time, last_activity
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"session-1", "alice@example.test", "AA-BB-CC-DD-EE-FF", "192.0.2.100", "dot1x",
		"branch-ap", "acct-123", "2026-05-05T11:00:00Z", "2026-05-05T11:30:00Z")
	require.NoError(t, err)

	synced, err := SyncNASSessionOwnershipFromSessions("node-a", time.Hour, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, synced)

	owner, err := LookupNASSessionOwnership("acct-123")
	require.NoError(t, err)
	assert.Equal(t, "session-1", owner.SessionID)
	assert.Equal(t, "acct-123", owner.AcctSessionID)
	assert.Equal(t, "branch-ap", owner.NASIdentifier)
	assert.Equal(t, "192.0.2.10", owner.NASIPAddress)
	assert.Equal(t, "branch-ap", owner.ShortName)
	assert.Equal(t, "cisco", owner.NASType)
	assert.Equal(t, NASSessionOwnershipStatusActive, owner.OwnerStatus)
	assert.Equal(t, "node-a", owner.OwnerNode)
	assert.Contains(t, owner.SupportedActions, "coa")
	assert.Contains(t, owner.SupportedActions, "disconnect")
	assert.Contains(t, owner.SupportedActions, "vendor_actions")
	assert.Contains(t, owner.SupportedTransports, "udp")
	assert.NotEmpty(t, owner.CapabilityHash)

	summary, err := GetNASCapabilityOwnershipSummary()
	require.NoError(t, err)
	assert.Equal(t, "ready", summary.Status)
	assert.Equal(t, 1, summary.EnabledClients)
	assert.Equal(t, 1, summary.CapabilityClients)
	assert.Equal(t, 1, summary.ActiveSessions)
	assert.Equal(t, 1, summary.OwnedSessions)
	assert.Equal(t, 100, summary.OwnershipCoverage)

	clients, err := ListNASCapabilityClients(10)
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "branch-ap", clients[0].ShortName)
	assert.True(t, clients[0].SecretSet)
	actions, transports := SupportedNASSessionOwnershipFromCapabilities(clients[0].Capabilities, clients[0].Transport)
	assert.Contains(t, actions, "vendor_actions")
	assert.Contains(t, transports, "udp")
}
