package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMABEndpointAndEventLifecycle(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mab-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	assert.Equal(t, "aa:bb:cc:dd:ee:ff", NormalizeMABMAC("aabb.ccdd.eeff"))
	assert.NotEmpty(t, HashMABMAC("AA-BB-CC-DD-EE-FF"))

	stored, err := UpsertMABEndpoint(MABEndpoint{
		MAC:                 "AA-BB-CC-DD-EE-FF",
		Status:              "approved",
		Role:                "printer",
		VLAN:                30,
		BandwidthProfile:    "iot-low",
		ACLPolicyName:       "printer-acl",
		Tenant:              "tenant-a",
		DeviceGroup:         "printers",
		Posture:             "trusted",
		Source:              "api",
		ProfileSnapshotJSON: `{"platform":"printer"}`,
	}, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", stored.MAC)
	assert.Equal(t, "approved", stored.Status)

	found, ok, err := GetMABEndpoint("aabbccddeeff")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "printer", found.Role)
	assert.Equal(t, 30, found.VLAN)

	endpoints, err := ListMABEndpoints("approved", 10)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)

	summary, err := GetMABEndpointSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEndpoints)
	assert.Equal(t, 1, summary.ApprovedCount)
	assert.Equal(t, 1, summary.ProfileLinkedCount)

	require.NoError(t, RecordMABEvent(MABEvent{
		MAC:              "aa:bb:cc:dd:ee:ff",
		NASIdentifier:    "sw1",
		NASPortType:      "Ethernet",
		Decision:         "accepted",
		State:            "approved",
		Reason:           "endpoint is approved",
		Role:             "printer",
		VLAN:             30,
		BandwidthProfile: "iot-low",
		ACLPolicyName:    "printer-acl",
		Tenant:           "tenant-a",
		DeviceGroup:      "printers",
		Posture:          "trusted",
	}, map[string]any{"test": true}, 100))

	events, err := ListMABEvents("accepted", "aa-bb-cc-dd-ee-ff", 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, HashMABMAC("aa:bb:cc:dd:ee:ff"), events[0].MACHash)

	eventSummary, err := GetMABEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, eventSummary.TotalRecords)
	assert.Equal(t, 1, eventSummary.AcceptedCount)

	deleted, err := DeleteMABEndpoint("aabb.ccdd.eeff")
	require.NoError(t, err)
	assert.True(t, deleted)
}
