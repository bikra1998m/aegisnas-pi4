package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRadiusPacketHardeningEventsPersistAndTrim(t *testing.T) {
	previous := DB
	file, err := os.CreateTemp("", "aegis-radius-hardening-*.db")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	t.Cleanup(func() {
		_ = Close()
		DB = previous
		_ = os.Remove(file.Name())
	})

	require.NoError(t, Init(file.Name()))
	require.NoError(t, Migrate())

	now := time.Now().UTC()
	require.NoError(t, RecordRadiusPacketHardeningEvent(RadiusPacketHardeningEvent{
		ObservedAt:                  now.Format(time.RFC3339),
		SourceIP:                    "192.0.2.10",
		Direction:                   "authentication",
		PacketCode:                  "Access-Request",
		PacketIdentifier:            7,
		Decision:                    "rejected",
		Reason:                      "missing_message_authenticator",
		Message:                     "Message-Authenticator is required.",
		PacketLength:                42,
		AttributeCount:              1,
		MessageAuthenticatorPresent: false,
		Details:                     map[string]any{"policy": "auto"},
	}, 1))
	require.NoError(t, RecordRadiusPacketHardeningEvent(RadiusPacketHardeningEvent{
		ObservedAt:       now.Add(time.Second).Format(time.RFC3339),
		SourceIP:         "192.0.2.11",
		Direction:        "accounting",
		PacketCode:       "Accounting-Request",
		PacketIdentifier: 8,
		Decision:         "accepted",
		Reason:           "accepted",
		Message:          "Packet accepted.",
	}, 1))

	events, err := ListRadiusPacketHardeningEvents(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.Equal(t, "192.0.2.11", events[0].SourceIP)

	stats, err := GetRadiusPacketHardeningStats()
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalEvents)
	assert.Equal(t, 1, stats.AcceptedCount)
	assert.Equal(t, 0, stats.RejectedCount)
}
