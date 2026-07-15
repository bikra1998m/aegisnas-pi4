package radius

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestParseBrokerPacketCapturesAccessChallengeState(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessChallenge, []byte("secret"))
	require.NoError(t, rfc2865.ReplyMessage_SetString(packet, "Enter OTP"))
	require.NoError(t, rfc2865.State_Set(packet, []byte{0x01, 0x02, 0x03, 0x04}))

	result := ParseBrokerPacket(packet)
	assert.True(t, result.Challenge)
	assert.Equal(t, "Enter OTP", result.ChallengePrompt)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}), result.ChallengeState)
}

func TestSetRADIUSStateAcceptsBase64URLState(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	encoded := base64.RawURLEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc})

	require.NoError(t, setRADIUSState(packet, encoded))
	state, err := rfc2865.State_Lookup(packet)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc}, state)
}
