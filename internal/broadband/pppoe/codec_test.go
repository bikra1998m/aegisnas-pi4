package pppoe

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalAndParseDiscoveryFrame(t *testing.T) {
	packet, err := MarshalDiscoveryFrame(CodePADI, 0, []Tag{
		{Type: TagServiceName, Value: []byte("internet")},
		{Type: TagHostUniq, Value: []byte{0x01, 0x02, 0x03, 0x04}},
	})
	require.NoError(t, err)

	frame, err := ParseDiscoveryFrame(packet)
	require.NoError(t, err)
	assert.Equal(t, byte(Version), frame.Version)
	assert.Equal(t, byte(Type), frame.Type)
	assert.Equal(t, byte(CodePADI), frame.Code)
	assert.Equal(t, uint16(0), frame.SessionID)
	require.Len(t, frame.Tags, 2)
	assert.Equal(t, TagServiceName, frame.Tags[0].Type)
	assert.Equal(t, []byte("internet"), frame.Tags[0].Value)
	value, ok := TagValueString(frame.Tags, TagServiceName)
	assert.True(t, ok)
	assert.Equal(t, "internet", value)
}

func TestParseDiscoveryFrameRejectsInvalidHeader(t *testing.T) {
	packet, err := MarshalDiscoveryFrame(CodePADO, 0, nil)
	require.NoError(t, err)
	packet[0] = 0x21

	_, err = ParseDiscoveryFrame(packet)
	require.ErrorIs(t, err, ErrInvalidHeader)
}

func TestParseDiscoveryFrameRejectsLengthMismatch(t *testing.T) {
	packet, err := MarshalDiscoveryFrame(CodePADR, 0, []Tag{{Type: TagServiceName, Value: []byte("svc")}})
	require.NoError(t, err)
	packet[5]++

	_, err = ParseDiscoveryFrame(packet)
	require.ErrorIs(t, err, ErrLengthMismatch)
}

func TestParseTagsRejectsTruncatedTag(t *testing.T) {
	_, err := ParseTags([]byte{0x01, 0x01, 0x00})
	require.ErrorIs(t, err, ErrInvalidTag)

	_, err = ParseTags([]byte{0x01, 0x01, 0x00, 0x04, 0x01})
	require.ErrorIs(t, err, ErrInvalidTag)
}

func TestMarshalDiscoveryFrameRejectsInvalidAndOversizedFrames(t *testing.T) {
	_, err := MarshalDiscoveryFrame(CodeSession, 0, nil)
	require.ErrorIs(t, err, ErrInvalidHeader)

	_, err = MarshalDiscoveryFrame(CodePADS, 1, []Tag{{Type: TagVendorSpecific, Value: make([]byte, 70000)}})
	require.True(t, errors.Is(err, ErrInvalidTag), err)
}
