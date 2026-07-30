package tacacs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketRoundTripEncryptedAuthorization(t *testing.T) {
	body := []byte{
		1, 15, AuthenTypeASCII, AuthenServiceShell,
		5, 4, 8, 3,
		byte(len("service=shell")), byte(len("cmd=show")), byte(len("cmd-arg=version")),
	}
	body = append(body, []byte("alice")...)
	body = append(body, []byte("tty1")...)
	body = append(body, []byte("10.0.0.5")...)
	body = append(body, []byte("service=shell")...)
	body = append(body, []byte("cmd=show")...)
	body = append(body, []byte("cmd-arg=version")...)

	var buf bytes.Buffer
	err := WritePacket(&buf, Packet{
		Header: Header{Version: VersionDefault, Type: TypeAuthorization, SeqNo: 1, SessionID: 42},
		Body:   body,
	}, "shared")
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "alice")

	packet, err := ReadPacket(&buf, "shared", 4096, false)
	require.NoError(t, err)
	require.Equal(t, TypeAuthorization, packet.Header.Type)
	req, err := ParseAuthorRequest(packet.Body, 16)
	require.NoError(t, err)
	assert.Equal(t, "alice", req.User)
	assert.Equal(t, "show version", CommandFromArgs(req.Args))
}

func TestAuthenContinueParsing(t *testing.T) {
	body := []byte{0, 6, 0, 0, 0}
	body = append(body, []byte("secret")...)
	cont, err := ParseAuthenContinue(body)
	require.NoError(t, err)
	assert.Equal(t, "secret", cont.UserMsg)
}

func TestRejectsUnencryptedWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	err := WritePacket(&buf, Packet{
		Header: Header{Version: VersionDefault, Type: TypeAccounting, SeqNo: 1, Flags: FlagUnencrypted, SessionID: 7},
		Body:   []byte{0, 1, 15, AuthenTypeASCII, AuthenServiceShell, 0, 0, 0, 0},
	}, "")
	require.NoError(t, err)
	_, err = ReadPacket(&buf, "", 4096, false)
	require.Error(t, err)
}
