package radius

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
)

func TestPacketHardeningRejectsMalformedLength(t *testing.T) {
	hardener := NewPacketHardener(hardeningTestConfig())
	raw := make([]byte, 20)
	raw[0] = byte(layehradius.CodeAccessRequest)
	binary.BigEndian.PutUint16(raw[2:4], 21)

	result := hardener.ValidateRawPacket(hardeningContext("192.0.2.10"), raw)
	require.False(t, result.Accepted)
	assert.Equal(t, "invalid_packet_length", result.Reason)
}

func TestPacketHardeningRejectsUnknownSource(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	raw, err := packet.MarshalBinary()
	require.NoError(t, err)

	result := NewPacketHardener(hardeningTestConfig()).ValidateRawPacket(hardeningContext("198.51.100.50"), raw)
	require.False(t, result.Accepted)
	assert.Equal(t, "unknown_source", result.Reason)
}

func TestPacketHardeningRequiresAndValidatesMessageAuthenticator(t *testing.T) {
	secret := []byte("secret")
	packet := layehradius.New(layehradius.CodeAccessRequest, secret)
	packet.Attributes.Add(layehradius.Type(79), layehradius.Attribute{2, 1, 0, 5, 1})
	rawMissing, err := packet.MarshalBinary()
	require.NoError(t, err)

	missing := NewPacketHardener(hardeningTestConfig()).ValidateRawPacket(hardeningContext("192.0.2.10"), rawMissing)
	require.False(t, missing.Accepted)
	assert.Equal(t, "missing_message_authenticator", missing.Reason)

	require.NoError(t, setMessageAuthenticator(packet))
	rawValid, err := packet.MarshalBinary()
	require.NoError(t, err)
	accepted := NewPacketHardener(hardeningTestConfig()).ValidateRawPacket(hardeningContext("192.0.2.10"), rawValid)
	require.True(t, accepted.Accepted)
	assert.True(t, accepted.MessageAuthenticatorPresent)

	rawInvalid := append([]byte(nil), rawValid...)
	rawInvalid[len(rawInvalid)-1] ^= 0xff
	rejected := NewPacketHardener(hardeningTestConfig()).ValidateRawPacket(hardeningContext("192.0.2.10"), rawInvalid)
	require.False(t, rejected.Accepted)
	assert.Equal(t, "invalid_message_authenticator", rejected.Reason)
}

func TestPacketHardeningRejectsReplay(t *testing.T) {
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	raw, err := packet.MarshalBinary()
	require.NoError(t, err)
	hardener := NewPacketHardener(hardeningTestConfig())

	first := hardener.ValidateRawPacket(hardeningContext("192.0.2.10"), raw)
	require.True(t, first.Accepted)

	second := hardener.ValidateRawPacket(hardeningContext("192.0.2.10"), raw)
	require.False(t, second.Accepted)
	assert.Equal(t, "replay_detected", second.Reason)
	assert.True(t, second.ReplayDetected)
}

func TestPacketHardeningRejectsProxyStateOverflow(t *testing.T) {
	cfg := hardeningTestConfig()
	cfg.Radius.PacketHardening.MaxProxyStateAttributes = 1
	packet := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	packet.Attributes.Add(layehradius.Type(33), layehradius.Attribute("one"))
	packet.Attributes.Add(layehradius.Type(33), layehradius.Attribute("two"))
	raw, err := packet.MarshalBinary()
	require.NoError(t, err)

	result := NewPacketHardener(cfg).ValidateRawPacket(hardeningContext("192.0.2.10"), raw)
	require.False(t, result.Accepted)
	assert.Equal(t, "proxy_state_count_exceeded", result.Reason)
}

func TestPacketHardeningRateLimitsPerSource(t *testing.T) {
	cfg := hardeningTestConfig()
	cfg.Radius.PacketHardening.ReplayCacheEnabled = false
	cfg.Radius.PacketHardening.PerClientRateLimitPerSecond = 1
	cfg.Radius.PacketHardening.PerClientBurst = 1
	hardener := NewPacketHardener(cfg)
	now := time.Now().UTC()

	firstPacket := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	firstRaw, err := firstPacket.MarshalBinary()
	require.NoError(t, err)
	first := hardener.ValidateRawPacket(hardeningContextAt("192.0.2.10", now), firstRaw)
	require.True(t, first.Accepted)

	secondPacket := layehradius.New(layehradius.CodeAccessRequest, []byte("secret"))
	secondRaw, err := secondPacket.MarshalBinary()
	require.NoError(t, err)
	second := hardener.ValidateRawPacket(hardeningContextAt("192.0.2.10", now), secondRaw)
	require.False(t, second.Accepted)
	assert.Equal(t, "rate_limited", second.Reason)
	assert.True(t, second.RateLimited)
}

func hardeningTestConfig() *config.Config {
	return &config.Config{Radius: config.RadiusConfig{
		Clients: []config.RadiusClient{{IP: "192.0.2.10", ShortName: "lab-ap", Secret: "secret"}},
		PacketHardening: config.RadiusPacketHardeningConfig{
			Enabled:                     true,
			FailClosed:                  true,
			RequireKnownSource:          true,
			AllowStatusServer:           true,
			RequireMessageAuthenticator: "auto",
			MaxPacketBytes:              4096,
			MaxAttributesPerPacket:      128,
			MaxProxyStateAttributes:     8,
			MaxProxyStateBytes:          1024,
			ReplayCacheEnabled:          true,
			ReplayWindowSeconds:         30,
			ReplayCacheMaxEntries:       1024,
			RateLimitEnabled:            true,
			PerClientRateLimitPerSecond: 250,
			PerClientBurst:              500,
			EventRetentionLimit:         100,
		},
	}}
}

func hardeningContext(host string) PacketValidationContext {
	return hardeningContextAt(host, time.Now().UTC())
}

func hardeningContextAt(host string, now time.Time) PacketValidationContext {
	return PacketValidationContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP(host), Port: 1812},
		Direction:    "authentication",
		Now:          now,
		SharedSecret: []byte("secret"),
	}
}
