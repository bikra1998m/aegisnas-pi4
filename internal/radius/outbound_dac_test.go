package radius

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3576"
)

func TestPreviewOutboundDACBuildsRFC5176CoAPlan(t *testing.T) {
	cfg := outboundDACTestConfig()

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:           "coa",
		TargetAddress:    "192.0.2.10",
		UserName:         "alice@example.test",
		AcctSessionID:    "acct-123",
		CallingStationID: "AA-BB-CC-DD-EE-FF",
		FilterID:         "employee",
		VLAN:             20,
		Confirm:          false,
	})
	require.NoError(t, err)

	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, int(layehradius.CodeCoARequest), preview.RequestCode)
	assert.Equal(t, int(layehradius.CodeCoAACK), preview.ExpectedACKCode)
	assert.Equal(t, int(layehradius.CodeCoANAK), preview.ExpectedNAKCode)
	assert.True(t, preview.MessageAuthenticator)
	assert.True(t, preview.Target.KnownClient)
	assert.True(t, preview.Target.SecretReady)
	assert.Equal(t, "radius_client", preview.Target.ResolvedFrom)
	assert.Equal(t, "192.0.2.10:3799", preview.Target.Endpoint)
	assert.Contains(t, outboundDACPlanNames(preview.Attributes), "Acct-Session-Id")
	assert.Contains(t, outboundDACPlanNames(preview.Attributes), "Filter-Id")
	assert.Contains(t, outboundDACPlanNames(preview.Attributes), "Tunnel-Private-Group-Id")
	assert.Contains(t, preview.Warnings, "send requires confirm=true")
	assert.NotEmpty(t, preview.RequestFingerprint)
}

func TestSendOutboundDACRequiresConfirmationAndRecordsBlockedRequest(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "disconnect",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-123",
	}, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, db.OutboundDACStatusBlocked, result.Status)
	assert.Contains(t, result.Message, "confirm=true")
	assert.Equal(t, db.OutboundDACStatusBlocked, result.Request.Status)

	summary, err := db.GetOutboundDACSummary(100)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.BlockedCount)
}

func TestSendOutboundDACBuildsPacketAndStoresACKHistory(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	var captured *layehradius.Packet
	var endpoint string
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		captured = packet
		endpoint = target
		response := packet.Response(layehradius.CodeCoAACK)
		require.NoError(t, rfc2865.ReplyMessage_SetString(response, "policy updated"))
		return response, 12 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:           "coa",
		TargetAddress:    "192.0.2.10",
		UserName:         "alice@example.test",
		AcctSessionID:    "acct-123",
		CallingStationID: "AA-BB-CC-DD-EE-FF",
		FramedIPAddress:  "192.0.2.100",
		FilterID:         "employee",
		VLAN:             20,
		SessionTimeout:   3600,
		IdleTimeout:      600,
		CorrelationID:    "incident-1",
		Confirm:          true,
	}, "ops@example.test")
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Equal(t, "192.0.2.10:3799", endpoint)
	assert.Equal(t, layehradius.CodeCoARequest, captured.Code)
	assert.Equal(t, "alice@example.test", rfc2865.UserName_GetString(captured))
	assert.Equal(t, "acct-123", rfc2866.AcctSessionID_GetString(captured))
	assert.Equal(t, "employee", rfc2865.FilterID_GetString(captured))
	_, vlan := rfc2868.TunnelPrivateGroupID_GetString(captured)
	assert.Equal(t, "20", vlan)
	assert.Equal(t, rfc2865.SessionTimeout(3600), rfc2865.SessionTimeout_Get(captured))
	assert.Equal(t, rfc2865.IdleTimeout(600), rfc2865.IdleTimeout_Get(captured))
	messageAuthenticator := rfc2869.MessageAuthenticator_Get(captured)
	assert.Len(t, messageAuthenticator, 16)
	assert.False(t, bytes.Equal(messageAuthenticator, make([]byte, 16)))

	assert.Equal(t, db.OutboundDACStatusACK, result.Status)
	assert.Equal(t, "policy updated", result.Message)
	assert.Equal(t, "incident-1", result.Request.CorrelationID)
	assert.Equal(t, db.OutboundDACStatusACK, result.Request.Status)
	require.Len(t, result.Attempts, 1)
	assert.Equal(t, int(layehradius.CodeCoAACK), result.Attempts[0].ResponseCode)
	assert.NotEmpty(t, result.Request.RequestFingerprint)
	assert.NotEmpty(t, result.Request.ResponseFingerprint)
}

func TestSendOutboundDACClassifiesNAKAndErrorCause(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		response := packet.Response(layehradius.CodeDisconnectNAK)
		require.NoError(t, rfc3576.ErrorCause_Set(response, rfc3576.ErrorCause_Value_SessionContextNotFound))
		return response, 7 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "disconnect",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-missing",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, db.OutboundDACStatusNAK, result.Status)
	assert.Equal(t, int(layehradius.CodeDisconnectNAK), result.Request.ResponseCode)
	assert.Equal(t, int(rfc3576.ErrorCause_Value_SessionContextNotFound), result.Request.ErrorCause)
	assert.Equal(t, "Session-Context-Not-Found", result.Request.ErrorCauseName)
}

func TestSendOutboundDACStoresTransportError(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		return nil, 5 * time.Millisecond, errors.New("i/o timeout")
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-timeout",
		FilterID:      "quarantine",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, db.OutboundDACStatusError, result.Status)
	assert.Contains(t, result.Message, "i/o timeout")
	require.Len(t, result.Attempts, 1)
	assert.Contains(t, result.Attempts[0].ErrorMessage, "i/o timeout")
}

func TestOutboundDACRejectsUnsupportedVendorActionAttributes(t *testing.T) {
	cfg := outboundDACTestConfig()

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-123",
		Attributes: []db.OutboundDACAttribute{
			{Name: "Cisco-AVPair", Value: "subscriber:command=reauthenticate"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "blocked", preview.Status)
	assert.Contains(t, preview.Message, "not supported by the NAS-0042 vendor-neutral DAC client")
}

func setupOutboundDACTestDB(t *testing.T) {
	t.Helper()
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, db.Migrate())
}

func insertOutboundDACTestClient(t *testing.T) {
	t.Helper()
	_, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled, transport)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"branch-ap", "192.0.2.10", "shared-secret", "cisco", true, "udp")
	require.NoError(t, err)
}

func outboundDACTestConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Secret: "global-secret",
			DynamicAuth: config.DynamicAuthConfig{
				Enabled:                     true,
				Port:                        3799,
				OutboundEnabled:             true,
				OutboundDefaultPort:         3799,
				OutboundTimeoutSeconds:      5,
				OutboundRequireKnownClient:  true,
				OutboundHistoryLimit:        1000,
				OutboundMaxAttributes:       32,
				OutboundAllowCoA:            true,
				OutboundAllowDisconnect:     true,
				OutboundRequireConfirmation: true,
			},
			Clients: []config.RadiusClient{{
				IP:        "192.0.2.10",
				Secret:    "shared-secret",
				ShortName: "branch-ap",
				NASType:   "cisco",
				Transport: "udp",
			}},
		},
	}
}

func outboundDACPlanNames(attrs []OutboundDACAttributePlan) []string {
	names := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		names = append(names, attr.Name)
	}
	return names
}
