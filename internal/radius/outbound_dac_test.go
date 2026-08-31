package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
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

func TestPreviewOutboundDACResolvesTargetFromSessionOwnership(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)
	insertOutboundDACTestSession(t, "session-owned", "acct-owned", "branch-ap")

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		AcctSessionID: "acct-owned",
		FilterID:      "employee",
		Confirm:       true,
	})
	require.NoError(t, err)

	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, "192.0.2.10", preview.Target.Address)
	assert.Equal(t, "branch-ap", preview.Target.ShortName)
	assert.Equal(t, "ready", preview.OwnershipDecision.Status)
	assert.Equal(t, "session-owned", preview.OwnershipDecision.SessionID)
	assert.Equal(t, db.NASSessionOwnershipStatusActive, preview.OwnershipDecision.OwnershipStatus)
	assert.Contains(t, preview.OwnershipDecision.SupportedActions, "coa")
	assert.Contains(t, preview.OwnershipDecision.SupportedTransports, "udp")
	assert.Contains(t, preview.OwnershipDecision.Required, "dynamic_authorization.coa")
}

func TestPreviewOutboundDACBlocksConflictingSessionOwnerTarget(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)
	insertOutboundDACTestSession(t, "session-owned", "acct-owned", "branch-ap")

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.11",
		AcctSessionID: "acct-owned",
		FilterID:      "employee",
		Confirm:       true,
	})
	require.NoError(t, err)

	assert.Equal(t, "blocked", preview.Status)
	assert.Equal(t, "blocked", preview.OwnershipDecision.Status)
	assert.Contains(t, preview.Message, "session session-owned is owned by NAS branch-ap")
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

func TestSendOutboundDACPersistsNASOwnershipDecision(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)
	insertOutboundDACTestSession(t, "session-owned", "acct-owned", "branch-ap")

	var endpoint string
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		endpoint = target
		return packet.Response(layehradius.CodeCoAACK), 9 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		AcctSessionID: "acct-owned",
		FilterID:      "employee",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, "192.0.2.10:3799", endpoint)
	assert.Equal(t, db.OutboundDACStatusACK, result.Status)
	assert.Equal(t, "session-owned", result.Request.OwnershipSessionID)
	assert.Equal(t, db.NASSessionOwnershipStatusActive, result.Request.OwnershipStatus)
	assert.Equal(t, "sessions", result.Request.OwnershipSource)
	assert.Equal(t, OutboundDACRuntimeComponent, result.Request.OwnershipOwnerNode)
	assert.Equal(t, "ready", result.Request.CapabilityDecision)
	assert.Empty(t, result.Request.CapabilityWarnings)
}

func TestPreviewAndSendOutboundDACBlockStandbyHandoff(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	cfg.Radius.NASIdentifier = "node-b"
	cfg.HighAvailability = config.HighAvailabilityConfig{
		Enabled:                     true,
		Role:                        "standby",
		PeerAPIURL:                  "https://active.example.test:8083",
		VirtualIP:                   "192.0.2.254/24",
		HeartbeatIntervalSeconds:    5,
		FailoverTimeoutSeconds:      30,
		SplitBrainProtectionEnabled: true,
	}
	insertOutboundDACTestClient(t)

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-standby",
		FilterID:      "employee",
		Confirm:       true,
	})
	require.NoError(t, err)
	assert.Equal(t, "blocked", preview.Status)
	assert.Equal(t, "blocked", preview.HandoffDecision.Status)
	assert.False(t, preview.HandoffDecision.CanSend)
	assert.Contains(t, preview.Message, "standby")

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-standby",
		FilterID:      "employee",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACStatusBlocked, result.Status)
	assert.Equal(t, "blocked", result.Request.HandoffDecision)
	assert.Equal(t, "node-b", result.Request.HandoffOwnerNode)
	assert.NotEmpty(t, result.Request.HandoffLeaseID)
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

func TestOutboundDACRejectsUnknownVendorActionAttributes(t *testing.T) {
	cfg := outboundDACTestConfig()

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-123",
		Attributes: []db.OutboundDACAttribute{
			{Name: "Cisco-Unsupported-Action", Value: "subscriber:command=reauthenticate"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "blocked", preview.Status)
	assert.Contains(t, preview.Message, "not supported")
}

func TestPreviewOutboundDACCompilesVendorActionAttributes(t *testing.T) {
	cfg := outboundDACTestConfig()

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-123",
		VendorAction:  "apply-acl",
		VendorPacks:   []string{"cisco", "aruba"},
		ACLName:       "guest-web",
		ACLRules: []ACLRule{{
			Action:          "permit",
			Direction:       "in",
			Protocol:        "tcp",
			Source:          "any",
			Destination:     "any",
			DestinationPort: "443",
		}},
		Confirm: true,
	})
	require.NoError(t, err)

	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, "compiled", preview.VendorActionDecision.Status)
	assert.Equal(t, "acl", preview.VendorActionDecision.Action)
	assert.Equal(t, []string{"cisco", "aruba"}, preview.VendorActionDecision.Packs)
	names := outboundDACPlanNames(preview.Attributes)
	assert.Contains(t, names, "Cisco-In-ACL")
	assert.Contains(t, names, "Cisco-Out-ACL")
	assert.Contains(t, names, "Cisco-AVPair")
	assert.Contains(t, names, "Aruba-NAS-Filter-Rule")
	for _, attr := range preview.Attributes {
		if strings.HasPrefix(attr.Name, "Cisco-") || strings.HasPrefix(attr.Name, "Aruba-") {
			assert.Equal(t, "vendor-dynamic-action", attr.Source)
			assert.False(t, attr.Selector)
		}
	}
}

func TestPreviewOutboundDACCompilesFortinetSecurityPackActions(t *testing.T) {
	cfg := outboundDACTestConfig()

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:           "coa",
		TargetAddress:    "192.0.2.10",
		AcctSessionID:    "acct-fortinet",
		VendorAction:     "qos",
		VendorPacks:      []string{"fortinet"},
		BandwidthProfile: "gold",
		DownloadRateKbps: 100000,
		UploadRateKbps:   25000,
		Confirm:          true,
	})
	require.NoError(t, err)

	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, "compiled", preview.VendorActionDecision.Status)
	assert.Equal(t, []string{"fortinet"}, preview.VendorActionDecision.Packs)
	names := outboundDACPlanNames(preview.Attributes)
	assert.Contains(t, names, "Fortinet-Access-Profile")
	assert.Contains(t, names, "Fortinet-FDD-Access-Profile")
	assert.Contains(t, names, "Fortinet-FortiWAN-AVPair")
	assert.Contains(t, names, "Fortinet-Host-Port-AVPair")
	values := outboundDACPlanValues(preview.Attributes)
	assert.Contains(t, values, "qos=gold")
	assert.Contains(t, values, "download_kbps=100000")
	assert.Contains(t, values, "upload_kbps=25000")
	for _, attr := range preview.Attributes {
		if strings.HasPrefix(attr.Name, "Fortinet-") {
			assert.Equal(t, "vendor-dynamic-action", attr.Source)
			assert.False(t, attr.Selector)
		}
	}
}

func TestSendOutboundDACVendorActionEncodesVSAsAndPersistsEvidence(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	var captured *layehradius.Packet
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		captured = packet
		return packet.Response(layehradius.CodeCoAACK), 9 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:        "coa",
		TargetAddress: "192.0.2.10",
		AcctSessionID: "acct-reauth",
		VendorAction:  "reauth",
		VendorPacks:   []string{"cisco"},
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)
	require.NotNil(t, captured)

	value, ok := LookupVendorAttributeValue(captured, 9, 1)
	require.True(t, ok)
	assert.Equal(t, "subscriber:command=reauthenticate", string(value))
	assert.Equal(t, db.OutboundDACStatusACK, result.Status)
	assert.Equal(t, "reauth", result.Preview.VendorActionDecision.Action)
	assert.Equal(t, "compiled", result.Request.VendorCompilerStatus)
	assert.Equal(t, "reauth", result.Request.VendorAction)
	assert.Equal(t, []string{"cisco"}, result.Request.VendorPacks)
}

func TestPreviewOutboundDACVendorActionFailsClosedWithoutSinglePack(t *testing.T) {
	cfg := outboundDACTestConfig()
	cfg.Radius.Clients[0].NASType = "other"

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:           "coa",
		TargetAddress:    "192.0.2.10",
		AcctSessionID:    "acct-ambiguous",
		VendorAction:     "qos",
		BandwidthProfile: "gold",
		Confirm:          true,
	})
	require.NoError(t, err)

	assert.Equal(t, "blocked", preview.Status)
	assert.Equal(t, "blocked", preview.VendorActionDecision.Status)
	assert.Contains(t, preview.Message, "vendor_action requires vendor_packs")
}

func TestBuildOutboundDACVendorActionReport(t *testing.T) {
	report := BuildOutboundDACVendorActionReport(outboundDACTestConfig())

	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.Enabled)
	assert.Contains(t, report.SupportedPacks, "cisco")
	assert.Contains(t, report.Actions, "reauth")
	assert.Contains(t, report.Actions, "qos")
}

func TestPreviewOutboundDACProxyRouteAddsProxyStateAndPolicyDecision(t *testing.T) {
	cfg := outboundDACProxyTestConfig(config.RadiusHomeServer{
		Name: "upstream-udp", Address: "203.0.113.20", DynamicAuthPort: 3799, Secret: "proxy-secret", Transport: "udp",
	})

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		DeliveryMode:  "proxy",
		ProxyRoute:    "corp",
		Action:        "coa",
		UserName:      "alice@corp.example.test",
		AcctSessionID: "acct-proxy",
		FilterID:      "employee",
		Confirm:       true,
	})
	require.NoError(t, err)

	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, "proxy", preview.Target.DeliveryMode)
	assert.Equal(t, "corp", preview.Target.ProxyRoute)
	assert.Equal(t, "corp.example.test", preview.Target.ProxyRealm)
	assert.Equal(t, "corp.example.test", preview.Target.SourceRealm)
	assert.Equal(t, "upstream-udp", preview.Target.ProxyHomeServer)
	assert.Equal(t, "udp", preview.Target.Transport)
	assert.Equal(t, "203.0.113.20:3799", preview.Target.Endpoint)
	assert.True(t, preview.ProxyPolicyDecision.Allowed)
	assert.Equal(t, "accepted", preview.ProxyPolicyDecision.Decision)
	assert.Contains(t, outboundDACPlanNames(preview.Attributes), "Proxy-State")
	assert.Equal(t, 1, preview.Target.ProxyHopCount)
	assert.Contains(t, strings.Join(preview.Target.ProxyState, "|"), "aegisnas:corp:node-a:corp.example.test")
}

func TestSendOutboundDACProxyUDPStoresRoutingHistory(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACProxyTestConfig(config.RadiusHomeServer{
		Name: "upstream-udp", Address: "203.0.113.20", DynamicAuthPort: 3799, Secret: "proxy-secret", Transport: "udp",
	})

	var captured *layehradius.Packet
	var endpoint string
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		captured = packet
		endpoint = target
		response := packet.Response(layehradius.CodeCoAACK)
		require.NoError(t, rfc2865.ReplyMessage_SetString(response, "proxied policy updated"))
		return response, 17 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		DeliveryMode:  "proxy",
		ProxyRoute:    "corp",
		Action:        "coa",
		UserName:      "alice@corp.example.test",
		AcctSessionID: "acct-proxy",
		FilterID:      "employee",
		CorrelationID: "proxy-ticket-1",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Equal(t, "203.0.113.20:3799", endpoint)
	proxyStates, err := rfc2865.ProxyState_GetStrings(captured)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(proxyStates, "|"), "aegisnas:corp:node-a:corp.example.test")
	assert.Equal(t, db.OutboundDACStatusACK, result.Status)
	assert.Equal(t, "proxy", result.Request.DeliveryMode)
	assert.Equal(t, "corp", result.Request.ProxyRoute)
	assert.Equal(t, "upstream-udp", result.Request.ProxyHomeServer)
	assert.Equal(t, "proxied policy updated", result.Request.ReplyMessage)
	require.Len(t, result.Attempts, 1)
	assert.Equal(t, "proxy", result.Attempts[0].DeliveryMode)
	assert.Equal(t, "corp", result.Attempts[0].ProxyRoute)
}

func TestSendOutboundDACProxyRadSecMutualTLS(t *testing.T) {
	setupOutboundDACTestDB(t)
	pki := createRadSecTestPKI(t)
	seen := make(chan *layehradius.Packet, 1)
	listener := startRadSecDACServer(t, pki, seen)
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := net.LookupPort("tcp", portText)
	require.NoError(t, err)
	cfg := outboundDACProxyTestConfig(config.RadiusHomeServer{
		Name: "upstream-radsec", Address: host, Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
			Port: port, ServerName: "aaa.example.test", CertificateFile: pki.clientCertFile, PrivateKeyFile: pki.clientKeyFile,
			CAFile: pki.caFile, TLSMinVersion: "1.2", TLSMaxVersion: "1.3", RadiusV11: "forbid",
		},
	})

	result, err := SendOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		DeliveryMode:  "proxy",
		ProxyRoute:    "corp",
		Action:        "coa",
		UserName:      "alice@corp.example.test",
		AcctSessionID: "acct-radsec",
		FilterID:      "employee",
		CorrelationID: "radsec-ticket-1",
		Confirm:       true,
	}, "ops@example.test")
	require.NoError(t, err)

	assert.Equal(t, db.OutboundDACStatusACK, result.Status)
	assert.Equal(t, "radsec", result.Request.TargetTransport)
	assert.Equal(t, "proxy", result.Request.DeliveryMode)
	assert.Equal(t, "upstream-radsec", result.Request.ProxyHomeServer)
	select {
	case packet := <-seen:
		assert.Equal(t, layehradius.CodeCoARequest, packet.Code)
		proxyStates, stateErr := rfc2865.ProxyState_GetStrings(packet)
		require.NoError(t, stateErr)
		assert.Contains(t, strings.Join(proxyStates, "|"), "aegisnas:corp:node-a:corp.example.test")
	case <-time.After(2 * time.Second):
		t.Fatal("RadSec DAC server did not receive a packet")
	}
}

func TestPreviewOutboundDACProxyRejectsLoopMarker(t *testing.T) {
	cfg := outboundDACProxyTestConfig(config.RadiusHomeServer{
		Name: "upstream-udp", Address: "203.0.113.20", DynamicAuthPort: 3799, Secret: "proxy-secret", Transport: "udp",
	})

	preview, err := PreviewOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		DeliveryMode:  "proxy",
		ProxyRoute:    "corp",
		Action:        "coa",
		UserName:      "alice@corp.example.test",
		AcctSessionID: "acct-loop",
		FilterID:      "employee",
		ProxyState:    []string{"aegisnas:corp:other-node:corp.example.test"},
		Confirm:       true,
	})
	require.NoError(t, err)

	assert.Equal(t, "blocked", preview.Status)
	assert.Contains(t, preview.Message, "proxy loop marker detected")
}

func TestEnqueueOutboundDACSuppressesDuplicateByIdempotencyKey(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	request := OutboundDACRequest{
		Action:           "coa",
		TargetAddress:    "192.0.2.10",
		UserName:         "alice@example.test",
		AcctSessionID:    "acct-123",
		CallingStationID: "AA-BB-CC-DD-EE-FF",
		FilterID:         "employee",
		IdempotencyKey:   "change-ticket-1",
		Confirm:          true,
	}
	created, err := EnqueueOutboundDAC(context.Background(), cfg, request, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "queued", created.Status)
	assert.True(t, created.Created)
	assert.False(t, created.Duplicate)
	assert.NotEmpty(t, created.Queue.QueueID)
	assert.True(t, strings.HasPrefix(created.Queue.IdempotencyKey, "sha256:"))
	assert.NotContains(t, outboundDACAttributeValues(created.Queue.Attributes), "alice@example.test")

	duplicate, err := EnqueueOutboundDAC(context.Background(), cfg, request, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "duplicate", duplicate.Status)
	assert.False(t, duplicate.Created)
	assert.True(t, duplicate.Duplicate)
	assert.Equal(t, created.Queue.QueueID, duplicate.Queue.QueueID)

	summary, err := db.GetOutboundDACQueueSummary(100)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.QueuedCount)
}

func TestReplayOutboundDACQueueACKRecordsHistoryAndAttempt(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	queued, err := EnqueueOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:         "coa",
		TargetAddress:  "192.0.2.10",
		AcctSessionID:  "acct-ack",
		FilterID:       "employee",
		IdempotencyKey: "ack-1",
		Confirm:        true,
	}, "ops@example.test")
	require.NoError(t, err)

	var captured *layehradius.Packet
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		captured = packet
		response := packet.Response(layehradius.CodeCoAACK)
		require.NoError(t, rfc2865.ReplyMessage_SetString(response, "queued update applied"))
		return response, 9 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	replay, err := ReplayOutboundDACQueue(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "ok", replay.Status)
	assert.Equal(t, 1, replay.Claimed)
	assert.Equal(t, 1, replay.ACK)
	require.NotNil(t, captured)
	assert.Equal(t, layehradius.CodeCoARequest, captured.Code)

	record, err := db.GetOutboundDACQueueByQueueID(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACQueueStatusACK, record.Status)

	history, err := db.GetOutboundDACRequest(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACStatusACK, history.Status)
	assert.Equal(t, "queued update applied", history.ReplyMessage)

	attempts, err := db.ListOutboundDACQueueAttempts(queued.Queue.QueueID, 10)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, db.OutboundDACQueueAttemptACK, attempts[0].Result)
}

func TestReplayOutboundDACQueueDoesNotClaimOnStandby(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	queued, err := EnqueueOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:         "coa",
		TargetAddress:  "192.0.2.10",
		AcctSessionID:  "acct-ha-queued",
		FilterID:       "employee",
		IdempotencyKey: "ha-standby-1",
		Confirm:        true,
	}, "ops@example.test")
	require.NoError(t, err)

	cfg.Radius.NASIdentifier = "node-b"
	cfg.HighAvailability = config.HighAvailabilityConfig{
		Enabled:                     true,
		Role:                        "standby",
		PeerAPIURL:                  "https://active.example.test:8083",
		VirtualIP:                   "192.0.2.254/24",
		HeartbeatIntervalSeconds:    5,
		FailoverTimeoutSeconds:      30,
		SplitBrainProtectionEnabled: true,
	}
	replay, err := ReplayOutboundDACQueue(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "blocked", replay.Status)
	assert.Equal(t, 0, replay.Claimed)
	assert.Equal(t, "blocked", replay.HandoffDecision.Status)

	record, err := db.GetOutboundDACQueueByQueueID(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACQueueStatusQueued, record.Status)
	assert.Empty(t, record.LockedUntil)
}

func TestReplayOutboundDACQueueAllowsPromotedStandby(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	insertOutboundDACTestClient(t)

	queued, err := EnqueueOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:         "coa",
		TargetAddress:  "192.0.2.10",
		AcctSessionID:  "acct-ha-promoted",
		FilterID:       "employee",
		IdempotencyKey: "ha-promoted-1",
		Confirm:        true,
	}, "ops@example.test")
	require.NoError(t, err)

	cfg.Radius.NASIdentifier = "node-b"
	cfg.HighAvailability = config.HighAvailabilityConfig{
		Enabled:                     true,
		Role:                        "standby",
		PeerAPIURL:                  "https://active.example.test:8083",
		VirtualIP:                   "192.0.2.254/24",
		HeartbeatIntervalSeconds:    5,
		FailoverTimeoutSeconds:      30,
		SplitBrainProtectionEnabled: true,
	}
	require.NoError(t, db.UpsertRuntimeStatus("high_availability", "ok", "standby promoted", map[string]any{
		"effective_role":  "active",
		"failover_active": true,
	}))
	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		return packet.Response(layehradius.CodeCoAACK), 8 * time.Millisecond, nil
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	replay, err := ReplayOutboundDACQueue(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, "ok", replay.Status)
	assert.Equal(t, 1, replay.Claimed)
	assert.Equal(t, 1, replay.ACK)
	assert.Equal(t, "ready", replay.HandoffDecision.Status)
	assert.Equal(t, "active", replay.HandoffDecision.EffectiveRole)

	record, err := db.GetOutboundDACQueueByQueueID(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACQueueStatusACK, record.Status)
}

func TestReplayOutboundDACQueueRetriesThenPoisonsTimeout(t *testing.T) {
	setupOutboundDACTestDB(t)
	cfg := outboundDACTestConfig()
	cfg.Radius.DynamicAuth.OutboundMaxAttempts = 2
	cfg.Radius.DynamicAuth.OutboundInitialRetrySeconds = 1
	cfg.Radius.DynamicAuth.OutboundMaxRetrySeconds = 2
	cfg.Radius.DynamicAuth.OutboundRecordTTLSeconds = 60
	insertOutboundDACTestClient(t)

	queued, err := EnqueueOutboundDAC(context.Background(), cfg, OutboundDACRequest{
		Action:         "disconnect",
		TargetAddress:  "192.0.2.10",
		AcctSessionID:  "acct-timeout",
		IdempotencyKey: "timeout-1",
		Confirm:        true,
	}, "ops@example.test")
	require.NoError(t, err)

	origSender := outboundDACPacketSender
	outboundDACPacketSender = func(ctx context.Context, packet *layehradius.Packet, target string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
		return nil, 5 * time.Millisecond, errors.New("i/o timeout")
	}
	t.Cleanup(func() { outboundDACPacketSender = origSender })

	first, err := ReplayOutboundDACQueue(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, first.Failed)
	record, err := db.GetOutboundDACQueueByQueueID(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACQueueStatusQueued, record.Status)
	assert.Equal(t, 1, record.AttemptCount)
	assert.Contains(t, record.LastError, "i/o timeout")

	_, err = db.DB.Exec(`UPDATE radius_outbound_dac_queue SET next_attempt_at = ? WHERE queue_id = ?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), queued.Queue.QueueID)
	require.NoError(t, err)
	second, err := ReplayOutboundDACQueue(context.Background(), cfg, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, second.Poisoned)
	record, err = db.GetOutboundDACQueueByQueueID(queued.Queue.QueueID)
	require.NoError(t, err)
	assert.Equal(t, db.OutboundDACQueueStatusPoison, record.Status)
	assert.Equal(t, 2, record.AttemptCount)
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
	capabilitiesJSON := `{"dynamic_authorization":{"coa":true,"disconnect":true,"vendor_actions":true,"transport":{"udp":true,"proxy":false,"radsec":false}},"policy":{"filter_id":true,"vlan":true,"acl":true,"qos":true,"quarantine":true}}`
	_, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled, transport, capabilities_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"branch-ap", "192.0.2.10", "shared-secret", "cisco", true, "udp", capabilitiesJSON)
	require.NoError(t, err)
}

func insertOutboundDACTestSession(t *testing.T, sessionID, acctSessionID, nasIdentifier string) {
	t.Helper()
	_, err := db.DB.Exec(`INSERT INTO sessions (
		id, username, mac, ip, auth_method, nas_identifier, radius_session_id, start_time, last_activity
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, "alice@example.test", "AA-BB-CC-DD-EE-FF", "192.0.2.100", "dot1x",
		nasIdentifier, acctSessionID, "2026-05-05T11:00:00Z", "2026-05-05T11:30:00Z")
	require.NoError(t, err)
}

func outboundDACTestConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			Secret: "global-secret",
			DynamicAuth: config.DynamicAuthConfig{
				Enabled:                            true,
				Port:                               3799,
				OutboundEnabled:                    true,
				OutboundDefaultPort:                3799,
				OutboundTimeoutSeconds:             5,
				OutboundRequireKnownClient:         true,
				OutboundHistoryLimit:               1000,
				OutboundMaxAttributes:              32,
				OutboundAllowCoA:                   true,
				OutboundAllowDisconnect:            true,
				OutboundRequireConfirmation:        true,
				OutboundQueueEnabled:               true,
				OutboundReplayEnabled:              true,
				OutboundMaxQueueRecords:            100,
				OutboundMaxAttempts:                6,
				OutboundInitialRetrySeconds:        5,
				OutboundMaxRetrySeconds:            300,
				OutboundRecordTTLSeconds:           3600,
				OutboundReplayIntervalSeconds:      15,
				OutboundBatchSize:                  10,
				OutboundLockSeconds:                60,
				OutboundACKRetentionSeconds:        86400,
				OutboundDeadLetterRetentionSeconds: 2592000,
				OutboundIdempotencyWindowSeconds:   3600,
				OutboundVendorActionsEnabled:       true,
				OutboundVendorActionsRequirePack:   true,
			},
			Vendor: config.RadiusVendorConfig{
				Enabled:            true,
				CompatibilityPacks: []string{"standard", "cisco", "aruba", "juniper", "ruckus", "fortinet", "mikrotik", "huawei", "h3c"},
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

func outboundDACProxyTestConfig(server config.RadiusHomeServer) *config.Config {
	cfg := outboundDACTestConfig()
	cfg.Radius.NASIdentifier = "node-a"
	cfg.Radius.DynamicAuth.OutboundRequireKnownClient = true
	cfg.Radius.DynamicAuth.OutboundProxyEnabled = true
	cfg.Radius.DynamicAuth.OutboundProxyAllowUDP = true
	cfg.Radius.DynamicAuth.OutboundProxyAllowRadSec = true
	cfg.Radius.DynamicAuth.OutboundProxyMaxHops = 8
	cfg.Radius.DynamicAuth.OutboundProxyLoopMarker = "aegisnas"
	cfg.Radius.DynamicAuth.OutboundProxyAddLoopMarker = true
	cfg.Radius.DynamicAuth.OutboundProxyRejectLoopMarker = true
	cfg.Radius.Upstream = config.RadiusUpstreamConfig{
		Enabled:      true,
		Realm:        "corp.example.test",
		PoolStrategy: "fail-over",
		StatusCheck:  "status-server",
		Servers:      []config.RadiusHomeServer{server},
		Routes: []config.RadiusProxyRouteConfig{{
			Name:         "corp",
			Enabled:      true,
			Realm:        "corp.example.test",
			MatchRealms:  []string{"corp.example.test"},
			Default:      true,
			PoolStrategy: "fail-over",
			StatusCheck:  "status-server",
			Servers:      []string{server.Name},
		}},
		TransportPolicy: config.RadiusTransportPolicyConfig{
			Enabled:                  true,
			Mode:                     "enforce",
			FailClosed:               true,
			DefaultRequiredTransport: "any",
		},
	}
	return cfg
}

func startRadSecDACServer(t *testing.T, pki radSecTestPKI, seen chan<- *layehradius.Packet) net.Listener {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.clientCAPool,
		NextProtos:   []string{"radius/1.0"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				header := make([]byte, 20)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(header[2:4]))
				wire := append([]byte(nil), header...)
				if length > 20 {
					body := make([]byte, length-20)
					if _, err := io.ReadFull(conn, body); err != nil {
						return
					}
					wire = append(wire, body...)
				}
				request, err := layehradius.Parse(wire, []byte(radSecSharedSecret))
				if err != nil {
					return
				}
				select {
				case seen <- request:
				default:
				}
				responseCode := layehradius.CodeCoAACK
				if request.Code == layehradius.CodeDisconnectRequest {
					responseCode = layehradius.CodeDisconnectACK
				}
				response := request.Response(responseCode)
				encoded, err := response.Encode()
				if err == nil {
					_, _ = conn.Write(encoded)
				}
			}(conn)
		}
	}()
	return listener
}

func outboundDACPlanNames(attrs []OutboundDACAttributePlan) []string {
	names := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		names = append(names, attr.Name)
	}
	return names
}

func outboundDACPlanValues(attrs []OutboundDACAttributePlan) string {
	values := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		values = append(values, attr.Value)
	}
	return strings.Join(values, "|")
}

func outboundDACAttributeValues(attrs []db.OutboundDACAttribute) string {
	values := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		values = append(values, attr.Value)
	}
	return strings.Join(values, "|")
}
