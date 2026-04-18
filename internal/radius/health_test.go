package radius

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func TestProbeUpstreamServersStatusServer(t *testing.T) {
	secret := []byte("upstream-secret")
	packetSeen := make(chan *layehradius.Packet, 1)

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	server := &layehradius.PacketServer{
		SecretSource: layehradius.StaticSecretSource(secret),
		Handler: layehradius.HandlerFunc(func(w layehradius.ResponseWriter, r *layehradius.Request) {
			packetSeen <- r.Packet
			reply := r.Response(layehradius.CodeAccessAccept)
			_ = rfc2865.ReplyMessage_SetString(reply, "upstream alive")
			_ = w.Write(reply)
		}),
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(conn)
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	host, portText, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}

	cfg := &config.Config{
		LAN: config.InterfaceConfig{Address: "127.0.0.1/32"},
		Portal: config.PortalConfig{
			ListenIP: "127.0.0.1",
		},
		Radius: config.RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			NASIdentifier:         "aegisnas-test",
			RequestTimeoutSeconds: 1,
			Upstream: config.RadiusUpstreamConfig{
				Enabled:     true,
				StatusCheck: "status-server",
				Servers: []config.RadiusHomeServer{
					{
						Name:     "primary",
						Address:  host,
						AuthPort: port,
						AcctPort: port + 1,
						Secret:   string(secret),
					},
				},
			},
		},
	}

	statuses, err := ProbeUpstreamServers(context.Background(), cfg)
	if err != nil {
		t.Fatalf("probe upstream servers: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("got %d statuses, want 1", len(statuses))
	}
	status := statuses[0]
	if status.Status != "ok" {
		t.Fatalf("got status %q, want ok", status.Status)
	}
	if status.ResponseCode != layehradius.CodeAccessAccept.String() {
		t.Fatalf("got response code %q, want %q", status.ResponseCode, layehradius.CodeAccessAccept)
	}
	if status.Message != "upstream alive" {
		t.Fatalf("got message %q", status.Message)
	}
	if !status.SupportsStatusServer {
		t.Fatalf("expected status-server support")
	}

	select {
	case request := <-packetSeen:
		if request.Code != layehradius.CodeStatusServer {
			t.Fatalf("got code %v, want Status-Server", request.Code)
		}
		if serviceType := rfc2865.ServiceType_Get(request); serviceType != rfc2865.ServiceType_Value_AuthenticateOnly {
			t.Fatalf("got service type %v", serviceType)
		}
		messageAuthenticator := rfc2869.MessageAuthenticator_Get(request)
		if len(messageAuthenticator) != 16 {
			t.Fatalf("got message authenticator length %d, want 16", len(messageAuthenticator))
		}
		if bytes.Equal(messageAuthenticator, make([]byte, 16)) {
			t.Fatalf("message authenticator was all zeros")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive probe request")
	}

	select {
	case err := <-serverErr:
		if err != nil && err != layehradius.ErrServerShutdown {
			t.Fatalf("server exited early: %v", err)
		}
	default:
	}
}

func TestProbeUpstreamServersDisabledProbe(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 1,
			Upstream: config.RadiusUpstreamConfig{
				Enabled:     true,
				StatusCheck: "none",
				Servers: []config.RadiusHomeServer{
					{
						Name:    "secondary",
						Address: "10.0.0.10",
						Secret:  "secret",
					},
				},
			},
		},
	}

	statuses, err := ProbeUpstreamServers(context.Background(), cfg)
	if err != nil {
		t.Fatalf("probe upstream servers: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("got %d statuses, want 1", len(statuses))
	}
	if statuses[0].Status != "disabled" {
		t.Fatalf("got status %q, want disabled", statuses[0].Status)
	}
}
