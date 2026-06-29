package session

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	aegisradius "github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// DynamicAuthServer listens for Disconnect-Request and CoA-Request packets.
type DynamicAuthServer struct {
	cfg    *config.Config
	logger *zap.Logger
	mgr    *Manager
	server *layehradius.PacketServer
}

func NewDynamicAuthServer(cfg *config.Config, logger *zap.Logger, mgr *Manager) *DynamicAuthServer {
	svc := &DynamicAuthServer{
		cfg:    cfg,
		logger: logger,
		mgr:    mgr,
	}
	svc.server = &layehradius.PacketServer{
		Addr:         fmt.Sprintf(":%d", cfg.Radius.DynamicAuth.Port),
		SecretSource: dynamicAuthSecretSource{cfg: cfg},
		Handler:      layehradius.HandlerFunc(svc.handle),
	}
	return svc
}

func (s *DynamicAuthServer) ListenAndServe(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	if ctx == nil {
		return s.server.ListenAndServe()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == layehradius.ErrServerShutdown {
			return nil
		}
		return err
	}
}

func (s *DynamicAuthServer) handle(w layehradius.ResponseWriter, r *layehradius.Request) {
	sessionID, _ := rfc2866.AcctSessionID_LookupString(r.Packet)
	username, _ := rfc2865.UserName_LookupString(r.Packet)
	mac, _ := rfc2865.CallingStationID_LookupString(r.Packet)

	switch r.Code {
	case layehradius.CodeDisconnectRequest:
		ok, err := s.mgr.TerminateByCriteria(sessionID, username, mac, "disconnect-request")
		if err != nil {
			s.writeNAK(w, r, layehradius.CodeDisconnectNAK, "disconnect failed")
			aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "disconnect", false, "disconnect failed")
			s.logger.Warn("coa disconnect failed", zap.Error(err))
			return
		}
		if !ok {
			s.writeNAK(w, r, layehradius.CodeDisconnectNAK, "session not found")
			aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "disconnect", false, "session not found")
			return
		}
		reply := r.Response(layehradius.CodeDisconnectACK)
		_ = rfc2865.ReplyMessage_SetString(reply, "session terminated")
		_ = w.Write(reply)
		aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "disconnect", true, "session terminated")

	case layehradius.CodeCoARequest:
		update, err := s.policyUpdateFromPacket(r.Packet)
		if err != nil {
			s.writeNAK(w, r, layehradius.CodeCoANAK, "invalid policy update")
			aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "coa", false, "invalid policy update")
			s.logger.Warn("coa policy decode failed", zap.Error(err))
			return
		}
		ok, err := s.mgr.ReclassifyByCriteria(sessionID, username, mac, update)
		if err != nil {
			s.writeNAK(w, r, layehradius.CodeCoANAK, "reclassify failed")
			aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "coa", false, "reclassify failed")
			s.logger.Warn("coa reclassify failed", zap.Error(err))
			return
		}
		if !ok {
			s.writeNAK(w, r, layehradius.CodeCoANAK, "session not found")
			aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "coa", false, "session not found")
			return
		}
		reply := r.Response(layehradius.CodeCoAACK)
		_ = rfc2865.ReplyMessage_SetString(reply, "session updated")
		_ = w.Write(reply)
		aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "coa", true, "session updated")

	default:
		s.writeNAK(w, r, layehradius.CodeCoANAK, "unsupported code")
		aegisradius.RecordVendorDynamicAuth(s.cfg, r.Packet, "coa", false, "unsupported dynamic authorization code")
	}
}

func (s *DynamicAuthServer) writeNAK(w layehradius.ResponseWriter, r *layehradius.Request, code layehradius.Code, message string) {
	reply := r.Response(code)
	_ = rfc2865.ReplyMessage_SetString(reply, message)
	_ = w.Write(reply)
}

func (s *DynamicAuthServer) policyUpdateFromPacket(packet *layehradius.Packet) (PolicyUpdate, error) {
	brokerResult := aegisradius.ParseBrokerPacketWithConfig(packet, s.cfg)
	policy, err := aegisradius.ResolveSessionPolicy(s.cfg.Policy.DefaultRole, brokerResult)
	if err != nil {
		return PolicyUpdate{}, err
	}
	return PolicyUpdate{
		Role:             policy.Role,
		VLAN:             policy.VLAN,
		BandwidthProfile: policy.BandwidthProfile,
		FilterID:         policy.FilterID,
		RadiusClass:      policy.RadiusClass,
		SessionTimeout:   policy.SessionTimeout,
		IdleTimeout:      policy.IdleTimeout,
	}, nil
}

type dynamicAuthSecretSource struct {
	cfg *config.Config
}

func (s dynamicAuthSecretSource) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	_ = ctx
	if s.cfg == nil {
		return nil, nil
	}
	host := remoteHost(remoteAddr)
	for _, server := range s.cfg.Radius.Upstream.Servers {
		if strings.EqualFold(strings.TrimSpace(server.Address), host) {
			return []byte(server.Secret), nil
		}
	}
	if s.cfg.Radius.Upstream.Enabled {
		return nil, nil
	}
	return []byte(s.cfg.Radius.Secret), nil
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}
