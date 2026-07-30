package tacacs

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const runtimeComponent = "tacacs_server"

type Server struct {
	cfg       *config.Config
	effective config.TACACSConfig
	logger    *zap.Logger
	resolver  *secrets.Resolver
}

type connectionState struct {
	client      ClientIdentity
	secret      string
	pendingAuth map[uint32]AuthenStart
}

func NewServer(cfg *config.Config, logger *zap.Logger) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Server{
		cfg:       cfg,
		effective: EffectiveConfig(cfg),
		logger:    logger,
		resolver:  secrets.NewResolver(secrets.OptionsFromConfig(cfg)),
	}
}

func StartServer(ctx context.Context, cfg *config.Config, logger *zap.Logger) error {
	server := NewServer(cfg, logger)
	return server.ListenAndServe(ctx)
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !s.effective.Enabled {
		_ = db.UpsertRuntimeStatus(runtimeComponent, "disabled", "TACACS+ server is disabled.", nil)
		return nil
	}
	address := net.JoinHostPort(s.effective.ListenAddress, strconv.Itoa(s.effective.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		_ = db.UpsertRuntimeStatus(runtimeComponent, "error", "TACACS+ listener failed to start.", map[string]any{"error": err.Error(), "address": address})
		return err
	}
	defer listener.Close()
	_ = db.UpsertRuntimeStatus(runtimeComponent, "ok", "TACACS+ server is listening.", map[string]any{"address": address})
	s.logger.Info("tacacs server listening", zap.String("address", address))

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	sem := make(chan struct{}, s.effective.MaxConnections)
	var wg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				_ = db.UpsertRuntimeStatus(runtimeComponent, "disabled", "TACACS+ server stopped.", nil)
				return nil
			}
			s.logger.Warn("accept tacacs connection", zap.Error(err))
			continue
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				s.handleConnection(ctx, conn)
			}()
		default:
			_ = db.UpsertRuntimeStatus(runtimeComponent, "degraded", "TACACS+ connection limit reached.", map[string]any{"max_connections": s.effective.MaxConnections})
			_ = conn.Close()
		}
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remoteIP := remoteIPString(conn.RemoteAddr())
	state := connectionState{pendingAuth: map[uint32]AuthenStart{}}
	client, secret, err := s.clientForRemote(ctx, remoteIP)
	if err != nil {
		s.logger.Warn("tacacs client rejected", zap.String("remote_ip", remoteIP), zap.Error(err))
		_ = db.RecordTACACSProtocolEvent(db.TACACSProtocolEvent{
			SessionID: 0,
			ClientIP:  remoteIP,
			EventType: "connection",
			Status:    "denied",
			Summary:   err.Error(),
		}, s.effective.RetentionLimit)
		return
	}
	state.client = client
	state.secret = secret
	_ = db.RecordTACACSProtocolEvent(db.TACACSProtocolEvent{
		SessionID:  0,
		ClientName: client.Name,
		ClientIP:   remoteIP,
		EventType:  "connection",
		Status:     "ok",
		Summary:    "TACACS+ client connected.",
	}, s.effective.RetentionLimit)

	for {
		if timeout := time.Duration(s.effective.ReadTimeoutSeconds) * time.Second; timeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(timeout))
		}
		packet, err := ReadPacket(conn, state.secret, s.effective.MaxPacketBytes, s.effective.AllowUnencrypted)
		if err != nil {
			if isTemporaryClose(err) {
				return
			}
			s.logger.Warn("read tacacs packet", zap.String("client", client.Name), zap.Error(err))
			_ = db.RecordTACACSProtocolEvent(db.TACACSProtocolEvent{
				SessionID:  packet.Header.SessionID,
				ClientName: client.Name,
				ClientIP:   remoteIP,
				EventType:  "protocol_error",
				Status:     "error",
				Summary:    err.Error(),
			}, s.effective.RetentionLimit)
			return
		}
		response, err := s.handlePacket(ctx, packet, &state)
		if err != nil {
			s.logger.Warn("handle tacacs packet", zap.String("client", client.Name), zap.Uint32("session_id", packet.Header.SessionID), zap.Error(err))
			response = errorResponseFor(packet, err.Error(), state.secret)
		}
		if timeout := time.Duration(s.effective.ReadTimeoutSeconds) * time.Second; timeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		}
		if err := WritePacket(conn, response, state.secret); err != nil {
			s.logger.Warn("write tacacs packet", zap.String("client", client.Name), zap.Error(err))
			return
		}
		if packet.Header.Flags&FlagSingleConnect == 0 {
			return
		}
		if timeout := time.Duration(s.effective.IdleTimeoutSeconds) * time.Second; timeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(timeout))
		}
	}
}

func (s *Server) handlePacket(ctx context.Context, packet Packet, state *connectionState) (Packet, error) {
	switch packet.Header.Type {
	case TypeAuthentication:
		body, err := s.handleAuthentication(packet, state)
		return responsePacket(packet, body, state.secret), err
	case TypeAuthorization:
		body, err := s.handleAuthorization(ctx, packet, state)
		return responsePacket(packet, body, state.secret), err
	case TypeAccounting:
		body, err := s.handleAccounting(packet, state)
		return responsePacket(packet, body, state.secret), err
	default:
		return Packet{}, fmt.Errorf("unsupported TACACS+ packet type %d", packet.Header.Type)
	}
}

func (s *Server) handleAuthentication(packet Packet, state *connectionState) ([]byte, error) {
	if strings.EqualFold(s.effective.AuthenticationSource, "disabled") {
		return MarshalAuthenReply(AuthenReply{Status: AuthenStatusFail, ServerMsg: "TACACS+ authentication is disabled"})
	}
	if packet.Header.SeqNo == 1 {
		start, err := ParseAuthenStart(packet.Body)
		if err != nil {
			return nil, err
		}
		if start.Action != AuthenActionLogin {
			return MarshalAuthenReply(AuthenReply{Status: AuthenStatusFail, ServerMsg: "unsupported authentication action"})
		}
		if start.AuthenType == AuthenTypePAP && len(start.Data) > 0 {
			return s.authenticatePassword(packet.Header.SessionID, state, start, string(start.Data))
		}
		if start.AuthenType == AuthenTypeASCII {
			state.pendingAuth[packet.Header.SessionID] = start
			return MarshalAuthenReply(AuthenReply{Status: AuthenStatusGetPass, ServerMsg: "Password:"})
		}
		return MarshalAuthenReply(AuthenReply{Status: AuthenStatusFail, ServerMsg: "unsupported authentication type"})
	}
	cont, err := ParseAuthenContinue(packet.Body)
	if err != nil {
		return nil, err
	}
	start, ok := state.pendingAuth[packet.Header.SessionID]
	if !ok {
		return MarshalAuthenReply(AuthenReply{Status: AuthenStatusError, ServerMsg: "authentication state not found"})
	}
	delete(state.pendingAuth, packet.Header.SessionID)
	password := cont.UserMsg
	if password == "" && len(cont.Data) > 0 {
		password = string(cont.Data)
	}
	return s.authenticatePassword(packet.Header.SessionID, state, start, password)
}

func (s *Server) authenticatePassword(sessionID uint32, state *connectionState, start AuthenStart, password string) ([]byte, error) {
	role, tenant, ok, err := validateLocalCredential(start.User, password)
	status := "failed"
	message := "TACACS+ authentication failed."
	replyStatus := AuthenStatusFail
	if err == nil && ok {
		status = "ok"
		message = "TACACS+ authentication succeeded."
		replyStatus = AuthenStatusPass
	}
	if err != nil {
		status = "error"
		message = "TACACS+ authentication lookup failed."
		replyStatus = AuthenStatusError
	}
	_ = db.RecordTACACSProtocolEvent(db.TACACSProtocolEvent{
		SessionID:  sessionID,
		ClientName: state.client.Name,
		ClientIP:   state.client.IP,
		EventType:  "authentication",
		Status:     status,
		Summary:    message,
		DetailsJSON: jsonObject(map[string]any{
			"username_hash": db.HashEAPIdentity(start.User),
			"role":          role,
			"tenant":        tenant,
			"authen_type":   start.AuthenType,
		}),
	}, s.effective.RetentionLimit)
	if err != nil {
		return MarshalAuthenReply(AuthenReply{Status: replyStatus, ServerMsg: "authentication error"})
	}
	if !ok {
		return MarshalAuthenReply(AuthenReply{Status: replyStatus, ServerMsg: "authentication failed"})
	}
	return MarshalAuthenReply(AuthenReply{Status: replyStatus, ServerMsg: "authentication successful"})
}

func (s *Server) handleAuthorization(ctx context.Context, packet Packet, state *connectionState) ([]byte, error) {
	start := time.Now()
	req, err := ParseAuthorRequest(packet.Body, s.effective.MaxArgs)
	if err != nil {
		return nil, err
	}
	command := CommandFromArgs(req.Args)
	if command == "" {
		command = "login"
	}
	if len(command) > s.effective.MaxCommandBytes {
		resp, _ := MarshalAuthorResponse(AuthorResponse{Status: AuthorStatusFail, ServerMsg: "command exceeds TACACS+ command length limit"})
		return resp, nil
	}
	role, tenant, _, _ := db.LocalUserRole(req.User)
	commandReq := CommandRequest{
		SessionID:      packet.Header.SessionID,
		Username:       req.User,
		Role:           role,
		Tenant:         tenant,
		Client:         state.client,
		Service:        ServiceFromArgs(req.Args, req.Service),
		Port:           req.Port,
		RemoteAddress:  req.RemoteAddress,
		Command:        command,
		Args:           req.Args,
		PrivilegeLevel: PrivilegeFromArgs(req.Args, req.Privilege),
		Authenticated:  true,
		EvaluatedAt:    start.UTC(),
	}
	decision, err := EvaluateCommand(ctx, s.cfg, commandReq, s.logger)
	if err != nil {
		return nil, err
	}
	responseStatus := AuthorStatusFail
	serverMsg := decision.Reason
	responseArgs := []string(nil)
	if decision.Permit || s.effective.Mode == "monitor" {
		responseStatus = AuthorStatusPassAdd
		responseArgs = decision.ResponseArgs
		if !decision.Permit {
			serverMsg = "monitor mode: " + decision.Reason
		}
	}
	response := AuthorResponse{Status: responseStatus, ServerMsg: serverMsg, Args: responseArgs}
	body, err := MarshalAuthorResponse(response)
	if err != nil {
		return nil, err
	}
	if s.effective.AuditEnabled {
		_ = db.RecordTACACSAuthorizationEvent(db.TACACSAuthorizationEvent{
			EventID:            decision.DecisionID,
			SessionID:          packet.Header.SessionID,
			UsernameHash:       req.User,
			Role:               role,
			Tenant:             tenant,
			ClientName:         state.client.Name,
			ClientIP:           state.client.IP,
			Vendor:             state.client.Vendor,
			Service:            commandReq.Service,
			Port:               req.Port,
			RemoteAddress:      req.RemoteAddress,
			Command:            command,
			PrivilegeLevel:     commandReq.PrivilegeLevel,
			Decision:           decision.Status,
			Reason:             decision.Reason,
			MatchedCommandSet:  decision.MatchedCommandSet,
			PolicyEvaluationID: decision.PolicyEvaluationID,
			Args:               req.Args,
			RequestJSON:        jsonObject(commandReq),
			ResponseJSON: jsonObject(map[string]any{
				"wire_status":      responseStatus,
				"server_msg":       serverMsg,
				"args":             responseArgs,
				"monitor_override": !decision.Permit && s.effective.Mode == "monitor",
			}),
			LatencyMS: time.Since(start).Milliseconds(),
		}, s.effective.RetentionLimit)
	}
	return body, nil
}

func (s *Server) handleAccounting(packet Packet, state *connectionState) ([]byte, error) {
	req, err := ParseAcctRequest(packet.Body, s.effective.MaxArgs)
	if err != nil {
		return nil, err
	}
	command := CommandFromArgs(req.Args)
	taskID := argValue(req.Args, "task_id")
	role, tenant, _, _ := db.LocalUserRole(req.User)
	record := db.TACACSAccountingRecord{
		SessionID:      packet.Header.SessionID,
		TaskID:         taskID,
		UsernameHash:   req.User,
		Role:           role,
		Tenant:         tenant,
		ClientName:     state.client.Name,
		ClientIP:       state.client.IP,
		Vendor:         state.client.Vendor,
		Service:        ServiceFromArgs(req.Args, req.Service),
		Port:           req.Port,
		RemoteAddress:  req.RemoteAddress,
		Command:        command,
		PrivilegeLevel: PrivilegeFromArgs(req.Args, req.Privilege),
		Flags:          int(req.Flags),
		Status:         "recorded",
		Args:           req.Args,
		RequestJSON:    jsonObject(req),
	}
	if err := db.RecordTACACSAccountingRecord(record, s.effective.RetentionLimit); err != nil {
		body, _ := MarshalAcctResponse(AcctResponse{Status: AcctStatusError, ServerMsg: "accounting record failed"})
		return body, nil
	}
	body, _ := MarshalAcctResponse(AcctResponse{Status: AcctStatusSuccess, ServerMsg: "accounting recorded"})
	return body, nil
}

func (s *Server) clientForRemote(ctx context.Context, remoteIP string) (ClientIdentity, string, error) {
	for _, raw := range s.effective.Clients {
		if !tacacsClientMatches(raw, remoteIP) {
			continue
		}
		client := ClientIdentity{
			Name:    strings.TrimSpace(raw.Name),
			IP:      remoteIP,
			Vendor:  strings.ToLower(strings.TrimSpace(raw.Vendor)),
			Model:   strings.TrimSpace(raw.Model),
			Tenant:  strings.TrimSpace(raw.Tenant),
			Known:   true,
			Enabled: raw.Enabled,
		}
		if !raw.Enabled {
			return client, "", errors.New("TACACS+ client is disabled")
		}
		secret, err := secrets.ResolveConfiguredSecret(ctx, s.resolver, "tacacs.clients."+client.Name+".secret", raw.Secret, raw.SecretRef)
		if err != nil {
			return client, "", err
		}
		if secret == "" {
			globalSecret, err := secrets.ResolveConfiguredSecret(ctx, s.resolver, "tacacs.secret", s.effective.Secret, s.effective.SecretRef)
			if err != nil {
				return client, "", err
			}
			secret = globalSecret
		}
		if secret == "" && !s.effective.AllowUnencrypted {
			return client, "", errors.New("TACACS+ client has no shared secret")
		}
		return client, secret, nil
	}
	if s.effective.RequireKnownClient {
		return ClientIdentity{IP: remoteIP, Enabled: false}, "", errors.New("unknown TACACS+ client")
	}
	globalSecret, err := secrets.ResolveConfiguredSecret(ctx, s.resolver, "tacacs.secret", s.effective.Secret, s.effective.SecretRef)
	if err != nil {
		return ClientIdentity{IP: remoteIP}, "", err
	}
	if globalSecret == "" && !s.effective.AllowUnencrypted {
		return ClientIdentity{IP: remoteIP}, "", errors.New("unknown TACACS+ client has no shared secret")
	}
	return ClientIdentity{Name: "unknown-" + strings.ReplaceAll(remoteIP, ":", "-"), IP: remoteIP, Known: false, Enabled: true}, globalSecret, nil
}

func validateLocalCredential(username, password string) (string, string, bool, error) {
	if db.DB == nil {
		return "", "", false, fmt.Errorf("database is not initialized")
	}
	var hash, role, tenant string
	err := db.DB.QueryRow(`SELECT password_hash, COALESCE(role, ''), COALESCE(tenant, '') FROM local_users WHERE username = ?`, strings.TrimSpace(username)).Scan(&hash, &role, &tenant)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", "", false, nil
	}
	return role, tenant, true, nil
}

func responsePacket(request Packet, body []byte, secret string) Packet {
	flags := byte(0)
	if secret == "" {
		flags = FlagUnencrypted
	}
	return Packet{
		Header: Header{
			Version:   request.Header.Version,
			Type:      request.Header.Type,
			SeqNo:     request.Header.SeqNo + 1,
			Flags:     flags,
			SessionID: request.Header.SessionID,
		},
		Body: body,
	}
}

func errorResponseFor(request Packet, message string, secret string) Packet {
	var body []byte
	switch request.Header.Type {
	case TypeAuthentication:
		body, _ = MarshalAuthenReply(AuthenReply{Status: AuthenStatusError, ServerMsg: message})
	case TypeAuthorization:
		body, _ = MarshalAuthorResponse(AuthorResponse{Status: AuthorStatusError, ServerMsg: message})
	case TypeAccounting:
		body, _ = MarshalAcctResponse(AcctResponse{Status: AcctStatusError, ServerMsg: message})
	default:
		body = []byte(message)
	}
	return responsePacket(request, body, secret)
}

func tacacsClientMatches(client config.TACACSClientConfig, remoteIP string) bool {
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	address := strings.TrimSpace(client.Address)
	if parsed := net.ParseIP(address); parsed != nil {
		return parsed.Equal(ip)
	}
	_, network, err := net.ParseCIDR(address)
	return err == nil && network.Contains(ip)
}

func remoteIPString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func isTemporaryClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func argValue(args []string, key string) string {
	for _, arg := range args {
		k, value, ok := strings.Cut(arg, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func DecodePacketBytes(raw []byte, secret string, maxPacketBytes int, allowUnencrypted bool) (Packet, error) {
	return ReadPacket(bytes.NewReader(raw), secret, maxPacketBytes, allowUnencrypted)
}

func EncodePacketBytes(packet Packet, secret string) ([]byte, error) {
	var buf bytes.Buffer
	if err := WritePacket(&buf, packet, secret); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func JSONForAudit(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
