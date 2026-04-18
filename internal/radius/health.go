package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

type UpstreamServerHealth struct {
	Name                 string `json:"name"`
	Address              string `json:"address"`
	AuthPort             int    `json:"auth_port"`
	AcctPort             int    `json:"acct_port"`
	Status               string `json:"status"`
	Message              string `json:"message"`
	ResponseCode         string `json:"response_code,omitempty"`
	LatencyMs            int64  `json:"latency_ms,omitempty"`
	CheckedAt            string `json:"checked_at"`
	SupportsStatusServer bool   `json:"supports_status_server"`
}

func ProbeUpstreamServers(ctx context.Context, cfg *config.Config) ([]UpstreamServerHealth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	statuses := make([]UpstreamServerHealth, len(cfg.Radius.Upstream.Servers))
	if len(statuses) == 0 {
		return statuses, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	var wg sync.WaitGroup
	for index, server := range cfg.Radius.Upstream.Servers {
		wg.Add(1)
		go func(index int, server config.RadiusHomeServer) {
			defer wg.Done()
			statuses[index] = probeUpstreamServer(ctx, cfg, server)
		}(index, server)
	}
	wg.Wait()

	return statuses, nil
}

func probeUpstreamServer(ctx context.Context, cfg *config.Config, server config.RadiusHomeServer) UpstreamServerHealth {
	authPort := server.AuthPort
	if authPort == 0 {
		authPort = cfg.Radius.AuthPort
	}
	acctPort := server.AcctPort
	if acctPort == 0 {
		acctPort = cfg.Radius.AcctPort
	}

	status := UpstreamServerHealth{
		Name:                 strings.TrimSpace(server.Name),
		Address:              strings.TrimSpace(server.Address),
		AuthPort:             authPort,
		AcctPort:             acctPort,
		CheckedAt:            time.Now().UTC().Format(time.RFC3339),
		SupportsStatusServer: cfg.Radius.Upstream.StatusCheck == "status-server",
	}
	component := runtimeStatusComponentName(status.Name)

	if !cfg.Radius.Upstream.Enabled {
		status.Status = "disabled"
		status.Message = "Upstream AAA is disabled"
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}
	if !status.SupportsStatusServer {
		status.Status = "disabled"
		status.Message = "Per-server probing is disabled because radius.upstream.status_check is none"
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}
	if status.Address == "" {
		status.Status = "down"
		status.Message = "Upstream server address is empty"
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}

	timeout := dashboardProbeTimeout(cfg)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := layehradius.New(layehradius.CodeStatusServer, []byte(server.Secret))
	if err := rfc2865.NASIdentifier_SetString(request, cfg.Radius.NASIdentifier); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}
	if err := rfc2865.ServiceType_Set(request, rfc2865.ServiceType_Value_AuthenticateOnly); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}
	if nasIP := resolveNASIP(cfg); nasIP != nil {
		if err := rfc2865.NASIPAddress_Set(request, nasIP); err != nil {
			status.Status = "unknown"
			status.Message = err.Error()
			_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
			return status
		}
	}
	if err := setMessageAuthenticator(request); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}

	endpoint := fmt.Sprintf("%s:%d", status.Address, status.AuthPort)
	start := time.Now()
	client := layehradius.Client{
		Retry: timeout / 3,
	}
	response, err := client.Exchange(probeCtx, request, endpoint)
	status.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		status.Status = "down"
		status.Message = err.Error()
		_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
		return status
	}

	status.ResponseCode = response.Code.String()
	replyMessage, _ := rfc2865.ReplyMessage_LookupString(response)
	if strings.TrimSpace(replyMessage) == "" {
		replyMessage = fmt.Sprintf("Status-Server answered with %s", response.Code)
	}

	switch response.Code {
	case layehradius.CodeAccessAccept, layehradius.CodeAccessChallenge:
		status.Status = "ok"
	case layehradius.CodeAccessReject:
		status.Status = "degraded"
	default:
		status.Status = "degraded"
	}
	status.Message = replyMessage
	_ = db.UpsertRuntimeStatus(component, status.Status, status.Message, runtimeStatusDetails(status))
	return status
}

func dashboardProbeTimeout(cfg *config.Config) time.Duration {
	timeout := time.Duration(cfg.Radius.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	return timeout
}

func setMessageAuthenticator(packet *layehradius.Packet) error {
	if packet == nil {
		return fmt.Errorf("packet is required")
	}
	if len(packet.Secret) == 0 {
		return fmt.Errorf("packet secret is required")
	}
	if err := rfc2869.MessageAuthenticator_Set(packet, make([]byte, 16)); err != nil {
		return err
	}

	wire, err := packet.MarshalBinary()
	if err != nil {
		return err
	}
	offset, err := messageAuthenticatorOffset(wire)
	if err != nil {
		return err
	}

	mac := hmac.New(md5.New, packet.Secret)
	_, _ = mac.Write(wire)
	sum := mac.Sum(nil)
	copy(wire[offset:offset+16], sum)
	return rfc2869.MessageAuthenticator_Set(packet, sum)
}

func messageAuthenticatorOffset(wire []byte) (int, error) {
	for offset := 20; offset < len(wire); {
		if offset+2 > len(wire) {
			return 0, fmt.Errorf("invalid radius attribute at offset %d", offset)
		}
		attrType := wire[offset]
		attrLen := int(wire[offset+1])
		if attrLen < 2 || offset+attrLen > len(wire) {
			return 0, fmt.Errorf("invalid radius attribute length %d", attrLen)
		}
		if attrType == byte(rfc2869.MessageAuthenticator_Type) {
			if attrLen != 18 {
				return 0, fmt.Errorf("unexpected message authenticator length %d", attrLen)
			}
			return offset + 2, nil
		}
		offset += attrLen
	}
	return 0, fmt.Errorf("message authenticator not found")
}

func runtimeStatusComponentName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.ReplaceAll(normalized, " ", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")
	if normalized == "" {
		normalized = "unnamed"
	}
	return "radius_upstream_" + normalized
}

func runtimeStatusDetails(status UpstreamServerHealth) map[string]any {
	return map[string]any{
		"name":                   status.Name,
		"endpoint":               fmt.Sprintf("%s:%d", status.Address, status.AuthPort),
		"address":                status.Address,
		"auth_port":              status.AuthPort,
		"acct_port":              status.AcctPort,
		"response_code":          status.ResponseCode,
		"latency_ms":             status.LatencyMs,
		"checked_at":             status.CheckedAt,
		"supports_status_server": status.SupportsStatusServer,
	}
}
