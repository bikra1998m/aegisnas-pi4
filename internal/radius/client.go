package radius

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	mikrotikvsa "layeh.com/radius/vendors/mikrotik"
	wisprvsa "layeh.com/radius/vendors/wispr"
)

type BrokerAuthRequest struct {
	Username         string
	Password         string
	CallingStationID string
	CalledStationID  string
	FramedIPAddress  string
	NASPort          int
}

type BrokerAuthResult struct {
	Accepted                 bool
	ReplyMessage             string
	FilterID                 string
	Class                    string
	VLAN                     int
	HasVLAN                  bool
	SessionTimeout           int
	HasSessionTimeout        bool
	IdleTimeout              int
	HasIdleTimeout           bool
	MikrotikRateLimit        string
	WISPrBandwidthMaxDown    int
	WISPrBandwidthMaxUp      int
	VendorRole               string
	VendorBandwidthProfile   string
	VendorPolicyTag          string
	VendorSessionAction      string
	VendorPortalProfile      string
	VendorDeviceGroup        string
	VendorTenant             string
	VendorDevicePosture      string
	VendorAccountingIdentity string
	VendorInboundACL         string
	VendorOutboundACL        string
	VendorAVPairs            []string
	VendorVLAN               int
	HasVendorVLAN            bool
	VendorTaggedVLANs        []int
	VendorMaxTotalOctets     uint64
	HasVendorMaxTotalOctets  bool
	VendorQuarantine         bool
	HasVendorQuarantine      bool
	VendorSessionTimeout     int
	HasVendorSessionTimeout  bool
	VendorIdleTimeout        int
	HasVendorIdleTimeout     bool
}

type accountingSendResult struct {
	ResponseCode string
	Latency      time.Duration
}

type accountingBuildError struct {
	err error
}

func (e accountingBuildError) Error() string {
	return e.err.Error()
}

func (e accountingBuildError) Unwrap() error {
	return e.err
}

var accountingPacketSender = sendAccountingDirect

func AuthenticatePAP(ctx context.Context, cfg *config.Config, req BrokerAuthRequest) (*BrokerAuthResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	request := layehradius.New(layehradius.CodeAccessRequest, []byte(cfg.Radius.Secret))
	if err := rfc2865.UserName_SetString(request, req.Username); err != nil {
		return nil, err
	}
	if err := rfc2865.UserPassword_SetString(request, req.Password); err != nil {
		return nil, err
	}
	if err := rfc2865.ServiceType_Set(request, rfc2865.ServiceType_Value_FramedUser); err != nil {
		return nil, err
	}
	if err := rfc2865.NASPortType_Set(request, rfc2865.NASPortType_Value_Wireless80211); err != nil {
		return nil, err
	}
	if err := rfc2865.NASIdentifier_SetString(request, cfg.Radius.NASIdentifier); err != nil {
		return nil, err
	}
	if nasIP := resolveNASIP(cfg); nasIP != nil {
		if err := rfc2865.NASIPAddress_Set(request, nasIP); err != nil {
			return nil, err
		}
	}
	if req.NASPort > 0 {
		if err := rfc2865.NASPort_Set(request, rfc2865.NASPort(req.NASPort)); err != nil {
			return nil, err
		}
	}
	if req.CallingStationID != "" {
		if err := rfc2865.CallingStationID_SetString(request, req.CallingStationID); err != nil {
			return nil, err
		}
	}
	if req.CalledStationID != "" {
		if err := rfc2865.CalledStationID_SetString(request, req.CalledStationID); err != nil {
			return nil, err
		}
	}
	if framedIP := net.ParseIP(req.FramedIPAddress); framedIP != nil {
		if err := rfc2865.FramedIPAddress_Set(request, framedIP); err != nil {
			return nil, err
		}
	}

	timeout := time.Duration(cfg.Radius.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	client := layehradius.Client{
		Retry: timeout / 3,
	}
	response, err := client.Exchange(ctx, request, fmt.Sprintf("127.0.0.1:%d", cfg.Radius.AuthPort))
	if err != nil {
		_ = db.UpsertRuntimeStatus("radius_broker_auth", "down", err.Error(), map[string]any{
			"endpoint":         fmt.Sprintf("127.0.0.1:%d", cfg.Radius.AuthPort),
			"upstream_enabled": cfg.Radius.Upstream.Enabled,
			"realm":            cfg.Radius.Upstream.Realm,
		})
		RecordVendorAuthTransportFailure(cfg, err.Error())
		return nil, err
	}

	result := ParseBrokerPacketWithConfig(response, cfg)
	result.Accepted = response.Code == layehradius.CodeAccessAccept
	if msg, err := rfc2865.ReplyMessage_LookupString(response); err == nil {
		result.ReplyMessage = msg
	}
	status := "ok"
	message := "broker auth succeeded"
	if !result.Accepted {
		status = "degraded"
		message = "broker auth rejected"
	}
	_ = db.UpsertRuntimeStatus("radius_broker_auth", status, message, map[string]any{
		"endpoint":         fmt.Sprintf("127.0.0.1:%d", cfg.Radius.AuthPort),
		"upstream_enabled": cfg.Radius.Upstream.Enabled,
		"realm":            cfg.Radius.Upstream.Realm,
		"response_code":    response.Code.String(),
	})
	RecordVendorAuthResult(cfg, result, response)
	return result, nil
}

func SendAccounting(ctx context.Context, cfg *config.Config, rec *AccountingRecord) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	if rec == nil {
		return fmt.Errorf("accounting record is required")
	}

	result, err := accountingPacketSender(ctx, cfg, rec)
	if err != nil {
		details := map[string]any{
			"endpoint":         accountingEndpoint(cfg),
			"upstream_enabled": cfg.Radius.Upstream.Enabled,
			"realm":            cfg.Radius.Upstream.Realm,
			"acct_status_type": rec.AcctStatusType,
		}
		if result.ResponseCode != "" {
			details["response_code"] = result.ResponseCode
		}
		status := "down"
		message := err.Error()
		if _, ok := err.(accountingBuildError); ok {
			status = "degraded"
		} else {
			spooled, queued, spoolErr := queueAccountingFailure(ctx, cfg, rec, err.Error())
			if spoolErr != nil {
				details["spool_error"] = spoolErr.Error()
			}
			if spooled.RecordID != "" {
				details["spool_record_id"] = spooled.RecordID
				details["spool_status"] = spooled.Status
				details["spool_queued"] = queued
				message = fmt.Sprintf("%s; accounting record spooled for replay", message)
			}
		}
		_ = db.UpsertRuntimeStatus("radius_broker_accounting", status, message, details)
		return err
	}
	_ = db.UpsertRuntimeStatus("radius_broker_accounting", "ok", "broker accounting succeeded", map[string]any{
		"endpoint":         accountingEndpoint(cfg),
		"upstream_enabled": cfg.Radius.Upstream.Enabled,
		"realm":            cfg.Radius.Upstream.Realm,
		"acct_status_type": rec.AcctStatusType,
		"response_code":    result.ResponseCode,
		"latency_ms":       result.Latency.Milliseconds(),
	})
	return nil
}

func sendAccountingDirect(ctx context.Context, cfg *config.Config, rec *AccountingRecord) (accountingSendResult, error) {
	packet := layehradius.New(layehradius.CodeAccountingRequest, []byte(cfg.Radius.Secret))

	if err := rfc2865.UserName_SetString(packet, rec.Username); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if err := rfc2866.AcctSessionID_SetString(packet, rec.SessionID); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if err := rfc2866.AcctStatusType_Set(packet, accountingStatusType(rec.AcctStatusType)); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if err := rfc2865.NASIdentifier_SetString(packet, cfg.Radius.NASIdentifier); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if nasIP := resolveNASIP(cfg); nasIP != nil {
		if err := rfc2865.NASIPAddress_Set(packet, nasIP); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if rec.CallingStationID != "" {
		if err := rfc2865.CallingStationID_SetString(packet, rec.CallingStationID); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if rec.CalledStationID != "" {
		if err := rfc2865.CalledStationID_SetString(packet, rec.CalledStationID); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if rec.FramedIPAddress != "" {
		if framedIP := net.ParseIP(rec.FramedIPAddress); framedIP != nil {
			if err := rfc2865.FramedIPAddress_Set(packet, framedIP); err != nil {
				return accountingSendResult{}, accountingBuildError{err: err}
			}
		}
	}
	if rec.NASPort > 0 {
		if err := rfc2865.NASPort_Set(packet, rfc2865.NASPort(rec.NASPort)); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if err := rfc2866.AcctInputOctets_Set(packet, rfc2866.AcctInputOctets(rec.AcctInputOctets)); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if err := rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(rec.AcctOutputOctets)); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}
	if rec.AcctSessionTime > 0 {
		if err := rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(rec.AcctSessionTime)); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if termCause, ok := accountingTerminateCause(rec.StopReason); ok {
		if err := rfc2866.AcctTerminateCause_Set(packet, termCause); err != nil {
			return accountingSendResult{}, accountingBuildError{err: err}
		}
	}
	if err := AddVendorAccountingAttributes(packet, cfg.Radius.Vendor, rec); err != nil {
		return accountingSendResult{}, accountingBuildError{err: err}
	}

	timeout := time.Duration(cfg.Radius.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	client := layehradius.Client{
		Retry: timeout / 3,
	}
	start := time.Now()
	response, err := client.Exchange(ctx, packet, accountingEndpoint(cfg))
	if err != nil {
		return accountingSendResult{Latency: time.Since(start)}, err
	}
	result := accountingSendResult{ResponseCode: response.Code.String(), Latency: time.Since(start)}
	if response.Code != layehradius.CodeAccountingResponse {
		return result, fmt.Errorf("unexpected accounting response code: %s", response.Code)
	}
	return result, nil
}

func accountingEndpoint(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return fmt.Sprintf("127.0.0.1:%d", cfg.Radius.AcctPort)
}

func ParseBrokerPacket(packet *layehradius.Packet) *BrokerAuthResult {
	result := &BrokerAuthResult{}
	if filterID, err := rfc2865.FilterID_LookupString(packet); err == nil {
		result.FilterID = filterID
	}
	if class, err := rfc2865.Class_LookupString(packet); err == nil {
		result.Class = class
	}
	if _, vlan, err := rfc2868.TunnelPrivateGroupID_LookupString(packet); err == nil {
		if parsed, convErr := strconv.Atoi(strings.TrimSpace(vlan)); convErr == nil {
			result.VLAN = parsed
			result.HasVLAN = true
		}
	}
	if sessionTimeout, err := rfc2865.SessionTimeout_Lookup(packet); err == nil {
		result.SessionTimeout = int(sessionTimeout)
		result.HasSessionTimeout = true
	}
	if idleTimeout, err := rfc2865.IdleTimeout_Lookup(packet); err == nil {
		result.IdleTimeout = int(idleTimeout)
		result.HasIdleTimeout = true
	}
	if rateLimit, err := mikrotikvsa.MikrotikRateLimit_LookupString(packet); err == nil {
		result.MikrotikRateLimit = rateLimit
	}
	if down, err := wisprvsa.WISPrBandwidthMaxDown_Lookup(packet); err == nil {
		result.WISPrBandwidthMaxDown = int(down)
	}
	if up, err := wisprvsa.WISPrBandwidthMaxUp_Lookup(packet); err == nil {
		result.WISPrBandwidthMaxUp = int(up)
	}
	return result
}

func resolveNASIP(cfg *config.Config) net.IP {
	if cfg == nil {
		return nil
	}
	if parsed := net.ParseIP(strings.TrimSpace(cfg.Portal.ListenIP)); parsed != nil {
		return parsed
	}
	address := strings.TrimSpace(cfg.LAN.Address)
	if address == "" {
		return nil
	}
	host := address
	if strings.Contains(address, "/") {
		parsedIP, _, err := net.ParseCIDR(address)
		if err == nil {
			return parsedIP
		}
		host = strings.Split(address, "/")[0]
	}
	return net.ParseIP(host)
}

func accountingStatusType(status string) rfc2866.AcctStatusType {
	switch status {
	case "Stop":
		return rfc2866.AcctStatusType_Value_Stop
	case "Interim-Update":
		return rfc2866.AcctStatusType_Value_InterimUpdate
	case "Accounting-On":
		return rfc2866.AcctStatusType_Value_AccountingOn
	case "Accounting-Off":
		return rfc2866.AcctStatusType_Value_AccountingOff
	default:
		return rfc2866.AcctStatusType_Value_Start
	}
}

func accountingTerminateCause(reason string) (rfc2866.AcctTerminateCause, bool) {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	switch normalized {
	case "idle timeout reached", "idle-timeout":
		return rfc2866.AcctTerminateCause_Value_IdleTimeout, true
	case "session timeout reached", "session-timeout":
		return rfc2866.AcctTerminateCause_Value_SessionTimeout, true
	case "admin termination", "admin reset", "disconnect-request":
		return rfc2866.AcctTerminateCause_Value_AdminReset, true
	case "user logout", "logout", "user-request":
		return rfc2866.AcctTerminateCause_Value_UserRequest, true
	case "nas request":
		return rfc2866.AcctTerminateCause_Value_NASRequest, true
	default:
		return rfc2866.AcctTerminateCause_Value_UserRequest, false
	}
}
