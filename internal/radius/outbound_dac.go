package radius

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc3576"
	"layeh.com/radius/rfc3580"
)

const (
	OutboundDACSchemaVersion     = 1
	OutboundDACRuntimeComponent  = "radius_outbound_dac_client"
	outboundDACDefaultTransport  = "udp"
	outboundDACUnsupportedRadSec = "outbound RadSec reverse DAC routing is scheduled for NAS-0044"
)

type OutboundDACRequest struct {
	Action           string                    `json:"action"`
	TargetAddress    string                    `json:"target_address,omitempty"`
	TargetPort       int                       `json:"target_port,omitempty"`
	TargetTransport  string                    `json:"target_transport,omitempty"`
	NASIdentifier    string                    `json:"nas_identifier,omitempty"`
	NASIPAddress     string                    `json:"nas_ip_address,omitempty"`
	ShortName        string                    `json:"shortname,omitempty"`
	NASType          string                    `json:"nas_type,omitempty"`
	SessionID        string                    `json:"session_id,omitempty"`
	AcctSessionID    string                    `json:"acct_session_id,omitempty"`
	UserName         string                    `json:"user_name,omitempty"`
	CallingStationID string                    `json:"calling_station_id,omitempty"`
	FramedIPAddress  string                    `json:"framed_ip_address,omitempty"`
	FilterID         string                    `json:"filter_id,omitempty"`
	VLAN             int                       `json:"vlan,omitempty"`
	SessionTimeout   int                       `json:"session_timeout,omitempty"`
	IdleTimeout      int                       `json:"idle_timeout,omitempty"`
	RadiusClass      string                    `json:"radius_class,omitempty"`
	State            string                    `json:"state,omitempty"`
	Attributes       []db.OutboundDACAttribute `json:"attributes,omitempty"`
	CorrelationID    string                    `json:"correlation_id,omitempty"`
	Confirm          bool                      `json:"confirm,omitempty"`
}

type OutboundDACTarget struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Transport     string `json:"transport"`
	Endpoint      string `json:"endpoint"`
	ResolvedFrom  string `json:"resolved_from"`
	NASIdentifier string `json:"nas_identifier,omitempty"`
	NASIPAddress  string `json:"nas_ip_address,omitempty"`
	ShortName     string `json:"shortname,omitempty"`
	NASType       string `json:"nas_type,omitempty"`
	KnownClient   bool   `json:"known_client"`
	SecretReady   bool   `json:"secret_ready"`
}

type OutboundDACAttributePlan struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Selector bool   `json:"selector"`
}

type OutboundDACPreview struct {
	SchemaVersion        int                        `json:"schema_version"`
	Status               string                     `json:"status"`
	Message              string                     `json:"message"`
	Action               string                     `json:"action"`
	RequestCode          int                        `json:"request_code"`
	ExpectedACKCode      int                        `json:"expected_ack_code"`
	ExpectedNAKCode      int                        `json:"expected_nak_code"`
	Target               OutboundDACTarget          `json:"target"`
	Attributes           []OutboundDACAttributePlan `json:"attributes"`
	AttributeCount       int                        `json:"attribute_count"`
	MaxAttributes        int                        `json:"max_attributes"`
	RequiresConfirm      bool                       `json:"requires_confirm"`
	MessageAuthenticator bool                       `json:"message_authenticator"`
	RequestFingerprint   string                     `json:"request_fingerprint"`
	Warnings             []string                   `json:"warnings,omitempty"`
	Blockers             []string                   `json:"blockers,omitempty"`
	RFCs                 []string                   `json:"rfcs"`
}

type OutboundDACReport struct {
	SchemaVersion int                           `json:"schema_version"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	Policy        map[string]any                `json:"policy"`
	Summary       db.OutboundDACSummary         `json:"summary"`
	Recent        []db.OutboundDACRequestRecord `json:"recent,omitempty"`
	RuntimeStatus *db.RuntimeStatus             `json:"runtime_status,omitempty"`
	Warnings      []string                      `json:"warnings,omitempty"`
	RFCs          []string                      `json:"rfcs"`
}

type OutboundDACSendResult struct {
	Status   string                        `json:"status"`
	Message  string                        `json:"message"`
	Preview  OutboundDACPreview            `json:"preview"`
	Request  db.OutboundDACRequestRecord   `json:"request"`
	Attempts []db.OutboundDACAttemptRecord `json:"attempts,omitempty"`
}

type outboundDACSendOutcome struct {
	Response     *layehradius.Packet
	Latency      time.Duration
	Err          error
	RequestWire  []byte
	RequestHash  string
	ResponseHash string
}

type outboundDACPacketSenderFunc func(ctx context.Context, packet *layehradius.Packet, endpoint string, timeout time.Duration) (*layehradius.Packet, time.Duration, error)

var outboundDACPacketSender outboundDACPacketSenderFunc = sendOutboundDACDirect

func BuildOutboundDACReport(cfg *config.Config) OutboundDACReport {
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	summary, _ := db.GetOutboundDACSummary(effective.OutboundHistoryLimit)
	recent, _ := db.ListOutboundDACRequests(db.OutboundDACRequestQuery{Limit: 12})
	runtime, _ := db.GetRuntimeStatus(OutboundDACRuntimeComponent)
	report := OutboundDACReport{
		SchemaVersion: OutboundDACSchemaVersion,
		Status:        "ready",
		Message:       "Outbound RFC 5176 CoA and Disconnect client is ready for immediate UDP sends to known NAS clients.",
		Policy: map[string]any{
			"enabled":                     effective.OutboundEnabled,
			"default_port":                effective.OutboundDefaultPort,
			"timeout_seconds":             effective.OutboundTimeoutSeconds,
			"require_known_client":        effective.OutboundRequireKnownClient,
			"history_limit":               effective.OutboundHistoryLimit,
			"max_attributes":              effective.OutboundMaxAttributes,
			"allow_coa":                   effective.OutboundAllowCoA,
			"allow_disconnect":            effective.OutboundAllowDisconnect,
			"require_confirmation":        effective.OutboundRequireConfirmation,
			"supported_transport":         []string{"udp"},
			"deferred_transport_features": []string{"NAS-0044 proxy CoA and RadSec reverse CoA routing"},
		},
		Summary:       summary,
		Recent:        recent,
		RuntimeStatus: runtime,
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 3576", "RFC 3580", "RFC 5176"},
	}
	if !effective.OutboundEnabled {
		report.Status = "disabled"
		report.Message = "Outbound dynamic authorization is disabled by configuration."
		report.Warnings = append(report.Warnings, "Enable radius.dynamic_auth.outbound_enabled before sending CoA or Disconnect packets.")
	}
	if effective.OutboundRequireKnownClient && len(configuredRadiusClients(cfg)) == 0 {
		report.Status = "blocked"
		report.Message = "Outbound DAC requires a known RADIUS client but no clients are configured."
		report.Warnings = append(report.Warnings, "Add managed RADIUS clients with resolvable secrets before production use.")
	}
	return report
}

func PreviewOutboundDAC(ctx context.Context, cfg *config.Config, request OutboundDACRequest) (OutboundDACPreview, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	request = normalizeOutboundDACRequest(request)
	preview := OutboundDACPreview{
		SchemaVersion:        OutboundDACSchemaVersion,
		Status:               "ready",
		Action:               request.Action,
		MaxAttributes:        effective.OutboundMaxAttributes,
		RequiresConfirm:      effective.OutboundRequireConfirmation,
		MessageAuthenticator: true,
		RFCs:                 []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 3576", "RFC 3580", "RFC 5176"},
	}
	if !effective.OutboundEnabled {
		preview.Status = "blocked"
		preview.Blockers = append(preview.Blockers, "outbound dynamic authorization is disabled")
	}
	code, ack, nak, err := outboundDACCodes(request.Action)
	if err != nil {
		preview.Status = "blocked"
		preview.Blockers = append(preview.Blockers, err.Error())
	} else {
		preview.RequestCode = int(code)
		preview.ExpectedACKCode = int(ack)
		preview.ExpectedNAKCode = int(nak)
		if request.Action == "coa" && !effective.OutboundAllowCoA {
			preview.Status = "blocked"
			preview.Blockers = append(preview.Blockers, "CoA requests are disabled by radius.dynamic_auth.outbound_allow_coa")
		}
		if request.Action == "disconnect" && !effective.OutboundAllowDisconnect {
			preview.Status = "blocked"
			preview.Blockers = append(preview.Blockers, "Disconnect requests are disabled by radius.dynamic_auth.outbound_allow_disconnect")
		}
	}
	enriched, hintWarnings := enrichOutboundDACRequestFromSession(request)
	request = enriched
	preview.Warnings = append(preview.Warnings, hintWarnings...)
	target, secret, targetWarnings, targetBlockers := resolveOutboundDACTarget(ctx, cfg, effective, request)
	_ = secret
	preview.Target = target
	preview.Warnings = append(preview.Warnings, targetWarnings...)
	preview.Blockers = append(preview.Blockers, targetBlockers...)
	attrs, attrErr := outboundDACAttributePlan(request, effective.OutboundMaxAttributes)
	if attrErr != nil {
		preview.Status = "blocked"
		preview.Blockers = append(preview.Blockers, attrErr.Error())
	}
	preview.Attributes = attrs
	preview.AttributeCount = len(attrs)
	if effective.OutboundRequireConfirmation && !request.Confirm {
		preview.Warnings = append(preview.Warnings, "send requires confirm=true")
	}
	preview.RequestFingerprint = db.FingerprintOutboundDAC(request.Action, target.Address, strconv.Itoa(target.Port), target.Transport, request.SessionID, request.AcctSessionID, request.UserName, request.CallingStationID, request.FramedIPAddress, attributePlanFingerprint(attrs))
	if len(preview.Blockers) > 0 {
		preview.Status = "blocked"
		preview.Message = strings.Join(preview.Blockers, "; ")
		return preview, nil
	}
	preview.Message = fmt.Sprintf("%s request can be sent to %s with %d attribute(s).", outboundDACActionLabel(request.Action), target.Endpoint, len(attrs))
	return preview, nil
}

func SendOutboundDAC(ctx context.Context, cfg *config.Config, request OutboundDACRequest, requestedBy string) (OutboundDACSendResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	request = normalizeOutboundDACRequest(request)
	request, _ = enrichOutboundDACRequestFromSession(request)
	preview, err := PreviewOutboundDAC(ctx, cfg, request)
	if err != nil {
		return OutboundDACSendResult{}, err
	}
	requestID := newOutboundDACRequestID(request, preview)
	now := time.Now().UTC()
	if effective.OutboundRequireConfirmation && !request.Confirm && len(preview.Blockers) == 0 {
		preview.Status = "blocked"
		preview.Blockers = append(preview.Blockers, "confirm=true is required before sending outbound dynamic authorization")
		preview.Message = "confirm=true is required before sending outbound dynamic authorization."
	}
	if len(preview.Blockers) > 0 {
		record, createErr := db.CreateOutboundDACRequest(db.OutboundDACCreate{
			RequestID:            requestID,
			Action:               firstNonEmptyString(preview.Action, request.Action),
			Status:               db.OutboundDACStatusBlocked,
			TargetAddress:        firstNonEmptyString(preview.Target.Address, "unresolved"),
			TargetPort:           firstNonZeroInt(preview.Target.Port, effective.OutboundDefaultPort),
			TargetTransport:      firstNonEmptyString(preview.Target.Transport, outboundDACDefaultTransport),
			NASIdentifier:        request.NASIdentifier,
			NASIPAddress:         request.NASIPAddress,
			NASType:              firstNonEmptyString(preview.Target.NASType, request.NASType),
			ShortName:            firstNonEmptyString(preview.Target.ShortName, request.ShortName),
			SessionID:            firstNonEmptyString(request.AcctSessionID, request.SessionID),
			Username:             request.UserName,
			CallingStationID:     request.CallingStationID,
			FramedIPAddress:      request.FramedIPAddress,
			Attributes:           dbAttributesFromPlan(preview.Attributes),
			RequestCode:          firstNonZeroInt(preview.RequestCode, int(layehradius.CodeCoARequest)),
			CorrelationID:        firstNonEmptyString(request.CorrelationID, requestID),
			RequestedBy:          requestedBy,
			RequestedAt:          now,
			FailureReason:        preview.Message,
			MessageAuthenticator: true,
			RequestFingerprint:   firstNonEmptyString(preview.RequestFingerprint, requestID),
		}, effective.OutboundHistoryLimit)
		if createErr != nil {
			return OutboundDACSendResult{}, createErr
		}
		_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, "blocked", preview.Message, map[string]any{"request_id": requestID, "action": request.Action})
		return OutboundDACSendResult{Status: "blocked", Message: preview.Message, Preview: preview, Request: record}, nil
	}
	target, secret, _, blockers := resolveOutboundDACTarget(ctx, cfg, effective, request)
	if len(blockers) > 0 {
		return OutboundDACSendResult{}, errors.New(strings.Join(blockers, "; "))
	}
	packet, attrs, err := buildOutboundDACPacket(request, secret, effective.OutboundMaxAttributes)
	if err != nil {
		return OutboundDACSendResult{}, err
	}
	if err := setMessageAuthenticator(packet); err != nil {
		return OutboundDACSendResult{}, fmt.Errorf("set Message-Authenticator: %w", err)
	}
	requestWire, err := packet.Encode()
	if err != nil {
		return OutboundDACSendResult{}, fmt.Errorf("encode outbound DAC packet: %w", err)
	}
	requestHash := packetWireSHA256(requestWire)
	record, err := db.CreateOutboundDACRequest(db.OutboundDACCreate{
		RequestID:            requestID,
		Action:               request.Action,
		Status:               db.OutboundDACStatusSent,
		TargetAddress:        target.Address,
		TargetPort:           target.Port,
		TargetTransport:      target.Transport,
		NASIdentifier:        firstNonEmptyString(request.NASIdentifier, target.NASIdentifier),
		NASIPAddress:         firstNonEmptyString(request.NASIPAddress, target.NASIPAddress),
		NASType:              firstNonEmptyString(target.NASType, request.NASType),
		ShortName:            firstNonEmptyString(target.ShortName, request.ShortName),
		SessionID:            firstNonEmptyString(request.AcctSessionID, request.SessionID),
		Username:             request.UserName,
		CallingStationID:     request.CallingStationID,
		FramedIPAddress:      request.FramedIPAddress,
		Attributes:           attrs,
		RequestCode:          int(packet.Code),
		CorrelationID:        firstNonEmptyString(request.CorrelationID, requestID),
		RequestedBy:          requestedBy,
		RequestedAt:          now,
		SentAt:               now,
		MessageAuthenticator: true,
		RequestFingerprint:   requestHash,
	}, effective.OutboundHistoryLimit)
	if err != nil {
		return OutboundDACSendResult{}, err
	}
	outcome := sendOutboundDACPacket(ctx, packet, target.Endpoint, time.Duration(effective.OutboundTimeoutSeconds)*time.Second, requestWire, requestHash)
	status, failure, responseCode, errorCause, errorCauseName, replyMessage := classifyOutboundDACResponse(request.Action, outcome.Response, outcome.Err)
	if err := db.RecordOutboundDACAttempt(db.OutboundDACAttemptCreate{
		RequestID:           requestID,
		Attempt:             1,
		Status:              status,
		TargetAddress:       target.Address,
		TargetPort:          target.Port,
		TargetTransport:     target.Transport,
		RequestCode:         int(packet.Code),
		ResponseCode:        responseCode,
		ErrorCause:          errorCause,
		ErrorCauseName:      errorCauseName,
		ReplyMessage:        replyMessage,
		LatencyMS:           outcome.Latency.Milliseconds(),
		PacketIdentifier:    int(packet.Identifier),
		RequestFingerprint:  requestHash,
		ResponseFingerprint: outcome.ResponseHash,
		ErrorMessage:        failure,
	}); err != nil {
		return OutboundDACSendResult{}, err
	}
	record, err = db.CompleteOutboundDACRequest(db.OutboundDACComplete{
		RequestID:           requestID,
		Status:              status,
		ResponseCode:        responseCode,
		ErrorCause:          errorCause,
		ErrorCauseName:      errorCauseName,
		ReplyMessage:        replyMessage,
		CompletedAt:         time.Now().UTC(),
		LatencyMS:           outcome.Latency.Milliseconds(),
		FailureReason:       failure,
		ResponseFingerprint: outcome.ResponseHash,
	})
	if err != nil {
		return OutboundDACSendResult{}, err
	}
	attempts, _ := db.ListOutboundDACAttempts(requestID, 10)
	message := outboundDACResultMessage(request.Action, status, failure, replyMessage, errorCauseName)
	_ = db.UpsertRuntimeStatus(OutboundDACRuntimeComponent, runtimeStatusForOutboundDAC(status), message, map[string]any{
		"request_id":            requestID,
		"action":                request.Action,
		"target":                target.Endpoint,
		"latency_ms":            outcome.Latency.Milliseconds(),
		"response_code":         responseCode,
		"error_cause":           errorCauseName,
		"correlation_id":        record.CorrelationID,
		"message_authenticator": true,
	})
	RecordVendorDynamicAuth(cfg, outcome.Response, request.Action, status == db.OutboundDACStatusACK, message)
	return OutboundDACSendResult{Status: status, Message: message, Preview: preview, Request: record, Attempts: attempts}, nil
}

func sendOutboundDACPacket(ctx context.Context, packet *layehradius.Packet, endpoint string, timeout time.Duration, requestWire []byte, requestHash string) outboundDACSendOutcome {
	response, latency, err := outboundDACPacketSender(ctx, packet, endpoint, timeout)
	outcome := outboundDACSendOutcome{Response: response, Latency: latency, Err: err, RequestWire: requestWire, RequestHash: requestHash}
	if response != nil {
		wire, wireErr := response.MarshalBinary()
		if wireErr == nil {
			outcome.ResponseHash = packetWireSHA256(wire)
		}
	}
	return outcome
}

func sendOutboundDACDirect(ctx context.Context, packet *layehradius.Packet, endpoint string, timeout time.Duration) (*layehradius.Packet, time.Duration, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	sendCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	client := &layehradius.Client{
		Net:             outboundDACDefaultTransport,
		Retry:           0,
		MaxPacketErrors: 1,
		Dialer:          net.Dialer{Timeout: timeout},
	}
	response, err := client.Exchange(sendCtx, packet, endpoint)
	return response, time.Since(start), err
}

func buildOutboundDACPacket(request OutboundDACRequest, secret string, maxAttributes int) (*layehradius.Packet, []db.OutboundDACAttribute, error) {
	code, _, _, err := outboundDACCodes(request.Action)
	if err != nil {
		return nil, nil, err
	}
	packet := layehradius.New(code, []byte(secret))
	attrs := []db.OutboundDACAttribute{}
	addString := func(name, value string, setter func(*layehradius.Packet, string) error) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if err := setter(packet, value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		attrs = append(attrs, db.OutboundDACAttribute{Name: name, Value: value})
		return nil
	}
	if err := addString("User-Name", request.UserName, rfc2865.UserName_SetString); err != nil {
		return nil, nil, err
	}
	if err := addString("Acct-Session-Id", firstNonEmptyString(request.AcctSessionID, request.SessionID), rfc2866.AcctSessionID_SetString); err != nil {
		return nil, nil, err
	}
	if err := addString("Calling-Station-Id", request.CallingStationID, rfc2865.CallingStationID_SetString); err != nil {
		return nil, nil, err
	}
	if err := addString("NAS-Identifier", request.NASIdentifier, rfc2865.NASIdentifier_SetString); err != nil {
		return nil, nil, err
	}
	if ip := net.ParseIP(strings.TrimSpace(request.NASIPAddress)); ip != nil {
		if err := rfc2865.NASIPAddress_Set(packet, ip); err != nil {
			return nil, nil, fmt.Errorf("NAS-IP-Address: %w", err)
		}
		attrs = append(attrs, db.OutboundDACAttribute{Name: "NAS-IP-Address", Value: ip.String()})
	}
	if ip := net.ParseIP(strings.TrimSpace(request.FramedIPAddress)); ip != nil {
		if err := rfc2865.FramedIPAddress_Set(packet, ip); err != nil {
			return nil, nil, fmt.Errorf("Framed-IP-Address: %w", err)
		}
		attrs = append(attrs, db.OutboundDACAttribute{Name: "Framed-IP-Address", Value: ip.String()})
	}
	if request.FilterID != "" {
		request.Attributes = append(request.Attributes, db.OutboundDACAttribute{Name: "Filter-Id", Value: request.FilterID})
	}
	if request.SessionTimeout > 0 {
		request.Attributes = append(request.Attributes, db.OutboundDACAttribute{Name: "Session-Timeout", Value: strconv.Itoa(request.SessionTimeout)})
	}
	if request.IdleTimeout > 0 {
		request.Attributes = append(request.Attributes, db.OutboundDACAttribute{Name: "Idle-Timeout", Value: strconv.Itoa(request.IdleTimeout)})
	}
	if request.RadiusClass != "" {
		request.Attributes = append(request.Attributes, db.OutboundDACAttribute{Name: "Class", Value: request.RadiusClass})
	}
	if request.State != "" {
		request.Attributes = append(request.Attributes, db.OutboundDACAttribute{Name: "State", Value: request.State})
	}
	if request.VLAN > 0 {
		request.Attributes = append(request.Attributes,
			db.OutboundDACAttribute{Name: "Tunnel-Type", Value: "VLAN"},
			db.OutboundDACAttribute{Name: "Tunnel-Medium-Type", Value: "IEEE-802"},
			db.OutboundDACAttribute{Name: "Tunnel-Private-Group-Id", Value: strconv.Itoa(request.VLAN)})
	}
	if len(request.Attributes)+len(attrs) > maxAttributes {
		return nil, nil, fmt.Errorf("outbound DAC attribute count exceeds configured limit %d", maxAttributes)
	}
	for _, attr := range request.Attributes {
		applied, err := applyOutboundDACAttribute(packet, attr)
		if err != nil {
			return nil, nil, err
		}
		attrs = append(attrs, applied)
	}
	if len(attrs) == 0 {
		return nil, nil, fmt.Errorf("at least one session selector or policy attribute is required")
	}
	return packet, attrs, nil
}

func applyOutboundDACAttribute(packet *layehradius.Packet, attr db.OutboundDACAttribute) (db.OutboundDACAttribute, error) {
	name := normalizeOutboundDACAttributeName(attr.Name)
	value := strings.TrimSpace(attr.Value)
	if name == "" || value == "" {
		return db.OutboundDACAttribute{}, fmt.Errorf("attribute name and value are required")
	}
	switch name {
	case "filter-id":
		return attrWithCanonicalName("Filter-Id", value), rfc2865.FilterID_SetString(packet, value)
	case "session-timeout":
		seconds, err := parseOutboundDACPositiveInt("Session-Timeout", value)
		if err != nil {
			return db.OutboundDACAttribute{}, err
		}
		return attrWithCanonicalName("Session-Timeout", strconv.Itoa(seconds)), rfc2865.SessionTimeout_Set(packet, rfc2865.SessionTimeout(seconds))
	case "idle-timeout":
		seconds, err := parseOutboundDACPositiveInt("Idle-Timeout", value)
		if err != nil {
			return db.OutboundDACAttribute{}, err
		}
		return attrWithCanonicalName("Idle-Timeout", strconv.Itoa(seconds)), rfc2865.IdleTimeout_Set(packet, rfc2865.IdleTimeout(seconds))
	case "reply-message":
		return attrWithCanonicalName("Reply-Message", value), rfc2865.ReplyMessage_SetString(packet, value)
	case "class":
		return attrWithCanonicalName("Class", value), rfc2865.Class_SetString(packet, value)
	case "state":
		return attrWithCanonicalName("State", value), rfc2865.State_SetString(packet, value)
	case "tunnel-type":
		if !strings.EqualFold(value, "vlan") && value != "13" {
			return db.OutboundDACAttribute{}, fmt.Errorf("Tunnel-Type only supports VLAN for NAS-0042")
		}
		return attrWithCanonicalName("Tunnel-Type", "VLAN"), rfc2868.TunnelType_Set(packet, 0, rfc3580.TunnelType_Value_VLAN)
	case "tunnel-medium-type":
		if !strings.EqualFold(value, "ieee-802") && value != "6" {
			return db.OutboundDACAttribute{}, fmt.Errorf("Tunnel-Medium-Type only supports IEEE-802 for NAS-0042")
		}
		return attrWithCanonicalName("Tunnel-Medium-Type", "IEEE-802"), rfc2868.TunnelMediumType_Set(packet, 0, rfc2868.TunnelMediumType_Value_IEEE802)
	case "tunnel-private-group-id":
		vlan, err := parseOutboundDACVLAN(value)
		if err != nil {
			return db.OutboundDACAttribute{}, err
		}
		return attrWithCanonicalName("Tunnel-Private-Group-Id", strconv.Itoa(vlan)), rfc2868.TunnelPrivateGroupID_SetString(packet, 0, strconv.Itoa(vlan))
	default:
		return db.OutboundDACAttribute{}, fmt.Errorf("attribute %q is not supported by the NAS-0042 vendor-neutral DAC client", attr.Name)
	}
}

func outboundDACAttributePlan(request OutboundDACRequest, maxAttributes int) ([]OutboundDACAttributePlan, error) {
	packet := layehradius.New(layehradius.CodeCoARequest, []byte("preview"))
	_, attrs, err := buildOutboundDACPacket(request, "preview", maxAttributes)
	if err != nil {
		_ = packet
		return nil, err
	}
	plans := make([]OutboundDACAttributePlan, 0, len(attrs))
	for _, attr := range attrs {
		plans = append(plans, OutboundDACAttributePlan{
			Name:     attr.Name,
			Value:    attr.Value,
			Source:   outboundDACAttributeSource(attr.Name),
			Selector: outboundDACAttributeIsSelector(attr.Name),
		})
	}
	return plans, nil
}

func resolveOutboundDACTarget(ctx context.Context, cfg *config.Config, policy config.DynamicAuthConfig, request OutboundDACRequest) (OutboundDACTarget, string, []string, []string) {
	target := OutboundDACTarget{
		Address:       strings.TrimSpace(request.TargetAddress),
		Port:          firstNonZeroInt(request.TargetPort, policy.OutboundDefaultPort),
		Transport:     strings.ToLower(strings.TrimSpace(firstNonEmptyString(request.TargetTransport, outboundDACDefaultTransport))),
		NASIdentifier: strings.TrimSpace(request.NASIdentifier),
		NASIPAddress:  strings.TrimSpace(request.NASIPAddress),
		ShortName:     strings.TrimSpace(request.ShortName),
		NASType:       strings.ToLower(strings.TrimSpace(request.NASType)),
	}
	if target.Transport == "" {
		target.Transport = outboundDACDefaultTransport
	}
	warnings := []string{}
	blockers := []string{}
	var matched *config.RadiusClient
	clients := configuredRadiusClients(cfg)
	for i := range clients {
		client := clients[i]
		if !outboundDACClientMatches(client, request, target.Address) {
			continue
		}
		matched = &client
		break
	}
	if matched != nil {
		target.KnownClient = true
		target.ResolvedFrom = "radius_client"
		target.Address = firstNonEmptyString(target.Address, strings.TrimSpace(matched.IP))
		target.ShortName = strings.TrimSpace(matched.ShortName)
		target.NASType = firstNonEmptyString(strings.TrimSpace(strings.ToLower(matched.NASType)), target.NASType)
		if target.NASIPAddress == "" && net.ParseIP(strings.TrimSpace(matched.IP)) != nil {
			target.NASIPAddress = strings.TrimSpace(matched.IP)
		}
		if target.NASIdentifier == "" {
			target.NASIdentifier = strings.TrimSpace(matched.ShortName)
		}
		if strings.TrimSpace(request.TargetTransport) == "" {
			target.Transport = firstNonEmptyString(strings.ToLower(strings.TrimSpace(matched.Transport)), outboundDACDefaultTransport)
		}
	}
	if target.Address == "" && strings.TrimSpace(request.NASIPAddress) != "" {
		target.Address = strings.TrimSpace(request.NASIPAddress)
		target.ResolvedFrom = firstNonEmptyString(target.ResolvedFrom, "nas_ip_address")
	}
	if target.Address == "" && strings.TrimSpace(request.NASIdentifier) != "" {
		target.Address = strings.TrimSpace(request.NASIdentifier)
		target.ResolvedFrom = firstNonEmptyString(target.ResolvedFrom, "nas_identifier")
	}
	if target.Address == "" {
		blockers = append(blockers, "target_address, nas_ip_address, nas_identifier, shortname, or resolvable session_id is required")
	}
	if target.Port < 1 || target.Port > 65535 {
		blockers = append(blockers, "target port is outside 1..65535")
	}
	if policy.OutboundRequireKnownClient && !target.KnownClient {
		blockers = append(blockers, "target is not a configured RADIUS client and outbound_require_known_client is enabled")
	}
	if target.Transport == "radsec" {
		blockers = append(blockers, outboundDACUnsupportedRadSec)
	} else if target.Transport != outboundDACDefaultTransport {
		blockers = append(blockers, fmt.Sprintf("transport %q is not supported by NAS-0042", target.Transport))
	}
	secret := ""
	if matched != nil {
		secret = resolveOutboundDACSecret(ctx, cfg, *matched, "radius.clients."+firstNonEmptyString(matched.ShortName, matched.IP)+".secret")
	}
	if secret == "" && cfg != nil {
		secret = resolveOutboundDACGlobalSecret(ctx, cfg)
	}
	target.SecretReady = secret != ""
	if secret == "" {
		blockers = append(blockers, "no RADIUS shared secret or resolvable secret_ref is available for outbound DAC")
	}
	if target.ResolvedFrom == "" {
		target.ResolvedFrom = "request"
	}
	if target.Address != "" && target.Endpoint == "" {
		target.Endpoint = net.JoinHostPort(target.Address, strconv.Itoa(target.Port))
	}
	return target, secret, warnings, blockers
}

func resolveOutboundDACSecret(ctx context.Context, cfg *config.Config, client config.RadiusClient, field string) string {
	if cfg == nil {
		return strings.TrimRight(client.Secret, "\r\n")
	}
	value, err := secrets.ResolveConfiguredSecret(ctx, secrets.NewResolver(secrets.OptionsFromConfig(cfg)), field, client.Secret, client.SecretRef)
	if err != nil {
		return ""
	}
	return strings.TrimRight(value, "\r\n")
}

func resolveOutboundDACGlobalSecret(ctx context.Context, cfg *config.Config) string {
	value, err := secrets.ResolveConfiguredSecret(ctx, secrets.NewResolver(secrets.OptionsFromConfig(cfg)), "radius.secret", cfg.Radius.Secret, cfg.Radius.SecretRef)
	if err != nil {
		return ""
	}
	return strings.TrimRight(value, "\r\n")
}

func enrichOutboundDACRequestFromSession(request OutboundDACRequest) (OutboundDACRequest, []string) {
	if strings.TrimSpace(request.SessionID) == "" {
		return request, nil
	}
	hint, err := db.LookupOutboundDACTargetHint(request.SessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return request, []string{"session_id did not match local session history; using request fields only"}
		}
		return request, []string{"session lookup was unavailable; using request fields only"}
	}
	if request.AcctSessionID == "" {
		request.AcctSessionID = firstNonEmptyString(hint.AcctSessionID, request.SessionID)
	}
	if request.UserName == "" {
		request.UserName = hint.Username
	}
	if request.CallingStationID == "" {
		request.CallingStationID = hint.CallingStationID
	}
	if request.FramedIPAddress == "" {
		request.FramedIPAddress = hint.FramedIPAddress
	}
	if request.NASIPAddress == "" && net.ParseIP(hint.NASIdentifier) != nil {
		request.NASIPAddress = hint.NASIdentifier
	}
	if request.NASIdentifier == "" {
		request.NASIdentifier = hint.NASIdentifier
	}
	return request, nil
}

func outboundDACClientMatches(client config.RadiusClient, request OutboundDACRequest, targetAddress string) bool {
	clientIP := strings.TrimSpace(client.IP)
	shortName := strings.TrimSpace(client.ShortName)
	if targetAddress != "" && strings.EqualFold(clientIP, strings.TrimSpace(targetAddress)) {
		return true
	}
	if request.NASIPAddress != "" && strings.EqualFold(clientIP, strings.TrimSpace(request.NASIPAddress)) {
		return true
	}
	if request.ShortName != "" && strings.EqualFold(shortName, strings.TrimSpace(request.ShortName)) {
		return true
	}
	if request.NASIdentifier != "" && strings.EqualFold(shortName, strings.TrimSpace(request.NASIdentifier)) {
		return true
	}
	return false
}

func classifyOutboundDACResponse(action string, response *layehradius.Packet, err error) (status, failure string, responseCode, errorCause int, errorCauseName, replyMessage string) {
	if err != nil {
		return db.OutboundDACStatusError, err.Error(), 0, 0, "", ""
	}
	if response == nil {
		return db.OutboundDACStatusError, "no response packet", 0, 0, "", ""
	}
	responseCode = int(response.Code)
	replyMessage, _ = rfc2865.ReplyMessage_LookupString(response)
	if cause, causeErr := rfc3576.ErrorCause_Lookup(response); causeErr == nil {
		errorCause = int(cause)
		errorCauseName = cause.String()
	}
	_, ack, nak, codeErr := outboundDACCodes(action)
	if codeErr != nil {
		return db.OutboundDACStatusError, codeErr.Error(), responseCode, errorCause, errorCauseName, replyMessage
	}
	switch response.Code {
	case ack:
		return db.OutboundDACStatusACK, "", responseCode, errorCause, errorCauseName, replyMessage
	case nak:
		if errorCauseName == "" {
			errorCauseName = "unspecified"
		}
		return db.OutboundDACStatusNAK, firstNonEmptyString(replyMessage, errorCauseName, "dynamic authorization rejected"), responseCode, errorCause, errorCauseName, replyMessage
	default:
		return db.OutboundDACStatusError, fmt.Sprintf("unexpected response code %s", response.Code.String()), responseCode, errorCause, errorCauseName, replyMessage
	}
}

func outboundDACCodes(action string) (request, ack, nak layehradius.Code, err error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "disconnect":
		return layehradius.CodeDisconnectRequest, layehradius.CodeDisconnectACK, layehradius.CodeDisconnectNAK, nil
	case "coa":
		return layehradius.CodeCoARequest, layehradius.CodeCoAACK, layehradius.CodeCoANAK, nil
	default:
		return 0, 0, 0, fmt.Errorf("action must be coa or disconnect")
	}
}

func normalizeOutboundDACRequest(request OutboundDACRequest) OutboundDACRequest {
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	switch request.Action {
	case "coa-request", "change-of-authorization":
		request.Action = "coa"
	case "disconnect-request":
		request.Action = "disconnect"
	}
	request.TargetAddress = strings.TrimSpace(request.TargetAddress)
	request.TargetTransport = strings.ToLower(strings.TrimSpace(request.TargetTransport))
	request.NASIdentifier = strings.TrimSpace(request.NASIdentifier)
	request.NASIPAddress = strings.TrimSpace(request.NASIPAddress)
	request.ShortName = strings.TrimSpace(request.ShortName)
	request.NASType = strings.TrimSpace(strings.ToLower(request.NASType))
	request.SessionID = strings.TrimSpace(request.SessionID)
	request.AcctSessionID = strings.TrimSpace(request.AcctSessionID)
	request.UserName = strings.TrimSpace(request.UserName)
	request.CallingStationID = strings.TrimSpace(request.CallingStationID)
	request.FramedIPAddress = strings.TrimSpace(request.FramedIPAddress)
	request.FilterID = strings.TrimSpace(request.FilterID)
	request.RadiusClass = strings.TrimSpace(request.RadiusClass)
	request.State = strings.TrimSpace(request.State)
	request.CorrelationID = strings.TrimSpace(request.CorrelationID)
	for i := range request.Attributes {
		request.Attributes[i].Name = strings.TrimSpace(request.Attributes[i].Name)
		request.Attributes[i].Value = strings.TrimSpace(request.Attributes[i].Value)
	}
	return request
}

func dynamicAuthConfig(cfg *config.Config) config.DynamicAuthConfig {
	if cfg == nil {
		return config.DynamicAuthConfig{}
	}
	return cfg.Radius.DynamicAuth
}

func normalizeOutboundDACAttributeName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
}

func attrWithCanonicalName(name, value string) db.OutboundDACAttribute {
	return db.OutboundDACAttribute{Name: name, Value: value}
}

func parseOutboundDACPositiveInt(name, value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func parseOutboundDACVLAN(value string) (int, error) {
	vlan, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || vlan < 1 || vlan > 4094 {
		return 0, fmt.Errorf("Tunnel-Private-Group-Id VLAN must be between 1 and 4094")
	}
	return vlan, nil
}

func outboundDACAttributeSource(name string) string {
	if outboundDACAttributeIsSelector(name) {
		return "session-selector"
	}
	return "policy"
}

func outboundDACAttributeIsSelector(name string) bool {
	switch normalizeOutboundDACAttributeName(name) {
	case "user-name", "acct-session-id", "calling-station-id", "nas-identifier", "nas-ip-address", "framed-ip-address":
		return true
	default:
		return false
	}
}

func dbAttributesFromPlan(plan []OutboundDACAttributePlan) []db.OutboundDACAttribute {
	attrs := make([]db.OutboundDACAttribute, 0, len(plan))
	for _, attr := range plan {
		attrs = append(attrs, db.OutboundDACAttribute{Name: attr.Name, Value: attr.Value})
	}
	return attrs
}

func attributePlanFingerprint(attrs []OutboundDACAttributePlan) string {
	parts := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		parts = append(parts, attr.Name+"="+attr.Value)
	}
	return strings.Join(parts, ";")
}

func packetWireSHA256(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func newOutboundDACRequestID(request OutboundDACRequest, preview OutboundDACPreview) string {
	correlation := firstNonEmptyString(request.CorrelationID, preview.RequestFingerprint, time.Now().UTC().Format(time.RFC3339Nano))
	return "dac-" + db.FingerprintOutboundDAC(correlation, request.Action, preview.Target.Endpoint, time.Now().UTC().Format(time.RFC3339Nano))[:24]
}

func outboundDACResultMessage(action, status, failure, replyMessage, errorCauseName string) string {
	label := outboundDACActionLabel(action)
	switch status {
	case db.OutboundDACStatusACK:
		return firstNonEmptyString(replyMessage, label+" acknowledged by NAS")
	case db.OutboundDACStatusNAK:
		return firstNonEmptyString(failure, errorCauseName, label+" rejected by NAS")
	case db.OutboundDACStatusError:
		return firstNonEmptyString(failure, label+" failed before ACK")
	default:
		return firstNonEmptyString(failure, label+" status "+status)
	}
}

func outboundDACActionLabel(action string) string {
	if strings.EqualFold(action, "disconnect") {
		return "Disconnect"
	}
	return "CoA"
}

func runtimeStatusForOutboundDAC(status string) string {
	switch status {
	case db.OutboundDACStatusACK:
		return "ok"
	case db.OutboundDACStatusNAK, db.OutboundDACStatusError:
		return "degraded"
	default:
		return status
	}
}

func firstNonZeroInt(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
