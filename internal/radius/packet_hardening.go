package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

const (
	PacketHardeningSchemaVersion    = 1
	PacketHardeningRuntimeComponent = "radius_packet_hardening"

	radiusHeaderBytes               = 20
	radiusMaxPacketBytes            = 4096
	radiusTypeProxyState            = 33
	radiusTypeEAPMessage            = 79
	radiusTypeMessageAuthenticator  = 80
	radiusMessageAuthenticatorBytes = 16
)

type PacketHardeningPolicy struct {
	Enabled                     bool     `json:"enabled"`
	FailClosed                  bool     `json:"fail_closed"`
	RequireKnownSource          bool     `json:"require_known_source"`
	AllowTrailingPadding        bool     `json:"allow_trailing_padding"`
	AllowStatusServer           bool     `json:"allow_status_server"`
	AllowStatusClient           bool     `json:"allow_status_client"`
	RequireMessageAuthenticator string   `json:"require_message_authenticator"`
	TrustedProxyCIDRs           []string `json:"trusted_proxy_cidrs"`
}

type PacketHardeningLimits struct {
	MaxPacketBytes              int  `json:"max_packet_bytes"`
	MaxAttributesPerPacket      int  `json:"max_attributes_per_packet"`
	MaxProxyStateAttributes     int  `json:"max_proxy_state_attributes"`
	MaxProxyStateBytes          int  `json:"max_proxy_state_bytes"`
	ReplayCacheEnabled          bool `json:"replay_cache_enabled"`
	ReplayWindowSeconds         int  `json:"replay_window_seconds"`
	ReplayCacheMaxEntries       int  `json:"replay_cache_max_entries"`
	RateLimitEnabled            bool `json:"rate_limit_enabled"`
	PerClientRateLimitPerSecond int  `json:"per_client_rate_limit_per_second"`
	PerClientBurst              int  `json:"per_client_burst"`
	EventRetentionLimit         int  `json:"event_retention_limit"`
}

type PacketHardeningReport struct {
	SchemaVersion  int                             `json:"schema_version"`
	Status         string                          `json:"status"`
	Message        string                          `json:"message"`
	Policy         PacketHardeningPolicy           `json:"policy"`
	Limits         PacketHardeningLimits           `json:"limits"`
	SupportedCodes []PacketCodeSupport             `json:"supported_codes"`
	SourceTrust    PacketHardeningSourceTrust      `json:"source_trust"`
	FreeRADIUS     PacketHardeningFreeRADIUS       `json:"freeradius"`
	RuntimeStats   db.RadiusPacketHardeningStats   `json:"runtime_stats"`
	RecentEvents   []db.RadiusPacketHardeningEvent `json:"recent_events,omitempty"`
	Warnings       []string                        `json:"warnings,omitempty"`
	RFCs           []string                        `json:"rfcs"`
}

type PacketCodeSupport struct {
	Code      int    `json:"code"`
	Name      string `json:"name"`
	Allowed   bool   `json:"allowed"`
	Direction string `json:"direction"`
}

type PacketHardeningSourceTrust struct {
	RequireKnownSource  bool     `json:"require_known_source"`
	TrustedSources      []string `json:"trusted_sources"`
	ConfiguredClients   int      `json:"configured_clients"`
	ConfiguredUpstreams int      `json:"configured_upstreams"`
}

type PacketHardeningFreeRADIUS struct {
	ClientRequireMessageAuthenticator string `json:"client_require_message_authenticator"`
	GeneratedClientPolicy             bool   `json:"generated_client_policy"`
	StatusServerPolicy                string `json:"status_server_policy"`
	ProxyStateLimitPolicy             string `json:"proxy_state_limit_policy"`
}

type PacketValidationContext struct {
	RemoteAddr   net.Addr
	LocalAddr    net.Addr
	Direction    string
	Now          time.Time
	SharedSecret []byte
}

type PacketValidationResult struct {
	Accepted                    bool                `json:"accepted"`
	Decision                    string              `json:"decision"`
	Reason                      string              `json:"reason"`
	Message                     string              `json:"message"`
	SourceIP                    string              `json:"source_ip"`
	Direction                   string              `json:"direction"`
	PacketCode                  string              `json:"packet_code"`
	Code                        int                 `json:"code"`
	Identifier                  int                 `json:"identifier"`
	PacketLength                int                 `json:"packet_length"`
	AttributeCount              int                 `json:"attribute_count"`
	ProxyStateCount             int                 `json:"proxy_state_count"`
	ProxyStateBytes             int                 `json:"proxy_state_bytes"`
	MessageAuthenticatorPresent bool                `json:"message_authenticator_present"`
	ReplayDetected              bool                `json:"replay_detected"`
	RateLimited                 bool                `json:"rate_limited"`
	Warnings                    []string            `json:"warnings,omitempty"`
	Details                     map[string]any      `json:"details,omitempty"`
	Packet                      *layehradius.Packet `json:"-"`
}

type PacketHardener struct {
	cfg     *config.Config
	policy  PacketHardeningPolicy
	limits  PacketHardeningLimits
	trusted []*net.IPNet

	mu      sync.Mutex
	replays map[string]time.Time
	buckets map[string]*packetTokenBucket
}

type packetTokenBucket struct {
	tokens float64
	seenAt time.Time
}

type parsedRadiusPacket struct {
	code                        byte
	identifier                  byte
	authenticator               [16]byte
	declaredLength              int
	attributes                  []parsedRadiusAttribute
	messageAuthenticatorPresent bool
	messageAuthenticatorOffset  int
	eapMessagePresent           bool
	proxyStateCount             int
	proxyStateBytes             int
}

type parsedRadiusAttribute struct {
	typ    byte
	offset int
	length int
	value  []byte
}

func NewPacketHardener(cfg *config.Config) *PacketHardener {
	policy, limits := effectivePacketHardening(cfg)
	return &PacketHardener{
		cfg:     cfg,
		policy:  policy,
		limits:  limits,
		trusted: trustedSourceNetworks(cfg, policy),
		replays: make(map[string]time.Time),
		buckets: make(map[string]*packetTokenBucket),
	}
}

func BuildPacketHardeningReport(cfg *config.Config) PacketHardeningReport {
	policy, limits := effectivePacketHardening(cfg)
	trustedText := trustedSourceNetworkStrings(cfg, policy)
	stats, _ := db.GetRadiusPacketHardeningStats()
	events, _ := db.ListRadiusPacketHardeningEvents(12)
	report := PacketHardeningReport{
		SchemaVersion:  PacketHardeningSchemaVersion,
		Status:         "ready",
		Message:        "RADIUS packet hardening is active with source trust, malformed-packet validation, Message-Authenticator policy, Proxy-State bounds, replay cache, and per-source rate controls.",
		Policy:         policy,
		Limits:         limits,
		SupportedCodes: supportedPacketCodes(policy),
		SourceTrust: PacketHardeningSourceTrust{
			RequireKnownSource:  policy.RequireKnownSource,
			TrustedSources:      trustedText,
			ConfiguredClients:   len(configuredRadiusClients(cfg)),
			ConfiguredUpstreams: len(configuredRadiusUpstreams(cfg)),
		},
		FreeRADIUS: PacketHardeningFreeRADIUS{
			ClientRequireMessageAuthenticator: FreeRADIUSMessageAuthenticatorMode(policy),
			GeneratedClientPolicy:             policy.Enabled,
			StatusServerPolicy:                statusServerPolicyText(policy),
			ProxyStateLimitPolicy:             fmt.Sprintf("reject over %d Proxy-State attributes or %d bytes", limits.MaxProxyStateAttributes, limits.MaxProxyStateBytes),
		},
		RuntimeStats: stats,
		RecentEvents: events,
		RFCs:         []string{"RFC 2865", "RFC 2869", "RFC 5176", "RFC 5997", "RFC 6614"},
	}
	if !policy.Enabled {
		report.Status = "disabled"
		report.Message = "RADIUS packet hardening is disabled by configuration."
		report.Warnings = append(report.Warnings, "Packet hardening should remain enabled for production NAS/AAA deployments.")
	}
	if policy.RequireKnownSource && len(trustedText) == 0 {
		report.Status = "blocked"
		report.Message = "RADIUS packet hardening requires known sources but no client, upstream, loopback, or trusted CIDR source is available."
		report.Warnings = append(report.Warnings, "Add RADIUS clients or trusted_proxy_cidrs before enabling fail-closed packet intake.")
	}
	if policy.RequireMessageAuthenticator == "never" {
		if report.Status == "ready" {
			report.Status = "degraded"
		}
		report.Warnings = append(report.Warnings, "Message-Authenticator enforcement is disabled.")
	}
	return report
}

func (h *PacketHardener) ValidateRawPacket(ctx PacketValidationContext, raw []byte) PacketValidationResult {
	if h == nil {
		h = NewPacketHardener(nil)
	}
	ctx = normalizePacketValidationContext(ctx)
	result := baseValidationResult(ctx)
	result.PacketLength = len(raw)
	if !h.policy.Enabled {
		return acceptResult(result, "disabled", "Packet hardening is disabled.")
	}
	if denied := h.checkSourceAndRate(ctx, &result); denied != nil {
		return *denied
	}
	parsed, errResult := h.parseRaw(raw, &result)
	if errResult != nil {
		return *errResult
	}
	result.Code = int(parsed.code)
	result.PacketCode = packetCodeName(int(parsed.code))
	result.Identifier = int(parsed.identifier)
	result.AttributeCount = len(parsed.attributes)
	result.ProxyStateCount = parsed.proxyStateCount
	result.ProxyStateBytes = parsed.proxyStateBytes
	result.MessageAuthenticatorPresent = parsed.messageAuthenticatorPresent
	if denied := h.validatePacketShape(ctx, parsed, &result, true, raw[:parsed.declaredLength]); denied != nil {
		return *denied
	}
	packet, err := layehradius.Parse(raw[:parsed.declaredLength], ctx.SharedSecret)
	if err != nil {
		return rejectResult(result, "malformed_packet", err.Error())
	}
	result.Packet = packet
	return acceptResult(result, "accepted", "Packet accepted by hardening policy.")
}

func (h *PacketHardener) ValidatePacket(ctx PacketValidationContext, packet *layehradius.Packet) PacketValidationResult {
	if h == nil {
		h = NewPacketHardener(nil)
	}
	ctx = normalizePacketValidationContext(ctx)
	result := baseValidationResult(ctx)
	if packet == nil {
		return rejectResult(result, "nil_packet", "RADIUS packet is required.")
	}
	result.Packet = packet
	result.Code = int(packet.Code)
	result.PacketCode = packetCodeName(int(packet.Code))
	result.Identifier = int(packet.Identifier)
	result.AttributeCount = len(packet.Attributes)
	if !h.policy.Enabled {
		return acceptResult(result, "disabled", "Packet hardening is disabled.")
	}
	if result.AttributeCount > h.limits.MaxAttributesPerPacket {
		return rejectResult(result, "too_many_attributes", "RADIUS packet exceeds the configured attribute count limit.")
	}
	if denied := h.checkSourceAndRate(ctx, &result); denied != nil {
		return *denied
	}
	parsed := parsedRadiusPacket{
		code:           byte(packet.Code),
		identifier:     packet.Identifier,
		authenticator:  packet.Authenticator,
		declaredLength: radiusHeaderBytes,
	}
	for _, attr := range packet.Attributes {
		if attr == nil {
			return rejectResult(result, "malformed_attribute", "Packet contains a nil attribute.")
		}
		parsed.declaredLength += 2 + len(attr.Attribute)
		switch int(attr.Type) {
		case radiusTypeMessageAuthenticator:
			parsed.messageAuthenticatorPresent = true
			if len(attr.Attribute) != radiusMessageAuthenticatorBytes {
				return rejectResult(result, "malformed_message_authenticator", "Message-Authenticator must contain 16 octets.")
			}
		case radiusTypeEAPMessage:
			parsed.eapMessagePresent = true
		case radiusTypeProxyState:
			parsed.proxyStateCount++
			parsed.proxyStateBytes += len(attr.Attribute)
		}
	}
	result.PacketLength = parsed.declaredLength
	if result.PacketLength > h.limits.MaxPacketBytes {
		return rejectResult(result, "oversized_packet", "RADIUS packet exceeds the configured maximum packet size.")
	}
	result.ProxyStateCount = parsed.proxyStateCount
	result.ProxyStateBytes = parsed.proxyStateBytes
	result.MessageAuthenticatorPresent = parsed.messageAuthenticatorPresent
	if denied := h.validatePacketShape(ctx, &parsed, &result, false, nil); denied != nil {
		return *denied
	}
	return acceptResult(result, "accepted", "Packet accepted by hardening policy.")
}

func (h *PacketHardener) checkSourceAndRate(ctx PacketValidationContext, result *PacketValidationResult) *PacketValidationResult {
	if h.policy.RequireKnownSource && !h.sourceAllowed(ctx.RemoteAddr) {
		RecordDynamicNASDiscovery(h.cfg, ctx.RemoteAddr, ctx.Direction, "unknown_source")
		rejected := rejectResult(*result, "unknown_source", "Packet source is not a configured RADIUS client, upstream server, loopback, or trusted CIDR.")
		return &rejected
	}
	if h.policy.RequireKnownSource {
		RecordDynamicNASHeartbeat(h.cfg, ctx.RemoteAddr, ctx.Direction)
	}
	if h.limits.RateLimitEnabled && !h.allowRate(ctx) {
		result.RateLimited = true
		rejected := rejectResult(*result, "rate_limited", "Packet source exceeded the configured per-client rate limit.")
		rejected.RateLimited = true
		return &rejected
	}
	return nil
}

func (h *PacketHardener) parseRaw(raw []byte, result *PacketValidationResult) (*parsedRadiusPacket, *PacketValidationResult) {
	if len(raw) < radiusHeaderBytes {
		rejected := rejectResult(*result, "short_packet", "RADIUS packet is shorter than the 20-octet header.")
		return nil, &rejected
	}
	if len(raw) > h.limits.MaxPacketBytes {
		rejected := rejectResult(*result, "oversized_packet", "RADIUS packet exceeds the configured maximum packet size.")
		return nil, &rejected
	}
	declared := int(binary.BigEndian.Uint16(raw[2:4]))
	if declared < radiusHeaderBytes || declared > radiusMaxPacketBytes || declared > len(raw) {
		rejected := rejectResult(*result, "invalid_packet_length", "RADIUS length field is outside valid bounds.")
		return nil, &rejected
	}
	if declared != len(raw) && !h.policy.AllowTrailingPadding {
		rejected := rejectResult(*result, "invalid_packet_length", "RADIUS datagram length must exactly match the packet length field.")
		return nil, &rejected
	}

	parsed := &parsedRadiusPacket{
		code:           raw[0],
		identifier:     raw[1],
		declaredLength: declared,
	}
	copy(parsed.authenticator[:], raw[4:20])
	for offset := radiusHeaderBytes; offset < declared; {
		if offset+2 > declared {
			rejected := rejectResult(*result, "malformed_attribute", "RADIUS attribute header is truncated.")
			return nil, &rejected
		}
		attrLen := int(raw[offset+1])
		if attrLen < 2 || offset+attrLen > declared {
			rejected := rejectResult(*result, "malformed_attribute", "RADIUS attribute length is invalid.")
			return nil, &rejected
		}
		attr := parsedRadiusAttribute{
			typ:    raw[offset],
			offset: offset,
			length: attrLen,
			value:  raw[offset+2 : offset+attrLen],
		}
		if len(parsed.attributes)+1 > h.limits.MaxAttributesPerPacket {
			rejected := rejectResult(*result, "too_many_attributes", "RADIUS packet exceeds the configured attribute count limit.")
			return nil, &rejected
		}
		switch int(attr.typ) {
		case radiusTypeMessageAuthenticator:
			parsed.messageAuthenticatorPresent = true
			parsed.messageAuthenticatorOffset = offset + 2
			if len(attr.value) != radiusMessageAuthenticatorBytes {
				rejected := rejectResult(*result, "malformed_message_authenticator", "Message-Authenticator must contain 16 octets.")
				return nil, &rejected
			}
		case radiusTypeEAPMessage:
			parsed.eapMessagePresent = true
		case radiusTypeProxyState:
			parsed.proxyStateCount++
			parsed.proxyStateBytes += len(attr.value)
		}
		parsed.attributes = append(parsed.attributes, attr)
		offset += attrLen
	}
	return parsed, nil
}

func (h *PacketHardener) validatePacketShape(ctx PacketValidationContext, parsed *parsedRadiusPacket, result *PacketValidationResult, canVerifyMessageAuthenticator bool, wire []byte) *PacketValidationResult {
	if !packetCodeAllowed(int(parsed.code), h.policy) {
		rejected := rejectResult(*result, "unsupported_code", "RADIUS packet code is not allowed by packet hardening policy.")
		return &rejected
	}
	if parsed.proxyStateCount > h.limits.MaxProxyStateAttributes {
		rejected := rejectResult(*result, "proxy_state_count_exceeded", "Proxy-State attribute count exceeds the configured limit.")
		return &rejected
	}
	if parsed.proxyStateBytes > h.limits.MaxProxyStateBytes {
		rejected := rejectResult(*result, "proxy_state_bytes_exceeded", "Proxy-State bytes exceed the configured limit.")
		return &rejected
	}
	maRequired := messageAuthenticatorRequired(h.policy, int(parsed.code), parsed.eapMessagePresent)
	if maRequired && !parsed.messageAuthenticatorPresent {
		rejected := rejectResult(*result, "missing_message_authenticator", "Message-Authenticator is required for this RADIUS packet.")
		return &rejected
	}
	if parsed.messageAuthenticatorPresent && canVerifyMessageAuthenticator && len(ctx.SharedSecret) > 0 && !verifyMessageAuthenticator(wire, parsed.messageAuthenticatorOffset, ctx.SharedSecret) {
		rejected := rejectResult(*result, "invalid_message_authenticator", "Message-Authenticator HMAC-MD5 validation failed.")
		return &rejected
	}
	if h.limits.ReplayCacheEnabled && h.replaySeen(ctx, parsed) {
		result.ReplayDetected = true
		rejected := rejectResult(*result, "replay_detected", "Packet replay detected within the configured replay window.")
		rejected.ReplayDetected = true
		return &rejected
	}
	return nil
}

func (h *PacketHardener) sourceAllowed(addr net.Addr) bool {
	if !h.policy.RequireKnownSource {
		return true
	}
	ip := remoteIP(addr)
	if ip == nil {
		return false
	}
	for _, network := range h.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *PacketHardener) allowRate(ctx PacketValidationContext) bool {
	source := remoteHost(ctx.RemoteAddr)
	if source == "" {
		source = "unknown"
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rate := float64(h.limits.PerClientRateLimitPerSecond)
	burst := float64(h.limits.PerClientBurst)
	if rate <= 0 || burst <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	bucket := h.buckets[source]
	if bucket == nil {
		h.buckets[source] = &packetTokenBucket{tokens: burst - 1, seenAt: now}
		return true
	}
	elapsed := now.Sub(bucket.seenAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	bucket.tokens += elapsed * rate
	if bucket.tokens > burst {
		bucket.tokens = burst
	}
	bucket.seenAt = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (h *PacketHardener) replaySeen(ctx PacketValidationContext, parsed *parsedRadiusPacket) bool {
	if parsed == nil {
		return false
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	window := time.Duration(h.limits.ReplayWindowSeconds) * time.Second
	key := fmt.Sprintf("%s|%d|%d|%s", remoteHost(ctx.RemoteAddr), parsed.code, parsed.identifier, hex.EncodeToString(parsed.authenticator[:]))
	h.mu.Lock()
	defer h.mu.Unlock()
	for existingKey, expiresAt := range h.replays {
		if !expiresAt.After(now) || len(h.replays) > h.limits.ReplayCacheMaxEntries {
			delete(h.replays, existingKey)
		}
	}
	if expiresAt, ok := h.replays[key]; ok && expiresAt.After(now) {
		return true
	}
	h.replays[key] = now.Add(window)
	return false
}

func SourceAllowedByPacketHardening(cfg *config.Config, remoteAddr net.Addr, direction string) bool {
	_ = direction
	policy, _ := effectivePacketHardening(cfg)
	if !policy.Enabled || !policy.RequireKnownSource {
		return true
	}
	return NewPacketHardener(cfg).sourceAllowed(remoteAddr)
}

func RecordPacketHardeningDecision(cfg *config.Config, result PacketValidationResult) {
	if strings.TrimSpace(result.Decision) == "" {
		if result.Accepted {
			result.Decision = "accepted"
		} else {
			result.Decision = "rejected"
		}
	}
	now := time.Now().UTC()
	retention := 0
	if cfg != nil {
		_, limits := effectivePacketHardening(cfg)
		retention = limits.EventRetentionLimit
	}
	_ = db.RecordRadiusPacketHardeningEvent(db.RadiusPacketHardeningEvent{
		ObservedAt:                  now.Format(time.RFC3339),
		SourceIP:                    result.SourceIP,
		Direction:                   result.Direction,
		PacketCode:                  result.PacketCode,
		PacketIdentifier:            result.Identifier,
		Decision:                    result.Decision,
		Reason:                      result.Reason,
		Message:                     result.Message,
		PacketLength:                result.PacketLength,
		AttributeCount:              result.AttributeCount,
		ProxyStateCount:             result.ProxyStateCount,
		ProxyStateBytes:             result.ProxyStateBytes,
		MessageAuthenticatorPresent: result.MessageAuthenticatorPresent,
		ReplayDetected:              result.ReplayDetected,
		RateLimited:                 result.RateLimited,
		Details:                     result.Details,
	}, retention)
	status := "ok"
	if !result.Accepted {
		status = "degraded"
	}
	_ = db.UpsertRuntimeStatus(PacketHardeningRuntimeComponent, status, result.Message, map[string]any{
		"decision":        result.Decision,
		"reason":          result.Reason,
		"source_ip":       result.SourceIP,
		"direction":       result.Direction,
		"packet_code":     result.PacketCode,
		"replay_detected": result.ReplayDetected,
		"rate_limited":    result.RateLimited,
		"observed_at":     now.Format(time.RFC3339),
	})
}

func FreeRADIUSMessageAuthenticatorMode(policy PacketHardeningPolicy) string {
	if !policy.Enabled {
		return "no"
	}
	switch strings.ToLower(strings.TrimSpace(policy.RequireMessageAuthenticator)) {
	case "always":
		return "yes"
	case "never":
		return "no"
	default:
		return "auto"
	}
}

func effectivePacketHardening(cfg *config.Config) (PacketHardeningPolicy, PacketHardeningLimits) {
	raw := config.RadiusPacketHardeningConfig{}
	unset := true
	if cfg != nil {
		raw = cfg.Radius.PacketHardening
		unset = packetHardeningConfigUnset(raw)
	}
	enabled := raw.Enabled
	if unset {
		enabled = true
	}
	failClosed := raw.FailClosed || unset
	requireKnown := raw.RequireKnownSource || unset
	allowStatus := raw.AllowStatusServer || unset
	mode := strings.ToLower(strings.TrimSpace(raw.RequireMessageAuthenticator))
	if mode == "" {
		mode = "auto"
	}
	policy := PacketHardeningPolicy{
		Enabled:                     enabled,
		FailClosed:                  failClosed,
		RequireKnownSource:          requireKnown,
		AllowTrailingPadding:        raw.AllowTrailingPadding,
		AllowStatusServer:           allowStatus,
		AllowStatusClient:           raw.AllowStatusClient,
		RequireMessageAuthenticator: mode,
		TrustedProxyCIDRs:           append([]string(nil), raw.TrustedProxyCIDRs...),
	}
	limits := PacketHardeningLimits{
		MaxPacketBytes:              defaultInt(raw.MaxPacketBytes, radiusMaxPacketBytes),
		MaxAttributesPerPacket:      defaultInt(raw.MaxAttributesPerPacket, 128),
		MaxProxyStateAttributes:     raw.MaxProxyStateAttributes,
		MaxProxyStateBytes:          defaultInt(raw.MaxProxyStateBytes, 1024),
		ReplayCacheEnabled:          raw.ReplayCacheEnabled || unset,
		ReplayWindowSeconds:         defaultInt(raw.ReplayWindowSeconds, 30),
		ReplayCacheMaxEntries:       defaultInt(raw.ReplayCacheMaxEntries, 16384),
		RateLimitEnabled:            raw.RateLimitEnabled || unset,
		PerClientRateLimitPerSecond: defaultInt(raw.PerClientRateLimitPerSecond, 250),
		PerClientBurst:              defaultInt(raw.PerClientBurst, 500),
		EventRetentionLimit:         defaultInt(raw.EventRetentionLimit, 6000),
	}
	if limits.MaxPacketBytes > radiusMaxPacketBytes {
		limits.MaxPacketBytes = radiusMaxPacketBytes
	}
	if unset {
		limits.MaxProxyStateAttributes = 8
	}
	return policy, limits
}

func packetHardeningConfigUnset(raw config.RadiusPacketHardeningConfig) bool {
	return !raw.Enabled && !raw.FailClosed && !raw.RequireKnownSource && !raw.AllowTrailingPadding &&
		!raw.AllowStatusServer && !raw.AllowStatusClient && strings.TrimSpace(raw.RequireMessageAuthenticator) == "" &&
		raw.MaxPacketBytes == 0 && raw.MaxAttributesPerPacket == 0 && raw.MaxProxyStateAttributes == 0 &&
		raw.MaxProxyStateBytes == 0 && !raw.ReplayCacheEnabled && raw.ReplayWindowSeconds == 0 &&
		raw.ReplayCacheMaxEntries == 0 && !raw.RateLimitEnabled && raw.PerClientRateLimitPerSecond == 0 &&
		raw.PerClientBurst == 0 && len(raw.TrustedProxyCIDRs) == 0 && raw.EventRetentionLimit == 0
}

func defaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func verifyMessageAuthenticator(wire []byte, valueOffset int, secret []byte) bool {
	if valueOffset <= 0 || valueOffset+radiusMessageAuthenticatorBytes > len(wire) || len(secret) == 0 {
		return false
	}
	expectedWire := append([]byte(nil), wire...)
	received := append([]byte(nil), expectedWire[valueOffset:valueOffset+radiusMessageAuthenticatorBytes]...)
	for i := 0; i < radiusMessageAuthenticatorBytes; i++ {
		expectedWire[valueOffset+i] = 0
	}
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(expectedWire)
	return hmac.Equal(received, mac.Sum(nil))
}

func packetCodeAllowed(code int, policy PacketHardeningPolicy) bool {
	switch layehradius.Code(code) {
	case layehradius.CodeAccessRequest, layehradius.CodeAccountingRequest,
		layehradius.CodeDisconnectRequest, layehradius.CodeCoARequest:
		return true
	case layehradius.CodeStatusServer:
		return policy.AllowStatusServer
	case layehradius.CodeStatusClient:
		return policy.AllowStatusClient
	default:
		return false
	}
}

func messageAuthenticatorRequired(policy PacketHardeningPolicy, code int, hasEAP bool) bool {
	switch policy.RequireMessageAuthenticator {
	case "always":
		return true
	case "never":
		return false
	default:
		switch layehradius.Code(code) {
		case layehradius.CodeAccessRequest:
			return hasEAP
		case layehradius.CodeStatusServer, layehradius.CodeCoARequest, layehradius.CodeDisconnectRequest:
			return true
		default:
			return false
		}
	}
}

func supportedPacketCodes(policy PacketHardeningPolicy) []PacketCodeSupport {
	codes := []struct {
		code      layehradius.Code
		direction string
	}{
		{layehradius.CodeAccessRequest, "authentication"},
		{layehradius.CodeAccountingRequest, "accounting"},
		{layehradius.CodeStatusServer, "status"},
		{layehradius.CodeStatusClient, "status"},
		{layehradius.CodeDisconnectRequest, "dynamic_authorization"},
		{layehradius.CodeCoARequest, "dynamic_authorization"},
	}
	out := make([]PacketCodeSupport, 0, len(codes))
	for _, item := range codes {
		out = append(out, PacketCodeSupport{
			Code:      int(item.code),
			Name:      packetCodeName(int(item.code)),
			Allowed:   packetCodeAllowed(int(item.code), policy),
			Direction: item.direction,
		})
	}
	return out
}

func trustedSourceNetworks(cfg *config.Config, policy PacketHardeningPolicy) []*net.IPNet {
	var networks []*net.IPNet
	add := func(value string) {
		if network := parseTrustedSource(value); network != nil {
			networks = append(networks, network)
		}
	}
	add("127.0.0.1")
	add("::1")
	for _, client := range configuredRadiusClients(cfg) {
		add(client.IP)
	}
	for _, server := range configuredRadiusUpstreams(cfg) {
		add(server.Address)
	}
	for _, cidr := range policy.TrustedProxyCIDRs {
		add(cidr)
	}
	return networks
}

func trustedSourceNetworkStrings(cfg *config.Config, policy PacketHardeningPolicy) []string {
	networks := trustedSourceNetworks(cfg, policy)
	out := make([]string, 0, len(networks))
	seen := map[string]struct{}{}
	for _, network := range networks {
		value := network.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func parseTrustedSource(value string) *net.IPNet {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil
	}
	return network
}

func configuredRadiusClients(cfg *config.Config) []config.RadiusClient {
	if db.DB != nil {
		clients, err := clientDefinitionsFromDB()
		if err == nil {
			return clients
		}
	}
	if cfg == nil {
		return nil
	}
	return cfg.Radius.Clients
}

func configuredRadiusUpstreams(cfg *config.Config) []config.RadiusHomeServer {
	if cfg == nil || !cfg.Radius.Upstream.Enabled {
		return nil
	}
	return cfg.Radius.Upstream.Servers
}

func normalizePacketValidationContext(ctx PacketValidationContext) PacketValidationContext {
	if ctx.Now.IsZero() {
		ctx.Now = time.Now().UTC()
	}
	ctx.Direction = strings.TrimSpace(ctx.Direction)
	if ctx.Direction == "" {
		ctx.Direction = "radius"
	}
	return ctx
}

func baseValidationResult(ctx PacketValidationContext) PacketValidationResult {
	return PacketValidationResult{
		Accepted:  false,
		Decision:  "rejected",
		Reason:    "not_evaluated",
		SourceIP:  remoteHost(ctx.RemoteAddr),
		Direction: ctx.Direction,
	}
}

func acceptResult(result PacketValidationResult, reason, message string) PacketValidationResult {
	result.Accepted = true
	result.Decision = "accepted"
	result.Reason = reason
	result.Message = message
	return result
}

func rejectResult(result PacketValidationResult, reason, message string) PacketValidationResult {
	result.Accepted = false
	result.Decision = "rejected"
	result.Reason = reason
	result.Message = message
	return result
}

func packetCodeName(code int) string {
	switch layehradius.Code(code) {
	case layehradius.CodeAccessRequest:
		return "Access-Request"
	case layehradius.CodeAccountingRequest:
		return "Accounting-Request"
	case layehradius.CodeStatusServer:
		return "Status-Server"
	case layehradius.CodeStatusClient:
		return "Status-Client"
	case layehradius.CodeDisconnectRequest:
		return "Disconnect-Request"
	case layehradius.CodeCoARequest:
		return "CoA-Request"
	default:
		return fmt.Sprintf("Code-%d", code)
	}
}

func remoteIP(addr net.Addr) net.IP {
	host := remoteHost(addr)
	if host == "" {
		return nil
	}
	return net.ParseIP(host)
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(addr.String())
}

func statusServerPolicyText(policy PacketHardeningPolicy) string {
	if policy.AllowStatusServer {
		return "allowed with Message-Authenticator in auto/always mode"
	}
	return "rejected"
}

func IsMessageAuthenticatorValidForTest(wire []byte, offset int, secret []byte) bool {
	return verifyMessageAuthenticator(wire, offset, secret)
}
