package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	OpaquePassThroughSchemaVersion = 1

	OpaquePassThroughDirectionAny                = "any"
	OpaquePassThroughDirectionInboundRequest     = "inbound_request"
	OpaquePassThroughDirectionOutboundReply      = "outbound_reply"
	OpaquePassThroughDirectionAccountingRequest  = "accounting_request"
	OpaquePassThroughDirectionAccountingResponse = "accounting_response"
	OpaquePassThroughDirectionCoARequest         = "coa_request"
	OpaquePassThroughDirectionCoAResponse        = "coa_response"
	OpaquePassThroughDirectionDisconnectRequest  = "disconnect_request"
	OpaquePassThroughDirectionDisconnectResponse = "disconnect_response"
	OpaquePassThroughDirectionProxyRequest       = "proxy_request"
	OpaquePassThroughDirectionProxyResponse      = "proxy_response"

	OpaquePassThroughKindStandard        = "standard"
	OpaquePassThroughKindVendor          = "vendor"
	OpaquePassThroughKindVendorAttribute = "vendor_attribute"

	OpaqueRegistryStateUnregistered = "unregistered"
	OpaqueRegistryStateMissing      = "registered_missing"
	OpaqueRegistryStatePartial      = "registered_partial"
	OpaqueRegistryStateImplemented  = "registered_implemented"

	defaultOpaquePassThroughMaxAttributes = 32
	defaultOpaquePassThroughMaxAttribute  = maxVendorPayloadLen
	defaultOpaquePassThroughMaxTotal      = 2048
)

type OpaquePassThroughPolicy struct {
	SchemaVersion int                     `json:"schema_version"`
	Enabled       bool                    `json:"enabled"`
	DefaultAction string                  `json:"default_action"`
	Limits        OpaquePassThroughLimits `json:"limits"`
	Rules         []OpaquePassThroughRule `json:"rules"`
	Notes         []string                `json:"notes,omitempty"`
}

type OpaquePassThroughLimits struct {
	MaxRADIUSPacketBytes    int `json:"max_radius_packet_bytes"`
	MaxAttributesPerPacket  int `json:"max_attributes_per_packet"`
	MaxAttributeBytes       int `json:"max_attribute_bytes"`
	MaxTotalBytesPerPacket  int `json:"max_total_bytes_per_packet"`
	MaxVendorSpecificBytes  int `json:"max_vendor_specific_bytes"`
	MaxStandardValueBytes   int `json:"max_standard_value_bytes"`
	MaxReplayRecordsPerCall int `json:"max_replay_records_per_call"`
}

type OpaquePassThroughRule struct {
	Direction         string `json:"direction"`
	Kind              string `json:"kind"`
	VendorID          uint32 `json:"vendor_id,omitempty"`
	Type              uint32 `json:"type,omitempty"`
	MaxAttributeBytes int    `json:"max_attribute_bytes,omitempty"`
	AllowKnown        bool   `json:"allow_known,omitempty"`
	Description       string `json:"description,omitempty"`
}

type OpaqueAttributeRecord struct {
	Kind          string   `json:"kind"`
	Direction     string   `json:"direction"`
	PacketCode    int      `json:"packet_code"`
	Type          uint32   `json:"type,omitempty"`
	VendorID      uint32   `json:"vendor_id,omitempty"`
	VendorType    uint32   `json:"vendor_type,omitempty"`
	RegistryState string   `json:"registry_state"`
	Attributes    []string `json:"attributes,omitempty"`
	RawBytes      int      `json:"raw_bytes"`
	ValueBytes    int      `json:"value_bytes"`
	RawSHA256     string   `json:"raw_sha256"`
	OuterIndex    int      `json:"outer_index,omitempty"`
	InnerIndex    int      `json:"inner_index,omitempty"`
	Reason        string   `json:"reason"`
	Raw           []byte   `json:"-"`
}

type OpaqueAttributeDrop struct {
	Kind          string `json:"kind"`
	Direction     string `json:"direction"`
	PacketCode    int    `json:"packet_code"`
	Type          uint32 `json:"type,omitempty"`
	VendorID      uint32 `json:"vendor_id,omitempty"`
	VendorType    uint32 `json:"vendor_type,omitempty"`
	RegistryState string `json:"registry_state,omitempty"`
	RawBytes      int    `json:"raw_bytes"`
	Reason        string `json:"reason"`
}

type OpaquePassThroughResult struct {
	SchemaVersion int                     `json:"schema_version"`
	Direction     string                  `json:"direction"`
	Accepted      []OpaqueAttributeRecord `json:"accepted"`
	Dropped       []OpaqueAttributeDrop   `json:"dropped"`
	Errors        []string                `json:"errors,omitempty"`
	Summary       OpaquePassThroughRun    `json:"summary"`
}

type OpaquePassThroughRun struct {
	AcceptedCount int `json:"accepted_count"`
	DroppedCount  int `json:"dropped_count"`
	ErrorCount    int `json:"error_count"`
	AcceptedBytes int `json:"accepted_bytes"`
}

type OpaquePassThroughReport struct {
	SchemaVersion    int                      `json:"schema_version"`
	ReleaseProfileID string                   `json:"release_profile_id"`
	SourceRelease    string                   `json:"source_release"`
	SourceSHA256     string                   `json:"source_sha256"`
	Status           string                   `json:"status"`
	Policy           OpaquePassThroughPolicy  `json:"policy"`
	Summary          OpaquePassThroughSummary `json:"summary"`
	Limits           OpaquePassThroughLimits  `json:"limits"`
	SensitiveTypes   []OpaqueStandardTypeDeny `json:"sensitive_types"`
	Notes            []string                 `json:"notes,omitempty"`
}

type OpaquePassThroughSummary struct {
	SourceAttributeCount          int  `json:"source_attribute_count"`
	RuntimeDecoderCount           int  `json:"runtime_decoder_count"`
	RuleCount                     int  `json:"rule_count"`
	AllowedStandardTypeCount      int  `json:"allowed_standard_type_count"`
	AllowedVendorCount            int  `json:"allowed_vendor_count"`
	AllowedVendorAttributeCount   int  `json:"allowed_vendor_attribute_count"`
	RegistryMissingAttributeCount int  `json:"registry_missing_attribute_count"`
	RegistryPartialAttributeCount int  `json:"registry_partial_attribute_count"`
	DefaultActionDrop             bool `json:"default_action_drop"`
}

type OpaqueStandardTypeDeny struct {
	Type   uint32 `json:"type"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func DefaultOpaquePassThroughPolicy() OpaquePassThroughPolicy {
	return OpaquePassThroughPolicy{
		SchemaVersion: OpaquePassThroughSchemaVersion,
		Enabled:       true,
		DefaultAction: "drop",
		Limits: OpaquePassThroughLimits{
			MaxRADIUSPacketBytes:    layehradius.MaxPacketLength,
			MaxAttributesPerPacket:  defaultOpaquePassThroughMaxAttributes,
			MaxAttributeBytes:       defaultOpaquePassThroughMaxAttribute,
			MaxTotalBytesPerPacket:  defaultOpaquePassThroughMaxTotal,
			MaxVendorSpecificBytes:  maxVendorPayloadLen,
			MaxStandardValueBytes:   253,
			MaxReplayRecordsPerCall: defaultOpaquePassThroughMaxAttributes,
		},
		Notes: []string{
			"Unknown attributes are preserved only when an explicit pass-through rule allows them.",
			"Sensitive credential, EAP, and integrity attributes are never handled as opaque payloads.",
		},
	}
}

func OpaquePassThroughPolicyFromConfig(cfg *config.Config) (OpaquePassThroughPolicy, error) {
	policy := DefaultOpaquePassThroughPolicy()
	if cfg == nil {
		return policy, policy.Validate()
	}
	raw := cfg.Radius.Vendor.OpaquePassThrough
	policy.Enabled = raw.Enabled
	policy.Limits.MaxAttributesPerPacket = firstPositive(raw.MaxAttributesPerPacket, policy.Limits.MaxAttributesPerPacket)
	policy.Limits.MaxAttributeBytes = firstPositive(raw.MaxAttributeBytes, policy.Limits.MaxAttributeBytes)
	policy.Limits.MaxTotalBytesPerPacket = firstPositive(raw.MaxTotalBytesPerPacket, policy.Limits.MaxTotalBytesPerPacket)
	policy.Limits.MaxReplayRecordsPerCall = policy.Limits.MaxAttributesPerPacket
	for _, rawRule := range raw.Rules {
		policy.Rules = append(policy.Rules, OpaquePassThroughRule{
			Direction:         rawRule.Direction,
			Kind:              rawRule.Kind,
			VendorID:          uint32(rawRule.VendorID),
			Type:              uint32(rawRule.Type),
			MaxAttributeBytes: rawRule.MaxAttributeBytes,
			AllowKnown:        rawRule.AllowKnown,
			Description:       rawRule.Description,
		})
	}
	return policy, policy.Validate()
}

func (p *OpaquePassThroughPolicy) Validate() error {
	if p == nil {
		return fmt.Errorf("opaque pass-through policy is required")
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = OpaquePassThroughSchemaVersion
	}
	if p.SchemaVersion != OpaquePassThroughSchemaVersion {
		return fmt.Errorf("opaque pass-through schema %d is unsupported", p.SchemaVersion)
	}
	p.DefaultAction = strings.ToLower(strings.TrimSpace(p.DefaultAction))
	if p.DefaultAction == "" {
		p.DefaultAction = "drop"
	}
	if p.DefaultAction != "drop" {
		return fmt.Errorf("opaque pass-through default_action must be drop")
	}
	if p.Limits.MaxRADIUSPacketBytes == 0 {
		p.Limits.MaxRADIUSPacketBytes = layehradius.MaxPacketLength
	}
	if p.Limits.MaxVendorSpecificBytes == 0 {
		p.Limits.MaxVendorSpecificBytes = maxVendorPayloadLen
	}
	if p.Limits.MaxStandardValueBytes == 0 {
		p.Limits.MaxStandardValueBytes = 253
	}
	if p.Limits.MaxAttributesPerPacket < 1 || p.Limits.MaxAttributesPerPacket > 128 {
		return fmt.Errorf("opaque pass-through max attributes per packet must be between 1 and 128")
	}
	if p.Limits.MaxAttributeBytes < 1 || p.Limits.MaxAttributeBytes > maxVendorPayloadLen {
		return fmt.Errorf("opaque pass-through max attribute bytes must be between 1 and %d", maxVendorPayloadLen)
	}
	if p.Limits.MaxTotalBytesPerPacket < p.Limits.MaxAttributeBytes || p.Limits.MaxTotalBytesPerPacket > layehradius.MaxPacketLength {
		return fmt.Errorf("opaque pass-through max total bytes must be between max_attribute_bytes and %d", layehradius.MaxPacketLength)
	}
	if p.Limits.MaxReplayRecordsPerCall == 0 {
		p.Limits.MaxReplayRecordsPerCall = p.Limits.MaxAttributesPerPacket
	}
	if p.Limits.MaxReplayRecordsPerCall < 1 || p.Limits.MaxReplayRecordsPerCall > 128 {
		return fmt.Errorf("opaque pass-through max replay records must be between 1 and 128")
	}
	for idx := range p.Rules {
		p.Rules[idx].Direction = normalizeOpaqueDirection(p.Rules[idx].Direction)
		p.Rules[idx].Kind = normalizeOpaqueKind(p.Rules[idx].Kind)
		if err := p.Rules[idx].Validate(p.Limits); err != nil {
			return fmt.Errorf("opaque pass-through rule[%d]: %w", idx, err)
		}
	}
	return nil
}

func (r OpaquePassThroughRule) Validate(limits OpaquePassThroughLimits) error {
	if !validOpaqueDirection(r.Direction) {
		return fmt.Errorf("direction %q is invalid", r.Direction)
	}
	if !validOpaqueKind(r.Kind) {
		return fmt.Errorf("kind %q is invalid", r.Kind)
	}
	if r.MaxAttributeBytes < 0 || r.MaxAttributeBytes > limits.MaxAttributeBytes {
		return fmt.Errorf("max_attribute_bytes must be between 0 and the policy max")
	}
	if strings.ContainsAny(r.Description, "\r\n\x00") || len(r.Description) > 240 {
		return fmt.Errorf("description contains invalid characters or is too long")
	}
	switch r.Kind {
	case OpaquePassThroughKindStandard:
		if r.VendorID != 0 {
			return fmt.Errorf("standard rules must not set vendor_id")
		}
		if r.Type < 1 || r.Type > 255 {
			return fmt.Errorf("standard type must be between 1 and 255")
		}
		if denied, ok := opaqueDeniedStandardType(r.Type); ok {
			return fmt.Errorf("standard type %d (%s) cannot be opaque pass-through: %s", r.Type, denied.Name, denied.Reason)
		}
	case OpaquePassThroughKindVendor:
		if r.VendorID == 0 {
			return fmt.Errorf("vendor rules require vendor_id")
		}
		if r.Type != 0 {
			return fmt.Errorf("vendor rules must not set type")
		}
	case OpaquePassThroughKindVendorAttribute:
		if r.VendorID == 0 {
			return fmt.Errorf("vendor_attribute rules require vendor_id")
		}
		if r.Type == 0 {
			return fmt.Errorf("vendor_attribute rules require type")
		}
	}
	return nil
}

func CollectOpaqueAttributes(packet *layehradius.Packet, direction string, policy OpaquePassThroughPolicy, registry *productconfigs.AttributeRegistry) OpaquePassThroughResult {
	direction = normalizeOpaqueDirection(direction)
	result := OpaquePassThroughResult{SchemaVersion: OpaquePassThroughSchemaVersion, Direction: direction}
	if err := policy.Validate(); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.finish()
		return result
	}
	if !policy.Enabled || packet == nil {
		result.finish()
		return result
	}
	if registry == nil {
		registry = productconfigs.MustBuiltInAttributeRegistry()
	}

	decoded, decodeErrs := DecodeVendorAttributes(packet, VSADecodeOptions{})
	for _, err := range decodeErrs {
		result.Errors = append(result.Errors, err.Error())
	}
	for _, avp := range packet.Attributes {
		if avp.Type == rfc2865.VendorSpecific_Type {
			continue
		}
		record := OpaqueAttributeRecord{
			Kind:          OpaquePassThroughKindStandard,
			Direction:     direction,
			PacketCode:    int(packet.Code),
			Type:          uint32(avp.Type),
			RegistryState: OpaqueRegistryStateUnregistered,
			Raw:           cloneAttribute(avp.Attribute),
			RawBytes:      len(avp.Attribute),
			ValueBytes:    len(avp.Attribute),
		}
		result.acceptOrDrop(record, policy, nil)
	}
	for _, attr := range decoded {
		if attr.Grouped {
			continue
		}
		state, names := opaqueRegistryState(registry, attr.VendorID, attr.Type)
		record := OpaqueAttributeRecord{
			Kind:          OpaquePassThroughKindVendorAttribute,
			Direction:     direction,
			PacketCode:    int(packet.Code),
			VendorID:      attr.VendorID,
			VendorType:    attr.Type,
			RegistryState: state,
			Attributes:    names,
			Raw:           cloneAttribute(attr.Raw),
			RawBytes:      len(attr.Raw),
			ValueBytes:    len(attr.Value),
			OuterIndex:    attr.OuterIndex,
			InnerIndex:    attr.InnerIndex,
		}
		result.acceptOrDrop(record, policy, registry)
	}
	result.finish()
	return result
}

func ApplyOpaqueAttributes(packet *layehradius.Packet, records []OpaqueAttributeRecord, policy OpaquePassThroughPolicy) error {
	if packet == nil {
		return fmt.Errorf("packet is required")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if !policy.Enabled || len(records) == 0 {
		return nil
	}
	if len(records) > policy.Limits.MaxReplayRecordsPerCall {
		return fmt.Errorf("opaque pass-through replay has %d records, exceeds %d", len(records), policy.Limits.MaxReplayRecordsPerCall)
	}
	total := 0
	for idx, record := range records {
		if len(record.Raw) == 0 {
			return fmt.Errorf("opaque pass-through record[%d] has empty raw payload", idx)
		}
		rule, ok := policy.ruleFor(record)
		if !ok {
			return fmt.Errorf("opaque pass-through record[%d] is not allowed by policy", idx)
		}
		maxBytes := ruleMaxAttributeBytes(rule, policy.Limits)
		if len(record.Raw) > maxBytes {
			return fmt.Errorf("opaque pass-through record[%d] exceeds %d bytes", idx, maxBytes)
		}
		total += len(record.Raw)
		if total > policy.Limits.MaxTotalBytesPerPacket {
			return fmt.Errorf("opaque pass-through replay exceeds %d total bytes", policy.Limits.MaxTotalBytesPerPacket)
		}
		switch normalizeOpaqueKind(record.Kind) {
		case OpaquePassThroughKindStandard:
			if denied, ok := opaqueDeniedStandardType(record.Type); ok {
				return fmt.Errorf("opaque pass-through record[%d] standard type %d (%s) is denied: %s", idx, record.Type, denied.Name, denied.Reason)
			}
			if record.Type < 1 || record.Type > 255 {
				return fmt.Errorf("opaque pass-through record[%d] standard type is outside 1..255", idx)
			}
			packet.Add(layehradius.Type(record.Type), cloneAttribute(record.Raw))
		case OpaquePassThroughKindVendorAttribute:
			if record.VendorID == 0 || record.VendorType == 0 {
				return fmt.Errorf("opaque pass-through record[%d] requires vendor_id and vendor_type", idx)
			}
			vsa, err := layehradius.NewVendorSpecific(record.VendorID, cloneAttribute(record.Raw))
			if err != nil {
				return fmt.Errorf("opaque pass-through record[%d] vendor payload: %w", idx, err)
			}
			packet.Add(rfc2865.VendorSpecific_Type, vsa)
		default:
			return fmt.Errorf("opaque pass-through record[%d] kind %q is unsupported", idx, record.Kind)
		}
	}
	return nil
}

func BuildOpaquePassThroughReport(registry *productconfigs.AttributeRegistry, cfg *config.Config) OpaquePassThroughReport {
	if registry == nil {
		registry = productconfigs.MustBuiltInAttributeRegistry()
	}
	policy, err := OpaquePassThroughPolicyFromConfig(cfg)
	status := "ready"
	notes := []string{
		"Software pass-through readiness is separate from real proxy, FreeRADIUS, and vendor hardware certification.",
		"Default action is drop; operators must explicitly allow each standard type, vendor, or vendor attribute.",
	}
	if err != nil {
		status = "blocked"
		notes = append(notes, err.Error())
	}
	summary := OpaquePassThroughSummary{
		SourceAttributeCount: registry.SourceAttributeCount,
		RuntimeDecoderCount:  len(registry.RuntimeMappings()),
		RuleCount:            len(policy.Rules),
		DefaultActionDrop:    strings.EqualFold(policy.DefaultAction, "drop"),
	}
	for _, entry := range registry.Entries {
		switch strings.ToLower(strings.TrimSpace(entry.DictionaryStatus)) {
		case "missing":
			summary.RegistryMissingAttributeCount++
		case "partial":
			summary.RegistryPartialAttributeCount++
		}
	}
	vendors := map[uint32]struct{}{}
	vendorAttrs := map[string]struct{}{}
	standard := map[uint32]struct{}{}
	for _, rule := range policy.Rules {
		switch normalizeOpaqueKind(rule.Kind) {
		case OpaquePassThroughKindStandard:
			standard[rule.Type] = struct{}{}
		case OpaquePassThroughKindVendor:
			vendors[rule.VendorID] = struct{}{}
		case OpaquePassThroughKindVendorAttribute:
			vendorAttrs[fmt.Sprintf("%d/%d", rule.VendorID, rule.Type)] = struct{}{}
		}
	}
	summary.AllowedStandardTypeCount = len(standard)
	summary.AllowedVendorCount = len(vendors)
	summary.AllowedVendorAttributeCount = len(vendorAttrs)
	return OpaquePassThroughReport{
		SchemaVersion:    OpaquePassThroughSchemaVersion,
		ReleaseProfileID: registry.ReleaseProfileID,
		SourceRelease:    registry.SourceRelease,
		SourceSHA256:     registry.SourceSHA256,
		Status:           status,
		Policy:           policy,
		Summary:          summary,
		Limits:           policy.Limits,
		SensitiveTypes:   OpaqueDeniedStandardTypes(),
		Notes:            notes,
	}
}

func (r *OpaquePassThroughResult) acceptOrDrop(record OpaqueAttributeRecord, policy OpaquePassThroughPolicy, registry *productconfigs.AttributeRegistry) {
	if record.Kind == OpaquePassThroughKindStandard {
		if denied, ok := opaqueDeniedStandardType(record.Type); ok {
			r.drop(record, "sensitive_standard_type:"+denied.Name)
			return
		}
	}
	rule, ok := policy.ruleFor(record)
	if !ok {
		r.drop(record, "default_drop")
		return
	}
	if record.RegistryState == OpaqueRegistryStateImplemented && !rule.AllowKnown {
		r.drop(record, "native_mapping_exists")
		return
	}
	maxBytes := ruleMaxAttributeBytes(rule, policy.Limits)
	if record.RawBytes > maxBytes {
		r.drop(record, fmt.Sprintf("attribute_too_large:%d>%d", record.RawBytes, maxBytes))
		return
	}
	if len(r.Accepted) >= policy.Limits.MaxAttributesPerPacket {
		r.drop(record, "max_attributes_exceeded")
		return
	}
	if r.Summary.AcceptedBytes+record.RawBytes > policy.Limits.MaxTotalBytesPerPacket {
		r.drop(record, "max_total_bytes_exceeded")
		return
	}
	record.RawSHA256 = sha256Hex(record.Raw)
	record.Reason = "policy_allow"
	r.Accepted = append(r.Accepted, record)
	r.Summary.AcceptedBytes += record.RawBytes
}

func (r *OpaquePassThroughResult) drop(record OpaqueAttributeRecord, reason string) {
	r.Dropped = append(r.Dropped, OpaqueAttributeDrop{
		Kind:          record.Kind,
		Direction:     record.Direction,
		PacketCode:    record.PacketCode,
		Type:          record.Type,
		VendorID:      record.VendorID,
		VendorType:    record.VendorType,
		RegistryState: record.RegistryState,
		RawBytes:      record.RawBytes,
		Reason:        reason,
	})
}

func (r *OpaquePassThroughResult) finish() {
	r.Summary.AcceptedCount = len(r.Accepted)
	r.Summary.DroppedCount = len(r.Dropped)
	r.Summary.ErrorCount = len(r.Errors)
}

func (p OpaquePassThroughPolicy) ruleFor(record OpaqueAttributeRecord) (OpaquePassThroughRule, bool) {
	direction := normalizeOpaqueDirection(record.Direction)
	recordKind := normalizeOpaqueKind(record.Kind)
	for _, rule := range p.Rules {
		rule.Direction = normalizeOpaqueDirection(rule.Direction)
		rule.Kind = normalizeOpaqueKind(rule.Kind)
		if rule.Direction != OpaquePassThroughDirectionAny && rule.Direction != direction {
			continue
		}
		switch rule.Kind {
		case OpaquePassThroughKindStandard:
			if recordKind == OpaquePassThroughKindStandard && rule.Type == record.Type {
				return rule, true
			}
		case OpaquePassThroughKindVendor:
			if recordKind == OpaquePassThroughKindVendorAttribute && rule.VendorID == record.VendorID {
				return rule, true
			}
		case OpaquePassThroughKindVendorAttribute:
			if recordKind == OpaquePassThroughKindVendorAttribute && rule.VendorID == record.VendorID && rule.Type == record.VendorType {
				return rule, true
			}
		}
	}
	return OpaquePassThroughRule{}, false
}

func OpaqueDeniedStandardTypes() []OpaqueStandardTypeDeny {
	out := []OpaqueStandardTypeDeny{
		{Type: 2, Name: "User-Password", Reason: "encrypted credential material must be owned by the authenticator"},
		{Type: 3, Name: "CHAP-Password", Reason: "challenge-response credential material must be owned by the authenticator"},
		{Type: 26, Name: "Vendor-Specific", Reason: "vendor payloads must use vendor or vendor_attribute rules"},
		{Type: 60, Name: "CHAP-Challenge", Reason: "challenge material is part of authentication state"},
		{Type: 69, Name: "Tunnel-Password", Reason: "hidden tunnel secrets must not be forwarded opaquely"},
		{Type: 79, Name: "EAP-Message", Reason: "EAP fragments require protocol-aware handling"},
		{Type: 80, Name: "Message-Authenticator", Reason: "packet integrity attributes must be rebuilt by transport logic"},
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func opaqueDeniedStandardType(typ uint32) (OpaqueStandardTypeDeny, bool) {
	for _, denied := range OpaqueDeniedStandardTypes() {
		if denied.Type == typ {
			return denied, true
		}
	}
	return OpaqueStandardTypeDeny{}, false
}

func opaqueRegistryState(registry *productconfigs.AttributeRegistry, vendorID, typ uint32) (string, []string) {
	entries := registry.LookupWire(vendorID, typ)
	if len(entries) == 0 {
		return OpaqueRegistryStateUnregistered, nil
	}
	names := make([]string, 0, len(entries))
	state := OpaqueRegistryStateMissing
	for _, entry := range entries {
		if entry.Attribute != "" {
			names = append(names, entry.Attribute)
		}
		switch strings.ToLower(strings.TrimSpace(entry.DictionaryStatus)) {
		case "implemented":
			state = OpaqueRegistryStateImplemented
		case "partial":
			if state != OpaqueRegistryStateImplemented {
				state = OpaqueRegistryStatePartial
			}
		}
	}
	sort.Strings(names)
	return state, uniqueOpaqueStrings(names)
}

func ruleMaxAttributeBytes(rule OpaquePassThroughRule, limits OpaquePassThroughLimits) int {
	if rule.MaxAttributeBytes > 0 {
		return rule.MaxAttributeBytes
	}
	return limits.MaxAttributeBytes
}

func normalizeOpaqueDirection(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return OpaquePassThroughDirectionAny
	}
	return value
}

func validOpaqueDirection(value string) bool {
	switch normalizeOpaqueDirection(value) {
	case OpaquePassThroughDirectionAny, OpaquePassThroughDirectionInboundRequest, OpaquePassThroughDirectionOutboundReply,
		OpaquePassThroughDirectionAccountingRequest, OpaquePassThroughDirectionAccountingResponse,
		OpaquePassThroughDirectionCoARequest, OpaquePassThroughDirectionCoAResponse,
		OpaquePassThroughDirectionDisconnectRequest, OpaquePassThroughDirectionDisconnectResponse,
		OpaquePassThroughDirectionProxyRequest, OpaquePassThroughDirectionProxyResponse:
		return true
	default:
		return false
	}
}

func normalizeOpaqueKind(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "vsa" {
		return OpaquePassThroughKindVendorAttribute
	}
	return value
}

func validOpaqueKind(value string) bool {
	switch normalizeOpaqueKind(value) {
	case OpaquePassThroughKindStandard, OpaquePassThroughKindVendor, OpaquePassThroughKindVendorAttribute:
		return true
	default:
		return false
	}
}

func firstPositive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func cloneAttribute(value []byte) layehradius.Attribute {
	out := make(layehradius.Attribute, len(value))
	copy(out, value)
	return out
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func uniqueOpaqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
