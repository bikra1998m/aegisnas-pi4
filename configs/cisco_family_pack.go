package configs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	CiscoFamilyPackSchemaVersion          = 1
	CiscoFamilyPackFeatureID              = "NAS-0061"
	CiscoFamilyPackExpectedAttributeCount = 922

	CiscoFamilySoftwareCertified = "software_certified"
	CiscoFamilyExternalRequired  = "external_certification_required"
)

type CiscoFamilyPackReport struct {
	SchemaVersion                 int                          `json:"schema_version"`
	FeatureID                     string                       `json:"feature_id"`
	ReleaseProfileID              string                       `json:"release_profile_id"`
	SourceRelease                 string                       `json:"source_release"`
	SourceSHA256                  string                       `json:"source_sha256"`
	SourceFileCount               int                          `json:"source_file_count"`
	SourceAttributeCount          int                          `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                       `json:"release_certification_checklist"`
	Summary                       CiscoFamilyPackSummary       `json:"summary"`
	VendorSummaries               []CiscoFamilyVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []CiscoFamilyCapabilityCount `json:"capability_summaries"`
	Grammar                       []CiscoFamilyGrammarRecord   `json:"grammar"`
	Records                       []CiscoFamilyAttributeRecord `json:"records"`
	Notes                         []string                     `json:"notes,omitempty"`
}

type CiscoFamilyPackSummary struct {
	VendorCount                        int     `json:"vendor_count"`
	AttributeCount                     int     `json:"attribute_count"`
	NativeSemanticMappings             int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings           int     `json:"typed_passthrough_mappings"`
	GrammarRuleCount                   int     `json:"grammar_rule_count"`
	SoftwareCertifiedMappings          int     `json:"software_certified_mappings"`
	SoftwareBlockedMappings            int     `json:"software_blocked_mappings"`
	ReadyForExternalValidationMappings int     `json:"ready_for_external_validation_mappings"`
	ExternalRequiredMappings           int     `json:"external_required_mappings"`
	SoftwareCompletionPercent          float64 `json:"software_completion_percent"`
	Fingerprint                        string  `json:"fingerprint"`
}

type CiscoFamilyVendorSummary struct {
	Vendor                    string  `json:"vendor"`
	PEN                       uint32  `json:"pen"`
	PackKey                   string  `json:"pack_key,omitempty"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type CiscoFamilyCapabilityCount struct {
	Capability                string  `json:"capability"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type CiscoFamilyGrammarRecord struct {
	Key           string   `json:"key"`
	Label         string   `json:"label"`
	Kind          string   `json:"kind"`
	Semantic      string   `json:"semantic"`
	Examples      []string `json:"examples"`
	ParserState   string   `json:"parser_state"`
	CompilerState string   `json:"compiler_state"`
	InboundState  string   `json:"inbound_state"`
	OutboundState string   `json:"outbound_state"`
	ExternalState string   `json:"external_state"`
	ReleaseScope  string   `json:"release_scope"`
}

type CiscoFamilyAttributeRecord struct {
	ID                         string             `json:"id"`
	Vendor                     string             `json:"vendor"`
	PEN                        uint32             `json:"pen"`
	PackKey                    string             `json:"pack_key,omitempty"`
	Attribute                  string             `json:"attribute"`
	Number                     uint32             `json:"number,omitempty"`
	OID                        string             `json:"oid,omitempty"`
	WireKey                    string             `json:"wire_key"`
	WireType                   string             `json:"wire_type"`
	WireCodec                  AttributeWireCodec `json:"wire_codec"`
	DictionaryStatus           string             `json:"dictionary_status"`
	Capability                 string             `json:"capability"`
	Semantic                   string             `json:"semantic,omitempty"`
	Directions                 []string           `json:"directions"`
	Functionality              string             `json:"functionality,omitempty"`
	ImplementationClass        string             `json:"implementation_class"`
	PacketProcessing           string             `json:"packet_processing"`
	PolicyEngine               string             `json:"policy_engine"`
	Enforcement                string             `json:"enforcement"`
	Storage                    string             `json:"storage"`
	APIUI                      string             `json:"api_ui"`
	Monitoring                 string             `json:"monitoring"`
	SoftwareState              string             `json:"software_state"`
	ExternalValidationRequired bool               `json:"external_validation_required"`
	ReadyForExternalValidation bool               `json:"ready_for_external_validation"`
	ClaimState                 string             `json:"claim_state"`
	Notes                      []string           `json:"notes,omitempty"`
}

func BuildCiscoFamilyPackReport() (CiscoFamilyPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return CiscoFamilyPackReport{}, err
	}
	records := make([]CiscoFamilyAttributeRecord, 0, CiscoFamilyPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isCiscoFamilyVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildCiscoFamilyAttributeRecord(entry))
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Vendor != records[j].Vendor {
			return records[i].Vendor < records[j].Vendor
		}
		if records[i].PEN != records[j].PEN {
			return records[i].PEN < records[j].PEN
		}
		if records[i].Number != records[j].Number {
			return records[i].Number < records[j].Number
		}
		return records[i].Attribute < records[j].Attribute
	})
	report := CiscoFamilyPackReport{
		SchemaVersion:                 CiscoFamilyPackSchemaVersion,
		FeatureID:                     CiscoFamilyPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0061-release-certification-checklist.md",
		Grammar:                       ciscoFamilyGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0061 covers all Cisco-family rows in the pinned FreeRADIUS 3.2.8 audit: Cisco, Airespace, Cisco-ASA, Cisco-BBSM, Cisco-VPN3000, Cisco-VPN5000, Starent, and Meraki.",
			"Software certification covers typed dictionary metadata, generic VSA packet safety, Cisco-AVPair parser/compiler handling, neutral semantic normalization when known, API/UI visibility, durable evidence, and observability readiness.",
			"Rows without a neutral runtime semantic are software-certified as typed pass-through or typed evidence, not as hardware-certified behavior.",
			"Real Cisco, Meraki, WLC, ASA/VPN, and Starent appliance acceptance remains in the NAS-0061 release certification checklist.",
		},
	}
	report.Summary = summarizeCiscoFamilyPack(records, report.Grammar)
	report.Summary.Fingerprint = ciscoFamilyPackFingerprint(records, report.Grammar, report.SourceSHA256)
	report.VendorSummaries = summarizeCiscoFamilyVendors(records)
	report.CapabilitySummaries = summarizeCiscoFamilyCapabilities(records)
	return report, nil
}

func ValidateCiscoFamilyPackReport(report CiscoFamilyPackReport) error {
	if report.SchemaVersion != CiscoFamilyPackSchemaVersion {
		return fmt.Errorf("Cisco family pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != CiscoFamilyPackFeatureID {
		return fmt.Errorf("Cisco family pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Cisco family pack release profile and source hash are required")
	}
	if len(report.Records) != CiscoFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Cisco family pack has %d records, expected %d", len(report.Records), CiscoFamilyPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != CiscoFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Cisco family pack summary has %d attributes, expected %d", report.Summary.AttributeCount, CiscoFamilyPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != CiscoFamilyPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Cisco family pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != CiscoFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Cisco family pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Cisco family pack fingerprint is required")
	}
	if len(report.Grammar) < 12 {
		return fmt.Errorf("Cisco family pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Cisco AVPair grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != CiscoFamilyExternalRequired {
			return fmt.Errorf("Cisco AVPair grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Cisco family record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Cisco family record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != CiscoFamilySoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Cisco family record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Cisco family record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildCiscoFamilyAttributeRecord(entry AttributeRegistryEntry) CiscoFamilyAttributeRecord {
	capability := ciscoFamilyCapability(entry)
	class := "typed_passthrough"
	if entry.DictionaryStatus != "missing" && strings.TrimSpace(entry.Semantic) != "" {
		class = "native_semantic_mapping"
	}
	if entry.Attribute == "Cisco-AVPair" {
		class = "avpair_parse_compile"
	}
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferCiscoFamilyDirections(entry)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = ciscoFamilySemantic(capability)
	}
	return CiscoFamilyAttributeRecord{
		ID:                         ciscoFamilyRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, ciscoFamilyDefaultPack(entry.Vendor)),
		Attribute:                  entry.Attribute,
		Number:                     entry.Number,
		OID:                        entry.OID,
		WireKey:                    entry.WireKey,
		WireType:                   entry.WireType,
		WireCodec:                  entry.WireCodec,
		DictionaryStatus:           entry.DictionaryStatus,
		Capability:                 capability,
		Semantic:                   semantic,
		Directions:                 directions,
		Functionality:              firstNonEmptyPackKey(entry.Functionality, ciscoFamilyFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           ciscoFamilyPacketProcessing(entry, class),
		PolicyEngine:               ciscoFamilyPolicyState(class, capability),
		Enforcement:                ciscoFamilyEnforcementState(class, capability),
		Storage:                    "bounded_raw_evidence_and_normalized_metadata",
		APIUI:                      "pack_report_history_preview_and_support_bundle",
		Monitoring:                 "vendor_family_counters_and_fingerprint",
		SoftwareState:              CiscoFamilySoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      ciscoFamilyRecordNotes(class),
	}
}

func ciscoFamilyGrammarRecords() []CiscoFamilyGrammarRecord {
	rows := []CiscoFamilyGrammarRecord{
		{"dynamic_acl_in", "Inbound downloadable ACL", "dynamic_acl", VendorSemanticDynamicACL, []string{"ip:inacl#1=permit tcp any any eq 443"}, "", "", "", "", "", ""},
		{"dynamic_acl_out", "Outbound downloadable ACL", "dynamic_acl", VendorSemanticDynamicACL, []string{"ip:outacl#1=deny udp any 10.0.0.0/24 eq 53"}, "", "", "", "", "", ""},
		{"trustsec_sgt", "TrustSec security group tag", "trustsec_sgt", VendorSemanticPolicyTag, []string{"cts:security-group-tag=42"}, "", "", "", "", "", ""},
		{"vpn_group_policy", "VPN group policy", "vpn_policy", VendorSemanticPolicyTag, []string{"vpn:group-policy=employees"}, "", "", "", "", "", ""},
		{"vpn_split_tunnel", "VPN split tunnel list", "vpn_policy", VendorSemanticPolicyTag, []string{"vpn:split-tunnel-list=corp-split"}, "", "", "", "", "", ""},
		{"voice_traffic_class", "Voice traffic class", "voice_policy", VendorSemanticDeviceGroup, []string{"device-traffic-class=voice"}, "", "", "", "", "", ""},
		{"command_privilege", "Shell privilege level", "command_authorization", VendorSemanticRole, []string{"shell:priv-lvl=15"}, "", "", "", "", "", ""},
		{"command_roles", "Shell role set", "command_authorization", VendorSemanticRole, []string{"shell:roles=network-admin"}, "", "", "", "", "", ""},
		{"posture_status", "Posture status", "posture", VendorSemanticDevicePosture, []string{"posture:status=compliant"}, "", "", "", "", "", ""},
		{"audit_session_id", "ISE audit session identifier", "posture", VendorSemanticAccountingIdentity, []string{"audit-session-id=0A000001000000000001"}, "", "", "", "", "", ""},
		{"ipv4_route", "IPv4 framed route", "route", VendorSemanticRoute, []string{"ip:route=10.80.0.0/16 192.0.2.1 10"}, "", "", "", "", "", ""},
		{"ipv6_route", "IPv6 framed route", "route", VendorSemanticRoute, []string{"ipv6:route=2001:db8:80::/48 2001:db8::1 10"}, "", "", "", "", "", ""},
		{"vrf", "VRF selection", "vrf", VendorSemanticVRF, []string{"ip:vrf-id=tenant-a"}, "", "", "", "", "", ""},
		{"address_pool", "IPv4 address pool", "address_pool", VendorSemanticAddressPool, []string{"ip:addr-pool=corp-pool"}, "", "", "", "", "", ""},
		{"delegated_ipv6", "Delegated IPv6 prefix", "address_pool", VendorSemanticDelegatedIPv6Prefix, []string{"ipv6:delegated-prefix=2001:db8:100::/56"}, "", "", "", "", "", ""},
		{"translation", "Translation policy and port block", "translation", VendorSemanticTranslationPolicy, []string{"translation-port-block=10000-10511"}, "", "", "", "", "", ""},
		{"charging", "Subscriber charging profile", "charging", VendorSemanticAccountingCounters, []string{"subscriber:charging-profile=prepaid-gold"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = CiscoFamilyExternalRequired
		rows[index].ReleaseScope = "Device and firmware acceptance is tracked in docs/nas-0061-release-certification-checklist.md."
	}
	return rows
}

func summarizeCiscoFamilyPack(records []CiscoFamilyAttributeRecord, grammar []CiscoFamilyGrammarRecord) CiscoFamilyPackSummary {
	summary := CiscoFamilyPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar)}
	vendors := map[string]struct{}{}
	for _, record := range records {
		vendors[record.Vendor+"\x00"+strconv.FormatUint(uint64(record.PEN), 10)] = struct{}{}
		if record.ImplementationClass == "native_semantic_mapping" || record.ImplementationClass == "avpair_parse_compile" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CiscoFamilySoftwareCertified {
			summary.SoftwareCertifiedMappings++
			summary.ReadyForExternalValidationMappings++
		} else {
			summary.SoftwareBlockedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	summary.VendorCount = len(vendors)
	summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
	return summary
}

func summarizeCiscoFamilyVendors(records []CiscoFamilyAttributeRecord) []CiscoFamilyVendorSummary {
	byKey := map[string]*CiscoFamilyVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &CiscoFamilyVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
			byKey[key] = summary
		}
		summary.AttributeCount++
		if record.ImplementationClass == "native_semantic_mapping" || record.ImplementationClass == "avpair_parse_compile" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CiscoFamilySoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]CiscoFamilyVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeCiscoFamilyCapabilities(records []CiscoFamilyAttributeRecord) []CiscoFamilyCapabilityCount {
	byCapability := map[string]*CiscoFamilyCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &CiscoFamilyCapabilityCount{Capability: record.Capability}
			byCapability[record.Capability] = summary
		}
		summary.AttributeCount++
		if record.ImplementationClass == "native_semantic_mapping" || record.ImplementationClass == "avpair_parse_compile" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CiscoFamilySoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]CiscoFamilyCapabilityCount, 0, len(byCapability))
	for _, summary := range byCapability {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AttributeCount != out[j].AttributeCount {
			return out[i].AttributeCount > out[j].AttributeCount
		}
		return out[i].Capability < out[j].Capability
	})
	return out
}

func isCiscoFamilyVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "cisco", "airespace", "cisco-asa", "cisco-bbsm", "cisco-vpn3000", "cisco-vpn5000", "starent", "meraki":
		return true
	default:
		return false
	}
}

func ciscoFamilyCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(entry.Vendor)
	name := strings.ToLower(entry.Attribute)
	switch {
	case vendor == "meraki":
		return "controller_and_cloud_accounting_context"
	case vendor == "airespace":
		return "enterprise_wireless_wlc_policy"
	case vendor == "starent":
		return ciscoFamilyStarentCapability(name)
	case strings.Contains(vendor, "vpn") || vendor == "cisco-asa":
		return ciscoFamilyVPNCapability(name)
	case strings.Contains(name, "avpair"):
		return "cisco_avpair_grammar"
	case containsAnyCiscoToken(name, "in-acl", "out-acl", "filter", "acl", "firewall"):
		return "acl_and_firewall_enforcement"
	case containsAnyCiscoToken(name, "qos", "policy-up", "policy-down", "data-rate", "xmit-rate"):
		return "bandwidth_and_qos_policy"
	case containsAnyCiscoToken(name, "route", "pool", "ip-address", "ipv6", "dhcp", "relay", "nat"):
		return "ip_addressing_routing_and_subscriber_context"
	case containsAnyCiscoToken(name, "h323", "sip", "fax", "call", "voice", "dsp", "media", "gw-"):
		return "voice_and_collaboration_accounting"
	case containsAnyCiscoToken(name, "command", "control-info", "account-info", "service-info", "subscriber", "priv"):
		return "command_and_subscriber_service_authorization"
	default:
		return "generic_cisco_vendor_context"
	}
}

func ciscoFamilyStarentCapability(name string) string {
	switch {
	case containsAnyCiscoToken(name, "charging", "credit", "prepaid", "quota", "dcca", "acct", "octets", "packets", "gigawords"):
		return "mobile_core_charging_and_accounting"
	case containsAnyCiscoToken(name, "qos", "policy", "rulebase", "traffic", "bandwidth"):
		return "mobile_core_policy_and_qos"
	case containsAnyCiscoToken(name, "ip", "ipv6", "pool", "nat", "dns", "route", "apn"):
		return "mobile_core_addressing_and_apn"
	case containsAnyCiscoToken(name, "imsi", "msisdn", "ggsn", "pdg", "wsg", "cscf", "sip", "sdp", "rohc"):
		return "mobile_core_subscriber_and_bearer_context"
	default:
		return "mobile_core_vendor_context"
	}
}

func ciscoFamilyVPNCapability(name string) string {
	switch {
	case containsAnyCiscoToken(name, "group-policy", "tunnel", "split", "ipsec", "webvpn", "acl"):
		return "remote_access_vpn_policy"
	case containsAnyCiscoToken(name, "dns", "wins", "address", "pool"):
		return "remote_access_vpn_addressing"
	case containsAnyCiscoToken(name, "simultaneous", "idle", "time", "logins"):
		return "remote_access_vpn_session_limits"
	case containsAnyCiscoToken(name, "privilege", "roles", "command"):
		return "remote_access_admin_authorization"
	default:
		return "remote_access_vpn_context"
	}
}

func ciscoFamilySemantic(capability string) string {
	switch capability {
	case "acl_and_firewall_enforcement", "enterprise_wireless_wlc_policy", "remote_access_vpn_policy":
		return VendorSemanticACL
	case "bandwidth_and_qos_policy", "mobile_core_policy_and_qos":
		return VendorSemanticBandwidthProfile
	case "ip_addressing_routing_and_subscriber_context", "remote_access_vpn_addressing", "mobile_core_addressing_and_apn":
		return VendorSemanticAddressPool
	case "voice_and_collaboration_accounting", "mobile_core_charging_and_accounting":
		return VendorSemanticAccountingCounters
	case "command_and_subscriber_service_authorization", "remote_access_admin_authorization":
		return VendorSemanticRole
	case "controller_and_cloud_accounting_context", "mobile_core_subscriber_and_bearer_context":
		return VendorSemanticAccountingIdentity
	default:
		return VendorSemanticPolicyTag
	}
}

func inferCiscoFamilyDirections(entry AttributeRegistryEntry) []string {
	name := strings.ToLower(entry.Attribute)
	if containsAnyCiscoToken(name, "acct", "octets", "packets", "session", "h323", "sip", "fax", "call", "imsi", "msisdn") {
		return []string{"accounting", "inbound"}
	}
	if containsAnyCiscoToken(name, "policy", "acl", "pool", "route", "qos", "vpn", "tunnel", "privilege") {
		return []string{"inbound", "outbound_reply"}
	}
	return []string{"inbound"}
}

func ciscoFamilyDefaultPack(vendor string) string {
	switch strings.ToLower(vendor) {
	case "cisco":
		return VendorPackCisco
	case "airespace":
		return VendorPackAirespace
	case "starent":
		return VendorPackStarent
	case "meraki":
		return VendorPackMeraki
	default:
		return "cisco-family"
	}
}

func ciscoFamilyFunctionality(entry AttributeRegistryEntry, capability string) string {
	return fmt.Sprintf("%s carries %s in Cisco-family RADIUS packets; AegisNAS stores bounded evidence and normalizes known semantics where the vendor grammar is defined.", entry.Attribute, strings.ReplaceAll(capability, "_", " "))
}

func ciscoFamilyPacketProcessing(entry AttributeRegistryEntry, class string) string {
	if entry.Attribute == "Cisco-AVPair" {
		return "cisco_avpair_parser_classifier_and_safe_unknown_preservation"
	}
	if class == "native_semantic_mapping" {
		return "native_runtime_decoder"
	}
	return "generic_vsa_codec_with_bounded_raw_evidence"
}

func ciscoFamilyPolicyState(class, capability string) string {
	if class == "typed_passthrough" {
		return "typed_evidence_only_until_policy_binding"
	}
	switch {
	case strings.Contains(capability, "acl"):
		return "acl_ast_and_vendor_compiler"
	case strings.Contains(capability, "qos"):
		return "qos_and_rate_policy"
	case strings.Contains(capability, "route") || strings.Contains(capability, "address"):
		return "route_address_translation_policy"
	default:
		return "neutral_policy_semantics"
	}
}

func ciscoFamilyEnforcementState(class, capability string) string {
	if class == "typed_passthrough" {
		return "safe_visibility_no_silent_enforcement_claim"
	}
	if strings.Contains(capability, "mobile_core") {
		return "subscriber_and_translation_enforcement_surfaces"
	}
	return "radius_reply_and_coa_enforcement_surfaces"
}

func ciscoFamilyRecordNotes(class string) []string {
	if class == "typed_passthrough" {
		return []string{"Software-ready typed pass-through does not claim native device behavior until release certification evidence is attached."}
	}
	return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
}

func ciscoFamilyRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func ciscoFamilyPackFingerprint(records []CiscoFamilyAttributeRecord, grammar []CiscoFamilyGrammarRecord, source string) string {
	hash := sha256.New()
	hash.Write([]byte(source))
	for _, record := range records {
		hash.Write([]byte(record.ID + "\x00" + record.ImplementationClass + "\x00" + record.Capability + "\x00" + record.SoftwareState + "\n"))
	}
	for _, row := range grammar {
		hash.Write([]byte(row.Key + "\x00" + row.Kind + "\x00" + row.ParserState + "\x00" + row.CompilerState + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func containsAnyCiscoToken(value string, tokens ...string) bool {
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func firstNonEmptyPackKey(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func percentage(part, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}
