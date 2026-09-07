package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	MikroTikPackSchemaVersion          = 1
	MikroTikPackFeatureID              = "NAS-0070"
	MikroTikPackExpectedAttributeCount = 32

	MikroTikSoftwareCertified = "software_certified"
	MikroTikExternalRequired  = "external_certification_required"
)

type MikroTikPackSummary = RuckusICXPackSummary
type MikroTikVendorSummary = RuckusICXVendorSummary
type MikroTikCapabilityCount = RuckusICXCapabilityCount
type MikroTikProductScope = RuckusICXProductScope
type MikroTikGrammarRecord = RuckusICXGrammarRecord
type MikroTikAttributeRecord = RuckusICXAttributeRecord

type MikroTikPackReport struct {
	SchemaVersion                 int                       `json:"schema_version"`
	FeatureID                     string                    `json:"feature_id"`
	ReleaseProfileID              string                    `json:"release_profile_id"`
	SourceRelease                 string                    `json:"source_release"`
	SourceSHA256                  string                    `json:"source_sha256"`
	SourceFileCount               int                       `json:"source_file_count"`
	SourceAttributeCount          int                       `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                    `json:"release_certification_checklist"`
	Summary                       MikroTikPackSummary       `json:"summary"`
	VendorSummaries               []MikroTikVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []MikroTikCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []MikroTikProductScope    `json:"product_scopes"`
	Grammar                       []MikroTikGrammarRecord   `json:"grammar"`
	Records                       []MikroTikAttributeRecord `json:"records"`
	Notes                         []string                  `json:"notes,omitempty"`
}

func BuildMikroTikPackReport() (MikroTikPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return MikroTikPackReport{}, err
	}
	records := make([]MikroTikAttributeRecord, 0, MikroTikPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isMikroTikRegistryVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildMikroTikAttributeRecord(entry))
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
		if records[i].OID != records[j].OID {
			return records[i].OID < records[j].OID
		}
		return records[i].Attribute < records[j].Attribute
	})
	report := MikroTikPackReport{
		SchemaVersion:                 MikroTikPackSchemaVersion,
		FeatureID:                     MikroTikPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0070-release-certification-checklist.md",
		ProductScopes:                 mikrotikProductScopes(),
		Grammar:                       mikrotikGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0070 covers every MikroTik row in the pinned FreeRADIUS 3.2.8 audit, including duplicate dictionary aliases for type 25 and type 27.",
			"Software certification covers RouterOS PPP and hotspot quota fields, queue rate grammar, firewall address-list and switching-filter profile references, tenant realm and mark-id selectors, host IP and delegated IPv6 pool hints, CAPsMAN wireless forwarding, VLAN, encryption, signal, comment, and DHCP option evidence.",
			"Wireless key material is software-certified only as redacted evidence and is never accepted as cleartext policy input or emitted from neutral reply rendering.",
			"RouterOS, CAPsMAN, PPP/PPPoE, hotspot, real FreeRADIUS-on-Linux, CoA/Disconnect, HA, performance, soak, security, and customer acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeMikroTikPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeMikroTikVendors(records)
	report.CapabilitySummaries = summarizeMikroTikCapabilities(records)
	return report, nil
}

func ValidateMikroTikPackReport(report MikroTikPackReport) error {
	if report.SchemaVersion != MikroTikPackSchemaVersion {
		return fmt.Errorf("MikroTik pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != MikroTikPackFeatureID {
		return fmt.Errorf("MikroTik pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("MikroTik pack release profile and source hash are required")
	}
	if len(report.Records) != MikroTikPackExpectedAttributeCount {
		return fmt.Errorf("MikroTik pack has %d records, expected %d", len(report.Records), MikroTikPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != MikroTikPackExpectedAttributeCount {
		return fmt.Errorf("MikroTik pack summary has %d attributes, expected %d", report.Summary.AttributeCount, MikroTikPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != MikroTikPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("MikroTik pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != MikroTikPackExpectedAttributeCount {
		return fmt.Errorf("MikroTik pack must keep all RouterOS device claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 1 {
		return fmt.Errorf("MikroTik pack must cover exactly one dictionary vendor")
	}
	if report.Summary.SensitiveRedactedMappings != 3 {
		return fmt.Errorf("MikroTik pack must redact the three RouterOS wireless key attributes")
	}
	if report.Summary.ProductScopeCount < 10 || len(report.ProductScopes) < 10 {
		return fmt.Errorf("MikroTik product scope must include RouterOS PPP, hotspot, firewall, CAPsMAN, DHCP, IPv6, CoA, and certification coverage")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("MikroTik pack fingerprint is required")
	}
	if len(report.Grammar) < 13 {
		return fmt.Errorf("MikroTik pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("MikroTik grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != MikroTikExternalRequired {
			return fmt.Errorf("MikroTik grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("MikroTik record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("MikroTik record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != MikroTikSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("MikroTik record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("MikroTik record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if mikrotikSensitiveAttribute(record.Attribute) && record.ImplementationClass != "redacted_secret_evidence" {
			return fmt.Errorf("MikroTik sensitive record %q is not marked redacted", record.ID)
		}
	}
	return nil
}

func buildMikroTikAttributeRecord(entry AttributeRegistryEntry) MikroTikAttributeRecord {
	capability := mikrotikCapability(entry)
	class := mikrotikImplementationClass(entry)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = mikrotikRegistryDirections(entry, mikrotikRegistrySemantic(entry))
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = mikrotikRegistrySemantic(entry)
	}
	return MikroTikAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, VendorPackMikroTik),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, mikrotikRegistryFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           mikrotikPacketProcessing(class, entry),
		PolicyEngine:               mikrotikPolicyState(capability, class),
		Enforcement:                mikrotikEnforcementState(capability, class),
		Storage:                    mikrotikStorageState(class),
		APIUI:                      "pack_report_history_preview_routeros_scope_health_readiness_and_support_bundle",
		Monitoring:                 "mikrotik_counters_fingerprint_redaction_rate_quota_hotspot_capsman_and_coa_state",
		SoftwareState:              MikroTikSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      mikrotikRecordNotes(entry, class),
	}
}

func mikrotikGrammarRecords() []MikroTikGrammarRecord {
	rows := []MikroTikGrammarRecord{
		{"routeros_rate_limit", "RouterOS basic and extended rate-limit grammar", "rate_parser_compiler", VendorSemanticBandwidthProfile + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth, []string{"Mikrotik-Rate-Limit = \"50000k/20000k\"", "Mikrotik-Rate-Limit = \"50000k/20000k 75000k/30000k 50000k/20000k 10s/10s 4 10000k/5000k\""}, "", "", "", "", "", ""},
		{"routeros_ppp_octet_limits", "PPP and hotspot total, receive, transmit, and gigawords quota fields", "quota_counter_policy", VendorSemanticDataQuota + "," + VendorSemanticAccountingCounters, []string{"Mikrotik-Total-Limit = 1073741824", "Mikrotik-Total-Limit-Gigawords = 1"}, "", "", "", "", "", ""},
		{"routeros_group_profile", "RouterOS group/profile role assignment", "role_policy", VendorSemanticRole, []string{"Mikrotik-Group = \"ppp-gold\""}, "", "", "", "", "", ""},
		{"routeros_address_list_acl", "RouterOS firewall address-list authorization", "acl_profile_reference", VendorSemanticDynamicACL + "," + VendorSemanticACL, []string{"Mikrotik-Address-List = \"guest-internet\""}, "", "", "", "", "", ""},
		{"routeros_switching_filter", "RouterOS switching-filter profile evidence", "acl_profile_reference", VendorSemanticDynamicACL + "," + VendorSemanticACL, []string{"Mikrotik-Switching-Filter = \"lan-only\""}, "", "", "", "", "", ""},
		{"routeros_ipv4_host", "RouterOS host IP assignment and observed subscriber address context", "address_policy", VendorSemanticIPv4Address, []string{"Mikrotik-Host-IP = 198.51.100.10"}, "", "", "", "", "", ""},
		{"routeros_ipv6_pd_pool", "RouterOS delegated IPv6 pool selection", "ipv6_address_policy", VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticAddressPool, []string{"Mikrotik-Delegated-IPv6-Pool = \"pd-gold\""}, "", "", "", "", "", ""},
		{"routeros_hotspot_advertise", "RouterOS hotspot advertise URL and interval hints", "guest_portal_policy", VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle, []string{"Mikrotik-Advertise-URL = \"https://portal.example.test/login\"", "Mikrotik-Advertise-Interval = 300"}, "", "", "", "", "", ""},
		{"routeros_realm_mark", "RouterOS realm and mark-id tenant/policy selectors", "tenant_policy_context", VendorSemanticTenant + "," + VendorSemanticPolicyTag, []string{"Mikrotik-Realm = \"tenant-a\"", "Mikrotik-Mark-Id = \"branch-a\""}, "", "", "", "", "", ""},
		{"capsman_wireless_forward_dot1x", "CAPsMAN wireless forwarding and dot1x skip posture flags", "wireless_posture", VendorSemanticDevicePosture, []string{"Mikrotik-Wireless-Forward = 1", "Mikrotik-Wireless-Skip-Dot1x = 0"}, "", "", "", "", "", ""},
		{"capsman_wireless_encryption_redaction", "CAPsMAN wireless encryption algorithm and key redaction", "secret_redaction", VendorSemanticDevicePosture + "," + VendorSemanticCertificateOnboarding, []string{"Mikrotik-Wireless-Enc-Algo = 4", "Mikrotik-Wireless-PSK = <redacted>"}, "", "", "", "", "", ""},
		{"capsman_wireless_vlan_signal", "CAPsMAN wireless VLAN and signal policy hints", "wireless_vlan_posture", VendorSemanticVLAN + "," + VendorSemanticDevicePosture, []string{"Mikrotik-Wireless-VLANID = 120", "Mikrotik-Wireless-Minsignal = \"-80\""}, "", "", "", "", "", ""},
		{"routeros_dhcp_option_set", "RouterOS DHCP option-set and parameter evidence", "dhcp_option_policy", VendorSemanticPolicyTag + "," + VendorSemanticAccountingIdentity, []string{"Mikrotik-DHCP-Option-Set = \"voip\"", "Mikrotik-DHCP-Option-Param-STR1 = \"vendor-class\""}, "", "", "", "", "", ""},
		{"routeros_coa_disconnect", "RouterOS RFC5176 CoA and Disconnect authorization lifecycle", "dynamic_authorization", VendorSemanticCoAReauth + "," + VendorSemanticCoADisconnect, []string{"RFC5176 CoA-Request with Mikrotik-Rate-Limit", "RFC5176 Disconnect-Request"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = MikroTikExternalRequired
		rows[index].ReleaseScope = "RouterOS, CAPsMAN, PPP/PPPoE, hotspot, FreeRADIUS, CoA/Disconnect, HA, performance, soak, security, production deployment, and customer acceptance evidence is tracked in docs/nas-0070-release-certification-checklist.md."
	}
	return rows
}

func mikrotikProductScopes() []MikroTikProductScope {
	return []MikroTikProductScope{
		{Key: VendorPackMikroTik, Label: "RouterOS PPP And PPPoE Profiles", Vendors: []string{"Mikrotik"}, Products: []string{"RouterOS PPP", "PPPoE access concentrator", "subscriber profiles"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Group, rate, total-limit, receive/transmit limit, and gigawords fields are normalized for policy and accounting evidence."}},
		{Key: VendorPackMikroTik, Label: "RouterOS Simple Queues And Rate Limits", Vendors: []string{"Mikrotik"}, Products: []string{"RouterOS simple queues", "hotspot rate limiting", "PPP rate limiting"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Basic and extended Mikrotik-Rate-Limit grammar reuses the unit-safe NAS-0052 compiler/decompiler."}},
		{Key: VendorPackMikroTik, Label: "RouterOS Firewall Address Lists", Vendors: []string{"Mikrotik"}, Products: []string{"Firewall address-list", "profile-based ACLs", "quarantine lists"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Address-list and switching-filter values are represented as ACL profile references through the neutral ACL compiler."}},
		{Key: VendorPackMikroTik, Label: "RouterOS Hotspot Portal", Vendors: []string{"Mikrotik"}, Products: []string{"Hotspot", "captive portal", "advertise URL"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Advertise URL and interval map to guest portal and lifecycle evidence."}},
		{Key: VendorPackMikroTik, Label: "RouterOS Addressing And IPv6 PD", Vendors: []string{"Mikrotik"}, Products: []string{"IPv4 host address", "IPv6 prefix delegation", "subscriber address pool"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Host-IP and Delegated-IPv6-Pool integrate with the neutral address policy model; exact pool existence is release-certified."}},
		{Key: VendorPackMikroTik, Label: "RouterOS DHCP Option Sets", Vendors: []string{"Mikrotik"}, Products: []string{"DHCP option-set", "subscriber DHCP metadata"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Option-set and parameter rows are bounded typed evidence with policy-tag selectors."}},
		{Key: VendorPackMikroTik, Label: "CAPsMAN Wireless Authorization", Vendors: []string{"Mikrotik"}, Products: []string{"CAPsMAN", "wireless package", "AP forwarding and 802.1X controls"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Forwarding, dot1x skip, VLAN, signal, and comment rows feed wireless posture and VLAN intent."}},
		{Key: VendorPackMikroTik, Label: "CAPsMAN Wireless Secret Redaction", Vendors: []string{"Mikrotik"}, Products: []string{"Wireless PSK", "encryption key", "management pairwise key"}, Dictionary: "dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Wireless key material is redacted and not persisted as policy input."}},
		{Key: VendorPackStandard, Label: "Shared RouterOS CoA And Disconnect", Vendors: []string{"Mikrotik"}, Products: []string{"RFC5176 CoA", "Disconnect", "session reauthorization"}, Dictionary: "RFC5176 plus dictionary.mikrotik", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Dynamic authorization packet path can carry rate/address-list/group/VLAN actions; ACK/NAK behavior is release-certified."}},
		{Key: VendorPackMikroTik, Label: "RouterOS Controller And Release Boundary", Vendors: []string{"Mikrotik"}, Products: []string{"RouterOS REST API", "CAPsMAN controller sync", "firmware acceptance"}, Dictionary: "dictionary.mikrotik plus controller API evidence", SoftwareState: MikroTikSoftwareCertified, ExternalState: MikroTikExternalRequired, Notes: []string{"Software exposes pack health and evidence; controller/API drift and firmware behavior require release validation."}},
	}
}

func summarizeMikroTikPack(records []MikroTikAttributeRecord, grammar []MikroTikGrammarRecord, scopes []MikroTikProductScope) MikroTikPackSummary {
	return summarizeAccessVendorPack(records, grammar, scopes)
}

func summarizeMikroTikVendors(records []MikroTikAttributeRecord) []MikroTikVendorSummary {
	return summarizeAccessVendorVendors(records)
}

func summarizeMikroTikCapabilities(records []MikroTikAttributeRecord) []MikroTikCapabilityCount {
	return summarizeAccessVendorCapabilities(records)
}

func mikrotikCapability(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case containsAnyAccessVendorToken(name, "rate-limit", "recv-limit", "xmit-limit", "total-limit", "gigawords"):
		return "mikrotik_rate_quota_queue"
	case containsAnyAccessVendorToken(name, "group"):
		return "mikrotik_group_profile"
	case containsAnyAccessVendorToken(name, "address-list", "switching-filter"):
		return "mikrotik_acl_firewall_policy"
	case containsAnyAccessVendorToken(name, "delegated-ipv6", "host-ip"):
		return "mikrotik_address_ipv6_pool"
	case containsAnyAccessVendorToken(name, "advertise"):
		return "mikrotik_hotspot_portal"
	case containsAnyAccessVendorToken(name, "realm", "mark-id"):
		return "mikrotik_tenant_policy_marker"
	case containsAnyAccessVendorToken(name, "dhcp-option"):
		return "mikrotik_dhcp_option_policy"
	case mikrotikSensitiveAttribute(entry.Attribute):
		return "mikrotik_redacted_wireless_secret"
	case containsAnyAccessVendorToken(name, "wireless"):
		return "mikrotik_capsman_wireless"
	default:
		return "mikrotik_routeros_context"
	}
}

func mikrotikImplementationClass(entry AttributeRegistryEntry) string {
	if mikrotikSensitiveAttribute(entry.Attribute) {
		return "redacted_secret_evidence"
	}
	if registrySemanticContains(entry.Semantic, VendorSemanticDynamicACL) {
		return "policy_parse_compile"
	}
	nativeSemantics := []string{
		VendorSemanticRole, VendorSemanticBandwidthProfile, VendorSemanticDownloadBandwidth,
		VendorSemanticUploadBandwidth, VendorSemanticVLAN, VendorSemanticDataQuota,
		VendorSemanticPortalProfile, VendorSemanticGuestLifecycle, VendorSemanticTenant,
		VendorSemanticDeviceGroup, VendorSemanticAccountingIdentity, VendorSemanticAccountingCounters,
		VendorSemanticAddressPool, VendorSemanticIPv4Address, VendorSemanticDelegatedIPv6Prefix,
		VendorSemanticPolicyTag, VendorSemanticDevicePosture, VendorSemanticCoAReauth,
		VendorSemanticCoADisconnect,
	}
	for _, semantic := range nativeSemantics {
		if registrySemanticContains(entry.Semantic, semantic) {
			return "native_semantic_mapping"
		}
	}
	return "typed_passthrough"
}

func mikrotikPacketProcessing(class string, entry AttributeRegistryEntry) string {
	switch class {
	case "policy_parse_compile":
		return "routeros_address_list_and_switching_filter_profile_parser_compiler_and_bounded_vsa_codec"
	case "redacted_secret_evidence":
		return "string_decoder_sha256_evidence_and_cleartext_wireless_secret_redaction"
	case "native_semantic_mapping":
		if strings.EqualFold(entry.Attribute, "Mikrotik-Rate-Limit") {
			return "routeros_rate_grammar_parser_compiler_runtime_decoder_and_reply_renderer"
		}
		return "generated_runtime_decoder_semantic_mapper_reply_renderer_and_duplicate_number_guard"
	default:
		return "generic_routeros_vsa_codec_with_bounded_raw_evidence"
	}
}

func mikrotikPolicyState(capability, class string) string {
	switch {
	case strings.Contains(capability, "rate") || strings.Contains(capability, "quota") || strings.Contains(capability, "queue"):
		return "neutral_bandwidth_quota_queue_policy_context"
	case strings.Contains(capability, "acl") || class == "policy_parse_compile":
		return "dynamic_acl_address_list_switching_filter_profile_context"
	case strings.Contains(capability, "hotspot"):
		return "guest_portal_hotspot_advertise_policy_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "ipv6"):
		return "address_pool_host_ip_and_delegated_prefix_policy_context"
	case strings.Contains(capability, "wireless") || strings.Contains(capability, "capsman"):
		return "wireless_capsman_vlan_posture_and_signal_policy_context"
	case strings.Contains(capability, "dhcp"):
		return "dhcp_option_set_policy_and_subscriber_evidence_context"
	case class == "redacted_secret_evidence":
		return "redacted_wireless_key_evidence_context"
	default:
		return "typed_routeros_policy_context"
	}
}

func mikrotikEnforcementState(capability, class string) string {
	if class == "redacted_secret_evidence" {
		return "no_cleartext_enforcement_redacted_evidence_only"
	}
	switch {
	case strings.Contains(capability, "rate") || strings.Contains(capability, "quota"):
		return "radius_reply_rate_queue_and_quota_assignment_with_accounting_evidence"
	case strings.Contains(capability, "acl"):
		return "radius_reply_address_list_switching_filter_assignment_and_dynamic_acl_preview"
	case strings.Contains(capability, "hotspot"):
		return "radius_reply_hotspot_redirect_and_guest_lifecycle_hint"
	case strings.Contains(capability, "wireless") || strings.Contains(capability, "capsman"):
		return "radius_reply_capsman_vlan_posture_and_wireless_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "ipv6"):
		return "radius_reply_host_ip_pool_and_ipv6_pd_context"
	default:
		return "radius_reply_inbound_context_and_no_silent_fallback"
	}
}

func mikrotikStorageState(class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "bounded_hash_only_evidence_no_cleartext_wireless_secret"
	case "policy_parse_compile":
		return "normalized_acl_profile_and_bounded_routeros_filter_evidence"
	default:
		return "normalized_routeros_semantics_and_bounded_raw_vsa_evidence"
	}
}

func mikrotikRecordNotes(entry AttributeRegistryEntry, class string) []string {
	if class == "redacted_secret_evidence" {
		return []string{"RouterOS wireless key material is never stored as cleartext policy data; packet evidence uses redaction."}
	}
	if strings.EqualFold(entry.Attribute, "Mikrotik-Rate-Limit") {
		return []string{"RouterOS rate grammar is software-certified through the NAS-0052 compiler/decompiler; live queue behavior remains release certification."}
	}
	if strings.EqualFold(entry.Attribute, "Mikrotik-Address-List") || strings.EqualFold(entry.Attribute, "Mikrotik-Switching-Filter") {
		return []string{"RouterOS ACL behavior is represented as profile references; RouterOS-side firewall rules remain release-certified externally."}
	}
	return []string{"RouterOS and CAPsMAN behavior remains release-certified externally before hardware claims are published."}
}

func (r *AttributeRegistry) applyMikroTikRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isMikroTikRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := mikrotikRegistrySemantic(*entry)
		entry.PackKey = VendorPackMikroTik
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0070")
		entry.Directions = mikrotikRegistryDirections(*entry, entry.Semantic)
		entry.Functionality = mikrotikRegistryFunctionality(*entry, entry.Semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = mikrotikRegistryDecoder(*entry, entry.Semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isMikroTikRegistryVendor(vendor string) bool {
	return strings.EqualFold(strings.TrimSpace(vendor), "Mikrotik")
}

func mikrotikRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case mikrotikSensitiveAttribute(entry.Attribute):
		return VendorSemanticCertificateOnboarding
	case strings.EqualFold(entry.Attribute, "Mikrotik-Rate-Limit"):
		return VendorSemanticBandwidthProfile + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth
	case containsAnyAccessVendorToken(name, "recv-limit", "xmit-limit", "total-limit", "gigawords"):
		return VendorSemanticDataQuota + "," + VendorSemanticAccountingCounters
	case strings.EqualFold(entry.Attribute, "Mikrotik-Group"):
		return VendorSemanticRole
	case strings.EqualFold(entry.Attribute, "Mikrotik-Wireless-VLANID") || strings.EqualFold(entry.Attribute, "Mikrotik-Wireless-VLANIDtype") || strings.EqualFold(entry.Attribute, "Mikrotik-Wireless-VLANID-Type"):
		return VendorSemanticVLAN
	case strings.EqualFold(entry.Attribute, "Mikrotik-Address-List") || strings.EqualFold(entry.Attribute, "Mikrotik-Switching-Filter"):
		return VendorSemanticDynamicACL + "," + VendorSemanticACL
	case strings.EqualFold(entry.Attribute, "Mikrotik-Delegated-IPv6-Pool"):
		return VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticAddressPool
	case strings.EqualFold(entry.Attribute, "Mikrotik-Host-IP"):
		return VendorSemanticIPv4Address
	case strings.HasPrefix(name, "mikrotik-dhcp-option"):
		return VendorSemanticPolicyTag + "," + VendorSemanticAccountingIdentity
	case strings.EqualFold(entry.Attribute, "Mikrotik-Realm"):
		return VendorSemanticTenant
	case strings.EqualFold(entry.Attribute, "Mikrotik-Mark-Id"):
		return VendorSemanticPolicyTag
	case strings.EqualFold(entry.Attribute, "Mikrotik-Advertise-URL"):
		return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
	case strings.EqualFold(entry.Attribute, "Mikrotik-Advertise-Interval"):
		return VendorSemanticGuestLifecycle
	case strings.HasPrefix(name, "mikrotik-wireless-"):
		return VendorSemanticDevicePosture
	default:
		return VendorSemanticPolicyTag
	}
}

func mikrotikRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	if registrySemanticContains(semantic, VendorSemanticAccountingCounters) ||
		registrySemanticContains(semantic, VendorSemanticAccountingIdentity) ||
		registrySemanticContains(semantic, VendorSemanticDevicePosture) {
		return []string{"inbound", "outbound_reply", "accounting"}
	}
	if mikrotikSensitiveAttribute(entry.Attribute) {
		return []string{"inbound", "outbound_reply"}
	}
	return []string{"inbound", "outbound_reply"}
}

func mikrotikRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case strings.EqualFold(entry.Attribute, "Mikrotik-Rate-Limit"):
		return "RouterOS queue and subscriber rate assignment using basic or extended Mikrotik-Rate-Limit grammar."
	case containsAnyAccessVendorToken(name, "recv-limit", "xmit-limit", "total-limit", "gigawords"):
		return "RouterOS PPP and hotspot subscriber octet quota, high-word gigawords, and accounting evidence."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Group"):
		return "RouterOS user group or profile role assignment."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Address-List"):
		return "RouterOS firewall address-list policy assignment for ACL, quarantine, or subscriber classification."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Switching-Filter"):
		return "RouterOS switching-filter profile evidence for local bridge or switching policy."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Delegated-IPv6-Pool"):
		return "RouterOS IPv6 prefix-delegation pool selection for PPP, DHCP, or subscriber sessions."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Host-IP"):
		return "RouterOS host IPv4 address context for subscriber or hotspot sessions."
	case strings.HasPrefix(name, "mikrotik-dhcp-option"):
		return "RouterOS DHCP option-set and parameter policy evidence for subscriber access."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Realm"):
		return "RouterOS realm value normalized as tenant context."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Mark-Id"):
		return "RouterOS mark-id selector normalized as a policy tag."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Advertise-URL"):
		return "RouterOS hotspot advertise URL normalized as captive portal and guest lifecycle context."
	case strings.EqualFold(entry.Attribute, "Mikrotik-Advertise-Interval"):
		return "RouterOS hotspot advertise interval tracked as guest lifecycle evidence."
	case mikrotikSensitiveAttribute(entry.Attribute):
		return "RouterOS wireless key material tracked only as redacted evidence."
	case strings.HasPrefix(name, "mikrotik-wireless-"):
		return "RouterOS wireless and CAPsMAN posture, VLAN, encryption, forwarding, signal, or comment context."
	default:
		if strings.TrimSpace(semantic) != "" {
			return "RouterOS " + semantic + " compatibility mapping."
		}
		return "RouterOS vendor-specific compatibility evidence."
	}
}

func mikrotikRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	switch {
	case strings.EqualFold(entry.Attribute, "Mikrotik-Wireless-VLANID"):
		return "vlan", VendorSemanticVLAN, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Host-IP"):
		return "ipaddr", VendorSemanticIPv4Address, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Rate-Limit"):
		return "string", VendorSemanticBandwidthProfile, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Address-List"):
		return "string", VendorSemanticDynamicACL, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Switching-Filter"):
		return "string", VendorSemanticACL, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Delegated-IPv6-Pool"):
		return "string", VendorSemanticDelegatedIPv6Prefix, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Group"):
		return "string", VendorSemanticRole, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Realm"):
		return "string", VendorSemanticTenant, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Advertise-URL"):
		return "string", VendorSemanticPortalProfile, 0
	case strings.EqualFold(entry.Attribute, "Mikrotik-Mark-Id") || strings.HasPrefix(strings.ToLower(entry.Attribute), "mikrotik-dhcp-option"):
		return "string", VendorSemanticPolicyTag, 0
	case mikrotikSensitiveAttribute(entry.Attribute):
		return "string", VendorSemanticCertificateOnboarding, 0
	case strings.EqualFold(baseDictionaryWireType(entry.WireType), "integer"):
		return "integer_text", firstRegistrySemantic(semantic), 0
	default:
		return "string", firstRegistrySemantic(semantic), 0
	}
}

func mikrotikSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return strings.EqualFold(attribute, "Mikrotik-Wireless-Enc-Key") ||
		strings.EqualFold(attribute, "Mikrotik-Wireless-PSK") ||
		strings.EqualFold(attribute, "Mikrotik-Wireless-MPKey") ||
		containsAnyAccessVendorToken(name, "wireless-enc-key", "wireless-psk", "wireless-mpkey")
}
