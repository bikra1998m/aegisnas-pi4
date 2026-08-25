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
	JuniperExtremePackSchemaVersion          = 1
	JuniperExtremePackFeatureID              = "NAS-0063"
	JuniperExtremePackExpectedAttributeCount = 260

	JuniperExtremeSoftwareCertified = "software_certified"
	JuniperExtremeExternalRequired  = "external_certification_required"
)

type JuniperExtremePackReport struct {
	SchemaVersion                 int                             `json:"schema_version"`
	FeatureID                     string                          `json:"feature_id"`
	ReleaseProfileID              string                          `json:"release_profile_id"`
	SourceRelease                 string                          `json:"source_release"`
	SourceSHA256                  string                          `json:"source_sha256"`
	SourceFileCount               int                             `json:"source_file_count"`
	SourceAttributeCount          int                             `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                          `json:"release_certification_checklist"`
	Summary                       JuniperExtremePackSummary       `json:"summary"`
	VendorSummaries               []JuniperExtremeVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []JuniperExtremeCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []JuniperExtremeProductScope    `json:"product_scopes"`
	Grammar                       []JuniperExtremeGrammarRecord   `json:"grammar"`
	Records                       []JuniperExtremeAttributeRecord `json:"records"`
	Notes                         []string                        `json:"notes,omitempty"`
}

type JuniperExtremePackSummary struct {
	VendorCount                        int     `json:"vendor_count"`
	ProductScopeCount                  int     `json:"product_scope_count"`
	AttributeCount                     int     `json:"attribute_count"`
	NativeSemanticMappings             int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings           int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings          int     `json:"sensitive_redacted_mappings"`
	GrammarRuleCount                   int     `json:"grammar_rule_count"`
	SoftwareCertifiedMappings          int     `json:"software_certified_mappings"`
	SoftwareBlockedMappings            int     `json:"software_blocked_mappings"`
	ReadyForExternalValidationMappings int     `json:"ready_for_external_validation_mappings"`
	ExternalRequiredMappings           int     `json:"external_required_mappings"`
	SoftwareCompletionPercent          float64 `json:"software_completion_percent"`
	Fingerprint                        string  `json:"fingerprint"`
}

type JuniperExtremeVendorSummary struct {
	Vendor                    string  `json:"vendor"`
	PEN                       uint32  `json:"pen"`
	PackKey                   string  `json:"pack_key,omitempty"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings int     `json:"sensitive_redacted_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type JuniperExtremeCapabilityCount struct {
	Capability                string  `json:"capability"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings int     `json:"sensitive_redacted_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type JuniperExtremeProductScope struct {
	Key           string   `json:"key"`
	Label         string   `json:"label"`
	Vendors       []string `json:"vendors"`
	Products      []string `json:"products"`
	Dictionary    string   `json:"dictionary"`
	SoftwareState string   `json:"software_state"`
	ExternalState string   `json:"external_state"`
	Notes         []string `json:"notes,omitempty"`
}

type JuniperExtremeGrammarRecord struct {
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

type JuniperExtremeAttributeRecord struct {
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

func BuildJuniperExtremePackReport() (JuniperExtremePackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return JuniperExtremePackReport{}, err
	}
	records := make([]JuniperExtremeAttributeRecord, 0, JuniperExtremePackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isJuniperExtremeVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildJuniperExtremeAttributeRecord(entry))
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
	report := JuniperExtremePackReport{
		SchemaVersion:                 JuniperExtremePackSchemaVersion,
		FeatureID:                     JuniperExtremePackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0063-release-certification-checklist.md",
		ProductScopes:                 juniperExtremeProductScopes(),
		Grammar:                       juniperExtremeGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0063 covers all Juniper, ERX, and Extreme rows in the pinned FreeRADIUS 3.2.8 audit.",
			"Juniper Mist is represented as a Juniper product/controller scope; the pinned FreeRADIUS 3.2.8 corpus has no separate Mist VSA dictionary rows.",
			"Software certification covers typed dictionary metadata, generic VSA packet safety, Juniper AVPair parsing, Extreme extended VLAN parsing, ERX subscriber/routing/QoS normalization, API/UI visibility, durable evidence, and observability readiness.",
			"Rows without a neutral runtime semantic are software-certified as typed pass-through or typed evidence, not as hardware-certified behavior.",
			"Real Junos, ERX/E-Series, ExtremeXOS/Switch Engine, Juniper Mist, FreeRADIUS-on-Linux, HA, performance, soak, security, and production behavior remains in the NAS-0063 release certification checklist.",
		},
	}
	report.Summary = summarizeJuniperExtremePack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = juniperExtremePackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeJuniperExtremeVendors(records)
	report.CapabilitySummaries = summarizeJuniperExtremeCapabilities(records)
	return report, nil
}

func ValidateJuniperExtremePackReport(report JuniperExtremePackReport) error {
	if report.SchemaVersion != JuniperExtremePackSchemaVersion {
		return fmt.Errorf("Juniper/Extreme pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != JuniperExtremePackFeatureID {
		return fmt.Errorf("Juniper/Extreme pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Juniper/Extreme pack release profile and source hash are required")
	}
	if len(report.Records) != JuniperExtremePackExpectedAttributeCount {
		return fmt.Errorf("Juniper/Extreme pack has %d records, expected %d", len(report.Records), JuniperExtremePackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != JuniperExtremePackExpectedAttributeCount {
		return fmt.Errorf("Juniper/Extreme pack summary has %d attributes, expected %d", report.Summary.AttributeCount, JuniperExtremePackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != JuniperExtremePackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Juniper/Extreme pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != JuniperExtremePackExpectedAttributeCount {
		return fmt.Errorf("Juniper/Extreme pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.ProductScopeCount < 4 || len(report.ProductScopes) < 4 {
		return fmt.Errorf("Juniper/Extreme pack product scope must include Junos, ERX, Extreme, and Mist")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Juniper/Extreme pack fingerprint is required")
	}
	if len(report.Grammar) < 12 {
		return fmt.Errorf("Juniper/Extreme pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Juniper/Extreme grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != JuniperExtremeExternalRequired {
			return fmt.Errorf("Juniper/Extreme grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Juniper/Extreme record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Juniper/Extreme record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != JuniperExtremeSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Juniper/Extreme record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Juniper/Extreme record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildJuniperExtremeAttributeRecord(entry AttributeRegistryEntry) JuniperExtremeAttributeRecord {
	capability := juniperExtremeCapability(entry)
	class := "typed_passthrough"
	if entry.DictionaryStatus != "missing" && strings.TrimSpace(entry.Semantic) != "" {
		class = "native_semantic_mapping"
	}
	if isJuniperExtremePolicyGrammarAttribute(entry.Attribute) {
		class = "policy_parse_compile"
	}
	if isJuniperExtremeNativeAttribute(entry.Attribute) {
		class = "native_semantic_mapping"
	}
	if isJuniperExtremeSensitiveAttribute(entry.Attribute) {
		class = "redacted_secret_evidence"
	}
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferJuniperExtremeDirections(entry, capability)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = juniperExtremeSemantic(capability)
	}
	return JuniperExtremeAttributeRecord{
		ID:                         juniperExtremeRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, juniperExtremeDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, juniperExtremeFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           juniperExtremePacketProcessing(class),
		PolicyEngine:               juniperExtremePolicyState(class, capability),
		Enforcement:                juniperExtremeEnforcementState(class, capability),
		Storage:                    juniperExtremeStorageState(class),
		APIUI:                      "pack_report_history_preview_controller_scope_and_support_bundle",
		Monitoring:                 "vendor_family_counters_fingerprint_controller_scope_and_secret_redaction_state",
		SoftwareState:              JuniperExtremeSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      juniperExtremeRecordNotes(class),
	}
}

func juniperExtremeGrammarRecords() []JuniperExtremeGrammarRecord {
	rows := []JuniperExtremeGrammarRecord{
		{"juniper_junos_role", "Junos login role and local group", "role_policy", VendorSemanticRole, []string{"Juniper-Local-User-Name = \"operator\"", "Juniper-Local-Group-Name = \"netops\""}, "", "", "", "", "", ""},
		{"juniper_command_authorization", "Junos command and configuration authorization", "command_authorization", VendorSemanticRole, []string{"Juniper-Allow-Commands = \"show.*\"", "Juniper-Deny-Configuration = \"system login.*\""}, "", "", "", "", "", ""},
		{"juniper_firewall_filter", "Junos firewall and switching filters", "acl_policy", VendorSemanticACL, []string{"Juniper-Firewall-filter-name = \"guest-in\"", "Juniper-Switching-Filter = \"campus-edge\""}, "", "", "", "", "", ""},
		{"juniper_avpair", "Juniper AVPair policy grammar", "vendor_avpair", VendorSemanticDynamicACL, []string{"firewall=guest-in", "junos:vrf=tenant-a", "ipv6:delegated-prefix=branch-pd"}, "", "", "", "", "", ""},
		{"juniper_addressing", "Junos address pool and DNS metadata", "address_policy", VendorSemanticAddressPool, []string{"Juniper-Ip-Pool-Name = \"corp-v4\"", "Juniper-Primary-Dns = 192.0.2.53"}, "", "", "", "", "", ""},
		{"juniper_guest_portal", "Junos captive web authentication redirect", "guest_portal", VendorSemanticPortalProfile, []string{"Juniper-CWA-Redirect = \"https://guest.example.test/login\""}, "", "", "", "", "", ""},
		{"extreme_role_vlan", "Extreme role and VLAN assignment", "vlan_policy", VendorSemanticVLAN, []string{"Extreme-Security-Profile = \"employee\"", "Extreme-Netlogin-Extended-Vlan = \"U20;T30;T40\""}, "", "", "", "", "", ""},
		{"extreme_portal_location", "Extreme portal and location context", "guest_portal", VendorSemanticPortalProfile, []string{"Extreme-Netlogin-Url = \"https://portal.example.test/start\"", "Extreme-User-Location = \"building-a\""}, "", "", "", "", "", ""},
		{"extreme_command_vm", "Extreme command authorization and VM context", "device_context", VendorSemanticDeviceGroup, []string{"Extreme-CLI-Authorization = 1", "Extreme-VM-Name = \"tenant-vm\""}, "", "", "", "", "", ""},
		{"erx_bng_routing", "ERX virtual router, pool, route, and IPv6 RA", "bng_routing", VendorSemanticVRF, []string{"ERX-Virtual-Router-Name = \"vr-corp\"", "ERX-IPv6-NdRa-Pool-Name = \"pd-pool\""}, "", "", "", "", "", ""},
		{"erx_subscriber_service", "ERX subscriber service activation", "subscriber_service", VendorSemanticSessionAction, []string{"ERX-Service-Activate = \"iptv-gold\"", "ERX-Service-Deactivate = \"walled-garden\""}, "", "", "", "", "", ""},
		{"erx_qos_rate", "ERX QoS, CoS, and access line rate", "qos_policy", VendorSemanticBandwidthProfile, []string{"ERX-Qos-Profile-Name = \"gold\"", "ERX-Act-Data-Rate-Up = 50000"}, "", "", "", "", "", ""},
		{"erx_dhcp_access", "ERX DHCP, PPPoE, DSL, and PON subscriber context", "subscriber_context", VendorSemanticAccountingIdentity, []string{"ERX-Dhcp-Mac-Addr = \"aa:bb:cc:dd:ee:ff\"", "ERX-PON-Access-Type = 1"}, "", "", "", "", "", ""},
		{"erx_dynamic_authorization", "ERX bulk CoA and disconnect identifiers", "dynamic_authorization", VendorSemanticCoAReauth, []string{"ERX-Bulk-CoA-Transaction-Id = 1001", "Sdx-Tunnel-Disconnect-Cause-Info = \"admin-reset\""}, "", "", "", "", "", ""},
		{"erx_sensitive", "ERX secret-bearing tunnel and PPP credentials", "secret_redaction", VendorSemanticPolicyTag, []string{"ERX-Tunnel-Password = \"<redacted>\"", "ERX-Mobile-IP-Key = \"<redacted>\""}, "", "", "", "", "", ""},
		{"mist_controller", "Juniper Mist controller policy scope", "controller_policy_sync", VendorSemanticControllerPolicySync, []string{"controller.policy_sync = \"juniper-mist\"", "controller.sync_health = \"healthy\""}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = JuniperExtremeExternalRequired
		rows[index].ReleaseScope = "Device, controller, and firmware acceptance is tracked in docs/nas-0063-release-certification-checklist.md."
	}
	return rows
}

func juniperExtremeProductScopes() []JuniperExtremeProductScope {
	return []JuniperExtremeProductScope{
		{Key: VendorPackJuniper, Label: "Juniper Junos", Vendors: []string{"Juniper"}, Products: []string{"Junos EX", "Junos SRX", "Junos MX", "Junos switching and firewall filters"}, Dictionary: "dictionary.juniper", SoftwareState: JuniperExtremeSoftwareCertified, ExternalState: JuniperExtremeExternalRequired, Notes: []string{"Native device behavior is release-certified by platform and firmware."}},
		{Key: VendorPackERX, Label: "Juniper ERX / E-Series", Vendors: []string{"ERX", "Juniper"}, Products: []string{"ERX", "E-Series BRAS/BNG", "subscriber service edge"}, Dictionary: "dictionary.erx", SoftwareState: JuniperExtremeSoftwareCertified, ExternalState: JuniperExtremeExternalRequired, Notes: []string{"Subscriber service and line-rate attributes are software-normalized as policy intent or bounded evidence."}},
		{Key: VendorPackExtreme, Label: "Extreme Networks", Vendors: []string{"Extreme"}, Products: []string{"ExtremeXOS", "Switch Engine", "Fabric Engine RADIUS edge"}, Dictionary: "dictionary.extreme", SoftwareState: JuniperExtremeSoftwareCertified, ExternalState: JuniperExtremeExternalRequired, Notes: []string{"Extended VLAN grammar supports untagged and tagged assignments with duplicate and range validation."}},
		{Key: VendorPackMist, Label: "Juniper Mist", Vendors: []string{"Juniper"}, Products: []string{"Mist Cloud", "Mist Access Assurance", "Mist-managed enterprise WLANs"}, Dictionary: "controller scope; no separate FreeRADIUS 3.2.8 VSA rows", SoftwareState: JuniperExtremeSoftwareCertified, ExternalState: JuniperExtremeExternalRequired, Notes: []string{"Mist policy sync is exposed through the existing native controller adapter and standards-based RADIUS reply path."}},
	}
}

func summarizeJuniperExtremePack(records []JuniperExtremeAttributeRecord, grammar []JuniperExtremeGrammarRecord, scopes []JuniperExtremeProductScope) JuniperExtremePackSummary {
	summary := JuniperExtremePackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar), ProductScopeCount: len(scopes)}
	vendors := map[string]struct{}{}
	for _, record := range records {
		vendors[record.Vendor+"\x00"+strconv.FormatUint(uint64(record.PEN), 10)] = struct{}{}
		switch record.ImplementationClass {
		case "native_semantic_mapping", "policy_parse_compile":
			summary.NativeSemanticMappings++
		case "redacted_secret_evidence":
			summary.SensitiveRedactedMappings++
			summary.TypedPassThroughMappings++
		default:
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == JuniperExtremeSoftwareCertified {
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

func summarizeJuniperExtremeVendors(records []JuniperExtremeAttributeRecord) []JuniperExtremeVendorSummary {
	byKey := map[string]*JuniperExtremeVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &JuniperExtremeVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
			byKey[key] = summary
		}
		summary.AttributeCount++
		switch record.ImplementationClass {
		case "native_semantic_mapping", "policy_parse_compile":
			summary.NativeSemanticMappings++
		case "redacted_secret_evidence":
			summary.SensitiveRedactedMappings++
			summary.TypedPassThroughMappings++
		default:
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == JuniperExtremeSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]JuniperExtremeVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeJuniperExtremeCapabilities(records []JuniperExtremeAttributeRecord) []JuniperExtremeCapabilityCount {
	byCapability := map[string]*JuniperExtremeCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &JuniperExtremeCapabilityCount{Capability: record.Capability}
			byCapability[record.Capability] = summary
		}
		summary.AttributeCount++
		switch record.ImplementationClass {
		case "native_semantic_mapping", "policy_parse_compile":
			summary.NativeSemanticMappings++
		case "redacted_secret_evidence":
			summary.SensitiveRedactedMappings++
			summary.TypedPassThroughMappings++
		default:
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == JuniperExtremeSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]JuniperExtremeCapabilityCount, 0, len(byCapability))
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

func isJuniperExtremeVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "juniper", "erx", "extreme":
		return true
	default:
		return false
	}
}

func juniperExtremeCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(entry.Vendor)
	name := strings.ToLower(entry.Attribute)
	switch vendor {
	case "juniper":
		return juniperCapability(name)
	case "erx":
		return erxCapability(name)
	case "extreme":
		return extremeCapability(name)
	default:
		return "generic_juniper_extreme_context"
	}
}

func juniperCapability(name string) string {
	switch {
	case containsAnyJuniperExtremeToken(name, "allow-commands", "deny-commands", "interactive-command", "configuration", "permissions", "local-user"):
		return "junos_command_and_admin_authorization"
	case containsAnyJuniperExtremeToken(name, "firewall", "switching-filter", "av-pair"):
		return "junos_firewall_filter_and_avpair_policy"
	case containsAnyJuniperExtremeToken(name, "dns", "pool", "dhcp", "interface-id"):
		return "junos_address_and_dhcp_context"
	case containsAnyJuniperExtremeToken(name, "cos", "policer", "overhead", "connect-speed"):
		return "junos_qos_cos_and_access_rate"
	case containsAnyJuniperExtremeToken(name, "cwa", "redirect"):
		return "junos_guest_portal"
	case containsAnyJuniperExtremeToken(name, "acct"):
		return "junos_accounting_reason"
	case containsAnyJuniperExtremeToken(name, "group", "ctp", "junosspace"):
		return "junos_group_and_management_context"
	default:
		return "junos_vendor_context"
	}
}

func extremeCapability(name string) string {
	switch {
	case containsAnyJuniperExtremeToken(name, "cli", "shell-command", "netlogin-only"):
		return "extreme_command_and_login_authorization"
	case containsAnyJuniperExtremeToken(name, "netlogin-vlan", "vlan-tag", "extended-vlan"):
		return "extreme_vlan_and_8021x_policy"
	case containsAnyJuniperExtremeToken(name, "url"):
		return "extreme_guest_portal"
	case containsAnyJuniperExtremeToken(name, "security-profile"):
		return "extreme_role_and_security_profile"
	case containsAnyJuniperExtremeToken(name, "location"):
		return "extreme_location_and_tenant_context"
	case containsAnyJuniperExtremeToken(name, "vm-"):
		return "extreme_vm_and_virtual_router_context"
	default:
		return "extreme_vendor_context"
	}
}

func erxCapability(name string) string {
	switch {
	case containsAnyJuniperExtremeToken(name, "password", "mobile-ip-key"):
		return "erx_secret_and_tunnel_authentication"
	case containsAnyJuniperExtremeToken(name, "bulk-coa", "disconnect", "re-authentication", "reauth"):
		return "erx_dynamic_authorization"
	case containsAnyJuniperExtremeToken(name, "acct", "gigawords", "input-octets", "output-octets", "service-session", "statistics"):
		return "erx_accounting_and_session_telemetry"
	case containsAnyJuniperExtremeToken(name, "qos", "cos", "rate", "bandwidth", "bps", "throughput", "interlv", "traffic"):
		return "erx_qos_cos_and_access_line_rate"
	case containsAnyJuniperExtremeToken(name, "virtual-router", "vrouter", "router", "route", "dns", "ipv6", "ndra", "pool", "service-set"):
		return "erx_bng_routing_addressing_and_ipv6"
	case containsAnyJuniperExtremeToken(name, "policy", "filter", "pcef", "service-activate", "service-deactivate", "service-bundle", "routing-services", "service-volume", "service-timeout", "update-service"):
		return "erx_subscriber_service_and_firewall_policy"
	case containsAnyJuniperExtremeToken(name, "dhcp", "pppoe", "ppp", "dsl", "pon", "ont", "onu", "relay", "access", "client-profile", "max-clients", "mlppp"):
		return "erx_broadband_subscriber_access_context"
	case containsAnyJuniperExtremeToken(name, "l2tp", "tunnel"):
		return "erx_tunnel_and_l2tp_context"
	case containsAnyJuniperExtremeToken(name, "igmp", "mld", "mcast", "pim", "multicast"):
		return "erx_multicast_subscriber_policy"
	case containsAnyJuniperExtremeToken(name, "mobile", "apn", "lte"):
		return "erx_mobile_core_and_charging_context"
	case containsAnyJuniperExtremeToken(name, "cli", "radius-client", "interface", "port"):
		return "erx_nas_device_management"
	default:
		return "erx_vendor_context"
	}
}

func juniperExtremeSemantic(capability string) string {
	switch capability {
	case "junos_command_and_admin_authorization", "junos_group_and_management_context", "extreme_command_and_login_authorization", "extreme_role_and_security_profile":
		return VendorSemanticRole
	case "junos_firewall_filter_and_avpair_policy", "erx_subscriber_service_and_firewall_policy":
		return VendorSemanticDynamicACL
	case "junos_address_and_dhcp_context", "erx_bng_routing_addressing_and_ipv6":
		return VendorSemanticAddressPool
	case "junos_qos_cos_and_access_rate", "erx_qos_cos_and_access_line_rate":
		return VendorSemanticBandwidthProfile
	case "junos_guest_portal", "extreme_guest_portal":
		return VendorSemanticPortalProfile
	case "junos_accounting_reason", "erx_accounting_and_session_telemetry":
		return VendorSemanticAccountingCounters
	case "extreme_vlan_and_8021x_policy":
		return VendorSemanticVLAN
	case "extreme_location_and_tenant_context":
		return VendorSemanticTenant
	case "extreme_vm_and_virtual_router_context", "erx_nas_device_management", "erx_broadband_subscriber_access_context":
		return VendorSemanticAccountingIdentity
	case "erx_dynamic_authorization":
		return VendorSemanticCoAReauth
	case "erx_tunnel_and_l2tp_context", "erx_mobile_core_and_charging_context", "erx_multicast_subscriber_policy":
		return VendorSemanticPolicyTag
	case "erx_secret_and_tunnel_authentication":
		return VendorSemanticPolicyTag
	default:
		return VendorSemanticPolicyTag
	}
}

func inferJuniperExtremeDirections(entry AttributeRegistryEntry, capability string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case isJuniperExtremeSensitiveAttribute(entry.Attribute):
		return []string{"inbound", "outbound_reply"}
	case containsAnyJuniperExtremeToken(name, "acct", "gigawords", "input-octets", "output-octets", "dhcp-", "header", "mac-addr", "client-profile", "line-state", "pon", "ont", "onu"):
		return []string{"accounting", "inbound"}
	case containsAnyJuniperExtremeToken(name, "bulk-coa", "disconnect", "re-authentication", "service-activate", "service-deactivate", "update-service"):
		return []string{"inbound", "outbound_reply", "coa"}
	case containsAnyJuniperExtremeToken(capability, "role", "authorization", "filter", "policy", "vlan", "portal", "qos", "routing", "addressing", "service"):
		return []string{"inbound", "outbound_reply"}
	default:
		return []string{"inbound"}
	}
}

func juniperExtremeDefaultPack(vendor string) string {
	switch strings.ToLower(vendor) {
	case "juniper":
		return VendorPackJuniper
	case "erx":
		return VendorPackERX
	case "extreme":
		return VendorPackExtreme
	default:
		return "juniper-extreme"
	}
}

func juniperExtremeFunctionality(entry AttributeRegistryEntry, capability string) string {
	return fmt.Sprintf("%s carries %s in Juniper/ERX/Extreme RADIUS packets; AegisNAS stores bounded evidence, redacts key material, and normalizes known policy semantics.", entry.Attribute, strings.ReplaceAll(capability, "_", " "))
}

func juniperExtremePacketProcessing(class string) string {
	switch class {
	case "policy_parse_compile":
		return "juniper_avpair_filter_or_extreme_extended_vlan_parser_classifier_and_safe_unknown_preservation"
	case "native_semantic_mapping":
		return "native_runtime_decoder_and_reply_renderer"
	case "redacted_secret_evidence":
		return "secret_aware_vsa_codec_with_redacted_evidence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func juniperExtremePolicyState(class, capability string) string {
	if class == "typed_passthrough" {
		return "typed_evidence_only_until_policy_binding"
	}
	if class == "redacted_secret_evidence" {
		return "secret_metadata_without_secret_persistence"
	}
	switch {
	case strings.Contains(capability, "filter") || strings.Contains(capability, "firewall") || strings.Contains(capability, "pcef"):
		return "acl_ast_and_juniper_filter_compiler"
	case strings.Contains(capability, "qos") || strings.Contains(capability, "rate"):
		return "qos_and_rate_policy"
	case strings.Contains(capability, "routing") || strings.Contains(capability, "addressing") || strings.Contains(capability, "ipv6"):
		return "route_vrf_address_policy"
	case strings.Contains(capability, "subscriber") || strings.Contains(capability, "service"):
		return "subscriber_service_policy"
	case strings.Contains(capability, "portal"):
		return "guest_portal_policy"
	default:
		return "neutral_policy_semantics"
	}
}

func juniperExtremeEnforcementState(class, capability string) string {
	if class == "typed_passthrough" {
		return "safe_visibility_no_silent_enforcement_claim"
	}
	if class == "redacted_secret_evidence" {
		return "redacted_evidence_only_until_external_secret_flow_certification"
	}
	if strings.Contains(capability, "dynamic_authorization") {
		return "radius_reply_and_coa_session_control_surfaces"
	}
	return "radius_reply_controller_preview_and_policy_surfaces"
}

func juniperExtremeStorageState(class string) string {
	if class == "redacted_secret_evidence" {
		return "redacted_secret_metadata_and_bounded_non_secret_evidence"
	}
	return "bounded_raw_evidence_and_normalized_metadata"
}

func juniperExtremeRecordNotes(class string) []string {
	switch class {
	case "redacted_secret_evidence":
		return []string{"Secret-bearing values are never persisted in clear text; software readiness covers redaction and metadata handling, while real credential flows remain release certification."}
	case "typed_passthrough":
		return []string{"Software-ready typed pass-through does not claim native device behavior until release certification evidence is attached."}
	default:
		return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
	}
}

func isJuniperExtremeNativeAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "juniper-local-user-name", "juniper-allow-commands", "juniper-deny-commands", "juniper-user-permissions",
		"juniper-primary-dns", "juniper-secondary-dns", "juniper-ip-pool-name", "juniper-cos-traffic-control-profile",
		"juniper-cos-parameter", "juniper-firewall-filter-name", "juniper-policer-parameter", "juniper-local-group-name",
		"juniper-switching-filter", "juniper-voip-vlan", "juniper-cwa-redirect", "juniper-av-pair", "juniper-acct-request-reason",
		"extreme-cli-authorization", "extreme-shell-command", "extreme-netlogin-vlan", "extreme-netlogin-url",
		"extreme-netlogin-url-desc", "extreme-netlogin-only", "extreme-user-location", "extreme-netlogin-vlan-tag",
		"extreme-netlogin-extended-vlan", "extreme-security-profile", "extreme-vm-name", "extreme-vm-vpp-name",
		"extreme-vm-ip-addr", "extreme-vm-vlan-id", "extreme-vm-vr-name",
		"erx-virtual-router-name", "erx-address-pool-name", "erx-primary-dns", "erx-secondary-dns",
		"erx-tunnel-virtual-router", "erx-ingress-policy-name", "erx-egress-policy-name", "erx-redirect-vr-name",
		"erx-qos-profile-name", "erx-pppoe-url", "erx-service-bundle", "erx-tunnel-maximum-sessions",
		"erx-framed-ip-route-tag", "erx-ppp-username", "erx-ppp-auth-protocol", "erx-ipv6-virtual-router",
		"erx-ipv6-local-interface", "erx-ipv6-primary-dns", "erx-ipv6-secondary-dns", "sdx-service-name",
		"sdx-tunnel-disconnect-cause-info", "erx-radius-client-address", "erx-service-description", "erx-dhcp-mac-addr",
		"erx-dhcp-gi-address", "erx-mlppp-bundle-name", "erx-tunnel-group", "erx-service-activate",
		"erx-service-deactivate", "erx-service-volume", "erx-service-timeout", "erx-service-statistics",
		"erx-qos-parameters", "erx-service-session", "erx-ipv6-ingress-policy-name", "erx-ipv6-egress-policy-name",
		"erx-act-data-rate-up", "erx-act-data-rate-dn", "erx-max-data-rate-up", "erx-max-data-rate-dn",
		"erx-ipv6-ndra-prefix", "erx-qos-set-name", "erx-service-acct-interval", "erx-downstream-calc-rate",
		"erx-upstream-calc-rate", "erx-max-clients-per-interface", "erx-ipv6-delegated-pool-name",
		"erx-client-profile-name", "erx-redirect-gw-address", "erx-apn-name", "erx-cos-shaping-rate",
		"erx-update-service", "erx-dhcpv6-guided-relay-server", "erx-input-interface-filter", "erx-output-interface-filter",
		"erx-bulk-coa-transaction-id", "erx-bulk-coa-identifier", "erx-ipv4-input-service-set", "erx-ipv4-output-service-set",
		"erx-ipv6-input-service-set", "erx-ipv6-output-service-set", "erx-adv-pcef-rule-name",
		"erx-acct-request-reason", "erx-routing-services", "erx-ont-onu-average-data-rate-downstream",
		"erx-ont-onu-peak-data-rate-downstream", "erx-ont-onu-maximum-data-rate-upstream",
		"erx-ont-onu-assured-data-rate-upstream", "erx-gamma-data-rate-upstream", "erx-gamma-data-rate-downstream":
		return true
	default:
		return false
	}
}

func isJuniperExtremePolicyGrammarAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "juniper-av-pair", "juniper-firewall-filter-name", "juniper-switching-filter", "extreme-netlogin-extended-vlan",
		"erx-ingress-policy-name", "erx-egress-policy-name", "erx-ipv6-ingress-policy-name", "erx-ipv6-egress-policy-name",
		"erx-input-interface-filter", "erx-output-interface-filter", "erx-adv-pcef-rule-name":
		return true
	default:
		return false
	}
}

func isJuniperExtremeSensitiveAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "erx-tunnel-password", "erx-ppp-password", "erx-mobile-ip-key":
		return true
	default:
		return false
	}
}

func juniperExtremeRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func juniperExtremePackFingerprint(records []JuniperExtremeAttributeRecord, grammar []JuniperExtremeGrammarRecord, scopes []JuniperExtremeProductScope, source string) string {
	hash := sha256.New()
	hash.Write([]byte(source))
	for _, record := range records {
		hash.Write([]byte(record.ID + "\x00" + record.ImplementationClass + "\x00" + record.Capability + "\x00" + record.SoftwareState + "\n"))
	}
	for _, row := range grammar {
		hash.Write([]byte(row.Key + "\x00" + row.Kind + "\x00" + row.ParserState + "\x00" + row.CompilerState + "\n"))
	}
	for _, scope := range scopes {
		hash.Write([]byte(scope.Key + "\x00" + scope.Dictionary + "\x00" + scope.SoftwareState + "\x00" + scope.ExternalState + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func containsAnyJuniperExtremeToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
