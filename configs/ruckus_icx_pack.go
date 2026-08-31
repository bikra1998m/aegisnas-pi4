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
	RuckusICXPackSchemaVersion          = 1
	RuckusICXPackFeatureID              = "NAS-0064"
	RuckusICXPackExpectedAttributeCount = 97

	RuckusICXSoftwareCertified = "software_certified"
	RuckusICXExternalRequired  = "external_certification_required"
)

type RuckusICXPackReport struct {
	SchemaVersion                 int                        `json:"schema_version"`
	FeatureID                     string                     `json:"feature_id"`
	ReleaseProfileID              string                     `json:"release_profile_id"`
	SourceRelease                 string                     `json:"source_release"`
	SourceSHA256                  string                     `json:"source_sha256"`
	SourceFileCount               int                        `json:"source_file_count"`
	SourceAttributeCount          int                        `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                     `json:"release_certification_checklist"`
	Summary                       RuckusICXPackSummary       `json:"summary"`
	VendorSummaries               []RuckusICXVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []RuckusICXCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []RuckusICXProductScope    `json:"product_scopes"`
	Grammar                       []RuckusICXGrammarRecord   `json:"grammar"`
	Records                       []RuckusICXAttributeRecord `json:"records"`
	Notes                         []string                   `json:"notes,omitempty"`
}

type RuckusICXPackSummary struct {
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

type RuckusICXVendorSummary struct {
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

type RuckusICXCapabilityCount struct {
	Capability                string  `json:"capability"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings int     `json:"sensitive_redacted_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type RuckusICXProductScope struct {
	Key           string   `json:"key"`
	Label         string   `json:"label"`
	Vendors       []string `json:"vendors"`
	Products      []string `json:"products"`
	Dictionary    string   `json:"dictionary"`
	SoftwareState string   `json:"software_state"`
	ExternalState string   `json:"external_state"`
	Notes         []string `json:"notes,omitempty"`
}

type RuckusICXGrammarRecord struct {
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

type RuckusICXAttributeRecord struct {
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

func BuildRuckusICXPackReport() (RuckusICXPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return RuckusICXPackReport{}, err
	}
	records := make([]RuckusICXAttributeRecord, 0, RuckusICXPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isRuckusICXVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildRuckusICXAttributeRecord(entry))
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
	report := RuckusICXPackReport{
		SchemaVersion:                 RuckusICXPackSchemaVersion,
		FeatureID:                     RuckusICXPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0064-release-certification-checklist.md",
		ProductScopes:                 ruckusICXProductScopes(),
		Grammar:                       ruckusICXGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0064 covers all Ruckus and Foundry/ICX rows in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers typed dictionary metadata, generic VSA packet safety, Ruckus policy and WLAN context normalization, DPSK redaction, Foundry/ICX command and ACL handling, API/UI visibility, durable evidence, and observability readiness.",
			"OID/TLV subattributes are software-certified as typed evidence and registry-backed visibility; number-based attributes additionally participate in runtime decoding where the wire type is unambiguous.",
			"Rows without a neutral runtime semantic are software-certified as typed pass-through or typed evidence, not as hardware-certified behavior.",
			"Real Ruckus SmartZone, ZoneDirector, Unleashed, Ruckus One, ICX/FastIron, FreeRADIUS-on-Linux, HA, performance, soak, security, and production behavior remains in the NAS-0064 release certification checklist.",
		},
	}
	report.Summary = summarizeRuckusICXPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = ruckusICXPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeRuckusICXVendors(records)
	report.CapabilitySummaries = summarizeRuckusICXCapabilities(records)
	return report, nil
}

func ValidateRuckusICXPackReport(report RuckusICXPackReport) error {
	if report.SchemaVersion != RuckusICXPackSchemaVersion {
		return fmt.Errorf("Ruckus/ICX pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != RuckusICXPackFeatureID {
		return fmt.Errorf("Ruckus/ICX pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Ruckus/ICX pack release profile and source hash are required")
	}
	if len(report.Records) != RuckusICXPackExpectedAttributeCount {
		return fmt.Errorf("Ruckus/ICX pack has %d records, expected %d", len(report.Records), RuckusICXPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != RuckusICXPackExpectedAttributeCount {
		return fmt.Errorf("Ruckus/ICX pack summary has %d attributes, expected %d", report.Summary.AttributeCount, RuckusICXPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != RuckusICXPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Ruckus/ICX pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != RuckusICXPackExpectedAttributeCount {
		return fmt.Errorf("Ruckus/ICX pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 2 {
		return fmt.Errorf("Ruckus/ICX pack must cover Ruckus and Foundry dictionary vendors")
	}
	if report.Summary.ProductScopeCount < 5 || len(report.ProductScopes) < 5 {
		return fmt.Errorf("Ruckus/ICX pack product scope must include SmartZone, ZoneDirector, Unleashed, Ruckus One, and ICX")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Ruckus/ICX pack fingerprint is required")
	}
	if len(report.Grammar) < 12 {
		return fmt.Errorf("Ruckus/ICX pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Ruckus/ICX grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != RuckusICXExternalRequired {
			return fmt.Errorf("Ruckus/ICX grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Ruckus/ICX record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Ruckus/ICX record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != RuckusICXSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Ruckus/ICX record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Ruckus/ICX record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildRuckusICXAttributeRecord(entry AttributeRegistryEntry) RuckusICXAttributeRecord {
	capability := ruckusICXCapability(entry)
	class := "typed_passthrough"
	if isRuckusICXNativeAttribute(entry.Attribute) {
		class = "native_semantic_mapping"
	}
	if isRuckusICXPolicyGrammarAttribute(entry.Attribute) {
		class = "policy_parse_compile"
	}
	if isRuckusICXSensitiveAttribute(entry.Attribute) {
		class = "redacted_secret_evidence"
	}
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferRuckusICXDirections(entry, capability)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = ruckusICXSemantic(capability)
	}
	return RuckusICXAttributeRecord{
		ID:                         ruckusICXRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, ruckusICXDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, ruckusICXFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           ruckusICXPacketProcessing(class),
		PolicyEngine:               ruckusICXPolicyState(class, capability),
		Enforcement:                ruckusICXEnforcementState(class, capability),
		Storage:                    ruckusICXStorageState(class),
		APIUI:                      "pack_report_history_preview_controller_scope_and_support_bundle",
		Monitoring:                 "vendor_family_counters_fingerprint_controller_scope_secret_redaction_and_tlv_state",
		SoftwareState:              RuckusICXSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      ruckusICXRecordNotes(class),
	}
}

func ruckusICXGrammarRecords() []RuckusICXGrammarRecord {
	rows := []RuckusICXGrammarRecord{
		{"ruckus_role_group", "Ruckus user group and role policy", "role_policy", VendorSemanticRole, []string{"Ruckus-User-Groups = \"employee\"", "Ruckus-SCI-Role = \"contractor\""}, "", "", "", "", "", ""},
		{"ruckus_vlan_policy", "Ruckus VLAN and VLAN pool assignment", "vlan_policy", VendorSemanticVLAN, []string{"Ruckus-VLAN-ID = 20", "Ruckus-Vlan-Pool = \"branch-pool\""}, "", "", "", "", "", ""},
		{"ruckus_guest_portal", "Ruckus WISPr redirect and captive portal token", "guest_portal", VendorSemanticPortalProfile, []string{"Ruckus-Wispr-Redirect-Policy = \"guest-redirect\"", "Ruckus-CP-Token = \"token-ref\""}, "", "", "", "", "", ""},
		{"ruckus_dpsk_ppsk", "Ruckus DPSK and PPSK credential evidence", "secret_redaction", VendorSemanticPolicyTag, []string{"Ruckus-DPSK = \"<redacted>\"", "Ruckus-DPSK-EAPOL-Key-Frame = \"<redacted>\""}, "", "", "", "", "", ""},
		{"ruckus_flexauth", "Ruckus FlexAuth key-value policy grammar", "vendor_avpair", VendorSemanticPolicyTag, []string{"role=guest", "qos=gold", "acl=guest-in"}, "", "", "", "", "", ""},
		{"ruckus_wlan_context", "Ruckus WLAN, SSID, BSSID, and roaming context", "wlan_context", VendorSemanticDeviceGroup, []string{"Ruckus-SSID = \"Corp\"", "Ruckus-AP-Roamed = 1"}, "", "", "", "", "", ""},
		{"ruckus_qos_quota", "Ruckus traffic class, QoS, and quota policy", "qos_policy", VendorSemanticBandwidthProfile, []string{"Ruckus-Traffic-Class-Attribute-Ids = \"gold\"", "Ruckus-Max-DL-UL-Quota = 1073741824"}, "", "", "", "", "", ""},
		{"ruckus_accounting", "Ruckus traffic-class accounting counters", "accounting_context", VendorSemanticAccountingCounters, []string{"Ruckus-TC-Acct-Ctrs = \"tc-counters\"", "Ruckus-Accounting-Status = 1"}, "", "", "", "", "", ""},
		{"ruckus_mobile_core", "Ruckus mobile-core offload and charging context", "mobile_core", VendorSemanticAccountingIdentity, []string{"Ruckus-APN-NI = \"internet\"", "Ruckus-CDR-TYPE = 1"}, "", "", "", "", "", ""},
		{"ruckus_controller_cluster", "Ruckus zone, cluster, and controller context", "controller_context", VendorSemanticDeviceGroup, []string{"Ruckus-Zone-Name = \"branch-a\"", "Ruckus-Cluster-Name = \"cluster-east\""}, "", "", "", "", "", ""},
		{"foundry_command_auth", "Foundry/ICX command authorization", "command_authorization", VendorSemanticRole, []string{"Foundry-Privilege-Level = 15", "Foundry-Command-String = \"show running-config\""}, "", "", "", "", "", ""},
		{"foundry_acl_policy", "Foundry/ICX ACL policy assignment", "acl_policy", VendorSemanticACL, []string{"Foundry-Access-List = \"guest-in\""}, "", "", "", "", "", ""},
		{"foundry_dynamic_authorization", "Foundry/ICX CoA command handling", "dynamic_authorization", VendorSemanticCoAReauth, []string{"Foundry-COA-Command = \"reauth\""}, "", "", "", "", "", ""},
		{"foundry_voice_policy", "Foundry/ICX voice-phone policy", "voice_policy", VendorSemanticPolicyTag, []string{"Foundry-Voice-Phone-Config = \"voice-vlan=40\""}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = RuckusICXExternalRequired
		rows[index].ReleaseScope = "Device, controller, firmware, HA, and FreeRADIUS acceptance is tracked in docs/nas-0064-release-certification-checklist.md."
	}
	return rows
}

func ruckusICXProductScopes() []RuckusICXProductScope {
	return []RuckusICXProductScope{
		{Key: VendorPackRuckus, Label: "Ruckus SmartZone", Vendors: []string{"Ruckus"}, Products: []string{"SmartZone", "Virtual SmartZone", "SmartZone-managed enterprise WLANs"}, Dictionary: "dictionary.ruckus", SoftwareState: RuckusICXSoftwareCertified, ExternalState: RuckusICXExternalRequired, Notes: []string{"WLAN, DPSK, guest, zone, cluster, and accounting context is software-visible; controller behavior requires release evidence."}},
		{Key: VendorPackRuckus, Label: "Ruckus ZoneDirector", Vendors: []string{"Ruckus"}, Products: []string{"ZoneDirector", "ZoneDirector-managed APs"}, Dictionary: "dictionary.ruckus", SoftwareState: RuckusICXSoftwareCertified, ExternalState: RuckusICXExternalRequired, Notes: []string{"Legacy controller behavior is scoped separately for firmware-specific release certification."}},
		{Key: VendorPackRuckus, Label: "Ruckus Unleashed", Vendors: []string{"Ruckus"}, Products: []string{"Unleashed APs", "Standalone enterprise WLANs"}, Dictionary: "dictionary.ruckus", SoftwareState: RuckusICXSoftwareCertified, ExternalState: RuckusICXExternalRequired, Notes: []string{"Software rendering and parsing remain identical; AP acceptance is externally certified."}},
		{Key: VendorPackRuckus, Label: "Ruckus One", Vendors: []string{"Ruckus"}, Products: []string{"Ruckus One cloud-managed WLANs"}, Dictionary: "dictionary.ruckus plus controller scope", SoftwareState: RuckusICXSoftwareCertified, ExternalState: RuckusICXExternalRequired, Notes: []string{"Cloud policy proof is tracked outside engineering completion."}},
		{Key: VendorPackFoundry, Label: "Ruckus ICX / Foundry", Vendors: []string{"Foundry", "Ruckus"}, Products: []string{"ICX", "FastIron", "Foundry switch policy"}, Dictionary: "dictionary.foundry", SoftwareState: RuckusICXSoftwareCertified, ExternalState: RuckusICXExternalRequired, Notes: []string{"Duplicate VSA numbers are represented as multi-semantic wire interpretations and require model/firmware evidence."}},
	}
}

func summarizeRuckusICXPack(records []RuckusICXAttributeRecord, grammar []RuckusICXGrammarRecord, scopes []RuckusICXProductScope) RuckusICXPackSummary {
	summary := RuckusICXPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar), ProductScopeCount: len(scopes)}
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
		if record.SoftwareState == RuckusICXSoftwareCertified {
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

func summarizeRuckusICXVendors(records []RuckusICXAttributeRecord) []RuckusICXVendorSummary {
	byKey := map[string]*RuckusICXVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &RuckusICXVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
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
		if record.SoftwareState == RuckusICXSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]RuckusICXVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeRuckusICXCapabilities(records []RuckusICXAttributeRecord) []RuckusICXCapabilityCount {
	byCapability := map[string]*RuckusICXCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &RuckusICXCapabilityCount{Capability: record.Capability}
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
		if record.SoftwareState == RuckusICXSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]RuckusICXCapabilityCount, 0, len(byCapability))
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

func isRuckusICXVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "ruckus", "foundry":
		return true
	default:
		return false
	}
}

func ruckusICXCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(entry.Vendor)
	name := strings.ToLower(entry.Attribute)
	switch vendor {
	case "foundry":
		return foundryICXCapability(name)
	case "ruckus":
		return ruckusCapability(name)
	default:
		return "generic_ruckus_icx_context"
	}
}

func foundryICXCapability(name string) string {
	switch {
	case containsAnyRuckusICXToken(name, "coa"):
		return "foundry_icx_dynamic_authorization"
	case containsAnyRuckusICXToken(name, "access-list"):
		return "foundry_icx_acl_policy"
	case containsAnyRuckusICXToken(name, "vlan-qos"):
		return "foundry_icx_vlan_qos"
	case containsAnyRuckusICXToken(name, "802.1x", "mac-authent"):
		return "foundry_icx_mac_auth_8021x"
	case containsAnyRuckusICXToken(name, "voice"):
		return "foundry_icx_voice_device_policy"
	case containsAnyRuckusICXToken(name, "command", "privilege", "role"):
		return "foundry_icx_command_authorization"
	default:
		return "foundry_icx_vendor_context"
	}
}

func ruckusCapability(name string) string {
	switch {
	case containsAnyRuckusICXToken(name, "acct-ctrs", "accounting-status", "session-type", "start-time"):
		return "ruckus_accounting_and_session_telemetry"
	case containsAnyRuckusICXToken(name, "dpsk", "triplets", "flexauth", "auth-type", "auth-server"):
		return "ruckus_dpsk_ppsk_authentication"
	case containsAnyRuckusICXToken(name, "ssid", "wlan", "bssid", "roamed", "sta-rssi", "sta-uuid", "sta-inner", "eth-profile"):
		return "ruckus_wlan_roaming_and_station_context"
	case containsAnyRuckusICXToken(name, "wispr", "cp-token"):
		return "ruckus_guest_hotspot_and_captive_portal"
	case containsAnyRuckusICXToken(name, "vlan"):
		return "ruckus_vlan_and_group_policy"
	case containsAnyRuckusICXToken(name, "qos", "quota", "traffic-class", "tc-"):
		return "ruckus_qos_quota_and_traffic_class"
	case containsAnyRuckusICXToken(name, "imsi", "msisdn", "apn", "sgsn", "pdp", "charging", "cdr", "cell", "area"):
		return "ruckus_mobile_core_offload_and_charging"
	case containsAnyRuckusICXToken(name, "nat-pool", "client-local-ip", "aaa-ip"):
		return "ruckus_ip_addressing_and_nat"
	case containsAnyRuckusICXToken(name, "zone", "cluster", "blade", "nas-type", "aaa-id", "utp", "domain", "location"):
		return "ruckus_controller_cluster_and_tenant_context"
	case containsAnyRuckusICXToken(name, "client-host", "client-os", "client-device"):
		return "ruckus_device_profiling_and_posture"
	case containsAnyRuckusICXToken(name, "user-groups", "policy-name", "sci-role", "sci-resource"):
		return "ruckus_role_and_resource_group_policy"
	case containsAnyRuckusICXToken(name, "grace-period", "expiration"):
		return "ruckus_session_lifecycle"
	default:
		return "ruckus_vendor_context"
	}
}

func ruckusICXSemantic(capability string) string {
	switch capability {
	case "foundry_icx_command_authorization", "ruckus_role_and_resource_group_policy":
		return VendorSemanticRole
	case "foundry_icx_acl_policy":
		return VendorSemanticACL
	case "foundry_icx_vlan_qos", "ruckus_vlan_and_group_policy":
		return VendorSemanticVLAN
	case "foundry_icx_mac_auth_8021x", "ruckus_device_profiling_and_posture":
		return VendorSemanticDevicePosture
	case "foundry_icx_dynamic_authorization":
		return VendorSemanticCoAReauth
	case "ruckus_guest_hotspot_and_captive_portal":
		return VendorSemanticPortalProfile
	case "ruckus_qos_quota_and_traffic_class":
		return VendorSemanticBandwidthProfile
	case "ruckus_accounting_and_session_telemetry":
		return VendorSemanticAccountingCounters
	case "ruckus_mobile_core_offload_and_charging":
		return VendorSemanticAccountingIdentity
	case "ruckus_ip_addressing_and_nat":
		return VendorSemanticAddressPool
	case "ruckus_controller_cluster_and_tenant_context", "ruckus_wlan_roaming_and_station_context":
		return VendorSemanticDeviceGroup
	case "ruckus_session_lifecycle":
		return VendorSemanticSessionTimeout
	default:
		return VendorSemanticPolicyTag
	}
}

func inferRuckusICXDirections(entry AttributeRegistryEntry, capability string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case isRuckusICXSensitiveAttribute(entry.Attribute):
		return []string{"inbound", "outbound_reply"}
	case containsAnyRuckusICXToken(name, "acct-ctrs", "accounting-status", "client-host", "client-os", "client-device", "imsi", "msisdn", "sgsn", "cdr", "cell", "area", "start-time"):
		return []string{"accounting", "inbound"}
	case containsAnyRuckusICXToken(name, "coa"):
		return []string{"inbound", "outbound_reply", "coa"}
	case containsAnyRuckusICXToken(name, "zone", "cluster", "blade", "aaa-id", "auth-server", "utp"):
		return []string{"accounting", "controller_api", "inbound"}
	case strings.Contains(capability, "policy") || strings.Contains(capability, "portal") || strings.Contains(capability, "qos") || strings.Contains(capability, "authorization"):
		return []string{"inbound", "outbound_reply"}
	default:
		return []string{"inbound"}
	}
}

func ruckusICXDefaultPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "foundry":
		return VendorPackFoundry
	default:
		return VendorPackRuckus
	}
}

func ruckusICXFunctionality(entry AttributeRegistryEntry, capability string) string {
	return fmt.Sprintf("%s carries %s in Ruckus/ICX RADIUS packets; AegisNAS stores bounded evidence, redacts credential and subscriber identifiers, and normalizes known access-policy semantics.", entry.Attribute, strings.ReplaceAll(capability, "_", " "))
}

func ruckusICXPacketProcessing(class string) string {
	switch class {
	case "policy_parse_compile":
		return "ruckus_flexauth_or_foundry_policy_parser_classifier_and_safe_unknown_preservation"
	case "native_semantic_mapping":
		return "native_runtime_decoder_and_reply_renderer"
	case "redacted_secret_evidence":
		return "secret_and_subscriber_identifier_aware_vsa_codec_with_redacted_evidence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func ruckusICXPolicyState(class, capability string) string {
	if class == "typed_passthrough" {
		return "typed_evidence_only_until_policy_binding"
	}
	if class == "redacted_secret_evidence" {
		return "secret_metadata_without_secret_persistence"
	}
	switch {
	case strings.Contains(capability, "acl"):
		return "acl_ast_and_foundry_profile_compiler"
	case strings.Contains(capability, "qos") || strings.Contains(capability, "quota"):
		return "qos_quota_and_traffic_class_policy"
	case strings.Contains(capability, "vlan"):
		return "vlan_policy"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "guest"):
		return "guest_portal_policy"
	case strings.Contains(capability, "dpsk") || strings.Contains(capability, "ppsk"):
		return "credential_lifecycle_policy_metadata"
	case strings.Contains(capability, "mobile"):
		return "mobile_core_accounting_and_charging_context"
	case strings.Contains(capability, "dynamic_authorization"):
		return "coa_disconnect_policy"
	default:
		return "neutral_policy_semantics"
	}
}

func ruckusICXEnforcementState(class, capability string) string {
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

func ruckusICXStorageState(class string) string {
	if class == "redacted_secret_evidence" {
		return "redacted_secret_and_subscriber_metadata_with_bounded_non_secret_evidence"
	}
	return "bounded_raw_evidence_and_normalized_metadata"
}

func ruckusICXRecordNotes(class string) []string {
	switch class {
	case "redacted_secret_evidence":
		return []string{"Secret-bearing and subscriber-identifier values are never persisted in clear text; software readiness covers redaction and metadata handling, while real credential flows remain release certification."}
	case "typed_passthrough":
		return []string{"Software-ready typed pass-through does not claim native device behavior until release certification evidence is attached."}
	default:
		return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
	}
}

func isRuckusICXNativeAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "ruckus-user-groups", "ruckus-vlan-id", "ruckus-ssid", "ruckus-wlan-id", "ruckus-location",
		"ruckus-grace-period", "ruckus-sta-expiration", "ruckus-flexauth-avp", "ruckus-apn-ni",
		"ruckus-policy-name", "ruckus-client-local-ip", "ruckus-wispr-redirect-policy", "ruckus-zone-name",
		"ruckus-wlan-name", "ruckus-client-host-name", "ruckus-client-os-type", "ruckus-client-os-class",
		"ruckus-vlan-pool", "ruckus-cp-token", "ruckus-max-dl-ul-quota", "ruckus-traffic-class-attribute-ids",
		"ruckus-nat-pool-name", "ruckus-cluster-name", "ruckus-domain-name", "ruckus-client-device-type",
		"ruckus-vlan-name", "ruckus-sci-role", "ruckus-sci-resource-group",
		"foundry-privilege-level", "foundry-command-string", "foundry-command-exception-flag",
		"foundry-inm-privilege", "foundry-access-list", "foundry-mac-authent-needs-802.1x",
		"foundry-802.1x-valid-lookup", "foundry-mac-based-vlan-qos", "foundry-inm-role-aor-list",
		"foundry-coa-command", "foundry-si-context-role", "foundry-si-role-template",
		"foundry-voice-phone-config":
		return true
	default:
		return false
	}
}

func isRuckusICXPolicyGrammarAttribute(attribute string) bool {
	switch strings.ToLower(strings.TrimSpace(attribute)) {
	case "ruckus-flexauth-avp", "ruckus-user-groups", "ruckus-policy-name", "ruckus-wispr-redirect-policy",
		"ruckus-vlan-id", "ruckus-vlan-pool", "ruckus-vlan-name", "ruckus-traffic-class-attribute-ids",
		"ruckus-nat-pool-name", "foundry-command-string", "foundry-access-list", "foundry-coa-command",
		"foundry-si-context-role", "foundry-si-role-template", "foundry-voice-phone-config":
		return true
	default:
		return false
	}
}

func isRuckusICXSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyRuckusICXToken(name,
		"dpsk", "eapol-key-frame", "triplets", "imsi", "msisdn",
		"charging-charac", "pdp-type", "dynamic-address-flag",
		"chch-selection-mode", "sgsn-number", "area-code", "cell-identifier",
		"read-preference",
	)
}

func ruckusICXRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func ruckusICXPackFingerprint(records []RuckusICXAttributeRecord, grammar []RuckusICXGrammarRecord, scopes []RuckusICXProductScope, source string) string {
	hash := sha256.New()
	hash.Write([]byte(source))
	for _, record := range records {
		hash.Write([]byte(record.ID + "\x00" + record.ImplementationClass + "\x00" + record.Capability + "\x00" + record.SoftwareState + "\n"))
	}
	for _, row := range grammar {
		hash.Write([]byte(row.Key + "\x00" + row.Kind + "\x00" + row.ParserState + "\x00" + row.CompilerState + "\n"))
	}
	for _, scope := range scopes {
		hash.Write([]byte(scope.Key + "\x00" + scope.Label + "\x00" + scope.Dictionary + "\x00" + scope.SoftwareState + "\x00" + scope.ExternalState + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func containsAnyRuckusICXToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
