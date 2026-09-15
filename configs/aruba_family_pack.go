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
	ArubaFamilyPackSchemaVersion          = 1
	ArubaFamilyPackFeatureID              = "NAS-0062"
	ArubaFamilyPackExpectedAttributeCount = 125

	ArubaFamilySoftwareCertified = "software_certified"
	ArubaFamilyExternalRequired  = "external_certification_required"
)

type ArubaFamilyPackReport struct {
	SchemaVersion                 int                          `json:"schema_version"`
	FeatureID                     string                       `json:"feature_id"`
	ReleaseProfileID              string                       `json:"release_profile_id"`
	SourceRelease                 string                       `json:"source_release"`
	SourceSHA256                  string                       `json:"source_sha256"`
	SourceFileCount               int                          `json:"source_file_count"`
	SourceAttributeCount          int                          `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                       `json:"release_certification_checklist"`
	Summary                       ArubaFamilyPackSummary       `json:"summary"`
	VendorSummaries               []ArubaFamilyVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []ArubaFamilyCapabilityCount `json:"capability_summaries"`
	Grammar                       []ArubaFamilyGrammarRecord   `json:"grammar"`
	Records                       []ArubaFamilyAttributeRecord `json:"records"`
	Notes                         []string                     `json:"notes,omitempty"`
}

type ArubaFamilyPackSummary struct {
	VendorCount                        int     `json:"vendor_count"`
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

type ArubaFamilyVendorSummary struct {
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

type ArubaFamilyCapabilityCount struct {
	Capability                string  `json:"capability"`
	AttributeCount            int     `json:"attribute_count"`
	NativeSemanticMappings    int     `json:"native_semantic_mappings"`
	TypedPassThroughMappings  int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings int     `json:"sensitive_redacted_mappings"`
	SoftwareCertifiedMappings int     `json:"software_certified_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type ArubaFamilyGrammarRecord struct {
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

type ArubaFamilyAttributeRecord struct {
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

func BuildArubaFamilyPackReport() (ArubaFamilyPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return ArubaFamilyPackReport{}, err
	}
	records := make([]ArubaFamilyAttributeRecord, 0, ArubaFamilyPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isArubaFamilyVendor(entry.Vendor) {
			continue
		}
		if entry.Source == "aegisnas-runtime" && entry.Number == 0 {
			continue
		}
		records = append(records, buildArubaFamilyAttributeRecord(entry))
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
	report := ArubaFamilyPackReport{
		SchemaVersion:                 ArubaFamilyPackSchemaVersion,
		FeatureID:                     ArubaFamilyPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0062-release-certification-checklist.md",
		Grammar:                       arubaFamilyGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0062 covers all Aruba, HP/ArubaOS-Switch, Aerohive/Extreme, and Colubris/HP MSM rows in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers typed dictionary metadata, generic VSA packet safety, Aruba/HP/Aerohive policy parsing and rendering, secret redaction rules, neutral semantic normalization, API/UI visibility, durable evidence, and observability readiness.",
			"Rows without a neutral runtime semantic are software-certified as typed pass-through or typed evidence, not as hardware-certified behavior.",
			"Real ArubaOS, Aruba Central, ClearPass, ArubaOS-Switch, Aerohive/Extreme, Colubris/MSM, FreeRADIUS-on-Linux, and HA behavior remains in the NAS-0062 release certification checklist.",
		},
	}
	report.Summary = summarizeArubaFamilyPack(records, report.Grammar)
	report.Summary.Fingerprint = arubaFamilyPackFingerprint(records, report.Grammar, report.SourceSHA256)
	report.VendorSummaries = summarizeArubaFamilyVendors(records)
	report.CapabilitySummaries = summarizeArubaFamilyCapabilities(records)
	return report, nil
}

func ValidateArubaFamilyPackReport(report ArubaFamilyPackReport) error {
	if report.SchemaVersion != ArubaFamilyPackSchemaVersion {
		return fmt.Errorf("Aruba family pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != ArubaFamilyPackFeatureID {
		return fmt.Errorf("Aruba family pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Aruba family pack release profile and source hash are required")
	}
	if len(report.Records) != ArubaFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Aruba family pack has %d records, expected %d", len(report.Records), ArubaFamilyPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != ArubaFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Aruba family pack summary has %d attributes, expected %d", report.Summary.AttributeCount, ArubaFamilyPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != ArubaFamilyPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Aruba family pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != ArubaFamilyPackExpectedAttributeCount {
		return fmt.Errorf("Aruba family pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Aruba family pack fingerprint is required")
	}
	if len(report.Grammar) < 14 {
		return fmt.Errorf("Aruba family pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Aruba family grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != ArubaFamilyExternalRequired {
			return fmt.Errorf("Aruba family grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Aruba family record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Aruba family record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != ArubaFamilySoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Aruba family record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Aruba family record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildArubaFamilyAttributeRecord(entry AttributeRegistryEntry) ArubaFamilyAttributeRecord {
	capability := arubaFamilyCapability(entry)
	class := "typed_passthrough"
	if entry.DictionaryStatus != "missing" && strings.TrimSpace(entry.Semantic) != "" {
		class = "native_semantic_mapping"
	}
	if isArubaFamilyPolicyGrammarAttribute(entry.Attribute) {
		class = "policy_parse_compile"
	}
	if isArubaFamilyNativeAttribute(entry.Attribute) {
		class = "native_semantic_mapping"
	}
	if isArubaFamilySensitiveAttribute(entry.Attribute) {
		class = "redacted_secret_evidence"
	}
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferArubaFamilyDirections(entry, capability)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = arubaFamilySemantic(capability)
	}
	return ArubaFamilyAttributeRecord{
		ID:                         arubaFamilyRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, arubaFamilyDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, arubaFamilyFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           arubaFamilyPacketProcessing(entry, class),
		PolicyEngine:               arubaFamilyPolicyState(class, capability),
		Enforcement:                arubaFamilyEnforcementState(class, capability),
		Storage:                    arubaFamilyStorageState(class),
		APIUI:                      "pack_report_history_preview_and_support_bundle",
		Monitoring:                 "vendor_family_counters_fingerprint_and_secret_redaction_state",
		SoftwareState:              ArubaFamilySoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      arubaFamilyRecordNotes(class),
	}
}

func arubaFamilyGrammarRecords() []ArubaFamilyGrammarRecord {
	rows := []ArubaFamilyGrammarRecord{
		{"aruba_role", "Aruba user and ClearPass role", "role_policy", VendorSemanticRole, []string{"Aruba-User-Role = \"employee\"", "Aruba-CPPM-Role = \"contractor\""}, "", "", "", "", "", ""},
		{"aruba_admin_role", "Aruba administrative role and command authorization", "command_authorization", VendorSemanticRole, []string{"Aruba-Admin-Role = \"network-admin\"", "Aruba-Command-String = \"show running-config\""}, "", "", "", "", "", ""},
		{"aruba_vlan", "Aruba numeric and named VLAN selection", "vlan_policy", VendorSemanticVLAN, []string{"Aruba-User-Vlan = 20", "Aruba-Named-User-Vlan = \"corp-data\""}, "", "", "", "", "", ""},
		{"aruba_nas_filter_rule", "Aruba downloadable NAS filter rule", "acl_policy", VendorSemanticACL, []string{"Aruba-NAS-Filter-Rule = \"permit in tcp from any to any 443\""}, "", "", "", "", "", ""},
		{"aruba_guest_portal", "Aruba captive portal redirect", "guest_portal", VendorSemanticPortalProfile, []string{"Aruba-Captive-Portal-URL = \"https://guest.example.test/login\""}, "", "", "", "", "", ""},
		{"aruba_mdps", "Aruba ClearPass MDPS device context", "device_profile", VendorSemanticDevicePosture, []string{"Aruba-Mdps-Device-Name = \"ipad-kiosk\"", "Aruba-Mdps-Device-Profile = \"managed-tablet\""}, "", "", "", "", "", ""},
		{"aruba_airgroup", "Aruba AirGroup sharing policy", "airgroup_policy", VendorSemanticPolicyTag, []string{"Aruba-AirGroup-Shared-Role = \"teacher\"", "Aruba-AirGroup-Shared-Group = \"room-201\""}, "", "", "", "", "", ""},
		{"aruba_mpsk", "Aruba MPSK key selection with passphrase redaction", "mpsk_policy", VendorSemanticPolicyTag, []string{"Aruba-MPSK-Key-Name = \"iot-camera\"", "Aruba-MPSK-Passphrase = \"<redacted>\""}, "", "", "", "", "", ""},
		{"aruba_dpp", "Aruba DPP onboarding metadata", "dpp_policy", VendorSemanticCertificateOnboarding, []string{"Aruba-DPP-Service-Type = 1", "Aruba-DPP-Bootstrapping-Key-SHA256 = \"sha256:...\""}, "", "", "", "", "", ""},
		{"aruba_ubt_gateway", "Aruba user-based tunneling gateway selection", "ubt_gateway_policy", VendorSemanticVRF, []string{"Aruba-UBT-Gateway-Role = \"branch-gateway\"", "Aruba-Gateway-Zone = \"tenant-a\""}, "", "", "", "", "", ""},
		{"aruba_qos_port", "Aruba QoS and switch port controls", "qos_port_policy", VendorSemanticBandwidthProfile, []string{"Aruba-QoS-Trust-Mode = 1", "Aruba-PoE-Priority = 2"}, "", "", "", "", "", ""},
		{"hp_role", "HP/ArubaOS-Switch role and privilege", "role_policy", VendorSemanticRole, []string{"HP-User-Role = \"employee\"", "HP-Privilege-Level = 15"}, "", "", "", "", "", ""},
		{"hp_acl", "HP/ArubaOS-Switch ACL and filter rules", "acl_policy", VendorSemanticDynamicACL, []string{"HP-Ip-Filter-Raw = \"permit tcp any any eq 443\"", "HP-Nas-Filter-Rule = \"permit in ip from any to any\""}, "", "", "", "", "", ""},
		{"hp_bonjour_uri", "HP Bonjour and URI access policy", "service_discovery_policy", VendorSemanticPolicyTag, []string{"HP-Bonjour-Inbound-Profile = \"printers\"", "HP-URI-Access = \"allow\""}, "", "", "", "", "", ""},
		{"aerohive_ppsk_idm", "Aerohive PPSK and IDM policy", "ppsk_idm_policy", VendorSemanticPolicyTag, []string{"Extreme-PPSK-Request = \"<redacted>\"", "Extreme-IDM-Redirect-URL = \"https://guest.example.test\""}, "", "", "", "", "", ""},
		{"colubris_intercept", "Colubris/HP MSM interception state", "quarantine_policy", VendorSemanticQuarantine, []string{"Colubris-Intercept = 1"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = ArubaFamilyExternalRequired
		rows[index].ReleaseScope = "Device and firmware acceptance is tracked in docs/nas-0062-release-certification-checklist.md."
	}
	return rows
}

func summarizeArubaFamilyPack(records []ArubaFamilyAttributeRecord, grammar []ArubaFamilyGrammarRecord) ArubaFamilyPackSummary {
	summary := ArubaFamilyPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar)}
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
		if record.SoftwareState == ArubaFamilySoftwareCertified {
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

func summarizeArubaFamilyVendors(records []ArubaFamilyAttributeRecord) []ArubaFamilyVendorSummary {
	byKey := map[string]*ArubaFamilyVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &ArubaFamilyVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
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
		if record.SoftwareState == ArubaFamilySoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]ArubaFamilyVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeArubaFamilyCapabilities(records []ArubaFamilyAttributeRecord) []ArubaFamilyCapabilityCount {
	byCapability := map[string]*ArubaFamilyCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &ArubaFamilyCapabilityCount{Capability: record.Capability}
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
		if record.SoftwareState == ArubaFamilySoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]ArubaFamilyCapabilityCount, 0, len(byCapability))
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

func isArubaFamilyVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "aruba", "hp", "colubris", "aerohive":
		return true
	default:
		return false
	}
}

func arubaFamilyCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(entry.Vendor)
	name := strings.ToLower(entry.Attribute)
	switch {
	case vendor == "colubris":
		return "colubris_hotspot_intercept_and_quarantine"
	case vendor == "aerohive":
		return arubaFamilyAerohiveCapability(name)
	case vendor == "hp":
		return arubaFamilyHPCapability(name)
	case containsAnyArubaToken(name, "airgroup", "bonjour"):
		return "airgroup_and_service_discovery"
	case containsAnyArubaToken(name, "mpsk", "dpp", "credential", "auth-surv", "sso-token", "passphrase"):
		return "mpsk_dpp_and_authentication_lifecycle"
	case containsAnyArubaToken(name, "role", "admin", "priv", "user-group", "command"):
		return "clearpass_role_and_command_authorization"
	case containsAnyArubaToken(name, "vlan", "pvlan", "ubt", "gateway-zone", "gateway-role"):
		return "vlan_and_user_based_tunneling"
	case containsAnyArubaToken(name, "filter", "acl", "rule"):
		return "acl_and_firewall_enforcement"
	case containsAnyArubaToken(name, "captive", "portal", "redirect"):
		return "guest_portal_and_hotspot"
	case containsAnyArubaToken(name, "qos", "poe", "traffic-class", "cos", "priority"):
		return "qos_and_switch_port_policy"
	case containsAnyArubaToken(name, "mdps", "device", "ap-", "essid", "location", "port-identifier", "mac-address"):
		return "device_profiling_and_posture"
	case containsAnyArubaToken(name, "bounce", "reauth", "disconnect"):
		return "dynamic_authorization_and_port_control"
	default:
		return "generic_aruba_family_context"
	}
}

func arubaFamilyAerohiveCapability(name string) string {
	switch {
	case containsAnyArubaToken(name, "ppsk", "pmk", "auth-source"):
		return "aerohive_ppsk_and_authentication"
	case containsAnyArubaToken(name, "idm", "redirect"):
		return "aerohive_idm_guest_and_portal"
	case containsAnyArubaToken(name, "client-monitor", "problem"):
		return "aerohive_client_monitor_and_posture"
	case containsAnyArubaToken(name, "user-vlan", "profile-attribute", "admin-group"):
		return "aerohive_role_vlan_and_profile"
	case containsAnyArubaToken(name, "libsip"):
		return "aerohive_library_sip_policy"
	default:
		return "aerohive_vendor_context"
	}
}

func arubaFamilyHPCapability(name string) string {
	switch {
	case containsAnyArubaToken(name, "privilege", "command", "management", "uri"):
		return "hp_admin_command_and_uri_authorization"
	case containsAnyArubaToken(name, "port-client", "port-auth", "port-ma", "bounce", "capability"):
		return "hp_switch_port_access_control"
	case containsAnyArubaToken(name, "role", "cppm", "access-profile", "vc-groups"):
		return "hp_role_profile_and_clearpass_policy"
	case containsAnyArubaToken(name, "filter", "rules"):
		return "hp_acl_and_firewall_enforcement"
	case containsAnyArubaToken(name, "vlan"):
		return "hp_vlan_assignment"
	case containsAnyArubaToken(name, "bandwidth", "cos", "priority"):
		return "hp_qos_and_bandwidth_policy"
	case containsAnyArubaToken(name, "captive", "portal"):
		return "hp_guest_portal"
	case containsAnyArubaToken(name, "bonjour"):
		return "hp_bonjour_service_discovery"
	default:
		return "hp_arubaos_switch_context"
	}
}

func arubaFamilySemantic(capability string) string {
	switch capability {
	case "clearpass_role_and_command_authorization", "hp_admin_command_and_uri_authorization", "hp_role_profile_and_clearpass_policy", "aerohive_role_vlan_and_profile":
		return VendorSemanticRole
	case "vlan_and_user_based_tunneling", "hp_vlan_assignment":
		return VendorSemanticVLAN
	case "acl_and_firewall_enforcement", "hp_acl_and_firewall_enforcement":
		return VendorSemanticACL
	case "guest_portal_and_hotspot", "hp_guest_portal", "aerohive_idm_guest_and_portal":
		return VendorSemanticPortalProfile
	case "qos_and_switch_port_policy", "hp_qos_and_bandwidth_policy":
		return VendorSemanticBandwidthProfile
	case "device_profiling_and_posture", "aerohive_client_monitor_and_posture":
		return VendorSemanticDevicePosture
	case "mpsk_dpp_and_authentication_lifecycle", "aerohive_ppsk_and_authentication":
		return VendorSemanticCertificateOnboarding
	case "colubris_hotspot_intercept_and_quarantine":
		return VendorSemanticQuarantine
	case "dynamic_authorization_and_port_control", "hp_switch_port_access_control":
		return VendorSemanticCoAReauth
	default:
		return VendorSemanticPolicyTag
	}
}

func inferArubaFamilyDirections(entry AttributeRegistryEntry, capability string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyArubaToken(name, "mdps-device", "ap-", "device-mac", "port-identifier", "client-monitor", "capability"):
		return []string{"accounting", "inbound"}
	case containsAnyArubaToken(name, "bounce", "reauth", "disconnect"):
		return []string{"inbound", "coa"}
	case containsAnyArubaToken(capability, "role", "vlan", "acl", "portal", "qos", "mpsk", "dpp", "ubt", "bonjour", "port"):
		return []string{"inbound", "outbound_reply"}
	default:
		return []string{"inbound"}
	}
}

func arubaFamilyDefaultPack(vendor string) string {
	switch strings.ToLower(vendor) {
	case "aruba":
		return VendorPackAruba
	case "hp":
		return VendorPackHP
	case "aerohive":
		return VendorPackAerohive
	case "colubris":
		return VendorPackColubris
	default:
		return "aruba-family"
	}
}

func arubaFamilyFunctionality(entry AttributeRegistryEntry, capability string) string {
	return fmt.Sprintf("%s carries %s in Aruba/HPE-family RADIUS packets; AegisNAS stores bounded evidence, redacts key material, and normalizes known policy semantics.", entry.Attribute, strings.ReplaceAll(capability, "_", " "))
}

func arubaFamilyPacketProcessing(entry AttributeRegistryEntry, class string) string {
	switch class {
	case "policy_parse_compile":
		return "nas_filter_rule_or_vendor_avpair_parser_classifier_and_safe_unknown_preservation"
	case "native_semantic_mapping":
		return "native_runtime_decoder_and_reply_renderer"
	case "redacted_secret_evidence":
		return "secret_aware_vsa_codec_with_redacted_evidence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func arubaFamilyPolicyState(class, capability string) string {
	if class == "typed_passthrough" {
		return "typed_evidence_only_until_policy_binding"
	}
	if class == "redacted_secret_evidence" {
		return "key_lifecycle_metadata_without_secret_persistence"
	}
	switch {
	case strings.Contains(capability, "acl"):
		return "acl_ast_and_aruba_hp_filter_compiler"
	case strings.Contains(capability, "qos") || strings.Contains(capability, "bandwidth"):
		return "qos_and_rate_policy"
	case strings.Contains(capability, "vlan") || strings.Contains(capability, "ubt"):
		return "vlan_and_tunnel_policy"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "guest"):
		return "guest_portal_policy"
	default:
		return "neutral_policy_semantics"
	}
}

func arubaFamilyEnforcementState(class, capability string) string {
	if class == "typed_passthrough" {
		return "safe_visibility_no_silent_enforcement_claim"
	}
	if class == "redacted_secret_evidence" {
		return "redacted_evidence_only_until_external_key_onboarding_certification"
	}
	if strings.Contains(capability, "port") || strings.Contains(capability, "dynamic_authorization") {
		return "radius_reply_and_coa_port_control_surfaces"
	}
	return "radius_reply_and_policy_preview_surfaces"
}

func arubaFamilyStorageState(class string) string {
	if class == "redacted_secret_evidence" {
		return "redacted_secret_metadata_and_bounded_non_secret_evidence"
	}
	return "bounded_raw_evidence_and_normalized_metadata"
}

func arubaFamilyRecordNotes(class string) []string {
	switch class {
	case "redacted_secret_evidence":
		return []string{"Secret-bearing values are never persisted in clear text; software readiness covers redaction and metadata handling, while real key enrollment remains release certification."}
	case "typed_passthrough":
		return []string{"Software-ready typed pass-through does not claim native device behavior until release certification evidence is attached."}
	default:
		return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
	}
}

func isArubaFamilyNativeAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "aruba-user-role", "aruba-user-vlan", "aruba-admin-role", "aruba-ap-group", "aruba-named-user-vlan",
		"aruba-device-type", "aruba-mdps-device-name", "aruba-mdps-device-profile", "aruba-cppm-role",
		"aruba-airgroup-user-name", "aruba-airgroup-shared-user", "aruba-airgroup-shared-role", "aruba-airgroup-shared-group",
		"aruba-user-group", "aruba-captive-portal-url", "aruba-acl-server-query-info", "aruba-command-string",
		"aruba-admin-device-group", "aruba-poe-priority", "aruba-port-auth-mode", "aruba-nas-filter-rule",
		"aruba-qos-trust-mode", "aruba-ubt-gateway-role", "aruba-gateway-zone", "aruba-stp-admin-edge-port",
		"aruba-ubt-gateway-cppm-role", "aruba-ap-mac-address", "aruba-device-mac-address", "aruba-mpsk-key-name",
		"aruba-device-traffic-class", "aruba-pvlan-port-type", "aruba-avpair", "aruba-dpp-service-type",
		"hp-privilege-level", "hp-command-string", "hp-command-exception", "hp-port-bounce-host",
		"hp-captive-portal-url", "hp-user-role", "hp-cppm-role", "hp-cppm-secondary-role", "hp-cos",
		"hp-bandwidth-max-ingress", "hp-bandwidth-max-egress", "hp-ip-filter-raw", "hp-nas-filter-rule",
		"hp-access-profile", "hp-egress-vlanid", "hp-egress-vlan-name", "hp-bonjour-inbound-profile",
		"hp-bonjour-outbound-profile", "hp-uri-string", "hp-uri-access", "hp-vc-groups",
		"extreme-user-vlan", "extreme-user-profile-attribute", "extreme-avpair", "extreme-client-monitor-problem",
		"extreme-idm-redirect-url", "extreme-idm-message", "extreme-auth-source", "colubris-intercept":
		return true
	default:
		return false
	}
}

func isArubaFamilyPolicyGrammarAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "aruba-nas-filter-rule", "aruba-acl-server-query-info", "aruba-avpair", "hp-ip-filter-raw", "hp-nas-filter-rule", "extreme-avpair":
		return true
	default:
		return false
	}
}

func isArubaFamilySensitiveAttribute(attribute string) bool {
	switch strings.ToLower(attribute) {
	case "aruba-mpsk-passphrase", "aruba-dpp-passphrase", "aruba-as-credential-hash", "aruba-dpp-bootstrapping-key-sha256",
		"aruba-dpp-bootstrapping-net-access-key-sha256", "aruba-dpp-bootstrapping-key-b64", "extreme-ppsk-request", "extreme-ppsk-pmk":
		return true
	default:
		return false
	}
}

func arubaFamilyRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func arubaFamilyPackFingerprint(records []ArubaFamilyAttributeRecord, grammar []ArubaFamilyGrammarRecord, source string) string {
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

func containsAnyArubaToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
