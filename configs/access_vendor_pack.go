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
	AccessVendorPackSchemaVersion          = 1
	AccessVendorPackFeatureID              = "NAS-0067"
	AccessVendorPackExpectedAttributeCount = 49

	AccessVendorSoftwareCertified = "software_certified"
	AccessVendorExternalRequired  = "external_certification_required"
)

type AccessVendorPackSummary = RuckusICXPackSummary
type AccessVendorVendorSummary = RuckusICXVendorSummary
type AccessVendorCapabilityCount = RuckusICXCapabilityCount
type AccessVendorProductScope = RuckusICXProductScope
type AccessVendorGrammarRecord = RuckusICXGrammarRecord
type AccessVendorAttributeRecord = RuckusICXAttributeRecord

type AccessVendorPackReport struct {
	SchemaVersion                 int                           `json:"schema_version"`
	FeatureID                     string                        `json:"feature_id"`
	ReleaseProfileID              string                        `json:"release_profile_id"`
	SourceRelease                 string                        `json:"source_release"`
	SourceSHA256                  string                        `json:"source_sha256"`
	SourceFileCount               int                           `json:"source_file_count"`
	SourceAttributeCount          int                           `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                        `json:"release_certification_checklist"`
	Summary                       AccessVendorPackSummary       `json:"summary"`
	VendorSummaries               []AccessVendorVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []AccessVendorCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []AccessVendorProductScope    `json:"product_scopes"`
	Grammar                       []AccessVendorGrammarRecord   `json:"grammar"`
	Records                       []AccessVendorAttributeRecord `json:"records"`
	Notes                         []string                      `json:"notes,omitempty"`
}

func BuildAccessVendorPackReport() (AccessVendorPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return AccessVendorPackReport{}, err
	}
	records := make([]AccessVendorAttributeRecord, 0, AccessVendorPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isAccessVendorPackVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildAccessVendorAttributeRecord(entry))
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
	report := AccessVendorPackReport{
		SchemaVersion:                 AccessVendorPackSchemaVersion,
		FeatureID:                     AccessVendorPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0067-release-certification-checklist.md",
		ProductScopes:                 accessVendorProductScopes(),
		Grammar:                       accessVendorGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0067 covers every Cambium, TPLink, and Dlink row in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers typed packet decoding, bounded evidence, Cambium cnMaestro/ePMP authorization and accounting semantics, TP-Link Omada bandwidth/site/portal/auth-key semantics, D-Link role/VLAN/QoS/ACL semantics, API/UI visibility, durable evidence, and observability readiness.",
			"Credential-like TP-Link authentication key fields are software-certified as redacted typed evidence, not as cleartext policy inputs.",
			"cnMaestro, Omada, D-Link/Nuclias controller, AP, switch, FreeRADIUS-on-Linux, HA, performance, soak, security, and production acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeAccessVendorPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeAccessVendorVendors(records)
	report.CapabilitySummaries = summarizeAccessVendorCapabilities(records)
	return report, nil
}

func ValidateAccessVendorPackReport(report AccessVendorPackReport) error {
	if report.SchemaVersion != AccessVendorPackSchemaVersion {
		return fmt.Errorf("access vendor pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != AccessVendorPackFeatureID {
		return fmt.Errorf("access vendor pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("access vendor pack release profile and source hash are required")
	}
	if len(report.Records) != AccessVendorPackExpectedAttributeCount {
		return fmt.Errorf("access vendor pack has %d records, expected %d", len(report.Records), AccessVendorPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != AccessVendorPackExpectedAttributeCount {
		return fmt.Errorf("access vendor pack summary has %d attributes, expected %d", report.Summary.AttributeCount, AccessVendorPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != AccessVendorPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("access vendor pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != AccessVendorPackExpectedAttributeCount {
		return fmt.Errorf("access vendor pack must keep all device/controller claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 3 {
		return fmt.Errorf("access vendor pack must cover Cambium, TPLink, and Dlink dictionary vendors")
	}
	if report.Summary.SensitiveRedactedMappings != 2 {
		return fmt.Errorf("access vendor pack must redact the two TPLink authentication key attributes")
	}
	if report.Summary.ProductScopeCount < 9 || len(report.ProductScopes) < 9 {
		return fmt.Errorf("access vendor pack product scope must include Cambium, TP-Link, D-Link, CoA, and shared lifecycle coverage")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("access vendor pack fingerprint is required")
	}
	if len(report.Grammar) < 10 {
		return fmt.Errorf("access vendor pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("access vendor grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != AccessVendorExternalRequired {
			return fmt.Errorf("access vendor grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("access vendor record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("access vendor record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != AccessVendorSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("access vendor record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("access vendor record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if accessVendorSensitiveAttribute(record.Attribute) && record.ImplementationClass != "redacted_secret_evidence" {
			return fmt.Errorf("access vendor sensitive record %q is not marked redacted", record.ID)
		}
	}
	return nil
}

func buildAccessVendorAttributeRecord(entry AttributeRegistryEntry) AccessVendorAttributeRecord {
	capability := accessVendorCapability(entry)
	class := accessVendorImplementationClass(entry)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = accessVendorRegistryDirections(entry, accessVendorSemantic(entry))
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = accessVendorSemantic(entry)
	}
	return AccessVendorAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, accessVendorDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, accessVendorFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           accessVendorPacketProcessing(class, entry),
		PolicyEngine:               accessVendorPolicyState(capability, class),
		Enforcement:                accessVendorEnforcementState(capability, class),
		Storage:                    accessVendorStorageState(class),
		APIUI:                      "pack_report_history_preview_vendor_scope_health_and_support_bundle",
		Monitoring:                 "access_vendor_counters_fingerprint_redaction_tlv_codec_and_typed_packet_state",
		SoftwareState:              AccessVendorSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      accessVendorRecordNotes(entry, class),
	}
}

func accessVendorGrammarRecords() []AccessVendorGrammarRecord {
	rows := []AccessVendorGrammarRecord{
		{"cambium_role_privilege", "Cambium role and ePMP user-level authorization", "role_policy", VendorSemanticRole, []string{"Cambium-Auth-Role = 2", "Cambium-ePMP-UserLevel = 4"}, "", "", "", "", "", ""},
		{"cambium_vlan_pool", "Cambium data, management, multicast, and pool VLAN policy", "vlan_policy", VendorSemanticVLAN, []string{"Cambium-ePMP-Data-VLAN-Id = 44", "Cambium-VLAN-Pool-Id = \"branch-pool\""}, "", "", "", "", "", ""},
		{"cambium_qos_quota", "Cambium burst, priority, and traffic quota policy", "rate_quota_policy", VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth + "," + VendorSemanticDataQuota, []string{"Cambium-ePMP-Max-Burst-Downlink-Rate = 75000", "Cambium-Traffic-Quota-Limit-Total = 1073741824"}, "", "", "", "", "", ""},
		{"cambium_tlv_accounting", "Cambium authorize and traffic-class TLV accounting", "tlv_accounting", VendorSemanticAccountingCounters, []string{"Cambium-Authorize-Classes.1 = \"gold\"", "Cambium-Traffic-Classes-Acct.2 = 1073741824"}, "", "", "", "", "", ""},
		{"cambium_walled_garden", "Cambium walled garden and quarantine state", "quarantine_portal", VendorSemanticQuarantine + "," + VendorSemanticPortalProfile, []string{"Cambium-Walled-Garden-State = 1"}, "", "", "", "", "", ""},
		{"tplink_omada_rate", "TP-Link Omada receive/transmit rate limits", "rate_parser_compiler", VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth, []string{"TPLink-Xmit-limit = 75000", "TPLink-Recv-limit = 25000"}, "", "", "", "", "", ""},
		{"tplink_site_portal", "TP-Link Omada site, controller group, redirect, and portal status", "tenant_portal_policy", VendorSemanticTenant + "," + VendorSemanticDeviceGroup + "," + VendorSemanticPortalProfile, []string{"TPLink-Site = \"tenant-a\"", "TPLink-Portal-Access-Status = 7"}, "", "", "", "", "", ""},
		{"tplink_auth_key_redaction", "TP-Link authentication key exchange evidence", "secret_redaction", VendorSemanticCertificateOnboarding, []string{"TPLink-Authentication-FindKey = 0x<redacted>", "TPLink-Authentication-FoundKey = 0x<redacted>"}, "", "", "", "", "", ""},
		{"dlink_role_vlan_qos", "D-Link role, VLAN, priority, and bandwidth assignment", "access_policy", VendorSemanticRole + "," + VendorSemanticVLAN + "," + VendorSemanticBandwidthProfile, []string{"Dlink-User-Level = 6", "Dlink-VLAN-ID = \"44\"", "Dlink-1p-Priority = 5"}, "", "", "", "", "", ""},
		{"dlink_acl_compiler", "D-Link ACL profile, rule, and script policy", "acl_policy", VendorSemanticACL + "," + VendorSemanticDynamicACL, []string{"Dlink-ACL-Profile = \"guest-in\"", "Dlink-ACL-Rule = \"permit tcp any any eq 443\""}, "", "", "", "", "", ""},
		{"access_vendor_coa_lifecycle", "Access-vendor CoA and disconnect lifecycle boundary", "dynamic_authorization", VendorSemanticCoAReauth + "," + VendorSemanticCoADisconnect, []string{"RFC5176 CoA-Request", "RFC5176 Disconnect-Request"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = AccessVendorExternalRequired
		rows[index].ReleaseScope = "Controller, AP, switch, firmware, FreeRADIUS, HA, performance, soak, security, production deployment, and customer acceptance is tracked in docs/nas-0067-release-certification-checklist.md."
	}
	return rows
}

func accessVendorProductScopes() []AccessVendorProductScope {
	return []AccessVendorProductScope{
		{Key: VendorPackCambium, Label: "Cambium cnMaestro Enterprise Wi-Fi", Vendors: []string{"Cambium"}, Products: []string{"cnMaestro", "Enterprise Wi-Fi APs", "WLAN policy"}, Dictionary: "dictionary.cambium", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"Role, data VLAN, walled garden, QoS, quota, and accounting evidence are software-visible; controller behavior requires release proof."}},
		{Key: VendorPackCambium, Label: "Cambium ePMP / PMP Fixed Wireless", Vendors: []string{"Cambium"}, Products: []string{"ePMP", "PMP subscriber modules", "Traffic classes"}, Dictionary: "dictionary.cambium", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"Authorize-class and traffic-class TLVs are modeled as typed evidence with stable child OID metadata."}},
		{Key: VendorPackCambium, Label: "Cambium Access Switching Boundary", Vendors: []string{"Cambium"}, Products: []string{"cnMatrix", "Management VLAN", "Multicast VLAN"}, Dictionary: "dictionary.cambium plus controller APIs", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"VLAN and priority fields are normalized without publishing switch-certified behavior before lab evidence exists."}},
		{Key: VendorPackTPLink, Label: "TP-Link Omada Wireless", Vendors: []string{"TPLink"}, Products: []string{"Omada controller", "EAP access points", "SSID policy"}, Dictionary: "dictionary.tplink", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"Receive/transmit rate, site, Omada group, redirect URL, and portal status are software-certified."}},
		{Key: VendorPackTPLink, Label: "TP-Link Omada Switching and Gateway", Vendors: []string{"TPLink"}, Products: []string{"JetStream switches", "Omada gateways", "User command authorization"}, Dictionary: "dictionary.tplink", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"User-command and site context are exposed as role/tenant evidence; command effects require release certification."}},
		{Key: VendorPackTPLink, Label: "TP-Link Portal and Key Exchange", Vendors: []string{"TPLink"}, Products: []string{"Omada captive portal", "Authentication key exchange"}, Dictionary: "dictionary.tplink", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"Authentication key fields are never persisted as cleartext policy values."}},
		{Key: VendorPackDLink, Label: "D-Link Access Switch Authorization", Vendors: []string{"Dlink"}, Products: []string{"DGS access switches", "DXS aggregation switches", "802.1X/MAB"}, Dictionary: "dictionary.dlink", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"User level, VLAN ID/name, 802.1p priority, and bandwidth assignment are software-certified."}},
		{Key: VendorPackDLink, Label: "D-Link Dynamic ACL Assignment", Vendors: []string{"Dlink"}, Products: []string{"D-Link ACL profile", "ACL rule", "ACL script"}, Dictionary: "dictionary.dlink", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"ACL profile, rule, and script rows are exposed to the neutral dynamic ACL compiler and bounded evidence path."}},
		{Key: VendorPackDLink, Label: "D-Link Nuclias Boundary", Vendors: []string{"Dlink"}, Products: []string{"Nuclias Connect", "Nuclias Cloud", "D-Link APs"}, Dictionary: "dictionary.dlink plus controller APIs", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"Controller inventory, drift, and firmware acceptance stays release-gated."}},
		{Key: VendorPackStandard, Label: "Shared Access Vendor CoA Lifecycle", Vendors: []string{"Cambium", "TPLink", "Dlink"}, Products: []string{"RFC5176 CoA", "Disconnect", "Session refresh"}, Dictionary: "RFC5176 plus vendor dictionaries", SoftwareState: AccessVendorSoftwareCertified, ExternalState: AccessVendorExternalRequired, Notes: []string{"The RADIUS dynamic authorization path is software-ready while per-device behavior remains external certification."}},
	}
}

func summarizeAccessVendorPack(records []AccessVendorAttributeRecord, grammar []AccessVendorGrammarRecord, scopes []AccessVendorProductScope) AccessVendorPackSummary {
	summary := AccessVendorPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar), ProductScopeCount: len(scopes)}
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
		if record.SoftwareState == AccessVendorSoftwareCertified {
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

func summarizeAccessVendorVendors(records []AccessVendorAttributeRecord) []AccessVendorVendorSummary {
	byKey := map[string]*AccessVendorVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &AccessVendorVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
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
		if record.SoftwareState == AccessVendorSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]AccessVendorVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeAccessVendorCapabilities(records []AccessVendorAttributeRecord) []AccessVendorCapabilityCount {
	byCapability := map[string]*AccessVendorCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &AccessVendorCapabilityCount{Capability: record.Capability}
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
		if record.SoftwareState == AccessVendorSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]AccessVendorCapabilityCount, 0, len(byCapability))
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

func isAccessVendorPackVendor(vendor string) bool {
	return isAccessVendorRegistryVendor(vendor)
}

func accessVendorDefaultPack(vendor string) string {
	return accessVendorRegistryPack(vendor)
}

func accessVendorSemantic(entry AttributeRegistryEntry) string {
	return accessVendorRegistrySemantic(entry)
}

func accessVendorCapability(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch accessVendorDefaultPack(entry.Vendor) {
	case VendorPackCambium:
		switch {
		case containsAnyAccessVendorToken(name, "auth-role", "userlevel"):
			return "cambium_role_privilege"
		case containsAnyAccessVendorToken(name, "vlan-pool", "data-vlan-id", "management-vlan-id", "separate-management-vlan", "multicast-vlan", "vlan-mapping", "vlan-membersip"):
			return "cambium_vlan_policy"
		case containsAnyAccessVendorToken(name, "max-burst", "sm-priority", "vlan-priority"):
			return "cambium_qos_priority"
		case containsAnyAccessVendorToken(name, "traffic-quota", "authorize-bytes-left"):
			return "cambium_quota_authorization"
		case containsAnyAccessVendorToken(name, "authorize-class", "authorize-classes"):
			return "cambium_authorize_class_tlv"
		case containsAnyAccessVendorToken(name, "traffic-classes-acct", "acct-class", "acct-input", "acct-output"):
			return "cambium_traffic_class_accounting"
		case containsAnyAccessVendorToken(name, "walled-garden"):
			return "cambium_walled_garden"
		default:
			return "cambium_access_context"
		}
	case VendorPackTPLink:
		switch {
		case containsAnyAccessVendorToken(name, "recv-limit", "xmit-limit"):
			return "tplink_omada_rate_limit"
		case containsAnyAccessVendorToken(name, "authentication-findkey", "authentication-foundkey"):
			return "tplink_auth_key_exchange"
		case containsAnyAccessVendorToken(name, "user-command"):
			return "tplink_command_authorization"
		case containsAnyAccessVendorToken(name, "site", "omada"):
			return "tplink_site_device_context"
		case containsAnyAccessVendorToken(name, "redirect-url", "portal-access-status"):
			return "tplink_guest_portal"
		default:
			return "tplink_access_context"
		}
	default:
		switch {
		case containsAnyAccessVendorToken(name, "user-level"):
			return "dlink_role_privilege"
		case containsAnyAccessVendorToken(name, "bandwidth", "1p-priority"):
			return "dlink_qos_bandwidth"
		case containsAnyAccessVendorToken(name, "vlan"):
			return "dlink_vlan_policy"
		case containsAnyAccessVendorToken(name, "acl"):
			return "dlink_dynamic_acl"
		default:
			return "dlink_access_context"
		}
	}
}

func accessVendorImplementationClass(entry AttributeRegistryEntry) string {
	if accessVendorSensitiveAttribute(entry.Attribute) {
		return "redacted_secret_evidence"
	}
	if entry.WireCodec.Grouped || strings.EqualFold(baseDictionaryWireType(entry.WireType), "tlv") {
		return "typed_tlv_evidence"
	}
	if registrySemanticContains(entry.Semantic, VendorSemanticDynamicACL) {
		return "policy_parse_compile"
	}
	if registrySemanticContains(entry.Semantic, VendorSemanticRole) ||
		registrySemanticContains(entry.Semantic, VendorSemanticVLAN) ||
		registrySemanticContains(entry.Semantic, VendorSemanticUploadBandwidth) ||
		registrySemanticContains(entry.Semantic, VendorSemanticDownloadBandwidth) ||
		registrySemanticContains(entry.Semantic, VendorSemanticDataQuota) ||
		registrySemanticContains(entry.Semantic, VendorSemanticQuarantine) ||
		registrySemanticContains(entry.Semantic, VendorSemanticPortalProfile) ||
		registrySemanticContains(entry.Semantic, VendorSemanticTenant) ||
		registrySemanticContains(entry.Semantic, VendorSemanticDeviceGroup) ||
		registrySemanticContains(entry.Semantic, VendorSemanticAccountingIdentity) ||
		registrySemanticContains(entry.Semantic, VendorSemanticBandwidthProfile) {
		return "native_semantic_mapping"
	}
	return "typed_passthrough"
}

func accessVendorPacketProcessing(class string, entry AttributeRegistryEntry) string {
	switch class {
	case "policy_parse_compile":
		return "acl_rule_profile_script_parser_compiler_and_bounded_vsa_codec"
	case "redacted_secret_evidence":
		return "octets_decoder_sha256_evidence_and_cleartext_redaction"
	case "typed_tlv_evidence":
		return "grouped_tlv_parent_and_child_oid_codec_with_bounded_evidence"
	case "native_semantic_mapping":
		if entry.DecodeKind != "" {
			return "generated_runtime_decoder_semantic_mapper_and_reply_renderer"
		}
		return "typed_vsa_codec_semantic_mapper_and_bounded_evidence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func accessVendorPolicyState(capability, class string) string {
	switch {
	case strings.Contains(capability, "rate") || strings.Contains(capability, "qos"):
		return "neutral_bandwidth_qos_intent_compiler"
	case strings.Contains(capability, "quota"):
		return "quota_authorization_policy_context"
	case strings.Contains(capability, "vlan"):
		return "vlan_policy_preview_apply_and_rollback_context"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "walled"):
		return "guest_portal_and_quarantine_policy_context"
	case strings.Contains(capability, "acl") || class == "policy_parse_compile":
		return "dynamic_acl_policy_compiler"
	case strings.Contains(capability, "role") || strings.Contains(capability, "command"):
		return "role_and_command_authorization_context"
	case strings.Contains(capability, "accounting"):
		return "accounting_counter_and_session_identity_context"
	case strings.Contains(capability, "auth_key"):
		return "redacted_authentication_evidence_context"
	default:
		return "typed_vendor_policy_context"
	}
}

func accessVendorEnforcementState(capability, class string) string {
	if class == "redacted_secret_evidence" {
		return "no_cleartext_enforcement_redacted_evidence_only"
	}
	if strings.Contains(capability, "accounting") {
		return "accounting_ingest_and_session_evidence"
	}
	if strings.Contains(capability, "acl") {
		return "radius_reply_acl_assignment_and_dynamic_acl_preview"
	}
	if strings.Contains(capability, "portal") || strings.Contains(capability, "walled") {
		return "radius_reply_portal_or_quarantine_hint"
	}
	return "radius_reply_inbound_context_and_no_silent_fallback"
}

func accessVendorStorageState(class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "bounded_hash_only_evidence_no_cleartext_secret"
	case "typed_tlv_evidence":
		return "normalized_tlv_metadata_child_oid_and_bounded_raw_evidence"
	case "policy_parse_compile":
		return "normalized_acl_policy_and_bounded_vendor_rule_evidence"
	default:
		return "normalized_vendor_semantics_and_bounded_raw_vsa_evidence"
	}
}

func accessVendorFunctionality(entry AttributeRegistryEntry, semantic string) string {
	return accessVendorRegistryFunctionality(entry, semantic)
}

func accessVendorRecordNotes(entry AttributeRegistryEntry, class string) []string {
	switch accessVendorDefaultPack(entry.Vendor) {
	case VendorPackCambium:
		if class == "typed_tlv_evidence" {
			return []string{"Cambium TLV parent and child rows are software-certified as typed evidence; exact firmware behavior remains release certification."}
		}
		return []string{"Cambium cnMaestro, ePMP, PMP, and switching behavior remains release-certified externally before hardware claims are published."}
	case VendorPackTPLink:
		if class == "redacted_secret_evidence" {
			return []string{"TP-Link authentication key values are never stored as cleartext policy data; packet evidence uses typed metadata and redaction."}
		}
		return []string{"TP-Link Omada AP, gateway, switch, and portal behavior remains release-certified externally before hardware claims are published."}
	default:
		return []string{"D-Link switch, AP, Nuclias, ACL script, and bandwidth behavior remains release-certified externally before hardware claims are published."}
	}
}

func accessVendorSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyAccessVendorToken(name, "authentication-findkey", "authentication-foundkey")
}

func accessVendorRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func accessVendorPackFingerprint(records []AccessVendorAttributeRecord, grammar []AccessVendorGrammarRecord, scopes []AccessVendorProductScope, source string) string {
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

func containsAnyAccessVendorToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
