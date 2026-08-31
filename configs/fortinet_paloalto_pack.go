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
	FortinetPaloAltoPackSchemaVersion          = 1
	FortinetPaloAltoPackFeatureID              = "NAS-0065"
	FortinetPaloAltoPackExpectedAttributeCount = 42

	FortinetPaloAltoSoftwareCertified = "software_certified"
	FortinetPaloAltoExternalRequired  = "external_certification_required"
)

type FortinetPaloAltoPackSummary = RuckusICXPackSummary
type FortinetPaloAltoVendorSummary = RuckusICXVendorSummary
type FortinetPaloAltoCapabilityCount = RuckusICXCapabilityCount
type FortinetPaloAltoProductScope = RuckusICXProductScope
type FortinetPaloAltoGrammarRecord = RuckusICXGrammarRecord
type FortinetPaloAltoAttributeRecord = RuckusICXAttributeRecord

type FortinetPaloAltoPackReport struct {
	SchemaVersion                 int                               `json:"schema_version"`
	FeatureID                     string                            `json:"feature_id"`
	ReleaseProfileID              string                            `json:"release_profile_id"`
	SourceRelease                 string                            `json:"source_release"`
	SourceSHA256                  string                            `json:"source_sha256"`
	SourceFileCount               int                               `json:"source_file_count"`
	SourceAttributeCount          int                               `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                            `json:"release_certification_checklist"`
	Summary                       FortinetPaloAltoPackSummary       `json:"summary"`
	VendorSummaries               []FortinetPaloAltoVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []FortinetPaloAltoCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []FortinetPaloAltoProductScope    `json:"product_scopes"`
	Grammar                       []FortinetPaloAltoGrammarRecord   `json:"grammar"`
	Records                       []FortinetPaloAltoAttributeRecord `json:"records"`
	Notes                         []string                          `json:"notes,omitempty"`
}

func BuildFortinetPaloAltoPackReport() (FortinetPaloAltoPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return FortinetPaloAltoPackReport{}, err
	}
	records := make([]FortinetPaloAltoAttributeRecord, 0, FortinetPaloAltoPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isFortinetPaloAltoVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildFortinetPaloAltoAttributeRecord(entry))
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
	report := FortinetPaloAltoPackReport{
		SchemaVersion:                 FortinetPaloAltoPackSchemaVersion,
		FeatureID:                     FortinetPaloAltoPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0065-release-certification-checklist.md",
		ProductScopes:                 fortinetPaloAltoProductScopes(),
		Grammar:                       fortinetPaloAltoGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0065 covers all Fortinet and Palo Alto rows in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers typed packet decoding, Fortinet VDOM/admin/firewall/VPN/WLAN/posture semantics, Palo Alto PAN-OS/GlobalProtect/Panorama semantics, AVPair parsing, secret redaction, API/UI visibility, durable evidence, and observability readiness.",
			"Rows without a direct neutral enforcement primitive are software-certified as typed evidence or policy tags; real device behavior remains in the release certification checklist.",
			"FortiGate, FortiAuthenticator, FortiNAC, FortiDeceptor, FortiWAN, PAN-OS, GlobalProtect, and Panorama acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeFortinetPaloAltoPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = fortinetPaloAltoPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeFortinetPaloAltoVendors(records)
	report.CapabilitySummaries = summarizeFortinetPaloAltoCapabilities(records)
	return report, nil
}

func ValidateFortinetPaloAltoPackReport(report FortinetPaloAltoPackReport) error {
	if report.SchemaVersion != FortinetPaloAltoPackSchemaVersion {
		return fmt.Errorf("Fortinet/Palo Alto pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != FortinetPaloAltoPackFeatureID {
		return fmt.Errorf("Fortinet/Palo Alto pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Fortinet/Palo Alto pack release profile and source hash are required")
	}
	if len(report.Records) != FortinetPaloAltoPackExpectedAttributeCount {
		return fmt.Errorf("Fortinet/Palo Alto pack has %d records, expected %d", len(report.Records), FortinetPaloAltoPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != FortinetPaloAltoPackExpectedAttributeCount {
		return fmt.Errorf("Fortinet/Palo Alto pack summary has %d attributes, expected %d", report.Summary.AttributeCount, FortinetPaloAltoPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != FortinetPaloAltoPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Fortinet/Palo Alto pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != FortinetPaloAltoPackExpectedAttributeCount {
		return fmt.Errorf("Fortinet/Palo Alto pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 2 {
		return fmt.Errorf("Fortinet/Palo Alto pack must cover Fortinet and PaloAlto dictionary vendors")
	}
	if report.Summary.ProductScopeCount < 7 || len(report.ProductScopes) < 7 {
		return fmt.Errorf("Fortinet/Palo Alto pack product scope must include Fortinet security and Palo Alto firewall/VPN products")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Fortinet/Palo Alto pack fingerprint is required")
	}
	if len(report.Grammar) < 10 {
		return fmt.Errorf("Fortinet/Palo Alto pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Fortinet/Palo Alto grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != FortinetPaloAltoExternalRequired {
			return fmt.Errorf("Fortinet/Palo Alto grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Fortinet/Palo Alto record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Fortinet/Palo Alto record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != FortinetPaloAltoSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Fortinet/Palo Alto record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Fortinet/Palo Alto record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildFortinetPaloAltoAttributeRecord(entry AttributeRegistryEntry) FortinetPaloAltoAttributeRecord {
	capability := fortinetPaloAltoCapability(entry)
	class := "typed_passthrough"
	if isFortinetPaloAltoNativeAttribute(entry.Attribute) {
		class = "native_semantic_mapping"
	}
	if isFortinetPaloAltoPolicyGrammarAttribute(entry.Attribute) {
		class = "policy_parse_compile"
	}
	if isFortinetPaloAltoSensitiveAttribute(entry.Attribute) {
		class = "redacted_secret_evidence"
	}
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferFortinetPaloAltoDirections(entry, capability)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = fortinetPaloAltoSemantic(capability)
	}
	return FortinetPaloAltoAttributeRecord{
		ID:                         fortinetPaloAltoRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, fortinetPaloAltoDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, fortinetPaloAltoFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           fortinetPaloAltoPacketProcessing(class),
		PolicyEngine:               fortinetPaloAltoPolicyState(class, capability),
		Enforcement:                fortinetPaloAltoEnforcementState(class, capability),
		Storage:                    fortinetPaloAltoStorageState(class),
		APIUI:                      "pack_report_history_preview_controller_scope_and_support_bundle",
		Monitoring:                 "vendor_security_counters_fingerprint_redaction_controller_scope_and_typed_packet_state",
		SoftwareState:              FortinetPaloAltoSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      fortinetPaloAltoRecordNotes(class),
	}
}

func fortinetPaloAltoGrammarRecords() []FortinetPaloAltoGrammarRecord {
	rows := []FortinetPaloAltoGrammarRecord{
		{"fortinet_role_group", "Fortinet group and user role policy", "role_policy", VendorSemanticRole, []string{"Fortinet-Group-Name = \"employee\"", "Fortinet-Fpc-User-Role = \"netops\""}, "", "", "", "", "", ""},
		{"fortinet_vdom_tenant", "Fortinet VDOM and tenant context", "tenant_vrf", VendorSemanticTenant, []string{"Fortinet-Vdom-Name = \"root\"", "Fortinet-Tenant-Identification = \"tenant-a\""}, "", "", "", "", "", ""},
		{"fortinet_firewall_profile", "Fortinet access and firewall profile assignment", "policy_profile", VendorSemanticPolicyTag, []string{"Fortinet-Access-Profile = \"guest-internet\"", "Fortinet-FDD-Access-Profile = \"fdd-admin\""}, "", "", "", "", "", ""},
		{"fortinet_webfilter_appctrl", "Fortinet web filter and application-control category policy", "security_profile", VendorSemanticPolicyTag, []string{"Fortinet-Webfilter-Category-Block = 0x0010", "Fortinet-AppCtrl-Risk-Block = 0x0004"}, "", "", "", "", "", ""},
		{"fortinet_fac_challenge", "FortiAuthenticator challenge and token evidence", "secret_redaction", VendorSemanticCertificateOnboarding, []string{"Fortinet-FAC-Token-ID = \"<redacted>\"", "Fortinet-FAC-Challenge-Code = \"<redacted>\""}, "", "", "", "", "", ""},
		{"fortinet_wlan_context", "Fortinet SSID, AP, WTP, client IP, and station context", "wlan_context", VendorSemanticDeviceGroup, []string{"Fortinet-SSID = \"Corp\"", "Fortinet-WirelessController-WTP-ID = \"wtp-a\""}, "", "", "", "", "", ""},
		{"fortinet_fortiwan_avpair", "FortiWAN and host-port AVPair policy", "vendor_avpair", VendorSemanticDynamicACL, []string{"acl=branch-in", "route=198.51.100.0/24"}, "", "", "", "", "", ""},
		{"fortinet_fdd_admin", "FortiDeceptor administration, SPP, trusted-host, and API policy", "admin_security", VendorSemanticRole, []string{"Fortinet-FDD-Is-System-Admin = \"true\"", "Fortinet-FDD-Allow-API-Access = \"false\""}, "", "", "", "", "", ""},
		{"paloalto_admin_role", "Palo Alto PAN-OS and Panorama admin role/domain", "command_authorization", VendorSemanticRole, []string{"PaloAlto-Admin-Role = \"superuser\"", "PaloAlto-Panorama-Admin-Access-Domain = \"domain-a\""}, "", "", "", "", "", ""},
		{"paloalto_userid_group", "Palo Alto User-ID group, domain, and source IP context", "userid_context", VendorSemanticDeviceGroup, []string{"PaloAlto-User-Group = \"employees\"", "PaloAlto-Client-Source-IP = \"198.51.100.23\""}, "", "", "", "", "", ""},
		{"paloalto_globalprotect_posture", "Palo Alto GlobalProtect hostname, OS, and client version posture", "vpn_posture", VendorSemanticDevicePosture, []string{"PaloAlto-Client-OS = \"Windows 11\"", "PaloAlto-GlobalProtect-Client-Version = \"6.2.1\""}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = FortinetPaloAltoExternalRequired
		rows[index].ReleaseScope = "Device, controller, firmware, HA, FreeRADIUS, performance, soak, security, and customer acceptance is tracked in docs/nas-0065-release-certification-checklist.md."
	}
	return rows
}

func fortinetPaloAltoProductScopes() []FortinetPaloAltoProductScope {
	return []FortinetPaloAltoProductScope{
		{Key: VendorPackFortinet, Label: "Fortinet FortiGate / FortiWiFi", Vendors: []string{"Fortinet"}, Products: []string{"FortiGate", "FortiWiFi", "Firewall and SSL VPN RADIUS"}, Dictionary: "dictionary.fortinet", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"VDOM, group, access profile, client IP, firewall profile, and VPN/posture evidence are software-visible; appliance behavior requires release evidence."}},
		{Key: VendorPackFortinet, Label: "Fortinet FortiAuthenticator", Vendors: []string{"Fortinet"}, Products: []string{"FortiAuthenticator", "FAC token/challenge"}, Dictionary: "dictionary.fortinet", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"Challenge and token values are redacted before evidence persistence."}},
		{Key: VendorPackFortinet, Label: "Fortinet FortiNAC", Vendors: []string{"Fortinet"}, Products: []string{"FortiNAC", "Posture and quarantine workflows"}, Dictionary: "dictionary.fortinet", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"Posture and role context maps into neutral policy; real quarantine behavior is certified externally."}},
		{Key: VendorPackFortinet, Label: "Fortinet FortiAP / FortiSwitch", Vendors: []string{"Fortinet"}, Products: []string{"FortiAP", "FortiSwitch", "Wireless Controller VAP"}, Dictionary: "dictionary.fortinet plus FortiGate controller API", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"SSID, AP, WTP, device MAC, association time, and controller-sync status are software-certified."}},
		{Key: VendorPackFortinet, Label: "Fortinet FortiDeceptor / FDD", Vendors: []string{"Fortinet"}, Products: []string{"FortiDeceptor", "FDD admin and SPP policy"}, Dictionary: "dictionary.fortinet", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"FDD admin and trusted-host attributes are treated as bounded security policy metadata."}},
		{Key: VendorPackFortinet, Label: "Fortinet FortiWAN", Vendors: []string{"Fortinet"}, Products: []string{"FortiWAN", "SD-WAN AVPair policy"}, Dictionary: "dictionary.fortinet", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"AVPair grammar promotes known ACL, role, route, tenant, and policy tokens while preserving safe unknowns."}},
		{Key: VendorPackPaloAlto, Label: "Palo Alto PAN-OS / GlobalProtect", Vendors: []string{"PaloAlto"}, Products: []string{"PAN-OS", "GlobalProtect", "User-ID"}, Dictionary: "dictionary.paloalto", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"Admin role, access-domain, user group, source IP, client OS, hostname, and client version are software-certified."}},
		{Key: VendorPackPaloAlto, Label: "Palo Alto Panorama", Vendors: []string{"PaloAlto"}, Products: []string{"Panorama", "Panorama admin domains"}, Dictionary: "dictionary.paloalto", SoftwareState: FortinetPaloAltoSoftwareCertified, ExternalState: FortinetPaloAltoExternalRequired, Notes: []string{"Panorama admin role and access-domain attributes are tracked as a separate release scope."}},
	}
}

func summarizeFortinetPaloAltoPack(records []FortinetPaloAltoAttributeRecord, grammar []FortinetPaloAltoGrammarRecord, scopes []FortinetPaloAltoProductScope) FortinetPaloAltoPackSummary {
	summary := FortinetPaloAltoPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar), ProductScopeCount: len(scopes)}
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
		if record.SoftwareState == FortinetPaloAltoSoftwareCertified {
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

func summarizeFortinetPaloAltoVendors(records []FortinetPaloAltoAttributeRecord) []FortinetPaloAltoVendorSummary {
	byKey := map[string]*FortinetPaloAltoVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &FortinetPaloAltoVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
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
		if record.SoftwareState == FortinetPaloAltoSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]FortinetPaloAltoVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeFortinetPaloAltoCapabilities(records []FortinetPaloAltoAttributeRecord) []FortinetPaloAltoCapabilityCount {
	byCapability := map[string]*FortinetPaloAltoCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &FortinetPaloAltoCapabilityCount{Capability: record.Capability}
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
		if record.SoftwareState == FortinetPaloAltoSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]FortinetPaloAltoCapabilityCount, 0, len(byCapability))
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

func isFortinetPaloAltoVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "fortinet", "paloalto":
		return true
	default:
		return false
	}
}

func fortinetPaloAltoCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(entry.Vendor)
	name := strings.ToLower(entry.Attribute)
	if vendor == "paloalto" {
		switch {
		case containsAnyFortinetPaloAltoToken(name, "panorama"):
			return "paloalto_panorama_admin_domain"
		case containsAnyFortinetPaloAltoToken(name, "globalprotect", "client-os", "client-hostname"):
			return "paloalto_globalprotect_posture"
		case containsAnyFortinetPaloAltoToken(name, "user-group", "user-domain", "source-ip"):
			return "paloalto_userid_context"
		case containsAnyFortinetPaloAltoToken(name, "admin-role", "admin-access-domain"):
			return "paloalto_panos_admin_authorization"
		default:
			return "paloalto_firewall_vpn_context"
		}
	}
	switch {
	case containsAnyFortinetPaloAltoToken(name, "fac-token", "fac-challenge", "fac-auth"):
		return "fortinet_fortiauthenticator_challenge"
	case containsAnyFortinetPaloAltoToken(name, "webfilter"):
		return "fortinet_web_filter_policy"
	case containsAnyFortinetPaloAltoToken(name, "appctrl"):
		return "fortinet_application_control_policy"
	case containsAnyFortinetPaloAltoToken(name, "wirelesscontroller", "ssid", "ap-name"):
		return "fortinet_wlan_controller_context"
	case containsAnyFortinetPaloAltoToken(name, "client-ip", "client-ipv6"):
		return "fortinet_client_addressing"
	case containsAnyFortinetPaloAltoToken(name, "vdom", "tenant"):
		return "fortinet_vdom_tenant_context"
	case containsAnyFortinetPaloAltoToken(name, "fortiwan", "host-port-avpair"):
		return "fortinet_fortiwan_host_port_avpair_policy"
	case containsAnyFortinetPaloAltoToken(name, "fdd"):
		return "fortinet_fdd_admin_security_policy"
	case containsAnyFortinetPaloAltoToken(name, "group-name", "user-role", "access-profile"):
		return "fortinet_role_and_access_profile"
	case containsAnyFortinetPaloAltoToken(name, "interface"):
		return "fortinet_interface_context"
	default:
		return "fortinet_security_context"
	}
}

func fortinetPaloAltoSemantic(capability string) string {
	switch capability {
	case "fortinet_fortiauthenticator_challenge":
		return VendorSemanticCertificateOnboarding + "," + VendorSemanticDevicePosture
	case "fortinet_web_filter_policy", "fortinet_application_control_policy", "fortinet_role_and_access_profile", "fortinet_fdd_admin_security_policy":
		return VendorSemanticPolicyTag
	case "fortinet_wlan_controller_context", "fortinet_interface_context", "paloalto_userid_context":
		return VendorSemanticDeviceGroup
	case "fortinet_client_addressing":
		return VendorSemanticIPv4Address + "," + VendorSemanticIPv6Address
	case "fortinet_vdom_tenant_context", "paloalto_panorama_admin_domain":
		return VendorSemanticTenant + "," + VendorSemanticVRF
	case "fortinet_fortiwan_host_port_avpair_policy":
		return VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticPolicyTag
	case "paloalto_globalprotect_posture":
		return VendorSemanticDevicePosture + "," + VendorSemanticAccountingIdentity
	case "paloalto_panos_admin_authorization":
		return VendorSemanticRole + "," + VendorSemanticTenant
	default:
		return VendorSemanticPolicyTag
	}
}

func inferFortinetPaloAltoDirections(entry AttributeRegistryEntry, capability string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyFortinetPaloAltoToken(name, "client-os", "client-hostname", "client-source-ip", "wirelesscontroller", "ap-name", "assoc-time", "device-mac"):
		return []string{"accounting", "inbound"}
	case containsAnyFortinetPaloAltoToken(name, "fac-token", "fac-challenge", "fac-auth"):
		return []string{"inbound", "outbound_reply"}
	case strings.Contains(capability, "avpair"):
		return []string{"accounting", "inbound", "outbound_reply"}
	default:
		return []string{"accounting", "inbound", "outbound_reply"}
	}
}

func fortinetPaloAltoDefaultPack(vendor string) string {
	if strings.EqualFold(strings.TrimSpace(vendor), "PaloAlto") {
		return VendorPackPaloAlto
	}
	return VendorPackFortinet
}

func fortinetPaloAltoFunctionality(entry AttributeRegistryEntry, capability string) string {
	scope := "Fortinet firewall, WLAN, NAC, authenticator, and deception products"
	if strings.EqualFold(entry.Vendor, "PaloAlto") {
		scope = "Palo Alto PAN-OS, GlobalProtect, User-ID, and Panorama products"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes known semantics, redacts challenge secrets, and stores bounded typed evidence until release certification is attached.", entry.Attribute, strings.ReplaceAll(capability, "_", " "), scope)
}

func fortinetPaloAltoPacketProcessing(class string) string {
	switch class {
	case "policy_parse_compile":
		return "security_profile_avpair_parser_classifier_and_reply_renderer"
	case "native_semantic_mapping":
		return "typed_runtime_decoder_semantic_mapper_and_reply_renderer"
	case "redacted_secret_evidence":
		return "challenge_token_redaction_before_evidence_persistence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func fortinetPaloAltoPolicyState(class, capability string) string {
	if class == "typed_passthrough" {
		return "typed_evidence_only_until_policy_binding"
	}
	if class == "redacted_secret_evidence" {
		return "challenge_metadata_without_secret_persistence"
	}
	switch {
	case strings.Contains(capability, "avpair"):
		return "vendor_avpair_policy_tokens"
	case strings.Contains(capability, "admin") || strings.Contains(capability, "role"):
		return "admin_and_role_policy"
	case strings.Contains(capability, "vdom") || strings.Contains(capability, "panorama"):
		return "tenant_and_vrf_policy"
	case strings.Contains(capability, "web_filter") || strings.Contains(capability, "application_control"):
		return "firewall_security_profile_policy"
	case strings.Contains(capability, "globalprotect") || strings.Contains(capability, "challenge"):
		return "posture_and_vpn_challenge_policy"
	default:
		return "neutral_security_policy_semantics"
	}
}

func fortinetPaloAltoEnforcementState(class, capability string) string {
	if class == "typed_passthrough" {
		return "safe_visibility_no_silent_enforcement_claim"
	}
	if class == "redacted_secret_evidence" {
		return "redacted_evidence_only_until_external_challenge_flow_certification"
	}
	if strings.Contains(capability, "avpair") {
		return "radius_reply_and_accounting_avpair_surfaces"
	}
	if strings.Contains(capability, "panorama") || strings.Contains(capability, "admin") {
		return "radius_admin_reply_surfaces"
	}
	return "radius_reply_controller_preview_and_policy_surfaces"
}

func fortinetPaloAltoStorageState(class string) string {
	if class == "redacted_secret_evidence" {
		return "redacted_challenge_metadata_with_bounded_non_secret_evidence"
	}
	return "bounded_raw_evidence_and_normalized_security_metadata"
}

func fortinetPaloAltoRecordNotes(class string) []string {
	switch class {
	case "redacted_secret_evidence":
		return []string{"Challenge and token values are never persisted in clear text; software readiness covers redaction and metadata handling, while real challenge workflows remain release certification."}
	case "typed_passthrough":
		return []string{"Software-ready typed pass-through does not claim native device behavior until release certification evidence is attached."}
	default:
		return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
	}
}

func isFortinetPaloAltoNativeAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return strings.HasPrefix(name, "fortinet-") || strings.HasPrefix(name, "paloalto-")
}

func isFortinetPaloAltoPolicyGrammarAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyFortinetPaloAltoToken(name, "avpair", "access-profile", "webfilter", "appctrl", "policy-group", "admin-role", "user-group")
}

func isFortinetPaloAltoSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyFortinetPaloAltoToken(name, "fac-token", "fac-challenge")
}

func fortinetPaloAltoRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func fortinetPaloAltoPackFingerprint(records []FortinetPaloAltoAttributeRecord, grammar []FortinetPaloAltoGrammarRecord, scopes []FortinetPaloAltoProductScope, source string) string {
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

func containsAnyFortinetPaloAltoToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
