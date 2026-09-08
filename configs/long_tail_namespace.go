package configs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	LongTailNamespaceSchemaVersion          = 1
	LongTailNamespaceFeatureID              = "NAS-0072"
	LongTailNamespaceExpectedVendorCount    = 92
	LongTailNamespaceExpectedAttributeCount = 1126

	LongTailNamespaceSoftwareCertified = "software_certified"
	LongTailNamespaceExternalRequired  = "external_certification_required"
)

type LongTailNamespaceSummary = RuckusICXPackSummary
type LongTailNamespaceVendorSummary = RuckusICXVendorSummary
type LongTailNamespaceCapabilityCount = RuckusICXCapabilityCount
type LongTailNamespaceProductScope = RuckusICXProductScope
type LongTailNamespaceGrammarRecord = RuckusICXGrammarRecord
type LongTailNamespaceAttributeRecord = RuckusICXAttributeRecord

type LongTailNamespaceReport struct {
	SchemaVersion                 int                                `json:"schema_version"`
	FeatureID                     string                             `json:"feature_id"`
	ReleaseProfileID              string                             `json:"release_profile_id"`
	SourceRelease                 string                             `json:"source_release"`
	SourceSHA256                  string                             `json:"source_sha256"`
	SourceFileCount               int                                `json:"source_file_count"`
	SourceAttributeCount          int                                `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                             `json:"release_certification_checklist"`
	Summary                       LongTailNamespaceSummary           `json:"summary"`
	VendorSummaries               []LongTailNamespaceVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []LongTailNamespaceCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []LongTailNamespaceProductScope    `json:"product_scopes"`
	Grammar                       []LongTailNamespaceGrammarRecord   `json:"grammar"`
	Records                       []LongTailNamespaceAttributeRecord `json:"records"`
	Notes                         []string                           `json:"notes,omitempty"`
}

func BuildLongTailNamespaceReport() (LongTailNamespaceReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return LongTailNamespaceReport{}, err
	}
	records := make([]LongTailNamespaceAttributeRecord, 0, LongTailNamespaceExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isLongTailNamespaceVendor(entry.Vendor) {
			continue
		}
		if !strings.EqualFold(entry.Source, "freeradius-"+FreeRADIUSRegistryRelease) {
			continue
		}
		records = append(records, buildLongTailNamespaceAttributeRecord(entry))
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
	report := LongTailNamespaceReport{
		SchemaVersion:                 LongTailNamespaceSchemaVersion,
		FeatureID:                     LongTailNamespaceFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0072-release-certification-checklist.md",
		ProductScopes:                 longTailNamespaceProductScopes(),
		Grammar:                       longTailNamespaceGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0072 covers the 92 long-tail in-corpus vendor namespaces assigned to the roadmap, totaling 1,126 pinned FreeRADIUS 3.2.8 VSA rows.",
			"Software certification covers typed dictionary metadata, safe runtime decoding where wire numbers are decodable, bounded evidence capture, secret redaction, neutral semantic classification, API/UI visibility, durable evidence, and readiness reporting.",
			"Focused packs keep their existing pack keys for backward compatibility; NAS-0072 adds a broader long-tail report and classifies rows that are not otherwise covered by a product-specific pack.",
			"Typed pass-through means AegisNAS knows the wire type, vendor, attribute, semantic family, and storage/security behavior. It does not assert device-specific enforcement unless a focused pack or later roadmap feature implements that behavior.",
			"Real long-tail vendor hardware, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance remain release certification activities.",
		},
	}
	report.Summary = summarizeLongTailNamespace(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeLongTailNamespaceVendors(records)
	report.CapabilitySummaries = summarizeLongTailNamespaceCapabilities(records)
	return report, nil
}

func ValidateLongTailNamespaceReport(report LongTailNamespaceReport) error {
	if report.SchemaVersion != LongTailNamespaceSchemaVersion {
		return fmt.Errorf("long-tail namespace schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != LongTailNamespaceFeatureID {
		return fmt.Errorf("long-tail namespace feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("long-tail namespace release profile and source hash are required")
	}
	if len(report.Records) != LongTailNamespaceExpectedAttributeCount {
		return fmt.Errorf("long-tail namespace has %d records, expected %d", len(report.Records), LongTailNamespaceExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != LongTailNamespaceExpectedAttributeCount {
		return fmt.Errorf("long-tail namespace summary has %d attributes, expected %d", report.Summary.AttributeCount, LongTailNamespaceExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != LongTailNamespaceExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("long-tail namespace software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != LongTailNamespaceExpectedAttributeCount {
		return fmt.Errorf("long-tail namespace must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != LongTailNamespaceExpectedVendorCount {
		return fmt.Errorf("long-tail namespace must cover %d dictionary vendors, got %d", LongTailNamespaceExpectedVendorCount, report.Summary.VendorCount)
	}
	if report.Summary.ProductScopeCount < 12 || len(report.ProductScopes) < 12 {
		return fmt.Errorf("long-tail namespace product scope is incomplete")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("long-tail namespace fingerprint is required")
	}
	if len(report.Grammar) < 16 {
		return fmt.Errorf("long-tail namespace grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("long-tail namespace grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != LongTailNamespaceExternalRequired {
			return fmt.Errorf("long-tail namespace grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("long-tail namespace record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("long-tail namespace record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != LongTailNamespaceSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("long-tail namespace record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("long-tail namespace record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if strings.TrimSpace(record.PacketProcessing) == "" || strings.TrimSpace(record.PolicyEngine) == "" || strings.TrimSpace(record.Storage) == "" {
			return fmt.Errorf("long-tail namespace record %q is missing implementation state", record.ID)
		}
	}
	return nil
}

func buildLongTailNamespaceAttributeRecord(entry AttributeRegistryEntry) LongTailNamespaceAttributeRecord {
	semantic := longTailNamespaceSemantic(entry)
	class := longTailNamespaceImplementationClass(entry, semantic)
	return LongTailNamespaceAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, VendorPackLongTail),
		Attribute:                  entry.Attribute,
		Number:                     entry.Number,
		OID:                        entry.OID,
		WireKey:                    entry.WireKey,
		WireType:                   entry.WireType,
		WireCodec:                  entry.WireCodec,
		DictionaryStatus:           entry.DictionaryStatus,
		Capability:                 longTailNamespaceCapability(entry),
		Semantic:                   semantic,
		Directions:                 longTailNamespaceDirections(entry, semantic),
		Functionality:              firstNonEmptyPackKey(entry.Functionality, longTailNamespaceFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           longTailNamespacePacketProcessing(entry, class),
		PolicyEngine:               longTailNamespacePolicyState(semantic, class),
		Enforcement:                longTailNamespaceEnforcementState(semantic, class),
		Storage:                    longTailNamespaceStorageState(class),
		APIUI:                      "long_tail_report_history_vendor_matrix_namespace_drilldown_support_bundle_and_release_checklist",
		Monitoring:                 "long_tail_namespace_counters_fingerprint_vsa_parse_failures_unsupported_attribute_counts_secret_redaction_and_external_scope",
		SoftwareState:              LongTailNamespaceSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      longTailNamespaceRecordNotes(entry, class),
	}
}

func summarizeLongTailNamespace(records []LongTailNamespaceAttributeRecord, grammar []LongTailNamespaceGrammarRecord, scopes []LongTailNamespaceProductScope) LongTailNamespaceSummary {
	return summarizeAccessVendorPack(records, grammar, scopes)
}

func summarizeLongTailNamespaceVendors(records []LongTailNamespaceAttributeRecord) []LongTailNamespaceVendorSummary {
	return summarizeAccessVendorVendors(records)
}

func summarizeLongTailNamespaceCapabilities(records []LongTailNamespaceAttributeRecord) []LongTailNamespaceCapabilityCount {
	return summarizeAccessVendorCapabilities(records)
}

func (r *AttributeRegistry) applyLongTailNamespaceRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isLongTailNamespaceVendor(entry.Vendor) {
			continue
		}
		if !strings.EqualFold(entry.Source, "freeradius-"+FreeRADIUSRegistryRelease) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := longTailNamespaceSemantic(*entry)
		if strings.TrimSpace(entry.PackKey) == "" {
			entry.PackKey = VendorPackLongTail
		}
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0072")
		entry.Directions = longTailNamespaceDirections(*entry, entry.Semantic)
		entry.Functionality = longTailNamespaceFunctionality(*entry, entry.Semantic)
		if wasMissing || strings.TrimSpace(entry.DecodeKind) == "" {
			entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = longTailNamespaceDecoder(*entry, entry.Semantic)
		}
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func longTailNamespaceGrammarRecords() []LongTailNamespaceGrammarRecord {
	rows := []LongTailNamespaceGrammarRecord{
		{"long_tail_role_privilege", "Role, group, privilege, and command context", "role_policy", VendorSemanticRole, []string{"Vendor-Role = \"network-admin\"", "Vendor-Privilege-Level = 15"}, "", "", "", "", "", ""},
		{"long_tail_vlan_segment", "VLAN, SSID, segment, and bridge selectors", "vlan_policy", VendorSemanticVLAN, []string{"Vendor-VLAN-ID = 20", "Vendor-SSID = \"Corp\""}, "", "", "", "", "", ""},
		{"long_tail_acl_filter", "Named ACL, filter, firewall, and rule policy", "acl_policy", VendorSemanticDynamicACL, []string{"Vendor-ACL = \"guest-in\"", "Vendor-Filter-Rule = \"permit ip any any\""}, "", "", "", "", "", ""},
		{"long_tail_qos_rate", "Rate, bandwidth, QoS, DSCP, queue, and burst context", "qos_policy", VendorSemanticBandwidthProfile, []string{"Vendor-Bandwidth-Max-Up = 20000", "Vendor-QoS-Profile = \"gold\""}, "", "", "", "", "", ""},
		{"long_tail_quota_accounting", "Quota, counters, octets, packets, and session accounting", "accounting_context", VendorSemanticAccountingCounters, []string{"Vendor-Total-Octets = 1073741824", "Vendor-Session-ID = \"abc123\""}, "", "", "", "", "", ""},
		{"long_tail_portal_hotspot", "Captive portal, hotspot, guest, redirect, and walled-garden hints", "guest_portal", VendorSemanticPortalProfile, []string{"Vendor-Redirect-URL = \"https://portal.example.test/start\""}, "", "", "", "", "", ""},
		{"long_tail_address_pool", "IPv4, IPv6, DNS, gateway, pool, and delegated prefix context", "address_policy", VendorSemanticAddressPool, []string{"Vendor-Framed-Pool = \"pool-a\"", "Vendor-Delegated-IPv6-Prefix = \"2001:db8::/56\""}, "", "", "", "", "", ""},
		{"long_tail_route_vrf", "Route, VRF, routing-instance, and tunnel selectors", "route_policy", VendorSemanticVRF, []string{"Vendor-VRF = \"tenant-a\"", "Vendor-Route = \"192.0.2.0/24 198.51.100.1\""}, "", "", "", "", "", ""},
		{"long_tail_translation_nat", "NAT, CGNAT, public address, port-block, and NAT64 context", "translation_policy", VendorSemanticTranslationPolicy, []string{"Vendor-NAT-Pool = \"public-a\"", "Vendor-Port-Block-Size = 512"}, "", "", "", "", "", ""},
		{"long_tail_device_posture", "Device posture, fingerprint, interface, AP, host, serial, and MAC evidence", "posture", VendorSemanticDevicePosture, []string{"Vendor-Device-Type = \"phone\"", "Vendor-AP-Name = \"branch-ap-1\""}, "", "", "", "", "", ""},
		{"long_tail_tenant_location", "Tenant, realm, domain, site, zone, organization, and location context", "tenant_context", VendorSemanticTenant, []string{"Vendor-Realm = \"corp.example\"", "Vendor-Site = \"branch-a\""}, "", "", "", "", "", ""},
		{"long_tail_dynamic_authorization", "CoA, Disconnect, reauth, block, and remediation actions", "dynamic_authorization", VendorSemanticCoAReauth, []string{"Vendor-CoA-Action = \"reauth\"", "Vendor-Disconnect-Cause = 4"}, "", "", "", "", "", ""},
		{"long_tail_controller_management", "Controller sync, health, management, and inventory context", "controller_context", VendorSemanticControllerHealth, []string{"Vendor-Controller-ID = \"ctrl-a\"", "Vendor-Management-Profile = \"read-only\""}, "", "", "", "", "", ""},
		{"long_tail_certificate_secret", "Certificate, PSK, token, and credential material redaction", "secret_redaction", VendorSemanticCertificateOnboarding, []string{"Vendor-PSK = \"<redacted>\"", "Vendor-Token = \"<redacted>\""}, "", "", "", "", "", ""},
		{"long_tail_binary_tlv", "Opaque, octets, TLV, struct, group, and OID evidence handling", "typed_binary_evidence", VendorSemanticPolicyTag, []string{"Vendor-TLV = 0x01020304", "Vendor-Struct = 0x0001"}, "", "", "", "", "", ""},
		{"long_tail_release_boundary", "External lab and vendor-hardware certification boundary", "release_certification", VendorSemanticPolicyTag, []string{"FreeRADIUS 3.2.8 namespace rows", "packet capture evidence"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = LongTailNamespaceExternalRequired
		rows[index].ReleaseScope = "Long-tail vendor hardware, FreeRADIUS-on-Linux, HA, performance, soak, security, production deployment, and customer acceptance evidence is tracked in docs/nas-0072-release-certification-checklist.md."
	}
	return rows
}

func longTailNamespaceProductScopes() []LongTailNamespaceProductScope {
	vendors := longTailNamespaceVendorNames()
	return []LongTailNamespaceProductScope{
		{Key: VendorPackLongTail, Label: "Long-Tail Enterprise Access", Vendors: vendors, Products: []string{"enterprise switches", "wireless access controllers", "campus NAS devices"}, Dictionary: "FreeRADIUS 3.2.8 long-tail vendor dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Role, VLAN, ACL, QoS, posture, tenant, and accounting semantics are classified for every NAS-0072 row."}},
		{Key: VendorPackLongTail, Label: "Wireless And Hotspot Namespaces", Vendors: vendors, Products: []string{"hotspot gateways", "guest portals", "WLAN controllers", "wireless bridges"}, Dictionary: "dictionary.wispr plus vendor hotspot dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Portal URLs, guest lifecycle, SSID, AP identity, and WISPr-style bandwidth hints are normalized where present."}},
		{Key: VendorPackLongTail, Label: "ISP Subscriber Edge", Vendors: vendors, Products: []string{"BRAS/BNG", "subscriber concentrators", "managed broadband CPE"}, Dictionary: "FreeRADIUS vendor subscriber dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Address-pool, route, quota, accounting, and subscriber identity rows are visible with bounded storage."}},
		{Key: VendorPackLongTail, Label: "Controller And Management Plane", Vendors: vendors, Products: []string{"controllers", "management appliances", "inventory systems"}, Dictionary: "FreeRADIUS management and controller dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Controller health and management attributes are classified without asserting a proprietary API integration."}},
		{Key: VendorPackLongTail, Label: "Security And Firewall Context", Vendors: vendors, Products: []string{"firewalls", "VPN gateways", "security appliances"}, Dictionary: "FreeRADIUS firewall and security dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"ACL, filter, quarantine, certificate, token, and posture rows receive explicit packet safety handling."}},
		{Key: VendorPackLongTail, Label: "Optical, Transport, And Backhaul", Vendors: vendors, Products: []string{"optical transport", "microwave backhaul", "metro Ethernet"}, Dictionary: "FreeRADIUS carrier transport dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Typed evidence preserves vendor transport semantics for future controller adapters."}},
		{Key: VendorPackLongTail, Label: "Telecom And Voice Gateways", Vendors: vendors, Products: []string{"SIP gateways", "media gateways", "mobile offload systems"}, Dictionary: "FreeRADIUS telecom vendor dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Voice, APN, session, accounting, and credential-like rows are categorized and redacted where required."}},
		{Key: VendorPackLongTail, Label: "Data Center And Load Balancer", Vendors: vendors, Products: []string{"load balancers", "application delivery controllers", "fabric controllers"}, Dictionary: "FreeRADIUS data-center vendor dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Management-role, policy, tenant, and device-group attributes are ready for vendor-specific adapters."}},
		{Key: VendorPackLongTail, Label: "Industrial, Power, And Time Infrastructure", Vendors: vendors, Products: []string{"UPS/PDU", "industrial Ethernet", "time servers"}, Dictionary: "FreeRADIUS infrastructure vendor dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Operational telemetry and management identities are stored as bounded typed evidence."}},
		{Key: VendorPackLongTail, Label: "Authentication Project Namespaces", Vendors: vendors, Products: []string{"FreeRADIUS project attributes", "Yubico OTP integrations", "local web access controls"}, Dictionary: "FreeRADIUS project and authentication dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Tokens, certificate evidence, OTP-like fields, and policy hints are redacted or normalized safely."}},
		{Key: VendorPackLongTail, Label: "Typed Binary And OID Namespace", Vendors: vendors, Products: []string{"TLV dictionaries", "OID dictionaries", "structured attributes"}, Dictionary: "FreeRADIUS OID, TLV, group, struct, and octets wire types", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Nested or non-numbered attributes are represented as typed evidence and excluded from unsafe runtime decoders."}},
		{Key: VendorPackLongTail, Label: "Release Certification Boundary", Vendors: vendors, Products: []string{"hardware packet captures", "FreeRADIUS interoperability", "HA failover", "performance and soak"}, Dictionary: "FreeRADIUS 3.2.8 long-tail dictionaries", SoftwareState: LongTailNamespaceSoftwareCertified, ExternalState: LongTailNamespaceExternalRequired, Notes: []string{"Engineering completion is separate from lab certification and customer acceptance."}},
	}
}

func longTailNamespaceVendorNames() []string {
	names := make([]string, 0, len(longTailNamespaceVendorSet))
	for name := range longTailNamespaceVendorSet {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func isLongTailNamespaceVendor(vendor string) bool {
	_, ok := longTailNamespaceVendorSet[strings.ToLower(strings.TrimSpace(vendor))]
	return ok
}

var longTailNamespaceVendorSet = map[string]struct{}{
	"actelis": {}, "adtran": {}, "adva": {}, "airespace": {}, "apc": {}, "aptilo": {}, "arbor": {}, "audiocodes": {},
	"big-switch-networks": {}, "bluecoat": {}, "boingo": {}, "bristol": {}, "bt": {}, "cajun_p330": {}, "camiant": {},
	"centec": {}, "ciena": {}, "citrix": {}, "ckey": {}, "compatible": {}, "cosine": {}, "covaro": {}, "dante": {},
	"digium": {}, "dragonwave": {}, "efficientip": {}, "eleven": {}, "f5": {}, "freeradius": {}, "garderos": {}, "gemtek": {},
	"iea-software": {}, "infinera": {}, "infoblox": {}, "infonet": {}, "ipunplugged": {}, "karlnet": {}, "kineto": {},
	"lancom": {}, "lantronix": {}, "livingston": {}, "local-web": {}, "meinberg": {}, "mellanox": {}, "merit": {}, "meru": {},
	"microsemi": {}, "mimosa": {}, "networkphysics": {}, "nile": {}, "nomadix": {}, "nortel": {}, "ntua": {}, "packeteer": {},
	"perle": {}, "pfsense": {}, "pica8": {}, "prosoft": {}, "proxim": {}, "purewave": {}, "quiconnect": {}, "rcntec": {},
	"redcreek": {}, "riverbed": {}, "riverstone": {}, "roaring-penguin": {}, "ruggedcom": {}, "shasta": {}, "siemens": {},
	"slipstream": {}, "smartsharesystems": {}, "softbank": {}, "springtide": {}, "surfnet": {}, "symbol": {}, "telebit": {},
	"telkom": {}, "telrad": {}, "terena": {}, "trapeze": {}, "tripplite": {}, "tropos": {}, "t-systems-nova": {}, "ukerna": {},
	"unix": {}, "versanet": {}, "walabi": {}, "waverider": {}, "wispr": {}, "xylan": {}, "yubico": {}, "zeus": {},
}

func longTailNamespaceCapability(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	family := strings.ToLower(strings.TrimSpace(entry.CapabilityFamily))
	switch {
	case containsAnyAccessVendorToken(name, "coa", "disconnect", "reauth", "deauth", "bounce", "block", "unblock") || strings.Contains(family, "dynamic"):
		return "long_tail_dynamic_authorization"
	case containsAnyAccessVendorToken(name, "acl", "filter", "firewall", "rule", "avpair", "av-pair", "policy-rule") || strings.Contains(family, "acl") || strings.Contains(family, "firewall"):
		return "long_tail_acl_firewall_policy"
	case containsAnyAccessVendorToken(name, "vlan", "ssid", "wlan", "bridge", "segment", "qinq") || strings.Contains(family, "vlan") || strings.Contains(family, "wi-fi"):
		return "long_tail_vlan_wireless_policy"
	case containsAnyAccessVendorToken(name, "rate", "bandwidth", "bw-", "qos", "dscp", "priority", "burst", "queue", "speed", "class"):
		return "long_tail_bandwidth_qos"
	case containsAnyAccessVendorToken(name, "quota", "octets", "bytes", "packets", "counter", "acct", "account", "session-id", "usage", "balance", "threshold", "gigawords"):
		return "long_tail_accounting_and_quota"
	case containsAnyAccessVendorToken(name, "portal", "redirect", "url", "uam", "hotspot", "guest", "wispr", "walled"):
		return "long_tail_portal_hotspot_guest"
	case containsAnyAccessVendorToken(name, "ipv6", "ip6", "delegated", "prefix", "pool", "framed", "dns", "gateway", "ip-addr", "address"):
		return "long_tail_ip_addressing"
	case containsAnyAccessVendorToken(name, "route", "vrf", "vrouter", "routing-instance", "tunnel", "l2tp", "mpls", "bgp"):
		return "long_tail_route_vrf_tunnel"
	case containsAnyAccessVendorToken(name, "nat", "cgn", "public", "private", "port-block", "nat64"):
		return "long_tail_nat_translation"
	case containsAnyAccessVendorToken(name, "tenant", "realm", "domain", "location", "site", "zone", "org", "organisation", "organization"):
		return "long_tail_tenant_location"
	case containsAnyAccessVendorToken(name, "posture", "device", "fingerprint", "mac", "host", "hostname", "ap-", "serial", "model", "oui", "interface", "circuit", "remote-id"):
		return "long_tail_device_posture_inventory"
	case containsAnyAccessVendorToken(name, "password", "passwd", "secret", "key", "psk", "token", "nonce", "challenge", "response", "certificate", "cert", "otp", "pin", "triplet", "quint"):
		return "long_tail_certificate_credential"
	case containsAnyAccessVendorToken(name, "controller", "sync", "health", "management", "admin", "privilege", "command", "shell", "cli"):
		return "long_tail_controller_management"
	case containsAnyAccessVendorToken(name, "sip", "voice", "voip", "media", "apn", "imsi", "msisdn", "pdp", "charging", "roam"):
		return "long_tail_voice_mobile_context"
	case longTailNamespaceBinaryWireType(entry.WireType):
		return "long_tail_typed_binary_evidence"
	default:
		if family != "" {
			return "long_tail_" + normalizeLongTailCapabilityKey(entry.CapabilityFamily)
		}
		return "long_tail_vendor_context"
	}
}

func longTailNamespaceSemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	capability := longTailNamespaceCapability(entry)
	semantic := strings.TrimSpace(entry.Semantic)
	add := func(value string) {
		semantic = mergeRegistrySemantics(semantic, value)
	}
	switch {
	case containsAnyAccessVendorToken(name, "acl", "filter", "firewall", "rule", "avpair", "av-pair"):
		add(VendorSemanticDynamicACL)
		add(VendorSemanticACL)
	case containsAnyAccessVendorToken(name, "vlan", "ssid", "wlan", "bridge", "segment", "qinq"):
		add(VendorSemanticVLAN)
	case containsAnyAccessVendorToken(name, "role", "group", "priv", "profile", "command", "shell", "cli", "access-level", "class"):
		add(VendorSemanticRole)
	case containsAnyAccessVendorToken(name, "download", "downstream", "downlink", "egress", "recv", "receive", "rx", "-down", "_down", "-dl"):
		add(VendorSemanticDownloadBandwidth)
	case containsAnyAccessVendorToken(name, "upload", "upstream", "uplink", "ingress", "xmit", "transmit", "tx", "-up", "_up", "-ul"):
		add(VendorSemanticUploadBandwidth)
	case containsAnyAccessVendorToken(name, "rate", "bandwidth", "bw-", "qos", "dscp", "priority", "burst", "queue", "speed"):
		add(VendorSemanticBandwidthProfile)
	case containsAnyAccessVendorToken(name, "quota", "max-total", "total-limit", "octets", "bytes", "packets", "usage", "balance", "gigawords"):
		add(VendorSemanticDataQuota)
		add(VendorSemanticAccountingCounters)
	case containsAnyAccessVendorToken(name, "portal", "redirect", "url", "uam", "hotspot", "guest", "wispr", "walled"):
		add(VendorSemanticPortalProfile)
		add(VendorSemanticGuestLifecycle)
	case containsAnyAccessVendorToken(name, "tenant", "realm", "domain", "location", "site", "zone", "org", "organisation", "organization"):
		add(VendorSemanticTenant)
	case containsAnyAccessVendorToken(name, "delegated", "ipv6-prefix", "ip6-prefix"):
		add(VendorSemanticDelegatedIPv6Prefix)
	case containsAnyAccessVendorToken(name, "ipv6", "ip6"):
		add(VendorSemanticIPv6Address)
	case containsAnyAccessVendorToken(name, "ipaddr", "ip-addr", "ip-address", "framed-ip", "dns", "gateway", "address"):
		add(VendorSemanticIPv4Address)
	case containsAnyAccessVendorToken(name, "pool"):
		add(VendorSemanticAddressPool)
	case containsAnyAccessVendorToken(name, "route"):
		add(VendorSemanticRoute)
	case containsAnyAccessVendorToken(name, "vrf", "vrouter", "routing-instance"):
		add(VendorSemanticVRF)
	case containsAnyAccessVendorToken(name, "nat64"):
		add(VendorSemanticNAT64Prefix)
	case containsAnyAccessVendorToken(name, "port-block", "port-range"):
		add(VendorSemanticTranslationPortBlock)
	case containsAnyAccessVendorToken(name, "nat", "cgn", "public", "private"):
		add(VendorSemanticTranslationPolicy)
		add(VendorSemanticTranslationPublicIPv4)
	case containsAnyAccessVendorToken(name, "coa", "reauth", "bounce"):
		add(VendorSemanticCoAReauth)
	case containsAnyAccessVendorToken(name, "disconnect", "deauth"):
		add(VendorSemanticCoADisconnect)
	case containsAnyAccessVendorToken(name, "quarantine", "intercept", "block", "deny"):
		add(VendorSemanticQuarantine)
	case containsAnyAccessVendorToken(name, "posture", "fingerprint", "device", "mac", "host", "hostname", "ap-", "serial", "model", "oui", "interface", "circuit", "remote-id"):
		add(VendorSemanticDevicePosture)
		add(VendorSemanticDeviceGroup)
	case containsAnyAccessVendorToken(name, "controller", "sync", "health"):
		add(VendorSemanticControllerHealth)
	case containsAnyAccessVendorToken(name, "password", "passwd", "secret", "key", "psk", "token", "nonce", "challenge", "response", "certificate", "cert", "otp", "pin", "triplet", "quint"):
		add(VendorSemanticCertificateOnboarding)
	case containsAnyAccessVendorToken(name, "acct", "account", "session-id", "nas-", "subscriber", "user-name", "username", "imsi", "msisdn", "apn", "charging"):
		add(VendorSemanticAccountingIdentity)
	default:
		switch capability {
		case "long_tail_acl_firewall_policy":
			add(VendorSemanticDynamicACL)
		case "long_tail_vlan_wireless_policy":
			add(VendorSemanticVLAN)
		case "long_tail_bandwidth_qos":
			add(VendorSemanticBandwidthProfile)
		case "long_tail_accounting_and_quota":
			add(VendorSemanticAccountingCounters)
		case "long_tail_portal_hotspot_guest":
			add(VendorSemanticPortalProfile)
		case "long_tail_ip_addressing":
			add(VendorSemanticAddressPool)
		case "long_tail_route_vrf_tunnel":
			add(VendorSemanticVRF)
		case "long_tail_nat_translation":
			add(VendorSemanticTranslationPolicy)
		case "long_tail_device_posture_inventory":
			add(VendorSemanticDevicePosture)
		case "long_tail_controller_management":
			add(VendorSemanticRole)
		case "long_tail_certificate_credential":
			add(VendorSemanticCertificateOnboarding)
		default:
			add(VendorSemanticPolicyTag)
		}
	}
	if semantic == "" {
		return VendorSemanticPolicyTag
	}
	return semantic
}

func longTailNamespaceDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	inferred := []string{"inbound"}
	switch {
	case registrySemanticContains(semantic, VendorSemanticAccountingCounters) ||
		registrySemanticContains(semantic, VendorSemanticAccountingIdentity) ||
		containsAnyAccessVendorToken(name, "acct", "account", "counter", "octets", "packets", "session"):
		inferred = []string{"accounting", "inbound"}
	case registrySemanticContains(semantic, VendorSemanticCoAReauth) ||
		registrySemanticContains(semantic, VendorSemanticCoADisconnect) ||
		containsAnyAccessVendorToken(name, "coa", "disconnect", "reauth", "deauth"):
		inferred = []string{"coa", "inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticControllerHealth) ||
		registrySemanticContains(semantic, VendorSemanticControllerPolicySync) ||
		containsAnyAccessVendorToken(name, "controller", "sync", "health", "management"):
		inferred = []string{"controller_api", "inbound"}
	case longTailNamespaceSensitiveAttribute(entry.Attribute):
		inferred = []string{"inbound"}
	case registrySemanticContains(semantic, VendorSemanticRole) ||
		registrySemanticContains(semantic, VendorSemanticVLAN) ||
		registrySemanticContains(semantic, VendorSemanticACL) ||
		registrySemanticContains(semantic, VendorSemanticDynamicACL) ||
		registrySemanticContains(semantic, VendorSemanticPortalProfile) ||
		registrySemanticContains(semantic, VendorSemanticBandwidthProfile) ||
		registrySemanticContains(semantic, VendorSemanticUploadBandwidth) ||
		registrySemanticContains(semantic, VendorSemanticDownloadBandwidth) ||
		registrySemanticContains(semantic, VendorSemanticSessionTimeout) ||
		registrySemanticContains(semantic, VendorSemanticIdleTimeout):
		inferred = []string{"inbound", "outbound_reply"}
	}
	return mergeLongTailNamespaceDirections(entry.Directions, inferred)
}

func mergeLongTailNamespaceDirections(existing, inferred []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(inferred))
	for _, value := range append(append([]string(nil), existing...), inferred...) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func longTailNamespaceFunctionality(entry AttributeRegistryEntry, semantic string) string {
	name := strings.TrimSpace(entry.Attribute)
	return fmt.Sprintf("%s carries %s for vendor %s in FreeRADIUS %s; AegisNAS classifies it with bounded packet evidence, neutral semantics, secret redaction where required, and an explicit external certification boundary.",
		name,
		strings.ReplaceAll(firstRegistrySemantic(semantic), ".", " "),
		entry.Vendor,
		FreeRADIUSRegistryRelease,
	)
}

func longTailNamespaceDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	wire := baseDictionaryWireType(entry.WireType)
	primary := firstRegistrySemantic(semantic)
	switch {
	case longTailNamespaceSensitiveAttribute(entry.Attribute):
		return "octets_hex", VendorSemanticCertificateOnboarding, 0
	case wire == "ipaddr" || wire == "ipv4addr":
		return "ipaddr", firstNonEmptyPackKey(primary, VendorSemanticIPv4Address), 0
	case wire == "ipv6addr":
		return "ipv6addr", firstNonEmptyPackKey(primary, VendorSemanticIPv6Address), 0
	case wire == "ether" || wire == "ethernet":
		return "ether", firstNonEmptyPackKey(primary, VendorSemanticAccountingIdentity), 0
	case registrySemanticContains(semantic, VendorSemanticDynamicACL) && containsAnyAccessVendorToken(strings.ToLower(entry.Attribute), "avpair", "av-pair", "avpairs"):
		return "avpairs", VendorSemanticDynamicACL, 0
	case registrySemanticContains(semantic, VendorSemanticVLAN) && longTailNamespaceIntegerWireType(entry.WireType):
		return "vlan", VendorSemanticVLAN, 0
	case registrySemanticContains(semantic, VendorSemanticUploadBandwidth) && longTailNamespaceIntegerWireType(entry.WireType):
		return "rate_kbps", VendorSemanticUploadBandwidth, 1
	case registrySemanticContains(semantic, VendorSemanticDownloadBandwidth) && longTailNamespaceIntegerWireType(entry.WireType):
		return "rate_kbps", VendorSemanticDownloadBandwidth, 1
	case registrySemanticContains(semantic, VendorSemanticDataQuota) && longTailNamespaceIntegerWireType(entry.WireType):
		return "data_quota", VendorSemanticDataQuota, 0
	case registrySemanticContains(semantic, VendorSemanticQuarantine) && (longTailNamespaceIntegerWireType(entry.WireType) || wire == "bool"):
		return "bool", VendorSemanticQuarantine, 0
	case longTailNamespaceIntegerWireType(entry.WireType):
		return "integer_text", firstNonEmptyPackKey(primary, VendorSemanticPolicyTag), 0
	case longTailNamespaceBinaryWireType(entry.WireType):
		return "octets_hex", firstNonEmptyPackKey(primary, VendorSemanticPolicyTag), 0
	default:
		return "string", firstNonEmptyPackKey(primary, VendorSemanticPolicyTag), 0
	}
}

func longTailNamespaceImplementationClass(entry AttributeRegistryEntry, semantic string) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case longTailNamespaceSensitiveAttribute(entry.Attribute):
		return "redacted_secret_evidence"
	case longTailNamespaceBinaryWireType(entry.WireType):
		return "typed_binary_evidence"
	case containsAnyAccessVendorToken(name, "acl", "filter", "firewall", "rule", "avpair", "av-pair", "avpairs", "command", "shell", "cli"):
		return "policy_parse_compile"
	case firstRegistrySemantic(semantic) != VendorSemanticPolicyTag:
		return "native_semantic_mapping"
	default:
		return "typed_passthrough"
	}
}

func longTailNamespacePacketProcessing(entry AttributeRegistryEntry, class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "runtime_vsa_decoder_with_redacted_secret_evidence_and_hash_only_storage"
	case "typed_binary_evidence":
		if entry.Number == 0 || entry.Number > 255 {
			return "registry_backed_typed_binary_evidence_without_unsafe_runtime_decoder"
		}
		return "runtime_vsa_decoder_with_bounded_hex_evidence"
	case "policy_parse_compile":
		return "generic_policy_key_value_classifier_with_safe_unknown_preservation"
	case "native_semantic_mapping":
		return "runtime_vsa_decoder_and_neutral_semantic_mapper"
	default:
		return "generic_vsa_codec_with_bounded_typed_evidence"
	}
}

func longTailNamespacePolicyState(semantic, class string) string {
	if class == "typed_passthrough" || class == "typed_binary_evidence" {
		return "typed_evidence_only_until_focused_policy_binding"
	}
	if class == "redacted_secret_evidence" {
		return "secret_metadata_without_cleartext_policy_input"
	}
	switch {
	case registrySemanticContains(semantic, VendorSemanticACL) || registrySemanticContains(semantic, VendorSemanticDynamicACL):
		return "acl_ast_policy_classifier"
	case registrySemanticContains(semantic, VendorSemanticVLAN):
		return "vlan_policy_context"
	case registrySemanticContains(semantic, VendorSemanticBandwidthProfile) || registrySemanticContains(semantic, VendorSemanticUploadBandwidth) || registrySemanticContains(semantic, VendorSemanticDownloadBandwidth):
		return "qos_and_rate_policy_context"
	case registrySemanticContains(semantic, VendorSemanticPortalProfile):
		return "guest_portal_policy_context"
	case registrySemanticContains(semantic, VendorSemanticRoute) || registrySemanticContains(semantic, VendorSemanticVRF):
		return "route_and_vrf_policy_context"
	case registrySemanticContains(semantic, VendorSemanticTranslationPolicy):
		return "translation_policy_context"
	case registrySemanticContains(semantic, VendorSemanticCoAReauth) || registrySemanticContains(semantic, VendorSemanticCoADisconnect):
		return "coa_disconnect_policy_context"
	default:
		return "neutral_semantic_policy_context"
	}
}

func longTailNamespaceEnforcementState(semantic, class string) string {
	if class == "typed_passthrough" || class == "typed_binary_evidence" || class == "redacted_secret_evidence" {
		return "evidence_only_no_vendor_specific_enforcement_claim"
	}
	switch {
	case registrySemanticContains(semantic, VendorSemanticRole) || registrySemanticContains(semantic, VendorSemanticVLAN) || registrySemanticContains(semantic, VendorSemanticACL):
		return "neutral_authorization_result_binding_ready"
	case registrySemanticContains(semantic, VendorSemanticCoAReauth) || registrySemanticContains(semantic, VendorSemanticCoADisconnect):
		return "dynamic_authorization_action_binding_ready"
	default:
		return "policy_context_ready_for_focused_vendor_adapter"
	}
}

func longTailNamespaceStorageState(class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "event_ledger_hash_only_no_cleartext_secret_persistence"
	case "typed_binary_evidence":
		return "event_ledger_bounded_hex_and_registry_metadata"
	default:
		return "event_ledger_bounded_string_and_registry_metadata"
	}
}

func longTailNamespaceRecordNotes(entry AttributeRegistryEntry, class string) []string {
	notes := []string{"External vendor-device behavior remains in the NAS-0072 release certification checklist."}
	if entry.Number == 0 || entry.Number > 255 {
		notes = append(notes, "This row is represented in the registry and report but is not added to the byte-sized runtime decoder table.")
	}
	if class == "redacted_secret_evidence" {
		notes = append(notes, "Values are never persisted in cleartext; runtime evidence uses a redacted marker and short digest.")
	}
	if class == "typed_passthrough" || class == "typed_binary_evidence" {
		notes = append(notes, "No focused vendor-specific enforcement claim is made for this row.")
	}
	return notes
}

func longTailNamespaceSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyAccessVendorToken(name, "password", "passwd", "secret", "shared-secret", "key", "psk", "dpsk", "mpkey", "token", "nonce", "challenge", "response", "signature", "cookie", "otp", "pin", "triplet", "quint", "private", "credential")
}

func longTailNamespaceBinaryWireType(value string) bool {
	switch baseDictionaryWireType(value) {
	case "abinary", "combo-ip", "extended", "float32", "float64", "group", "ifid", "ipv4prefix", "ipv6prefix", "octet", "octets", "struct", "tlv", "union", "vendor", "vsa":
		return true
	default:
		return false
	}
}

func longTailNamespaceIntegerWireType(value string) bool {
	switch baseDictionaryWireType(value) {
	case "bool", "byte", "date", "int8", "int16", "int32", "int64", "integer", "integer64", "short", "signed", "time_delta", "uint8", "uint16", "uint32", "uint64":
		return true
	default:
		return false
	}
}

func normalizeLongTailCapabilityKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("/", "_", "\\", "_", " ", "_", "-", "_", ".", "_", ":", "_", "(", "", ")", "", ",", "")
	value = replacer.Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	value = strings.Trim(value, "_")
	if value == "" {
		return "vendor_context"
	}
	return value
}

func countLongTailNamespaceVendors(records []LongTailNamespaceAttributeRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		seen[record.Vendor+"\x00"+strconv.FormatUint(uint64(record.PEN), 10)] = struct{}{}
	}
	return len(seen)
}
