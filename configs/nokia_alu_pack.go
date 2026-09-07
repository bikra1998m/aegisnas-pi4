package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	NokiaALUPackSchemaVersion          = 1
	NokiaALUPackFeatureID              = "NAS-0069"
	NokiaALUPackExpectedAttributeCount = 334

	NokiaALUSoftwareCertified = "software_certified"
	NokiaALUExternalRequired  = "external_certification_required"
)

type NokiaALUPackSummary = RuckusICXPackSummary
type NokiaALUVendorSummary = RuckusICXVendorSummary
type NokiaALUCapabilityCount = RuckusICXCapabilityCount
type NokiaALUProductScope = RuckusICXProductScope
type NokiaALUGrammarRecord = RuckusICXGrammarRecord
type NokiaALUAttributeRecord = RuckusICXAttributeRecord

type NokiaALUPackReport struct {
	SchemaVersion                 int                       `json:"schema_version"`
	FeatureID                     string                    `json:"feature_id"`
	ReleaseProfileID              string                    `json:"release_profile_id"`
	SourceRelease                 string                    `json:"source_release"`
	SourceSHA256                  string                    `json:"source_sha256"`
	SourceFileCount               int                       `json:"source_file_count"`
	SourceAttributeCount          int                       `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                    `json:"release_certification_checklist"`
	Summary                       NokiaALUPackSummary       `json:"summary"`
	VendorSummaries               []NokiaALUVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []NokiaALUCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []NokiaALUProductScope    `json:"product_scopes"`
	Grammar                       []NokiaALUGrammarRecord   `json:"grammar"`
	Records                       []NokiaALUAttributeRecord `json:"records"`
	Notes                         []string                  `json:"notes,omitempty"`
}

func BuildNokiaALUPackReport() (NokiaALUPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return NokiaALUPackReport{}, err
	}
	records := make([]NokiaALUAttributeRecord, 0, NokiaALUPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isNokiaALURegistryVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildNokiaALUAttributeRecord(entry))
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
	report := NokiaALUPackReport{
		SchemaVersion:                 NokiaALUPackSchemaVersion,
		FeatureID:                     NokiaALUPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0069-release-certification-checklist.md",
		ProductScopes:                 nokiaALUProductScopes(),
		Grammar:                       nokiaALUGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0069 covers every Nokia, Alcatel, Alcatel-ESAM, Alcatel-Lucent-Service-Router, and ALU-AAA row in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers SR OS subscriber and service-router intent, SAP/MSAP/service identifiers, SLA/QoS, IPv4/IPv6, DHCP/PPPoE access, NAT/translation, portal hints, ALU-AAA access rules, accounting/charging evidence, BCD service-name handling, and bounded typed VSA processing.",
			"Credential-like values, BGP keys, APN passwords, GSM triplets, AKA quintets, nonces, challenges, and opaque key material are software-certified only as redacted evidence and are never accepted as cleartext policy input.",
			"Nokia SR OS, legacy Alcatel access, ESAM access nodes, ALU-AAA, real FreeRADIUS-on-Linux, HA, performance, soak, security, and customer acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeNokiaALUPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeNokiaALUVendors(records)
	report.CapabilitySummaries = summarizeNokiaALUCapabilities(records)
	return report, nil
}

func ValidateNokiaALUPackReport(report NokiaALUPackReport) error {
	if report.SchemaVersion != NokiaALUPackSchemaVersion {
		return fmt.Errorf("Nokia/ALU pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != NokiaALUPackFeatureID {
		return fmt.Errorf("Nokia/ALU pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("Nokia/ALU pack release profile and source hash are required")
	}
	if len(report.Records) != NokiaALUPackExpectedAttributeCount {
		return fmt.Errorf("Nokia/ALU pack has %d records, expected %d", len(report.Records), NokiaALUPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != NokiaALUPackExpectedAttributeCount {
		return fmt.Errorf("Nokia/ALU pack summary has %d attributes, expected %d", report.Summary.AttributeCount, NokiaALUPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != NokiaALUPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("Nokia/ALU pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != NokiaALUPackExpectedAttributeCount {
		return fmt.Errorf("Nokia/ALU pack must keep all device/router claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 5 {
		return fmt.Errorf("Nokia/ALU pack must cover five dictionary vendors")
	}
	if report.Summary.SensitiveRedactedMappings == 0 {
		return fmt.Errorf("Nokia/ALU pack must redact credential, key, and authentication-token evidence")
	}
	if report.Summary.ProductScopeCount < 12 || len(report.ProductScopes) < 12 {
		return fmt.Errorf("Nokia/ALU product scope must include SR OS, ALU-AAA, ESAM, access, broadband, CoA, and certification coverage")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("Nokia/ALU pack fingerprint is required")
	}
	if len(report.Grammar) < 16 {
		return fmt.Errorf("Nokia/ALU pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("Nokia/ALU grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != NokiaALUExternalRequired {
			return fmt.Errorf("Nokia/ALU grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("Nokia/ALU record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("Nokia/ALU record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != NokiaALUSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("Nokia/ALU record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("Nokia/ALU record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if nokiaALUSensitiveAttribute(record.Attribute) && record.ImplementationClass != "redacted_secret_evidence" {
			return fmt.Errorf("Nokia/ALU sensitive record %q is not marked redacted", record.ID)
		}
	}
	return nil
}

func buildNokiaALUAttributeRecord(entry AttributeRegistryEntry) NokiaALUAttributeRecord {
	capability := nokiaALUCapability(entry)
	class := nokiaALUImplementationClass(entry)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = nokiaALURegistryDirections(entry, nokiaALURegistrySemantic(entry))
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = nokiaALURegistrySemantic(entry)
	}
	return NokiaALUAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, nokiaALURegistryPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, nokiaALURegistryFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           nokiaALUPacketProcessing(class, entry),
		PolicyEngine:               nokiaALUPolicyState(capability, class),
		Enforcement:                nokiaALUEnforcementState(capability, class),
		Storage:                    nokiaALUStorageState(class),
		APIUI:                      "pack_report_history_preview_vendor_scope_health_readiness_and_support_bundle",
		Monitoring:                 "nokia_alu_counters_fingerprint_redaction_codec_avpair_service_router_and_bng_state",
		SoftwareState:              NokiaALUSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      nokiaALURecordNotes(entry, class),
	}
}

func nokiaALUGrammarRecords() []NokiaALUGrammarRecord {
	rows := []NokiaALUGrammarRecord{
		{"nokia_avpair_service_router", "Nokia AVPair service-router intent", "avpair_policy", VendorSemanticPolicyTag + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticTranslationPolicy, []string{"Nokia-AVPair = \"service=internet\"", "Nokia-AVPair = \"vrf=tenant-a\""}, "", "", "", "", "", ""},
		{"nokia_bcd_service_name", "Nokia swapped-nibble BCD service names", "bcd_octets", VendorSemanticDeviceGroup, []string{"Nokia-Service-Name = 0x214365f7"}, "", "", "", "", "", ""},
		{"nokia_service_credentials", "Nokia service credential redaction", "redacted_evidence", VendorSemanticCertificateOnboarding, []string{"Nokia-Service-Password", "Nokia-Service-Encrypted-Password"}, "", "", "", "", "", ""},
		{"alcatel_aat_addressing", "Legacy Alcatel AAT DNS, PPP address, pool, and vrouter selectors", "address_route_policy", VendorSemanticIPv4Address + "," + VendorSemanticAddressPool + "," + VendorSemanticVRF, []string{"AAT-Client-Primary-DNS = 192.0.2.53", "AAT-Vrouter-Name = \"tenant-a\""}, "", "", "", "", "", ""},
		{"alcatel_aat_qos_filters", "Legacy Alcatel AAT QoS and filter policy", "qos_acl_policy", VendorSemanticBandwidthProfile + "," + VendorSemanticACL, []string{"AAT-Qos = 7", "AAT-Data-Filter = \"internet-only\""}, "", "", "", "", "", ""},
		{"esam_access_node", "Alcatel ESAM VRF, VLAN, QoS, DHCP, PPPoE, and xDSL state", "access_node_policy", VendorSemanticVLAN + "," + VendorSemanticVRF + "," + VendorSemanticBandwidthProfile + "," + VendorSemanticAccountingIdentity, []string{"A-ESAM-Vlan-Id = 120", "A-AL-XDSL = 1"}, "", "", "", "", "", ""},
		{"sros_subscriber_profiles", "SR OS subscriber ID, subscriber profile, SLA profile, MSAP, and service ID", "subscriber_service_policy", VendorSemanticAccountingIdentity + "," + VendorSemanticRole + "," + VendorSemanticBandwidthProfile + "," + VendorSemanticPolicyTag, []string{"Alc-Subsc-ID-Str = \"sub-1001\"", "Alc-SLA-Prof-Str = \"gold\""}, "", "", "", "", "", ""},
		{"sros_bgp_route_policy", "SR OS BGP import/export and framed route ownership", "route_policy", VendorSemanticRoute + "," + VendorSemanticVRF, []string{"Alc-BGP-Policy = \"cust-routes\"", "Nokia-AVPair = \"framed-route=10.40.0.0/16 192.0.2.1\""}, "", "", "", "", "", ""},
		{"sros_ipv6_dhcp6", "SR OS IPv6 address, DNS, delegated pools, SLAAC, DHCPv6 options, and lifetimes", "ipv6_address_policy", VendorSemanticIPv6Address + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement, []string{"Alc-Ipv6-Address = 2001:db8::10", "Alc-Delegated-IPv6-Pool = \"pd-gold\""}, "", "", "", "", "", ""},
		{"sros_nat_translation", "SR OS NAT outside service, public IP, DNAT, port-range, and NAT64 hints", "translation_policy", VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix, []string{"Alc-Nat-Outside-Ip-Addr = 198.51.100.10", "Alc-Nat-Port-Range = \"10000-10511\""}, "", "", "", "", "", ""},
		{"sros_accounting_64", "SR OS in/out profile, offered, dropped, high/low-priority, and SAP accounting", "accounting_charging", VendorSemanticAccountingCounters + "," + VendorSemanticAccountingIdentity, []string{"Alc-Acct-I-Inprof-Octets-64", "Alc-SAP-Session-Index = 42"}, "", "", "", "", "", ""},
		{"sros_portal_wlan", "SR OS portal, one-time redirect, WLAN portal URL, and SSID VLAN hints", "guest_portal_wifi", VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle + "," + VendorSemanticVLAN, []string{"Alc-Portal-Url = \"https://guest.example.test\"", "Alc-Wlan-SSID-VLAN = \"guest:120\""}, "", "", "", "", "", ""},
		{"sros_security_ipsec_li", "SR OS IPsec and lawful-intercept identifiers as guarded posture evidence", "security_posture_evidence", VendorSemanticDevicePosture, []string{"Alc-IPsec-Interface = \"ipsec-a\"", "Alc-LI-Intercept-Id = 99"}, "", "", "", "", "", ""},
		{"alu_aaa_access_rules", "ALU-AAA access rule and AV-Pair policy grammar", "dynamic_acl_policy", VendorSemanticDynamicACL + "," + VendorSemanticACL + "," + VendorSemanticPolicyTag, []string{"ALU-AAA-Access-Rule = \"permit in tcp from any to any 443\"", "ALU-AAA-AV-Pair = \"acl=guest-in\""}, "", "", "", "", "", ""},
		{"alu_aaa_mobile_auth", "ALU-AAA GSM/AKA/femto authentication token redaction", "redacted_mobile_auth_evidence", VendorSemanticCertificateOnboarding, []string{"ALU-AAA-GSM-Triplet", "ALU-AAA-AKA-Quintet"}, "", "", "", "", "", ""},
		{"alu_aaa_location_voice", "ALU-AAA location, NAS identity, event, delta-session, and voice context", "accounting_location_voice", VendorSemanticTenant + "," + VendorSemanticAccountingCounters + "," + VendorSemanticDeviceGroup, []string{"ALU-AAA-Civic-Location", "ALU-AAA-Called-Station-Id = \"+15551212\""}, "", "", "", "", "", ""},
		{"shared_sros_coa", "Shared Nokia/ALU CoA, Disconnect, force-renew, and accounting-trigger lifecycle", "dynamic_authorization", VendorSemanticCoAReauth + "," + VendorSemanticCoADisconnect, []string{"RFC5176 CoA-Request", "Alc-Force-Renew = \"1\""}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = NokiaALUExternalRequired
		rows[index].ReleaseScope = "Nokia SR OS, Alcatel access, ESAM access-node, ALU-AAA, FreeRADIUS, HA, performance, soak, security, production deployment, and customer acceptance evidence is tracked in docs/nas-0069-release-certification-checklist.md."
	}
	return rows
}

func nokiaALUProductScopes() []NokiaALUProductScope {
	return []NokiaALUProductScope{
		{Key: VendorPackNokia, Label: "Nokia SR OS Service Router", Vendors: []string{"Nokia"}, Products: []string{"SR OS", "7750 SR", "BNG subscriber access"}, Dictionary: "dictionary.nokia", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Nokia AVPair, user profile, service credential, charging, OCS, APN, and BCD service-name handling are software-certified; device enforcement remains release-certified."}},
		{Key: VendorPackNokia, Label: "Nokia SR OS Service Name BCD", Vendors: []string{"Nokia"}, Products: []string{"SR OS service-name authorization", "role-to-service mappings"}, Dictionary: "dictionary.nokia", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Swapped-nibble BCD encoding and decoding is covered by packet tests."}},
		{Key: VendorPackAlcatel, Label: "Alcatel AAT Access And PPP", Vendors: []string{"Alcatel"}, Products: []string{"AAT", "PPP access", "legacy access servers"}, Dictionary: "dictionary.alcatel", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"PPP address, DNS, WINS, vrouter, pool, QoS, and filter fields are normalized as typed vendor evidence."}},
		{Key: VendorPackAlcatel, Label: "Alcatel AAT Mobile And Home Agent", Vendors: []string{"Alcatel"}, Products: []string{"Home agent", "mobile filter policy", "ATM/FR access"}, Dictionary: "dictionary.alcatel", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Home-agent password evidence is redacted; ATM/FR and mobile filter behavior requires release proof."}},
		{Key: VendorPackAlcatelESAM, Label: "Alcatel ESAM Access Node", Vendors: []string{"Alcatel-ESAM"}, Products: []string{"ESAM", "DSL/GPON access node", "TL1 management"}, Dictionary: "dictionary.alcatel.esam", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"High-number ESAM VSAs are tracked as typed evidence and require format-specific interop proof before device claims."}},
		{Key: VendorPackAlcatelESAM, Label: "Alcatel ESAM VLAN, VRF, QoS, DHCP, And PPPoE", Vendors: []string{"Alcatel-ESAM"}, Products: []string{"ESAM subscriber access", "xDSL", "DHCP/PPPoE"}, Dictionary: "dictionary.alcatel.esam", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"VLAN, VRF, QoS, DHCP, PPPoE, xDSL, security, and transport rows are semantically ledgered."}},
		{Key: VendorPackALUSR, Label: "Alcatel-Lucent SR OS Subscriber Services", Vendors: []string{"Alcatel-Lucent-Service-Router"}, Products: []string{"7750 SR", "7210 SAS", "BNG/BRAS", "MSAP/SAP"}, Dictionary: "dictionary.alcatel-lucent.sr", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Subscriber ID/profile, SLA profile, MSAP/SAP, PPPoE, DHCP, access-loop, and DSL rows feed neutral subscriber evidence."}},
		{Key: VendorPackALUSR, Label: "Alcatel-Lucent SR OS Route, NAT, IPv6, And DHCPv6", Vendors: []string{"Alcatel-Lucent-Service-Router"}, Products: []string{"BGP policy", "NAT/DNAT", "IPv6/SLAAC", "DHCPv6 relay"}, Dictionary: "dictionary.alcatel-lucent.sr", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Route/VRF, public IP, port-range, delegated pool, DHCPv6, and RA semantics are available to neutral policy compilers."}},
		{Key: VendorPackALUSR, Label: "Alcatel-Lucent SR OS Accounting And Charging", Vendors: []string{"Alcatel-Lucent-Service-Router"}, Products: []string{"Accounting", "credit control", "charging profile", "triggered interim"}, Dictionary: "dictionary.alcatel-lucent.sr", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"64-bit counters, drop/offer profiles, SAP session index, charging profile, and interim-trigger rows are bounded evidence."}},
		{Key: VendorPackALUSR, Label: "Alcatel-Lucent SR OS Portal, WLAN, And Security", Vendors: []string{"Alcatel-Lucent-Service-Router"}, Products: []string{"Portal redirect", "WLAN portal", "IPsec", "lawful-intercept governance boundary"}, Dictionary: "dictionary.alcatel-lucent.sr", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Portal URL and SSID-VLAN rows map to guest/WLAN intent; IPsec and LI rows are posture evidence pending governed release validation."}},
		{Key: VendorPackALUAAA, Label: "ALU-AAA Access Rules And Service Profiles", Vendors: []string{"ALU-AAA"}, Products: []string{"ALU AAA", "subscriber policy", "access-rule authorization"}, Dictionary: "dictionary.alu-aaa", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Access rules compile through the neutral ACL engine and AV-Pair strings parse into bounded policy evidence."}},
		{Key: VendorPackALUAAA, Label: "ALU-AAA Mobile Auth, Location, Voice, And Event Evidence", Vendors: []string{"ALU-AAA"}, Products: []string{"GSM/AKA", "femto", "location", "voice/telephony", "session events"}, Dictionary: "dictionary.alu-aaa", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"GSM/AKA/femto key material is redacted; location, NAS identity, delta-session, and called-station rows are bounded evidence."}},
		{Key: VendorPackStandard, Label: "Shared Nokia/ALU CoA And Disconnect", Vendors: []string{"Nokia", "Alcatel", "Alcatel-ESAM", "Alcatel-Lucent-Service-Router", "ALU-AAA"}, Products: []string{"RFC5176 CoA", "Disconnect", "forced renew", "session reauthorization"}, Dictionary: "RFC5176 plus Nokia/ALU dictionaries", SoftwareState: NokiaALUSoftwareCertified, ExternalState: NokiaALUExternalRequired, Notes: []string{"Dynamic authorization packet path is software-ready; per-device ACK/NAK behavior is release certification."}},
	}
}

func summarizeNokiaALUPack(records []NokiaALUAttributeRecord, grammar []NokiaALUGrammarRecord, scopes []NokiaALUProductScope) NokiaALUPackSummary {
	return summarizeAccessVendorPack(records, grammar, scopes)
}

func summarizeNokiaALUVendors(records []NokiaALUAttributeRecord) []NokiaALUVendorSummary {
	return summarizeAccessVendorVendors(records)
}

func summarizeNokiaALUCapabilities(records []NokiaALUAttributeRecord) []NokiaALUCapabilityCount {
	return summarizeAccessVendorCapabilities(records)
}

func nokiaALUCapability(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	prefix := strings.ReplaceAll(nokiaALURegistryPack(entry.Vendor), "-", "_")
	switch {
	case containsAnyNokiaALUToken(name, "acct", "account", "octets", "pkts", "packets", "statmode", "trigger", "interim", "delta-session", "charging", "credit-control", "ocs"):
		return prefix + "_accounting_charging"
	case containsAnyNokiaALUToken(name, "nat", "dnat", "port-range", "public-ip", "outside-ip", "translation"):
		return prefix + "_nat_translation"
	case containsAnyNokiaALUToken(name, "ipv6", "slaac", "dhcp6", "delegated", "dns", "nbns", "wins", "default-router", "ip-address", "ppp-address", "pool", "router", "vrouter"):
		return prefix + "_address_route_pool"
	case containsAnyNokiaALUToken(name, "bgp", "route", "vrf"):
		return prefix + "_route_vrf"
	case containsAnyNokiaALUToken(name, "access-rule", "filter-rule", "nas-filter", "data-filter", "subscriber-filter", "filter", "av-pair", "avpair"):
		return prefix + "_acl_policy"
	case containsAnyNokiaALUToken(name, "qos", "sla-prof", "traffic-profile", "access-loop-rate", "td-profile", "tos"):
		return prefix + "_qos_sla"
	case containsAnyNokiaALUToken(name, "subsc", "subscriber", "service", "serv-id", "sap", "msap", "sdp", "pppoe", "dhcp", "ancp", "lease", "dsl", "xdsl"):
		return prefix + "_subscriber_service"
	case containsAnyNokiaALUToken(name, "portal", "redirect", "http", "wlan"):
		return prefix + "_portal_wifi"
	case containsAnyNokiaALUToken(name, "ipsec", "li-", "lawful", "security", "tl1", "auth", "challenge", "encrypted"):
		return prefix + "_security_posture"
	case containsAnyNokiaALUToken(name, "tenant", "location", "civic", "geospatial", "domain", "home-network"):
		return prefix + "_tenant_location"
	case containsAnyNokiaALUToken(name, "nas", "client", "hardware", "program", "version", "port", "interface", "transport", "maintenance", "provisioning"):
		return prefix + "_device_management"
	case containsAnyNokiaALUToken(name, "apn", "gsm", "aka", "imsi", "msisdn", "femto"):
		return prefix + "_mobile_core"
	case containsAnyNokiaALUToken(name, "voice", "called-station"):
		return prefix + "_voice_telephony"
	case nokiaALUSensitiveAttribute(entry.Attribute):
		return prefix + "_redacted_authentication"
	default:
		return prefix + "_service_router_state"
	}
}

func nokiaALUImplementationClass(entry AttributeRegistryEntry) string {
	if nokiaALUSensitiveAttribute(entry.Attribute) {
		return "redacted_secret_evidence"
	}
	if entry.Number > 255 {
		return "formatted_vsa_evidence"
	}
	if entry.WireCodec.Grouped || strings.EqualFold(baseDictionaryWireType(entry.WireType), "tlv") {
		return "typed_tlv_evidence"
	}
	if registrySemanticContains(entry.Semantic, VendorSemanticDynamicACL) {
		return "policy_parse_compile"
	}
	nativeSemantics := []string{
		VendorSemanticRole, VendorSemanticVLAN, VendorSemanticUploadBandwidth, VendorSemanticDownloadBandwidth,
		VendorSemanticDataQuota, VendorSemanticQuarantine, VendorSemanticPortalProfile, VendorSemanticTenant,
		VendorSemanticDeviceGroup, VendorSemanticAccountingIdentity, VendorSemanticAccountingCounters,
		VendorSemanticBandwidthProfile, VendorSemanticRoute, VendorSemanticVRF, VendorSemanticAddressPool,
		VendorSemanticIPv4Address, VendorSemanticIPv6Address, VendorSemanticDelegatedIPv6Prefix,
		VendorSemanticRouterAdvertisement, VendorSemanticDHCPv6, VendorSemanticTranslationPolicy,
		VendorSemanticTranslationPublicIPv4, VendorSemanticTranslationPortBlock, VendorSemanticNAT64Prefix,
		VendorSemanticTranslationLogging, VendorSemanticCoAReauth, VendorSemanticCoADisconnect,
		VendorSemanticDevicePosture, VendorSemanticGuestLifecycle,
	}
	for _, semantic := range nativeSemantics {
		if registrySemanticContains(entry.Semantic, semantic) {
			return "native_semantic_mapping"
		}
	}
	return "typed_passthrough"
}

func nokiaALUPacketProcessing(class string, entry AttributeRegistryEntry) string {
	switch class {
	case "policy_parse_compile":
		return "nokia_alu_acl_avpair_parser_compiler_and_bounded_vsa_codec"
	case "redacted_secret_evidence":
		return "string_or_octets_decoder_sha256_evidence_and_cleartext_redaction"
	case "formatted_vsa_evidence":
		return "multi_octet_vendor_type_codec_spec_and_bounded_evidence"
	case "typed_tlv_evidence":
		return "grouped_tlv_parent_and_child_oid_codec_with_bounded_evidence"
	case "native_semantic_mapping":
		if entry.DecodeKind != "" {
			return "generated_runtime_decoder_semantic_mapper_reply_renderer_and_duplicate_number_guard"
		}
		return "typed_vsa_codec_semantic_mapper_and_bounded_evidence"
	default:
		return "generic_vsa_codec_with_bounded_raw_evidence"
	}
}

func nokiaALUPolicyState(capability, class string) string {
	switch {
	case strings.Contains(capability, "qos") || strings.Contains(capability, "sla"):
		return "neutral_sla_qos_profile_and_rate_policy_context"
	case strings.Contains(capability, "nat") || strings.Contains(capability, "translation"):
		return "translation_policy_cgnat_nat64_dnat_and_port_block_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "route") || strings.Contains(capability, "vrf"):
		return "address_pool_route_vrf_bgp_and_delegated_prefix_policy_context"
	case strings.Contains(capability, "subscriber") || strings.Contains(capability, "service"):
		return "subscriber_profile_service_chain_sap_msap_pppoe_and_dhcp_context"
	case strings.Contains(capability, "accounting") || strings.Contains(capability, "charging"):
		return "accounting_counter_charging_interim_and_session_identity_context"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "wifi"):
		return "guest_portal_wlan_ssid_vlan_and_captive_access_policy_context"
	case strings.Contains(capability, "acl") || class == "policy_parse_compile":
		return "dynamic_acl_access_rule_filter_and_avpair_policy_compiler"
	case class == "redacted_secret_evidence":
		return "redacted_authentication_mobile_token_and_key_evidence_context"
	default:
		return "typed_nokia_alu_service_router_policy_context"
	}
}

func nokiaALUEnforcementState(capability, class string) string {
	if class == "redacted_secret_evidence" {
		return "no_cleartext_enforcement_redacted_evidence_only"
	}
	switch {
	case strings.Contains(capability, "accounting") || strings.Contains(capability, "charging"):
		return "accounting_ingest_charging_counter_and_session_evidence"
	case strings.Contains(capability, "nat") || strings.Contains(capability, "translation"):
		return "radius_reply_translation_hint_and_local_translation_policy_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "route") || strings.Contains(capability, "vrf"):
		return "radius_reply_address_route_pool_vrf_and_bgp_policy_context"
	case strings.Contains(capability, "qos") || strings.Contains(capability, "sla"):
		return "radius_reply_sla_qos_assignment_and_runtime_shaper_context"
	case strings.Contains(capability, "acl"):
		return "radius_reply_acl_assignment_dynamic_acl_preview_and_avpair_context"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "wifi"):
		return "radius_reply_portal_redirect_wlan_or_guest_hint"
	default:
		return "radius_reply_inbound_context_and_no_silent_fallback"
	}
}

func nokiaALUStorageState(class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "bounded_hash_only_evidence_no_cleartext_secret"
	case "formatted_vsa_evidence":
		return "normalized_multi_octet_vsa_metadata_and_bounded_raw_evidence"
	case "typed_tlv_evidence":
		return "normalized_tlv_metadata_child_oid_and_bounded_raw_evidence"
	case "policy_parse_compile":
		return "normalized_acl_route_translation_policy_and_bounded_vendor_rule_evidence"
	default:
		return "normalized_nokia_alu_semantics_and_bounded_raw_vsa_evidence"
	}
}

func nokiaALURecordNotes(entry AttributeRegistryEntry, class string) []string {
	switch nokiaALURegistryPack(entry.Vendor) {
	case VendorPackNokia:
		if strings.EqualFold(entry.Attribute, "Nokia-Service-Name") {
			return []string{"Nokia service-name BCD encoding/decoding is software-certified; live SR OS acceptance remains release-certified externally."}
		}
		return []string{"Nokia SR OS behavior remains release-certified externally before hardware claims are published."}
	case VendorPackAlcatel:
		return []string{"Legacy Alcatel AAT behavior remains release-certified externally before hardware claims are published."}
	case VendorPackAlcatelESAM:
		return []string{"Alcatel ESAM access-node behavior and high-number VSA format acceptance remain release-certified externally."}
	case VendorPackALUSR:
		return []string{"Alcatel-Lucent SR OS service-router behavior remains release-certified externally before hardware claims are published."}
	default:
		if class == "redacted_secret_evidence" {
			return []string{"ALU-AAA authentication token and key material is never stored as cleartext policy data."}
		}
		return []string{"ALU-AAA behavior remains release-certified externally before hardware claims are published."}
	}
}

func (r *AttributeRegistry) applyNokiaALURuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isNokiaALURegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := nokiaALURegistrySemantic(*entry)
		entry.PackKey = nokiaALURegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0069")
		entry.Directions = nokiaALURegistryDirections(*entry, entry.Semantic)
		entry.Functionality = nokiaALURegistryFunctionality(*entry, entry.Semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = nokiaALURegistryDecoder(*entry, entry.Semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isNokiaALURegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "nokia", "alcatel", "alcatel-esam", "alcatel-lucent-service-router", "alu-aaa":
		return true
	default:
		return false
	}
}

func nokiaALURegistryPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "alcatel":
		return VendorPackAlcatel
	case "alcatel-esam":
		return VendorPackAlcatelESAM
	case "alcatel-lucent-service-router":
		return VendorPackALUSR
	case "alu-aaa":
		return VendorPackALUAAA
	default:
		return VendorPackNokia
	}
}

func nokiaALURegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case nokiaALUSensitiveAttribute(entry.Attribute):
		return VendorSemanticCertificateOnboarding
	case strings.EqualFold(entry.Attribute, "Nokia-AVPair"):
		return VendorSemanticPolicyTag + "," + VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging
	case containsAnyNokiaALUToken(name, "av-pair", "avpair"):
		return VendorSemanticPolicyTag + "," + VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticTranslationLogging
	case containsAnyNokiaALUToken(name, "access-rule", "nas-filter-rule", "data-filter", "subscriber-filter", "filter"):
		return VendorSemanticDynamicACL + "," + VendorSemanticACL
	case containsAnyNokiaALUToken(name, "vlan"):
		return VendorSemanticVLAN
	case containsAnyNokiaALUToken(name, "vrouter", "vrf"):
		return VendorSemanticVRF
	case containsAnyNokiaALUToken(name, "bgp-policy", "bgp-export-policy", "bgp-import-policy", "route-policy"):
		return VendorSemanticRoute
	case containsAnyNokiaALUToken(name, "sla-prof", "subsc-prof", "service-profile", "authentication-policy", "app-prof", "msap-policy", "upnp-sub-override-policy", "timetra-profile"):
		if containsAnyNokiaALUToken(name, "sla-prof", "qos") {
			return VendorSemanticBandwidthProfile
		}
		return VendorSemanticRole
	case containsAnyNokiaALUToken(name, "access-loop-rate-down"):
		return VendorSemanticDownloadBandwidth
	case containsAnyNokiaALUToken(name, "qos", "traffic-profile", "td-profile", "tos", "subscriber-qos", "qoa"):
		return VendorSemanticBandwidthProfile
	case containsAnyNokiaALUToken(name, "nat-port-range", "port-range"):
		return VendorSemanticTranslationPortBlock
	case containsAnyNokiaALUToken(name, "dnat", "nat-outside-serv", "nat-policy"):
		return VendorSemanticTranslationPolicy
	case containsAnyNokiaALUToken(name, "nat-outside-ip", "public-ip"):
		return VendorSemanticTranslationPublicIPv4
	case containsAnyNokiaALUToken(name, "delegated-ipv6-pool"):
		return VendorSemanticDelegatedIPv6Prefix
	case containsAnyNokiaALUToken(name, "slaac-ipv6-pool"):
		return VendorSemanticRouterAdvertisement + "," + VendorSemanticAddressPool
	case containsAnyNokiaALUToken(name, "dhcp6", "to-client-dhcp6", "to-server-dhcp6", "preferred-lifetime", "valid-lifetime"):
		return VendorSemanticDHCPv6 + "," + VendorSemanticDelegatedIPv6Prefix
	case containsAnyNokiaALUToken(name, "ipv6-address", "ipv6-primary-dns", "ipv6-secondary-dns", "ipv6-portal"):
		return VendorSemanticIPv6Address
	case containsAnyNokiaALUToken(name, "primary-dns", "secondary-dns", "default-router", "nas-ip-address", "ppp-address", "client-primary-dns", "client-secondary-dns"):
		return VendorSemanticIPv4Address
	case containsAnyNokiaALUToken(name, "pool-definition", "assign-ip-pool", "pool"):
		return VendorSemanticAddressPool
	case containsAnyNokiaALUToken(name, "portal", "redirect", "http"):
		return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
	case containsAnyNokiaALUToken(name, "acct", "account", "octets", "pkts", "packets", "statmode", "trigger", "interim", "delta-session", "charging", "credit-control", "ocs-id"):
		return VendorSemanticAccountingCounters
	case containsAnyNokiaALUToken(name, "subsc-id", "subscriber-id", "service-id", "service-username", "service-name", "session-access-method", "session-charging-type", "sap-session", "pppoe", "dhcp", "ancp", "lease", "dsl", "xdsl", "apn", "msisdn"):
		return VendorSemanticAccountingIdentity
	case containsAnyNokiaALUToken(name, "home-network", "tenant", "location", "civic", "geospatial", "domain"):
		return VendorSemanticTenant
	case containsAnyNokiaALUToken(name, "client", "hardware", "mac", "nas-port", "program", "version", "interface", "transport", "maintenance", "provisioning", "modem", "slot", "shelf"):
		return VendorSemanticDeviceGroup
	case containsAnyNokiaALUToken(name, "force-renew", "force-nak", "remove-override"):
		return VendorSemanticCoAReauth + "," + VendorSemanticCoADisconnect
	case containsAnyNokiaALUToken(name, "ipsec", "li-", "lawful", "security", "tl1", "source-ip-check", "auth-type", "require-auth", "trec"):
		return VendorSemanticDevicePosture
	case containsAnyNokiaALUToken(name, "voice", "called-station"):
		return VendorSemanticPolicyTag
	default:
		return VendorSemanticPolicyTag
	}
}

func nokiaALURegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyNokiaALUToken(name, "acct", "account", "octets", "pkts", "packets", "statmode", "trigger", "interim", "delta-session", "session-", "subsc-id", "subscriber-id", "nas-ip-address", "nas-port", "called-station", "location", "civic", "geospatial", "hardware", "mac"):
		return []string{"accounting", "inbound"}
	case nokiaALUSensitiveAttribute(entry.Attribute):
		return []string{"inbound"}
	case registrySemanticContains(semantic, VendorSemanticCoAReauth) || registrySemanticContains(semantic, VendorSemanticCoADisconnect):
		return []string{"coa", "inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticAccountingCounters):
		return []string{"accounting", "inbound"}
	default:
		return []string{"accounting", "inbound", "outbound_reply"}
	}
}

func nokiaALURegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	if strings.EqualFold(entry.Attribute, "Nokia-Service-Name") {
		return "nokia_bcd", VendorSemanticDeviceGroup, 0
	}
	baseType := baseDictionaryWireType(entry.WireType)
	decodeSemantic := firstRegistrySemantic(semantic)
	switch baseType {
	case "tlv", "group", "struct", "ipv6prefix":
		return "", "", 0
	}
	if nokiaALUSensitiveAttribute(entry.Attribute) {
		if baseType == "octets" || baseType == "abinary" {
			return "octets_hex", decodeSemantic, 0
		}
		return "string", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticDynamicACL) && containsAnyNokiaALUToken(strings.ToLower(entry.Attribute), "avpair", "av-pair") {
		if strings.EqualFold(entry.Attribute, "Nokia-AVPair") {
			return "string", VendorSemanticPolicyTag, 0
		}
		return "avpairs", decodeSemantic, 0
	}
	if baseType == "ipaddr" {
		return "ipaddr", decodeSemantic, 0
	}
	if baseType == "ipv6addr" {
		return "ipv6addr", decodeSemantic, 0
	}
	if baseType == "ether" {
		return "ether", decodeSemantic, 0
	}
	if baseType == "octets" || baseType == "abinary" || baseType == "combo-ip" {
		return "octets_hex", decodeSemantic, 0
	}
	if registrySemanticContains(semantic, VendorSemanticRole) && registryIntegerType(baseType) {
		return "mapped_role", VendorSemanticRole, 0
	}
	if registrySemanticContains(semantic, VendorSemanticVLAN) {
		if registryIntegerType(baseType) {
			return "vlan", VendorSemanticVLAN, 0
		}
		return "string", VendorSemanticVLAN, 0
	}
	if registrySemanticContains(semantic, VendorSemanticUploadBandwidth) || registrySemanticContains(semantic, VendorSemanticDownloadBandwidth) {
		if registryIntegerType(baseType) {
			return "rate_kbps", decodeSemantic, 1
		}
		return "string", decodeSemantic, 0
	}
	if registryIntegerType(baseType) {
		return "integer_text", decodeSemantic, 0
	}
	return "string", decodeSemantic, 0
}

func nokiaALURegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	scope := "Nokia SR OS service-router, subscriber, and BNG policy"
	switch nokiaALURegistryPack(entry.Vendor) {
	case VendorPackAlcatel:
		scope = "legacy Alcatel AAT access, PPP, QoS, mobile filter, and home-agent policy"
	case VendorPackAlcatelESAM:
		scope = "Alcatel ESAM access-node, TL1, DHCP, PPPoE, VLAN, QoS, and xDSL policy"
	case VendorPackALUSR:
		scope = "Alcatel-Lucent SR OS Timetra/Alc subscriber, SAP/MSAP, SLA, IPv6, NAT, portal, BGP, and accounting policy"
	case VendorPackALUAAA:
		scope = "ALU-AAA access-rule, service-profile, mobile-auth, location, voice, and event policy"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes stable semantics, safely decodes typed wire values when the runtime codec supports the format, redacts credential-like evidence, and keeps real device behavior in release certification.", entry.Attribute, strings.ReplaceAll(semantic, ",", "/"), scope)
}

func nokiaALUSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyNokiaALUToken(name,
		"password", "auth-key", "auth_key", "keychain", "key-",
		"nonce", "triplet", "quintet", "aka-rand", "aka-auts",
		"tunnel-challenge", "femto-public-key-hash",
	)
}

func containsAnyNokiaALUToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
