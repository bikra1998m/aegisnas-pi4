package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	BroadbandVendorPackSchemaVersion          = 1
	BroadbandVendorPackFeatureID              = "NAS-0068"
	BroadbandVendorPackExpectedAttributeCount = 308

	BroadbandVendorSoftwareCertified = "software_certified"
	BroadbandVendorExternalRequired  = "external_certification_required"
)

type BroadbandVendorPackSummary = RuckusICXPackSummary
type BroadbandVendorVendorSummary = RuckusICXVendorSummary
type BroadbandVendorCapabilityCount = RuckusICXCapabilityCount
type BroadbandVendorProductScope = RuckusICXProductScope
type BroadbandVendorGrammarRecord = RuckusICXGrammarRecord
type BroadbandVendorAttributeRecord = RuckusICXAttributeRecord

type BroadbandVendorPackReport struct {
	SchemaVersion                 int                              `json:"schema_version"`
	FeatureID                     string                           `json:"feature_id"`
	ReleaseProfileID              string                           `json:"release_profile_id"`
	SourceRelease                 string                           `json:"source_release"`
	SourceSHA256                  string                           `json:"source_sha256"`
	SourceFileCount               int                              `json:"source_file_count"`
	SourceAttributeCount          int                              `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                           `json:"release_certification_checklist"`
	Summary                       BroadbandVendorPackSummary       `json:"summary"`
	VendorSummaries               []BroadbandVendorVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []BroadbandVendorCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []BroadbandVendorProductScope    `json:"product_scopes"`
	Grammar                       []BroadbandVendorGrammarRecord   `json:"grammar"`
	Records                       []BroadbandVendorAttributeRecord `json:"records"`
	Notes                         []string                         `json:"notes,omitempty"`
}

func BuildBroadbandVendorPackReport() (BroadbandVendorPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return BroadbandVendorPackReport{}, err
	}
	records := make([]BroadbandVendorAttributeRecord, 0, BroadbandVendorPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isBroadbandVendorRegistryVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildBroadbandVendorAttributeRecord(entry))
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
	report := BroadbandVendorPackReport{
		SchemaVersion:                 BroadbandVendorPackSchemaVersion,
		FeatureID:                     BroadbandVendorPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0068-release-certification-checklist.md",
		ProductScopes:                 broadbandVendorProductScopes(),
		Grammar:                       broadbandVendorGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0068 covers every Huawei, H3C, and ZTE row in the pinned FreeRADIUS 3.2.8 audit.",
			"Software certification covers typed VSA decoding, duplicate-number ledgering, broadband subscriber state semantics, pools, routes, QoS, command authorization, multicast, portal, accounting, charging, NAT/translation, CoA boundaries, API/UI visibility, durable evidence, and readiness checks.",
			"Huawei credential-like password, DPSK, and web-authentication fields are software-certified as redacted typed evidence and are never treated as cleartext policy input.",
			"Huawei MA/CloudEngine/Agile Controller/iMaster, H3C Comware/IMC, ZTE ZX/BNG, real FreeRADIUS-on-Linux, HA, performance, soak, security, and production acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeBroadbandVendorPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeBroadbandVendorVendors(records)
	report.CapabilitySummaries = summarizeBroadbandVendorCapabilities(records)
	return report, nil
}

func ValidateBroadbandVendorPackReport(report BroadbandVendorPackReport) error {
	if report.SchemaVersion != BroadbandVendorPackSchemaVersion {
		return fmt.Errorf("broadband vendor pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != BroadbandVendorPackFeatureID {
		return fmt.Errorf("broadband vendor pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("broadband vendor pack release profile and source hash are required")
	}
	if len(report.Records) != BroadbandVendorPackExpectedAttributeCount {
		return fmt.Errorf("broadband vendor pack has %d records, expected %d", len(report.Records), BroadbandVendorPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != BroadbandVendorPackExpectedAttributeCount {
		return fmt.Errorf("broadband vendor pack summary has %d attributes, expected %d", report.Summary.AttributeCount, BroadbandVendorPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != BroadbandVendorPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("broadband vendor pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != BroadbandVendorPackExpectedAttributeCount {
		return fmt.Errorf("broadband vendor pack must keep all device/controller claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 3 {
		return fmt.Errorf("broadband vendor pack must cover Huawei, H3C, and ZTE dictionary vendors")
	}
	if report.Summary.SensitiveRedactedMappings != 3 {
		return fmt.Errorf("broadband vendor pack must redact Huawei password, DPSK, and web-authentication evidence")
	}
	if report.Summary.ProductScopeCount < 10 || len(report.ProductScopes) < 10 {
		return fmt.Errorf("broadband vendor pack product scope must include Huawei, H3C, ZTE, shared BNG, CoA, and controller coverage")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("broadband vendor pack fingerprint is required")
	}
	if len(report.Grammar) < 14 {
		return fmt.Errorf("broadband vendor pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("broadband vendor grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != BroadbandVendorExternalRequired {
			return fmt.Errorf("broadband vendor grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("broadband vendor record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("broadband vendor record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != BroadbandVendorSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("broadband vendor record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("broadband vendor record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if broadbandVendorSensitiveAttribute(record.Attribute) && record.ImplementationClass != "redacted_secret_evidence" {
			return fmt.Errorf("broadband vendor sensitive record %q is not marked redacted", record.ID)
		}
	}
	return nil
}

func buildBroadbandVendorAttributeRecord(entry AttributeRegistryEntry) BroadbandVendorAttributeRecord {
	capability := broadbandVendorCapability(entry)
	class := broadbandVendorImplementationClass(entry)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = broadbandVendorRegistryDirections(entry, broadbandVendorRegistrySemantic(entry))
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = broadbandVendorRegistrySemantic(entry)
	}
	return BroadbandVendorAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, broadbandVendorRegistryPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, broadbandVendorRegistryFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           broadbandVendorPacketProcessing(class, entry),
		PolicyEngine:               broadbandVendorPolicyState(capability, class),
		Enforcement:                broadbandVendorEnforcementState(capability, class),
		Storage:                    broadbandVendorStorageState(class),
		APIUI:                      "pack_report_history_preview_vendor_scope_health_readiness_and_support_bundle",
		Monitoring:                 "broadband_vendor_counters_fingerprint_redaction_duplicate_number_codec_and_typed_packet_state",
		SoftwareState:              BroadbandVendorSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      broadbandVendorRecordNotes(entry, class),
	}
}

func broadbandVendorGrammarRecords() []BroadbandVendorGrammarRecord {
	rows := []BroadbandVendorGrammarRecord{
		{"huawei_qos_hierarchy", "Huawei CIR/PIR, average-rate, burst, priority, and profile QoS", "qos_policy", VendorSemanticUploadBandwidth + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticBandwidthProfile, []string{"Huawei-Input-Average-Rate = 25000", "Huawei-Output-Average-Rate = 75000", "Huawei-Qos-Profile-Name = \"gold\""}, "", "", "", "", "", ""},
		{"huawei_address_pool_route", "Huawei framed pool, IPv4, IPv6, delegated-prefix, DNS, and route hints", "address_route_policy", VendorSemanticAddressPool + "," + VendorSemanticIPv4Address + "," + VendorSemanticIPv6Address + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticRoute, []string{"Huawei-Framed-Pool = \"pool-a\"", "Huawei-Delegated-IPv6-Prefix-Pool = \"pd-a\""}, "", "", "", "", "", ""},
		{"huawei_nat_translation", "Huawei NAT, port block, DS-Lite, PCP, and translation lifecycle evidence", "translation_policy", VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix, []string{"Huawei-AVpair = \"translation-public-ipv4=198.51.100.2\"", "Huawei-NAT-Port-Range-Update = 1"}, "", "", "", "", "", ""},
		{"huawei_command_auth", "Huawei command mode, exec privilege, access service, and device-management authorization", "command_authorization", VendorSemanticRole + "," + VendorSemanticPolicyTag, []string{"Huawei-Exec-Privilege = 15", "Huawei-Command-Mode = \"system-view\""}, "", "", "", "", "", ""},
		{"huawei_portal_guest", "Huawei portal, redirect, web URL, ACS URL, and captive-access hints", "guest_portal", VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle, []string{"Huawei-HTTP-Redirect-URL = \"https://guest.example.test/login\"", "Huawei-Portal-Mode = 1"}, "", "", "", "", "", ""},
		{"huawei_accounting_charging", "Huawei accounting, tariff, charging, gigaword, and termination evidence", "accounting_charging", VendorSemanticAccountingCounters + "," + VendorSemanticAccountingIdentity, []string{"Huawei-Acct-IPv6-Input-Octets = 1234", "Huawei-Tariff-Output-Octets = \"2048\""}, "", "", "", "", "", ""},
		{"huawei_multicast_voice", "Huawei multicast groups, IGMP state, and voice service context", "multicast_voice_policy", VendorSemanticPolicyTag, []string{"Huawei-Multicast-Receive-Group = 239.0.0.1", "Huawei-VoiceVlan = 20"}, "", "", "", "", "", ""},
		{"h3c_qos_nat", "H3C Comware rate, burst, NAT address, and port-block evidence", "qos_translation_policy", VendorSemanticUploadBandwidth + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock, []string{"H3C-Input-Average-Rate = 25000", "H3C-NAT-IP-Address = 198.51.100.9"}, "", "", "", "", "", ""},
		{"h3c_command_access", "H3C command, exec privilege, user role, group, and ITA policy", "command_authorization", VendorSemanticRole + "," + VendorSemanticDeviceGroup + "," + VendorSemanticPolicyTag, []string{"H3C-User-Role = \"operator\"", "H3C-Ita-Policy = \"internet-only\""}, "", "", "", "", "", ""},
		{"h3c_multicast_subscriber", "H3C multicast receive groups, subscriber profile, PPP/L2TP, and ANCP context", "subscriber_multicast_policy", VendorSemanticPolicyTag + "," + VendorSemanticAccountingIdentity, []string{"H3C-Subscriber-ID = \"sub-123\"", "H3C-IPv6-Multicast-Receive-Group = ff3e::1"}, "", "", "", "", "", ""},
		{"zte_pppoe_qos", "ZTE PPPoE portal, tunnel controls, QoS profiles, SCR/PCR/PBS, and privilege", "pppoe_qos_policy", VendorSemanticPortalProfile + "," + VendorSemanticBandwidthProfile + "," + VendorSemanticUploadBandwidth + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticRole, []string{"ZTE-PPPOE-URL = \"https://portal.example.test\"", "ZTE-Rate-Ctrl-SCR-Down = 75000", "ZTE-SW-Privilege = 15"}, "", "", "", "", "", ""},
		{"zte_ipv6_rate", "ZTE IPv6 up/down QoS profile, SCR, burst, and PBS controls", "ipv6_qos_policy", VendorSemanticUploadBandwidth + "," + VendorSemanticDownloadBandwidth + "," + VendorSemanticBandwidthProfile, []string{"ZTE-Rate-Ctrl-SCR-Up-v6 = 25000", "ZTE-QoS-Profile-Down-v6 = \"gold-v6\""}, "", "", "", "", "", ""},
		{"zte_multicast_tunnel", "ZTE multicast send/receive limits and tunnel session controls", "multicast_tunnel_policy", VendorSemanticPolicyTag + "," + VendorSemanticSessionTimeout, []string{"ZTE-Mcast-MaxGroups = 8", "ZTE-Tunnel-Max-Sessions = 32"}, "", "", "", "", "", ""},
		{"shared_bng_coa", "Shared BRAS/BNG CoA, Disconnect, session refresh, and evidence boundary", "dynamic_authorization", VendorSemanticCoAReauth + "," + VendorSemanticCoADisconnect, []string{"RFC5176 CoA-Request", "RFC5176 Disconnect-Request"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = BroadbandVendorExternalRequired
		rows[index].ReleaseScope = "Huawei, H3C, ZTE, FreeRADIUS, HA, performance, soak, security, production deployment, and customer acceptance evidence is tracked in docs/nas-0068-release-certification-checklist.md."
	}
	return rows
}

func broadbandVendorProductScopes() []BroadbandVendorProductScope {
	return []BroadbandVendorProductScope{
		{Key: VendorPackHuawei, Label: "Huawei BRAS/BNG Subscriber Access", Vendors: []string{"Huawei"}, Products: []string{"MA series", "NE/BNG", "PPP/DHCP subscriber access"}, Dictionary: "dictionary.huawei", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Subscriber QoS, framed pool, route, NAT, tariff, and accounting evidence is software-visible; line-card enforcement requires release proof."}},
		{Key: VendorPackHuawei, Label: "Huawei Campus Switching And WLAN", Vendors: []string{"Huawei"}, Products: []string{"CloudEngine", "S series switches", "WLAN AC/AP", "iMaster NCE-Campus"}, Dictionary: "dictionary.huawei plus controller APIs", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Role, User-Class, portal, VoiceVLAN, AP information, and access-service semantics are normalized without hardware-certified claims."}},
		{Key: VendorPackHuawei, Label: "Huawei NAT, DS-Lite, PCP, And Lawful-Intercept Boundary", Vendors: []string{"Huawei"}, Products: []string{"BNG NAT", "DS-Lite", "PCP", "LI handoff"}, Dictionary: "dictionary.huawei", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Translation and LI identifiers are bounded evidence; legal authorization and device dataplane behavior are external certification items."}},
		{Key: VendorPackH3C, Label: "H3C Comware Access And Command Authorization", Vendors: []string{"H3C"}, Products: []string{"Comware switches", "iMC", "802.1X/MAB", "admin command authorization"}, Dictionary: "dictionary.h3c", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"User role, group, ITA policy, exec privilege, command, portal, and AVPair semantics are software-certified."}},
		{Key: VendorPackH3C, Label: "H3C Broadband NAT And Multicast", Vendors: []string{"H3C"}, Products: []string{"BRAS/BNG", "NAT", "IGMP/MLD", "ANCP"}, Dictionary: "dictionary.h3c", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"NAT IP/port and multicast receive group rows are normalized as typed evidence pending hardware proof."}},
		{Key: VendorPackZTE, Label: "ZTE PPPoE Access And Portal", Vendors: []string{"ZTE"}, Products: []string{"ZX/BNG", "PPPoE portal", "tunnel controls"}, Dictionary: "dictionary.zte", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"PPPoE URL, MOTM, access type, tunnel session, and privilege rows are represented in software."}},
		{Key: VendorPackZTE, Label: "ZTE Broadband QoS And IPv6 Rate Policy", Vendors: []string{"ZTE"}, Products: []string{"ZTE BNG", "QoS profile", "IPv4 and IPv6 rate policy"}, Dictionary: "dictionary.zte", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"SCR/PCR/PBS, burst, TCP rate, and IPv6 rate rows are available as neutral QoS evidence."}},
		{Key: VendorPackStandard, Label: "Shared Broadband Address And Route Lifecycle", Vendors: []string{"Huawei", "H3C", "ZTE"}, Products: []string{"Framed routes", "address pools", "delegated prefixes", "DNS hints"}, Dictionary: "RFC2865/RFC2866/RFC3162 plus vendor dictionaries", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Software compilers own neutral intent; exact vendor acceptance remains release-certified."}},
		{Key: VendorPackStandard, Label: "Shared Broadband Accounting And Charging", Vendors: []string{"Huawei", "H3C", "ZTE"}, Products: []string{"Accounting-Request", "tariff counters", "gigawords", "charging records"}, Dictionary: "RFC2866 plus vendor accounting dictionaries", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Counters and charging selectors are bounded evidence until production collection and reconciliation are certified."}},
		{Key: VendorPackStandard, Label: "Shared Broadband CoA And Disconnect", Vendors: []string{"Huawei", "H3C", "ZTE"}, Products: []string{"RFC5176 CoA", "Disconnect", "session reauthorization"}, Dictionary: "RFC5176 plus vendor dictionaries", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Dynamic authorization packet path is software-ready; per-device ACK/NAK behavior is external certification."}},
		{Key: VendorPackStandard, Label: "Shared Controller Health And Drift Boundary", Vendors: []string{"Huawei", "H3C", "ZTE"}, Products: []string{"iMaster", "Agile Controller", "H3C iMC", "ZTE controller/NMS"}, Dictionary: "vendor dictionaries plus controller APIs", SoftwareState: BroadbandVendorSoftwareCertified, ExternalState: BroadbandVendorExternalRequired, Notes: []string{"Native controller adapters and drift tests are tracked as external/product release evidence unless a simulator is used."}},
	}
}

func summarizeBroadbandVendorPack(records []BroadbandVendorAttributeRecord, grammar []BroadbandVendorGrammarRecord, scopes []BroadbandVendorProductScope) BroadbandVendorPackSummary {
	return summarizeAccessVendorPack(records, grammar, scopes)
}

func summarizeBroadbandVendorVendors(records []BroadbandVendorAttributeRecord) []BroadbandVendorVendorSummary {
	return summarizeAccessVendorVendors(records)
}

func summarizeBroadbandVendorCapabilities(records []BroadbandVendorAttributeRecord) []BroadbandVendorCapabilityCount {
	return summarizeAccessVendorCapabilities(records)
}

func broadbandVendorCapability(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	prefix := broadbandVendorRegistryPack(entry.Vendor)
	switch {
	case containsAnyBroadbandVendorToken(name, "acct", "account", "tariff", "gigawords", "octets", "packets", "volume", "remain", "remanent", "connection-time", "terminate", "result-code", "error-reason"):
		return prefix + "_accounting_charging"
	case containsAnyBroadbandVendorToken(name, "nat", "ds-lite", "pcp", "public-ip", "port-range", "port-forwarding"):
		return prefix + "_nat_translation"
	case containsAnyBroadbandVendorToken(name, "framed-pool", "pool", "ip-address", "ipv6", "gateway", "dns", "wins", "subnet", "policy-route", "route", "dhcp", "option121", "option43", "option37", "option38"):
		return prefix + "_address_route_pool"
	case containsAnyBroadbandVendorToken(name, "command", "exec-privilege", "privilege", "command-mode", "user-role", "user-class", "user-group"):
		return prefix + "_command_authorization"
	case containsAnyBroadbandVendorToken(name, "portal", "redirect", "web-url", "acs-url", "url"):
		return prefix + "_portal_hotspot"
	case containsAnyBroadbandVendorToken(name, "subscriber", "ppp", "pppoe", "l2tp", "ancp", "service-scheme", "service-info", "service-chg", "access-service"):
		return prefix + "_subscriber_service"
	case containsAnyBroadbandVendorToken(name, "qos", "rate", "burst", "cir", "pir", "rate-ctrl-scr", "rate-ctrl-pcr", "rate-ctrl-pbs", "priority", "queue", "tcp-syn"):
		return prefix + "_qos_rate"
	case containsAnyBroadbandVendorToken(name, "multicast", "igmp", "mld", "mcast"):
		return prefix + "_multicast_service"
	case containsAnyBroadbandVendorToken(name, "vpn", "security", "li-", "tunnel-vpn", "vpn-id"):
		return prefix + "_security_vpn_posture"
	case containsAnyBroadbandVendorToken(name, "voice", "sip", "voip", "pstn", "codec", "call-reference"):
		return prefix + "_voice_telephony"
	case containsAnyBroadbandVendorToken(name, "domain", "zone", "tenant", "longitude", "latitude"):
		return prefix + "_tenant_location"
	case containsAnyBroadbandVendorToken(name, "nas", "product-id", "version", "device", "lldp", "ap-information", "access-device", "startup", "loopback", "interface"):
		return prefix + "_device_management"
	case containsAnyBroadbandVendorToken(name, "filter", "acl", "avpair", "av-pair"):
		return prefix + "_acl_policy"
	case broadbandVendorSensitiveAttribute(entry.Attribute):
		return prefix + "_redacted_authentication"
	default:
		return prefix + "_broadband_vendor_state"
	}
}

func broadbandVendorImplementationClass(entry AttributeRegistryEntry) string {
	if broadbandVendorSensitiveAttribute(entry.Attribute) {
		return "redacted_secret_evidence"
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
		VendorSemanticDevicePosture, VendorSemanticGuestLifecycle, VendorSemanticCertificateOnboarding,
	}
	for _, semantic := range nativeSemantics {
		if registrySemanticContains(entry.Semantic, semantic) {
			return "native_semantic_mapping"
		}
	}
	return "typed_passthrough"
}

func broadbandVendorPacketProcessing(class string, entry AttributeRegistryEntry) string {
	switch class {
	case "policy_parse_compile":
		return "vendor_avpair_acl_route_translation_parser_compiler_and_bounded_vsa_codec"
	case "redacted_secret_evidence":
		return "string_or_octets_decoder_sha256_evidence_and_cleartext_redaction"
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

func broadbandVendorPolicyState(capability, class string) string {
	switch {
	case strings.Contains(capability, "qos"):
		return "neutral_hierarchical_qos_rate_unit_compiler"
	case strings.Contains(capability, "nat") || strings.Contains(capability, "translation"):
		return "translation_policy_cgnat_nat64_and_port_block_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "route"):
		return "address_pool_route_vrf_and_delegated_prefix_policy_context"
	case strings.Contains(capability, "subscriber") || strings.Contains(capability, "ppp"):
		return "subscriber_service_chain_and_bng_state_context"
	case strings.Contains(capability, "accounting"):
		return "accounting_counter_charging_and_session_identity_context"
	case strings.Contains(capability, "portal"):
		return "guest_portal_and_captive_access_policy_context"
	case strings.Contains(capability, "multicast"):
		return "multicast_entitlement_policy_context"
	case strings.Contains(capability, "command") || strings.Contains(capability, "role"):
		return "role_and_command_authorization_context"
	case strings.Contains(capability, "acl") || class == "policy_parse_compile":
		return "dynamic_acl_route_and_translation_avpair_policy_compiler"
	case class == "redacted_secret_evidence":
		return "redacted_authentication_evidence_context"
	default:
		return "typed_broadband_vendor_policy_context"
	}
}

func broadbandVendorEnforcementState(capability, class string) string {
	if class == "redacted_secret_evidence" {
		return "no_cleartext_enforcement_redacted_evidence_only"
	}
	switch {
	case strings.Contains(capability, "accounting"):
		return "accounting_ingest_charging_correlation_and_session_evidence"
	case strings.Contains(capability, "nat") || strings.Contains(capability, "translation"):
		return "radius_reply_translation_hint_and_local_translation_policy_context"
	case strings.Contains(capability, "address") || strings.Contains(capability, "route"):
		return "radius_reply_address_route_pool_and_vrf_context"
	case strings.Contains(capability, "qos"):
		return "radius_reply_qos_assignment_and_runtime_shaper_context"
	case strings.Contains(capability, "acl"):
		return "radius_reply_acl_assignment_dynamic_acl_preview_and_avpair_context"
	case strings.Contains(capability, "portal"):
		return "radius_reply_portal_redirect_or_guest_hint"
	default:
		return "radius_reply_inbound_context_and_no_silent_fallback"
	}
}

func broadbandVendorStorageState(class string) string {
	switch class {
	case "redacted_secret_evidence":
		return "bounded_hash_only_evidence_no_cleartext_secret"
	case "typed_tlv_evidence":
		return "normalized_tlv_metadata_child_oid_and_bounded_raw_evidence"
	case "policy_parse_compile":
		return "normalized_acl_route_translation_policy_and_bounded_vendor_rule_evidence"
	default:
		return "normalized_broadband_vendor_semantics_and_bounded_raw_vsa_evidence"
	}
}

func broadbandVendorRecordNotes(entry AttributeRegistryEntry, class string) []string {
	switch broadbandVendorRegistryPack(entry.Vendor) {
	case VendorPackHuawei:
		if class == "redacted_secret_evidence" {
			return []string{"Huawei credential-like values are never stored as cleartext policy data; packet evidence uses typed metadata and redaction."}
		}
		return []string{"Huawei MA/NE/CloudEngine/WLAN/iMaster behavior remains release-certified externally before hardware claims are published."}
	case VendorPackH3C:
		return []string{"H3C Comware/iMC/BRAS behavior remains release-certified externally before hardware claims are published."}
	default:
		return []string{"ZTE ZX/BNG/PPPoE behavior remains release-certified externally before hardware claims are published."}
	}
}

func (r *AttributeRegistry) applyBroadbandVendorRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isBroadbandVendorRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := broadbandVendorRegistrySemantic(*entry)
		entry.PackKey = broadbandVendorRegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0068")
		entry.Directions = broadbandVendorRegistryDirections(*entry, semantic)
		entry.Functionality = broadbandVendorRegistryFunctionality(*entry, semantic)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = broadbandVendorRegistryDecoder(*entry, semantic)
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isBroadbandVendorRegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "huawei", "h3c", "zte":
		return true
	default:
		return false
	}
}

func broadbandVendorRegistryPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "huawei":
		return VendorPackHuawei
	case "h3c":
		return VendorPackH3C
	default:
		return VendorPackZTE
	}
}

func broadbandVendorRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case broadbandVendorSensitiveAttribute(entry.Attribute):
		return VendorSemanticCertificateOnboarding
	case containsAnyBroadbandVendorToken(name, "avpair", "av-pair"):
		return VendorSemanticDynamicACL + "," + VendorSemanticRoute + "," + VendorSemanticVRF + "," + VendorSemanticAddressPool + "," + VendorSemanticDelegatedIPv6Prefix + "," + VendorSemanticDHCPv6 + "," + VendorSemanticRouterAdvertisement + "," + VendorSemanticTranslationPolicy + "," + VendorSemanticTranslationPublicIPv4 + "," + VendorSemanticTranslationPortBlock + "," + VendorSemanticNAT64Prefix + "," + VendorSemanticTranslationLogging
	case containsAnyBroadbandVendorToken(name, "data-filter", "filter", "acl"):
		return VendorSemanticACL
	case containsAnyBroadbandVendorToken(name, "input-average-rate", "input-peak-information-rate", "input-committed-information-rate", "input-peak-rate", "rate-ctrl-scr-up", "rate-bust-upir"):
		return VendorSemanticUploadBandwidth
	case containsAnyBroadbandVendorToken(name, "output-average-rate", "output-peak-information-rate", "output-committed-information-rate", "output-peak-rate", "rate-ctrl-scr-down", "rate-bust-dpir"):
		return VendorSemanticDownloadBandwidth
	case containsAnyBroadbandVendorToken(name, "qos", "burst", "committed-burst", "peak-burst", "basic-rate", "priority", "queue", "tcp-syn", "tcp-limit", "pcr", "pbs", "pir", "cir"):
		return VendorSemanticBandwidthProfile
	case containsAnyBroadbandVendorToken(name, "nat-start-port", "nat-end-port", "port-range", "port-forwarding"):
		return VendorSemanticTranslationPortBlock
	case containsAnyBroadbandVendorToken(name, "nat-policy", "ds-lite", "pcp", "nat-port"):
		return VendorSemanticTranslationPolicy
	case containsAnyBroadbandVendorToken(name, "nat-ip-address", "nat-public-address", "public-ip"):
		return VendorSemanticTranslationPublicIPv4
	case containsAnyBroadbandVendorToken(name, "framed-pool", "pool-group", "address-pool", "pool"):
		return VendorSemanticAddressPool
	case containsAnyBroadbandVendorToken(name, "delegated-ipv6-prefix-pool"):
		return VendorSemanticDelegatedIPv6Prefix
	case containsAnyBroadbandVendorToken(name, "framed-ipv6-address", "ipv6-address"):
		return VendorSemanticIPv6Address
	case containsAnyBroadbandVendorToken(name, "ipv6-policy-route", "policy-route"):
		return VendorSemanticRoute
	case containsAnyBroadbandVendorToken(name, "ipv6-prefix", "dhcpv6", "option37", "option38"):
		return VendorSemanticDHCPv6 + "," + VendorSemanticDelegatedIPv6Prefix
	case containsAnyBroadbandVendorToken(name, "dhcp", "option121", "option43", "lease-time"):
		return VendorSemanticAccountingIdentity
	case containsAnyBroadbandVendorToken(name, "client-primary-dns", "client-secondary-dns", "client-dns-pri", "client-dns-sec", "primary-dns", "secondary-dns", "gateway-address", "ip-address", "subnet-mask", "dns-server-ipv6"):
		if strings.Contains(name, "ipv6") {
			return VendorSemanticIPv6Address
		}
		return VendorSemanticIPv4Address
	case containsAnyBroadbandVendorToken(name, "vpn-instance", "vrf"):
		return VendorSemanticVRF
	case containsAnyBroadbandVendorToken(name, "domain", "zone", "longitude-latitude", "access-domain"):
		return VendorSemanticTenant
	case containsAnyBroadbandVendorToken(name, "user-role", "user-class", "exec-privilege", "sw-privilege", "command", "command-mode", "access-service", "service-scheme", "service-info", "service-chg", "voip-service-type", "igmp-service-profile"):
		return VendorSemanticRole
	case containsAnyBroadbandVendorToken(name, "user-group", "access-device", "nas-port-name", "backup-nas", "original_nas", "ap-information", "product-id", "version", "lldp", "interface", "pstn-port", "max-users"):
		return VendorSemanticDeviceGroup
	case containsAnyBroadbandVendorToken(name, "portal", "redirect", "web-url", "acs-url", "url"):
		return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
	case containsAnyBroadbandVendorToken(name, "subscriber", "ppp", "pppoe", "l2tp", "ancp"):
		return VendorSemanticAccountingIdentity
	case containsAnyBroadbandVendorToken(name, "acct", "account", "tariff", "gigawords", "octets", "packets", "volume", "remanent", "remain", "connection-time", "terminate", "result-code", "error-reason"):
		return VendorSemanticAccountingCounters
	case containsAnyBroadbandVendorToken(name, "multicast", "igmp", "mld", "mcast"):
		return VendorSemanticPolicyTag
	case containsAnyBroadbandVendorToken(name, "security", "vpn-id", "li-", "reachable-detect", "auth-detail", "authentication-type", "auth-type", "web-authen"):
		return VendorSemanticDevicePosture
	case containsAnyBroadbandVendorToken(name, "voice", "sip", "codec", "call-reference"):
		return VendorSemanticPolicyTag
	default:
		return VendorSemanticPolicyTag
	}
}

func broadbandVendorRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(entry.Attribute)
	switch {
	case containsAnyBroadbandVendorToken(name, "acct", "account", "tariff", "gigawords", "octets", "packets", "volume", "remain", "remanent", "startup", "result-code", "error-reason", "connection-time", "terminate", "subscriber-id", "nas-port-name", "user-mac", "access-device", "product-id", "version"):
		return []string{"accounting", "inbound"}
	case broadbandVendorSensitiveAttribute(entry.Attribute):
		return []string{"inbound"}
	case registrySemanticContains(semantic, VendorSemanticCoAReauth) || registrySemanticContains(semantic, VendorSemanticCoADisconnect):
		return []string{"coa", "inbound", "outbound_reply"}
	case registrySemanticContains(semantic, VendorSemanticAccountingCounters):
		return []string{"accounting", "inbound"}
	case registrySemanticContains(semantic, VendorSemanticControllerHealth):
		return []string{"controller_api", "inbound"}
	default:
		return []string{"accounting", "inbound", "outbound_reply"}
	}
}

func broadbandVendorRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	if entry.Number == 0 || entry.Number > 255 {
		return "", "", 0
	}
	baseType := baseDictionaryWireType(entry.WireType)
	decodeSemantic := firstRegistrySemantic(semantic)
	switch baseType {
	case "tlv", "group", "struct", "ipv6prefix":
		return "", "", 0
	}
	if broadbandVendorSensitiveAttribute(entry.Attribute) {
		return "string", decodeSemantic, 0
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
	if baseType == "octets" {
		return "octets_hex", decodeSemantic, 0
	}
	name := strings.ToLower(entry.Attribute)
	if registrySemanticContains(semantic, VendorSemanticDynamicACL) && containsAnyBroadbandVendorToken(name, "avpair", "av-pair") {
		return "avpairs", VendorSemanticDynamicACL, 0
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
	if registrySemanticContains(semantic, VendorSemanticTranslationPortBlock) && registryIntegerType(baseType) {
		return "integer_text", VendorSemanticTranslationPortBlock, 0
	}
	if registryIntegerType(baseType) {
		return "integer_text", decodeSemantic, 0
	}
	return "string", decodeSemantic, 0
}

func broadbandVendorRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	scope := "Huawei BRAS/BNG, campus switching, WLAN, iMaster, and controller policy"
	switch broadbandVendorRegistryPack(entry.Vendor) {
	case VendorPackH3C:
		scope = "H3C Comware, iMC, BRAS/BNG, switching, and controller policy"
	case VendorPackZTE:
		scope = "ZTE ZX/BNG, PPPoE, tunnel, multicast, and broadband QoS policy"
	}
	return fmt.Sprintf("%s carries %s for %s; AegisNAS normalizes stable semantics, safely decodes typed wire values, redacts credential-like evidence, and keeps real device behavior in release certification.", entry.Attribute, strings.ReplaceAll(semantic, ",", "/"), scope)
}

func broadbandVendorSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	return containsAnyBroadbandVendorToken(name, "user-password", "dpsk-info", "web-authen-info")
}

func containsAnyBroadbandVendorToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
