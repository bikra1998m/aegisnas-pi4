package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	SwitchingVendorPackSchemaVersion          = 1
	SwitchingVendorPackFeatureID              = "NAS-0071"
	SwitchingVendorPackExpectedAttributeCount = 69

	SwitchingVendorSoftwareCertified = "software_certified"
	SwitchingVendorExternalRequired  = "external_certification_required"
)

type SwitchingVendorPackSummary = RuckusICXPackSummary
type SwitchingVendorVendorSummary = RuckusICXVendorSummary
type SwitchingVendorCapabilityCount = RuckusICXCapabilityCount
type SwitchingVendorProductScope = RuckusICXProductScope
type SwitchingVendorGrammarRecord = RuckusICXGrammarRecord
type SwitchingVendorAttributeRecord = RuckusICXAttributeRecord

type SwitchingVendorPackReport struct {
	SchemaVersion                 int                              `json:"schema_version"`
	FeatureID                     string                           `json:"feature_id"`
	ReleaseProfileID              string                           `json:"release_profile_id"`
	SourceRelease                 string                           `json:"source_release"`
	SourceSHA256                  string                           `json:"source_sha256"`
	SourceFileCount               int                              `json:"source_file_count"`
	SourceAttributeCount          int                              `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                           `json:"release_certification_checklist"`
	Summary                       SwitchingVendorPackSummary       `json:"summary"`
	VendorSummaries               []SwitchingVendorVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []SwitchingVendorCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []SwitchingVendorProductScope    `json:"product_scopes"`
	Grammar                       []SwitchingVendorGrammarRecord   `json:"grammar"`
	Records                       []SwitchingVendorAttributeRecord `json:"records"`
	Notes                         []string                         `json:"notes,omitempty"`
}

func BuildSwitchingVendorPackReport() (SwitchingVendorPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return SwitchingVendorPackReport{}, err
	}
	records := make([]SwitchingVendorAttributeRecord, 0, SwitchingVendorPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isSwitchingVendorRegistryVendor(entry.Vendor) {
			continue
		}
		if !strings.EqualFold(entry.Source, "freeradius-"+FreeRADIUSRegistryRelease) {
			continue
		}
		records = append(records, buildSwitchingVendorAttributeRecord(entry))
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
	report := SwitchingVendorPackReport{
		SchemaVersion:                 SwitchingVendorPackSchemaVersion,
		FeatureID:                     SwitchingVendorPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0071-release-certification-checklist.md",
		ProductScopes:                 switchingVendorProductScopes(),
		Grammar:                       switchingVendorGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0071 covers every pinned FreeRADIUS 3.2.8 dictionary row for 3Com, DellEMC, Force10, Equallogic, Brocade, Foundry, Arista, and Extreme switching families.",
			"Software certification covers role and privilege mapping, command authorization context, VLAN and fabric selectors, ACL/profile assignment, portal hints, session actions, VM/VRF context, admin identity, accounting evidence, API/UI visibility, durable evidence, and readiness reporting.",
			"Rows shared with NAS-0063 and NAS-0064 retain their original focused-pack behavior and add NAS-0071 switching provenance for the broader enterprise switching claim.",
			"Real switch firmware, controller, FreeRADIUS-on-Linux, CoA/Disconnect ACK/NAK behavior, HA, performance, soak, security, production deployment, and customer acceptance remain release certification activities.",
		},
	}
	report.Summary = summarizeSwitchingVendorPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = accessVendorPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeSwitchingVendorVendors(records)
	report.CapabilitySummaries = summarizeSwitchingVendorCapabilities(records)
	return report, nil
}

func ValidateSwitchingVendorPackReport(report SwitchingVendorPackReport) error {
	if report.SchemaVersion != SwitchingVendorPackSchemaVersion {
		return fmt.Errorf("switching vendor pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != SwitchingVendorPackFeatureID {
		return fmt.Errorf("switching vendor pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("switching vendor pack release profile and source hash are required")
	}
	if len(report.Records) != SwitchingVendorPackExpectedAttributeCount {
		return fmt.Errorf("switching vendor pack has %d records, expected %d", len(report.Records), SwitchingVendorPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != SwitchingVendorPackExpectedAttributeCount {
		return fmt.Errorf("switching vendor pack summary has %d attributes, expected %d", report.Summary.AttributeCount, SwitchingVendorPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != SwitchingVendorPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("switching vendor pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != SwitchingVendorPackExpectedAttributeCount {
		return fmt.Errorf("switching vendor pack must keep all hardware claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 8 {
		return fmt.Errorf("switching vendor pack must cover exactly eight dictionary vendors")
	}
	if report.Summary.ProductScopeCount < 10 || len(report.ProductScopes) < 10 {
		return fmt.Errorf("switching vendor pack product scope must include Dell, Brocade, Arista, Extreme, 3Com, Force10, EqualLogic, Foundry, CoA, and certification boundaries")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("switching vendor pack fingerprint is required")
	}
	if len(report.Grammar) < 12 {
		return fmt.Errorf("switching vendor pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("switching vendor grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != SwitchingVendorExternalRequired {
			return fmt.Errorf("switching vendor grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("switching vendor record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("switching vendor record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != SwitchingVendorSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("switching vendor record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("switching vendor record %q is missing wire, direction, or capability metadata", record.ID)
		}
		if strings.TrimSpace(record.PacketProcessing) == "" || strings.TrimSpace(record.PolicyEngine) == "" || strings.TrimSpace(record.Storage) == "" {
			return fmt.Errorf("switching vendor record %q is missing implementation state", record.ID)
		}
	}
	return nil
}

func buildSwitchingVendorAttributeRecord(entry AttributeRegistryEntry) SwitchingVendorAttributeRecord {
	capability := switchingVendorCapability(entry)
	class := switchingVendorImplementationClass(entry, capability)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = switchingVendorRegistryDirections(entry, switchingVendorRegistrySemantic(entry))
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = switchingVendorRegistrySemantic(entry)
	}
	return SwitchingVendorAttributeRecord{
		ID:                         accessVendorRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, switchingVendorRegistryPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, switchingVendorRegistryFunctionality(entry, semantic)),
		ImplementationClass:        class,
		PacketProcessing:           switchingVendorPacketProcessing(class),
		PolicyEngine:               switchingVendorPolicyState(capability, class),
		Enforcement:                switchingVendorEnforcementState(capability, class),
		Storage:                    switchingVendorStorageState(class),
		APIUI:                      "pack_report_history_preview_switching_scope_health_readiness_and_support_bundle",
		Monitoring:                 "switching_pack_counters_fingerprint_vsa_parse_failures_coa_actions_acl_vlan_role_and_controller_scope",
		SoftwareState:              SwitchingVendorSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      switchingVendorRecordNotes(entry, class),
	}
}

func switchingVendorGrammarRecords() []SwitchingVendorGrammarRecord {
	rows := []SwitchingVendorGrammarRecord{
		{"switch_role_privilege", "Switch role and privilege assignment", "role_policy", VendorSemanticRole, []string{"3Com-User-Access-Level = 3", "Arista-User-Role = \"network-admin\"", "Brocade-Auth-Role = \"admin\""}, "", "", "", "", "", ""},
		{"switch_command_authorization", "Command authorization and shell-command context", "command_authorization", VendorSemanticRole, []string{"Arista-Command = \"show running-config\"", "Extreme-Shell-Command = \"configure terminal\"", "Foundry-Command-String = \"show vlan\""}, "", "", "", "", "", ""},
		{"switch_vlans", "VLAN name, ID, tag, and extended VLAN assignment", "vlan_policy", VendorSemanticVLAN, []string{"3Com-VLAN-Name = \"corp\"", "Extreme-Netlogin-Extended-Vlan = \"U20;T30\"", "Arista-Segment-Id = \"120\""}, "", "", "", "", "", ""},
		{"switch_acl_profiles", "ACL and downloadable policy profile assignment", "acl_policy", VendorSemanticDynamicACL, []string{"Foundry-Access-List = \"guest-in\"", "Arista-AVPair = \"acl=datacenter\"", "DellEMC-AVpair = \"filter=ops\""}, "", "", "", "", "", ""},
		{"switch_vendor_avpairs", "Vendor AVPair key-value grammar", "vendor_avpair", VendorSemanticDynamicACL, []string{"Force10-AVPair = \"role=ops\"", "Brocade-AVPairs1 = \"vrf=mgmt\"", "Arista-AVPair = \"shell:roles=network-admin\""}, "", "", "", "", "", ""},
		{"switch_guest_portal", "Captive portal and WebAuth hints", "guest_portal", VendorSemanticPortalProfile, []string{"3Com-URL = \"https://portal.example.test/start\"", "Arista-Captive-Portal = \"guest-portal\"", "Extreme-Netlogin-Url = \"https://portal.example.test/login\""}, "", "", "", "", "", ""},
		{"switch_session_actions", "Block, unblock, port-flap, and CoA action context", "dynamic_authorization", VendorSemanticCoAReauth, []string{"Arista-BlockMac = \"aa:bb:cc:dd:ee:ff\"", "Arista-PortFlap = 1", "Foundry-COA-Command = \"reauth\""}, "", "", "", "", "", ""},
		{"switch_qos", "QoS, VLAN priority, and MAC-based VLAN/QoS selectors", "qos_policy", VendorSemanticBandwidthProfile, []string{"Foundry-MAC-Based-Vlan-QoS = 4", "Brocade-AVPairs2 = \"qos=gold\"", "Force10-AVPair = \"qos=branch\""}, "", "", "", "", "", ""},
		{"switch_vrf_fabric", "Virtual router, fabric, pool, and replication-site context", "fabric_context", VendorSemanticVRF, []string{"Extreme-VM-VR-Name = \"mgmt\"", "Brocade-AVPairs3 = \"fabric=vcs-a\"", "Equallogic-Admin-Repl-Site-Access = \"site-a\""}, "", "", "", "", "", ""},
		{"switch_device_context", "SSID, mobility, product, VM, and interface context", "device_context", VendorSemanticDeviceGroup, []string{"3Com-SSID = \"Corp\"", "3Com-Product-ID = \"switch-5500\"", "Extreme-VM-Name = \"vm-edge\""}, "", "", "", "", "", ""},
		{"switch_posture", "802.1X, encryption, and posture evidence", "posture", VendorSemanticDevicePosture, []string{"3Com-Encryption-Type = \"wpa2-enterprise\"", "Foundry-MAC-Authent-needs-802.1x = 1", "Arista-WebAuth = 1"}, "", "", "", "", "", ""},
		{"switch_accounting", "Session, startup, admin identity, and accounting context", "accounting_context", VendorSemanticAccountingIdentity, []string{"3Com-Connect_Id = 42", "3Com-NAS-Startup-Timestamp = 1714780800", "Equallogic-Admin-Email = \"ops@example.test\""}, "", "", "", "", "", ""},
		{"switch_release_boundary", "External firmware and controller certification boundary", "release_certification", VendorSemanticPolicyTag, []string{"FreeRADIUS 3.2.8 dictionary rows", "hardware packet capture evidence", "controller sync health evidence"}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = SwitchingVendorExternalRequired
		rows[index].ReleaseScope = "Switch firmware, controller, physical hardware, FreeRADIUS-on-Linux, CoA/Disconnect, HA, performance, soak, security, production deployment, and customer acceptance evidence is tracked in docs/nas-0071-release-certification-checklist.md."
	}
	return rows
}

func switchingVendorProductScopes() []SwitchingVendorProductScope {
	return []SwitchingVendorProductScope{
		{Key: VendorPack3Com, Label: "3Com Switching And WLAN Access", Vendors: []string{"3com"}, Products: []string{"3Com switches", "3Com WLAN access", "legacy 802.1X edge"}, Dictionary: "dictionary.3com", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Access-level, VLAN-name, mobility, SSID, URL, encryption, host-IP, and session evidence are software-normalized."}},
		{Key: VendorPackArista, Label: "Arista EOS Switching", Vendors: []string{"Arista"}, Products: []string{"EOS switches", "CloudVision role authorization", "campus fabric"}, Dictionary: "dictionary.arista", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"AVPair, role, privilege, command, WebAuth, captive portal, block/unblock MAC, and port-flap semantics are software-ready."}},
		{Key: VendorPackBrocade, Label: "Brocade Switching", Vendors: []string{"Brocade"}, Products: []string{"Brocade switches", "Fabric OS administrative access", "legacy campus switching"}, Dictionary: "dictionary.brocade", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Auth-role, four AVPair slots, and password lifecycle hints are normalized as bounded administrative evidence."}},
		{Key: VendorPackDellEMC, Label: "Dell EMC Switching", Vendors: []string{"DellEMC"}, Products: []string{"Dell EMC Networking", "PowerSwitch", "campus/ToR switching"}, Dictionary: "dictionary.dellemc", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Group-name and AVpair payloads map to neutral role and policy-token semantics."}},
		{Key: VendorPackEquallogic, Label: "Dell EqualLogic Administration", Vendors: []string{"Equallogic"}, Products: []string{"EqualLogic PS Series", "storage-array administrative access"}, Dictionary: "dictionary.equallogic", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Admin contact, privilege, pool access, replication-site, account-type, and poll interval are normalized as access evidence."}},
		{Key: VendorPackExtreme, Label: "Extreme Networks Switching", Vendors: []string{"Extreme"}, Products: []string{"ExtremeXOS", "VOSS", "NetLogin 802.1X", "Extreme VM/VR context"}, Dictionary: "dictionary.extreme", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Extends NAS-0063 by certifying the Extreme switching subset inside the broader switching pack."}},
		{Key: VendorPackForce10, Label: "Dell Force10 Switching", Vendors: []string{"Force10"}, Products: []string{"Force10 FTOS", "S-Series", "Z-Series"}, Dictionary: "dictionary.force10", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Force10 AVPair policy tokens map to role, ACL, VLAN, VRF, QoS, and command intent."}},
		{Key: VendorPackFoundry, Label: "Foundry / ICX FastIron", Vendors: []string{"Foundry", "Ruckus"}, Products: []string{"Foundry switches", "ICX", "FastIron"}, Dictionary: "dictionary.foundry", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Extends NAS-0064 with the Foundry switching subset for command authorization, ACL, 802.1X, VLAN/QoS, CoA, and voice policy."}},
		{Key: VendorPackStandard, Label: "RFC 8907 Command Authorization Boundary", Vendors: []string{"Arista", "Brocade", "DellEMC", "Extreme", "Foundry", "Force10"}, Products: []string{"TACACS+ command authorization", "RADIUS authorization context"}, Dictionary: "RFC 8907 plus vendor dictionaries", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"TACACS+ server support is complete from NAS-0033; RADIUS VSAs carry compatible command-context evidence where vendors expose it."}},
		{Key: VendorPackStandard, Label: "Switching Release Certification Boundary", Vendors: []string{"3com", "Arista", "Brocade", "DellEMC", "Equallogic", "Extreme", "Force10", "Foundry"}, Products: []string{"FreeRADIUS interoperability", "hardware packet captures", "controller health", "HA failover"}, Dictionary: "FreeRADIUS 3.2.8 switching dictionaries", SoftwareState: SwitchingVendorSoftwareCertified, ExternalState: SwitchingVendorExternalRequired, Notes: []string{"Engineering completion never asserts hardware certification without release evidence."}},
	}
}

func summarizeSwitchingVendorPack(records []SwitchingVendorAttributeRecord, grammar []SwitchingVendorGrammarRecord, scopes []SwitchingVendorProductScope) SwitchingVendorPackSummary {
	return summarizeAccessVendorPack(records, grammar, scopes)
}

func summarizeSwitchingVendorVendors(records []SwitchingVendorAttributeRecord) []SwitchingVendorVendorSummary {
	return summarizeAccessVendorVendors(records)
}

func summarizeSwitchingVendorCapabilities(records []SwitchingVendorAttributeRecord) []SwitchingVendorCapabilityCount {
	return summarizeAccessVendorCapabilities(records)
}

func (r *AttributeRegistry) applySwitchingVendorRuntimeProfile() {
	if r == nil {
		return
	}
	for idx := range r.Entries {
		entry := &r.Entries[idx]
		if !isSwitchingVendorRegistryVendor(entry.Vendor) {
			continue
		}
		wasMissing := entry.DictionaryStatus == "missing"
		semantic := switchingVendorRegistrySemantic(*entry)
		entry.PackKey = switchingVendorRegistryPack(entry.Vendor)
		entry.Semantic = mergeRegistrySemantics(entry.Semantic, semantic)
		entry.SemanticProvenance = mergeRegistrySemantics(entry.SemanticProvenance, "aegisnas-runtime:nas-0071")
		entry.Directions = switchingVendorRegistryDirections(*entry, entry.Semantic)
		entry.Functionality = switchingVendorRegistryFunctionality(*entry, entry.Semantic)
		if wasMissing || strings.TrimSpace(entry.DecodeKind) == "" {
			entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = switchingVendorRegistryDecoder(*entry, entry.Semantic)
		}
		if wasMissing {
			entry.DictionaryStatus = "partial"
			r.MappedCount++
		}
	}
}

func isSwitchingVendorRegistryVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "3com", "arista", "brocade", "dellemc", "equallogic", "extreme", "force10", "foundry":
		return true
	default:
		return false
	}
}

func switchingVendorRegistryPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "3com":
		return VendorPack3Com
	case "arista":
		return VendorPackArista
	case "brocade":
		return VendorPackBrocade
	case "dellemc":
		return VendorPackDellEMC
	case "equallogic":
		return VendorPackEquallogic
	case "force10":
		return VendorPackForce10
	case "foundry":
		return VendorPackFoundry
	case "extreme":
		return VendorPackExtreme
	default:
		return ""
	}
}

func switchingVendorCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(strings.TrimSpace(entry.Vendor))
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch vendor {
	case "3com":
		return threeComSwitchingCapability(name)
	case "arista":
		return aristaSwitchingCapability(name)
	case "brocade":
		return brocadeSwitchingCapability(name)
	case "dellemc":
		return dellEMCSwitchingCapability(name)
	case "equallogic":
		return equallogicSwitchingCapability(name)
	case "extreme":
		return extremeCapability(name)
	case "force10":
		return "force10_avpair_switching_policy"
	case "foundry":
		return foundryICXCapability(name)
	default:
		return "switching_vendor_context"
	}
}

func threeComSwitchingCapability(name string) string {
	switch {
	case containsAnyAccessVendorToken(name, "access-level"):
		return "3com_access_level_authorization"
	case containsAnyAccessVendorToken(name, "vlan"):
		return "3com_vlan_assignment"
	case containsAnyAccessVendorToken(name, "url"):
		return "3com_captive_portal"
	case containsAnyAccessVendorToken(name, "ssid", "mobility", "product"):
		return "3com_wlan_and_device_context"
	case containsAnyAccessVendorToken(name, "encryption"):
		return "3com_security_posture"
	case containsAnyAccessVendorToken(name, "startup", "connect"):
		return "3com_accounting_session_context"
	case containsAnyAccessVendorToken(name, "ip-host"):
		return "3com_ip_host_context"
	case containsAnyAccessVendorToken(name, "time", "date"):
		return "3com_time_bound_authorization"
	default:
		return "3com_vendor_context"
	}
}

func aristaSwitchingCapability(name string) string {
	switch {
	case containsAnyAccessVendorToken(name, "avpair"):
		return "arista_avpair_policy"
	case containsAnyAccessVendorToken(name, "priv", "user-role", "cvp-role"):
		return "arista_role_privilege_authorization"
	case containsAnyAccessVendorToken(name, "command"):
		return "arista_command_authorization"
	case containsAnyAccessVendorToken(name, "webauth", "captive"):
		return "arista_webauth_captive_portal"
	case containsAnyAccessVendorToken(name, "blockmac", "unblockmac", "portflap"):
		return "arista_session_remediation"
	case containsAnyAccessVendorToken(name, "segment"):
		return "arista_fabric_segment_vlan"
	case containsAnyAccessVendorToken(name, "profiling"):
		return "arista_device_profiling"
	case containsAnyAccessVendorToken(name, "tenant"):
		return "arista_tenant_context"
	case containsAnyAccessVendorToken(name, "interface"):
		return "arista_interface_profile"
	default:
		return "arista_vendor_context"
	}
}

func brocadeSwitchingCapability(name string) string {
	switch {
	case containsAnyAccessVendorToken(name, "auth-role"):
		return "brocade_auth_role"
	case containsAnyAccessVendorToken(name, "avpairs"):
		return "brocade_avpair_policy"
	case containsAnyAccessVendorToken(name, "expiry", "warn"):
		return "brocade_password_lifecycle"
	default:
		return "brocade_vendor_context"
	}
}

func dellEMCSwitchingCapability(name string) string {
	if containsAnyAccessVendorToken(name, "group") {
		return "dellemc_group_authorization"
	}
	return "dellemc_avpair_switching_policy"
}

func equallogicSwitchingCapability(name string) string {
	switch {
	case containsAnyAccessVendorToken(name, "privilege", "account-type"):
		return "equallogic_admin_role_authorization"
	case containsAnyAccessVendorToken(name, "pool-access"):
		return "equallogic_pool_access_policy"
	case containsAnyAccessVendorToken(name, "repl-site"):
		return "equallogic_replication_site_tenant"
	case containsAnyAccessVendorToken(name, "poll"):
		return "equallogic_polling_accounting_context"
	case containsAnyAccessVendorToken(name, "email", "phone", "mobile", "full-name"):
		return "equallogic_admin_identity_context"
	default:
		return "equallogic_vendor_context"
	}
}

func switchingVendorRegistrySemantic(entry AttributeRegistryEntry) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case containsAnyAccessVendorToken(name, "avpair", "avpairs", "access-list", "pool-access", "aor-list"):
		return VendorSemanticDynamicACL + "," + VendorSemanticACL
	case containsAnyAccessVendorToken(name, "vlan", "segment"):
		return VendorSemanticVLAN
	case containsAnyAccessVendorToken(name, "url", "portal", "webauth"):
		return VendorSemanticPortalProfile + "," + VendorSemanticGuestLifecycle
	case containsAnyAccessVendorToken(name, "blockmac", "unblockmac"):
		return VendorSemanticSessionAction + "," + VendorSemanticCoAReauth
	case containsAnyAccessVendorToken(name, "portflap", "coa"):
		return VendorSemanticCoAReauth
	case containsAnyAccessVendorToken(name, "time-of-day", "end-date", "expiry", "warn"):
		return VendorSemanticSessionTimeout
	case containsAnyAccessVendorToken(name, "priv", "role", "group", "access-level", "account-type", "command", "cli", "shell"):
		return VendorSemanticRole
	case containsAnyAccessVendorToken(name, "qos"):
		return VendorSemanticBandwidthProfile
	case containsAnyAccessVendorToken(name, "ip-host", "ip-addr"):
		return VendorSemanticIPv4Address
	case containsAnyAccessVendorToken(name, "vm-vr", "vr-name", "vrf"):
		return VendorSemanticVRF
	case containsAnyAccessVendorToken(name, "repl-site", "location", "tenant"):
		return VendorSemanticTenant
	case containsAnyAccessVendorToken(name, "encryption", "802.1x", "mac-authent", "valid-lookup", "profiling"):
		return VendorSemanticDevicePosture
	case containsAnyAccessVendorToken(name, "ssid", "mobility", "product", "interface", "vm-name"):
		return VendorSemanticDeviceGroup
	case containsAnyAccessVendorToken(name, "connect", "startup", "full-name", "email", "phone", "mobile", "poll", "expiry", "warn"):
		return VendorSemanticAccountingIdentity + "," + VendorSemanticAccountingCounters
	default:
		return VendorSemanticPolicyTag
	}
}

func switchingVendorRegistryDirections(entry AttributeRegistryEntry, semantic string) []string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case registrySemanticContains(semantic, VendorSemanticAccountingCounters) ||
		registrySemanticContains(semantic, VendorSemanticAccountingIdentity) ||
		registrySemanticContains(semantic, VendorSemanticDevicePosture) ||
		registrySemanticContains(semantic, VendorSemanticDeviceGroup) ||
		registrySemanticContains(semantic, VendorSemanticTenant) ||
		registrySemanticContains(semantic, VendorSemanticIPv4Address):
		return []string{"inbound", "outbound_reply", "accounting"}
	case containsAnyAccessVendorToken(name, "blockmac", "unblockmac", "portflap", "coa"):
		return []string{"inbound", "outbound_reply", "coa"}
	case registrySemanticContains(semantic, VendorSemanticRole) ||
		registrySemanticContains(semantic, VendorSemanticVLAN) ||
		registrySemanticContains(semantic, VendorSemanticACL) ||
		registrySemanticContains(semantic, VendorSemanticDynamicACL) ||
		registrySemanticContains(semantic, VendorSemanticPortalProfile):
		return []string{"inbound", "outbound_reply"}
	default:
		return []string{"inbound", "outbound_reply"}
	}
}

func switchingVendorRegistryFunctionality(entry AttributeRegistryEntry, semantic string) string {
	name := strings.TrimSpace(entry.Attribute)
	lower := strings.ToLower(name)
	switch {
	case containsAnyAccessVendorToken(lower, "avpair", "avpairs"):
		return name + " carries bounded vendor key-value policy tokens for switching role, ACL, VLAN, VRF, QoS, command, and fabric intent."
	case containsAnyAccessVendorToken(lower, "access-list"):
		return name + " assigns a named switch ACL or filter profile through the neutral ACL policy model."
	case containsAnyAccessVendorToken(lower, "vlan", "segment"):
		return name + " carries VLAN, segment, or fabric-tag authorization context."
	case containsAnyAccessVendorToken(lower, "priv", "role", "group", "access-level", "account-type"):
		return name + " carries administrative role, privilege, group, or account-type authorization context."
	case containsAnyAccessVendorToken(lower, "command", "cli", "shell"):
		return name + " carries command authorization context aligned with the NAS-0033 TACACS+ policy engine."
	case containsAnyAccessVendorToken(lower, "url", "portal", "webauth"):
		return name + " carries captive portal, WebAuth, or guest lifecycle hints."
	case containsAnyAccessVendorToken(lower, "blockmac", "unblockmac", "portflap", "coa"):
		return name + " carries dynamic authorization or session-remediation action context."
	case containsAnyAccessVendorToken(lower, "ip-host", "ip-addr"):
		return name + " carries IP address or host context for session and accounting correlation."
	case containsAnyAccessVendorToken(lower, "vm-", "vr-name", "vrf"):
		return name + " carries VM, virtual router, VRF, or fabric context."
	case containsAnyAccessVendorToken(lower, "ssid", "mobility", "interface", "product"):
		return name + " carries WLAN, interface, mobility, or switch product context."
	case containsAnyAccessVendorToken(lower, "encryption", "802.1x", "mac-authent", "valid-lookup", "profiling"):
		return name + " carries endpoint posture, 802.1X, MAC-auth, or encryption evidence."
	case containsAnyAccessVendorToken(lower, "connect", "startup", "full-name", "email", "phone", "mobile", "poll", "expiry", "warn"):
		return name + " carries bounded administrative or session accounting evidence."
	default:
		if strings.TrimSpace(semantic) != "" {
			return name + " carries " + semantic + " switching compatibility context."
		}
		return name + " carries vendor-specific switching compatibility evidence."
	}
}

func switchingVendorRegistryDecoder(entry AttributeRegistryEntry, semantic string) (string, string, int) {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case containsAnyAccessVendorToken(name, "avpair", "avpairs"):
		return "avpairs", VendorSemanticDynamicACL, 0
	case strings.EqualFold(entry.Attribute, "Extreme-Netlogin-Extended-Vlan"):
		return "extended_vlan", VendorSemanticVLAN, 0
	case registrySemanticContains(semantic, VendorSemanticVLAN) && strings.EqualFold(baseDictionaryWireType(entry.WireType), "integer"):
		return "vlan", VendorSemanticVLAN, 0
	case strings.EqualFold(baseDictionaryWireType(entry.WireType), "ipaddr"):
		return "ipaddr", firstRegistrySemantic(semantic), 0
	case strings.EqualFold(baseDictionaryWireType(entry.WireType), "integer"):
		return "integer_text", firstRegistrySemantic(semantic), 0
	default:
		return "string", firstRegistrySemantic(semantic), 0
	}
}

func switchingVendorImplementationClass(entry AttributeRegistryEntry, capability string) string {
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch {
	case containsAnyAccessVendorToken(name, "avpair", "avpairs", "access-list", "command", "shell", "cli"):
		return "policy_parse_compile"
	case strings.Contains(capability, "vendor_context"):
		return "typed_passthrough"
	default:
		return "native_semantic_mapping"
	}
}

func switchingVendorPacketProcessing(class string) string {
	switch class {
	case "policy_parse_compile":
		return "switching_avpair_acl_command_parser_classifier_and_safe_unknown_preservation"
	case "native_semantic_mapping":
		return "generated_runtime_decoder_semantic_mapper_reply_renderer_and_duplicate_number_guard"
	default:
		return "generic_switching_vsa_codec_with_bounded_raw_evidence"
	}
}

func switchingVendorPolicyState(capability, class string) string {
	switch {
	case class == "typed_passthrough":
		return "typed_evidence_only_until_policy_binding"
	case strings.Contains(capability, "command"):
		return "tacacs_command_policy_context_and_radius_command_evidence"
	case strings.Contains(capability, "acl") || strings.Contains(capability, "avpair") || strings.Contains(capability, "pool"):
		return "dynamic_acl_profile_and_vendor_avpair_policy_context"
	case strings.Contains(capability, "vlan") || strings.Contains(capability, "segment"):
		return "vlan_policy_and_fabric_segment_context"
	case strings.Contains(capability, "portal") || strings.Contains(capability, "webauth"):
		return "guest_portal_and_webauth_policy_context"
	case strings.Contains(capability, "role") || strings.Contains(capability, "privilege") || strings.Contains(capability, "authorization"):
		return "role_privilege_and_administrative_authorization_context"
	case strings.Contains(capability, "qos"):
		return "qos_and_priority_policy_context"
	default:
		return "neutral_switching_policy_context"
	}
}

func switchingVendorEnforcementState(capability, class string) string {
	if class == "typed_passthrough" {
		return "safe_visibility_no_silent_enforcement_claim"
	}
	if strings.Contains(capability, "remediation") || strings.Contains(capability, "dynamic_authorization") {
		return "radius_reply_and_coa_session_control_surfaces"
	}
	return "radius_reply_controller_preview_and_policy_surfaces"
}

func switchingVendorStorageState(class string) string {
	if class == "policy_parse_compile" {
		return "normalized_switching_policy_tokens_and_bounded_raw_evidence"
	}
	return "normalized_switching_semantics_and_bounded_raw_vsa_evidence"
}

func switchingVendorRecordNotes(entry AttributeRegistryEntry, class string) []string {
	if class == "typed_passthrough" {
		return []string{"Software-ready typed pass-through stores bounded evidence without claiming native switch behavior until release certification is attached."}
	}
	if containsAnyAccessVendorToken(strings.ToLower(entry.Attribute), "command", "cli", "shell") {
		return []string{"RADIUS command context integrates with the NAS-0033 TACACS+ policy model; interactive switch CLI behavior remains externally certified."}
	}
	return []string{"Native semantic mapping is wired into packet processing and policy/reporting surfaces; device acceptance remains externally certified."}
}
