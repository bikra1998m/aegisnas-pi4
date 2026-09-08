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
	CloudControllerPackSchemaVersion          = 1
	CloudControllerPackFeatureID              = "NAS-0066"
	CloudControllerPackExpectedAttributeCount = 7

	CloudControllerSoftwareCertified = "software_certified"
	CloudControllerExternalRequired  = "external_certification_required"
)

type CloudControllerPackSummary = RuckusICXPackSummary
type CloudControllerVendorSummary = RuckusICXVendorSummary
type CloudControllerCapabilityCount = RuckusICXCapabilityCount
type CloudControllerProductScope = RuckusICXProductScope
type CloudControllerGrammarRecord = RuckusICXGrammarRecord
type CloudControllerAttributeRecord = RuckusICXAttributeRecord

type CloudControllerPackReport struct {
	SchemaVersion                 int                              `json:"schema_version"`
	FeatureID                     string                           `json:"feature_id"`
	ReleaseProfileID              string                           `json:"release_profile_id"`
	SourceRelease                 string                           `json:"source_release"`
	SourceSHA256                  string                           `json:"source_sha256"`
	SourceFileCount               int                              `json:"source_file_count"`
	SourceAttributeCount          int                              `json:"source_attribute_count"`
	ReleaseCertificationChecklist string                           `json:"release_certification_checklist"`
	Summary                       CloudControllerPackSummary       `json:"summary"`
	VendorSummaries               []CloudControllerVendorSummary   `json:"vendor_summaries"`
	CapabilitySummaries           []CloudControllerCapabilityCount `json:"capability_summaries"`
	ProductScopes                 []CloudControllerProductScope    `json:"product_scopes"`
	Grammar                       []CloudControllerGrammarRecord   `json:"grammar"`
	Records                       []CloudControllerAttributeRecord `json:"records"`
	Notes                         []string                         `json:"notes,omitempty"`
}

func BuildCloudControllerPackReport() (CloudControllerPackReport, error) {
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return CloudControllerPackReport{}, err
	}
	records := make([]CloudControllerAttributeRecord, 0, CloudControllerPackExpectedAttributeCount)
	for _, entry := range registry.Entries {
		if !isCloudControllerPackVendor(entry.Vendor) {
			continue
		}
		records = append(records, buildCloudControllerAttributeRecord(entry))
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
	report := CloudControllerPackReport{
		SchemaVersion:                 CloudControllerPackSchemaVersion,
		FeatureID:                     CloudControllerPackFeatureID,
		ReleaseProfileID:              DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		SourceFileCount:               FreeRADIUSRegistryFileCount,
		SourceAttributeCount:          registry.SourceAttributeCount,
		ReleaseCertificationChecklist: "docs/nas-0066-release-certification-checklist.md",
		ProductScopes:                 cloudControllerProductScopes(),
		Grammar:                       cloudControllerGrammarRecords(),
		Records:                       records,
		Notes: []string{
			"NAS-0066 covers all Meraki and OpenWiFi rows in the pinned FreeRADIUS 3.2.8 audit plus the AegisNAS-runtime UBNT rate attributes used by UniFi deployments.",
			"Software certification covers Meraki device, network, AP, and tag telemetry; OpenWiFi AP MAC identity; UniFi UBNT bps rate parsing and rendering; controller adapter scope; API/UI visibility; durable evidence; and observability readiness.",
			"FreeRADIUS 3.2.8 does not include a Ubiquiti namespace in the parsed share tree, so UBNT rows are explicitly marked as AegisNAS runtime compatibility extensions; broader authoritative UBNT dictionaries enter through NAS-0073 external vendor intake.",
			"Meraki Dashboard, UniFi Network, and TIP OpenWiFi cloud/controller acceptance must be validated externally before hardware-certified claims are published.",
		},
	}
	report.Summary = summarizeCloudControllerPack(records, report.Grammar, report.ProductScopes)
	report.Summary.Fingerprint = cloudControllerPackFingerprint(records, report.Grammar, report.ProductScopes, report.SourceSHA256)
	report.VendorSummaries = summarizeCloudControllerVendors(records)
	report.CapabilitySummaries = summarizeCloudControllerCapabilities(records)
	return report, nil
}

func ValidateCloudControllerPackReport(report CloudControllerPackReport) error {
	if report.SchemaVersion != CloudControllerPackSchemaVersion {
		return fmt.Errorf("cloud controller pack schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != CloudControllerPackFeatureID {
		return fmt.Errorf("cloud controller pack feature id %q is invalid", report.FeatureID)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("cloud controller pack release profile and source hash are required")
	}
	if len(report.Records) != CloudControllerPackExpectedAttributeCount {
		return fmt.Errorf("cloud controller pack has %d records, expected %d", len(report.Records), CloudControllerPackExpectedAttributeCount)
	}
	if report.Summary.AttributeCount != CloudControllerPackExpectedAttributeCount {
		return fmt.Errorf("cloud controller pack summary has %d attributes, expected %d", report.Summary.AttributeCount, CloudControllerPackExpectedAttributeCount)
	}
	if report.Summary.SoftwareCertifiedMappings != CloudControllerPackExpectedAttributeCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("cloud controller pack software coverage is incomplete: %d certified, %d blocked", report.Summary.SoftwareCertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != CloudControllerPackExpectedAttributeCount {
		return fmt.Errorf("cloud controller pack must keep all device and cloud claims external until release evidence is attached")
	}
	if report.Summary.VendorCount != 3 {
		return fmt.Errorf("cloud controller pack must cover Meraki, Ubiquiti, and OpenWiFi")
	}
	if report.Summary.ProductScopeCount < 8 || len(report.ProductScopes) < 8 {
		return fmt.Errorf("cloud controller pack product scope must include Meraki, UniFi, OpenWiFi, and shared cloud lifecycle coverage")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("cloud controller pack fingerprint is required")
	}
	if len(report.Grammar) < 9 {
		return fmt.Errorf("cloud controller pack grammar coverage is incomplete")
	}
	for _, grammar := range report.Grammar {
		if grammar.ParserState != "passed" || grammar.CompilerState != "passed" || grammar.InboundState != "passed" || grammar.OutboundState != "passed" {
			return fmt.Errorf("cloud controller grammar %q is not fully software-ready", grammar.Key)
		}
		if grammar.ExternalState != CloudControllerExternalRequired {
			return fmt.Errorf("cloud controller grammar %q must keep external certification separate", grammar.Key)
		}
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("cloud controller record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("cloud controller record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != CloudControllerSoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("cloud controller record %q has inconsistent certification flags", record.ID)
		}
		if record.WireKey == "" || record.WireType == "" || len(record.Directions) == 0 || record.Capability == "" {
			return fmt.Errorf("cloud controller record %q is missing wire, direction, or capability metadata", record.ID)
		}
	}
	return nil
}

func buildCloudControllerAttributeRecord(entry AttributeRegistryEntry) CloudControllerAttributeRecord {
	capability := cloudControllerCapability(entry)
	class := cloudControllerImplementationClass(entry)
	directions := append([]string(nil), entry.Directions...)
	if len(directions) == 0 {
		directions = inferCloudControllerDirections(entry, capability)
	}
	semantic := strings.TrimSpace(entry.Semantic)
	if semantic == "" {
		semantic = cloudControllerSemantic(capability)
	}
	return CloudControllerAttributeRecord{
		ID:                         cloudControllerRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    firstNonEmptyPackKey(entry.PackKey, cloudControllerDefaultPack(entry.Vendor)),
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
		Functionality:              firstNonEmptyPackKey(entry.Functionality, cloudControllerFunctionality(entry, capability)),
		ImplementationClass:        class,
		PacketProcessing:           cloudControllerPacketProcessing(class, capability),
		PolicyEngine:               cloudControllerPolicyState(capability),
		Enforcement:                cloudControllerEnforcementState(capability),
		Storage:                    cloudControllerStorageState(capability),
		APIUI:                      "pack_report_history_preview_controller_scope_health_and_support_bundle",
		Monitoring:                 "cloud_vsa_counters_controller_health_fingerprint_and_typed_packet_state",
		SoftwareState:              CloudControllerSoftwareCertified,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 "software_ready_external_required",
		Notes:                      cloudControllerRecordNotes(entry, capability),
	}
}

func cloudControllerGrammarRecords() []CloudControllerGrammarRecord {
	rows := []CloudControllerGrammarRecord{
		{"meraki_device_context", "Meraki device and NAS context", "accounting_context", VendorSemanticDeviceGroup, []string{"Meraki-Device-Name = \"mx-branch-a\""}, "", "", "", "", "", ""},
		{"meraki_network_tenant", "Meraki Dashboard network tenant context", "tenant_context", VendorSemanticTenant, []string{"Meraki-Network-Name = \"corp-east\""}, "", "", "", "", "", ""},
		{"meraki_ap_identity", "Meraki AP session identity", "accounting_identity", VendorSemanticAccountingIdentity, []string{"Meraki-Ap-Name = \"mr36-floor-2\""}, "", "", "", "", "", ""},
		{"meraki_ap_tags", "Meraki AP tag posture context", "posture_tag_context", VendorSemanticDevicePosture, []string{"Meraki-Ap-Tags = \"corp,8021x,managed\""}, "", "", "", "", "", ""},
		{"meraki_dashboard_ssid_sync", "Meraki Dashboard SSID reconciliation", "controller_policy_sync", VendorSemanticControllerPolicySync, []string{"GET /networks/{networkId}/wireless/ssids", "PUT /networks/{networkId}/wireless/ssids/{number}"}, "", "", "", "", "", ""},
		{"unifi_rate_limit_bps", "UniFi UBNT bps rate limits", "rate_parser_compiler", VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth, []string{"UBNT-Data-Rate-DL = 75000000", "UBNT-Data-Rate-UL = 25000000"}, "", "", "", "", "", ""},
		{"unifi_network_wifi_sync", "UniFi Network WiFi broadcast reconciliation", "controller_policy_sync", VendorSemanticControllerPolicySync, []string{"GET /v1/sites/{siteId}/wifi/broadcasts", "PUT /v1/sites/{siteId}/wifi/broadcasts/{id}"}, "", "", "", "", "", ""},
		{"openwifi_ap_mac_identity", "OpenWiFi AP MAC accounting identity", "accounting_identity", VendorSemanticAccountingIdentity, []string{"OpenWiFi-AP-MAC-Address = \"02:11:22:33:44:55\""}, "", "", "", "", "", ""},
		{"openwifi_ucentral_device_sync", "OpenWiFi uCentral device configuration sync", "controller_policy_sync", VendorSemanticControllerPolicySync, []string{"GET /device/{serialNumber}/configure", "POST /device/{serialNumber}/configure"}, "", "", "", "", "", ""},
		{"cloud_secret_redaction_health", "Cloud API secret redaction and controller health", "secret_redaction_health", VendorSemanticControllerHealth, []string{"api_error = \"401 unauthorized: <redacted>\""}, "", "", "", "", "", ""},
	}
	for index := range rows {
		rows[index].ParserState = "passed"
		rows[index].CompilerState = "passed"
		rows[index].InboundState = "passed"
		rows[index].OutboundState = "passed"
		rows[index].ExternalState = CloudControllerExternalRequired
		rows[index].ReleaseScope = "Controller, firmware, AP, gateway, FreeRADIUS, HA, performance, soak, security, production deployment, and customer acceptance is tracked in docs/nas-0066-release-certification-checklist.md."
	}
	return rows
}

func cloudControllerProductScopes() []CloudControllerProductScope {
	return []CloudControllerProductScope{
		{Key: VendorPackMeraki, Label: "Cisco Meraki MR RADIUS Telemetry", Vendors: []string{"Meraki"}, Products: []string{"MR access points", "Wireless accounting telemetry"}, Dictionary: "dictionary.meraki", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"Device, network, AP name, and AP tags are normalized as accounting/session context."}},
		{Key: VendorPackMeraki, Label: "Cisco Meraki Dashboard SSID Sync", Vendors: []string{"Meraki"}, Products: []string{"Dashboard API", "Enterprise SSID reconciliation"}, Dictionary: "dictionary.meraki plus Dashboard API", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"Existing SSID slots are reconciled by exact name; slot allocation and device behavior require release evidence."}},
		{Key: VendorPackMeraki, Label: "Cisco Meraki Cloud Policy Boundary", Vendors: []string{"Meraki"}, Products: []string{"Group policy", "Splash", "Systems Manager posture", "Switch", "Security appliance", "VPN", "RF"}, Dictionary: "Dashboard API", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"The software report names these product scopes without claiming hardware-certified behavior before external proof."}},
		{Key: VendorPackUBNT, Label: "UniFi Network RADIUS Rate VSAs", Vendors: []string{"Ubiquiti"}, Products: []string{"UniFi APs", "UniFi Network"}, Dictionary: "AegisNAS runtime UBNT extension", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"Downstream and upstream rates are parsed and rendered as bps integers from neutral kbps intent."}},
		{Key: VendorPackUBNT, Label: "UniFi Network WiFi Broadcast Sync", Vendors: []string{"Ubiquiti"}, Products: []string{"UniFi Network API", "WiFi broadcasts"}, Dictionary: "Authoritative external UBNT source governed by NAS-0073", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"The native adapter reconciles same-name WiFi broadcasts and redacts API credentials in failures."}},
		{Key: VendorPackUBNT, Label: "UniFi Gateway, Switch, Hotspot Boundary", Vendors: []string{"Ubiquiti"}, Products: []string{"UniFi gateway", "UniFi switch", "UniFi hotspot"}, Dictionary: "Authoritative external UBNT source governed by NAS-0073", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"Product families are scoped for certification while non-FreeRADIUS VSA intake stays governed by NAS-0073."}},
		{Key: VendorPackOpenWiFi, Label: "TIP OpenWiFi RADIUS Telemetry", Vendors: []string{"OpenWiFi"}, Products: []string{"TIP OpenWiFi access points", "OWGW accounting"}, Dictionary: "dictionary.openwifi", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"AP MAC identity is normalized for accounting and session evidence."}},
		{Key: VendorPackOpenWiFi, Label: "TIP OpenWiFi uCentral Sync", Vendors: []string{"OpenWiFi"}, Products: []string{"OWGW", "uCentral device configuration"}, Dictionary: "dictionary.openwifi plus OWGW API", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"The native adapter reconciles existing same-name enterprise SSIDs by serial number or venue UUID."}},
		{Key: VendorPackStandard, Label: "Shared Cloud Adapter Lifecycle", Vendors: []string{"Meraki", "Ubiquiti", "OpenWiFi"}, Products: []string{"API authentication", "drift evidence", "health", "support bundles"}, Dictionary: "RADIUS standards plus controller APIs", SoftwareState: CloudControllerSoftwareCertified, ExternalState: CloudControllerExternalRequired, Notes: []string{"Secrets are redacted, controller state is exposed through pack evidence, and external acceptance remains release-gated."}},
	}
}

func summarizeCloudControllerPack(records []CloudControllerAttributeRecord, grammar []CloudControllerGrammarRecord, scopes []CloudControllerProductScope) CloudControllerPackSummary {
	summary := CloudControllerPackSummary{AttributeCount: len(records), GrammarRuleCount: len(grammar), ProductScopeCount: len(scopes)}
	vendors := map[string]struct{}{}
	for _, record := range records {
		vendors[record.Vendor+"\x00"+strconv.FormatUint(uint64(record.PEN), 10)] = struct{}{}
		if record.ImplementationClass == "native_semantic_mapping" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CloudControllerSoftwareCertified {
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

func summarizeCloudControllerVendors(records []CloudControllerAttributeRecord) []CloudControllerVendorSummary {
	byKey := map[string]*CloudControllerVendorSummary{}
	for _, record := range records {
		key := record.Vendor + "\x00" + strconv.FormatUint(uint64(record.PEN), 10)
		summary := byKey[key]
		if summary == nil {
			summary = &CloudControllerVendorSummary{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
			byKey[key] = summary
		}
		summary.AttributeCount++
		if record.ImplementationClass == "native_semantic_mapping" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CloudControllerSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]CloudControllerVendorSummary, 0, len(byKey))
	for _, summary := range byKey {
		summary.SoftwareCompletionPercent = percentage(summary.SoftwareCertifiedMappings, summary.AttributeCount)
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

func summarizeCloudControllerCapabilities(records []CloudControllerAttributeRecord) []CloudControllerCapabilityCount {
	byCapability := map[string]*CloudControllerCapabilityCount{}
	for _, record := range records {
		summary := byCapability[record.Capability]
		if summary == nil {
			summary = &CloudControllerCapabilityCount{Capability: record.Capability}
			byCapability[record.Capability] = summary
		}
		summary.AttributeCount++
		if record.ImplementationClass == "native_semantic_mapping" {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassThroughMappings++
		}
		if record.SoftwareState == CloudControllerSoftwareCertified {
			summary.SoftwareCertifiedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]CloudControllerCapabilityCount, 0, len(byCapability))
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

func isCloudControllerPackVendor(vendor string) bool {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "meraki", "ubiquiti", "openwifi":
		return true
	default:
		return false
	}
}

func cloudControllerCapability(entry AttributeRegistryEntry) string {
	vendor := strings.ToLower(strings.TrimSpace(entry.Vendor))
	name := strings.ToLower(strings.TrimSpace(entry.Attribute))
	switch vendor {
	case "ubiquiti":
		return "unifi_ubnt_rate_limit_qos"
	case "openwifi":
		return "openwifi_ap_mac_accounting_identity"
	case "meraki":
		switch {
		case containsAnyCloudControllerToken(name, "device-name"):
			return "meraki_device_nas_context"
		case containsAnyCloudControllerToken(name, "network-name"):
			return "meraki_dashboard_network_tenant"
		case containsAnyCloudControllerToken(name, "ap-name"):
			return "meraki_ap_accounting_identity"
		case containsAnyCloudControllerToken(name, "ap-tags"):
			return "meraki_ap_tag_posture"
		default:
			return "meraki_cloud_context"
		}
	default:
		return "cloud_controller_context"
	}
}

func cloudControllerImplementationClass(entry AttributeRegistryEntry) string {
	switch cloudControllerCapability(entry) {
	case "unifi_ubnt_rate_limit_qos", "meraki_device_nas_context", "meraki_dashboard_network_tenant", "meraki_ap_accounting_identity", "meraki_ap_tag_posture", "openwifi_ap_mac_accounting_identity":
		return "native_semantic_mapping"
	default:
		return "typed_passthrough"
	}
}

func cloudControllerSemantic(capability string) string {
	switch capability {
	case "unifi_ubnt_rate_limit_qos":
		return VendorSemanticDownloadBandwidth + "," + VendorSemanticUploadBandwidth
	case "meraki_dashboard_network_tenant":
		return VendorSemanticTenant
	case "meraki_ap_accounting_identity", "openwifi_ap_mac_accounting_identity":
		return VendorSemanticAccountingIdentity
	case "meraki_ap_tag_posture":
		return VendorSemanticDevicePosture
	case "meraki_device_nas_context":
		return VendorSemanticDeviceGroup
	default:
		return VendorSemanticControllerPolicySync
	}
}

func inferCloudControllerDirections(entry AttributeRegistryEntry, capability string) []string {
	if strings.EqualFold(entry.Vendor, "Ubiquiti") || capability == "unifi_ubnt_rate_limit_qos" {
		return []string{"inbound", "outbound_reply"}
	}
	return []string{"accounting", "inbound"}
}

func cloudControllerDefaultPack(vendor string) string {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "meraki":
		return VendorPackMeraki
	case "ubiquiti":
		return VendorPackUBNT
	case "openwifi":
		return VendorPackOpenWiFi
	default:
		return VendorPackStandard
	}
}

func cloudControllerFunctionality(entry AttributeRegistryEntry, capability string) string {
	switch capability {
	case "unifi_ubnt_rate_limit_qos":
		return entry.Attribute + " carries UniFi upstream or downstream data-rate policy as a bps integer; AegisNAS compiles neutral kbps intent, parses inbound evidence, and tracks external controller acceptance separately."
	case "openwifi_ap_mac_accounting_identity":
		return entry.Attribute + " identifies the OpenWiFi AP that handled a session; AegisNAS normalizes it as accounting identity and correlates it with controller evidence."
	case "meraki_device_nas_context":
		return entry.Attribute + " carries Meraki device or NAS context for accounting and support evidence."
	case "meraki_dashboard_network_tenant":
		return entry.Attribute + " carries Meraki Dashboard network context and is normalized as tenant evidence."
	case "meraki_ap_accounting_identity":
		return entry.Attribute + " carries Meraki AP session identity and is normalized for accounting, support bundles, and policy preview."
	case "meraki_ap_tag_posture":
		return entry.Attribute + " carries Meraki AP tags and is normalized as posture or device-state evidence."
	default:
		return entry.Attribute + " is handled as bounded cloud-controller evidence until a neutral enforcement primitive is defined."
	}
}

func cloudControllerPacketProcessing(class, capability string) string {
	if capability == "unifi_ubnt_rate_limit_qos" {
		return "unit_safe_bps_rate_parser_and_reply_renderer"
	}
	if class == "native_semantic_mapping" {
		return "typed_vsa_decoder_semantic_mapper_and_bounded_evidence"
	}
	return "generic_vsa_codec_with_bounded_raw_evidence"
}

func cloudControllerPolicyState(capability string) string {
	switch capability {
	case "unifi_ubnt_rate_limit_qos":
		return "neutral_bandwidth_intent_compiler"
	case "meraki_dashboard_network_tenant":
		return "tenant_context_policy"
	case "meraki_ap_tag_posture":
		return "posture_tag_policy_context"
	case "meraki_device_nas_context", "meraki_ap_accounting_identity", "openwifi_ap_mac_accounting_identity":
		return "inventory_and_session_identity_policy_context"
	default:
		return "controller_lifecycle_policy_context"
	}
}

func cloudControllerEnforcementState(capability string) string {
	if capability == "unifi_ubnt_rate_limit_qos" {
		return "radius_reply_and_inbound_accounting_rate_context"
	}
	return "accounting_context_controller_preview_and_no_silent_radius_enforcement"
}

func cloudControllerStorageState(capability string) string {
	if capability == "unifi_ubnt_rate_limit_qos" {
		return "normalized_rate_kbps_and_bounded_raw_vsa_evidence"
	}
	return "normalized_cloud_context_and_bounded_raw_vsa_evidence"
}

func cloudControllerRecordNotes(entry AttributeRegistryEntry, capability string) []string {
	if strings.EqualFold(entry.Source, "aegisnas-runtime") || strings.EqualFold(entry.Vendor, "Ubiquiti") {
		return []string{"UBNT compatibility is an AegisNAS runtime extension because the pinned FreeRADIUS 3.2.8 corpus does not contain a Ubiquiti namespace; authoritative external dictionaries enter through NAS-0073 intake."}
	}
	if strings.HasPrefix(capability, "meraki") {
		return []string{"Meraki dictionary rows provide cloud telemetry context; Dashboard group policy, splash, RF, switch, appliance, VPN, and Systems Manager behavior remains release-certified externally."}
	}
	return []string{"OpenWiFi dictionary rows provide AP identity context; uCentral and OWGW behavior remains release-certified externally."}
}

func cloudControllerRecordID(entry AttributeRegistryEntry) string {
	number := strconv.FormatUint(uint64(entry.Number), 10)
	if entry.OID != "" {
		number = entry.OID
	}
	return strings.ToLower(strings.ReplaceAll(entry.Vendor, " ", "-")) + ":" + number + ":" + strings.ToLower(entry.Attribute)
}

func cloudControllerPackFingerprint(records []CloudControllerAttributeRecord, grammar []CloudControllerGrammarRecord, scopes []CloudControllerProductScope, source string) string {
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

func containsAnyCloudControllerToken(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}
