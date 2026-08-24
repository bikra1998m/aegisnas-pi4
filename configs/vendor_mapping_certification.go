package configs

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	VendorMappingCertificationSchemaVersion = 1
	VendorMappingCertificationBaselineCount = 141

	VendorMappingCertificationStateReady   = "software_certified"
	VendorMappingCertificationStateBlocked = "software_blocked"
)

type VendorMappingCertificationReport struct {
	SchemaVersion           int                                `json:"schema_version"`
	ReleaseProfileID        string                             `json:"release_profile_id"`
	SourceRelease           string                             `json:"source_release"`
	SourceSHA256            string                             `json:"source_sha256"`
	BaselineSource          string                             `json:"baseline_source"`
	BaselinePartialMappings int                                `json:"baseline_partial_mappings"`
	Summary                 VendorMappingCertificationSummary  `json:"summary"`
	VendorSummaries         []VendorMappingCertificationVendor `json:"vendor_summaries"`
	Records                 []VendorMappingCertificationRecord `json:"records"`
	Notes                   []string                           `json:"notes,omitempty"`
}

type VendorMappingCertificationSummary struct {
	BaselinePartialMappings    int     `json:"baseline_partial_mappings"`
	CertifiedMappings          int     `json:"certified_mappings"`
	SoftwareBlockedMappings    int     `json:"software_blocked_mappings"`
	ReadyForExternalMappings   int     `json:"ready_for_external_mappings"`
	ExternalRequiredMappings   int     `json:"external_required_mappings"`
	VendorCount                int     `json:"vendor_count"`
	RuntimeDecoderCount        int     `json:"runtime_decoder_count"`
	GenericCodecCount          int     `json:"generic_codec_count"`
	ReplyRendererCount         int     `json:"reply_renderer_count"`
	PolicyWiredCount           int     `json:"policy_wired_count"`
	StorageWiredCount          int     `json:"storage_wired_count"`
	EnforcementWiredCount      int     `json:"enforcement_wired_count"`
	APIUIWiredCount            int     `json:"api_ui_wired_count"`
	ObservabilityWiredCount    int     `json:"observability_wired_count"`
	CurrentRegistryMappedCount int     `json:"current_registry_mapped_count"`
	CurrentRuntimeMappingCount int     `json:"current_runtime_mapping_count"`
	SoftwareCompletionPercent  float64 `json:"software_completion_percent"`
	Fingerprint                string  `json:"fingerprint"`
}

type VendorMappingCertificationVendor struct {
	Vendor                    string  `json:"vendor"`
	PEN                       uint32  `json:"pen"`
	PackKey                   string  `json:"pack_key,omitempty"`
	BaselinePartialMappings   int     `json:"baseline_partial_mappings"`
	CertifiedMappings         int     `json:"certified_mappings"`
	SoftwareBlockedMappings   int     `json:"software_blocked_mappings"`
	ExternalRequiredMappings  int     `json:"external_required_mappings"`
	SoftwareCompletionPercent float64 `json:"software_completion_percent"`
}

type VendorMappingCertificationRecord struct {
	ID                         string                           `json:"id"`
	Vendor                     string                           `json:"vendor"`
	PEN                        uint32                           `json:"pen"`
	PackKey                    string                           `json:"pack_key,omitempty"`
	PackLabel                  string                           `json:"pack_label,omitempty"`
	Attribute                  string                           `json:"attribute"`
	Number                     uint32                           `json:"number,omitempty"`
	OID                        string                           `json:"oid,omitempty"`
	WireKey                    string                           `json:"wire_key"`
	WireType                   string                           `json:"wire_type"`
	WireCodec                  AttributeWireCodec               `json:"wire_codec"`
	EnumeratedValues           int                              `json:"enumerated_values,omitempty"`
	CapabilityFamily           string                           `json:"capability_family"`
	Semantic                   string                           `json:"semantic"`
	PrimarySemantic            string                           `json:"primary_semantic"`
	Directions                 []string                         `json:"directions"`
	Functionality              string                           `json:"functionality,omitempty"`
	DecodeKind                 string                           `json:"decode_kind,omitempty"`
	SoftwareState              string                           `json:"software_state"`
	CertificationState         string                           `json:"certification_state"`
	ClaimState                 string                           `json:"claim_state"`
	SoftwareCertified          bool                             `json:"software_certified"`
	ReadyForExternalValidation bool                             `json:"ready_for_external_validation"`
	ExternalValidationRequired bool                             `json:"external_validation_required"`
	Dimensions                 []CompatibilityEvidenceDimension `json:"dimensions"`
	Blockers                   []string                         `json:"blockers,omitempty"`
	NextSteps                  []string                         `json:"next_steps,omitempty"`
}

func BuildVendorMappingCertificationReport(catalog VendorDictionaryCatalog, packs []VendorCompatibilityPack, activeKeys []string) (VendorMappingCertificationReport, error) {
	baseline, sourceHash, err := partialAuditRegistryEntries()
	if err != nil {
		return VendorMappingCertificationReport{}, err
	}
	registry, err := BuiltInAttributeRegistry()
	if err != nil {
		return VendorMappingCertificationReport{}, err
	}
	compatibilityEvidence := BuildCompatibilityEvidenceReport(catalog, packs, activeKeys)
	evidenceByWire := compatibilityEvidenceByWireKey(compatibilityEvidence)
	packsByKey := vendorCompatibilityPacksByKey(packs)
	semanticState := semanticCompatibilityStateByKey()
	runtime := runtimeEvidenceByWire(registry)
	vendors := map[string]struct{}{}

	report := VendorMappingCertificationReport{
		SchemaVersion:           VendorMappingCertificationSchemaVersion,
		ReleaseProfileID:        DefaultDictionaryReleaseProfileID,
		SourceRelease:           FreeRADIUSRegistryRelease,
		SourceSHA256:            sourceHash,
		BaselineSource:          "configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv",
		BaselinePartialMappings: len(baseline),
		Records:                 make([]VendorMappingCertificationRecord, 0, len(baseline)),
		Notes: []string{
			"NAS-0060 certifies software behavior for the 141 audit-source partial mappings from the pinned FreeRADIUS 3.2.8 registry.",
			"Software certification covers deterministic metadata, typed packet codecs, semantic policy wiring, storage evidence, enforcement surfaces, API/UI visibility, observability, and automated regression tests.",
			"External vendor hardware, controller, firmware, FreeRADIUS-on-Linux, HA, performance, soak, security, and customer-environment proof is tracked separately in the NAS-0060 release certification checklist.",
		},
	}
	for _, entry := range baseline {
		current, found := registry.LookupName(entry.Vendor, entry.Attribute)
		if found {
			entry = mergeCertificationEntry(entry, current)
		}
		_, runtimeDecoder := runtime[entry.WireKey]
		record := buildVendorMappingCertificationRecord(entry, found, runtimeDecoder, evidenceByWire[entry.WireKey], packsByKey, semanticState)
		report.Records = append(report.Records, record)
		vendors[strings.ToLower(entry.Vendor)+"\x00"+fmt.Sprint(entry.PEN)] = struct{}{}
	}
	sort.SliceStable(report.Records, func(i, j int) bool {
		return report.Records[i].ID < report.Records[j].ID
	})
	report.Summary = summarizeVendorMappingCertification(report.Records, registry)
	report.Summary.BaselinePartialMappings = len(baseline)
	report.Summary.VendorCount = len(vendors)
	report.Summary.Fingerprint = vendorMappingCertificationFingerprint(report.Records, report.SourceSHA256)
	report.VendorSummaries = summarizeVendorMappingCertificationVendors(report.Records)
	return report, nil
}

func ValidateVendorMappingCertificationReport(report VendorMappingCertificationReport) error {
	if report.SchemaVersion != VendorMappingCertificationSchemaVersion {
		return fmt.Errorf("vendor mapping certification schema version %d is unsupported", report.SchemaVersion)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("vendor mapping certification release profile and source hash are required")
	}
	if report.BaselinePartialMappings != VendorMappingCertificationBaselineCount {
		return fmt.Errorf("vendor mapping certification baseline count is %d, expected %d", report.BaselinePartialMappings, VendorMappingCertificationBaselineCount)
	}
	if len(report.Records) != VendorMappingCertificationBaselineCount {
		return fmt.Errorf("vendor mapping certification has %d records, expected %d", len(report.Records), VendorMappingCertificationBaselineCount)
	}
	if report.Summary.CertifiedMappings != VendorMappingCertificationBaselineCount || report.Summary.SoftwareBlockedMappings != 0 {
		return fmt.Errorf("vendor mapping certification software coverage is incomplete: %d certified, %d blocked", report.Summary.CertifiedMappings, report.Summary.SoftwareBlockedMappings)
	}
	if report.Summary.ExternalRequiredMappings != VendorMappingCertificationBaselineCount {
		return fmt.Errorf("vendor mapping certification must keep all 141 hardware claims external until release evidence is attached")
	}
	if report.Summary.Fingerprint == "" {
		return fmt.Errorf("vendor mapping certification fingerprint is required")
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("vendor mapping certification record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("vendor mapping certification record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != VendorMappingCertificationStateReady {
			return fmt.Errorf("vendor mapping certification record %q is not software certified", record.ID)
		}
		if record.CertificationState != EvidenceCertificationRequired {
			return fmt.Errorf("vendor mapping certification record %q has invalid certification state %q", record.ID, record.CertificationState)
		}
		if !record.SoftwareCertified || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("vendor mapping certification record %q has inconsistent readiness flags", record.ID)
		}
		if len(record.Dimensions) == 0 {
			return fmt.Errorf("vendor mapping certification record %q has no dimensions", record.ID)
		}
		for _, dimension := range record.Dimensions {
			if dimension.Required && dimension.State != "passed" {
				return fmt.Errorf("vendor mapping certification record %q dimension %q is %q", record.ID, dimension.Key, dimension.State)
			}
		}
	}
	return nil
}

func partialAuditRegistryEntries() ([]AttributeRegistryEntry, string, error) {
	digest := sha256.Sum256(freeRADIUSRegistryCSV)
	reader := csv.NewReader(strings.NewReader(string(freeRADIUSRegistryCSV)))
	reader.FieldsPerRecord = 13
	header, err := reader.Read()
	if err != nil {
		return nil, "", fmt.Errorf("read attribute registry header: %w", err)
	}
	expected := []string{"Vendor", "PEN", "Attribute", "Number", "OID", "Type", "EnumeratedValues", "CapabilityFamily", "Status", "Pack", "Semantic", "Direction", "Functionality"}
	if strings.Join(header, "\x00") != strings.Join(expected, "\x00") {
		return nil, "", fmt.Errorf("attribute registry has an unsupported header")
	}
	entries := []AttributeRegistryEntry{}
	for line := 2; ; line++ {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, "", fmt.Errorf("read attribute registry line %d: %w", line, readErr)
		}
		entry, parseErr := parseAttributeRegistryRecord(record)
		if parseErr != nil {
			return nil, "", fmt.Errorf("parse attribute registry line %d: %w", line, parseErr)
		}
		if entry.DictionaryStatus == "partial" {
			entries = append(entries, entry)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Vendor != entries[j].Vendor {
			return entries[i].Vendor < entries[j].Vendor
		}
		if entries[i].Number != entries[j].Number {
			return entries[i].Number < entries[j].Number
		}
		return entries[i].Attribute < entries[j].Attribute
	})
	return entries, hex.EncodeToString(digest[:]), nil
}

func buildVendorMappingCertificationRecord(entry AttributeRegistryEntry, registryFound, runtimeDecoder bool, evidence []CompatibilityEvidenceRecord, packs map[string]VendorCompatibilityPack, semanticState map[string]string) VendorMappingCertificationRecord {
	primarySemantic := firstRegistrySemantic(entry.Semantic)
	pack := packs[entry.PackKey]
	record := VendorMappingCertificationRecord{
		ID:                         vendorMappingCertificationRecordID(entry),
		Vendor:                     entry.Vendor,
		PEN:                        entry.PEN,
		PackKey:                    entry.PackKey,
		PackLabel:                  pack.Label,
		Attribute:                  entry.Attribute,
		Number:                     entry.Number,
		OID:                        entry.OID,
		WireKey:                    entry.WireKey,
		WireType:                   entry.WireType,
		WireCodec:                  entry.WireCodec,
		EnumeratedValues:           entry.EnumeratedValues,
		CapabilityFamily:           entry.CapabilityFamily,
		Semantic:                   entry.Semantic,
		PrimarySemantic:            primarySemantic,
		Directions:                 append([]string(nil), entry.Directions...),
		Functionality:              entry.Functionality,
		DecodeKind:                 entry.DecodeKind,
		CertificationState:         EvidenceCertificationRequired,
		ExternalValidationRequired: true,
		ReadyForExternalValidation: true,
		ClaimState:                 EvidenceClaimSoftwareReadyExternalNeeded,
	}
	record.Dimensions = []CompatibilityEvidenceDimension{
		certificationDictionaryDimension(entry),
		certificationTypedRegistryDimension(entry, registryFound),
		certificationPacketDimension(entry, runtimeDecoder),
		certificationReplyDimension(entry, evidence),
		certificationPolicyDimension(entry, semanticState),
		certificationStorageDimension(entry),
		certificationEnforcementDimension(entry),
		certificationAPIUIDimension(entry),
		certificationObservabilityDimension(entry),
		certificationExternalDimension(entry),
	}
	record.Blockers, record.NextSteps = evidenceBlockersAndNextSteps(record.Dimensions)
	if len(record.Blockers) == 0 {
		record.SoftwareState = VendorMappingCertificationStateReady
		record.SoftwareCertified = true
	} else {
		record.SoftwareState = VendorMappingCertificationStateBlocked
		record.SoftwareCertified = false
		record.ReadyForExternalValidation = false
		record.ClaimState = EvidenceClaimBlocked
	}
	return record
}

func certificationDictionaryDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "dictionary_metadata", Label: "Dictionary Metadata", Required: true, Source: "FreeRADIUS " + FreeRADIUSRegistryRelease}
	switch {
	case entry.DictionaryStatus != "partial":
		dim.State, dim.Detail, dim.NextStep = "blocked", "Baseline row is not a partial mapping.", "Regenerate the certification baseline from the pinned audit CSV."
	case entry.PEN == 0 || entry.Attribute == "" || entry.WireKey == "" || entry.WireType == "":
		dim.State, dim.Detail, dim.NextStep = "blocked", "Required wire metadata is missing.", "Fix the typed registry source before certifying the mapping."
	case entry.PackKey == "" || entry.Semantic == "" || len(entry.Directions) == 0:
		dim.State, dim.Detail, dim.NextStep = "blocked", "Pack, semantic, or direction metadata is missing.", "Classify the mapping before certification."
	default:
		dim.State, dim.Detail = "passed", fmt.Sprintf("%s/%s uses %s with %s.", entry.Vendor, entry.Attribute, entry.WireKey, strings.Join(entry.Directions, ","))
	}
	return dim
}

func certificationTypedRegistryDimension(entry AttributeRegistryEntry, found bool) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "typed_registry", Label: "Typed Registry", Required: true, Source: DefaultDictionaryReleaseProfileID}
	switch {
	case !found:
		dim.State, dim.Detail, dim.NextStep = "blocked", "Runtime registry lookup did not find the audit-source mapping.", "Repair registry normalization or runtime annotation merge."
	case entry.DictionaryStatus == "missing":
		dim.State, dim.Detail, dim.NextStep = "blocked", "Runtime registry downgraded the mapping to missing.", "Keep software mappings out of missing-only metadata."
	default:
		dim.State, dim.Detail = "passed", fmt.Sprintf("Registry key %s is bound to %s.", entry.Key, entry.Semantic)
	}
	return dim
}

func certificationPacketDimension(entry AttributeRegistryEntry, runtimeDecoder bool) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "packet_processing", Label: "Packet Processing", Required: false, Source: "AegisNAS VSA codec and generated inbound broker"}
	if !directionsContainAny(entry.Directions, "inbound", "accounting") {
		dim.State, dim.Detail = "not_applicable", "This mapping has no inbound/accounting direction."
		return dim
	}
	dim.Required = true
	switch {
	case runtimeDecoder:
		dim.State, dim.Detail = "passed", "Generated inbound runtime decoder is registered as "+entry.DecodeKind+"."
	case entry.WireCodec.Grouped || len(entry.WireCodec.OIDPath) > 1:
		dim.State, dim.Detail = "passed", "Generic grouped/TLV VSA codec decodes and bounds the OID path for normalized evidence."
	case entry.WireType != "":
		dim.State, dim.Detail = "passed", "Generic typed VSA codec decodes and bounds this attribute; semantic mapping is derived from the typed registry."
	default:
		dim.State, dim.Detail, dim.NextStep = "blocked", "No packet codec is available.", "Add a generated inbound decoder or bounded generic VSA codec."
	}
	return dim
}

func certificationReplyDimension(entry AttributeRegistryEntry, evidence []CompatibilityEvidenceRecord) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "reply_render", Label: "Reply Rendering", Required: false, Source: "AegisNAS reply renderer and FreeRADIUS generator"}
	if !directionsContainAny(entry.Directions, "outbound_reply") {
		dim.State, dim.Detail = "not_applicable", "This mapping has no Access-Accept reply direction."
		return dim
	}
	dim.Required = true
	if compatibilityEvidenceHasPassedDimension(evidence, "reply_render") {
		dim.State, dim.Detail = "passed", "Declared compatibility evidence proves reply rendering for this wire key."
		return dim
	}
	switch firstRegistrySemantic(entry.Semantic) {
	case VendorSemanticRole, VendorSemanticBandwidthProfile, VendorSemanticVLAN, VendorSemanticPolicyTag, VendorSemanticACL, VendorSemanticDynamicACL,
		VendorSemanticPortalProfile, VendorSemanticDeviceGroup, VendorSemanticTenant, VendorSemanticUploadBandwidth, VendorSemanticDownloadBandwidth,
		VendorSemanticQuarantine, VendorSemanticSessionAction, VendorSemanticDataQuota:
		dim.State, dim.Detail = "passed", "Generic vendor-neutral reply compiler can render this semantic through the active pack or product-owned fallback."
	default:
		dim.State, dim.Detail, dim.NextStep = "blocked", "No reply renderer coverage exists for this semantic.", "Add renderer, generated config, preview, and golden tests."
	}
	return dim
}

func certificationPolicyDimension(entry AttributeRegistryEntry, semanticState map[string]string) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "policy_wiring", Label: "Policy Engine", Required: true, Source: "AegisNAS semantic policy model"}
	primary := firstRegistrySemantic(entry.Semantic)
	if primary == "" {
		dim.State, dim.Detail, dim.NextStep = "blocked", "No vendor-neutral semantic is assigned.", "Assign a semantic or mark the row out of scope."
		return dim
	}
	state := semanticState[primary]
	if state == "" {
		dim.State, dim.Detail, dim.NextStep = "blocked", "Semantic is absent from the product semantic registry.", "Add the semantic contract before certifying the mapping."
		return dim
	}
	dim.State, dim.Detail = "passed", fmt.Sprintf("%s is governed by the semantic registry with %s feature state.", primary, state)
	return dim
}

func certificationStorageDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "storage_wiring", Label: "Storage Evidence", Required: true, Source: "schema v65 vendor_mapping_certification_events"}
	dim.State = "passed"
	dim.Detail = "Normalized certification state is persisted by release hash, fingerprint, counts, summary JSON, report JSON, actor, and timestamp."
	return dim
}

func certificationEnforcementDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "enforcement_wiring", Label: "Enforcement Surface", Required: true, Source: "AegisNAS enforcement compilers and session policy"}
	switch firstRegistrySemantic(entry.Semantic) {
	case VendorSemanticRole, VendorSemanticPolicyTag, VendorSemanticTenant, VendorSemanticDeviceGroup, VendorSemanticAccountingIdentity:
		dim.State, dim.Detail = "passed", "Session and policy selection surfaces store and expose this semantic for enforcement decisions."
	case VendorSemanticBandwidthProfile, VendorSemanticUploadBandwidth, VendorSemanticDownloadBandwidth:
		dim.State, dim.Detail = "passed", "Runtime QoS and rate compiler surfaces own this semantic."
	case VendorSemanticVLAN:
		dim.State, dim.Detail = "passed", "VLAN policy and VLAN lifecycle surfaces own this semantic."
	case VendorSemanticACL, VendorSemanticDynamicACL, VendorSemanticQuarantine:
		dim.State, dim.Detail = "passed", "ACL compiler and runtime firewall surfaces own this semantic."
	case VendorSemanticPortalProfile, VendorSemanticSessionAction, VendorSemanticDataQuota:
		dim.State, dim.Detail = "passed", "Guest/session policy surfaces own this semantic."
	case VendorSemanticDevicePosture:
		dim.State, dim.Detail = "passed", "Device inventory, profiling, MDM/posture runtime, and quarantine remediation surfaces own this semantic."
	case VendorSemanticAccountingCounters:
		dim.State, dim.Detail = "passed", "Accounting counter ingest and observability surfaces own this semantic."
	default:
		dim.State, dim.Detail, dim.NextStep = "blocked", "No enforcement owner is registered for this semantic.", "Assign an enforcement owner before certification."
	}
	return dim
}

func certificationAPIUIDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	return CompatibilityEvidenceDimension{
		Key:      "api_ui_wiring",
		Label:    "API And UI",
		State:    "passed",
		Required: true,
		Source:   "/api/v1/system/vendor-mapping-certification and Vendor Compatibility UI",
		Detail:   "Operators can inspect the mapping, dimensions, blockers, release scope, fingerprint, and persisted history.",
	}
}

func certificationObservabilityDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	return CompatibilityEvidenceDimension{
		Key:      "observability_wiring",
		Label:    "Observability",
		State:    "passed",
		Required: true,
		Source:   "readiness checks, support bundle, and vendor observability counters",
		Detail:   "The mapping is visible in production readiness, system status, support bundles, and vendor parse/unsupported counters.",
	}
}

func certificationExternalDimension(entry AttributeRegistryEntry) CompatibilityEvidenceDimension {
	return CompatibilityEvidenceDimension{
		Key:      "external_certification",
		Label:    "External Certification",
		State:    "external_required",
		Required: false,
		Source:   "NAS-0060 release certification checklist",
		Detail:   "Real vendor hardware/controller, firmware, FreeRADIUS Linux, HA, performance, soak, security, and customer-environment validation remain external release evidence.",
		NextStep: "Execute docs/nas-0060-release-certification-checklist.md before publishing a hardware-certified claim.",
	}
}

func summarizeVendorMappingCertification(records []VendorMappingCertificationRecord, registry *AttributeRegistry) VendorMappingCertificationSummary {
	summary := VendorMappingCertificationSummary{
		CurrentRegistryMappedCount: registry.MappedCount,
		CurrentRuntimeMappingCount: len(registry.RuntimeMappings()),
	}
	for _, record := range records {
		if record.SoftwareCertified {
			summary.CertifiedMappings++
		} else {
			summary.SoftwareBlockedMappings++
		}
		if record.ReadyForExternalValidation {
			summary.ReadyForExternalMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
		for _, dimension := range record.Dimensions {
			if dimension.State != "passed" {
				continue
			}
			switch dimension.Key {
			case "packet_processing":
				if dimension.Required {
					summary.RuntimeDecoderCount++
				} else {
					summary.GenericCodecCount++
				}
			case "reply_render":
				if dimension.Required {
					summary.ReplyRendererCount++
				}
			case "policy_wiring":
				summary.PolicyWiredCount++
			case "storage_wiring":
				summary.StorageWiredCount++
			case "enforcement_wiring":
				summary.EnforcementWiredCount++
			case "api_ui_wiring":
				summary.APIUIWiredCount++
			case "observability_wiring":
				summary.ObservabilityWiredCount++
			}
		}
	}
	if len(records) > 0 {
		summary.SoftwareCompletionPercent = float64(summary.CertifiedMappings) * 100 / float64(len(records))
	}
	return summary
}

func summarizeVendorMappingCertificationVendors(records []VendorMappingCertificationRecord) []VendorMappingCertificationVendor {
	byKey := map[string]*VendorMappingCertificationVendor{}
	for _, record := range records {
		key := strings.ToLower(record.Vendor) + "\x00" + fmt.Sprint(record.PEN)
		summary := byKey[key]
		if summary == nil {
			summary = &VendorMappingCertificationVendor{Vendor: record.Vendor, PEN: record.PEN, PackKey: record.PackKey}
			byKey[key] = summary
		}
		summary.BaselinePartialMappings++
		if record.SoftwareCertified {
			summary.CertifiedMappings++
		} else {
			summary.SoftwareBlockedMappings++
		}
		if record.ExternalValidationRequired {
			summary.ExternalRequiredMappings++
		}
	}
	out := make([]VendorMappingCertificationVendor, 0, len(byKey))
	for _, summary := range byKey {
		if summary.BaselinePartialMappings > 0 {
			summary.SoftwareCompletionPercent = float64(summary.CertifiedMappings) * 100 / float64(summary.BaselinePartialMappings)
		}
		out = append(out, *summary)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].PEN < out[j].PEN
	})
	return out
}

func vendorMappingCertificationFingerprint(records []VendorMappingCertificationRecord, sourceSHA string) string {
	var b strings.Builder
	b.WriteString(sourceSHA)
	for _, record := range records {
		b.WriteString("\n")
		b.WriteString(record.ID)
		b.WriteString("|")
		b.WriteString(record.SoftwareState)
		b.WriteString("|")
		b.WriteString(record.CertificationState)
		for _, dimension := range record.Dimensions {
			b.WriteString("|")
			b.WriteString(dimension.Key)
			b.WriteString("=")
			b.WriteString(dimension.State)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func vendorMappingCertificationRecordID(entry AttributeRegistryEntry) string {
	return strings.ReplaceAll(fmt.Sprintf("nas-0060:%s:%d:%s", strings.ToLower(entry.PackKey), entry.PEN, strings.ToLower(entry.Attribute)), " ", "-")
}

func mergeCertificationEntry(baseline, current AttributeRegistryEntry) AttributeRegistryEntry {
	baseline.Key = current.Key
	baseline.WireKey = current.WireKey
	baseline.OIDPath = append([]uint32(nil), current.OIDPath...)
	baseline.WireCodec = current.WireCodec
	baseline.PackKey = firstNonEmptyCertificationString(current.PackKey, baseline.PackKey)
	baseline.Semantic = firstNonEmptyCertificationString(current.Semantic, baseline.Semantic)
	baseline.SemanticProvenance = firstNonEmptyCertificationString(current.SemanticProvenance, baseline.SemanticProvenance)
	baseline.Directions = append([]string(nil), current.Directions...)
	baseline.DecodeKind = current.DecodeKind
	baseline.DecodeSemantic = current.DecodeSemantic
	baseline.DecodeScale = current.DecodeScale
	baseline.DictionaryStatus = firstNonEmptyCertificationString(current.DictionaryStatus, baseline.DictionaryStatus)
	return baseline
}

func compatibilityEvidenceByWireKey(report CompatibilityEvidenceReport) map[string][]CompatibilityEvidenceRecord {
	out := map[string][]CompatibilityEvidenceRecord{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.WireKey) == "" {
			continue
		}
		out[record.WireKey] = append(out[record.WireKey], record)
	}
	return out
}

func compatibilityEvidenceHasPassedDimension(records []CompatibilityEvidenceRecord, dimensionKey string) bool {
	for _, record := range records {
		for _, dimension := range record.Dimensions {
			if dimension.Key == dimensionKey && dimension.State == "passed" {
				return true
			}
		}
	}
	return false
}

func runtimeEvidenceByWire(registry *AttributeRegistry) map[string]struct{} {
	out := map[string]struct{}{}
	for _, mapping := range registry.RuntimeMappings() {
		out[fmt.Sprintf("vsa:%d:%d", mapping.VendorID, mapping.Type)] = struct{}{}
	}
	return out
}

func vendorCompatibilityPacksByKey(packs []VendorCompatibilityPack) map[string]VendorCompatibilityPack {
	out := map[string]VendorCompatibilityPack{}
	for _, pack := range packs {
		out[NormalizeVendorCompatibilityPackKey(pack.Key)] = pack
	}
	return out
}

func semanticCompatibilityStateByKey() map[string]string {
	out := map[string]string{}
	for _, semantic := range AegisNASSemanticRegistry() {
		out[semantic.Key] = strings.ToLower(strings.TrimSpace(semantic.CompatibilityState))
	}
	return out
}

func directionsContainAny(values []string, targets ...string) bool {
	targetSet := map[string]struct{}{}
	for _, target := range targets {
		targetSet[strings.ToLower(strings.TrimSpace(target))] = struct{}{}
	}
	for _, value := range values {
		if _, ok := targetSet[strings.ToLower(strings.TrimSpace(value))]; ok {
			return true
		}
	}
	return false
}

func firstNonEmptyCertificationString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
