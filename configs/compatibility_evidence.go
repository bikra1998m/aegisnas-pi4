package configs

import (
	"fmt"
	"sort"
	"strings"
)

const (
	CompatibilityEvidenceSchemaVersion = 1

	EvidenceSoftwareStateReady       = "ready"
	EvidenceSoftwareStatePlanned     = "planned"
	EvidenceSoftwareStateBlocked     = "blocked"
	EvidenceSoftwareStateMetadata    = "metadata_only"
	EvidenceCertificationNotRequired = "not_required"
	EvidenceCertificationRequired    = "external_required"
	EvidenceCertificationCertified   = "certified"

	EvidenceClaimSoftwareReady               = "software_ready"
	EvidenceClaimSoftwareReadyExternalNeeded = "software_ready_external_required"
	EvidenceClaimPlanned                     = "planned"
	EvidenceClaimBlocked                     = "blocked"
	EvidenceClaimMetadataOnly                = "metadata_only"
)

type CompatibilityEvidenceReport struct {
	SchemaVersion    int                           `json:"schema_version"`
	ReleaseProfileID string                        `json:"release_profile_id"`
	SourceSHA256     string                        `json:"source_sha256"`
	Summary          CompatibilityEvidenceSummary  `json:"summary"`
	Records          []CompatibilityEvidenceRecord `json:"records"`
	Notes            []string                      `json:"notes,omitempty"`
}

type CompatibilityEvidenceSummary struct {
	TotalRecords             int `json:"total_records"`
	SoftwareReadyCount       int `json:"software_ready_count"`
	SoftwarePlannedCount     int `json:"software_planned_count"`
	SoftwareBlockedCount     int `json:"software_blocked_count"`
	MetadataOnlyCount        int `json:"metadata_only_count"`
	ExternalRequiredCount    int `json:"external_required_count"`
	ExternallyCertifiedCount int `json:"externally_certified_count"`
	DictionaryPassedCount    int `json:"dictionary_passed_count"`
	RegistryPassedCount      int `json:"registry_passed_count"`
	PacketDecodePassedCount  int `json:"packet_decode_passed_count"`
	ReplyRenderPassedCount   int `json:"reply_render_passed_count"`
	PolicyWiredCount         int `json:"policy_wired_count"`
	DeviceCertificationCount int `json:"device_certification_count"`
}

type CompatibilityEvidenceRecord struct {
	ID                 string                           `json:"id"`
	SubjectType        string                           `json:"subject_type"`
	PackKey            string                           `json:"pack_key,omitempty"`
	PackLabel          string                           `json:"pack_label,omitempty"`
	Active             bool                             `json:"active"`
	VendorName         string                           `json:"vendor_name,omitempty"`
	VendorID           int                              `json:"vendor_id,omitempty"`
	Attribute          string                           `json:"attribute,omitempty"`
	Semantic           string                           `json:"semantic,omitempty"`
	Direction          string                           `json:"direction,omitempty"`
	ValueType          string                           `json:"value_type,omitempty"`
	CompatibilityState string                           `json:"compatibility_state,omitempty"`
	DictionaryStatus   string                           `json:"dictionary_status,omitempty"`
	RegistryKey        string                           `json:"registry_key,omitempty"`
	WireKey            string                           `json:"wire_key,omitempty"`
	SoftwareState      string                           `json:"software_state"`
	CertificationState string                           `json:"certification_state"`
	ClaimState         string                           `json:"claim_state"`
	SoftwareReady      bool                             `json:"software_ready"`
	ReadyForExternal   bool                             `json:"ready_for_external_validation"`
	ExternalValidation bool                             `json:"external_validation_required"`
	Dimensions         []CompatibilityEvidenceDimension `json:"dimensions"`
	Blockers           []string                         `json:"blockers,omitempty"`
	NextSteps          []string                         `json:"next_steps,omitempty"`
}

type CompatibilityEvidenceDimension struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	State    string `json:"state"`
	Required bool   `json:"required"`
	Source   string `json:"source,omitempty"`
	Detail   string `json:"detail,omitempty"`
	NextStep string `json:"next_step,omitempty"`
}

func BuildCompatibilityEvidenceReport(catalog VendorDictionaryCatalog, packs []VendorCompatibilityPack, activeKeys []string) CompatibilityEvidenceReport {
	registry := MustBuiltInAttributeRegistry()
	releaseProfile := DefaultDictionaryReleaseProfile()
	coverage := BuildVendorDictionaryCoverageReport(catalog, packs, activeKeys)
	coverageByMapping := vendorCoverageByMapping(coverage)
	runtimeByMapping := runtimeEvidenceByMapping(registry)
	active := normalizedPackSet(activeKeys)

	report := CompatibilityEvidenceReport{
		SchemaVersion:    CompatibilityEvidenceSchemaVersion,
		ReleaseProfileID: releaseProfile.ID,
		SourceSHA256:     registry.SourceSHA256,
		Records:          make([]CompatibilityEvidenceRecord, 0, len(packs)*4),
		Notes: []string{
			"compatibility_state is retained for backward compatibility; evidence dimensions are the authoritative software claim model.",
			"software_ready means AegisNAS code paths are wired and tested for the declared scope. It does not mean a physical vendor device is certified.",
			"external_required marks records that need real device, controller, firmware, FreeRADIUS, HA, performance, or customer-environment validation.",
		},
	}

	for _, pack := range packs {
		packKey := NormalizeVendorCompatibilityPackKey(pack.Key)
		for _, mapping := range pack.Attributes {
			coverageRecord := coverageByMapping[mappingEvidenceKey(packKey, mapping.Semantic, mapping.Attribute, mapping.Direction)]
			registryEntry, registryFound := registry.lookupPackAttribute(pack, mapping.Attribute)
			_, activePack := active[packKey]
			record := buildMappingEvidenceRecord(pack, mapping, activePack, coverageRecord, registryEntry, registryFound, runtimeByMapping)
			report.Records = append(report.Records, record)
		}
	}
	sort.SliceStable(report.Records, func(i, j int) bool {
		return report.Records[i].ID < report.Records[j].ID
	})
	report.Summary = summarizeCompatibilityEvidence(report.Records)
	return report
}

func AttachSemanticEvidence(semantics []VendorSemanticCapability) []VendorSemanticCapability {
	out := append([]VendorSemanticCapability(nil), semantics...)
	for i := range out {
		out[i].Evidence = buildSemanticEvidenceRecord(out[i])
	}
	return out
}

func ValidateCompatibilityEvidenceReport(report CompatibilityEvidenceReport) error {
	if report.SchemaVersion != CompatibilityEvidenceSchemaVersion {
		return fmt.Errorf("compatibility evidence schema version %d is unsupported", report.SchemaVersion)
	}
	if strings.TrimSpace(report.ReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("compatibility evidence release profile and source hash are required")
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("compatibility evidence record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("compatibility evidence record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		switch record.SoftwareState {
		case EvidenceSoftwareStateReady, EvidenceSoftwareStatePlanned, EvidenceSoftwareStateBlocked, EvidenceSoftwareStateMetadata:
		default:
			return fmt.Errorf("compatibility evidence record %q has invalid software state %q", record.ID, record.SoftwareState)
		}
		switch record.CertificationState {
		case EvidenceCertificationNotRequired, EvidenceCertificationRequired, EvidenceCertificationCertified:
		default:
			return fmt.Errorf("compatibility evidence record %q has invalid certification state %q", record.ID, record.CertificationState)
		}
		if record.CertificationState == EvidenceCertificationCertified {
			return fmt.Errorf("compatibility evidence record %q claims external certification without a certification evidence store", record.ID)
		}
		if record.SoftwareReady != (record.SoftwareState == EvidenceSoftwareStateReady) {
			return fmt.Errorf("compatibility evidence record %q has inconsistent software_ready flag", record.ID)
		}
		if len(record.Dimensions) == 0 {
			return fmt.Errorf("compatibility evidence record %q has no dimensions", record.ID)
		}
	}
	return nil
}

func buildMappingEvidenceRecord(pack VendorCompatibilityPack, mapping VendorPackAttributeMapping, active bool, coverage VendorDictionaryAttributeCoverage, registryEntry AttributeRegistryEntry, registryFound bool, runtime map[string]struct{}) CompatibilityEvidenceRecord {
	packKey := NormalizeVendorCompatibilityPackKey(pack.Key)
	direction := strings.ToLower(strings.TrimSpace(mapping.Direction))
	compatibilityState := strings.ToLower(strings.TrimSpace(mapping.CompatibilityState))
	vendorName := strings.TrimSpace(pack.VendorName)
	record := CompatibilityEvidenceRecord{
		ID:                 evidenceRecordID("attribute", packKey, mapping.Semantic, mapping.Attribute, direction),
		SubjectType:        "attribute",
		PackKey:            packKey,
		PackLabel:          strings.TrimSpace(pack.Label),
		Active:             active,
		VendorName:         vendorName,
		VendorID:           pack.VendorID,
		Attribute:          strings.TrimSpace(mapping.Attribute),
		Semantic:           strings.TrimSpace(mapping.Semantic),
		Direction:          direction,
		ValueType:          strings.TrimSpace(mapping.ValueType),
		CompatibilityState: compatibilityState,
	}
	if registryFound {
		record.RegistryKey = registryEntry.Key
		record.WireKey = registryEntry.WireKey
		record.DictionaryStatus = registryEntry.DictionaryStatus
	}

	dimensions := []CompatibilityEvidenceDimension{
		dictionaryEvidenceDimension(packKey, coverage, direction),
		registryEvidenceDimension(packKey, direction, registryEntry, registryFound),
		packetDecodeEvidenceDimension(packKey, mapping, registryEntry, registryFound, runtime),
		replyRenderEvidenceDimension(packKey, mapping),
		policyEvidenceDimension(mapping),
		deviceCertificationEvidenceDimension(packKey, vendorName, compatibilityState),
	}
	record.Dimensions = dimensions
	record.Blockers, record.NextSteps = evidenceBlockersAndNextSteps(dimensions)
	record.SoftwareState = mappingSoftwareState(compatibilityState, dimensions)
	record.CertificationState = mappingCertificationState(dimensions)
	record.SoftwareReady = record.SoftwareState == EvidenceSoftwareStateReady
	record.ExternalValidation = record.CertificationState == EvidenceCertificationRequired
	record.ReadyForExternal = record.SoftwareReady && record.ExternalValidation
	record.ClaimState = mappingClaimState(record.SoftwareState, record.CertificationState)
	return record
}

func buildSemanticEvidenceRecord(semantic VendorSemanticCapability) CompatibilityEvidenceRecord {
	state := strings.ToLower(strings.TrimSpace(semantic.CompatibilityState))
	record := CompatibilityEvidenceRecord{
		ID:                 evidenceRecordID("semantic", "semantic", semantic.Key, semantic.Label, ""),
		SubjectType:        "semantic",
		Semantic:           semantic.Key,
		Attribute:          semantic.ProductAttribute,
		Direction:          strings.Join(semantic.Directions, ","),
		ValueType:          semantic.ValueType,
		CompatibilityState: state,
	}
	dimensions := []CompatibilityEvidenceDimension{
		{Key: "semantic_contract", Label: "Semantic Contract", State: "passed", Required: true, Source: "AegisNAS semantic registry", Detail: semantic.Description},
		{Key: "product_attribute", Label: "Product Attribute", State: semanticProductAttributeState(semantic), Required: false, Source: "dictionary.aegisnas", Detail: semantic.ProductAttribute},
		{Key: "policy_wiring", Label: "Policy Wiring", State: semanticPolicyState(state), Required: true, Source: "AegisNAS policy engine", Detail: semantic.HardwareScope, NextStep: semantic.NextStep},
		{Key: "external_certification", Label: "External Certification", State: semanticCertificationState(state), Required: false, Source: "release certification", Detail: "Semantic behavior is product-owned unless it renders vendor-specific enforcement."},
	}
	record.Dimensions = dimensions
	record.Blockers, record.NextSteps = evidenceBlockersAndNextSteps(dimensions)
	record.SoftwareState = mappingSoftwareState(state, dimensions)
	record.CertificationState = mappingCertificationState(dimensions)
	record.SoftwareReady = record.SoftwareState == EvidenceSoftwareStateReady
	record.ExternalValidation = record.CertificationState == EvidenceCertificationRequired
	record.ReadyForExternal = record.SoftwareReady && record.ExternalValidation
	record.ClaimState = mappingClaimState(record.SoftwareState, record.CertificationState)
	return record
}

func dictionaryEvidenceDimension(packKey string, coverage VendorDictionaryAttributeCoverage, direction string) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "dictionary", Label: "Dictionary Metadata", Required: true, Source: "FreeRADIUS catalog"}
	switch {
	case direction == "controller_api":
		dim.State, dim.Required, dim.Detail = "not_applicable", false, "Controller-native capability does not require a RADIUS dictionary attribute."
	case packKey == VendorPackStandard:
		dim.State, dim.Detail = "passed", "Standard RADIUS attribute."
	case coverage.DictionaryAttributeFound:
		dim.State, dim.Detail = "passed", fmt.Sprintf("Dictionary type %s, values %d.", coverage.DictionaryType, coverage.DictionaryValueCount)
	case coverage.Attribute == "":
		dim.State, dim.Detail, dim.NextStep = "metadata_only", "Coverage metadata was not available for this mapping.", "Rebuild the compatibility coverage report."
	default:
		dim.State, dim.Detail, dim.NextStep = "blocked", coverage.Warning, "Import the vendor dictionary or mark the mapping planned until a reviewed dictionary source is available."
	}
	return dim
}

func registryEvidenceDimension(packKey, direction string, entry AttributeRegistryEntry, found bool) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "typed_registry", Label: "Typed Registry", Required: true, Source: DefaultDictionaryReleaseProfileID}
	switch {
	case direction == "controller_api" || packKey == VendorPackStandard || packKey == VendorPackAegisNAS:
		dim.State, dim.Required, dim.Detail = "not_applicable", false, "Mapping is standards-based, product-owned, or controller-native."
	case !found:
		dim.State, dim.Detail, dim.NextStep = "blocked", "No typed registry entry matched this pack attribute.", "Add or correct the registry mapping before claiming packet behavior."
	case entry.DictionaryStatus == "missing":
		dim.State, dim.Detail, dim.NextStep = "blocked", "Registry entry exists only as missing metadata.", "Classify the attribute semantics and direction before using it in policy."
	default:
		dim.State, dim.Detail = "passed", fmt.Sprintf("%s %s", entry.WireKey, entry.Semantic)
	}
	return dim
}

func packetDecodeEvidenceDimension(packKey string, mapping VendorPackAttributeMapping, entry AttributeRegistryEntry, found bool, runtime map[string]struct{}) CompatibilityEvidenceDimension {
	direction := strings.ToLower(strings.TrimSpace(mapping.Direction))
	dim := CompatibilityEvidenceDimension{Key: "packet_decode", Label: "Packet Decode", Required: false, Source: "AegisNAS RADIUS decoder"}
	if direction != "inbound" && direction != "accounting" {
		dim.State, dim.Detail = "not_applicable", "No inbound/accounting decode is required for this direction."
		return dim
	}
	dim.Required = true
	if packKey == VendorPackStandard || packKey == VendorPackAegisNAS {
		dim.State, dim.Detail = "passed", "Handled by standard or product-owned packet paths."
		return dim
	}
	if !found || entry.Number == 0 {
		dim.State, dim.Detail, dim.NextStep = "blocked", "No executable registry entry is available for decode.", "Add a typed runtime decoder or downgrade this mapping to planned."
		return dim
	}
	key := runtimeEvidenceKey(packKey, entry.PEN, entry.Number, mapping.Semantic)
	if _, ok := runtime[key]; ok {
		dim.State, dim.Detail = "passed", entry.DecodeKind
		return dim
	}
	dim.State, dim.Detail, dim.NextStep = "planned", "The registry entry has metadata but no executable decoder.", "Add golden packet vectors and a bounded decoder before enabling inbound behavior."
	return dim
}

func replyRenderEvidenceDimension(packKey string, mapping VendorPackAttributeMapping) CompatibilityEvidenceDimension {
	direction := strings.ToLower(strings.TrimSpace(mapping.Direction))
	state := strings.ToLower(strings.TrimSpace(mapping.CompatibilityState))
	dim := CompatibilityEvidenceDimension{Key: "reply_render", Label: "Reply Renderer", Required: false, Source: "AegisNAS reply preview and FreeRADIUS generator"}
	if direction != "outbound_reply" {
		dim.State, dim.Detail = "not_applicable", "No Access-Accept reply rendering is required for this direction."
		return dim
	}
	dim.Required = true
	if state == "implemented" {
		dim.State, dim.Detail = "passed", "Reply preview and generated RADIUS config can render this mapping."
		if packKey != VendorPackStandard && packKey != VendorPackAegisNAS {
			dim.Detail += " Device-side enforcement still needs external certification."
		}
		return dim
	}
	dim.State, dim.Detail, dim.NextStep = "planned", "Mapping is declared but not implemented for reply rendering.", "Implement renderer, preview, generated config, and tests before enabling."
	return dim
}

func policyEvidenceDimension(mapping VendorPackAttributeMapping) CompatibilityEvidenceDimension {
	state := strings.ToLower(strings.TrimSpace(mapping.CompatibilityState))
	dim := CompatibilityEvidenceDimension{Key: "policy_wiring", Label: "Policy Wiring", Required: true, Source: "AegisNAS semantic policy"}
	if strings.TrimSpace(mapping.Semantic) == "" {
		dim.State, dim.Detail, dim.NextStep = "blocked", "Mapping has no vendor-neutral semantic.", "Assign an AegisNAS semantic or explicitly mark the attribute out of scope."
		return dim
	}
	if state == "implemented" {
		dim.State, dim.Detail = "passed", mapping.Semantic
		return dim
	}
	dim.State, dim.Detail, dim.NextStep = "planned", "Semantic is known but software behavior is not fully wired.", "Complete packet, renderer, policy, persistence, API, UI, and tests for this semantic."
	return dim
}

func deviceCertificationEvidenceDimension(packKey, vendorName, compatibilityState string) CompatibilityEvidenceDimension {
	dim := CompatibilityEvidenceDimension{Key: "external_certification", Label: "External Certification", Required: false, Source: "release certification checklist"}
	switch {
	case compatibilityState != "implemented":
		dim.State, dim.Detail = "planned", "Software implementation is not complete, so external certification is not ready."
	case packKey == VendorPackStandard || packKey == VendorPackAegisNAS || strings.TrimSpace(vendorName) == "":
		dim.State, dim.Detail = "not_applicable", "No third-party vendor firmware certification is required for this product-owned or standards-only mapping."
	default:
		dim.State, dim.Detail, dim.NextStep = "external_required", "Exact vendor hardware, controller, firmware, FreeRADIUS, HA, performance, and customer-environment validation is required.", "Execute the release certification checklist before publishing a certified claim."
	}
	return dim
}

func mappingSoftwareState(compatibilityState string, dimensions []CompatibilityEvidenceDimension) string {
	compatibilityState = strings.ToLower(strings.TrimSpace(compatibilityState))
	if compatibilityState == "" || compatibilityState == "missing" {
		return EvidenceSoftwareStateMetadata
	}
	if compatibilityState != "implemented" {
		return EvidenceSoftwareStatePlanned
	}
	for _, dim := range dimensions {
		if dim.Required && dim.State == "blocked" {
			return EvidenceSoftwareStateBlocked
		}
	}
	for _, dim := range dimensions {
		if dim.Required && dim.State == "planned" {
			return EvidenceSoftwareStatePlanned
		}
	}
	return EvidenceSoftwareStateReady
}

func mappingCertificationState(dimensions []CompatibilityEvidenceDimension) string {
	for _, dim := range dimensions {
		if dim.Key == "external_certification" {
			switch dim.State {
			case "external_required":
				return EvidenceCertificationRequired
			case "passed", "certified":
				return EvidenceCertificationCertified
			default:
				return EvidenceCertificationNotRequired
			}
		}
	}
	return EvidenceCertificationNotRequired
}

func mappingClaimState(softwareState, certificationState string) string {
	switch {
	case softwareState == EvidenceSoftwareStateReady && certificationState == EvidenceCertificationRequired:
		return EvidenceClaimSoftwareReadyExternalNeeded
	case softwareState == EvidenceSoftwareStateReady:
		return EvidenceClaimSoftwareReady
	case softwareState == EvidenceSoftwareStateBlocked:
		return EvidenceClaimBlocked
	case softwareState == EvidenceSoftwareStatePlanned:
		return EvidenceClaimPlanned
	default:
		return EvidenceClaimMetadataOnly
	}
}

func evidenceBlockersAndNextSteps(dimensions []CompatibilityEvidenceDimension) ([]string, []string) {
	var blockers []string
	var next []string
	seenNext := map[string]struct{}{}
	for _, dim := range dimensions {
		if dim.Required && dim.State == "blocked" {
			blockers = append(blockers, dim.Label+": "+strings.TrimSpace(dim.Detail))
		}
		if strings.TrimSpace(dim.NextStep) != "" {
			key := strings.ToLower(strings.TrimSpace(dim.NextStep))
			if _, exists := seenNext[key]; !exists {
				seenNext[key] = struct{}{}
				next = append(next, strings.TrimSpace(dim.NextStep))
			}
		}
	}
	return blockers, next
}

func summarizeCompatibilityEvidence(records []CompatibilityEvidenceRecord) CompatibilityEvidenceSummary {
	var summary CompatibilityEvidenceSummary
	summary.TotalRecords = len(records)
	for _, record := range records {
		switch record.SoftwareState {
		case EvidenceSoftwareStateReady:
			summary.SoftwareReadyCount++
		case EvidenceSoftwareStatePlanned:
			summary.SoftwarePlannedCount++
		case EvidenceSoftwareStateBlocked:
			summary.SoftwareBlockedCount++
		case EvidenceSoftwareStateMetadata:
			summary.MetadataOnlyCount++
		}
		switch record.CertificationState {
		case EvidenceCertificationRequired:
			summary.ExternalRequiredCount++
		case EvidenceCertificationCertified:
			summary.ExternallyCertifiedCount++
		}
		for _, dim := range record.Dimensions {
			if dim.State != "passed" {
				continue
			}
			switch dim.Key {
			case "dictionary":
				summary.DictionaryPassedCount++
			case "typed_registry":
				summary.RegistryPassedCount++
			case "packet_decode":
				summary.PacketDecodePassedCount++
			case "reply_render":
				summary.ReplyRenderPassedCount++
			case "policy_wiring":
				summary.PolicyWiredCount++
			case "external_certification":
				summary.DeviceCertificationCount++
			}
		}
	}
	return summary
}

func vendorCoverageByMapping(coverage VendorDictionaryCoverageReport) map[string]VendorDictionaryAttributeCoverage {
	out := map[string]VendorDictionaryAttributeCoverage{}
	for _, row := range coverage.Rows {
		for _, attr := range row.Attributes {
			out[mappingEvidenceKey(row.PackKey, attr.Semantic, attr.Attribute, attr.Direction)] = attr
		}
	}
	return out
}

func runtimeEvidenceByMapping(registry *AttributeRegistry) map[string]struct{} {
	out := map[string]struct{}{}
	for _, mapping := range registry.RuntimeMappings() {
		out[runtimeEvidenceKey(mapping.PackKey, mapping.VendorID, uint32(mapping.Type), mapping.Semantic)] = struct{}{}
	}
	return out
}

func runtimeEvidenceKey(packKey string, pen, number uint32, semantic string) string {
	return fmt.Sprintf("%s\x00%d\x00%d\x00%s", NormalizeVendorCompatibilityPackKey(packKey), pen, number, strings.ToLower(strings.TrimSpace(semantic)))
}

func mappingEvidenceKey(packKey, semantic, attribute, direction string) string {
	return strings.Join([]string{
		NormalizeVendorCompatibilityPackKey(packKey),
		strings.ToLower(strings.TrimSpace(semantic)),
		strings.ToLower(strings.TrimSpace(attribute)),
		strings.ToLower(strings.TrimSpace(direction)),
	}, "\x00")
}

func evidenceRecordID(subjectType, packKey, semantic, attribute, direction string) string {
	parts := []string{
		subjectType,
		NormalizeVendorCompatibilityPackKey(packKey),
		strings.ToLower(strings.TrimSpace(semantic)),
		strings.ToLower(strings.TrimSpace(attribute)),
		strings.ToLower(strings.TrimSpace(direction)),
	}
	return strings.ReplaceAll(strings.Join(parts, ":"), " ", "-")
}

func semanticProductAttributeState(semantic VendorSemanticCapability) string {
	if strings.TrimSpace(semantic.ProductAttribute) != "" || len(semantic.StandardAttributes) > 0 {
		return "passed"
	}
	return "not_applicable"
}

func semanticPolicyState(state string) string {
	if state == "implemented" {
		return "passed"
	}
	return "planned"
}

func semanticCertificationState(state string) string {
	if state == "implemented" {
		return "not_applicable"
	}
	return "planned"
}
