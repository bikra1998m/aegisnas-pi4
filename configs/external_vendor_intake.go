package configs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ExternalVendorIntakeSchemaVersion = 1
	ExternalVendorIntakeFeatureID     = "NAS-0073"
	ExternalVendorIntakeMaxBytes      = 1024 * 1024
	ExternalVendorIntakeMaxAttributes = 2048

	ExternalVendorIntakeSoftwareReady = "software_ready"
	ExternalVendorIntakeSoftwareBlock = "software_blocked"
	ExternalVendorIntakeExternalScope = "external_certification_required"
)

type ExternalVendorIntakeRequest struct {
	VendorName       string   `json:"vendor_name"`
	PEN              uint32   `json:"pen"`
	IntendedPackKey  string   `json:"intended_pack_key,omitempty"`
	ProductFamilies  []string `json:"product_families,omitempty"`
	DictionaryName   string   `json:"dictionary_name,omitempty"`
	DictionaryText   string   `json:"dictionary_text"`
	SourceURL        string   `json:"source_url"`
	SourceSHA256     string   `json:"source_sha256,omitempty"`
	LicenseID        string   `json:"license_id"`
	LicenseReference string   `json:"license_reference"`
	UpstreamVersion  string   `json:"upstream_version"`
	RetrievedAt      string   `json:"retrieved_at"`
	Submitter        string   `json:"submitter,omitempty"`
	ReviewNotes      []string `json:"review_notes,omitempty"`
}

type ExternalVendorIntakeGovernanceReport struct {
	SchemaVersion                 int      `json:"schema_version"`
	FeatureID                     string   `json:"feature_id"`
	Status                        string   `json:"status"`
	DictionaryReleaseProfileID    string   `json:"dictionary_release_profile_id"`
	SourceRelease                 string   `json:"source_release"`
	SourceSHA256                  string   `json:"source_sha256"`
	MaxDictionaryBytes            int      `json:"max_dictionary_bytes"`
	MaxAttributes                 int      `json:"max_attributes"`
	AllowedLicenses               []string `json:"allowed_licenses"`
	RequiredProvenanceFields      []string `json:"required_provenance_fields"`
	SupportedDictionaryDirectives []string `json:"supported_dictionary_directives"`
	SupportedWireTypes            []string `json:"supported_wire_types"`
	SupportedSemantics            []string `json:"supported_semantics"`
	ExternalVendorExamples        []string `json:"external_vendor_examples"`
	ReleaseCertificationChecklist string   `json:"release_certification_checklist"`
	Notes                         []string `json:"notes,omitempty"`
}

type ExternalVendorIntakeReport struct {
	SchemaVersion                 int                             `json:"schema_version"`
	FeatureID                     string                          `json:"feature_id"`
	Status                        string                          `json:"status"`
	GeneratedAt                   string                          `json:"generated_at"`
	DictionaryReleaseProfileID    string                          `json:"dictionary_release_profile_id"`
	SourceRelease                 string                          `json:"source_release"`
	SourceSHA256                  string                          `json:"source_sha256"`
	ReleaseCertificationChecklist string                          `json:"release_certification_checklist"`
	Vendor                        ExternalVendorIntakeVendor      `json:"vendor"`
	Provenance                    ExternalVendorIntakeProvenance  `json:"provenance"`
	Summary                       ExternalVendorIntakeSummary     `json:"summary"`
	ProductScopes                 []ExternalVendorIntakeScope     `json:"product_scopes"`
	Records                       []ExternalVendorIntakeAttribute `json:"records"`
	Blockers                      []string                        `json:"blockers,omitempty"`
	Warnings                      []string                        `json:"warnings,omitempty"`
	Notes                         []string                        `json:"notes,omitempty"`
}

type ExternalVendorIntakeVendor struct {
	Name                  string   `json:"name"`
	CanonicalName         string   `json:"canonical_name"`
	PEN                   uint32   `json:"pen"`
	IntendedPackKey       string   `json:"intended_pack_key"`
	ProductFamilies       []string `json:"product_families,omitempty"`
	DictionaryName        string   `json:"dictionary_name,omitempty"`
	InPinnedCorpus        bool     `json:"in_pinned_corpus"`
	RuntimeExtensionKnown bool     `json:"runtime_extension_known"`
	OutOfCorpus           bool     `json:"out_of_corpus"`
}

type ExternalVendorIntakeProvenance struct {
	SourceURL        string `json:"source_url"`
	SourceSHA256     string `json:"source_sha256"`
	ComputedSHA256   string `json:"computed_sha256"`
	LicenseID        string `json:"license_id"`
	LicenseReference string `json:"license_reference"`
	UpstreamVersion  string `json:"upstream_version"`
	RetrievedAt      string `json:"retrieved_at"`
	Submitter        string `json:"submitter,omitempty"`
	LicenseState     string `json:"license_state"`
	ProvenanceState  string `json:"provenance_state"`
	PENState         string `json:"pen_state"`
	SemanticState    string `json:"semantic_state"`
}

type ExternalVendorIntakeSummary struct {
	VendorCount                       int     `json:"vendor_count"`
	ProductScopeCount                 int     `json:"product_scope_count"`
	AttributeCount                    int     `json:"attribute_count"`
	RuntimeDecodableAttributes        int     `json:"runtime_decodable_attributes"`
	MetadataOnlyAttributes            int     `json:"metadata_only_attributes"`
	NativeSemanticMappings            int     `json:"native_semantic_mappings"`
	TypedPassthroughMappings          int     `json:"typed_passthrough_mappings"`
	SensitiveRedactedMappings         int     `json:"sensitive_redacted_mappings"`
	EnumeratedValueCount              int     `json:"enumerated_value_count"`
	SoftwareReadyAttributes           int     `json:"software_ready_attributes"`
	SoftwareBlockedAttributes         int     `json:"software_blocked_attributes"`
	ReadyForExternalValidation        int     `json:"ready_for_external_validation_attributes"`
	ExternalCertificationRequirements int     `json:"external_certification_required_attributes"`
	WarningCount                      int     `json:"warning_count"`
	BlockerCount                      int     `json:"blocker_count"`
	SoftwareCompletionPercent         float64 `json:"software_completion_percent"`
	Fingerprint                       string  `json:"fingerprint"`
}

type ExternalVendorIntakeScope struct {
	Key           string   `json:"key"`
	Label         string   `json:"label"`
	Vendors       []string `json:"vendors"`
	Products      []string `json:"products"`
	Dictionary    string   `json:"dictionary"`
	SoftwareState string   `json:"software_state"`
	ExternalState string   `json:"external_state"`
	Notes         []string `json:"notes,omitempty"`
}

type ExternalVendorIntakeAttribute struct {
	ID                         string             `json:"id"`
	Vendor                     string             `json:"vendor"`
	PEN                        uint32             `json:"pen"`
	PackKey                    string             `json:"pack_key"`
	Attribute                  string             `json:"attribute"`
	Number                     uint32             `json:"number,omitempty"`
	OID                        string             `json:"oid,omitempty"`
	WireKey                    string             `json:"wire_key"`
	WireType                   string             `json:"wire_type"`
	WireCodec                  AttributeWireCodec `json:"wire_codec"`
	EnumeratedValues           int                `json:"enumerated_values,omitempty"`
	Capability                 string             `json:"capability"`
	Semantic                   string             `json:"semantic"`
	Directions                 []string           `json:"directions"`
	DecodeKind                 string             `json:"decode_kind,omitempty"`
	DecodeSemantic             string             `json:"decode_semantic,omitempty"`
	DecodeScale                int                `json:"decode_scale,omitempty"`
	Functionality              string             `json:"functionality"`
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
	Blockers                   []string           `json:"blockers,omitempty"`
	Warnings                   []string           `json:"warnings,omitempty"`
	Notes                      []string           `json:"notes,omitempty"`
}

var externalVendorPackKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func BuildExternalVendorIntakeGovernanceReport() ExternalVendorIntakeGovernanceReport {
	registry := MustBuiltInAttributeRegistry()
	return ExternalVendorIntakeGovernanceReport{
		SchemaVersion:              ExternalVendorIntakeSchemaVersion,
		FeatureID:                  ExternalVendorIntakeFeatureID,
		Status:                     ExternalVendorIntakeSoftwareReady,
		DictionaryReleaseProfileID: DefaultDictionaryReleaseProfileID,
		SourceRelease:              FreeRADIUSRegistryRelease,
		SourceSHA256:               registry.SourceSHA256,
		MaxDictionaryBytes:         ExternalVendorIntakeMaxBytes,
		MaxAttributes:              ExternalVendorIntakeMaxAttributes,
		AllowedLicenses: []string{
			"BSD-2-Clause",
			"BSD-3-Clause",
			"MIT",
			"Apache-2.0",
			"ISC",
			"Proprietary-Allowed-With-Grant",
		},
		RequiredProvenanceFields: []string{
			"vendor_name",
			"pen",
			"dictionary_text",
			"source_url",
			"source_sha256",
			"license_id",
			"license_reference",
			"upstream_version",
			"retrieved_at",
		},
		SupportedDictionaryDirectives: []string{"VENDOR", "BEGIN-VENDOR", "END-VENDOR", "ATTRIBUTE", "VALUE"},
		SupportedWireTypes:            externalVendorSupportedWireTypes(),
		SupportedSemantics: []string{
			VendorSemanticRole,
			VendorSemanticVLAN,
			VendorSemanticACL,
			VendorSemanticDynamicACL,
			VendorSemanticUploadBandwidth,
			VendorSemanticDownloadBandwidth,
			VendorSemanticPortalProfile,
			VendorSemanticGuestLifecycle,
			VendorSemanticDevicePosture,
			VendorSemanticTenant,
			VendorSemanticAccountingIdentity,
			VendorSemanticAccountingCounters,
			VendorSemanticCoAReauth,
			VendorSemanticCoADisconnect,
			VendorSemanticAddressPool,
			VendorSemanticIPv4Address,
			VendorSemanticIPv6Address,
			VendorSemanticRoute,
			VendorSemanticVRF,
			VendorSemanticTranslationPolicy,
			VendorSemanticCertificateOnboarding,
			VendorSemanticControllerHealth,
			VendorSemanticPolicyTag,
		},
		ExternalVendorExamples:        []string{"Ubiquiti/UBNT", "Netgear", "future vendor dictionaries not present in the pinned FreeRADIUS corpus"},
		ReleaseCertificationChecklist: "docs/nas-0073-release-certification-checklist.md",
		Notes: []string{
			"NAS-0073 is the governed software intake path for authoritative vendor dictionaries that are not present in the pinned FreeRADIUS 3.2.8 corpus.",
			"Software readiness covers provenance, hash, license, PEN, parser, semantic classification, typed packet handling, redaction, APIs, UI, durable evidence, support bundles, and production-readiness reporting.",
			"Vendor hardware interoperability, production FreeRADIUS validation, HA drills, performance, security audit, and customer acceptance remain release certification activities.",
		},
	}
}

func ValidateExternalVendorIntakeGovernanceReport(report ExternalVendorIntakeGovernanceReport) error {
	if report.SchemaVersion != ExternalVendorIntakeSchemaVersion {
		return fmt.Errorf("external vendor intake schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != ExternalVendorIntakeFeatureID {
		return fmt.Errorf("external vendor intake feature id %q is invalid", report.FeatureID)
	}
	if report.Status != ExternalVendorIntakeSoftwareReady {
		return fmt.Errorf("external vendor intake governance is not software ready")
	}
	if strings.TrimSpace(report.DictionaryReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("external vendor intake release profile and source hash are required")
	}
	if report.MaxDictionaryBytes < 65536 || report.MaxAttributes < 1 {
		return fmt.Errorf("external vendor intake limits are too small")
	}
	if len(report.AllowedLicenses) < 4 || len(report.RequiredProvenanceFields) < 8 || len(report.SupportedWireTypes) < 16 {
		return fmt.Errorf("external vendor intake governance metadata is incomplete")
	}
	if strings.TrimSpace(report.ReleaseCertificationChecklist) == "" {
		return fmt.Errorf("external vendor intake release checklist is required")
	}
	return nil
}

func BuildExternalVendorIntakeReport(input ExternalVendorIntakeRequest) ExternalVendorIntakeReport {
	input = normalizeExternalVendorIntakeRequest(input)
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	registry := MustBuiltInAttributeRegistry()
	payloadBytes := []byte(strings.TrimSpace(input.DictionaryText))
	computed := sha256.Sum256(payloadBytes)
	computedSHA := hex.EncodeToString(computed[:])
	catalog := ParseVendorDictionaryCatalog(firstNonEmptyPackKey(input.DictionaryName, input.SourceURL), input.DictionaryText)
	vendor, vendorWarnings := selectExternalVendorDictionary(catalog, input)
	canonicalVendor := NormalizeDictionaryVendorName(DefaultDictionaryReleaseProfileID, firstNonEmptyPackKey(vendor.Name, input.VendorName))
	packKey := externalVendorIntakePackKey(input.IntendedPackKey, canonicalVendor)

	report := ExternalVendorIntakeReport{
		SchemaVersion:                 ExternalVendorIntakeSchemaVersion,
		FeatureID:                     ExternalVendorIntakeFeatureID,
		Status:                        ExternalVendorIntakeSoftwareReady,
		GeneratedAt:                   generatedAt,
		DictionaryReleaseProfileID:    DefaultDictionaryReleaseProfileID,
		SourceRelease:                 FreeRADIUSRegistryRelease,
		SourceSHA256:                  registry.SourceSHA256,
		ReleaseCertificationChecklist: "docs/nas-0073-release-certification-checklist.md",
		Vendor: ExternalVendorIntakeVendor{
			Name:                  firstNonEmptyPackKey(input.VendorName, vendor.Name),
			CanonicalName:         canonicalVendor,
			PEN:                   input.PEN,
			IntendedPackKey:       packKey,
			ProductFamilies:       input.ProductFamilies,
			DictionaryName:        input.DictionaryName,
			InPinnedCorpus:        externalVendorInPinnedCorpus(registry, canonicalVendor, input.PEN),
			RuntimeExtensionKnown: externalVendorRuntimeExtensionKnown(registry, canonicalVendor, input.PEN),
			OutOfCorpus:           true,
		},
		Provenance: ExternalVendorIntakeProvenance{
			SourceURL:        input.SourceURL,
			SourceSHA256:     strings.ToLower(input.SourceSHA256),
			ComputedSHA256:   computedSHA,
			LicenseID:        input.LicenseID,
			LicenseReference: input.LicenseReference,
			UpstreamVersion:  input.UpstreamVersion,
			RetrievedAt:      input.RetrievedAt,
			Submitter:        input.Submitter,
			LicenseState:     "accepted",
			ProvenanceState:  "verified",
			PENState:         "verified",
			SemanticState:    "classified",
		},
		Warnings: append([]string(nil), vendorWarnings...),
		Notes: []string{
			"External dictionary attributes are classified and made visible as software-ready intake records only; hardware behavior remains external certification.",
			"Known runtime-extension attributes can be matched during intake, but the report does not claim inclusion in the pinned FreeRADIUS corpus.",
			"Secret-like attribute names are redacted and stored as hash-only evidence.",
		},
	}
	report.Blockers = append(report.Blockers, externalVendorRequestBlockers(input, computedSHA, catalog, vendor)...)
	if report.Vendor.InPinnedCorpus {
		report.Blockers = append(report.Blockers, fmt.Sprintf("vendor %s/PEN %d already exists in the pinned FreeRADIUS %s corpus; use the in-corpus vendor pack workflow instead", canonicalVendor, input.PEN, FreeRADIUSRegistryRelease))
		report.Vendor.OutOfCorpus = false
	}
	if vendor.ID > 0 && uint32(vendor.ID) != input.PEN {
		report.Blockers = append(report.Blockers, fmt.Sprintf("dictionary PEN %d does not match requested PEN %d", vendor.ID, input.PEN))
	}
	if len(catalog.Warnings) > 0 {
		for _, warning := range catalog.Warnings {
			report.Warnings = append(report.Warnings, fmt.Sprintf("dictionary line %d: %s", warning.Line, warning.Message))
		}
	}

	report.Records = buildExternalVendorIntakeRecords(vendor, canonicalVendor, input.PEN, packKey)
	applyExternalVendorIntakeStates(input, vendor, &report)
	report.ProductScopes = externalVendorIntakeScopes(report.Vendor, input)
	report.Summary = summarizeExternalVendorIntake(report)
	report.Summary.Fingerprint = externalVendorIntakeFingerprint(report)
	report.Status = externalVendorIntakeStatus(report)
	report.Summary.SoftwareCompletionPercent = externalVendorIntakeCompletion(report.Summary.SoftwareReadyAttributes, report.Summary.AttributeCount)
	return report
}

func applyExternalVendorIntakeStates(input ExternalVendorIntakeRequest, vendor VendorDictionary, report *ExternalVendorIntakeReport) {
	if report == nil {
		return
	}
	if !allowedExternalVendorLicense(input.LicenseID) || strings.TrimSpace(input.LicenseReference) == "" {
		report.Provenance.LicenseState = "blocked"
	}
	if strings.TrimSpace(input.SourceURL) == "" ||
		!validExternalVendorSourceURL(input.SourceURL) ||
		strings.TrimSpace(input.SourceSHA256) == "" ||
		!validHexSHA256(input.SourceSHA256) ||
		!strings.EqualFold(input.SourceSHA256, report.Provenance.ComputedSHA256) {
		report.Provenance.ProvenanceState = "blocked"
	}
	if _, err := parseExternalVendorRetrievedAt(input.RetrievedAt); err != nil {
		report.Provenance.ProvenanceState = "blocked"
	}
	if input.PEN == 0 ||
		input.PEN == uint32(AegisNASPlaceholderVendorID) ||
		report.Vendor.InPinnedCorpus ||
		(vendor.ID > 0 && uint32(vendor.ID) != input.PEN) {
		report.Provenance.PENState = "blocked"
	}
	if len(vendor.Attributes) == 0 || len(externalVendorDictionaryBlockers(vendor)) > 0 {
		report.Provenance.SemanticState = "blocked"
	}
}

func ValidateExternalVendorIntakeReport(report ExternalVendorIntakeReport) error {
	if report.SchemaVersion != ExternalVendorIntakeSchemaVersion {
		return fmt.Errorf("external vendor intake schema version %d is unsupported", report.SchemaVersion)
	}
	if report.FeatureID != ExternalVendorIntakeFeatureID {
		return fmt.Errorf("external vendor intake feature id %q is invalid", report.FeatureID)
	}
	if report.Status != ExternalVendorIntakeSoftwareReady {
		return fmt.Errorf("external vendor intake is not software ready: %s", strings.Join(report.Blockers, "; "))
	}
	if strings.TrimSpace(report.DictionaryReleaseProfileID) == "" || strings.TrimSpace(report.SourceSHA256) == "" {
		return fmt.Errorf("external vendor intake release profile and source hash are required")
	}
	if strings.TrimSpace(report.Vendor.CanonicalName) == "" || report.Vendor.PEN == 0 || !report.Vendor.OutOfCorpus || report.Vendor.InPinnedCorpus {
		return fmt.Errorf("external vendor intake requires an out-of-corpus vendor and non-zero PEN")
	}
	if strings.TrimSpace(report.Provenance.SourceURL) == "" || strings.TrimSpace(report.Provenance.SourceSHA256) == "" || strings.TrimSpace(report.Provenance.ComputedSHA256) == "" {
		return fmt.Errorf("external vendor intake provenance hashes are required")
	}
	if !strings.EqualFold(report.Provenance.SourceSHA256, report.Provenance.ComputedSHA256) {
		return fmt.Errorf("external vendor intake source hash mismatch")
	}
	if report.Provenance.LicenseState != "accepted" || report.Provenance.ProvenanceState != "verified" || report.Provenance.PENState != "verified" || report.Provenance.SemanticState != "classified" {
		return fmt.Errorf("external vendor intake provenance, license, PEN, and semantic states must be verified")
	}
	if report.Summary.AttributeCount == 0 || report.Summary.AttributeCount > ExternalVendorIntakeMaxAttributes {
		return fmt.Errorf("external vendor intake attribute count %d is invalid", report.Summary.AttributeCount)
	}
	if report.Summary.SoftwareBlockedAttributes != 0 || report.Summary.SoftwareReadyAttributes != report.Summary.AttributeCount {
		return fmt.Errorf("external vendor intake software coverage is incomplete")
	}
	if report.Summary.ExternalCertificationRequirements != report.Summary.AttributeCount || report.Summary.ReadyForExternalValidation != report.Summary.AttributeCount {
		return fmt.Errorf("external vendor intake must keep every attribute ready for external certification")
	}
	if strings.TrimSpace(report.Summary.Fingerprint) == "" {
		return fmt.Errorf("external vendor intake fingerprint is required")
	}
	seen := map[string]struct{}{}
	for _, record := range report.Records {
		if strings.TrimSpace(record.ID) == "" {
			return fmt.Errorf("external vendor intake record id is required")
		}
		if _, exists := seen[record.ID]; exists {
			return fmt.Errorf("external vendor intake record %q is duplicated", record.ID)
		}
		seen[record.ID] = struct{}{}
		if record.SoftwareState != ExternalVendorIntakeSoftwareReady || !record.ReadyForExternalValidation || !record.ExternalValidationRequired {
			return fmt.Errorf("external vendor intake record %q has inconsistent readiness flags", record.ID)
		}
		if strings.TrimSpace(record.WireKey) == "" || strings.TrimSpace(record.WireType) == "" || len(record.Directions) == 0 {
			return fmt.Errorf("external vendor intake record %q is missing wire metadata", record.ID)
		}
		if strings.TrimSpace(record.PacketProcessing) == "" || strings.TrimSpace(record.PolicyEngine) == "" || strings.TrimSpace(record.Storage) == "" {
			return fmt.Errorf("external vendor intake record %q is missing implementation state", record.ID)
		}
		if record.Number > 0 && record.Number <= 255 && strings.TrimSpace(record.DecodeKind) == "" {
			return fmt.Errorf("external vendor intake record %q is missing decode metadata", record.ID)
		}
	}
	return nil
}

func ExternalVendorIntakeRuntimeMappings(report ExternalVendorIntakeReport) ([]AttributeRuntimeMapping, error) {
	if err := ValidateExternalVendorIntakeReport(report); err != nil {
		return nil, err
	}
	mappings := make([]AttributeRuntimeMapping, 0, report.Summary.RuntimeDecodableAttributes)
	for _, record := range report.Records {
		if record.Number == 0 || record.Number > 255 {
			continue
		}
		mappings = append(mappings, AttributeRuntimeMapping{
			PackKey:   record.PackKey,
			VendorID:  record.PEN,
			Type:      byte(record.Number),
			Attribute: record.Attribute,
			Semantic:  firstNonEmptyPackKey(record.DecodeSemantic, firstRegistrySemantic(record.Semantic)),
			Kind:      record.DecodeKind,
			Scale:     record.DecodeScale,
		})
	}
	return mappings, nil
}

func normalizeExternalVendorIntakeRequest(input ExternalVendorIntakeRequest) ExternalVendorIntakeRequest {
	input.VendorName = strings.TrimSpace(input.VendorName)
	input.IntendedPackKey = strings.TrimSpace(input.IntendedPackKey)
	input.DictionaryName = strings.TrimSpace(input.DictionaryName)
	input.DictionaryText = strings.TrimSpace(input.DictionaryText)
	input.SourceURL = strings.TrimSpace(input.SourceURL)
	input.SourceSHA256 = strings.ToLower(strings.TrimSpace(input.SourceSHA256))
	input.LicenseID = strings.TrimSpace(input.LicenseID)
	input.LicenseReference = strings.TrimSpace(input.LicenseReference)
	input.UpstreamVersion = strings.TrimSpace(input.UpstreamVersion)
	input.RetrievedAt = strings.TrimSpace(input.RetrievedAt)
	input.Submitter = strings.TrimSpace(input.Submitter)
	input.ProductFamilies = normalizeExternalVendorStringList(input.ProductFamilies)
	input.ReviewNotes = normalizeExternalVendorStringList(input.ReviewNotes)
	return input
}

func selectExternalVendorDictionary(catalog VendorDictionaryCatalog, input ExternalVendorIntakeRequest) (VendorDictionary, []string) {
	warnings := []string{}
	if vendor, ok := catalog.VendorByName(input.VendorName); ok {
		return vendor, warnings
	}
	if input.PEN > 0 {
		for _, vendor := range catalog.Vendors {
			if uint32(vendor.ID) == input.PEN {
				warnings = append(warnings, fmt.Sprintf("selected dictionary vendor %s by PEN %d because vendor_name %q did not exactly match", vendor.Name, input.PEN, input.VendorName))
				return vendor, warnings
			}
		}
	}
	if len(catalog.Vendors) == 1 {
		warnings = append(warnings, fmt.Sprintf("selected only dictionary vendor %s because vendor_name %q was not found", catalog.Vendors[0].Name, input.VendorName))
		return catalog.Vendors[0], warnings
	}
	return VendorDictionary{}, warnings
}

func externalVendorRequestBlockers(input ExternalVendorIntakeRequest, computedSHA string, catalog VendorDictionaryCatalog, vendor VendorDictionary) []string {
	blockers := []string{}
	if strings.TrimSpace(input.VendorName) == "" {
		blockers = append(blockers, "vendor_name is required")
	}
	if input.PEN == 0 || input.PEN == uint32(AegisNASPlaceholderVendorID) {
		blockers = append(blockers, "a non-placeholder IANA Private Enterprise Number is required")
	}
	if len(input.DictionaryText) == 0 {
		blockers = append(blockers, "dictionary_text is required")
	}
	if len([]byte(input.DictionaryText)) > ExternalVendorIntakeMaxBytes {
		blockers = append(blockers, fmt.Sprintf("dictionary_text exceeds %d bytes", ExternalVendorIntakeMaxBytes))
	}
	if strings.TrimSpace(input.SourceURL) == "" {
		blockers = append(blockers, "source_url is required")
	} else if !validExternalVendorSourceURL(input.SourceURL) {
		blockers = append(blockers, "source_url must be an HTTPS, Git HTTPS, or URN SHA-256 authority")
	}
	if strings.TrimSpace(input.SourceSHA256) == "" {
		blockers = append(blockers, "source_sha256 is required")
	} else if !validHexSHA256(input.SourceSHA256) {
		blockers = append(blockers, "source_sha256 must be a 64-character hex SHA-256")
	} else if !strings.EqualFold(input.SourceSHA256, computedSHA) {
		blockers = append(blockers, "source_sha256 does not match dictionary_text")
	}
	if !allowedExternalVendorLicense(input.LicenseID) {
		blockers = append(blockers, "license_id must be an accepted permissive license or a documented proprietary grant")
	}
	if strings.TrimSpace(input.LicenseReference) == "" {
		blockers = append(blockers, "license_reference is required")
	}
	if strings.TrimSpace(input.UpstreamVersion) == "" {
		blockers = append(blockers, "upstream_version is required")
	}
	if _, err := parseExternalVendorRetrievedAt(input.RetrievedAt); err != nil {
		blockers = append(blockers, "retrieved_at must be RFC3339 or YYYY-MM-DD")
	}
	if strings.TrimSpace(input.IntendedPackKey) != "" && !validExternalVendorPackKey(input.IntendedPackKey) {
		blockers = append(blockers, "intended_pack_key must use lower-case letters, numbers, and dashes")
	}
	if len(catalog.Vendors) == 0 {
		blockers = append(blockers, "dictionary must contain a VENDOR directive")
	}
	if strings.TrimSpace(vendor.Name) == "" {
		blockers = append(blockers, "dictionary vendor could not be matched to the requested vendor_name or PEN")
	}
	if vendor.ID == 0 {
		blockers = append(blockers, "dictionary vendor must include a numeric PEN")
	}
	if len(vendor.Attributes) == 0 {
		blockers = append(blockers, "dictionary vendor must include at least one ATTRIBUTE")
	}
	if len(vendor.Attributes) > ExternalVendorIntakeMaxAttributes {
		blockers = append(blockers, fmt.Sprintf("dictionary vendor includes %d attributes, limit is %d", len(vendor.Attributes), ExternalVendorIntakeMaxAttributes))
	}
	blockers = append(blockers, externalVendorDictionaryBlockers(vendor)...)
	return dedupeExternalVendorMessages(blockers)
}

func buildExternalVendorIntakeRecords(vendor VendorDictionary, canonicalVendor string, pen uint32, packKey string) []ExternalVendorIntakeAttribute {
	records := make([]ExternalVendorIntakeAttribute, 0, len(vendor.Attributes))
	for _, attr := range vendor.Attributes {
		entry := AttributeRegistryEntry{
			Source:             "external-authoritative",
			ReleaseProfileID:   DefaultDictionaryReleaseProfileID,
			Vendor:             canonicalVendor,
			PEN:                pen,
			Attribute:          NormalizeDictionaryAttributeName(DefaultDictionaryReleaseProfileID, canonicalVendor, attr.Name),
			Number:             uint32(externalVendorNonNegativeInt(attr.Number)),
			OID:                strings.TrimSpace(attr.OID),
			WireType:           strings.ToLower(strings.TrimSpace(attr.Type)),
			EnumeratedValues:   len(attr.Values),
			DictionaryStatus:   "partial",
			PackKey:            packKey,
			SemanticProvenance: "external-intake:" + ExternalVendorIntakeFeatureID,
		}
		if entry.Number > 0 {
			entry.WireKey = fmt.Sprintf("vsa:%d:%d", entry.PEN, entry.Number)
		} else {
			entry.WireKey = fmt.Sprintf("vsa:%d:%s", entry.PEN, entry.OID)
		}
		entry.OIDPath = attributeRegistryOIDPath(entry.Number, entry.OID)
		entry.WireCodec = attributeRegistryWireCodec(entry)
		entry.CapabilityFamily = longTailNamespaceCapability(entry)
		semantic := longTailNamespaceSemantic(entry)
		entry.Semantic = semantic
		entry.Directions = longTailNamespaceDirections(entry, semantic)
		entry.Functionality = externalVendorFunctionality(entry)
		entry.DecodeKind, entry.DecodeSemantic, entry.DecodeScale = longTailNamespaceDecoder(entry, semantic)
		class := longTailNamespaceImplementationClass(entry, semantic)

		record := ExternalVendorIntakeAttribute{
			ID:                         externalVendorRecordID(entry),
			Vendor:                     entry.Vendor,
			PEN:                        entry.PEN,
			PackKey:                    packKey,
			Attribute:                  entry.Attribute,
			Number:                     entry.Number,
			OID:                        entry.OID,
			WireKey:                    entry.WireKey,
			WireType:                   entry.WireType,
			WireCodec:                  entry.WireCodec,
			EnumeratedValues:           len(attr.Values),
			Capability:                 entry.CapabilityFamily,
			Semantic:                   semantic,
			Directions:                 entry.Directions,
			DecodeKind:                 entry.DecodeKind,
			DecodeSemantic:             entry.DecodeSemantic,
			DecodeScale:                entry.DecodeScale,
			Functionality:              entry.Functionality,
			ImplementationClass:        class,
			PacketProcessing:           longTailNamespacePacketProcessing(entry, class),
			PolicyEngine:               longTailNamespacePolicyState(semantic, class),
			Enforcement:                longTailNamespaceEnforcementState(semantic, class),
			Storage:                    longTailNamespaceStorageState(class),
			APIUI:                      "external_vendor_intake_preview_history_matrix_attribute_drilldown_support_bundle_and_release_checklist",
			Monitoring:                 "external_vendor_intake_counters_hash_provenance_pen_collisions_parse_warnings_secret_redaction_and_release_scope",
			SoftwareState:              ExternalVendorIntakeSoftwareReady,
			ExternalValidationRequired: true,
			ReadyForExternalValidation: true,
			ClaimState:                 "software_ready_external_required",
			Notes:                      externalVendorRecordNotes(entry, class),
		}
		if !ValidVendorDictionaryAttributeType(record.WireType) {
			record.SoftwareState = ExternalVendorIntakeSoftwareBlock
			record.ReadyForExternalValidation = false
			record.Blockers = append(record.Blockers, "unsupported FreeRADIUS dictionary wire type")
		}
		if record.Number == 0 && strings.TrimSpace(record.OID) == "" {
			record.SoftwareState = ExternalVendorIntakeSoftwareBlock
			record.ReadyForExternalValidation = false
			record.Blockers = append(record.Blockers, "attribute requires a numeric type or OID")
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Number != records[j].Number {
			return records[i].Number < records[j].Number
		}
		if records[i].OID != records[j].OID {
			return records[i].OID < records[j].OID
		}
		return records[i].Attribute < records[j].Attribute
	})
	return records
}

func summarizeExternalVendorIntake(report ExternalVendorIntakeReport) ExternalVendorIntakeSummary {
	summary := ExternalVendorIntakeSummary{
		VendorCount:       1,
		ProductScopeCount: len(report.ProductScopes),
		AttributeCount:    len(report.Records),
		WarningCount:      len(report.Warnings),
		BlockerCount:      len(report.Blockers),
	}
	for _, record := range report.Records {
		if record.Number > 0 && record.Number <= 255 && record.WireCodec.TypeOctets > 0 {
			summary.RuntimeDecodableAttributes++
		} else {
			summary.MetadataOnlyAttributes++
		}
		if record.ImplementationClass == "typed_passthrough" || record.ImplementationClass == "typed_binary_evidence" {
			summary.TypedPassthroughMappings++
		} else if firstRegistrySemantic(record.Semantic) != VendorSemanticPolicyTag {
			summary.NativeSemanticMappings++
		} else {
			summary.TypedPassthroughMappings++
		}
		if record.ImplementationClass == "redacted_secret_evidence" {
			summary.SensitiveRedactedMappings++
		}
		summary.EnumeratedValueCount += record.EnumeratedValues
		if len(record.Blockers) == 0 && record.SoftwareState == ExternalVendorIntakeSoftwareReady {
			summary.SoftwareReadyAttributes++
		} else {
			summary.SoftwareBlockedAttributes++
			summary.BlockerCount += len(record.Blockers)
		}
		if record.ReadyForExternalValidation {
			summary.ReadyForExternalValidation++
		}
		if record.ExternalValidationRequired {
			summary.ExternalCertificationRequirements++
		}
		summary.WarningCount += len(record.Warnings)
	}
	if summary.AttributeCount == 0 {
		summary.VendorCount = 0
	}
	return summary
}

func externalVendorIntakeStatus(report ExternalVendorIntakeReport) string {
	if len(report.Blockers) > 0 || report.Summary.SoftwareBlockedAttributes > 0 || report.Summary.AttributeCount == 0 {
		return ExternalVendorIntakeSoftwareBlock
	}
	return ExternalVendorIntakeSoftwareReady
}

func externalVendorIntakeCompletion(ready, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(ready) * 100 / float64(total)
}

func externalVendorIntakeScopes(vendor ExternalVendorIntakeVendor, input ExternalVendorIntakeRequest) []ExternalVendorIntakeScope {
	products := append([]string(nil), vendor.ProductFamilies...)
	if len(products) == 0 {
		products = []string{"external NAS, AP, switch, gateway, controller, or subscriber edge firmware family"}
	}
	dictionary := firstNonEmptyPackKey(input.DictionaryName, input.SourceURL, "authoritative external vendor dictionary")
	return []ExternalVendorIntakeScope{
		{Key: vendor.IntendedPackKey, Label: "External Dictionary Intake", Vendors: []string{vendor.CanonicalName}, Products: products, Dictionary: dictionary, SoftwareState: ExternalVendorIntakeSoftwareReady, ExternalState: ExternalVendorIntakeExternalScope, Notes: []string{"Parser, provenance, hash, license, PEN, semantic classification, packet safety, and evidence storage are handled in software."}},
		{Key: vendor.IntendedPackKey, Label: "Runtime Packet Safety", Vendors: []string{vendor.CanonicalName}, Products: products, Dictionary: dictionary, SoftwareState: ExternalVendorIntakeSoftwareReady, ExternalState: ExternalVendorIntakeExternalScope, Notes: []string{"Numbered byte-sized VSAs can use bounded generic decoding; OID or extended rows remain metadata-only until a focused adapter exists."}},
		{Key: vendor.IntendedPackKey, Label: "Release Certification Boundary", Vendors: []string{vendor.CanonicalName}, Products: []string{"hardware packet captures", "FreeRADIUS Linux interoperability", "HA failover", "performance and soak"}, Dictionary: dictionary, SoftwareState: ExternalVendorIntakeSoftwareReady, ExternalState: ExternalVendorIntakeExternalScope, Notes: []string{"No vendor hardware claim is closed by intake alone."}},
	}
}

func externalVendorDictionaryBlockers(vendor VendorDictionary) []string {
	blockers := []string{}
	seenNames := map[string]struct{}{}
	seenNumbers := map[int]string{}
	seenOIDs := map[string]string{}
	for _, attr := range vendor.Attributes {
		nameKey := strings.ToLower(strings.TrimSpace(attr.Name))
		if nameKey == "" {
			blockers = append(blockers, "dictionary contains an ATTRIBUTE with an empty name")
		} else if _, exists := seenNames[nameKey]; exists {
			blockers = append(blockers, "dictionary contains duplicate ATTRIBUTE name "+attr.Name)
		}
		seenNames[nameKey] = struct{}{}
		if attr.Number > 0 {
			if previous, exists := seenNumbers[attr.Number]; exists {
				blockers = append(blockers, fmt.Sprintf("dictionary attributes %s and %s share numeric type %d", previous, attr.Name, attr.Number))
			}
			seenNumbers[attr.Number] = attr.Name
		}
		if strings.TrimSpace(attr.OID) != "" {
			oid := strings.TrimSpace(attr.OID)
			if previous, exists := seenOIDs[oid]; exists {
				blockers = append(blockers, fmt.Sprintf("dictionary attributes %s and %s share OID %s", previous, attr.Name, oid))
			}
			seenOIDs[oid] = attr.Name
		}
		if !ValidVendorDictionaryAttributeType(attr.Type) {
			blockers = append(blockers, "dictionary attribute "+attr.Name+" has unsupported wire type "+attr.Type)
		}
		if attr.Number > 255 {
			blockers = append(blockers, fmt.Sprintf("dictionary attribute %s uses numeric type %d; runtime byte-sized VSA decoding supports 1..255 and requires a focused adapter for larger encodings", attr.Name, attr.Number))
		}
	}
	return dedupeExternalVendorMessages(blockers)
}

func externalVendorFunctionality(entry AttributeRegistryEntry) string {
	return fmt.Sprintf("%s carries %s context for out-of-corpus vendor %s/PEN %d; AegisNAS classifies it with bounded packet evidence, neutral semantics, secret redaction where required, and an explicit release certification boundary.",
		entry.Attribute,
		strings.ReplaceAll(firstRegistrySemantic(entry.Semantic), ".", " "),
		entry.Vendor,
		entry.PEN,
	)
}

func externalVendorRecordNotes(entry AttributeRegistryEntry, class string) []string {
	notes := []string{"External vendor-device behavior remains in docs/nas-0073-release-certification-checklist.md."}
	if entry.Number == 0 || entry.Number > 255 {
		notes = append(notes, "This row is represented as typed metadata and excluded from byte-sized runtime decoder claims.")
	}
	if class == "redacted_secret_evidence" {
		notes = append(notes, "Values are never persisted in cleartext; evidence records must store a redacted marker and digest only.")
	}
	if class == "typed_passthrough" || class == "typed_binary_evidence" {
		notes = append(notes, "No focused vendor-specific enforcement claim is made for this row during intake.")
	}
	return notes
}

func externalVendorRecordID(entry AttributeRegistryEntry) string {
	if entry.Number > 0 {
		return fmt.Sprintf("nas-0073:%d:%d:%s", entry.PEN, entry.Number, strings.ToLower(entry.Attribute))
	}
	return fmt.Sprintf("nas-0073:%d:%s:%s", entry.PEN, strings.ToLower(entry.OID), strings.ToLower(entry.Attribute))
}

func externalVendorIntakeFingerprint(report ExternalVendorIntakeReport) string {
	parts := []string{
		ExternalVendorIntakeFeatureID,
		report.DictionaryReleaseProfileID,
		report.SourceSHA256,
		report.Vendor.CanonicalName,
		strconv.FormatUint(uint64(report.Vendor.PEN), 10),
		report.Vendor.IntendedPackKey,
		report.Provenance.ComputedSHA256,
		report.Provenance.LicenseID,
		report.Provenance.UpstreamVersion,
	}
	for _, record := range report.Records {
		parts = append(parts, strings.Join([]string{
			record.ID,
			record.WireKey,
			record.WireType,
			record.Capability,
			record.Semantic,
			record.ImplementationClass,
			strings.Join(record.Directions, ","),
		}, "|"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func externalVendorInPinnedCorpus(registry *AttributeRegistry, vendor string, pen uint32) bool {
	if registry == nil || pen == 0 {
		return false
	}
	vendorKey := normalizedDictionaryReleaseKey(vendor)
	for _, entry := range registry.Entries {
		if entry.PEN != pen {
			continue
		}
		if !strings.EqualFold(entry.Source, "freeradius-"+FreeRADIUSRegistryRelease) {
			continue
		}
		if normalizedDictionaryReleaseKey(entry.Vendor) == vendorKey {
			return true
		}
	}
	return false
}

func externalVendorRuntimeExtensionKnown(registry *AttributeRegistry, vendor string, pen uint32) bool {
	if registry == nil || pen == 0 {
		return false
	}
	vendorKey := normalizedDictionaryReleaseKey(vendor)
	for _, entry := range registry.Entries {
		if entry.PEN == pen && normalizedDictionaryReleaseKey(entry.Vendor) == vendorKey && !strings.EqualFold(entry.Source, "freeradius-"+FreeRADIUSRegistryRelease) {
			return true
		}
	}
	return false
}

func externalVendorIntakePackKey(input, vendor string) string {
	key := strings.ToLower(strings.TrimSpace(input))
	if key == "" {
		key = "external-" + externalVendorSlug(vendor)
	}
	if validExternalVendorPackKey(key) {
		return key
	}
	return "external-" + externalVendorSlug(vendor)
}

func externalVendorSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	builder := strings.Builder{}
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		out = "vendor"
	}
	if len(out) > 55 {
		out = strings.Trim(out[:55], "-")
	}
	return out
}

func validExternalVendorPackKey(value string) bool {
	return externalVendorPackKeyPattern.MatchString(strings.TrimSpace(value))
}

func validExternalVendorSourceURL(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "git+https://") || strings.HasPrefix(value, "urn:sha256:")
}

func validHexSHA256(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func allowedExternalVendorLicense(value string) bool {
	switch strings.TrimSpace(value) {
	case "BSD-2-Clause", "BSD-3-Clause", "MIT", "Apache-2.0", "ISC", "Proprietary-Allowed-With-Grant":
		return true
	default:
		return false
	}
}

func parseExternalVendorRetrievedAt(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("retrieved_at is required")
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, nil
	}
	return time.Parse("2006-01-02", value)
}

func normalizeExternalVendorStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func dedupeExternalVendorMessages(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func externalVendorSupportedWireTypes() []string {
	types := []string{"abinary", "bool", "byte", "combo-ip", "date", "ether", "ethernet", "extended", "float32", "float64", "group", "ifid", "int8", "int16", "int32", "int64", "integer", "integer64", "ipaddr", "ipv4addr", "ipv4prefix", "ipv6addr", "ipv6prefix", "octet", "octets", "short", "signed", "string", "struct", "text", "time_delta", "tlv", "uint8", "uint16", "uint32", "uint64", "union", "vendor", "vsa"}
	sort.Strings(types)
	return types
}

func externalVendorNonNegativeInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}
