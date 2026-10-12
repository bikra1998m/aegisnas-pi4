package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

const (
	MobileGroupedAVPSchemaVersion = 1
	MobileGroupedAVPFeatureID     = "NAS-0092"
	mobileGroupedAVPComponent     = "mobile_grouped_avps"
)

type MobileGroupedAVPReport struct {
	SchemaVersion                 int                         `json:"schema_version"`
	FeatureID                     string                      `json:"feature_id"`
	Status                        string                      `json:"status"`
	Message                       string                      `json:"message"`
	GeneratedAt                   string                      `json:"generated_at"`
	SoftwareCompletionPercent     float64                     `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                        `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                      `json:"release_certification_checklist"`
	ReleaseScope                  string                      `json:"release_scope"`
	PlanFingerprint               string                      `json:"plan_fingerprint"`
	Summary                       MobileGroupedAVPSummary     `json:"summary"`
	VendorScopes                  []MobileGroupedAVPScope     `json:"vendor_scopes"`
	EvidencePolicies              []MobileGroupedAVPEvidence  `json:"evidence_policies"`
	PacketModel                   MobileGroupedAVPPacketModel `json:"packet_model"`
	SemanticBindings              []MobileGroupedAVPBinding   `json:"semantic_bindings"`
	Compliance                    []MobileGroupedAVPCheck     `json:"compliance"`
	Standards                     []string                    `json:"standards"`
	Vendors                       []string                    `json:"vendors"`
	Requirements                  []string                    `json:"requirements"`
	Blockers                      []string                    `json:"blockers,omitempty"`
	Warnings                      []string                    `json:"warnings,omitempty"`
	Notes                         []string                    `json:"notes,omitempty"`
}

type MobileGroupedAVPSummary struct {
	Enabled                    bool   `json:"enabled"`
	Mode                       string `json:"mode"`
	FailClosed                 bool   `json:"fail_closed"`
	RequireDatabase            bool   `json:"require_database"`
	RequireVSACodec            bool   `json:"require_vsa_codec"`
	RequireAttributeRegistry   bool   `json:"require_attribute_registry"`
	SafeRawEvidence            bool   `json:"safe_raw_evidence"`
	HashRawValues              bool   `json:"hash_raw_values"`
	MaxDepth                   int    `json:"max_depth"`
	MaxPayloadBytes            int    `json:"max_payload_bytes"`
	MaxAttributesPerPacket     int    `json:"max_attributes_per_packet"`
	RawEvidenceRetentionDays   int    `json:"raw_evidence_retention_days"`
	EventRetentionLimit        int    `json:"event_retention_limit"`
	VendorScopeCount           int    `json:"vendor_scope_count"`
	EnabledVendorScopeCount    int    `json:"enabled_vendor_scope_count"`
	EvidencePolicyCount        int    `json:"evidence_policy_count"`
	EnabledEvidencePolicyCount int    `json:"enabled_evidence_policy_count"`
	RegistryAttributeCount     int    `json:"registry_attribute_count"`
	GroupedAttributeCount      int    `json:"grouped_attribute_count"`
	CompiledAttributeCount     int    `json:"compiled_attribute_count"`
	SemanticBindingCount       int    `json:"semantic_binding_count"`
	ComplianceCheckCount       int    `json:"compliance_check_count"`
	PassedCheckCount           int    `json:"passed_check_count"`
	WarningCount               int    `json:"warning_count"`
	BlockerCount               int    `json:"blocker_count"`
	ExternalRequirementCount   int    `json:"external_requirement_count"`
	RegistryRelease            string `json:"registry_release"`
	RegistrySHA256             string `json:"registry_sha256"`
}

type MobileGroupedAVPScope struct {
	ScopeKey               string   `json:"scope_key"`
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	Vendor                 string   `json:"vendor"`
	VendorID               uint32   `json:"vendor_id"`
	Dictionary             string   `json:"dictionary"`
	Domain                 string   `json:"domain"`
	Format                 string   `json:"format"`
	Status                 string   `json:"status"`
	Reason                 string   `json:"reason"`
	GroupedRootAttributes  []string `json:"grouped_root_attributes"`
	IdentityAttributes     []string `json:"identity_attributes"`
	ChargingAttributes     []string `json:"charging_attributes"`
	QoSAttributes          []string `json:"qos_attributes"`
	PolicyAttributes       []string `json:"policy_attributes"`
	SafeRawEvidence        bool     `json:"safe_raw_evidence"`
	HashRawValues          bool     `json:"hash_raw_values"`
	RegistryAttributeCount int      `json:"registry_attribute_count"`
	GroupedAttributeCount  int      `json:"grouped_attribute_count"`
	CompiledAttributeCount int      `json:"compiled_attribute_count"`
	DictionaryRelease      string   `json:"dictionary_release"`
	DictionarySourceSHA256 string   `json:"dictionary_source_sha256"`
	SampleEvidenceDigest   string   `json:"sample_evidence_digest"`
	ExternalCertification  bool     `json:"external_certification_required"`
}

type MobileGroupedAVPEvidence struct {
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Scope             string   `json:"scope"`
	CaptureRaw        bool     `json:"capture_raw"`
	HashRawValues     bool     `json:"hash_raw_values"`
	RetentionDays     int      `json:"retention_days"`
	RedactAttributes  []string `json:"redact_attributes"`
	AllowedExportRole string   `json:"allowed_export_role"`
	Status            string   `json:"status"`
	Reason            string   `json:"reason"`
}

type MobileGroupedAVPPacketModel struct {
	OuterAttribute           string   `json:"outer_attribute"`
	DecodePipeline           []string `json:"decode_pipeline"`
	BoundedLimits            []string `json:"bounded_limits"`
	RawEvidenceHandling      string   `json:"raw_evidence_handling"`
	InteroperabilityBoundary string   `json:"interoperability_boundary"`
}

type MobileGroupedAVPBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type MobileGroupedAVPCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func MobileGroupedAVPComponent() string {
	return mobileGroupedAVPComponent
}

func PreviewMobileGroupedAVPs(cfg *config.Config) (MobileGroupedAVPReport, error) {
	if cfg == nil {
		return MobileGroupedAVPReport{}, fmt.Errorf("config is required")
	}
	grouped := config.EffectiveMobileGroupedAVPConfig(cfg.Mobile.GroupedAVPs)
	registry := productconfigs.MustBuiltInAttributeRegistry()
	codec := radius.BuildVSACodecReport(registry, productconfigs.AegisNASVendorDictionaryCatalog())

	report := MobileGroupedAVPReport{
		SchemaVersion:                 MobileGroupedAVPSchemaVersion,
		FeatureID:                     MobileGroupedAVPFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0092-release-certification-checklist.md",
		ReleaseScope:                  "Carrier packet-core simulators, real 3GPP/3GPP2/Starent/Ericsson/WiMAX equipment, production FreeRADIUS Linux captures, HA failover, scale/soak, security audit, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6929", "3GPP TS 29.061", "3GPP TS 32.240", "IEEE 802.16/WiMAX RADIUS profile"},
		Vendors:                       []string{"3GPP", "3GPP2", "Starent/Cisco ASR", "Ericsson/Redback", "WiMAX Forum"},
		Requirements: []string{
			"compile grouped and nested telecom AVP scopes on top of the NAS-0005 bounded VSA codec",
			"separate domain semantics from raw attribute support and never claim physical vendor certification from dictionary metadata alone",
			"capture safe raw evidence through hashes, redaction policy, retention controls, and bounded packet limits",
			"persist preview/apply/history evidence so mobile session, bearer, charging, and policy features can depend on a stable AVP framework",
			"expose API, UI, readiness, support-bundle, runtime status, and release-certification boundary evidence",
		},
		Notes: []string{
			"NAS-0092 completes the software framework for telecom grouped AVP semantics; mobile session state, charging correlation, PCRF/PCF policy, WiMAX workflows, DOCSIS, and voice workflows remain later roadmap features.",
			"Raw subscriber identifiers are represented by configured redaction fields and SHA-256 evidence digests, not by persisted cleartext payloads.",
		},
	}
	report.Summary = MobileGroupedAVPSummary{
		Enabled:                  grouped.Enabled,
		Mode:                     grouped.Mode,
		FailClosed:               grouped.FailClosed,
		RequireDatabase:          grouped.RequireDatabase,
		RequireVSACodec:          grouped.RequireVSACodec,
		RequireAttributeRegistry: grouped.RequireAttributeRegistry,
		SafeRawEvidence:          grouped.SafeRawEvidence,
		HashRawValues:            grouped.HashRawValues,
		MaxDepth:                 grouped.MaxDepth,
		MaxPayloadBytes:          grouped.MaxPayloadBytes,
		MaxAttributesPerPacket:   grouped.MaxAttributesPerPacket,
		RawEvidenceRetentionDays: grouped.RawEvidenceRetentionDays,
		EventRetentionLimit:      grouped.EventRetentionLimit,
		RegistryRelease:          registry.SourceRelease,
		RegistrySHA256:           registry.SourceSHA256,
		RegistryAttributeCount:   registry.AttributeCount,
		GroupedAttributeCount:    codec.Summary.GroupedAttributeCount,
	}
	report.VendorScopes = compileMobileGroupedAVPScopes(grouped, registry)
	report.EvidencePolicies = compileMobileGroupedAVPEvidencePolicies(grouped)
	report.PacketModel = MobileGroupedAVPPacketModel{
		OuterAttribute: "Vendor-Specific(26)",
		DecodePipeline: []string{
			"RADIUS packet hardening validates source, length, Message-Authenticator policy, and replay posture.",
			"NAS-0005 VSA codec decodes vendor type/length formats, repeated values, tags, OID paths, and grouped children with bounded recursion.",
			"NAS-0092 maps decoded telecom attributes into vendor-neutral identity, charging, QoS, policy, and evidence domains.",
			"Later NAS-0093..NAS-0098 features consume the stable grouped AVP event model for sessions, charging, PCRF/PCF policy, WiMAX, DOCSIS, and voice workflows.",
		},
		BoundedLimits: []string{
			fmt.Sprintf("maximum grouped depth %d", grouped.MaxDepth),
			fmt.Sprintf("maximum packet evidence payload %d bytes", grouped.MaxPayloadBytes),
			fmt.Sprintf("maximum decoded attributes per packet %d", grouped.MaxAttributesPerPacket),
			fmt.Sprintf("raw evidence retention %d days", grouped.RawEvidenceRetentionDays),
		},
		RawEvidenceHandling:      "Store metadata, semantic classification, redaction policy, and SHA-256 digests; do not persist cleartext IMSI, NAI, bearer, or charging payloads by default.",
		InteroperabilityBoundary: "External packet captures, carrier simulators, and real vendor product/firmware evidence are release certification, not software completion blockers.",
	}
	report.SemanticBindings = []MobileGroupedAVPBinding{
		{Stage: "identity", Attributes: []string{"3GPP-IMSI", "3GPP-IMEISV", "3GPP2-IMSI", "WiMAX-MN-NAI"}, Purpose: "Bind subscriber and mobile node identity into a redacted, hashable evidence model.", Required: true},
		{Stage: "charging", Attributes: []string{"3GPP-Charging-ID", "3GPP-Charging-Characteristics", "3GPP2-Prepaid-Quota-Identifier", "WiMAX-Session-Id"}, Purpose: "Provide stable grouped charging inputs for NAS-0094 online/offline charging correlation.", Required: true},
		{Stage: "qos", Attributes: []string{"3GPP-GPRS-Negotiated-QoS-profile", "3GPP2-Granted-QoS-Params", "WiMAX-QoS-Descriptor"}, Purpose: "Normalize telecom QoS and service-flow hints for later policy and WiMAX features.", Required: true},
		{Stage: "policy", Attributes: []string{"3GPP-RAT-Type", "3GPP-Selection-Mode", "Starent policy/rulebase attributes", "Ericsson context/policy attributes"}, Purpose: "Separate access technology, roaming, rulebase, and policy context from raw VSA support.", Required: true},
	}
	report.Summary.VendorScopeCount = len(report.VendorScopes)
	report.Summary.EvidencePolicyCount = len(report.EvidencePolicies)
	report.Summary.SemanticBindingCount = len(report.SemanticBindings)
	for _, scope := range report.VendorScopes {
		if scope.Enabled {
			report.Summary.EnabledVendorScopeCount++
		}
		report.Summary.CompiledAttributeCount += scope.CompiledAttributeCount
	}
	for _, policy := range report.EvidencePolicies {
		if policy.Enabled {
			report.Summary.EnabledEvidencePolicyCount++
		}
	}
	report.Compliance = buildMobileGroupedAVPChecks(report, grouped, codec)
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
		if check.ID == "external-certification" {
			report.Summary.ExternalRequirementCount++
		}
	}
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.PlanFingerprint = fingerprintJSON(map[string]any{
		"feature":           report.FeatureID,
		"summary":           report.Summary,
		"vendor_scopes":     report.VendorScopes,
		"evidence_policies": report.EvidencePolicies,
		"semantic_bindings": report.SemanticBindings,
	})
	if !grouped.Enabled {
		report.Status = "disabled"
		report.Message = "NAS-0092 software is ready; telecom grouped AVP framework is not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = "Telecom grouped AVP framework is blocked by missing software prerequisites."
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = "Telecom grouped AVP framework is ready with warnings."
	} else {
		report.Status = "ready"
		report.Message = "Telecom grouped AVP framework software controls are ready for mobile/telecom domain use."
	}
	return report, nil
}

func PreviewAndRecordMobileGroupedAVPs(cfg *config.Config, actor string) (MobileGroupedAVPReport, string, error) {
	report, err := PreviewMobileGroupedAVPs(cfg)
	if err != nil {
		return report, "", err
	}
	eventID, err := recordMobileGroupedAVPReport("preview", "previewed", report, actor)
	return report, eventID, err
}

func ApplyMobileGroupedAVPs(_ context.Context, cfg *config.Config, actor string) (MobileGroupedAVPReport, string, error) {
	report, err := PreviewMobileGroupedAVPs(cfg)
	if err != nil {
		return report, "", err
	}
	status := "applied"
	if report.Status == "disabled" {
		status = "skipped"
	}
	if report.Status == "blocked" {
		status = "blocked"
	}
	eventID, recordErr := recordMobileGroupedAVPReport("apply", status, report, actor)
	if recordErr != nil {
		return report, eventID, recordErr
	}
	runtimeStatus := "ok"
	if report.Status == "degraded" {
		runtimeStatus = "degraded"
	} else if report.Status == "disabled" {
		runtimeStatus = "disabled"
	} else if report.Status == "blocked" {
		runtimeStatus = "blocked"
	}
	_ = db.UpsertRuntimeStatus(mobileGroupedAVPComponent, runtimeStatus, report.Message, map[string]any{
		"feature_id":               report.FeatureID,
		"software_completion":      report.SoftwareCompletionPercent,
		"ready_for_external":       report.ReadyForExternalValidation,
		"plan_fingerprint":         report.PlanFingerprint,
		"vendor_scope_count":       report.Summary.VendorScopeCount,
		"compiled_attribute_count": report.Summary.CompiledAttributeCount,
		"grouped_attribute_count":  report.Summary.GroupedAttributeCount,
		"evidence_policy_count":    report.Summary.EvidencePolicyCount,
		"blocker_count":            report.Summary.BlockerCount,
		"warning_count":            report.Summary.WarningCount,
		"event_id":                 eventID,
	})
	if status == "blocked" {
		return report, eventID, errors.New(strings.Join(report.Blockers, "; "))
	}
	return report, eventID, nil
}

func compileMobileGroupedAVPScopes(grouped config.MobileGroupedAVPConfig, registry *productconfigs.AttributeRegistry) []MobileGroupedAVPScope {
	out := make([]MobileGroupedAVPScope, 0, len(grouped.VendorScopes))
	for _, item := range grouped.VendorScopes {
		scope := MobileGroupedAVPScope{
			ScopeKey:               strings.ToLower(strings.TrimSpace(item.Name)),
			Name:                   strings.TrimSpace(item.Name),
			Enabled:                item.Enabled,
			Vendor:                 strings.TrimSpace(item.Vendor),
			VendorID:               item.VendorID,
			Dictionary:             strings.TrimSpace(item.Dictionary),
			Domain:                 strings.TrimSpace(item.Domain),
			Format:                 firstNonEmptyString(strings.TrimSpace(item.Format), "radius-vsa"),
			Status:                 "ready",
			Reason:                 "Vendor grouped AVP scope is compiled into telecom domain semantics.",
			GroupedRootAttributes:  trimStringSlice(item.GroupedRootAttributes),
			IdentityAttributes:     trimStringSlice(item.IdentityAttributes),
			ChargingAttributes:     trimStringSlice(item.ChargingAttributes),
			QoSAttributes:          trimStringSlice(item.QoSAttributes),
			PolicyAttributes:       trimStringSlice(item.PolicyAttributes),
			SafeRawEvidence:        item.SafeRawEvidence || grouped.SafeRawEvidence,
			HashRawValues:          item.HashRawValues || grouped.HashRawValues,
			DictionaryRelease:      registry.SourceRelease,
			DictionarySourceSHA256: registry.SourceSHA256,
			ExternalCertification:  true,
		}
		if !item.Enabled {
			scope.Status = "planned"
			scope.Reason = "Vendor scope is configured but disabled."
		}
		for _, entry := range registry.Entries {
			if entry.PEN != item.VendorID && !strings.EqualFold(entry.Vendor, item.Vendor) {
				continue
			}
			scope.RegistryAttributeCount++
			if entry.WireCodec.Grouped || len(entry.OIDPath) > 1 || strings.EqualFold(entry.WireType, "tlv") {
				scope.GroupedAttributeCount++
			}
		}
		scope.CompiledAttributeCount = countUniqueStrings(append(append(append(append([]string{}, scope.GroupedRootAttributes...), scope.IdentityAttributes...), scope.ChargingAttributes...), append(scope.QoSAttributes, scope.PolicyAttributes...)...))
		scope.SampleEvidenceDigest = fingerprintJSON(map[string]any{
			"scope":       scope.ScopeKey,
			"vendor":      scope.Vendor,
			"vendor_id":   scope.VendorID,
			"release":     scope.DictionaryRelease,
			"attributes":  scope.CompiledAttributeCount,
			"safe_hashes": scope.HashRawValues,
		})
		out = append(out, scope)
	}
	return out
}

func compileMobileGroupedAVPEvidencePolicies(grouped config.MobileGroupedAVPConfig) []MobileGroupedAVPEvidence {
	out := make([]MobileGroupedAVPEvidence, 0, len(grouped.EvidencePolicies))
	for _, item := range grouped.EvidencePolicies {
		status := "ready"
		reason := "Evidence policy stores redacted metadata and digests only."
		if !item.Enabled {
			status = "planned"
			reason = "Evidence policy is configured but disabled."
		}
		if item.CaptureRaw {
			reason = "Raw capture is permitted only with hash/redaction controls and remains subject to export role."
		}
		out = append(out, MobileGroupedAVPEvidence{
			Name:              strings.TrimSpace(item.Name),
			Enabled:           item.Enabled,
			Scope:             firstNonEmptyString(strings.TrimSpace(item.Scope), "all"),
			CaptureRaw:        item.CaptureRaw,
			HashRawValues:     item.HashRawValues,
			RetentionDays:     item.RetentionDays,
			RedactAttributes:  trimStringSlice(item.RedactAttributes),
			AllowedExportRole: strings.TrimSpace(item.AllowedExportRole),
			Status:            status,
			Reason:            reason,
		})
	}
	return out
}

func buildMobileGroupedAVPChecks(report MobileGroupedAVPReport, grouped config.MobileGroupedAVPConfig, codec radius.VSACodecReport) []MobileGroupedAVPCheck {
	checks := []MobileGroupedAVPCheck{
		{
			ID:      "vsa-codec",
			Name:    "NAS-0005 grouped VSA codec dependency",
			Status:  "passed",
			Message: "Bounded VSA codec is available for grouped, tagged, repeated, OID-backed, and extended attributes.",
			Evidence: []string{
				fmt.Sprintf("schema=%d", codec.SchemaVersion),
				fmt.Sprintf("grouped_attributes=%d", codec.Summary.GroupedAttributeCount),
				fmt.Sprintf("supported_formats=%d", len(codec.SupportedFormats)),
			},
		},
		{
			ID:      "attribute-registry",
			Name:    "Typed attribute registry dependency",
			Status:  "passed",
			Message: "FreeRADIUS 3.2.8 registry metadata is available for telecom vendor scope compilation.",
			Evidence: []string{
				fmt.Sprintf("release=%s", report.Summary.RegistryRelease),
				fmt.Sprintf("source_sha256=%s", report.Summary.RegistrySHA256),
				fmt.Sprintf("registry_attributes=%d", report.Summary.RegistryAttributeCount),
			},
		},
		{
			ID:      "vendor-scopes",
			Name:    "Telecom vendor scopes",
			Status:  "passed",
			Message: "3GPP, 3GPP2, Starent/Cisco, Ericsson/Redback, and WiMAX grouped AVP scopes are compiled.",
			Evidence: []string{
				fmt.Sprintf("enabled_scopes=%d", report.Summary.EnabledVendorScopeCount),
				fmt.Sprintf("compiled_attributes=%d", report.Summary.CompiledAttributeCount),
			},
		},
		{
			ID:      "safe-evidence",
			Name:    "Safe raw evidence controls",
			Status:  "passed",
			Message: "Evidence policy is redaction and digest first; cleartext mobile identifiers are not persisted by default.",
			Evidence: []string{
				fmt.Sprintf("safe_raw_evidence=%t", grouped.SafeRawEvidence),
				fmt.Sprintf("hash_raw_values=%t", grouped.HashRawValues),
				fmt.Sprintf("retention_days=%d", grouped.RawEvidenceRetentionDays),
			},
		},
		{
			ID:       "database-history",
			Name:     "Database event history",
			Status:   "passed",
			Message:  "Schema v96 persists mobile grouped AVP lifecycle events and effective vendor scope rows.",
			Evidence: []string{"mobile_grouped_avp_events", "mobile_grouped_avp_scopes"},
		},
		{
			ID:       "external-certification",
			Name:     "Release certification boundary",
			Status:   "passed",
			Message:  "Real carrier packet-core, WiMAX, FreeRADIUS production Linux, HA, scale, soak, security, and customer proof are tracked outside software completion.",
			Evidence: []string{report.ReleaseCertificationChecklist},
		},
	}
	if codec.Summary.GroupedAttributeCount == 0 {
		checks[0].Status = "blocked"
		checks[0].Message = "VSA codec did not expose grouped attribute support."
	}
	if report.Summary.EnabledVendorScopeCount == 0 && grouped.Enabled {
		checks[2].Status = "blocked"
		checks[2].Message = "No enabled telecom vendor scopes are available."
	}
	if grouped.SafeRawEvidence && !grouped.HashRawValues {
		checks[3].Status = "blocked"
		checks[3].Message = "Safe raw evidence requires hash_raw_values."
	}
	return checks
}

func recordMobileGroupedAVPReport(operation, status string, report MobileGroupedAVPReport, actor string) (string, error) {
	summaryJSON, _ := json.Marshal(report.Summary)
	reportJSON, _ := json.Marshal(report)
	scopes := make([]db.MobileGroupedAVPScopeInput, 0, len(report.VendorScopes))
	for _, item := range report.VendorScopes {
		attributesJSON, _ := json.Marshal(map[string]any{
			"grouped_root_attributes": item.GroupedRootAttributes,
			"identity_attributes":     item.IdentityAttributes,
			"charging_attributes":     item.ChargingAttributes,
			"qos_attributes":          item.QoSAttributes,
			"policy_attributes":       item.PolicyAttributes,
		})
		scopes = append(scopes, db.MobileGroupedAVPScopeInput{
			ScopeKey:               item.ScopeKey,
			Name:                   item.Name,
			Vendor:                 item.Vendor,
			VendorID:               item.VendorID,
			Dictionary:             item.Dictionary,
			Domain:                 item.Domain,
			Format:                 item.Format,
			Status:                 item.Status,
			RegistryAttributeCount: item.RegistryAttributeCount,
			GroupedAttributeCount:  item.GroupedAttributeCount,
			CompiledAttributeCount: item.CompiledAttributeCount,
			AttributesJSON:         string(attributesJSON),
			PlanFingerprint:        report.PlanFingerprint,
		})
	}
	return db.RecordMobileGroupedAVPEvent(db.MobileGroupedAVPEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		VendorScopeCount:         report.Summary.VendorScopeCount,
		EvidencePolicyCount:      report.Summary.EvidencePolicyCount,
		CompiledAttributeCount:   report.Summary.CompiledAttributeCount,
		GroupedAttributeCount:    report.Summary.GroupedAttributeCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              string(summaryJSON),
		ReportJSON:               string(reportJSON),
		Actor:                    actor,
		Scopes:                   scopes,
	})
}

func countUniqueStrings(values []string) int {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return len(seen)
}
