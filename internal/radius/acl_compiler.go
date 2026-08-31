package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const (
	ACLCompilerSchemaVersion = 1
	ACLCompilerVersion       = "nas-0049.1"

	aclCompilerMaxRules           = 64
	aclCompilerMaxAttributes      = 128
	aclCompilerMaxValueBytes      = 253
	aclCompilerProfileMaxBytes    = 128
	aclCompilerStatusCompiled     = "compiled"
	aclCompilerStatusProfile      = "profile_reference"
	aclCompilerStatusBlocked      = "blocked"
	aclCompilerStatusUnsupported  = "unsupported"
	aclCertificationSoftware      = "software-certified"
	aclCertificationProfile       = "profile-reference"
	aclCertificationUnsupported   = "unsupported"
	aclCertificationExternalScope = "external-certification-required"
)

type ACLCompilerLimits struct {
	MaxRules               int  `json:"max_rules"`
	MaxAttributes          int  `json:"max_attributes"`
	MaxAttributeValueBytes int  `json:"max_attribute_value_bytes"`
	SupportsLineRules      bool `json:"supports_line_rules"`
	SupportsProfile        bool `json:"supports_profile"`
	SupportsDecompile      bool `json:"supports_decompile"`
}

type ACLCompilerCapability struct {
	PackKey                       string            `json:"pack_key"`
	PackLabel                     string            `json:"pack_label"`
	VendorName                    string            `json:"vendor_name,omitempty"`
	VendorID                      int               `json:"vendor_id,omitempty"`
	OutputMode                    string            `json:"output_mode"`
	Status                        string            `json:"status"`
	CertificationState            string            `json:"certification_state"`
	ExternalCertificationRequired bool              `json:"external_certification_required"`
	Grammars                      []string          `json:"grammars"`
	Attributes                    []string          `json:"attributes"`
	Limits                        ACLCompilerLimits `json:"limits"`
	Notes                         []string          `json:"notes,omitempty"`
}

type ACLCompilerRequest struct {
	PolicyName  string        `json:"policy_name,omitempty"`
	Description string        `json:"description,omitempty"`
	InboundACL  string        `json:"inbound_acl,omitempty"`
	OutboundACL string        `json:"outbound_acl,omitempty"`
	Rules       []ACLRule     `json:"rules,omitempty"`
	ACLAST      *ACLPolicyAST `json:"acl_ast,omitempty"`
	PackKeys    []string      `json:"pack_keys,omitempty"`
}

type ACLCompilerRun struct {
	SchemaVersion   int                     `json:"schema_version"`
	CompilerVersion string                  `json:"compiler_version"`
	Status          string                  `json:"status"`
	Summary         ACLCompilerSummary      `json:"summary"`
	ACLAST          ACLPolicyAST            `json:"acl_ast"`
	NormalizedRules []ACLRule               `json:"normalized_rules,omitempty"`
	ACLFingerprint  string                  `json:"acl_fingerprint"`
	ACLRoundTrip    ACLRoundTrip            `json:"acl_round_trip"`
	Diagnostics     []ACLDiagnostic         `json:"diagnostics,omitempty"`
	Results         []ACLCompileResult      `json:"results"`
	Capabilities    []ACLCompilerCapability `json:"capabilities,omitempty"`
}

type ACLCompilerSummary struct {
	CompilerCount           int `json:"compiler_count"`
	CompiledCount           int `json:"compiled_count"`
	ProfileReferenceCount   int `json:"profile_reference_count"`
	UnsupportedCount        int `json:"unsupported_count"`
	BlockedCount            int `json:"blocked_count"`
	ArtifactCount           int `json:"artifact_count"`
	LineRuleArtifactCount   int `json:"line_rule_artifact_count"`
	ProfileArtifactCount    int `json:"profile_artifact_count"`
	DecompileSupportedCount int `json:"decompile_supported_count"`
	NonLosslessCount        int `json:"non_lossless_count"`
	DiagnosticCount         int `json:"diagnostic_count"`
}

type ACLCompileResult struct {
	PackKey                       string                `json:"pack_key"`
	PackLabel                     string                `json:"pack_label"`
	CompilerVersion               string                `json:"compiler_version"`
	OutputMode                    string                `json:"output_mode"`
	Status                        string                `json:"status"`
	CertificationState            string                `json:"certification_state"`
	ExternalCertificationRequired bool                  `json:"external_certification_required"`
	Grammar                       string                `json:"grammar"`
	Attributes                    []ReplyAttributeItem  `json:"attributes"`
	Artifacts                     []ACLCompiledArtifact `json:"artifacts"`
	FreeRADIUS                    string                `json:"freeradius"`
	ASTFingerprint                string                `json:"ast_fingerprint"`
	ArtifactFingerprint           string                `json:"artifact_fingerprint,omitempty"`
	Lossless                      bool                  `json:"lossless"`
	DecompileSupported            bool                  `json:"decompile_supported"`
	DecompiledRules               []ACLRule             `json:"decompiled_rules,omitempty"`
	RoundTrip                     ACLRoundTrip          `json:"round_trip"`
	Limits                        ACLCompilerLimits     `json:"limits"`
	Diagnostics                   []ACLDiagnostic       `json:"diagnostics,omitempty"`
	Warnings                      []string              `json:"warnings,omitempty"`
}

type ACLCompiledArtifact struct {
	Sequence     int    `json:"sequence"`
	Attribute    string `json:"attribute"`
	Value        string `json:"value"`
	Quoted       bool   `json:"quoted"`
	Direction    string `json:"direction,omitempty"`
	Grammar      string `json:"grammar"`
	SourceRuleID string `json:"source_rule_id,omitempty"`
	Fingerprint  string `json:"fingerprint"`
}

type ACLDecompileRequest struct {
	PackKey    string               `json:"pack_key"`
	PolicyName string               `json:"policy_name,omitempty"`
	Attributes []ReplyAttributeItem `json:"attributes"`
}

type ACLDecompileResult struct {
	SchemaVersion       int             `json:"schema_version"`
	CompilerVersion     string          `json:"compiler_version"`
	PackKey             string          `json:"pack_key"`
	PackLabel           string          `json:"pack_label"`
	Status              string          `json:"status"`
	OutputMode          string          `json:"output_mode"`
	Grammar             string          `json:"grammar"`
	ProfileReferences   []string        `json:"profile_references,omitempty"`
	Rules               []ACLRule       `json:"rules,omitempty"`
	ACLAST              ACLPolicyAST    `json:"acl_ast"`
	ACLFingerprint      string          `json:"acl_fingerprint"`
	ACLRoundTrip        ACLRoundTrip    `json:"acl_round_trip"`
	ArtifactFingerprint string          `json:"artifact_fingerprint,omitempty"`
	ArtifactCount       int             `json:"artifact_count"`
	Diagnostics         []ACLDiagnostic `json:"diagnostics,omitempty"`
	Warnings            []string        `json:"warnings,omitempty"`
}

type aclCompilerDefinition struct {
	PackKey            string
	OutputMode         string
	Status             string
	CertificationState string
	Grammar            string
	LineAttribute      string
	ProfileAttributes  []string
	SupportsDecompile  bool
	MaxValueBytes      int
	Notes              []string
}

func ACLCompilerCapabilities() []ACLCompilerCapability {
	packs := productconfigs.AegisNASVendorCompatibilityPacks()
	out := make([]ACLCompilerCapability, 0, len(packs))
	for _, pack := range packs {
		def := aclCompilerDefinitionForPack(pack.Key)
		out = append(out, aclCompilerCapabilityForDefinition(def, pack))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PackKey < out[j].PackKey
	})
	return out
}

func CompileACLPolicyForPacks(req ACLCompilerRequest) (ACLCompilerRun, error) {
	packKeys := normalizeReplyPackKeys(req.PackKeys)
	if len(packKeys) == 0 {
		packKeys = []string{productconfigs.VendorPackStandard}
	}
	normalization, err := NormalizeACLPolicyIntent(req.PolicyName, req.Description, req.InboundACL, req.OutboundACL, req.Rules, req.ACLAST)
	if err != nil {
		return ACLCompilerRun{}, err
	}
	run := ACLCompilerRun{
		SchemaVersion:   ACLCompilerSchemaVersion,
		CompilerVersion: ACLCompilerVersion,
		Status:          "ready",
		ACLAST:          normalization.AST,
		NormalizedRules: normalization.Rules,
		ACLFingerprint:  normalization.Fingerprint,
		ACLRoundTrip:    normalization.RoundTrip,
		Diagnostics:     append([]ACLDiagnostic(nil), normalization.Diagnostics...),
		Results:         make([]ACLCompileResult, 0, len(packKeys)),
	}
	for _, packKey := range packKeys {
		result := compileACLPolicyForPack(packKey, req, normalization)
		run.Results = append(run.Results, result)
		run.Summary.CompilerCount++
		run.Summary.ArtifactCount += len(result.Artifacts)
		for _, artifact := range result.Artifacts {
			if artifact.Grammar == "profile-ref-v1" {
				run.Summary.ProfileArtifactCount++
			} else {
				run.Summary.LineRuleArtifactCount++
			}
		}
		if result.DecompileSupported {
			run.Summary.DecompileSupportedCount++
		}
		if !result.Lossless {
			run.Summary.NonLosslessCount++
		}
		run.Summary.DiagnosticCount += len(result.Diagnostics)
		switch result.Status {
		case aclCompilerStatusCompiled:
			run.Summary.CompiledCount++
		case aclCompilerStatusProfile:
			run.Summary.ProfileReferenceCount++
		case aclCompilerStatusUnsupported:
			run.Summary.UnsupportedCount++
		case aclCompilerStatusBlocked:
			run.Summary.BlockedCount++
		}
	}
	switch {
	case run.Summary.BlockedCount == run.Summary.CompilerCount:
		run.Status = "blocked"
	case run.Summary.BlockedCount > 0 || run.Summary.UnsupportedCount > 0 || run.Summary.NonLosslessCount > 0 || len(run.Diagnostics) > 0:
		run.Status = "degraded"
	default:
		run.Status = "ready"
	}
	return run, nil
}

func CompileACLPolicyForPack(req ACLCompilerRequest, packKey string) (ACLCompileResult, error) {
	req.PackKeys = []string{packKey}
	run, err := CompileACLPolicyForPacks(req)
	if err != nil {
		return ACLCompileResult{}, err
	}
	if len(run.Results) == 0 {
		return ACLCompileResult{}, fmt.Errorf("no ACL compiler result for pack %q", packKey)
	}
	return run.Results[0], nil
}

func DecompileACLAttributes(req ACLDecompileRequest) (ACLDecompileResult, error) {
	packKey := productconfigs.NormalizeVendorCompatibilityPackKey(req.PackKey)
	def := aclCompilerDefinitionForPack(packKey)
	pack, _ := productconfigs.VendorCompatibilityPackByKey(packKey)
	capability := aclCompilerCapabilityForDefinition(def, pack)
	result := ACLDecompileResult{
		SchemaVersion:       ACLCompilerSchemaVersion,
		CompilerVersion:     ACLCompilerVersion,
		PackKey:             capability.PackKey,
		PackLabel:           capability.PackLabel,
		OutputMode:          capability.OutputMode,
		Grammar:             def.Grammar,
		ArtifactFingerprint: fingerprintReplyAttributeItems(req.Attributes),
		ArtifactCount:       len(req.Attributes),
	}
	if def.Status == aclCompilerStatusUnsupported || def.PackKey == "" {
		result.Status = aclCompilerStatusUnsupported
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "vendor_acl_compiler_unsupported", Path: "pack_key", Message: fmt.Sprintf("pack %q does not have a certified ACL compiler", strings.TrimSpace(req.PackKey))})
		return result, nil
	}
	if !def.SupportsDecompile {
		result.Status = aclCompilerStatusUnsupported
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "decompile_not_supported", Path: "attributes", Message: fmt.Sprintf("pack %s does not support ACL decompile", def.PackKey)})
		return result, nil
	}
	rules, profileRefs, diagnostics := decompileACLAttributesForDefinition(def, req.Attributes)
	result.ProfileReferences = profileRefs
	result.Diagnostics = append(result.Diagnostics, diagnostics...)
	if len(rules) == 0 && len(profileRefs) == 0 {
		result.Status = aclCompilerStatusBlocked
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "warning", Code: "no_acl_artifacts", Path: "attributes", Message: "no ACL artifacts matched the selected vendor compiler"})
	} else if len(rules) == 0 && len(profileRefs) > 0 {
		result.Status = aclCompilerStatusProfile
		result.Warnings = append(result.Warnings, "Decompiled profile reference only; line-rule contents must be learned from the vendor controller or device.")
	} else {
		result.Status = aclCompilerStatusCompiled
	}
	normalization := buildDecompiledACLNormalization(strings.TrimSpace(req.PolicyName), def.PackKey, rules, profileRefs)
	result.Rules = normalization.Rules
	result.ACLAST = normalization.AST
	result.ACLFingerprint = normalization.Fingerprint
	result.ACLRoundTrip = normalization.RoundTrip
	result.Diagnostics = append(result.Diagnostics, normalization.Diagnostics...)
	if result.Status == aclCompilerStatusCompiled && len(result.Diagnostics) > 0 {
		result.Status = "degraded"
	}
	return result, nil
}

func compileACLPolicyForPack(packKey string, req ACLCompilerRequest, normalization ACLPolicyNormalization) ACLCompileResult {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	def := aclCompilerDefinitionForPack(packKey)
	pack, _ := productconfigs.VendorCompatibilityPackByKey(packKey)
	capability := aclCompilerCapabilityForDefinition(def, pack)
	result := ACLCompileResult{
		PackKey:                       capability.PackKey,
		PackLabel:                     capability.PackLabel,
		CompilerVersion:               ACLCompilerVersion,
		OutputMode:                    capability.OutputMode,
		Status:                        capability.Status,
		CertificationState:            capability.CertificationState,
		ExternalCertificationRequired: capability.ExternalCertificationRequired,
		Grammar:                       def.Grammar,
		ASTFingerprint:                normalization.Fingerprint,
		Lossless:                      normalization.RoundTrip.Lossless,
		DecompileSupported:            capability.Limits.SupportsDecompile,
		RoundTrip:                     normalization.RoundTrip,
		Limits:                        capability.Limits,
		Diagnostics:                   append([]ACLDiagnostic(nil), normalization.Diagnostics...),
	}
	switch def.Status {
	case aclCompilerStatusUnsupported, "":
		result.Status = aclCompilerStatusUnsupported
		if aclCompilerHasIntent(req, normalization) {
			result.Status = aclCompilerStatusBlocked
			result.Lossless = false
			result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "vendor_acl_compiler_unsupported", Path: "pack_key", Message: fmt.Sprintf("pack %s has no certified RADIUS ACL compiler in this release", packKey)})
		}
		return finalizeACLCompileResult(result)
	case aclCompilerStatusProfile:
		return compileProfileACL(def, req, normalization, result)
	default:
		return compileLineACL(def, req, normalization, result)
	}
}

func compileLineACL(def aclCompilerDefinition, req ACLCompilerRequest, normalization ACLPolicyNormalization, result ACLCompileResult) ACLCompileResult {
	if len(normalization.Rules) > result.Limits.MaxRules {
		result.Status = aclCompilerStatusBlocked
		result.Lossless = false
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "compiler_rule_limit", Path: "rules", Message: fmt.Sprintf("pack %s supports at most %d compiled ACL rules", def.PackKey, result.Limits.MaxRules)})
		return finalizeACLCompileResult(result)
	}
	var items []ReplyAttributeItem
	appendItem := func(attribute, value string, quoted bool) {
		attribute = strings.TrimSpace(attribute)
		value = strings.TrimSpace(value)
		if attribute == "" || value == "" {
			return
		}
		items = append(items, ReplyAttributeItem{Name: attribute, Value: value, Quoted: quoted})
	}
	profileName := firstReplyValue(strings.TrimSpace(req.PolicyName), strings.TrimSpace(req.InboundACL), strings.TrimSpace(req.OutboundACL), strings.TrimSpace(normalization.AST.Name))
	for _, attr := range def.ProfileAttributes {
		switch attr {
		case "Cisco-In-ACL":
			appendItem(attr, req.InboundACL, true)
		case "Cisco-Out-ACL":
			appendItem(attr, req.OutboundACL, true)
		default:
			appendItem(attr, profileName, true)
		}
	}
	if def.Grammar == "cisco-avpair-acl-v1" {
		for _, value := range renderCiscoAVPairACLRules(normalization.Rules) {
			appendItem(def.LineAttribute, value, true)
		}
	} else {
		for _, value := range renderNASFilterRules(normalization.Rules) {
			appendItem(def.LineAttribute, value, true)
		}
	}
	result.Attributes = items
	if len(result.Attributes) > result.Limits.MaxAttributes {
		result.Status = aclCompilerStatusBlocked
		result.Lossless = false
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "compiler_attribute_limit", Path: "attributes", Message: fmt.Sprintf("pack %s emitted %d ACL attributes, above limit %d", def.PackKey, len(result.Attributes), result.Limits.MaxAttributes)})
		return finalizeACLCompileResult(result)
	}
	result.Artifacts = aclArtifactsFromItems(def.Grammar, result.Attributes, normalization.Rules)
	result.ArtifactFingerprint = fingerprintReplyAttributeItems(result.Attributes)
	result.FreeRADIUS = renderReplyAttributeItems(result.Attributes)
	result.Status = aclCompilerStatusCompiled
	for idx, item := range result.Attributes {
		if len([]byte(item.Value)) > result.Limits.MaxAttributeValueBytes {
			result.Status = aclCompilerStatusBlocked
			result.Lossless = false
			result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "compiler_value_limit", Path: fmt.Sprintf("attributes[%d].value", idx), Message: fmt.Sprintf("%s value is %d byte(s), above limit %d", item.Name, len([]byte(item.Value)), result.Limits.MaxAttributeValueBytes)})
		}
	}
	if result.DecompileSupported && result.Status != aclCompilerStatusBlocked {
		decompiled, err := DecompileACLAttributes(ACLDecompileRequest{PackKey: def.PackKey, PolicyName: req.PolicyName, Attributes: result.Attributes})
		if err != nil {
			result.Status = "degraded"
			result.Lossless = false
			result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "compiler_decompile_failed", Path: "attributes", Message: err.Error()})
		} else {
			result.DecompiledRules = decompiled.Rules
			if !aclCompiledWireEquivalent(def, normalization.Rules, decompiled.Rules) {
				result.Status = "degraded"
				result.Lossless = false
				result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "warning", Code: "compiler_round_trip_mismatch", Path: "attributes", Message: fmt.Sprintf("pack %s compiled artifacts did not decompile back to equivalent ACL rules", def.PackKey)})
			}
		}
	}
	return finalizeACLCompileResult(result)
}

func compileProfileACL(def aclCompilerDefinition, req ACLCompilerRequest, normalization ACLPolicyNormalization, result ACLCompileResult) ACLCompileResult {
	profileName := firstReplyValue(strings.TrimSpace(req.PolicyName), strings.TrimSpace(req.InboundACL), strings.TrimSpace(req.OutboundACL), strings.TrimSpace(normalization.AST.Name))
	if profileName == "" {
		if len(normalization.Rules) > 0 {
			result.Status = aclCompilerStatusBlocked
			result.Lossless = false
			result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "profile_name_required", Path: "policy_name", Message: fmt.Sprintf("pack %s requires a named ACL/profile because it cannot carry line rules in RADIUS", def.PackKey)})
		}
		return finalizeACLCompileResult(result)
	}
	if !validACLToken(profileName) || len([]byte(profileName)) > result.Limits.MaxAttributeValueBytes {
		result.Status = aclCompilerStatusBlocked
		result.Lossless = false
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "error", Code: "profile_name_invalid", Path: "policy_name", Message: fmt.Sprintf("profile name for pack %s is invalid or longer than %d bytes", def.PackKey, result.Limits.MaxAttributeValueBytes)})
		return finalizeACLCompileResult(result)
	}
	for _, attr := range def.ProfileAttributes {
		result.Attributes = append(result.Attributes, ReplyAttributeItem{Name: attr, Value: profileName, Quoted: true})
	}
	result.Artifacts = aclArtifactsFromItems(def.Grammar, result.Attributes, nil)
	result.ArtifactFingerprint = fingerprintReplyAttributeItems(result.Attributes)
	result.FreeRADIUS = renderReplyAttributeItems(result.Attributes)
	if len(normalization.Rules) > 0 {
		result.Lossless = false
		result.Diagnostics = append(result.Diagnostics, ACLDiagnostic{Severity: "warning", Code: "profile_reference_only", Path: "attributes", Message: fmt.Sprintf("pack %s exports ACL policy name %q; line rules require controller-side policy with the same name", def.PackKey, profileName)})
		result.Warnings = append(result.Warnings, "Line rules are preserved in AegisNAS but this vendor pack exports only a named ACL/profile reference.")
	}
	result.Status = aclCompilerStatusProfile
	return finalizeACLCompileResult(result)
}

func finalizeACLCompileResult(result ACLCompileResult) ACLCompileResult {
	if result.ArtifactFingerprint == "" {
		result.ArtifactFingerprint = fingerprintReplyAttributeItems(result.Attributes)
	}
	if result.FreeRADIUS == "" && len(result.Attributes) > 0 {
		result.FreeRADIUS = renderReplyAttributeItems(result.Attributes)
	}
	result.RoundTrip.Lossless = result.Lossless
	result.RoundTrip.UnsupportedFields = aclUnsupportedRoundTripFields(result.Diagnostics)
	if len(result.RoundTrip.UnsupportedFields) > 0 {
		result.Lossless = false
		result.RoundTrip.Lossless = false
		if result.Status == aclCompilerStatusCompiled {
			result.Status = "degraded"
		}
	}
	if result.Status == "" {
		result.Status = aclCompilerStatusCompiled
	}
	return result
}

func decompileACLAttributesForDefinition(def aclCompilerDefinition, attrs []ReplyAttributeItem) ([]ACLRule, []string, []ACLDiagnostic) {
	var rules []ACLRule
	var profiles []string
	var diagnostics []ACLDiagnostic
	for idx, item := range attrs {
		name := strings.TrimSpace(item.Name)
		value := strings.TrimSpace(item.Value)
		if name == "" || value == "" {
			continue
		}
		if def.LineAttribute != "" && strings.EqualFold(name, def.LineAttribute) {
			var (
				rule ACLRule
				err  error
				ok   bool
			)
			if def.Grammar == "cisco-avpair-acl-v1" {
				rule, ok, err = parseCiscoAVPairACLRule(value)
				if !ok && err == nil {
					continue
				}
			} else {
				rule, err = parseNASFilterRule(value)
			}
			if err != nil {
				diagnostics = append(diagnostics, ACLDiagnostic{Severity: "error", Code: "decompile_parse_failed", Path: fmt.Sprintf("attributes[%d]", idx), Message: err.Error()})
				continue
			}
			rules = append(rules, rule)
			continue
		}
		for _, profileAttribute := range def.ProfileAttributes {
			if strings.EqualFold(name, profileAttribute) {
				profiles = appendUniqueACLCompilerString(profiles, name+"="+value)
			}
		}
	}
	normalized, err := NormalizeACLRules(rules)
	if err != nil {
		diagnostics = append(diagnostics, ACLDiagnostic{Severity: "error", Code: "decompile_normalize_failed", Path: "rules", Message: err.Error()})
		return nil, profiles, diagnostics
	}
	return normalized, profiles, diagnostics
}

func buildDecompiledACLNormalization(policyName, packKey string, rules []ACLRule, profileRefs []string) ACLPolicyNormalization {
	normalizedRules, err := NormalizeACLRules(rules)
	if err != nil {
		ast := BuildACLPolicyASTFromRules(policyName, "", "", "", rules)
		fingerprint := FingerprintACLPolicyAST(ast)
		return ACLPolicyNormalization{
			AST:         ast,
			Rules:       rules,
			Fingerprint: fingerprint,
			Diagnostics: []ACLDiagnostic{{Severity: "error", Code: "decompile_normalize_failed", Path: "rules", Message: err.Error()}},
			RoundTrip: ACLRoundTrip{
				Lossless:          false,
				ASTFingerprint:    fingerprint,
				ASTRuleCount:      len(ast.Rules),
				RuleCount:         len(rules),
				UnsupportedFields: []string{"rules"},
			},
		}
	}
	ast := BuildACLPolicyASTFromRules(policyName, "", "", "", normalizedRules)
	if ast.Metadata == nil {
		ast.Metadata = map[string]string{}
	}
	ast.Metadata["decompiled_pack"] = packKey
	if len(profileRefs) > 0 {
		sort.Strings(profileRefs)
		ast.Metadata["profile_references"] = strings.Join(profileRefs, ";")
	}
	fingerprint := FingerprintACLPolicyAST(ast)
	roundTrip := ACLRoundTrip{
		Lossless:       len(normalizedRules) > 0 || len(profileRefs) == 0,
		ASTFingerprint: fingerprint,
		ASTRuleCount:   len(ast.Rules),
		RuleCount:      len(normalizedRules),
	}
	if len(normalizedRules) == 0 && len(profileRefs) > 0 {
		roundTrip.UnsupportedFields = []string{"attributes"}
	}
	return ACLPolicyNormalization{
		AST:         ast,
		Rules:       normalizedRules,
		Fingerprint: fingerprint,
		RoundTrip:   roundTrip,
	}
}

func parseNASFilterRule(value string) (ACLRule, error) {
	tokens := strings.Fields(strings.TrimSpace(value))
	if len(tokens) < 7 {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule requires action, direction, protocol, from, source, to, and destination")
	}
	rule := ACLRule{Action: tokens[0], Direction: tokens[1], Protocol: tokens[2]}
	if !strings.EqualFold(tokens[3], "from") {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule token 4 must be from")
	}
	rule.Source = tokens[4]
	idx := 5
	if idx >= len(tokens) {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule is missing to")
	}
	if !strings.EqualFold(tokens[idx], "to") {
		rule.SourcePort = tokens[idx]
		idx++
	}
	if idx >= len(tokens) || !strings.EqualFold(tokens[idx], "to") {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule is missing to")
	}
	idx++
	if idx >= len(tokens) {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule is missing destination")
	}
	rule.Destination = tokens[idx]
	idx++
	if idx < len(tokens) && !strings.EqualFold(tokens[idx], "log") {
		rule.DestinationPort = tokens[idx]
		idx++
	}
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "log") {
		rule.Log = true
		idx++
	}
	if idx != len(tokens) {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule contains trailing tokens")
	}
	normalized, ok := normalizeACLRule(rule)
	if !ok {
		return ACLRule{}, fmt.Errorf("NAS-Filter-Rule contains invalid values")
	}
	return normalized, nil
}

func parseCiscoAVPairACLRule(value string) (ACLRule, bool, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(value), "ip:") {
		return ACLRule{}, false, nil
	}
	left, body, ok := strings.Cut(value[3:], "=")
	if !ok {
		return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair is missing =")
	}
	directionToken := strings.ToLower(strings.TrimSpace(left))
	if hash := strings.Index(directionToken, "#"); hash >= 0 {
		if _, err := strconv.Atoi(directionToken[hash+1:]); err != nil {
			return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair sequence is invalid")
		}
		directionToken = directionToken[:hash]
	}
	direction := ""
	switch directionToken {
	case "inacl":
		direction = "in"
	case "outacl":
		direction = "out"
	default:
		return ACLRule{}, false, nil
	}
	tokens := strings.Fields(body)
	if len(tokens) < 4 {
		return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair requires action, protocol, source, and destination")
	}
	rule := ACLRule{Action: tokens[0], Direction: direction, Protocol: tokens[1], Source: tokens[2]}
	idx := 3
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "eq") {
		idx++
		if idx >= len(tokens) {
			return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair source eq is missing a port")
		}
		rule.SourcePort = tokens[idx]
		idx++
	}
	if idx >= len(tokens) {
		return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair is missing destination")
	}
	rule.Destination = tokens[idx]
	idx++
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "eq") {
		idx++
		if idx >= len(tokens) {
			return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair destination eq is missing a port")
		}
		rule.DestinationPort = tokens[idx]
		idx++
	}
	if idx < len(tokens) && strings.EqualFold(tokens[idx], "log") {
		rule.Log = true
		idx++
	}
	if idx != len(tokens) {
		return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair contains trailing tokens")
	}
	normalized, ok := normalizeACLRule(rule)
	if !ok {
		return ACLRule{}, true, fmt.Errorf("Cisco ACL AVPair contains invalid values")
	}
	return normalized, true, nil
}

func aclCompilerDefinitionForPack(packKey string) aclCompilerDefinition {
	packKey = productconfigs.NormalizeVendorCompatibilityPackKey(packKey)
	defs := map[string]aclCompilerDefinition{
		productconfigs.VendorPackStandard: {
			PackKey: packKey, OutputMode: "line_rules", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "nas-filter-rule-v1", LineAttribute: "NAS-Filter-Rule", SupportsDecompile: true,
			Notes: []string{"Compiles the RFC 2865 NAS-Filter-Rule string grammar used by FreeRADIUS."},
		},
		productconfigs.VendorPackAegisNAS: {
			PackKey: packKey, OutputMode: "mixed", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "aegisnas-acl-v1", LineAttribute: "AegisNAS-ACL-Rule", ProfileAttributes: []string{"AegisNAS-ACL-Name"}, SupportsDecompile: true,
			Notes: []string{"Compiles AegisNAS product ACL name and line-rule VSAs using the same validated grammar as NAS-Filter-Rule."},
		},
		productconfigs.VendorPackCisco: {
			PackKey: packKey, OutputMode: "mixed", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "cisco-avpair-acl-v1", LineAttribute: "Cisco-AVPair", ProfileAttributes: []string{"Cisco-In-ACL", "Cisco-Out-ACL"}, SupportsDecompile: true,
			Notes: []string{"Compiles generated Cisco ip:inacl/ip:outacl AVPairs with deterministic per-direction numbering."},
		},
		productconfigs.VendorPackAruba: {
			PackKey: packKey, OutputMode: "line_rules", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "nas-filter-rule-v1", LineAttribute: "Aruba-NAS-Filter-Rule", SupportsDecompile: true,
			Notes: []string{"Compiles Aruba-NAS-Filter-Rule values using the validated NAS filter grammar."},
		},
		productconfigs.VendorPackHP: {
			PackKey: packKey, OutputMode: "line_rules", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "nas-filter-rule-v1", LineAttribute: "Ip-Filter-Raw", SupportsDecompile: true,
			Notes: []string{"Compiles HP/ArubaOS-Switch Ip-Filter-Raw line rules."},
		},
		productconfigs.VendorPackDLink: {
			PackKey: packKey, OutputMode: "mixed", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "nas-filter-rule-v1", LineAttribute: "Dlink-ACL-Rule", ProfileAttributes: []string{"Dlink-ACL-Profile"}, SupportsDecompile: true,
			Notes: []string{"Compiles D-Link ACL profile and line-rule attributes."},
		},
		productconfigs.VendorPackPica8: {
			PackKey: packKey, OutputMode: "mixed", Status: aclCompilerStatusCompiled, CertificationState: aclCertificationSoftware,
			Grammar: "nas-filter-rule-v1", LineAttribute: "IP-Downloadable-ACL-Rule", ProfileAttributes: []string{"IP-Downloadable-ACL-Name"}, SupportsDecompile: true,
			Notes: []string{"Compiles Pica8 downloadable ACL profile and line-rule attributes."},
		},
		productconfigs.VendorPackMikroTik: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"Mikrotik-Address-List"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"RouterOS RADIUS carries an address-list/profile reference; line-rule contents live on RouterOS/controller policy."},
		},
		productconfigs.VendorPackFortinet: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"Fortinet-Access-Profile"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"Fortinet RADIUS carries an access-profile name; firewall policy contents are controller/device-side state."},
		},
		productconfigs.VendorPackRuckus: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"Ruckus-User-Groups"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"Ruckus RADIUS carries user-group/profile references rather than portable line-rule ACLs."},
		},
		productconfigs.VendorPackJuniper: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"Juniper-Firewall-filter-name", "Juniper-Switching-Filter"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"Juniper RADIUS ACL enforcement is represented by named firewall/switching filters."},
		},
		productconfigs.VendorPackHuawei: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"Huawei-Data-Filter"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"Huawei RADIUS ACL enforcement is represented by named data-filter policy."},
		},
		productconfigs.VendorPackH3C: {
			PackKey: packKey, OutputMode: "profile_reference", Status: aclCompilerStatusProfile, CertificationState: aclCertificationProfile,
			Grammar: "profile-ref-v1", ProfileAttributes: []string{"H3C-Ita-Policy"}, SupportsDecompile: true, MaxValueBytes: aclCompilerProfileMaxBytes,
			Notes: []string{"H3C/Comware ACL-like enforcement is represented by a named ITA policy."},
		},
	}
	if def, ok := defs[packKey]; ok {
		if def.MaxValueBytes <= 0 {
			def.MaxValueBytes = aclCompilerMaxValueBytes
		}
		return def
	}
	return aclCompilerDefinition{
		PackKey: packKey, OutputMode: "unsupported", Status: aclCompilerStatusUnsupported, CertificationState: aclCertificationUnsupported,
		Grammar: "", MaxValueBytes: aclCompilerMaxValueBytes,
		Notes: []string{"No certified RADIUS ACL compiler is available for this pack in NAS-0049."},
	}
}

func aclCompilerCapabilityForDefinition(def aclCompilerDefinition, pack productconfigs.VendorCompatibilityPack) ACLCompilerCapability {
	packKey := def.PackKey
	if packKey == "" {
		packKey = pack.Key
	}
	label := pack.Label
	if strings.TrimSpace(label) == "" {
		label = packKey
	}
	attrs := append([]string(nil), def.ProfileAttributes...)
	if def.LineAttribute != "" {
		attrs = append(attrs, def.LineAttribute)
	}
	maxValue := def.MaxValueBytes
	if maxValue <= 0 {
		maxValue = aclCompilerMaxValueBytes
	}
	return ACLCompilerCapability{
		PackKey:                       packKey,
		PackLabel:                     label,
		VendorName:                    pack.VendorName,
		VendorID:                      pack.VendorID,
		OutputMode:                    firstReplyValue(def.OutputMode, "unsupported"),
		Status:                        firstReplyValue(def.Status, aclCompilerStatusUnsupported),
		CertificationState:            firstReplyValue(def.CertificationState, aclCertificationUnsupported),
		ExternalCertificationRequired: def.Status != aclCompilerStatusUnsupported,
		Grammars:                      optionalACLList(def.Grammar),
		Attributes:                    attrs,
		Limits: ACLCompilerLimits{
			MaxRules:               aclCompilerMaxRules,
			MaxAttributes:          aclCompilerMaxAttributes,
			MaxAttributeValueBytes: maxValue,
			SupportsLineRules:      def.LineAttribute != "",
			SupportsProfile:        len(def.ProfileAttributes) > 0,
			SupportsDecompile:      def.SupportsDecompile,
		},
		Notes: append(append([]string(nil), def.Notes...), aclCertificationExternalScope),
	}
}

func aclArtifactsFromItems(grammar string, items []ReplyAttributeItem, rules []ACLRule) []ACLCompiledArtifact {
	out := make([]ACLCompiledArtifact, 0, len(items))
	ruleIDs := make([]string, 0, len(rules))
	directions := make([]string, 0, len(rules))
	for _, rule := range rules {
		ruleIDs = append(ruleIDs, rule.ID)
		directions = append(directions, rule.Direction)
	}
	for idx, item := range items {
		sourceRuleID := ""
		direction := ""
		if idx < len(ruleIDs) {
			sourceRuleID = ruleIDs[idx]
			direction = directions[idx]
		}
		if strings.Contains(item.Value, "inacl") || strings.Contains(item.Value, " in ") {
			direction = "in"
		}
		if strings.Contains(item.Value, "outacl") || strings.Contains(item.Value, " out ") {
			direction = "out"
		}
		fingerprint := fingerprintACLArtifact(item.Name, item.Value)
		out = append(out, ACLCompiledArtifact{
			Sequence:     idx + 1,
			Attribute:    item.Name,
			Value:        item.Value,
			Quoted:       item.Quoted,
			Direction:    direction,
			Grammar:      grammar,
			SourceRuleID: sourceRuleID,
			Fingerprint:  fingerprint,
		})
	}
	return out
}

func aclCompiledWireEquivalent(def aclCompilerDefinition, original, decompiled []ACLRule) bool {
	if def.Grammar == "cisco-avpair-acl-v1" {
		return stringSliceEqual(renderCiscoAVPairACLRules(original), renderCiscoAVPairACLRules(decompiled))
	}
	return stringSliceEqual(renderNASFilterRules(original), renderNASFilterRules(decompiled))
}

func stringSliceEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for idx := range left {
		if left[idx] != right[idx] {
			return false
		}
	}
	return true
}

func aclCompilerHasIntent(req ACLCompilerRequest, normalization ACLPolicyNormalization) bool {
	return strings.TrimSpace(req.PolicyName) != "" || strings.TrimSpace(req.InboundACL) != "" ||
		strings.TrimSpace(req.OutboundACL) != "" || len(normalization.Rules) > 0 || len(normalization.AST.Rules) > 0
}

func appendUniqueACLCompilerString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func fingerprintReplyAttributeItems(items []ReplyAttributeItem) string {
	if len(items) == 0 {
		return ""
	}
	payload, _ := json.Marshal(items)
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fingerprintACLArtifact(name, value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(name) + "\x00" + strings.TrimSpace(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}
