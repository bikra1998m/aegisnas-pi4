package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type aclCompilerDecompileRequest struct {
	PackKey    string                 `json:"pack_key"`
	PolicyName string                 `json:"policy_name"`
	Attributes []aclCompilerAttribute `json:"attributes"`
}

type aclCompilerAttribute struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Quoted bool   `json:"quoted"`
}

func HandleGetACLCompilers(w http.ResponseWriter, r *http.Request) {
	capabilities := radius.ACLCompilerCapabilities()
	summary, events, err := aclCompilerEvidence()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	capabilitySummary := summarizeACLCompilerCapabilities(capabilities)
	status := "ready"
	message := "ACL compiler catalog is ready."
	if capabilitySummary["software_certified"].(int) == 0 {
		status = "blocked"
		message = "No software-certified ACL compilers are available."
	} else if summary.BlockedCount > 0 || summary.UnsupportedCount > 0 || capabilitySummary["unsupported"].(int) > 0 {
		status = "degraded"
		message = "One or more ACL compiler events or vendor packs require review."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version":   radius.ACLCompilerSchemaVersion,
			"compiler_version": radius.ACLCompilerVersion,
			"status":           status,
			"message":          message,
			"summary":          capabilitySummary,
			"evidence_summary": summary,
			"recent_events":    events,
			"capabilities":     capabilities,
			"rfcs":             []string{"RFC 2865"},
		},
	})
}

func HandleCompileACL(w http.ResponseWriter, r *http.Request) {
	var req radius.ACLCompilerRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	run, err := radius.CompileACLPolicyForPacks(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	for _, result := range run.Results {
		if err := recordACLCompilerResult("compile", strings.TrimSpace(req.PolicyName), actor, result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"run":          run,
	})
}

func HandleDecompileACL(w http.ResponseWriter, r *http.Request) {
	var req aclCompilerDecompileRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.PackKey) == "" {
		http.Error(w, "pack_key is required", http.StatusBadRequest)
		return
	}
	if len(req.Attributes) > 128 {
		http.Error(w, "attributes cannot contain more than 128 entries", http.StatusBadRequest)
		return
	}
	result, err := radius.DecompileACLAttributes(radius.ACLDecompileRequest{
		PackKey:    req.PackKey,
		PolicyName: req.PolicyName,
		Attributes: aclCompilerReplyItems(req.Attributes),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	if err := recordACLDecompilerResult(strings.TrimSpace(req.PolicyName), actor, result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"result":       result,
	})
}

func HandleListACLCompilerHistory(w http.ResponseWriter, r *http.Request) {
	summary, events, err := aclCompilerEvidence()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"summary":      summary,
		"history":      events,
	})
}

func aclCompilerEvidence() (db.ACLCompilerEventSummary, []db.ACLCompilerEvent, error) {
	if db.DB == nil {
		return db.ACLCompilerEventSummary{}, nil, nil
	}
	summary, err := db.GetACLCompilerEventSummary()
	if err != nil {
		return db.ACLCompilerEventSummary{}, nil, err
	}
	events, err := db.ListACLCompilerEvents(50)
	if err != nil {
		return db.ACLCompilerEventSummary{}, nil, err
	}
	return summary, events, nil
}

func summarizeACLCompilerCapabilities(capabilities []radius.ACLCompilerCapability) map[string]any {
	summary := map[string]any{
		"total_compilers":        len(capabilities),
		"software_certified":     0,
		"profile_reference":      0,
		"unsupported":            0,
		"line_rule_compilers":    0,
		"decompile_supported":    0,
		"external_cert_required": 0,
	}
	for _, capability := range capabilities {
		switch capability.CertificationState {
		case "software-certified":
			summary["software_certified"] = summary["software_certified"].(int) + 1
		case "profile-reference":
			summary["profile_reference"] = summary["profile_reference"].(int) + 1
		default:
			summary["unsupported"] = summary["unsupported"].(int) + 1
		}
		if capability.Limits.SupportsLineRules {
			summary["line_rule_compilers"] = summary["line_rule_compilers"].(int) + 1
		}
		if capability.Limits.SupportsDecompile {
			summary["decompile_supported"] = summary["decompile_supported"].(int) + 1
		}
		if capability.ExternalCertificationRequired {
			summary["external_cert_required"] = summary["external_cert_required"].(int) + 1
		}
	}
	return summary
}

func recordACLCompilerResult(operation, policyName, actor string, result radius.ACLCompileResult) error {
	diagnosticsJSON, _ := json.Marshal(result.Diagnostics)
	detailsJSON, _ := json.Marshal(map[string]any{
		"compiler_version":     result.CompilerVersion,
		"output_mode":          result.OutputMode,
		"certification_state":  result.CertificationState,
		"decompile_supported":  result.DecompileSupported,
		"warnings":             result.Warnings,
		"artifact_fingerprint": result.ArtifactFingerprint,
	})
	_, err := db.RecordACLCompilerEvent(db.ACLCompilerEventInput{
		Operation:           operation,
		Status:              result.Status,
		PackKey:             result.PackKey,
		PolicyName:          policyName,
		ASTFingerprint:      result.ASTFingerprint,
		ArtifactFingerprint: result.ArtifactFingerprint,
		ArtifactCount:       len(result.Artifacts),
		RuleCount:           result.RoundTrip.RuleCount,
		Lossless:            result.Lossless,
		DiagnosticsJSON:     string(diagnosticsJSON),
		DetailsJSON:         string(detailsJSON),
		Actor:               actor,
	})
	return err
}

func recordACLDecompilerResult(policyName, actor string, result radius.ACLDecompileResult) error {
	diagnosticsJSON, _ := json.Marshal(result.Diagnostics)
	detailsJSON, _ := json.Marshal(map[string]any{
		"compiler_version":     result.CompilerVersion,
		"output_mode":          result.OutputMode,
		"profile_references":   result.ProfileReferences,
		"warnings":             result.Warnings,
		"artifact_fingerprint": result.ArtifactFingerprint,
	})
	_, err := db.RecordACLCompilerEvent(db.ACLCompilerEventInput{
		Operation:           "decompile",
		Status:              result.Status,
		PackKey:             result.PackKey,
		PolicyName:          policyName,
		ASTFingerprint:      result.ACLFingerprint,
		ArtifactFingerprint: result.ArtifactFingerprint,
		ArtifactCount:       result.ArtifactCount,
		RuleCount:           len(result.Rules),
		Lossless:            result.ACLRoundTrip.Lossless,
		DiagnosticsJSON:     string(diagnosticsJSON),
		DetailsJSON:         string(detailsJSON),
		Actor:               actor,
	})
	return err
}

func aclCompilerReplyItems(attrs []aclCompilerAttribute) []radius.ReplyAttributeItem {
	out := make([]radius.ReplyAttributeItem, 0, len(attrs))
	for _, attr := range attrs {
		name := strings.TrimSpace(attr.Name)
		value := strings.TrimSpace(attr.Value)
		if name == "" || value == "" {
			continue
		}
		out = append(out, radius.ReplyAttributeItem{Name: name, Value: value, Quoted: attr.Quoted})
	}
	return out
}
