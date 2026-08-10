package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type aclPolicyData struct {
	Name               string
	Description        string
	InboundACL         string
	OutboundACL        string
	Rules              []radius.ACLRule
	RulesJSON          string
	ACLAST             radius.ACLPolicyAST
	ACLASTJSON         string
	ASTFingerprint     string
	ASTDiagnostics     []radius.ACLDiagnostic
	ASTDiagnosticsJSON string
	ACLRoundTrip       radius.ACLRoundTrip
	Enabled            bool
}

func parseACLPolicyPayload(data map[string]any) (aclPolicyData, error) {
	policy := aclPolicyData{
		Name:        strings.TrimSpace(stringValue(data, "name")),
		Description: strings.TrimSpace(stringValue(data, "description")),
		InboundACL:  strings.TrimSpace(stringValue(data, "inbound_acl")),
		OutboundACL: strings.TrimSpace(stringValue(data, "outbound_acl")),
		Enabled:     true,
	}
	if policy.Name == "" {
		return policy, fmt.Errorf("name is required")
	}
	if len(policy.Name) > 128 {
		return policy, fmt.Errorf("name cannot exceed 128 characters")
	}
	if len(policy.Description) > 2048 {
		return policy, fmt.Errorf("description cannot exceed 2048 characters")
	}
	if len(policy.InboundACL) > 255 || len(policy.OutboundACL) > 255 {
		return policy, fmt.Errorf("inbound_acl and outbound_acl cannot exceed 255 characters")
	}
	if value, ok := data["enabled"]; ok && value != nil {
		enabled, valid := value.(bool)
		if !valid {
			return policy, fmt.Errorf("enabled must be a boolean")
		}
		policy.Enabled = enabled
	}

	rulesValue := data["rules"]
	if rulesValue == nil {
		rulesValue = []any{}
	}
	rulesData, err := json.Marshal(rulesValue)
	if err != nil {
		return policy, fmt.Errorf("rules: %w", err)
	}
	if raw, ok := rulesValue.(string); ok {
		rulesData = []byte(raw)
	}
	if err := json.Unmarshal(rulesData, &policy.Rules); err != nil {
		return policy, fmt.Errorf("rules must be an array of ACL rules")
	}
	if len(policy.Rules) > 64 {
		return policy, fmt.Errorf("rules cannot contain more than 64 rules")
	}
	var aclAST *radius.ACLPolicyAST
	if value, ok := data["acl_ast"]; ok && value != nil {
		aclAST, err = parseACLASTValue(value)
		if err != nil {
			return policy, err
		}
	}
	normalization, err := radius.NormalizeACLPolicyIntent(policy.Name, policy.Description, policy.InboundACL, policy.OutboundACL, policy.Rules, aclAST)
	if err != nil {
		return policy, err
	}
	policy.Rules = normalization.Rules
	rulesData, err = json.Marshal(policy.Rules)
	if err != nil {
		return policy, err
	}
	policy.RulesJSON = string(rulesData)
	astData, err := json.Marshal(normalization.AST)
	if err != nil {
		return policy, err
	}
	policy.ACLAST = normalization.AST
	policy.ACLASTJSON = string(astData)
	policy.ASTFingerprint = normalization.Fingerprint
	policy.ASTDiagnostics = normalization.Diagnostics
	diagnosticsData, err := json.Marshal(normalization.Diagnostics)
	if err != nil {
		return policy, err
	}
	policy.ASTDiagnosticsJSON = string(diagnosticsData)
	policy.ACLRoundTrip = normalization.RoundTrip
	return policy, nil
}

func parseACLASTValue(value any) (*radius.ACLPolicyAST, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("acl_ast: %w", err)
	}
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, nil
		}
		raw = []byte(text)
	}
	var ast radius.ACLPolicyAST
	if err := json.Unmarshal(raw, &ast); err != nil {
		return nil, fmt.Errorf("acl_ast must be a valid ACL AST object")
	}
	return &ast, nil
}

func stageACLPolicy(w http.ResponseWriter, r *http.Request, resourceID, operation string) {
	var payload map[string]any
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	policy, err := parseACLPolicyPayload(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	normalized := map[string]any{
		"name": policy.Name, "description": policy.Description, "inbound_acl": policy.InboundACL,
		"outbound_acl": policy.OutboundACL, "rules": policy.Rules, "acl_ast": policy.ACLAST,
		"ast_fingerprint": policy.ASTFingerprint, "ast_diagnostics": policy.ASTDiagnostics,
		"acl_round_trip": policy.ACLRoundTrip, "enabled": policy.Enabled,
	}
	if err := stageChange(r, "acl_policy", resourceID, operation, normalized); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "staged"})
}

func HandleListACLPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), COALESCE(inbound_acl, ''), COALESCE(outbound_acl, ''), rules_json,
			COALESCE(ast_json, '{}'), COALESCE(ast_fingerprint, ''), COALESCE(ast_diagnostics_json, '[]'),
			enabled, created_at, updated_at
		FROM acl_policies ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	policies := make([]map[string]any, 0)
	for rows.Next() {
		var id int
		var name, description, inboundACL, outboundACL, rulesJSON, astJSON, astFingerprint, diagnosticsJSON, createdAt, updatedAt string
		var enabled bool
		if err := rows.Scan(&id, &name, &description, &inboundACL, &outboundACL, &rulesJSON, &astJSON, &astFingerprint, &diagnosticsJSON, &enabled, &createdAt, &updatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var rules []radius.ACLRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			http.Error(w, fmt.Sprintf("decode ACL policy %q: %v", name, err), http.StatusInternalServerError)
			return
		}
		var ast radius.ACLPolicyAST
		if strings.TrimSpace(astJSON) != "" && strings.TrimSpace(astJSON) != "{}" {
			if err := json.Unmarshal([]byte(astJSON), &ast); err != nil {
				http.Error(w, fmt.Sprintf("decode ACL policy AST %q: %v", name, err), http.StatusInternalServerError)
				return
			}
		}
		normalization, err := radius.NormalizeACLPolicyIntent(name, description, inboundACL, outboundACL, rules, &ast)
		if err != nil {
			http.Error(w, fmt.Sprintf("normalize ACL policy %q: %v", name, err), http.StatusInternalServerError)
			return
		}
		var diagnostics []radius.ACLDiagnostic
		_ = json.Unmarshal([]byte(diagnosticsJSON), &diagnostics)
		if len(diagnostics) == 0 {
			diagnostics = normalization.Diagnostics
		}
		if strings.TrimSpace(astFingerprint) == "" {
			astFingerprint = normalization.Fingerprint
		}
		policies = append(policies, map[string]any{
			"id": id, "name": name, "description": description, "inbound_acl": inboundACL,
			"outbound_acl": outboundACL, "rules": normalization.Rules,
			"acl_ast": normalization.AST, "ast_fingerprint": astFingerprint,
			"ast_diagnostics": diagnostics, "acl_round_trip": normalization.RoundTrip,
			"enabled":    enabled,
			"created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func HandleCreateACLPolicy(w http.ResponseWriter, r *http.Request) {
	stageACLPolicy(w, r, "", "create")
}

func HandleUpdateACLPolicy(w http.ResponseWriter, r *http.Request) {
	stageACLPolicy(w, r, chi.URLParam(r, "id"), "update")
}

func HandleDeleteACLPolicy(w http.ResponseWriter, r *http.Request) {
	if err := stageChange(r, "acl_policy", chi.URLParam(r, "id"), "delete", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "staged"})
}

func loadACLPolicy(name string) (aclPolicyData, bool, error) {
	stored, found, err := radius.LoadACLPolicy(name)
	if err != nil || !found {
		return aclPolicyData{}, found, err
	}
	rulesJSON, err := json.Marshal(stored.Rules)
	if err != nil {
		return aclPolicyData{}, false, err
	}
	return aclPolicyData{
		Name: stored.Name, Description: stored.Description, InboundACL: stored.InboundACL,
		OutboundACL: stored.OutboundACL, Rules: stored.Rules, RulesJSON: string(rulesJSON),
		ACLAST: stored.AST, ASTFingerprint: stored.ASTFingerprint,
		ASTDiagnostics: stored.ASTDiagnostics, ACLRoundTrip: stored.RoundTrip, Enabled: true,
	}, true, nil
}
