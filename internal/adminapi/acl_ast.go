package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type aclASTNormalizeRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	InboundACL  string               `json:"inbound_acl"`
	OutboundACL string               `json:"outbound_acl"`
	Rules       []radius.ACLRule     `json:"rules"`
	ACLAST      *radius.ACLPolicyAST `json:"acl_ast,omitempty"`
}

type aclASTPolicyStatus struct {
	ID             int                    `json:"id"`
	Name           string                 `json:"name"`
	Enabled        bool                   `json:"enabled"`
	RuleCount      int                    `json:"rule_count"`
	ASTRuleCount   int                    `json:"ast_rule_count"`
	ObjectGroups   int                    `json:"object_groups"`
	ServiceGroups  int                    `json:"service_groups"`
	Lossless       bool                   `json:"lossless"`
	ASTFingerprint string                 `json:"ast_fingerprint"`
	Diagnostics    []radius.ACLDiagnostic `json:"diagnostics,omitempty"`
	UpdatedAt      string                 `json:"updated_at,omitempty"`
}

func HandleGetACLASTReport(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		http.Error(w, "database not initialized", http.StatusInternalServerError)
		return
	}
	policies, err := loadACLASTPolicyStatuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary := map[string]any{
		"total_policies":        len(policies),
		"ast_backed_policies":   0,
		"non_lossless_policies": 0,
		"diagnostic_count":      0,
		"rule_count":            0,
		"ast_rule_count":        0,
		"object_group_count":    0,
		"service_group_count":   0,
	}
	for _, policy := range policies {
		if policy.ASTFingerprint != "" {
			summary["ast_backed_policies"] = summary["ast_backed_policies"].(int) + 1
		}
		if !policy.Lossless {
			summary["non_lossless_policies"] = summary["non_lossless_policies"].(int) + 1
		}
		summary["diagnostic_count"] = summary["diagnostic_count"].(int) + len(policy.Diagnostics)
		summary["rule_count"] = summary["rule_count"].(int) + policy.RuleCount
		summary["ast_rule_count"] = summary["ast_rule_count"].(int) + policy.ASTRuleCount
		summary["object_group_count"] = summary["object_group_count"].(int) + policy.ObjectGroups
		summary["service_group_count"] = summary["service_group_count"].(int) + policy.ServiceGroups
	}
	status := "ready"
	message := "ACL AST policy normalization is ready."
	if summary["non_lossless_policies"].(int) > 0 {
		status = "degraded"
		message = "One or more ACL policies contain AST fields that cannot be rendered losslessly into flat RADIUS ACL rules."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report": map[string]any{
			"schema_version": radius.ACLASTSchemaVersion,
			"status":         status,
			"message":        message,
			"summary":        summary,
			"policies":       policies,
			"rfcs":           []string{"RFC 2865"},
		},
	})
}

func HandleNormalizeACLAST(w http.ResponseWriter, r *http.Request) {
	var req aclASTNormalizeRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	normalization, err := radius.NormalizeACLPolicyIntent(req.Name, req.Description, req.InboundACL, req.OutboundACL, req.Rules, req.ACLAST)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":   radius.ACLASTSchemaVersion,
		"acl_ast":          normalization.AST,
		"normalized_rules": normalization.Rules,
		"acl_fingerprint":  normalization.Fingerprint,
		"acl_diagnostics":  normalization.Diagnostics,
		"acl_round_trip":   normalization.RoundTrip,
	})
}

func loadACLASTPolicyStatuses() ([]aclASTPolicyStatus, error) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), COALESCE(inbound_acl, ''), COALESCE(outbound_acl, ''),
			rules_json, COALESCE(ast_json, '{}'), COALESCE(ast_fingerprint, ''), COALESCE(ast_diagnostics_json, '[]'), enabled, updated_at
		FROM acl_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []aclASTPolicyStatus
	for rows.Next() {
		var (
			id                           int
			name, description            string
			inboundACL, outboundACL      string
			rulesJSON, astJSON           string
			fingerprint, diagnosticsJSON string
			enabled                      bool
			updatedAt                    string
		)
		if err := rows.Scan(&id, &name, &description, &inboundACL, &outboundACL, &rulesJSON, &astJSON, &fingerprint, &diagnosticsJSON, &enabled, &updatedAt); err != nil {
			return nil, err
		}
		var rules []radius.ACLRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			return nil, fmt.Errorf("decode ACL policy %q rules: %w", name, err)
		}
		var ast radius.ACLPolicyAST
		if strings.TrimSpace(astJSON) != "" && strings.TrimSpace(astJSON) != "{}" {
			if err := json.Unmarshal([]byte(astJSON), &ast); err != nil {
				return nil, fmt.Errorf("decode ACL policy %q AST: %w", name, err)
			}
		}
		normalization, err := radius.NormalizeACLPolicyIntent(name, description, inboundACL, outboundACL, rules, &ast)
		if err != nil {
			return nil, fmt.Errorf("normalize ACL policy %q: %w", name, err)
		}
		var diagnostics []radius.ACLDiagnostic
		_ = json.Unmarshal([]byte(diagnosticsJSON), &diagnostics)
		if len(diagnostics) == 0 {
			diagnostics = normalization.Diagnostics
		}
		if strings.TrimSpace(fingerprint) == "" {
			fingerprint = normalization.Fingerprint
		}
		out = append(out, aclASTPolicyStatus{
			ID:             id,
			Name:           name,
			Enabled:        enabled,
			RuleCount:      len(normalization.Rules),
			ASTRuleCount:   len(normalization.AST.Rules),
			ObjectGroups:   len(normalization.AST.ObjectGroups),
			ServiceGroups:  len(normalization.AST.ServiceGroups),
			Lossless:       normalization.RoundTrip.Lossless,
			ASTFingerprint: fingerprint,
			Diagnostics:    diagnostics,
			UpdatedAt:      updatedAt,
		})
	}
	return out, rows.Err()
}
