package adminapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type aclPolicyData struct {
	Name        string
	Description string
	InboundACL  string
	OutboundACL string
	Rules       []radius.ACLRule
	RulesJSON   string
	Enabled     bool
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
	policy.Rules, err = radius.NormalizeACLRules(policy.Rules)
	if err != nil {
		return policy, err
	}
	rulesData, err = json.Marshal(policy.Rules)
	if err != nil {
		return policy, err
	}
	policy.RulesJSON = string(rulesData)
	return policy, nil
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
		"outbound_acl": policy.OutboundACL, "rules": policy.Rules, "enabled": policy.Enabled,
	}
	if err := stageChange(r, "acl_policy", resourceID, operation, normalized); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "staged"})
}

func HandleListACLPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), COALESCE(inbound_acl, ''), COALESCE(outbound_acl, ''), rules_json, enabled, created_at, updated_at
		FROM acl_policies ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	policies := make([]map[string]any, 0)
	for rows.Next() {
		var id int
		var name, description, inboundACL, outboundACL, rulesJSON, createdAt, updatedAt string
		var enabled bool
		if err := rows.Scan(&id, &name, &description, &inboundACL, &outboundACL, &rulesJSON, &enabled, &createdAt, &updatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var rules []radius.ACLRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			http.Error(w, fmt.Sprintf("decode ACL policy %q: %v", name, err), http.StatusInternalServerError)
			return
		}
		policies = append(policies, map[string]any{
			"id": id, "name": name, "description": description, "inbound_acl": inboundACL,
			"outbound_acl": outboundACL, "rules": rules, "enabled": enabled,
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
	if db.DB == nil || strings.TrimSpace(name) == "" {
		return aclPolicyData{}, false, nil
	}
	var policy aclPolicyData
	err := db.DB.QueryRow(`SELECT name, COALESCE(description, ''), COALESCE(inbound_acl, ''), COALESCE(outbound_acl, ''), rules_json, enabled
		FROM acl_policies WHERE name = ? AND enabled = 1`, strings.TrimSpace(name)).Scan(
		&policy.Name, &policy.Description, &policy.InboundACL, &policy.OutboundACL, &policy.RulesJSON, &policy.Enabled,
	)
	if err == sql.ErrNoRows {
		return aclPolicyData{}, false, nil
	}
	if err != nil {
		return aclPolicyData{}, false, err
	}
	if err := json.Unmarshal([]byte(policy.RulesJSON), &policy.Rules); err != nil {
		return aclPolicyData{}, false, fmt.Errorf("decode ACL policy %q: %w", name, err)
	}
	policy.Rules, err = radius.NormalizeACLRules(policy.Rules)
	if err != nil {
		return aclPolicyData{}, false, fmt.Errorf("ACL policy %q: %w", name, err)
	}
	return policy, true, nil
}
