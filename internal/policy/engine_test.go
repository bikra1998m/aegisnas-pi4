package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestEngine_Evaluate(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(logger)

	// Insert test rules into DB (setup DB before test)
	// For simplicity, we'll mock the rule loading by directly testing matches function.

	req := &Request{
		Authenticated: true,
		Role:          "guest-basic",
		AuthMethod:    "pap",
	}

	// Create a rule that matches
	rule := Rule{
		Name:            "test-rule",
		Priority:        10,
		Enabled:         true,
		MatchConditions: json.RawMessage(`{"authenticated": true, "role": "guest-basic"}`),
		Action:          "allow",
	}
	var vlan int = 20
	rule.VLAN = &vlan
	aclPolicyName := "guest-internet"
	rule.ACLPolicyName = &aclPolicyName

	match, err := engine.matches(req, rule)
	require.NoError(t, err)
	assert.True(t, match)

	dec := ruleToDecision(&rule)
	assert.True(t, dec.Allow)
	assert.Equal(t, 20, *dec.VLAN)
	assert.Equal(t, "guest-internet", *dec.ACLPolicyName)
}

func TestMatches_MultipleConditions(t *testing.T) {
	logger := zap.NewNop()
	engine := NewEngine(logger)

	req := &Request{
		Authenticated: true,
		Role:          "corp-standard",
		Groups:        []string{"engineering", "staff"},
		SSID:          "CorpWiFi",
	}

	rule := Rule{
		MatchConditions: json.RawMessage(`{"authenticated": true, "group": "engineering", "ssid": "CorpWiFi"}`),
	}
	match, err := engine.matches(req, rule)
	require.NoError(t, err)
	assert.True(t, match)

	// Negative case
	rule2 := Rule{
		MatchConditions: json.RawMessage(`{"authenticated": true, "group": "marketing"}`),
	}
	match, err = engine.matches(req, rule2)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestEngineTenantPolicySetDoesNotFallbackToGlobalPolicy(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tenant-policy.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
database:
  path: `+strconvQuote(dbPath)+`
health:
  port: 8080
radius:
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
policy:
  typed_engine_enabled: true
  mode: enforce
  fail_closed: true
  audit_enabled: true
  max_policy_set_depth: 8
governance:
  delegated_admin_enabled: true
  multi_tenant_enabled: true
  tenant_claim: tenant
  isolation_mode: enforce
  fail_closed: true
  tenant_profile_required: false
  enforce_policy_set_ownership: true
  enforce_resource_ownership: true
  resource_audit_enabled: true
ldap:
  enabled: true
`), 0644))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(dbPath))
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Migrate())

	globalContent := `{"schema_version":1,"key":"default","name":"Global","enabled":true,"rules":[{"name":"global-allow","priority":100,"enabled":true,"match_conditions":{"field":"authenticated","op":"eq","value":true},"action":"allow"}]}`
	tenantContent := `{"schema_version":1,"key":"default","tenant":"tenant-a","name":"Tenant A","enabled":true,"rules":[{"name":"tenant-a-allow","priority":100,"enabled":true,"match_conditions":{"field":"tenant","op":"eq","value":"tenant-a"},"action":"allow"}]}`
	global, err := db.CreatePolicySetVersion(context.Background(), db.CreatePolicySetVersionRequest{
		SetKey:           "default",
		ContentJSON:      globalContent,
		ContentSHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicySHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RuleCount:        1,
		MaxDepth:         1,
		ApprovalRequired: false,
		Status:           db.PolicySetStatusApproved,
		CreatedBy:        "maker",
	})
	require.NoError(t, err)
	tenant, err := db.CreatePolicySetVersion(context.Background(), db.CreatePolicySetVersionRequest{
		SetKey:           "default",
		Tenant:           "tenant-a",
		ContentJSON:      tenantContent,
		ContentSHA256:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicySHA256:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		RuleCount:        1,
		MaxDepth:         1,
		ApprovalRequired: false,
		Status:           db.PolicySetStatusApproved,
		CreatedBy:        "maker",
	})
	require.NoError(t, err)

	tx, err := db.DB.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = db.MarkPolicySetVersionActiveTx(tx, global.ID, "admin", "activate global")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	tx, err = db.DB.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = db.MarkPolicySetVersionActiveTx(tx, tenant.ID, "admin", "activate tenant")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	engine := NewEngine(zap.NewNop())
	tenantResult, err := engine.EvaluateDetailed(&Request{Authenticated: true, Tenant: "tenant-a"})
	require.NoError(t, err)
	assert.True(t, tenantResult.Decision.Allow)
	require.Len(t, tenantResult.MatchedRules, 1)
	assert.Equal(t, "default/tenant-a-allow", tenantResult.MatchedRules[0].Name)

	otherTenantResult, err := engine.EvaluateDetailed(&Request{Authenticated: true, Tenant: "tenant-b"})
	require.NoError(t, err)
	assert.False(t, otherTenantResult.Decision.Allow)
	assert.Empty(t, otherTenantResult.MatchedRules)
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
