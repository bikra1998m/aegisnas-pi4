package acceptance

import (
	"encoding/json"
	"testing"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"go.uber.org/zap"
)

func TestPolicyEvaluation(t *testing.T) {
	// Insert a test policy rule
	matchCond := json.RawMessage(`{"authenticated": true, "role": "corp-standard"}`)
	_, err := db.DB.Exec(`INSERT INTO policy_rules (name, priority, match_conditions, action, vlan, bandwidth_profile, session_timeout)
		VALUES ('corp-rule', 10, ?, 'allow', 30, '100m-down-50m-up', 28800)`, matchCond)
	if err != nil {
		t.Fatalf("failed to insert policy rule: %v", err)
	}

	engine := policy.NewEngine(zap.NewNop())
	req := &policy.Request{
		Authenticated: true,
		Role:          "corp-standard",
		AuthMethod:    "eap-peap",
	}
	decision, err := engine.Evaluate(req)
	if err != nil {
		t.Fatalf("policy evaluation failed: %v", err)
	}
	if !decision.Allow {
		t.Error("expected allow, got deny")
	}
	if decision.VLAN == nil || *decision.VLAN != 30 {
		t.Errorf("expected VLAN 30, got %v", decision.VLAN)
	}
	if decision.BandwidthProfile == nil || *decision.BandwidthProfile != "100m-down-50m-up" {
		t.Errorf("expected bandwidth profile '100m-down-50m-up', got %v", decision.BandwidthProfile)
	}
}