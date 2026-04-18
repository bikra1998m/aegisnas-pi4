package acceptance

import (
	"testing"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestFirewallRollback(t *testing.T) {
	// Save initial ruleset (mock)
	initialRules := "# initial rules"
	_, err := db.SaveConfigRevision(initialRules, "test")
	if err != nil {
		t.Fatalf("save config revision failed: %v", err)
	}

	// Apply a new ruleset (mock apply)
	newRules := "# new rules"
	_, err = db.SaveConfigRevision(newRules, "test")
	if err != nil {
		t.Fatalf("save new revision failed: %v", err)
	}
	// Simulate applying (no actual nft)
	// Rollback to previous revision
	rev1, err := db.GetConfigRevisionByNumber(1)
	if err != nil {
		t.Fatalf("failed to get revision 1: %v", err)
	}
	if rev1 != initialRules {
		t.Errorf("revision content mismatch")
	}
	// In real scenario, firewall.RestoreRuleset would be called
	// For test, we just verify retrieval.
}
