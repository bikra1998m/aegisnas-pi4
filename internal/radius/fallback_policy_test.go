package radius

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestEvaluateFallbackPolicyAllowsAllowlistedRoleInEnforceMode(t *testing.T) {
	cfg := fallbackPolicyTestConfig()
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	decision := EvaluateFallbackPolicy(cfg, FallbackEvaluationRequest{
		Username:        "alice@example.com",
		Role:            "guest-basic",
		IdentitySource:  "local",
		Source:          "portal",
		OutageStartedAt: now.Add(-time.Minute),
		Now:             now,
	})

	assert.True(t, decision.Allowed)
	assert.Equal(t, "allowed", decision.Decision)
	assert.False(t, decision.MonitorOnly)
	assert.NotEmpty(t, decision.UsernameHash)
	assert.NotContains(t, decision.UsernameHash, "alice")
}

func TestEvaluateFallbackPolicyDeniesUnknownIdentityInEnforceMode(t *testing.T) {
	cfg := fallbackPolicyTestConfig()
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	decision := EvaluateFallbackPolicy(cfg, FallbackEvaluationRequest{
		Username:        "mallory@example.net",
		Role:            "contractor",
		IdentitySource:  "local",
		Source:          "portal",
		OutageStartedAt: now.Add(-time.Minute),
		Now:             now,
	})

	assert.False(t, decision.Allowed)
	assert.Equal(t, "denied", decision.Decision)
	assert.Contains(t, decision.Reason, "identity is not in the fallback allowlist")
}

func TestEvaluateFallbackPolicyMonitorAuditsButAllows(t *testing.T) {
	cfg := fallbackPolicyTestConfig()
	cfg.Radius.Upstream.FallbackPolicy.Mode = "monitor"
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	decision := EvaluateFallbackPolicy(cfg, FallbackEvaluationRequest{
		Username:        "mallory@example.net",
		Role:            "contractor",
		IdentitySource:  "local",
		Source:          "portal",
		OutageStartedAt: now.Add(-time.Minute),
		Now:             now,
	})

	assert.True(t, decision.Allowed)
	assert.Equal(t, "allowed", decision.Decision)
	assert.True(t, decision.MonitorOnly)
}

func TestEvaluateFallbackPolicyDeniesExpiredOutageWindow(t *testing.T) {
	cfg := fallbackPolicyTestConfig()
	now := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	decision := EvaluateFallbackPolicy(cfg, FallbackEvaluationRequest{
		Username:        "alice@example.com",
		Role:            "guest-basic",
		IdentitySource:  "local",
		Source:          "portal",
		OutageStartedAt: now.Add(-20 * time.Minute),
		Now:             now,
	})

	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "fallback outage window expired")
}

func TestBuildFallbackPolicyReportIncludesAuditSummary(t *testing.T) {
	setupFallbackPolicyDB(t)
	cfg := fallbackPolicyTestConfig()
	require.NoError(t, RecordFallbackDecision(cfg, FallbackDecision{
		Allowed:        true,
		Decision:       "allowed",
		Reason:         "fallback policy permits this identity",
		Mode:           "enforce",
		FailClosed:     true,
		Source:         "portal",
		IdentitySource: "local",
		Role:           "guest-basic",
		UsernameHash:   HashFallbackIdentity("alice@example.com"),
		UpstreamStatus: "down",
	}))

	report := BuildFallbackPolicyReport(cfg)

	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.AuditSummary.TotalRecords)
	assert.Equal(t, 1, report.Summary.AllowedRoleCount)
	assert.True(t, report.Summary.IdentityAllowlistSet)
	require.Len(t, report.Recent, 1)
	assert.Equal(t, "allowed", report.Recent[0].Decision)
}

func fallbackPolicyTestConfig() *config.Config {
	cfg := proxyRoutingTestConfig()
	cfg.Portal.RadiusAuth = true
	cfg.Portal.LocalFallback = true
	cfg.LDAP.Enabled = true
	cfg.Radius.Upstream.FallbackPolicy = config.RadiusFallbackPolicyConfig{
		Enabled:                  true,
		Mode:                     "enforce",
		FailClosed:               true,
		AllowPortalLocal:         true,
		AllowLDAP:                false,
		RequireIdentityAllowlist: true,
		MaxOutageSeconds:         900,
		StalePolicySeconds:       3600,
		RecoverySuccesses:        2,
		AllowedUsers:             []string{"breakglass@example.com"},
		AllowedRealms:            []string{"guest.example.com"},
		AllowedRoles:             []string{"guest-basic"},
		AuditEnabled:             true,
		RetentionLimit:           6000,
	}
	return cfg
}

func setupFallbackPolicyDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "fallback-policy-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, db.Init(dbPath))
	require.NoError(t, db.Migrate())
}
