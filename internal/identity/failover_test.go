package identity

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestBuildSourcePlanUsesConfiguredOrderAndLDAPConfig(t *testing.T) {
	setupIdentityFailoverServiceDB(t)
	cfg := identityFailoverTestConfig()
	cfg.Identity.Failover.SourceOrder = []string{"ldap-primary", "local"}
	cfg.LDAP.Enabled = true

	plan := BuildSourcePlan(cfg)

	require.GreaterOrEqual(t, len(plan), 2)
	assert.Equal(t, "ldap-primary", plan[0].Name)
	assert.Equal(t, "ldap", plan[0].Type)
	assert.True(t, plan[0].Executable)
	assert.Equal(t, "local", plan[1].Name)
	assert.True(t, plan[1].Executable)
}

func TestBuildSourcePlanSkipsOpenCircuitOnlyInEnforceMode(t *testing.T) {
	setupIdentityFailoverServiceDB(t)
	now := time.Now().UTC().Add(-10 * time.Second)
	for i := 0; i < 3; i++ {
		require.NoError(t, db.RecordIdentitySourceEvent(db.IdentitySourceEvent{
			ObservedAt:   now.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			SourceName:   "ldap-primary",
			SourceType:   "ldap",
			UsernameHash: db.HashIdentityUsername("alice@example.com"),
			Decision:     "failed",
			Reason:       "ldap timeout",
			CircuitState: "closed",
		}, nil, 10))
	}
	cfg := identityFailoverTestConfig()
	cfg.Identity.Failover.SourceOrder = []string{"ldap-primary"}
	cfg.Identity.Failover.Mode = "enforce"
	cfg.LDAP.Enabled = true

	enforcePlan := BuildSourcePlan(cfg)
	require.GreaterOrEqual(t, len(enforcePlan), 1)
	assert.Equal(t, "open", enforcePlan[0].CircuitState.State)
	assert.False(t, enforcePlan[0].Executable)

	cfg.Identity.Failover.Mode = "monitor"
	monitorPlan := BuildSourcePlan(cfg)
	require.GreaterOrEqual(t, len(monitorPlan), 1)
	assert.Equal(t, "open", monitorPlan[0].CircuitState.State)
	assert.True(t, monitorPlan[0].Executable)
}

func TestBuildFailoverReportIncludesAuditAndCacheSummary(t *testing.T) {
	setupIdentityFailoverServiceDB(t)
	cfg := identityFailoverTestConfig()
	cfg.Identity.Failover.Mode = "enforce"
	require.NoError(t, RecordEvent(FailoverPolicyFromConfig(cfg), EventRecord{
		SourceName: "local",
		SourceType: "local",
		Username:   "alice@example.com",
		Decision:   "accepted",
		Reason:     "credentials accepted",
	}))

	report := BuildFailoverReport(cfg)

	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, 1, report.AuditSummary.TotalRecords)
	assert.Equal(t, 1, report.Summary.ExecutableSourceCount)
	require.NotEmpty(t, report.Recent)
	assert.Equal(t, "accepted", report.Recent[0].Decision)
}

func identityFailoverTestConfig() *config.Config {
	return &config.Config{
		Portal: config.PortalConfig{Enabled: true, LocalFallback: true},
		LDAP:   config.LDAPConfig{Enabled: false},
		Identity: config.IdentityConfig{Failover: config.IdentityFailoverConfig{
			Enabled:                    true,
			Mode:                       "enforce",
			FailClosed:                 true,
			SourceOrder:                []string{"local"},
			MaxFailures:                3,
			CircuitOpenSeconds:         300,
			StaleCacheSeconds:          3600,
			SplitResultPolicy:          "deny",
			HealthCheckIntervalSeconds: 60,
			AuditEnabled:               true,
			RetentionLimit:             6000,
		}},
	}
}

func setupIdentityFailoverServiceDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "identity-failover-service-*.db")
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
