package adminapi

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/network"
)

func TestApplyNetworkServicesRollsBackOnValidationFailure(t *testing.T) {
	originalSaveSnapshot := saveNetworkSnapshotFn
	originalApplyManaged := applyManagedNetworkFn
	originalApplyFirewall := applyFirewallRulesetFn
	originalRestoreSnapshot := restoreNetworkSnapshotFn
	originalValidate := validateAppliedNetworkFn
	originalBuildDNS := buildDNSMasqConfigFn
	originalApplyDNS := applyDNSMasqContentFn
	originalBuildFirewall := buildFirewallRulesFn
	originalAssessRisk := assessApplyRiskFn
	originalGetRuntimeStatus := getRuntimeStatusFn
	defer func() {
		saveNetworkSnapshotFn = originalSaveSnapshot
		applyManagedNetworkFn = originalApplyManaged
		applyFirewallRulesetFn = originalApplyFirewall
		restoreNetworkSnapshotFn = originalRestoreSnapshot
		validateAppliedNetworkFn = originalValidate
		buildDNSMasqConfigFn = originalBuildDNS
		applyDNSMasqContentFn = originalApplyDNS
		buildFirewallRulesFn = originalBuildFirewall
		assessApplyRiskFn = originalAssessRisk
		getRuntimeStatusFn = originalGetRuntimeStatus
	}()

	cfg := &config.Config{}
	cfg.Database.Path = t.TempDir() + "/aegisnas.db"

	saveNetworkSnapshotFn = func(cfg *config.Config, snapshot network.Snapshot) error { return nil }
	applyManagedNetworkFn = func(cfg *config.Config) error { return nil }
	buildDNSMasqConfigFn = func(cfg *config.Config) (string, error) { return "dnsmasq", nil }
	applyDNSMasqContentFn = func(enabled bool, content string) error { return nil }
	buildFirewallRulesFn = func(cfg *config.Config) (string, error) { return "table inet aegis {}", nil }
	applyFirewallRulesetFn = func(content string) error { return nil }
	getRuntimeStatusFn = func(component string) (*db.RuntimeStatus, error) { return nil, nil }

	rolledBack := false
	restoreNetworkSnapshotFn = func(cfg *config.Config, snapshot network.Snapshot) error {
		rolledBack = true
		return nil
	}
	validateAppliedNetworkFn = func(cfg *config.Config) (network.ValidationReport, error) {
		report := network.NewValidationReport()
		report.AddCheck("service:dnsmasq", "failed", "dnsmasq is not active after apply.")
		return report, nil
	}
	assessApplyRiskFn = func(cfg *config.Config, current, desired network.AppliedState) network.ApplyRiskAssessment {
		return network.ApplyRiskAssessment{}
	}

	result, err := applyNetworkServices(cfg, "tester", "")

	require.Error(t, err)
	assert.True(t, rolledBack)
	assert.NotEmpty(t, result.BackupID)
	assert.Contains(t, err.Error(), "post-apply validation failed")
	assert.Contains(t, err.Error(), "automatic rollback restored snapshot")
}

func TestValidateAppliedNetworkServicesHealthy(t *testing.T) {
	originalHealthCheck := checkLocalHealthEndpointFn
	originalServiceActive := checkSystemdServiceActiveFn
	defer func() {
		checkLocalHealthEndpointFn = originalHealthCheck
		checkSystemdServiceActiveFn = originalServiceActive
	}()

	cfg := &config.Config{}
	cfg.AdminPort = 8083
	cfg.Health.Port = 8080
	cfg.Portal.Port = 8081
	cfg.DHCP.Enabled = true

	checkSystemdServiceActiveFn = func(name string) (bool, string, error) {
		return true, "active", nil
	}
	checkLocalHealthEndpointFn = func(name string, port int) error { return nil }

	report, err := validateAppliedNetworkServices(cfg)

	require.NoError(t, err)
	assert.True(t, report.Healthy)
	assert.NotEmpty(t, report.Checks)
}

func TestValidateAppliedNetworkServicesFlagsHealthFailures(t *testing.T) {
	originalHealthCheck := checkLocalHealthEndpointFn
	originalServiceActive := checkSystemdServiceActiveFn
	defer func() {
		checkLocalHealthEndpointFn = originalHealthCheck
		checkSystemdServiceActiveFn = originalServiceActive
	}()

	cfg := &config.Config{}
	cfg.AdminPort = 8083
	cfg.Health.Port = 8080
	cfg.Portal.Port = 8081
	cfg.DHCP.Enabled = true

	checkSystemdServiceActiveFn = func(name string) (bool, string, error) {
		return false, "failed", nil
	}
	checkLocalHealthEndpointFn = func(name string, port int) error {
		if name == "admin_api" {
			return errors.New("admin_api health endpoint on port 8083 did not respond")
		}
		return nil
	}

	report, err := validateAppliedNetworkServices(cfg)

	require.NoError(t, err)
	assert.False(t, report.Healthy)
	assert.Contains(t, report.Summary(), "dnsmasq is not active after apply")
	assert.Contains(t, report.Summary(), "admin_api health endpoint")
}

func TestApplyNetworkServicesRequiresConfirmationForRiskyChanges(t *testing.T) {
	originalAssessRisk := assessApplyRiskFn
	originalGetRuntimeStatus := getRuntimeStatusFn
	defer func() {
		assessApplyRiskFn = originalAssessRisk
		getRuntimeStatusFn = originalGetRuntimeStatus
	}()

	cfg := &config.Config{}
	cfg.Database.Path = t.TempDir() + "/aegisnas.db"

	assessApplyRiskFn = func(cfg *config.Config, current, desired network.AppliedState) network.ApplyRiskAssessment {
		return network.ApplyRiskAssessment{
			RequiresConfirmation: true,
			ConfirmationPhrase:   network.ApplyConfirmationPhrase,
			Summary:              "risk",
		}
	}
	getRuntimeStatusFn = func(component string) (*db.RuntimeStatus, error) { return nil, nil }

	result, err := applyNetworkServices(cfg, "tester", "")

	require.Error(t, err)
	assert.Equal(t, network.ApplyConfirmationPhrase, result.Risk.ConfirmationPhrase)
	assert.Contains(t, err.Error(), "confirmation phrase")
}
