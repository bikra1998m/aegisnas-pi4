package eap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestEAPFrameworkReportCatalogsGeneratedAndPlannedMethods(t *testing.T) {
	cfg := eapFrameworkTestConfig()
	report := BuildFrameworkReport(cfg, RuntimeSummary{TotalEvents: 3})

	assert.Equal(t, FrameworkSchemaVersion, report.SchemaVersion)
	assert.Equal(t, "ready", report.Status)
	assert.Equal(t, "enforce", report.Policy.Mode)
	assert.Equal(t, 3, report.Summary.EnabledMethodCount)
	assert.Equal(t, 3, report.Summary.GeneratedMethodCount)
	assert.GreaterOrEqual(t, report.Summary.PlannedMethodCount, 1)
	assert.Equal(t, 0, report.Runtime.Rejected)

	teap, ok := methodReportByName(report.Methods, "teap")
	assert.True(t, ok)
	assert.Equal(t, "planned", teap.EffectiveStatus)
	assert.Contains(t, teap.Dependencies, "NAS-0023")
}

func TestEAPFrameworkEvaluateRejectsMissingMessageAuthenticatorInEnforceMode(t *testing.T) {
	cfg := eapFrameworkTestConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Method:            "peap",
		InnerMethod:       "mschapv2",
		EAPMessagePresent: true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "Message-Authenticator")
}

func TestEAPFrameworkEvaluateMonitorAllowsUnsupportedMethod(t *testing.T) {
	cfg := eapFrameworkTestConfig()
	cfg.Radius.EAP.Framework.Mode = "monitor"
	cfg.Radius.EAP.Framework.AllowedMethods = append(cfg.Radius.EAP.Framework.AllowedMethods, "teap")
	decision := Evaluate(cfg, EvaluationRequest{
		Method:                      "teap",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
	})

	assert.Equal(t, "monitor_allowed", decision.Decision)
	assert.Contains(t, decision.Reason, "generated")
}

func TestEAPFrameworkEvaluateAcceptsGeneratedMethod(t *testing.T) {
	cfg := eapFrameworkTestConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Method:                      "ttls",
		InnerMethod:                 "pap",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		IdentitySource:              "identity-failover",
	})

	assert.Equal(t, "accepted", decision.Decision)
	assert.Equal(t, "identity-failover", decision.IdentitySource)
}

func eapFrameworkTestConfig() *config.Config {
	return &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 2048,
			EAP: config.RadiusEAPConfig{
				DefaultType:   "peap",
				PEAPInner:     "mschapv2",
				TTLSInner:     "pap",
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
				Framework: config.RadiusEAPFramework{
					Enabled:                     true,
					Mode:                        "enforce",
					FailClosed:                  true,
					AllowedMethods:              []string{"peap", "ttls", "tls"},
					AllowedInnerMethods:         []string{"mschapv2", "pap", "chap", "gtc", "tls"},
					DefaultOuterIdentitySource:  "configured-default",
					DefaultInnerIdentitySource:  "identity-failover",
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      true,
					TelemetryEnabled:            true,
					EventRetentionLimit:         6000,
					MethodTimeoutSeconds:        60,
					FragmentSize:                1024,
					IdentitySources: []config.RadiusEAPIdentitySource{
						{Name: "identity-failover", Source: "identity_failover", Enabled: true, Methods: []string{"peap", "ttls"}, AllowPasswordVerifier: true, Priority: 10},
						{Name: "certificate-subject", Source: "certificate", Enabled: true, Methods: []string{"tls"}, AllowCertificateSubject: true, Priority: 20},
					},
					MethodPolicies: []config.RadiusEAPMethodPolicy{
						{Method: "peap", Enabled: true, InnerMethods: []string{"mschapv2", "gtc"}, IdentitySource: "identity-failover", AllowPasswordVerifier: true, MinTLSVersion: "1.2", MaxTLSVersion: "1.3"},
						{Method: "ttls", Enabled: true, InnerMethods: []string{"mschapv2", "pap"}, IdentitySource: "identity-failover", AllowPasswordVerifier: true, MinTLSVersion: "1.2", MaxTLSVersion: "1.3"},
						{Method: "tls", Enabled: true, IdentitySource: "certificate-subject", RequireCertificate: true, AllowPasswordVerifier: false, MinTLSVersion: "1.2", MaxTLSVersion: "1.3"},
					},
				},
			},
		},
	}
}
