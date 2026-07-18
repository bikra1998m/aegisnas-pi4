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
	assert.Equal(t, "complete", teap.SoftwareStatus)
	assert.Equal(t, "disabled", teap.EffectiveStatus)
	assert.False(t, teap.GeneratedInFreeRADIUS)

	fast, ok := methodReportByName(report.Methods, "fast")
	assert.True(t, ok)
	assert.Equal(t, "complete", fast.SoftwareStatus)
	assert.Equal(t, "disabled", fast.EffectiveStatus)

	pwd, ok := methodReportByName(report.Methods, "pwd")
	assert.True(t, ok)
	assert.Equal(t, "complete", pwd.SoftwareStatus)
	assert.Equal(t, "disabled", pwd.EffectiveStatus)
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
	cfg.Radius.EAP.Framework.AllowedMethods = append(cfg.Radius.EAP.Framework.AllowedMethods, "sim")
	decision := Evaluate(cfg, EvaluationRequest{
		Method:                      "sim",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
	})

	assert.Equal(t, "monitor_allowed", decision.Decision)
	assert.Contains(t, decision.Reason, "generated")
}

func TestFASTPWDReportAndEvaluationAcceptsMethods(t *testing.T) {
	cfg := eapFrameworkFASTPWDTestConfig()
	report := BuildFASTPWDReport(cfg, FASTPWDRuntimeSummary{})

	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.FAST.GeneratedInFreeRADIUS)
	assert.True(t, report.PWD.GeneratedInFreeRADIUS)
	assert.NotEmpty(t, report.Attributes)

	fastDecision := Evaluate(cfg, EvaluationRequest{
		Method:                      "fast",
		InnerMethod:                 "mschapv2",
		UserIdentity:                "alice@example.com",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TLSVersion:                  "1.3",
		CryptoBindingValid:          true,
		PACPresented:                true,
		EAPPayloadPresent:           true,
	})
	assert.Equal(t, "accepted", fastDecision.Decision)
	assert.Equal(t, "identity-failover", fastDecision.IdentitySource)

	pwdDecision := EvaluateFASTPWD(cfg, FASTPWDEvaluationRequest{
		Method:                      "pwd",
		Identity:                    "bob@example.com",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		PasswordProofValid:          true,
		PWDGroup:                    19,
		PWDServerID:                 "aegisnas-pwd",
	})
	assert.Equal(t, "accepted", pwdDecision.Decision)
}

func TestFASTPWDEvaluationRejectsMissingPACWhenRequired(t *testing.T) {
	cfg := eapFrameworkFASTPWDTestConfig()
	cfg.Radius.EAP.FAST.RequirePAC = true

	decision := EvaluateFASTPWD(cfg, FASTPWDEvaluationRequest{
		Method:                      "fast",
		InnerMethod:                 "mschapv2",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TLSVersion:                  "1.3",
		CryptoBindingValid:          true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "PAC is required")
}

func TestFASTPWDEvaluationRejectsPWDReplay(t *testing.T) {
	cfg := eapFrameworkFASTPWDTestConfig()

	decision := EvaluateFASTPWD(cfg, FASTPWDEvaluationRequest{
		Method:                      "pwd",
		Identity:                    "bob@example.com",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		PasswordProofValid:          true,
		PWDGroup:                    19,
		ReplayDetected:              true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "replay")
}

func TestTEAPReportAndEvaluationAcceptMachineUserChain(t *testing.T) {
	cfg := eapFrameworkTEAPTestConfig()
	report := BuildTEAPReport(cfg, TEAPRuntimeSummary{})

	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.Policy.GeneratedInFreeRADIUS)
	assert.Equal(t, "machine_then_user", report.Policy.ChainMode)
	assert.NotEmpty(t, report.TLVs)

	decision := EvaluateTEAPChain(cfg, TEAPChainEvaluationRequest{
		InnerMethod:                 "mschapv2",
		OuterIdentity:               "anonymous@example.com",
		UserIdentity:                "alice@example.com",
		MachineIdentity:             "host/laptop.example.com",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TLSVersion:                  "1.3",
		CryptoBindingValid:          true,
		IdentityTypePresented:       true,
		EAPPayloadPresent:           true,
		IntermediateResultPresent:   true,
		IntermediateResultSuccess:   true,
		FinalResultPresent:          true,
		FinalResultSuccess:          true,
		StepCount:                   2,
	})

	assert.Equal(t, "accepted", decision.Decision)
	assert.Equal(t, "complete", decision.ChainState)
	assert.Equal(t, "machine_user", decision.IdentityCorrelation)
}

func TestTEAPEvaluationRejectsMissingCryptoBinding(t *testing.T) {
	cfg := eapFrameworkTEAPTestConfig()
	decision := Evaluate(cfg, EvaluationRequest{
		Method:                      "teap",
		InnerMethod:                 "mschapv2",
		UserIdentity:                "alice@example.com",
		MachineIdentity:             "host/laptop.example.com",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		IdentityTypePresented:       true,
		StepCount:                   2,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "Crypto-Binding")
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

func eapFrameworkTEAPTestConfig() *config.Config {
	cfg := eapFrameworkTestConfig()
	cfg.Radius.EAP.DefaultType = "teap"
	cfg.Radius.EAP.TEAP = config.RadiusEAPTEAPConfig{
		Enabled:                true,
		DefaultInnerMethod:     "mschapv2",
		ChainMode:              "machine_then_user",
		RequireCryptoBinding:   true,
		RequireIdentityType:    true,
		RequireMachineIdentity: true,
		RequireUserIdentity:    true,
		AllowPAC:               true,
		PACProvisioning:        "authenticated",
		PACAuthorityID:         "aegisnas-teap",
		AllowEAPPayload:        true,
		MaxChainSteps:          2,
		SessionTTLSeconds:      900,
		EventRetentionLimit:    6000,
	}
	cfg.Radius.EAP.Framework.AllowedMethods = []string{"peap", "ttls", "tls", "teap"}
	cfg.Radius.EAP.Framework.IdentitySources[0].Methods = []string{"peap", "ttls", "teap"}
	cfg.Radius.EAP.Framework.MethodPolicies = append(cfg.Radius.EAP.Framework.MethodPolicies, config.RadiusEAPMethodPolicy{
		Method:                "teap",
		Enabled:               true,
		InnerMethods:          []string{"mschapv2", "gtc", "tls"},
		IdentitySource:        "identity-failover",
		AllowPasswordVerifier: false,
		MinTLSVersion:         "1.2",
		MaxTLSVersion:         "1.3",
	})
	return cfg
}

func eapFrameworkFASTPWDTestConfig() *config.Config {
	cfg := eapFrameworkTestConfig()
	cfg.Radius.EAP.FAST = config.RadiusEAPFASTConfig{
		Enabled:                    true,
		DefaultInnerMethod:         "mschapv2",
		RequireCryptoBinding:       true,
		AllowPAC:                   true,
		PACProvisioning:            "authenticated",
		PACAuthorityID:             "aegisnas-fast",
		PACLifetimeSeconds:         2592000,
		AllowAnonymousProvisioning: false,
		AllowEAPPayload:            true,
		MaxProvisioningAttempts:    3,
		SessionTTLSeconds:          900,
		EventRetentionLimit:        6000,
	}
	cfg.Radius.EAP.PWD = config.RadiusEAPPWDConfig{
		Enabled:              true,
		Group:                19,
		ServerID:             "aegisnas-pwd",
		RequireStrongGroup:   true,
		PasswordSource:       "identity-failover",
		AllowLocalVerifier:   true,
		RequireIdentity:      true,
		RequirePasswordProof: true,
		ReplayWindowSeconds:  30,
		FragmentSize:         1020,
		EventRetentionLimit:  6000,
	}
	cfg.Radius.EAP.Framework.AllowedMethods = []string{"peap", "ttls", "tls", "fast", "pwd"}
	cfg.Radius.EAP.Framework.IdentitySources[0].Methods = []string{"peap", "ttls", "fast", "pwd"}
	cfg.Radius.EAP.Framework.MethodPolicies = append(cfg.Radius.EAP.Framework.MethodPolicies,
		config.RadiusEAPMethodPolicy{
			Method:                "fast",
			Enabled:               true,
			InnerMethods:          []string{"mschapv2", "gtc", "tls"},
			IdentitySource:        "identity-failover",
			AllowPasswordVerifier: true,
			MinTLSVersion:         "1.2",
			MaxTLSVersion:         "1.3",
		},
		config.RadiusEAPMethodPolicy{
			Method:                "pwd",
			Enabled:               true,
			IdentitySource:        "identity-failover",
			AllowPasswordVerifier: true,
		},
	)
	return cfg
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
