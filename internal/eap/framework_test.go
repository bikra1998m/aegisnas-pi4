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
	assert.Equal(t, 0, report.Summary.PlannedMethodCount)
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

	sim, ok := methodReportByName(report.Methods, "sim")
	assert.True(t, ok)
	assert.Equal(t, "complete", sim.SoftwareStatus)
	assert.Equal(t, "disabled", sim.EffectiveStatus)
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
	cfg.Radius.EAP.Framework.AllowedMethods = append(cfg.Radius.EAP.Framework.AllowedMethods, "leap")
	decision := Evaluate(cfg, EvaluationRequest{
		Method:                      "leap",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
	})

	assert.Equal(t, "monitor_allowed", decision.Decision)
	assert.Contains(t, decision.Reason, "generated")
}

func TestSIMAKAReportAndEvaluationAcceptsMobileMethods(t *testing.T) {
	cfg := eapFrameworkSIMAKATestConfig()
	report := BuildSIMAKAReport(cfg, SIMAKARuntimeSummary{})

	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.Policy.GeneratedInFreeRADIUS)
	assert.ElementsMatch(t, []string{"sim", "aka", "aka-prime"}, report.Policy.GeneratedMethods)
	assert.NotEmpty(t, report.Attributes)

	simDecision := Evaluate(cfg, EvaluationRequest{
		Method:                      "sim",
		UserIdentity:                "001010123456789",
		PermanentIdentity:           "001010123456789",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		VectorProviderAvailable:     true,
		VectorAvailable:             true,
		VectorFresh:                 true,
		VectorAgeSeconds:            30,
		TripletCount:                2,
		RESValid:                    true,
	})
	assert.Equal(t, "accepted", simDecision.Decision)
	assert.Equal(t, "sim-aka-vector-provider", simDecision.IdentitySource)

	akaPrimeDecision := EvaluateSIMAKA(cfg, SIMAKAEvaluationRequest{
		Method:                      "aka-prime",
		PermanentIdentity:           "001010123456789",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		VectorProviderAvailable:     true,
		VectorAvailable:             true,
		VectorFresh:                 true,
		VectorAgeSeconds:            45,
		QuintupletCount:             1,
		RESValid:                    true,
		MACValid:                    true,
		AUTNValid:                   true,
		NetworkName:                 "wlan.mnc001.mcc001.3gppnetwork.org",
		KDFValid:                    true,
	})
	assert.Equal(t, "accepted", akaPrimeDecision.Decision)
}

func TestSIMAKAEvaluationRejectsMissingVector(t *testing.T) {
	cfg := eapFrameworkSIMAKATestConfig()

	decision := EvaluateSIMAKA(cfg, SIMAKAEvaluationRequest{
		Method:                      "aka",
		PermanentIdentity:           "001010123456789",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		VectorProviderAvailable:     true,
		VectorFresh:                 true,
		QuintupletCount:             1,
		RESValid:                    true,
		MACValid:                    true,
		AUTNValid:                   true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "vector")
}

func TestSIMAKAEvaluationRejectsReplay(t *testing.T) {
	cfg := eapFrameworkSIMAKATestConfig()

	decision := EvaluateSIMAKA(cfg, SIMAKAEvaluationRequest{
		Method:                      "sim",
		PermanentIdentity:           "001010123456789",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		VectorProviderAvailable:     true,
		VectorAvailable:             true,
		VectorFresh:                 true,
		TripletCount:                2,
		RESValid:                    true,
		ReplayDetected:              true,
	})

	assert.Equal(t, "rejected", decision.Decision)
	assert.Contains(t, decision.Reason, "replay")
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

func TestMachineUserReportAndEvaluationAcceptsCorrelation(t *testing.T) {
	cfg := eapFrameworkMachineUserTestConfig()
	report := BuildMachineUserReport(cfg, MachineUserRuntimeSummary{})
	assert.Equal(t, "ready", report.Status)
	assert.True(t, report.Policy.Enabled)
	assert.Equal(t, "machine_then_user", report.Policy.CorrelationMode)
	assert.True(t, report.Policy.TEAPGenerated)

	decision := EvaluateMachineUserCorrelation(cfg, MachineUserEvaluationRequest{
		CorrelationID:               "acct-123",
		MachineIdentity:             "host/laptop01.example.com",
		UserIdentity:                "alice@example.com",
		CallingStationID:            "00-11-22-33-44-55",
		NASIdentifier:               "ap-1",
		MachineMethod:               "teap",
		UserMethod:                  "teap",
		MachineAuthenticated:        true,
		UserAuthenticated:           true,
		MachineAuthAgeSeconds:       300,
		UserAuthAgeSeconds:          30,
		MachineRole:                 "managed-device",
		UserRole:                    "employee",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TEAPChainComplete:           true,
		IdentityTypePresented:       true,
		CryptoBindingValid:          true,
	})
	assert.Equal(t, "accepted", decision.Decision)
	assert.Equal(t, "employee", decision.EffectiveRole)
	assert.True(t, decision.MachineBeforeUser)
	assert.True(t, decision.SameCallingStation)
}

func TestMachineUserEvaluationRejectsStaleMachineAuth(t *testing.T) {
	cfg := eapFrameworkMachineUserTestConfig()
	decision := EvaluateMachineUserCorrelation(cfg, MachineUserEvaluationRequest{
		MachineIdentity:             "host/laptop01.example.com",
		UserIdentity:                "alice@example.com",
		CallingStationID:            "00-11-22-33-44-55",
		MachineMethod:               "teap",
		UserMethod:                  "teap",
		MachineAuthenticated:        true,
		UserAuthenticated:           true,
		MachineAuthAgeSeconds:       40000,
		UserAuthAgeSeconds:          30,
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TEAPChainComplete:           true,
		IdentityTypePresented:       true,
		CryptoBindingValid:          true,
	})
	assert.Equal(t, "rejected", decision.Decision)
	assert.True(t, decision.StaleMachineAuth)
	assert.Equal(t, "machine authentication evidence is stale", decision.Reason)
}

func TestMachineUserEvaluationQuarantinesRoleConflict(t *testing.T) {
	cfg := eapFrameworkMachineUserTestConfig()
	cfg.Radius.EAP.MachineUser.ConflictAction = "quarantine"
	cfg.Radius.EAP.MachineUser.RoleMergeStrategy = "deny_conflict"
	decision := EvaluateMachineUserCorrelation(cfg, MachineUserEvaluationRequest{
		MachineIdentity:             "host/laptop01.example.com",
		UserIdentity:                "alice@example.com",
		CallingStationID:            "00-11-22-33-44-55",
		MachineMethod:               "teap",
		UserMethod:                  "teap",
		MachineAuthenticated:        true,
		UserAuthenticated:           true,
		MachineAuthAgeSeconds:       300,
		UserAuthAgeSeconds:          30,
		MachineRole:                 "contractor-device",
		UserRole:                    "employee",
		EAPMessagePresent:           true,
		MessageAuthenticatorPresent: true,
		TEAPChainComplete:           true,
		IdentityTypePresented:       true,
		CryptoBindingValid:          true,
	})
	assert.Equal(t, "quarantined", decision.Decision)
	assert.True(t, decision.ConflictDetected)
	assert.Equal(t, "quarantine", decision.EffectiveRole)
}

func eapFrameworkMachineUserTestConfig() *config.Config {
	cfg := eapFrameworkTEAPTestConfig()
	cfg.Radius.EAP.MachineUser = config.RadiusEAPMachineUserConfig{
		Enabled:                   true,
		Mode:                      "enforce",
		FailClosed:                true,
		CorrelationMode:           "machine_then_user",
		RequireTEAP:               true,
		RequireMachineIdentity:    true,
		RequireUserIdentity:       true,
		RequireMachineBeforeUser:  true,
		RequireSameCallingStation: true,
		RequireFreshMachineAuth:   true,
		MachineAuthTTLSeconds:     28800,
		UserAuthTTLSeconds:        28800,
		TransitionWindowSeconds:   900,
		AllowedMachineMethods:     []string{"teap", "tls"},
		AllowedUserMethods:        []string{"teap", "peap", "ttls"},
		IdentityPrecedence:        "user_over_machine",
		RoleMergeStrategy:         "user_primary",
		ConflictAction:            "reject",
		StaleMachineAction:        "reject",
		MachineIdentityPrefixes:   []string{"host/", "machine/"},
		MaxActiveCorrelations:     100000,
		AuditEnabled:              true,
		EventRetentionLimit:       6000,
	}
	return cfg
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

func eapFrameworkSIMAKATestConfig() *config.Config {
	cfg := eapFrameworkTestConfig()
	cfg.Radius.EAP.DefaultType = "sim"
	cfg.Radius.EAP.SIMAKA = config.RadiusEAPSIMAKAConfig{
		Enabled:                   true,
		Methods:                   []string{"sim", "aka", "aka-prime"},
		RequireIdentity:           true,
		RequirePermanentIdentity:  true,
		AllowPseudonymIdentity:    true,
		PseudonymTTLSeconds:       86400,
		ReauthTTLSeconds:          43200,
		VectorProvider:            "external-http",
		VectorProviderRef:         "env:AEGIS_SIMAKA_VECTOR_PROVIDER_URL",
		RequireFreshVectors:       true,
		MaxVectorAgeSeconds:       300,
		MinTriplets:               2,
		MinQuintuplets:            1,
		AllowResynchronization:    true,
		ResyncWindowSeconds:       300,
		RequireNetworkName:        true,
		NetworkName:               "wlan.mnc001.mcc001.3gppnetwork.org",
		RequireKDF:                true,
		FailOnProviderUnavailable: true,
		EventRetentionLimit:       6000,
	}
	cfg.Radius.EAP.Framework.AllowedMethods = []string{"peap", "ttls", "tls", "sim", "aka", "aka-prime"}
	cfg.Radius.EAP.Framework.IdentitySources = append(cfg.Radius.EAP.Framework.IdentitySources, config.RadiusEAPIdentitySource{
		Name:     "sim-aka-vector-provider",
		Source:   "external",
		Enabled:  true,
		Methods:  []string{"sim", "aka", "aka-prime"},
		Priority: 30,
	})
	cfg.Radius.EAP.Framework.MethodPolicies = append(cfg.Radius.EAP.Framework.MethodPolicies,
		config.RadiusEAPMethodPolicy{
			Method:         "sim",
			Enabled:        true,
			IdentitySource: "sim-aka-vector-provider",
		},
		config.RadiusEAPMethodPolicy{
			Method:         "aka",
			Enabled:        true,
			IdentitySource: "sim-aka-vector-provider",
		},
		config.RadiusEAPMethodPolicy{
			Method:         "aka-prime",
			Enabled:        true,
			IdentitySource: "sim-aka-vector-provider",
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
