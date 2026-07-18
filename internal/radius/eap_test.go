package radius

import (
	"strings"
	"testing"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestGenerateEAPConfigReferencesTLSConfig(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
			EAP: config.RadiusEAPConfig{
				DefaultType:          "peap",
				PEAPInner:            "mschapv2",
				TTLSInner:            "mschapv2",
				TLSMinVersion:        "1.2",
				TLSMaxVersion:        "1.3",
				CheckCRL:             true,
				CheckAllCRL:          true,
				CAPathReloadInterval: 300,
				OCSP: config.RadiusEAPOCSPConfig{
					Enabled:         true,
					OverrideCertURL: true,
					URL:             "https://pki.example.test/ocsp",
					UseNonce:        true,
					TimeoutSeconds:  5,
				},
			},
		},
	}

	content, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err != nil {
		t.Fatalf("GenerateEAPConfig returned error: %v", err)
	}

	if !strings.Contains(content, "peap {\n\t\tdefault_eap_type = mschapv2\n\t\ttls = tls-common") {
		t.Fatalf("expected peap block to reference tls-common, got:\n%s", content)
	}
	if !strings.Contains(content, "ttls {\n\t\tdefault_eap_type = mschapv2\n\t\ttls = tls-common") {
		t.Fatalf("expected ttls block to reference tls-common, got:\n%s", content)
	}
	for _, expected := range []string{
		"check_crl = yes",
		"check_all_crl = yes",
		"ca_path = /etc/freeradius/3.0/certs",
		"ca_path_reload_interval = 300",
		"enable = yes",
		"override_cert_url = yes",
		`url = "https://pki.example.test/ocsp"`,
		"use_nonce = yes",
		"timeout = 5",
		"softfail = no",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected EAP config to contain %q, got:\n%s", expected, content)
		}
	}
}

func TestGenerateEAPConfigUsesFrameworkLimits(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
			EAP: config.RadiusEAPConfig{
				DefaultType:   "ttls",
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
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      true,
					MaxConcurrentSessions:       512,
					MethodTimeoutSeconds:        45,
					FragmentSize:                1200,
				},
			},
		},
	}

	content, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err != nil {
		t.Fatalf("GenerateEAPConfig returned error: %v", err)
	}
	for _, expected := range []string{
		"NAS-0022 EAP framework status: ready",
		"EAP framework mode: enforce, fail_closed=true",
		"default_eap_type = ttls",
		"timer_expire = 45",
		"max_sessions = 512",
		"fragment_size = 1200",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected EAP config to contain %q, got:\n%s", expected, content)
		}
	}
}

func TestGenerateEAPConfigBlocksUnsupportedMethodInEnforceMode(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
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
					AllowedMethods:              []string{"peap", "leap"},
					AllowedInnerMethods:         []string{"mschapv2", "pap"},
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      false,
				},
			},
		},
	}

	_, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err == nil || !strings.Contains(err.Error(), "EAP framework blocked") {
		t.Fatalf("expected enforce mode to block unsupported EAP method, got %v", err)
	}
}

func TestGenerateEAPConfigIncludesTEAPWhenAllowed(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
			EAP: config.RadiusEAPConfig{
				DefaultType:   "teap",
				PEAPInner:     "mschapv2",
				TTLSInner:     "pap",
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
				TEAP: config.RadiusEAPTEAPConfig{
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
				},
				Framework: config.RadiusEAPFramework{
					Enabled:                     true,
					Mode:                        "enforce",
					FailClosed:                  true,
					AllowedMethods:              []string{"peap", "ttls", "tls", "teap"},
					AllowedInnerMethods:         []string{"mschapv2", "pap", "chap", "gtc", "tls"},
					DefaultInnerIdentitySource:  "identity-failover",
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      true,
					MethodTimeoutSeconds:        60,
					FragmentSize:                1024,
				},
			},
		},
	}

	content, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err != nil {
		t.Fatalf("GenerateEAPConfig returned error: %v", err)
	}
	for _, expected := range []string{
		"NAS-0023 TEAP generated: true, chain_mode=machine_then_user, cryptobinding=true",
		"default_eap_type = teap",
		"teap {\n\t\tdefault_eap_type = mschapv2\n\t\ttls = tls-common",
		`virtual_server = "inner-tunnel"`,
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected EAP config to contain %q, got:\n%s", expected, content)
		}
	}
}

func TestGenerateEAPConfigIncludesFASTAndPWDWhenAllowed(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
			EAP: config.RadiusEAPConfig{
				DefaultType:   "fast",
				PEAPInner:     "mschapv2",
				TTLSInner:     "pap",
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
				FAST: config.RadiusEAPFASTConfig{
					Enabled:                 true,
					DefaultInnerMethod:      "mschapv2",
					RequireCryptoBinding:    true,
					AllowPAC:                true,
					PACProvisioning:         "authenticated",
					PACAuthorityID:          "aegisnas-fast",
					AllowEAPPayload:         true,
					MaxProvisioningAttempts: 3,
					SessionTTLSeconds:       900,
					EventRetentionLimit:     6000,
				},
				PWD: config.RadiusEAPPWDConfig{
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
				},
				Framework: config.RadiusEAPFramework{
					Enabled:                     true,
					Mode:                        "enforce",
					FailClosed:                  true,
					AllowedMethods:              []string{"peap", "ttls", "tls", "fast", "pwd"},
					AllowedInnerMethods:         []string{"mschapv2", "pap", "chap", "gtc", "tls"},
					DefaultInnerIdentitySource:  "identity-failover",
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      true,
					MethodTimeoutSeconds:        60,
					FragmentSize:                1024,
				},
			},
		},
	}

	content, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err != nil {
		t.Fatalf("GenerateEAPConfig returned error: %v", err)
	}
	for _, expected := range []string{
		"NAS-0024 EAP-FAST generated: true, pac=true, cryptobinding=true",
		"NAS-0024 EAP-PWD generated: true, group=19, source=identity-failover",
		"default_eap_type = fast",
		"fast {\n\t\tdefault_eap_type = mschapv2\n\t\ttls = tls-common",
		"pwd {\n\t\tgroup = 19",
		`server_id = "aegisnas-pwd"`,
		"fragment_size = 1020",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected EAP config to contain %q, got:\n%s", expected, content)
		}
	}
}

func TestGenerateEAPConfigIncludesSIMAKAWhenAllowed(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			MaxSessions: 1024,
			EAP: config.RadiusEAPConfig{
				DefaultType:   "sim",
				PEAPInner:     "mschapv2",
				TTLSInner:     "pap",
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
				SIMAKA: config.RadiusEAPSIMAKAConfig{
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
				},
				Framework: config.RadiusEAPFramework{
					Enabled:                     true,
					Mode:                        "enforce",
					FailClosed:                  true,
					AllowedMethods:              []string{"peap", "ttls", "tls", "sim", "aka", "aka-prime"},
					AllowedInnerMethods:         []string{"mschapv2", "pap", "chap", "gtc", "tls"},
					DefaultInnerIdentitySource:  "identity-failover",
					UnsupportedMethodAction:     "reject",
					RequireMessageAuthenticator: true,
					RequireIdentityBinding:      true,
					MethodTimeoutSeconds:        60,
					FragmentSize:                1024,
				},
			},
		},
	}

	content, err := GenerateEAPConfig(cfg, "/etc/freeradius/3.0/certs")
	if err != nil {
		t.Fatalf("GenerateEAPConfig returned error: %v", err)
	}
	for _, expected := range []string{
		"NAS-0025 EAP-SIM/AKA generated: true, methods=AKA,AKA-prime,SIM, vector_provider=external-http, fresh_vectors=true",
		"default_eap_type = sim",
		"sim {\n\t\t# EAP-SIM vectors are resolved by AegisNAS policy via external-http.",
		"aka {\n\t\t# EAP-AKA quintuplets are resolved by AegisNAS policy via external-http.",
		"aka_prime {\n\t\t# EAP-AKA-prime enforces network-name and KDF policy before enabling this block.",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected EAP config to contain %q, got:\n%s", expected, content)
		}
	}
}
