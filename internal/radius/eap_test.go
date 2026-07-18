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

func TestGenerateEAPConfigBlocksPlannedMethodInEnforceMode(t *testing.T) {
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
					AllowedMethods:              []string{"peap", "teap"},
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
		t.Fatalf("expected enforce mode to block planned EAP method, got %v", err)
	}
}
