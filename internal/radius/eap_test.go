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
				DefaultType:   "peap",
				PEAPInner:     "mschapv2",
				TTLSInner:     "mschapv2",
				TLSMinVersion: "1.2",
				TLSMaxVersion: "1.3",
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
}
