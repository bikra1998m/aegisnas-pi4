package radius

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureBootstrapCertificates(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureBootstrapCertificates(dir, "aegisnas-test"); err != nil {
		t.Fatalf("EnsureBootstrapCertificates returned error: %v", err)
	}

	for _, name := range []string{"server.key", "server.crt", "ca.key", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatalf("read server cert: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM encoded server certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server certificate: %v", err)
	}
	if cert.Subject.CommonName != "aegisnas-test" {
		t.Fatalf("unexpected common name %q", cert.Subject.CommonName)
	}
}
