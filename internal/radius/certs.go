package radius

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"go.uber.org/zap"
)

func EnsureBootstrapCertificates(certDir, commonName string) error {
	if strings.TrimSpace(certDir) == "" {
		return fmt.Errorf("radius cert_dir cannot be empty")
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	serverKeyPath := filepath.Join(certDir, "server.key")
	serverCertPath := filepath.Join(certDir, "server.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	caCertPath := filepath.Join(certDir, "ca.crt")

	if certFileExists(serverKeyPath) && certFileExists(serverCertPath) && certFileExists(caCertPath) {
		return ensureCertificatePermissions(certDir, serverKeyPath, serverCertPath, caKeyPath, caCertPath)
	}

	if strings.TrimSpace(commonName) == "" {
		commonName = "aegisnas.local"
	}

	now := time.Now().UTC()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName:   commonName + " CA",
			Organization: []string{"AegisNAS"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"AegisNAS"},
		},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName, "aegisnas", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}

	if err := writePEMFile(caKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey), 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := writePEMFile(caCertPath, "CERTIFICATE", caDER, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := writePEMFile(serverKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey), 0600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}
	if err := writePEMFile(serverCertPath, "CERTIFICATE", serverDER, 0644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	if err := ensureCertificatePermissions(certDir, serverKeyPath, serverCertPath, caKeyPath, caCertPath); err != nil {
		return err
	}

	logging.L().Info("generated bootstrap FreeRADIUS certificates",
		zap.String("cert_dir", certDir),
		zap.String("common_name", commonName),
	)
	return nil
}

func certFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func ensureCertificatePermissions(certDir string, paths ...string) error {
	if err := os.Chmod(certDir, 0750); err != nil && !os.IsPermission(err) {
		return fmt.Errorf("chmod cert dir: %w", err)
	}

	for _, path := range paths {
		if !certFileExists(path) {
			continue
		}
		mode := os.FileMode(0644)
		if strings.HasSuffix(path, ".key") {
			mode = 0640
		}
		if err := os.Chmod(path, mode); err != nil && !os.IsPermission(err) {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}

	if runtime.GOOS == "windows" {
		return nil
	}

	group, err := user.LookupGroup("freerad")
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil
	}
	for _, path := range append([]string{certDir}, paths...) {
		if err := os.Chown(path, -1, gid); err != nil && !os.IsPermission(err) && !os.IsNotExist(err) {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}
