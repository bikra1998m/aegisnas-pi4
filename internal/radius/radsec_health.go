package radius

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	layehradius "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const radSecSharedSecret = "radsec"

func probeRadSecServer(ctx context.Context, cfg *config.Config, server config.RadiusHomeServer, status UpstreamServerHealth) UpstreamServerHealth {
	component := runtimeStatusComponentName(status.Name)
	if !cfg.Radius.Upstream.Enabled {
		status.Status = "disabled"
		status.Message = "Upstream AAA is disabled"
		persistUpstreamProbeStatus(component, status)
		return status
	}
	if status.Address == "" {
		status.Status = "down"
		status.Message = "RadSec upstream address is empty"
		persistUpstreamProbeStatus(component, status)
		return status
	}

	timeout := dashboardProbeTimeout(cfg)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	if server.RadSec.PSK.Enabled {
		status.Status = "unknown"
		status.Message = "RadSec TLS-PSK peer is configured; active PSK transport validation is tracked by the NAS-0014 release certification workflow."
		status.LatencyMs = time.Since(start).Milliseconds()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	tlsConfig, err := radSecTLSConfig(server.RadSec)
	if err != nil {
		status.Status = "down"
		status.Message = err.Error()
		persistUpstreamProbeStatus(component, status)
		return status
	}

	endpoint := net.JoinHostPort(status.Address, fmt.Sprintf("%d", server.RadSec.Port))
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(probeCtx, "tcp", endpoint)
	if err != nil {
		status.Status = "down"
		status.Message = fmt.Sprintf("RadSec TCP connection failed: %v", err)
		status.LatencyMs = time.Since(start).Milliseconds()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		status.Status = "down"
		status.Message = fmt.Sprintf("RadSec mutual TLS handshake failed: %v", err)
		status.LatencyMs = time.Since(start).Milliseconds()
		persistUpstreamProbeStatus(component, status)
		return status
	}

	state := tlsConn.ConnectionState()
	if server.RadSec.CheckCRL {
		if err := verifyRadSecPeerRevocation(state, server.RadSec.CAFile, server.RadSec.CAPath); err != nil {
			status.Status = "down"
			status.Message = fmt.Sprintf("RadSec peer revocation validation failed: %v", err)
			status.LatencyMs = time.Since(start).Milliseconds()
			persistUpstreamProbeStatus(component, status)
			return status
		}
	}
	status.TLSVersion = tlsVersionName(state.Version)
	status.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)
	status.TLSALPN = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		peer := state.PeerCertificates[0]
		status.PeerSubject = peer.Subject.String()
		status.PeerIssuer = peer.Issuer.String()
		status.PeerSerial = peer.SerialNumber.String()
		status.PeerNotAfter = peer.NotAfter.UTC().Format(time.RFC3339)
	}
	if err := validateRadSecALPN(server.RadSec.RadiusV11, status.TLSALPN); err != nil {
		status.Status = "down"
		status.Message = err.Error()
		status.LatencyMs = time.Since(start).Milliseconds()
		persistUpstreamProbeStatus(component, status)
		return status
	}

	status.LatencyMs = time.Since(start).Milliseconds()
	if cfg.Radius.Upstream.StatusCheck != "status-server" {
		status.Status = "ok"
		status.Message = "RadSec mutual TLS handshake succeeded"
		applyCertificateExpiryStatus(cfg, &status)
		persistUpstreamProbeStatus(component, status)
		return status
	}
	if status.TLSALPN == "radius/1.1" {
		status.Status = "ok"
		status.Message = "RadSec RADIUS/1.1 mutual TLS and ALPN negotiation succeeded"
		applyCertificateExpiryStatus(cfg, &status)
		persistUpstreamProbeStatus(component, status)
		return status
	}

	request := layehradius.New(layehradius.CodeStatusServer, []byte(radSecSharedSecret))
	if err := rfc2865.NASIdentifier_SetString(request, cfg.Radius.NASIdentifier); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	if err := rfc2865.ServiceType_Set(request, rfc2865.ServiceType_Value_AuthenticateOnly); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	if err := setMessageAuthenticator(request); err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	wire, err := request.Encode()
	if err != nil {
		status.Status = "unknown"
		status.Message = err.Error()
		persistUpstreamProbeStatus(component, status)
		return status
	}
	if _, err := tlsConn.Write(wire); err != nil {
		status.Status = "down"
		status.Message = fmt.Sprintf("write RadSec Status-Server: %v", err)
		persistUpstreamProbeStatus(component, status)
		return status
	}
	header := make([]byte, 20)
	if _, err := io.ReadFull(tlsConn, header); err != nil {
		status.Status = "down"
		status.Message = fmt.Sprintf("read RadSec Status-Server response: %v", err)
		persistUpstreamProbeStatus(component, status)
		return status
	}
	packetLength := int(binary.BigEndian.Uint16(header[2:4]))
	if packetLength < 20 || packetLength > layehradius.MaxPacketLength {
		status.Status = "down"
		status.Message = fmt.Sprintf("invalid RadSec RADIUS packet length %d", packetLength)
		persistUpstreamProbeStatus(component, status)
		return status
	}
	responseWire := append([]byte(nil), header...)
	if packetLength > 20 {
		body := make([]byte, packetLength-20)
		if _, err := io.ReadFull(tlsConn, body); err != nil {
			status.Status = "down"
			status.Message = fmt.Sprintf("read RadSec RADIUS response body: %v", err)
			persistUpstreamProbeStatus(component, status)
			return status
		}
		responseWire = append(responseWire, body...)
	}
	if !layehradius.IsAuthenticResponse(responseWire, wire, []byte(radSecSharedSecret)) {
		status.Status = "down"
		status.Message = "RadSec Status-Server response authenticator is invalid"
		persistUpstreamProbeStatus(component, status)
		return status
	}
	response, err := layehradius.Parse(responseWire, []byte(radSecSharedSecret))
	if err != nil {
		status.Status = "down"
		status.Message = fmt.Sprintf("parse RadSec Status-Server response: %v", err)
		persistUpstreamProbeStatus(component, status)
		return status
	}
	status.ResponseCode = response.Code.String()
	status.LatencyMs = time.Since(start).Milliseconds()
	switch response.Code {
	case layehradius.CodeAccessAccept, layehradius.CodeAccessChallenge:
		status.Status = "ok"
	case layehradius.CodeAccessReject:
		status.Status = "degraded"
	default:
		status.Status = "degraded"
	}
	status.Message = fmt.Sprintf("RadSec Status-Server answered with %s", response.Code)
	applyCertificateExpiryStatus(cfg, &status)
	persistUpstreamProbeStatus(component, status)
	return status
}

func radSecTLSConfig(peer config.RadiusRadSecPeerConfig) (*tls.Config, error) {
	roots, err := loadRadSecRoots(peer.CAFile, peer.CAPath)
	if err != nil {
		return nil, err
	}
	certificate, err := loadRadSecCertificate(peer.CertificateFile, peer.PrivateKeyFile, peer.PrivateKeyPasswordEnv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tlsVersion(peer.TLSMinVersion),
		MaxVersion:   tlsVersion(peer.TLSMaxVersion),
		ServerName:   strings.TrimSpace(peer.ServerName),
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   radSecALPNProtocols(peer.RadiusV11),
	}, nil
}

func loadRadSecRoots(caFile, caPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	loaded := false
	load := func(path string) error {
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !pool.AppendCertsFromPEM(contents) {
			return fmt.Errorf("no CA certificates found in %s", path)
		}
		loaded = true
		return nil
	}
	if strings.TrimSpace(caFile) != "" {
		if err := load(caFile); err != nil {
			return nil, fmt.Errorf("load RadSec CA file: %w", err)
		}
	}
	if strings.TrimSpace(caPath) != "" {
		entries, err := os.ReadDir(caPath)
		if err != nil {
			return nil, fmt.Errorf("read RadSec CA path: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(caPath, entry.Name())
			contents, err := os.ReadFile(path)
			if err == nil && pool.AppendCertsFromPEM(contents) {
				loaded = true
			}
		}
	}
	if !loaded {
		return nil, fmt.Errorf("no RadSec trust anchors were loaded")
	}
	return pool, nil
}

func verifyRadSecPeerRevocation(state tls.ConnectionState, caFile, caPath string) error {
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) < 2 {
		return fmt.Errorf("verified peer certificate chain is unavailable")
	}
	leaf := state.PeerCertificates[0]
	issuer := state.VerifiedChains[0][1]
	paths := []string{}
	if strings.TrimSpace(caFile) != "" {
		paths = append(paths, caFile)
	}
	if strings.TrimSpace(caPath) != "" {
		entries, err := os.ReadDir(caPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				paths = append(paths, filepath.Join(caPath, entry.Name()))
			}
		}
	}
	foundIssuerCRL := false
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, crl := range parseRevocationLists(contents) {
			if crl.Issuer.String() != issuer.Subject.String() || crl.CheckSignatureFrom(issuer) != nil {
				continue
			}
			foundIssuerCRL = true
			if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
				return fmt.Errorf("CRL issued by %s expired at %s", crl.Issuer, crl.NextUpdate.UTC().Format(time.RFC3339))
			}
			for _, revoked := range crl.RevokedCertificateEntries {
				if leaf.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					return fmt.Errorf("peer certificate serial %s was revoked at %s", leaf.SerialNumber, revoked.RevocationTime.UTC().Format(time.RFC3339))
				}
			}
		}
	}
	if !foundIssuerCRL {
		return fmt.Errorf("no current issuer CRL was found")
	}
	return nil
}

func parseRevocationLists(contents []byte) []*x509.RevocationList {
	lists := []*x509.RevocationList{}
	remainder := contents
	for {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		remainder = rest
		if block.Type != "X509 CRL" && block.Type != "CRL" {
			continue
		}
		if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
			lists = append(lists, crl)
		}
	}
	if len(lists) == 0 {
		if crl, err := x509.ParseRevocationList(contents); err == nil {
			lists = append(lists, crl)
		}
	}
	return lists
}

func loadRadSecCertificate(certificateFile, privateKeyFile, passwordEnv string) (tls.Certificate, error) {
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read RadSec client certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read RadSec client private key: %w", err)
	}
	if strings.TrimSpace(passwordEnv) != "" {
		password, exists := os.LookupEnv(strings.TrimSpace(passwordEnv))
		if !exists || password == "" {
			return tls.Certificate{}, fmt.Errorf("RadSec private key password environment variable %s is not set", passwordEnv)
		}
		block, rest := pem.Decode(privateKeyPEM)
		if block == nil || !x509.IsEncryptedPEMBlock(block) {
			return tls.Certificate{}, fmt.Errorf("RadSec private key password was configured but the key is not a supported encrypted PEM block")
		}
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("decrypt RadSec private key: %w", err)
		}
		privateKeyPEM = append(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: decrypted}), rest...)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load RadSec client key pair: %w", err)
	}
	return certificate, nil
}

func radSecALPNProtocols(mode string) []string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "require":
		return []string{"radius/1.1"}
	case "allow":
		return []string{"radius/1.1", "radius/1.0"}
	default:
		return []string{"radius/1.0"}
	}
}

func validateRadSecALPN(mode, negotiated string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "require":
		if negotiated != "radius/1.1" {
			return fmt.Errorf("RadSec peer did not negotiate required radius/1.1 ALPN")
		}
	case "forbid", "":
		if negotiated == "radius/1.1" {
			return fmt.Errorf("RadSec peer negotiated forbidden radius/1.1 ALPN")
		}
	case "allow":
		if negotiated != "" && negotiated != "radius/1.0" && negotiated != "radius/1.1" {
			return fmt.Errorf("RadSec peer negotiated unsupported ALPN %q", negotiated)
		}
	}
	return nil
}

func tlsVersion(value string) uint16 {
	if strings.TrimSpace(value) == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func applyCertificateExpiryStatus(cfg *config.Config, status *UpstreamServerHealth) {
	if status == nil || status.PeerNotAfter == "" {
		return
	}
	expires, err := time.Parse(time.RFC3339, status.PeerNotAfter)
	if err != nil {
		return
	}
	warningDays := cfg.Radius.RadSec.CertificateExpiryWarningDays
	if warningDays <= 0 {
		warningDays = 30
	}
	if time.Until(expires) <= time.Duration(warningDays)*24*time.Hour {
		status.Status = "degraded"
		status.Message = fmt.Sprintf("%s; peer certificate expires at %s", status.Message, status.PeerNotAfter)
	}
}
