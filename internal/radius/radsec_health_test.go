package radius

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

type radSecTestPKI struct {
	caFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile string
	serverCertificate                                                    tls.Certificate
	clientCAPool                                                         *x509.CertPool
}

func TestProbeUpstreamServersRadSecMutualTLS(t *testing.T) {
	pki := createRadSecTestPKI(t)
	listener := startRadSecStatusServer(t, pki, []string{"radius/1.0"})
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, _ := net.LookupPort("tcp", portText)

	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = previousDB })
	cfg := radSecProbeConfig(host, port, pki)
	statuses, err := ProbeUpstreamServers(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, "ok", statuses[0].Status)
	assert.Equal(t, "radsec", statuses[0].Transport)
	assert.Equal(t, "radius/1.0", statuses[0].TLSALPN)
	assert.NotEmpty(t, statuses[0].TLSVersion)
	assert.NotEmpty(t, statuses[0].TLSCipherSuite)
	assert.Contains(t, statuses[0].PeerSubject, "aaa.example.test")
	assert.Equal(t, layehradius.CodeAccessAccept.String(), statuses[0].ResponseCode)
}

func TestProbeUpstreamServersRadSecRejectsWrongServerIdentity(t *testing.T) {
	pki := createRadSecTestPKI(t)
	listener := startRadSecStatusServer(t, pki, []string{"radius/1.0"})
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, _ := net.LookupPort("tcp", portText)

	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = previousDB })
	cfg := radSecProbeConfig(host, port, pki)
	cfg.Radius.Upstream.Servers[0].RadSec.ServerName = "wrong.example.test"
	statuses, err := ProbeUpstreamServers(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, "down", statuses[0].Status)
	assert.Contains(t, statuses[0].Message, "certificate")
}

func TestProbeUpstreamServersRadSecRequiresRadiusV11ALPN(t *testing.T) {
	pki := createRadSecTestPKI(t)
	listener := startRadSecStatusServer(t, pki, []string{"radius/1.0"})
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, _ := net.LookupPort("tcp", portText)

	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = previousDB })
	cfg := radSecProbeConfig(host, port, pki)
	cfg.Radius.Upstream.Servers[0].RadSec.RadiusV11 = "require"
	cfg.Radius.Upstream.Servers[0].RadSec.TLSMinVersion = "1.3"
	statuses, err := ProbeUpstreamServers(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, "down", statuses[0].Status)
	assert.Contains(t, statuses[0].Message, "handshake failed")
}

func radSecProbeConfig(host string, port int, pki radSecTestPKI) *config.Config {
	return &config.Config{Radius: config.RadiusConfig{
		NASIdentifier: "aegis-test", AuthPort: 1812, AcctPort: 1813, RequestTimeoutSeconds: 2,
		RadSec: config.RadiusRadSecConfig{CertificateExpiryWarningDays: 7},
		Upstream: config.RadiusUpstreamConfig{Enabled: true, StatusCheck: "status-server", Servers: []config.RadiusHomeServer{{
			Name: "secure-aaa", Address: host, Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
				Port: port, ServerName: "aaa.example.test", CertificateFile: pki.clientCertFile, PrivateKeyFile: pki.clientKeyFile,
				CAFile: pki.caFile, TLSMinVersion: "1.2", TLSMaxVersion: "1.3", RadiusV11: "forbid",
			},
		}}},
	}}
}

func startRadSecStatusServer(t *testing.T, pki radSecTestPKI, protocols []string) net.Listener {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.clientCAPool, NextProtos: protocols,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				header := make([]byte, 20)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(header[2:4]))
				wire := append([]byte(nil), header...)
				if length > 20 {
					body := make([]byte, length-20)
					if _, err := io.ReadFull(conn, body); err != nil {
						return
					}
					wire = append(wire, body...)
				}
				request, err := layehradius.Parse(wire, []byte(radSecSharedSecret))
				if err != nil {
					return
				}
				response := request.Response(layehradius.CodeAccessAccept)
				encoded, err := response.Encode()
				if err == nil {
					_, _ = conn.Write(encoded)
				}
			}(conn)
		}
	}()
	return listener
}

func createRadSecTestPKI(t *testing.T) radSecTestPKI {
	dir := t.TempDir()
	now := time.Now().Add(-time.Hour)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Aegis Test CA"},
		NotBefore: now, NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caFile := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600))

	issue := func(name string, serial int64, server bool) (string, string, tls.Certificate) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			DNSNames: []string{name}, NotBefore: now, NotAfter: now.AddDate(1, 0, 0),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		certFile := filepath.Join(dir, name+".crt")
		keyFile := filepath.Join(dir, name+".key")
		require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600))
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		require.NoError(t, err)
		return certFile, keyFile, certificate
	}
	serverCertFile, serverKeyFile, serverCertificate := issue("aaa.example.test", 2, true)
	clientCertFile, clientKeyFile, _ := issue("aegis-client.example.test", 3, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return radSecTestPKI{caFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile, serverCertificate, pool}
}
