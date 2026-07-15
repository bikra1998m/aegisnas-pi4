package radius

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

const RadSecCredentialSchemaVersion = 1

type RadSecCredentialReport struct {
	SchemaVersion int                        `json:"schema_version"`
	Status        string                     `json:"status"`
	Message       string                     `json:"message"`
	Summary       RadSecCredentialSummary    `json:"summary"`
	Inbound       []RadSecCredentialEndpoint `json:"inbound"`
	Upstream      []RadSecCredentialEndpoint `json:"upstream"`
	Warnings      []string                   `json:"warnings,omitempty"`
	RFCs          []string                   `json:"rfcs"`
}

type RadSecCredentialSummary struct {
	InboundEnabled      bool `json:"inbound_enabled"`
	UpstreamRadSecPeers int  `json:"upstream_radsec_peers"`
	MTLSEndpoints       int  `json:"mtls_endpoints"`
	PSKEndpoints        int  `json:"psk_endpoints"`
	RotationStaged      int  `json:"rotation_staged"`
	RotationActive      int  `json:"rotation_active"`
	RotationExpired     int  `json:"rotation_expired"`
	CertificateWarnings int  `json:"certificate_warnings"`
	BlockingIssues      int  `json:"blocking_issues"`
}

type RadSecCredentialEndpoint struct {
	Name                    string   `json:"name"`
	Direction               string   `json:"direction"`
	Address                 string   `json:"address,omitempty"`
	Port                    int      `json:"port,omitempty"`
	ServerName              string   `json:"server_name,omitempty"`
	Mode                    string   `json:"mode"`
	Status                  string   `json:"status"`
	Message                 string   `json:"message"`
	CertificateFileSet      bool     `json:"certificate_file_set,omitempty"`
	PrivateKeyFileSet       bool     `json:"private_key_file_set,omitempty"`
	CAFileSet               bool     `json:"ca_file_set,omitempty"`
	CAPathSet               bool     `json:"ca_path_set,omitempty"`
	CertificateNotAfter     string   `json:"certificate_not_after,omitempty"`
	PSKIdentity             string   `json:"psk_identity,omitempty"`
	PSKSecretRefSet         bool     `json:"psk_secret_ref_set,omitempty"`
	PSKSecretRefFingerprint string   `json:"psk_secret_ref_fingerprint,omitempty"`
	EffectivePSKIdentity    string   `json:"effective_psk_identity,omitempty"`
	EffectivePSKFingerprint string   `json:"effective_psk_secret_ref_fingerprint,omitempty"`
	UsingNextPSK            bool     `json:"using_next_psk,omitempty"`
	NextPSKIdentity         string   `json:"next_psk_identity,omitempty"`
	NextPSKSecretRefSet     bool     `json:"next_psk_secret_ref_set,omitempty"`
	NextPSKRefFingerprint   string   `json:"next_psk_ref_fingerprint,omitempty"`
	NextNotBefore           string   `json:"next_not_before,omitempty"`
	NextNotAfter            string   `json:"next_not_after,omitempty"`
	RotationStatus          string   `json:"rotation_status"`
	Warnings                []string `json:"warnings,omitempty"`
}

type RadSecSelectedPSK struct {
	Identity       string
	SecretRef      string
	RotationStatus string
	UsingNext      bool
}

func SelectRadSecPSK(psk config.RadiusRadSecPSKConfig, now time.Time) (RadSecSelectedPSK, error) {
	selected := RadSecSelectedPSK{
		Identity:       strings.TrimSpace(psk.Identity),
		SecretRef:      strings.TrimSpace(psk.SecretRef),
		RotationStatus: "steady",
	}
	nextIdentity := strings.TrimSpace(psk.NextIdentity)
	nextRef := strings.TrimSpace(psk.NextSecretRef)
	nextBefore := strings.TrimSpace(psk.NextNotBefore)
	nextAfter := strings.TrimSpace(psk.NextNotAfter)
	if nextIdentity == "" && nextRef == "" && nextBefore == "" && nextAfter == "" {
		return selected, nil
	}
	notBefore, beforeErr := time.Parse(time.RFC3339, nextBefore)
	notAfter, afterErr := time.Parse(time.RFC3339, nextAfter)
	if nextIdentity == "" || nextRef == "" || beforeErr != nil || afterErr != nil || !notAfter.After(notBefore) {
		selected.RotationStatus = "invalid"
		return selected, fmt.Errorf("next PSK rotation window is invalid")
	}
	if now.Before(notBefore) {
		selected.RotationStatus = "staged"
		return selected, nil
	}
	if now.After(notAfter) {
		selected.RotationStatus = "expired"
		return selected, fmt.Errorf("next PSK rotation window has expired")
	}
	selected.Identity = nextIdentity
	selected.SecretRef = nextRef
	selected.RotationStatus = "active"
	selected.UsingNext = true
	return selected, nil
}

func BuildRadSecCredentialReport(cfg *config.Config) RadSecCredentialReport {
	report := RadSecCredentialReport{
		SchemaVersion: RadSecCredentialSchemaVersion,
		Status:        "disabled",
		Message:       "RadSec is not enabled for inbound or upstream transport.",
		RFCs:          []string{"RFC 6614", "RFC 8996", "RFC 9765", "RFC 9813"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		report.Summary.BlockingIssues = 1
		return report
	}
	if cfg.Radius.RadSec.Enabled {
		report.Summary.InboundEnabled = true
		endpoint := buildMTLSCredentialEndpoint("inbound-listener", "inbound", cfg.Radius.RadSec.ListenAddress, cfg.Radius.RadSec.Port, "", cfg.Radius.RadSec.CertificateFile, cfg.Radius.RadSec.PrivateKeyFile, cfg.Radius.RadSec.CAFile, cfg.Radius.RadSec.CAPath, cfg.Radius.RadSec.CertificateExpiryWarningDays)
		report.Inbound = append(report.Inbound, endpoint)
		accumulateRadSecEndpoint(&report, endpoint)
	}
	for _, server := range cfg.Radius.Upstream.Servers {
		if !strings.EqualFold(strings.TrimSpace(server.Transport), "radsec") {
			continue
		}
		report.Summary.UpstreamRadSecPeers++
		if server.RadSec.PSK.Enabled {
			endpoint := buildPSKCredentialEndpoint(server)
			report.Upstream = append(report.Upstream, endpoint)
			accumulateRadSecEndpoint(&report, endpoint)
			continue
		}
		endpoint := buildMTLSCredentialEndpoint(server.Name, "upstream", server.Address, server.RadSec.Port, server.RadSec.ServerName, server.RadSec.CertificateFile, server.RadSec.PrivateKeyFile, server.RadSec.CAFile, server.RadSec.CAPath, cfg.Radius.RadSec.CertificateExpiryWarningDays)
		report.Upstream = append(report.Upstream, endpoint)
		accumulateRadSecEndpoint(&report, endpoint)
	}
	total := len(report.Inbound) + len(report.Upstream)
	if total == 0 {
		return report
	}
	switch {
	case report.Summary.BlockingIssues > 0:
		report.Status = "blocked"
		report.Message = "RadSec credential configuration has blocking issues."
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = "RadSec credentials are configured with warnings."
	default:
		report.Status = "ready"
		report.Message = "RadSec credential configuration is ready."
	}
	return report
}

func buildMTLSCredentialEndpoint(name, direction, address string, port int, serverName, certificateFile, privateKeyFile, caFile, caPath string, warningDays int) RadSecCredentialEndpoint {
	endpoint := RadSecCredentialEndpoint{
		Name:               strings.TrimSpace(name),
		Direction:          direction,
		Address:            strings.TrimSpace(address),
		Port:               port,
		ServerName:         strings.TrimSpace(serverName),
		Mode:               "mtls",
		Status:             "ready",
		Message:            "mTLS credential references are configured.",
		RotationStatus:     "manual",
		CertificateFileSet: strings.TrimSpace(certificateFile) != "",
		PrivateKeyFileSet:  strings.TrimSpace(privateKeyFile) != "",
		CAFileSet:          strings.TrimSpace(caFile) != "",
		CAPathSet:          strings.TrimSpace(caPath) != "",
	}
	for label, path := range map[string]string{
		"certificate_file": certificateFile,
		"private_key_file": privateKeyFile,
	} {
		if strings.TrimSpace(path) == "" {
			endpoint.Status = "blocked"
			endpoint.Warnings = append(endpoint.Warnings, label+" is not configured")
		}
	}
	if strings.TrimSpace(caFile) == "" && strings.TrimSpace(caPath) == "" {
		endpoint.Status = "blocked"
		endpoint.Warnings = append(endpoint.Warnings, "ca_file or ca_path is required")
	}
	if expires, ok := firstCertificateExpiry(certificateFile); ok {
		endpoint.CertificateNotAfter = expires.Format(time.RFC3339)
		if warningDays <= 0 {
			warningDays = 30
		}
		if time.Until(expires) <= time.Duration(warningDays)*24*time.Hour {
			if endpoint.Status == "ready" {
				endpoint.Status = "degraded"
			}
			endpoint.Warnings = append(endpoint.Warnings, "certificate is inside the warning window")
		}
	}
	if len(endpoint.Warnings) > 0 {
		endpoint.Message = strings.Join(endpoint.Warnings, "; ")
	}
	return endpoint
}

func buildPSKCredentialEndpoint(server config.RadiusHomeServer) RadSecCredentialEndpoint {
	psk := server.RadSec.PSK
	endpoint := RadSecCredentialEndpoint{
		Name:                    strings.TrimSpace(server.Name),
		Direction:               "upstream",
		Address:                 strings.TrimSpace(server.Address),
		Port:                    server.RadSec.Port,
		ServerName:              strings.TrimSpace(server.RadSec.ServerName),
		Mode:                    "tls-psk",
		Status:                  "ready",
		Message:                 "TLS-PSK credential references are configured.",
		PSKIdentity:             strings.TrimSpace(psk.Identity),
		PSKSecretRefSet:         strings.TrimSpace(psk.SecretRef) != "",
		PSKSecretRefFingerprint: secrets.Fingerprint(psk.SecretRef),
		EffectivePSKIdentity:    strings.TrimSpace(psk.Identity),
		EffectivePSKFingerprint: secrets.Fingerprint(psk.SecretRef),
		NextPSKIdentity:         strings.TrimSpace(psk.NextIdentity),
		NextPSKSecretRefSet:     strings.TrimSpace(psk.NextSecretRef) != "",
		NextPSKRefFingerprint:   secrets.Fingerprint(psk.NextSecretRef),
		NextNotBefore:           strings.TrimSpace(psk.NextNotBefore),
		NextNotAfter:            strings.TrimSpace(psk.NextNotAfter),
		RotationStatus:          "steady",
	}
	if endpoint.PSKIdentity == "" {
		endpoint.Status = "blocked"
		endpoint.Warnings = append(endpoint.Warnings, "psk identity is not configured")
	}
	if !endpoint.PSKSecretRefSet {
		endpoint.Status = "blocked"
		endpoint.Warnings = append(endpoint.Warnings, "psk secret_ref is not configured")
	}
	now := time.Now().UTC()
	if selected, err := SelectRadSecPSK(psk, now); err == nil {
		endpoint.EffectivePSKIdentity = selected.Identity
		endpoint.EffectivePSKFingerprint = secrets.Fingerprint(selected.SecretRef)
		endpoint.UsingNextPSK = selected.UsingNext
		endpoint.RotationStatus = selected.RotationStatus
	} else {
		endpoint.RotationStatus = selectedRotationStatus(psk, now)
		endpoint.Status = "blocked"
		endpoint.Warnings = append(endpoint.Warnings, err.Error())
	}
	if endpoint.NextPSKIdentity != "" || endpoint.NextPSKSecretRefSet || endpoint.NextNotBefore != "" || endpoint.NextNotAfter != "" {
		notBefore, beforeErr := time.Parse(time.RFC3339, endpoint.NextNotBefore)
		notAfter, afterErr := time.Parse(time.RFC3339, endpoint.NextNotAfter)
		switch {
		case endpoint.NextPSKIdentity == "" || !endpoint.NextPSKSecretRefSet || beforeErr != nil || afterErr != nil || !notAfter.After(notBefore):
			endpoint.RotationStatus = "invalid"
			endpoint.Status = "blocked"
			if !containsString(endpoint.Warnings, "next PSK rotation window is invalid") {
				endpoint.Warnings = append(endpoint.Warnings, "next PSK rotation window is invalid")
			}
		case now.Before(notBefore):
			endpoint.RotationStatus = "staged"
		case now.After(notAfter):
			endpoint.RotationStatus = "expired"
			endpoint.Status = "blocked"
			if !containsString(endpoint.Warnings, "next PSK rotation window has expired") {
				endpoint.Warnings = append(endpoint.Warnings, "next PSK rotation window has expired")
			}
		default:
			endpoint.RotationStatus = "active"
			warningDays := psk.WarningDays
			if warningDays <= 0 {
				warningDays = 30
			}
			if time.Until(notAfter) <= time.Duration(warningDays)*24*time.Hour {
				endpoint.Status = "degraded"
				endpoint.Warnings = append(endpoint.Warnings, "next PSK rotation window ends soon")
			}
		}
	}
	if len(endpoint.Warnings) > 0 {
		endpoint.Message = strings.Join(endpoint.Warnings, "; ")
	}
	return endpoint
}

func selectedRotationStatus(psk config.RadiusRadSecPSKConfig, now time.Time) string {
	nextBefore := strings.TrimSpace(psk.NextNotBefore)
	nextAfter := strings.TrimSpace(psk.NextNotAfter)
	notBefore, beforeErr := time.Parse(time.RFC3339, nextBefore)
	notAfter, afterErr := time.Parse(time.RFC3339, nextAfter)
	if beforeErr != nil || afterErr != nil || !notAfter.After(notBefore) {
		return "invalid"
	}
	if now.Before(notBefore) {
		return "staged"
	}
	if now.After(notAfter) {
		return "expired"
	}
	return "active"
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func accumulateRadSecEndpoint(report *RadSecCredentialReport, endpoint RadSecCredentialEndpoint) {
	if endpoint.Mode == "tls-psk" {
		report.Summary.PSKEndpoints++
	} else {
		report.Summary.MTLSEndpoints++
	}
	switch endpoint.RotationStatus {
	case "staged":
		report.Summary.RotationStaged++
	case "active":
		report.Summary.RotationActive++
	case "expired", "invalid":
		report.Summary.RotationExpired++
	}
	switch endpoint.Status {
	case "blocked":
		report.Summary.BlockingIssues++
		report.Warnings = append(report.Warnings, endpoint.Name+": "+endpoint.Message)
	case "degraded":
		report.Summary.CertificateWarnings++
		report.Warnings = append(report.Warnings, endpoint.Name+": "+endpoint.Message)
	}
}

func firstCertificateExpiry(path string) (time.Time, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return time.Time{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return time.Time{}, false
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, false
		}
		return certificate.NotAfter.UTC(), true
	}
}
