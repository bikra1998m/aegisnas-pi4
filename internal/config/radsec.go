package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var radiusEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var radiusConfigAtom = regexp.MustCompile(`^[A-Za-z0-9_.:@/-]+$`)

func normalizeRadiusTransport(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "udp"
	}
	return value
}

func validateRadSecConfig(c *Config) error {
	r := c.Radius.RadSec
	if !r.Enabled {
		if r.Port != 0 && (r.Port < 1 || r.Port > 65535) {
			return fmt.Errorf("radius.radsec.port %d out of range", r.Port)
		}
		return nil
	}
	if r.Port != 0 && (r.Port < 1 || r.Port > 65535) {
		return fmt.Errorf("radius.radsec.port %d out of range", r.Port)
	}
	if r.ProbeIntervalSeconds < 0 {
		return fmt.Errorf("radius.radsec.probe_interval_seconds %d cannot be negative", r.ProbeIntervalSeconds)
	}
	if r.CertificateExpiryWarningDays < 0 {
		return fmt.Errorf("radius.radsec.certificate_expiry_warning_days %d cannot be negative", r.CertificateExpiryWarningDays)
	}
	if err := validateTLSVersions("radius.radsec", r.TLSMinVersion, r.TLSMaxVersion); err != nil {
		return err
	}
	if err := validateRadiusV11("radius.radsec.radius_v11", r.RadiusV11); err != nil {
		return err
	}
	if radiusV11Enabled(r.RadiusV11) && r.TLSMinVersion != "1.3" {
		return errors.New("radius.radsec.radius_v11 allow or require needs radius.radsec.tls_min_version 1.3")
	}
	if err := validateConnectionLimits("radius.radsec", r.MaxConnections, 0, r.LifetimeSeconds, r.IdleTimeoutSeconds); err != nil {
		return err
	}
	if r.CheckAllCRL && !r.CheckCRL {
		return errors.New("radius.radsec.check_all_crl requires radius.radsec.check_crl")
	}
	if net.ParseIP(strings.TrimSpace(r.ListenAddress)) == nil {
		return fmt.Errorf("radius.radsec.listen_address %q must be an IPv4 or IPv6 address", r.ListenAddress)
	}
	if r.Port == 0 {
		return errors.New("radius.radsec.port is required when RadSec is enabled")
	}
	if err := requireTLSFiles("radius.radsec", r.CertificateFile, r.PrivateKeyFile, r.CAFile, r.CAPath); err != nil {
		return err
	}
	if err := validatePasswordEnvironment("radius.radsec.private_key_password_env", r.PrivateKeyPasswordEnv); err != nil {
		return err
	}
	if strings.TrimSpace(r.CipherList) == "" || containsConfigControl(r.CipherList) {
		return errors.New("radius.radsec.cipher_list must be non-empty and contain no control characters")
	}
	return nil
}

func validateRadiusClientTransport(index int, client RadiusClient, listenerEnabled bool) error {
	if !validRadiusClientAddress(client.IP) {
		return fmt.Errorf("radius.client[%d].ip %q must be an IPv4/IPv6 address or CIDR", index, client.IP)
	}
	if !radiusConfigAtom.MatchString(strings.TrimSpace(client.ShortName)) {
		return fmt.Errorf("radius.client[%d].shortname %q contains invalid FreeRADIUS configuration characters", index, client.ShortName)
	}
	transport := normalizeRadiusTransport(client.Transport)
	if transport != "udp" && transport != "radsec" {
		return fmt.Errorf("radius.client[%d].transport %q is invalid", index, client.Transport)
	}
	if transport == "udp" {
		return nil
	}
	if !listenerEnabled {
		return fmt.Errorf("radius.client[%d] uses RadSec but radius.radsec.enabled is false", index)
	}
	if strings.TrimSpace(client.RadSecCertificateCN) == "" {
		return fmt.Errorf("radius.client[%d].radsec_certificate_cn is required for RadSec", index)
	}
	if !radiusConfigAtom.MatchString(strings.TrimSpace(client.RadSecCertificateCN)) {
		return fmt.Errorf("radius.client[%d].radsec_certificate_cn %q contains invalid FreeRADIUS configuration characters", index, client.RadSecCertificateCN)
	}
	for field, value := range map[string]string{
		"radsec_certificate_cn":     client.RadSecCertificateCN,
		"radsec_certificate_issuer": client.RadSecCertificateIssuer,
	} {
		if containsConfigControl(value) {
			return fmt.Errorf("radius.client[%d].%s contains invalid control characters", index, field)
		}
	}
	return validateRadiusV11(fmt.Sprintf("radius.client[%d].radsec_radius_v11", index), client.RadSecRadiusV11)
}

func validateRadSecPeer(index int, server RadiusHomeServer) error {
	transport := normalizeRadiusTransport(server.Transport)
	if transport != "udp" && transport != "radsec" {
		return fmt.Errorf("radius.upstream.server[%d].transport %q is invalid", index, server.Transport)
	}
	if transport == "udp" {
		return nil
	}
	prefix := fmt.Sprintf("radius.upstream.server[%d].radsec", index)
	r := server.RadSec
	if !radiusConfigAtom.MatchString(strings.TrimSpace(server.Name)) || !radiusConfigAtom.MatchString(strings.TrimSpace(server.Address)) {
		return fmt.Errorf("radius.upstream.server[%d] name or address contains invalid FreeRADIUS configuration characters", index)
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("%s.port %d out of range", prefix, r.Port)
	}
	if strings.TrimSpace(r.ServerName) == "" || containsConfigControl(r.ServerName) {
		return fmt.Errorf("%s.server_name is required and must be safe for TLS SNI verification", prefix)
	}
	if r.PSK.Enabled {
		if err := validateRadSecPSKConfig(prefix+".psk", r.PSK); err != nil {
			return err
		}
		if err := validateTLSVersions(prefix, r.TLSMinVersion, r.TLSMaxVersion); err != nil {
			return err
		}
		if err := validateRadiusV11(prefix+".radius_v11", r.RadiusV11); err != nil {
			return err
		}
		if radiusV11Enabled(r.RadiusV11) && r.TLSMinVersion != "1.3" {
			return fmt.Errorf("%s.radius_v11 allow or require needs %s.tls_min_version 1.3", prefix, prefix)
		}
		if strings.TrimSpace(r.CipherList) == "" || containsConfigControl(r.CipherList) {
			return fmt.Errorf("%s.cipher_list must be non-empty and contain no control characters", prefix)
		}
		return validateConnectionLimits(prefix, r.MaxConnections, r.MaxRequests, r.LifetimeSeconds, r.IdleTimeoutSeconds)
	}
	if err := requireTLSFiles(prefix, r.CertificateFile, r.PrivateKeyFile, r.CAFile, r.CAPath); err != nil {
		return err
	}
	if err := validatePasswordEnvironment(prefix+".private_key_password_env", r.PrivateKeyPasswordEnv); err != nil {
		return err
	}
	if err := validateTLSVersions(prefix, r.TLSMinVersion, r.TLSMaxVersion); err != nil {
		return err
	}
	if err := validateRadiusV11(prefix+".radius_v11", r.RadiusV11); err != nil {
		return err
	}
	if radiusV11Enabled(r.RadiusV11) && r.TLSMinVersion != "1.3" {
		return fmt.Errorf("%s.radius_v11 allow or require needs %s.tls_min_version 1.3", prefix, prefix)
	}
	if strings.TrimSpace(r.CipherList) == "" || containsConfigControl(r.CipherList) {
		return fmt.Errorf("%s.cipher_list must be non-empty and contain no control characters", prefix)
	}
	return validateConnectionLimits(prefix, r.MaxConnections, r.MaxRequests, r.LifetimeSeconds, r.IdleTimeoutSeconds)
}

func validateRadSecPSKConfig(prefix string, psk RadiusRadSecPSKConfig) error {
	if strings.TrimSpace(psk.Identity) == "" || !radiusConfigAtom.MatchString(strings.TrimSpace(psk.Identity)) {
		return fmt.Errorf("%s.identity is required and must be safe for TLS-PSK identity use", prefix)
	}
	if strings.TrimSpace(psk.SecretRef) == "" {
		return fmt.Errorf("%s.secret_ref is required", prefix)
	}
	if err := validateSecretRefField(prefix+".secret_ref", psk.SecretRef); err != nil {
		return err
	}
	if psk.OverlapSeconds < 0 || psk.OverlapSeconds > 2592000 {
		return fmt.Errorf("%s.overlap_seconds must be between 0 and 2592000", prefix)
	}
	if psk.WarningDays < 0 || psk.WarningDays > 365 {
		return fmt.Errorf("%s.warning_days must be between 0 and 365", prefix)
	}
	nextIdentity := strings.TrimSpace(psk.NextIdentity)
	nextRef := strings.TrimSpace(psk.NextSecretRef)
	nextBefore := strings.TrimSpace(psk.NextNotBefore)
	nextAfter := strings.TrimSpace(psk.NextNotAfter)
	if nextIdentity == "" && nextRef == "" && nextBefore == "" && nextAfter == "" {
		return nil
	}
	if nextIdentity == "" || !radiusConfigAtom.MatchString(nextIdentity) {
		return fmt.Errorf("%s.next_identity is required and must be safe when staging a next PSK", prefix)
	}
	if nextRef == "" {
		return fmt.Errorf("%s.next_secret_ref is required when staging a next PSK", prefix)
	}
	if err := validateSecretRefField(prefix+".next_secret_ref", nextRef); err != nil {
		return err
	}
	notBefore, err := parseOptionalRFC3339(prefix+".next_not_before", nextBefore)
	if err != nil {
		return err
	}
	notAfter, err := parseOptionalRFC3339(prefix+".next_not_after", nextAfter)
	if err != nil {
		return err
	}
	if notBefore.IsZero() || notAfter.IsZero() {
		return fmt.Errorf("%s.next_not_before and %s.next_not_after are required when staging a next PSK", prefix, prefix)
	}
	if !notAfter.After(notBefore) {
		return fmt.Errorf("%s.next_not_after must be after %s.next_not_before", prefix, prefix)
	}
	return nil
}

func parseOptionalRFC3339(field, value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339", field)
	}
	return parsed, nil
}

func requireTLSFiles(prefix, certificateFile, privateKeyFile, caFile, caPath string) error {
	for name, value := range map[string]string{
		"certificate_file": certificateFile,
		"private_key_file": privateKeyFile,
	} {
		if strings.TrimSpace(value) == "" || containsConfigControl(value) {
			return fmt.Errorf("%s.%s is required and must be a safe path", prefix, name)
		}
	}
	if strings.TrimSpace(caFile) == "" && strings.TrimSpace(caPath) == "" {
		return fmt.Errorf("%s.ca_file or %s.ca_path is required", prefix, prefix)
	}
	if containsConfigControl(caFile) || containsConfigControl(caPath) {
		return fmt.Errorf("%s CA path contains invalid control characters", prefix)
	}
	return nil
}

func validateTLSVersions(prefix, minimum, maximum string) error {
	if minimum != "1.2" && minimum != "1.3" {
		return fmt.Errorf("%s.tls_min_version %q must be 1.2 or 1.3", prefix, minimum)
	}
	if maximum != "1.2" && maximum != "1.3" {
		return fmt.Errorf("%s.tls_max_version %q must be 1.2 or 1.3", prefix, maximum)
	}
	if minimum == "1.3" && maximum == "1.2" {
		return fmt.Errorf("%s.tls_min_version cannot exceed tls_max_version", prefix)
	}
	return nil
}

func validateRadiusV11(field, value string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	switch value {
	case "forbid", "allow", "require":
		return nil
	default:
		return fmt.Errorf("%s %q must be forbid, allow, or require", field, value)
	}
}

func radiusV11Enabled(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "allow" || value == "require"
}

func validatePasswordEnvironment(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !radiusEnvironmentName.MatchString(value) {
		return fmt.Errorf("%s %q is not a valid environment variable name", field, value)
	}
	return nil
}

func validateConnectionLimits(prefix string, maxConnections, maxRequests, lifetime, idleTimeout int) error {
	for name, value := range map[string]int{
		"max_connections":      maxConnections,
		"max_requests":         maxRequests,
		"lifetime_seconds":     lifetime,
		"idle_timeout_seconds": idleTimeout,
	} {
		if value < 0 {
			return fmt.Errorf("%s.%s %d cannot be negative", prefix, name, value)
		}
	}
	return nil
}

func containsConfigControl(value string) bool {
	return strings.ContainsAny(value, "\r\n\x00{}\"")
}

func validRadiusClientAddress(value string) bool {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}
