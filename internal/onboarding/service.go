package onboarding

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"go.uber.org/zap"
)

const (
	complianceUnknown      = "unknown"
	complianceCompliant    = "compliant"
	complianceNonCompliant = "non_compliant"
)

type Device struct {
	ID                    int    `json:"id"`
	MAC                   string `json:"mac"`
	Tenant                string `json:"tenant"`
	Username              string `json:"username"`
	FriendlyName          string `json:"friendly_name"`
	Ownership             string `json:"ownership"`
	Platform              string `json:"platform"`
	DeviceType            string `json:"device_type"`
	UserAgent             string `json:"user_agent"`
	Source                string `json:"source"`
	Managed               bool   `json:"managed"`
	Compliant             *bool  `json:"compliant,omitempty"`
	ComplianceStatus      string `json:"compliance_status"`
	RemediationState      string `json:"remediation_state"`
	MDMProvider           string `json:"mdm_provider"`
	MDMDeviceID           string `json:"mdm_device_id"`
	CertificateID         string `json:"certificate_id"`
	CertificateSerial     string `json:"certificate_serial"`
	CertificateSubject    string `json:"certificate_subject"`
	CertificateValidUntil string `json:"certificate_valid_until"`
	LastIP                string `json:"last_ip"`
	LastSessionID         string `json:"last_session_id"`
	FirstSeen             string `json:"first_seen"`
	LastSeen              string `json:"last_seen"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

type DeviceCertificate struct {
	ID         string `json:"id"`
	DeviceMAC  string `json:"device_mac"`
	Username   string `json:"username"`
	CommonName string `json:"common_name"`
	Serial     string `json:"serial_number"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	CAPath     string `json:"ca_path"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	RevokedAt  string `json:"revoked_at"`
}

type RegisterRequest struct {
	MAC          string
	Username     string
	SessionID    string
	LastIP       string
	FriendlyName string
	Ownership    string
	Platform     string
	UserAgent    string
	Source       string
}

type RegisterResult struct {
	Device           *Device            `json:"device"`
	Certificate      *DeviceCertificate `json:"certificate,omitempty"`
	CertificatePEM   string             `json:"certificate_pem,omitempty"`
	PrivateKeyPEM    string             `json:"private_key_pem,omitempty"`
	CertificateCAPEM string             `json:"ca_pem,omitempty"`
}

type ComplianceRecord struct {
	MAC              string `json:"mac"`
	Managed          bool   `json:"managed"`
	Compliant        bool   `json:"compliant"`
	ComplianceStatus string `json:"compliance_status"`
	RemediationState string `json:"remediation_state"`
	MDMProvider      string `json:"mdm_provider"`
	MDMDeviceID      string `json:"mdm_device_id"`
	FriendlyName     string `json:"friendly_name"`
	Platform         string `json:"platform"`
}

type Service struct {
	cfg    *config.Config
	logger *zap.Logger
	client *http.Client
}

func New(cfg *config.Config, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) ObserveDevice(mac, ip, username, sessionID, userAgent, source string) error {
	if s.cfg == nil || (!s.cfg.Onboarding.DeviceInventoryEnabled && !s.cfg.Profiling.MACInventoryEnabled) {
		return nil
	}
	mac = normalizeMAC(mac)
	if mac == "" {
		return nil
	}
	tenant := s.lookupTenant(strings.TrimSpace(username))
	platform, deviceType := fingerprintUserAgent(userAgent)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.DB.Exec(`INSERT INTO device_inventory (
		mac, tenant, username, platform, device_type, user_agent, source, compliance_status, last_ip, last_session_id, first_seen, last_seen, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		tenant = COALESCE(excluded.tenant, device_inventory.tenant),
		username = COALESCE(excluded.username, device_inventory.username),
		platform = CASE WHEN device_inventory.platform = '' OR device_inventory.platform IS NULL THEN excluded.platform ELSE device_inventory.platform END,
		device_type = CASE WHEN device_inventory.device_type = '' OR device_inventory.device_type IS NULL THEN excluded.device_type ELSE device_inventory.device_type END,
		user_agent = CASE WHEN excluded.user_agent <> '' THEN excluded.user_agent ELSE device_inventory.user_agent END,
		source = CASE WHEN excluded.source <> '' THEN excluded.source ELSE device_inventory.source END,
		last_ip = CASE WHEN excluded.last_ip <> '' THEN excluded.last_ip ELSE device_inventory.last_ip END,
		last_session_id = CASE WHEN excluded.last_session_id <> '' THEN excluded.last_session_id ELSE device_inventory.last_session_id END,
		last_seen = excluded.last_seen,
		updated_at = excluded.updated_at`,
		mac, nullable(tenant), nullable(username), nullable(platform), nullable(deviceType), nullable(userAgent), nullable(source), complianceUnknown, nullable(ip), nullable(sessionID), now, now, now)
	return err
}

func (s *Service) RegisterDevice(ctx context.Context, req RegisterRequest) (*RegisterResult, error) {
	if s.cfg == nil {
		return nil, errors.New("configuration is required")
	}
	mac := normalizeMAC(req.MAC)
	if mac == "" {
		return nil, errors.New("device MAC is required")
	}
	if strings.TrimSpace(req.Username) == "" {
		return nil, errors.New("username is required")
	}
	tenant := s.lookupTenant(strings.TrimSpace(req.Username))
	now := time.Now().UTC().Format(time.RFC3339)
	platform := strings.TrimSpace(req.Platform)
	deviceType := ""
	if platform == "" {
		platform, deviceType = fingerprintUserAgent(req.UserAgent)
	} else {
		_, deviceType = fingerprintUserAgent(req.UserAgent)
	}
	if _, err := db.DB.Exec(`INSERT INTO device_inventory (
		mac, tenant, username, friendly_name, ownership, platform, device_type, user_agent, source, compliance_status, last_ip, last_session_id, first_seen, last_seen, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		tenant = COALESCE(excluded.tenant, device_inventory.tenant),
		username = excluded.username,
		friendly_name = COALESCE(excluded.friendly_name, device_inventory.friendly_name),
		ownership = COALESCE(excluded.ownership, device_inventory.ownership),
		platform = COALESCE(excluded.platform, device_inventory.platform),
		device_type = COALESCE(excluded.device_type, device_inventory.device_type),
		user_agent = COALESCE(excluded.user_agent, device_inventory.user_agent),
		source = COALESCE(excluded.source, device_inventory.source),
		last_ip = COALESCE(excluded.last_ip, device_inventory.last_ip),
		last_session_id = COALESCE(excluded.last_session_id, device_inventory.last_session_id),
		last_seen = excluded.last_seen,
		updated_at = excluded.updated_at`,
		mac, nullable(tenant), req.Username, nullable(req.FriendlyName), nullable(req.Ownership), nullable(platform), nullable(deviceType),
		nullable(req.UserAgent), nullable(req.Source), complianceUnknown, nullable(req.LastIP), nullable(req.SessionID), now, now, now); err != nil {
		return nil, err
	}

	device, err := s.GetDeviceByMAC(mac)
	if err != nil {
		return nil, err
	}
	result := &RegisterResult{Device: device}
	if s.cfg.Onboarding.CertificateEnrollmentEnabled && strings.EqualFold(strings.TrimSpace(s.cfg.Onboarding.CAMode), "internal") {
		cert, certPEM, keyPEM, caPEM, err := s.issueClientCertificate(device, req.Username)
		if err != nil {
			return nil, err
		}
		result.Certificate = cert
		result.CertificatePEM = certPEM
		result.PrivateKeyPEM = keyPEM
		result.CertificateCAPEM = caPEM
	}
	return result, nil
}

func (s *Service) GetDeviceByMAC(mac string) (*Device, error) {
	row := db.DB.QueryRow(`SELECT id, mac, COALESCE(tenant, ''), COALESCE(username, ''), COALESCE(friendly_name, ''), COALESCE(ownership, ''),
		COALESCE(platform, ''), COALESCE(device_type, ''), COALESCE(user_agent, ''), COALESCE(source, ''),
		COALESCE(managed, 0), compliant, COALESCE(compliance_status, ''), COALESCE(remediation_state, ''),
		COALESCE(mdm_provider, ''), COALESCE(mdm_device_id, ''),
		COALESCE((SELECT id FROM device_certificates WHERE device_mac = device_inventory.mac AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1), ''),
		COALESCE(certificate_serial, ''),
		COALESCE(certificate_subject, ''), COALESCE(certificate_valid_until, ''), COALESCE(last_ip, ''),
		COALESCE(last_session_id, ''), COALESCE(first_seen, ''), COALESCE(last_seen, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM device_inventory WHERE mac = ?`, normalizeMAC(mac))
	return scanDevice(row)
}

func (s *Service) ListDevices(limit int, tenantScopes ...string) ([]Device, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `SELECT id, mac, COALESCE(tenant, ''), COALESCE(username, ''), COALESCE(friendly_name, ''), COALESCE(ownership, ''),
		COALESCE(platform, ''), COALESCE(device_type, ''), COALESCE(user_agent, ''), COALESCE(source, ''),
		COALESCE(managed, 0), compliant, COALESCE(compliance_status, ''), COALESCE(remediation_state, ''),
		COALESCE(mdm_provider, ''), COALESCE(mdm_device_id, ''),
		COALESCE((SELECT id FROM device_certificates WHERE device_mac = device_inventory.mac AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1), ''),
		COALESCE(certificate_serial, ''),
		COALESCE(certificate_subject, ''), COALESCE(certificate_valid_until, ''), COALESCE(last_ip, ''),
		COALESCE(last_session_id, ''), COALESCE(first_seen, ''), COALESCE(last_seen, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM device_inventory`
	args := []any{}
	if scopes := normalizeTenants(tenantScopes); len(scopes) > 0 {
		query += ` WHERE COALESCE(tenant, '') IN (` + strings.TrimRight(strings.Repeat("?,", len(scopes)), ",") + `)`
		for _, scope := range scopes {
			args = append(args, scope)
		}
	}
	query += ` ORDER BY COALESCE(last_seen, created_at) DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *device)
	}
	return devices, rows.Err()
}

func (s *Service) ListCertificates() ([]DeviceCertificate, error) {
	rows, err := db.DB.Query(`SELECT id, device_mac, COALESCE(username, ''), common_name, serial_number, cert_path, key_path, ca_path,
		COALESCE(created_at, ''), COALESCE(expires_at, ''), COALESCE(revoked_at, '')
		FROM device_certificates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []DeviceCertificate
	for rows.Next() {
		var item DeviceCertificate
		if err := rows.Scan(&item.ID, &item.DeviceMAC, &item.Username, &item.CommonName, &item.Serial, &item.CertPath, &item.KeyPath, &item.CAPath, &item.CreatedAt, &item.ExpiresAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) LoadCertificateBundle(certificateID string) (*DeviceCertificate, string, string, string, error) {
	var item DeviceCertificate
	err := db.DB.QueryRow(`SELECT id, device_mac, COALESCE(username, ''), common_name, serial_number, cert_path, key_path, ca_path,
		COALESCE(created_at, ''), COALESCE(expires_at, ''), COALESCE(revoked_at, '')
		FROM device_certificates WHERE id = ?`, certificateID).
		Scan(&item.ID, &item.DeviceMAC, &item.Username, &item.CommonName, &item.Serial, &item.CertPath, &item.KeyPath, &item.CAPath, &item.CreatedAt, &item.ExpiresAt, &item.RevokedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", "", errors.New("certificate not found")
		}
		return nil, "", "", "", err
	}
	certPEM, err := os.ReadFile(item.CertPath)
	if err != nil {
		return nil, "", "", "", err
	}
	keyPEM, err := os.ReadFile(item.KeyPath)
	if err != nil {
		return nil, "", "", "", err
	}
	caPEM, err := os.ReadFile(item.CAPath)
	if err != nil {
		return nil, "", "", "", err
	}
	return &item, string(certPEM), string(keyPEM), string(caPEM), nil
}

func (s *Service) ApplyCompliance(records []ComplianceRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, record := range records {
		mac := normalizeMAC(record.MAC)
		if mac == "" {
			continue
		}
		status := strings.TrimSpace(record.ComplianceStatus)
		if status == "" {
			if record.Compliant {
				status = complianceCompliant
			} else {
				status = complianceNonCompliant
			}
		}
		managed := 0
		if record.Managed {
			managed = 1
		}
		_, err := tx.Exec(`INSERT INTO device_inventory (
			mac, tenant, friendly_name, platform, managed, compliant, compliance_status, remediation_state, mdm_provider, mdm_device_id, source, last_seen, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			tenant = COALESCE(device_inventory.tenant, excluded.tenant),
			friendly_name = COALESCE(excluded.friendly_name, device_inventory.friendly_name),
			platform = COALESCE(excluded.platform, device_inventory.platform),
			managed = excluded.managed,
			compliant = excluded.compliant,
			compliance_status = excluded.compliance_status,
			remediation_state = COALESCE(excluded.remediation_state, device_inventory.remediation_state),
			mdm_provider = COALESCE(excluded.mdm_provider, device_inventory.mdm_provider),
			mdm_device_id = COALESCE(excluded.mdm_device_id, device_inventory.mdm_device_id),
			source = COALESCE(excluded.source, device_inventory.source),
			last_seen = excluded.last_seen,
			updated_at = excluded.updated_at`,
			mac, nullable(s.lookupTenant("")),
			nullable(record.FriendlyName), nullable(record.Platform), managed, record.Compliant, status,
			nullable(record.RemediationState), nullable(record.MDMProvider), nullable(record.MDMDeviceID), "mdm-sync",
			time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.applyPostureToSessions()
}

func (s *Service) SyncFromMDM(ctx context.Context) error {
	if s.cfg == nil || !s.cfg.Profiling.MDMSyncEnabled {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Profiling.MDMEndpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mdm sync returned %s", resp.Status)
	}
	var records []ComplianceRecord
	if err := jsonNewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	return s.ApplyCompliance(records)
}

func (s *Service) SyncFromComplianceWebhook(ctx context.Context) error {
	if s.cfg == nil || strings.TrimSpace(s.cfg.Profiling.ComplianceWebhook) == "" {
		return nil
	}
	active, err := s.activeDevices()
	if err != nil {
		return err
	}
	payload, err := jsonMarshal(map[string]any{"devices": active})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Profiling.ComplianceWebhook, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("compliance webhook returned %s", resp.Status)
	}
	var records []ComplianceRecord
	if err := jsonNewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	return s.ApplyCompliance(records)
}

func (s *Service) applyPostureToSessions() error {
	if s.cfg == nil || !s.cfg.Profiling.PostureEnabled {
		return nil
	}
	rows, err := db.DB.Query(`SELECT mac, compliance_status FROM device_inventory`)
	if err != nil {
		return err
	}
	defer rows.Close()
	nonCompliant := map[string]bool{}
	for rows.Next() {
		var mac, status string
		if err := rows.Scan(&mac, &status); err != nil {
			return err
		}
		if strings.EqualFold(strings.TrimSpace(status), complianceNonCompliant) {
			nonCompliant[normalizeMAC(mac)] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	activeRows, err := db.DB.Query(`SELECT id, COALESCE(mac, ''), COALESCE(filter_id, '') FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		return err
	}
	defer activeRows.Close()
	for activeRows.Next() {
		var id, mac, filterID string
		if err := activeRows.Scan(&id, &mac, &filterID); err != nil {
			return err
		}
		mac = normalizeMAC(mac)
		if nonCompliant[mac] {
			if filterID != "quarantine-posture" {
				if _, err := db.DB.Exec(`UPDATE sessions SET filter_id = ?, last_activity = ? WHERE id = ?`, "quarantine-posture", time.Now(), id); err != nil {
					return err
				}
			}
		} else if filterID == "quarantine-posture" {
			if _, err := db.DB.Exec(`UPDATE sessions SET filter_id = NULL, last_activity = ? WHERE id = ?`, time.Now(), id); err != nil {
				return err
			}
		}
	}
	if err := activeRows.Err(); err != nil {
		return err
	}
	return syncRuntimeEnforcement(s.cfg)
}

func (s *Service) issueClientCertificate(device *Device, username string) (*DeviceCertificate, string, string, string, error) {
	caCertPath := strings.TrimSpace(s.cfg.Onboarding.CACertPath)
	caKeyPath := strings.TrimSpace(s.cfg.Onboarding.CAKeyPath)
	if caCertPath == "" || caKeyPath == "" {
		return nil, "", "", "", errors.New("internal CA paths are required for certificate enrollment")
	}
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, "", "", "", err
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, "", "", "", err
	}
	caCert, err := parseCertificatePEM(caCertPEM)
	if err != nil {
		return nil, "", "", "", err
	}
	caKey, err := parsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		return nil, "", "", "", err
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", "", err
	}
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", "", "", err
	}
	commonName := fmt.Sprintf("%s-%s", sanitizeCN(username), strings.ReplaceAll(device.MAC, ":", ""))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"AegisNAS Devices"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, "", "", "", err
	}
	certPEM := encodePEM("CERTIFICATE", clientDER)
	keyPEM := encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	baseDir := filepath.Join(filepath.Dir(s.cfg.Database.Path), "device-certs")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, "", "", "", err
	}
	id := uuid.NewString()
	certPath := filepath.Join(baseDir, id+".crt")
	keyPath := filepath.Join(baseDir, id+".key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		return nil, "", "", "", err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return nil, "", "", "", err
	}

	if _, err := db.DB.Exec(`INSERT INTO device_certificates (id, device_mac, username, common_name, serial_number, cert_path, key_path, ca_path, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, device.MAC, username, commonName, serial.Text(16), certPath, keyPath, caCertPath, now.Format(time.RFC3339), template.NotAfter.Format(time.RFC3339)); err != nil {
		return nil, "", "", "", err
	}
	if _, err := db.DB.Exec(`UPDATE device_inventory
		SET certificate_serial = ?, certificate_subject = ?, certificate_valid_until = ?, updated_at = ?
		WHERE mac = ?`, serial.Text(16), commonName, template.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339), device.MAC); err != nil {
		return nil, "", "", "", err
	}
	device.CertificateSerial = serial.Text(16)
	device.CertificateSubject = commonName
	device.CertificateValidUntil = template.NotAfter.Format(time.RFC3339)
	return &DeviceCertificate{
		ID:         id,
		DeviceMAC:  device.MAC,
		Username:   username,
		CommonName: commonName,
		Serial:     serial.Text(16),
		CertPath:   certPath,
		KeyPath:    keyPath,
		CAPath:     caCertPath,
		CreatedAt:  now.Format(time.RFC3339),
		ExpiresAt:  template.NotAfter.Format(time.RFC3339),
	}, certPEM, keyPEM, string(caCertPEM), nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDevice(row scanner) (*Device, error) {
	device := &Device{}
	var compliant sql.NullBool
	if err := row.Scan(&device.ID, &device.MAC, &device.Tenant, &device.Username, &device.FriendlyName, &device.Ownership, &device.Platform, &device.DeviceType,
		&device.UserAgent, &device.Source, &device.Managed, &compliant, &device.ComplianceStatus, &device.RemediationState,
		&device.MDMProvider, &device.MDMDeviceID, &device.CertificateID, &device.CertificateSerial, &device.CertificateSubject, &device.CertificateValidUntil,
		&device.LastIP, &device.LastSessionID, &device.FirstSeen, &device.LastSeen, &device.CreatedAt, &device.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("device not found")
		}
		return nil, err
	}
	if compliant.Valid {
		value := compliant.Bool
		device.Compliant = &value
	}
	return device, nil
}

func normalizeMAC(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func (s *Service) lookupTenant(username string) string {
	username = strings.TrimSpace(username)
	if username == "" || db.DB == nil {
		return ""
	}
	var tenant sql.NullString
	if err := db.DB.QueryRow(`SELECT COALESCE(tenant, '') FROM local_users WHERE username = ?`, username).Scan(&tenant); err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(tenant.String))
}

func normalizeTenants(scopes []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" || scope == "*" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func sanitizeCN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "device"
	}
	value = strings.ReplaceAll(value, " ", "-")
	return value
}

func encodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func parseCertificatePEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid certificate pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid private key pem")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func fingerprintUserAgent(ua string) (platform, deviceType string) {
	value := strings.ToLower(strings.TrimSpace(ua))
	switch {
	case strings.Contains(value, "iphone") || strings.Contains(value, "ipad") || strings.Contains(value, "ios"):
		platform = "ios"
	case strings.Contains(value, "android"):
		platform = "android"
	case strings.Contains(value, "windows"):
		platform = "windows"
	case strings.Contains(value, "mac os") || strings.Contains(value, "macintosh"):
		platform = "macos"
	case strings.Contains(value, "linux"):
		platform = "linux"
	default:
		platform = ""
	}
	switch {
	case strings.Contains(value, "mobile") || strings.Contains(value, "iphone") || strings.Contains(value, "android"):
		deviceType = "phone"
	case strings.Contains(value, "ipad") || strings.Contains(value, "tablet"):
		deviceType = "tablet"
	case strings.Contains(value, "windows") || strings.Contains(value, "macintosh") || strings.Contains(value, "linux"):
		deviceType = "laptop"
	default:
		deviceType = "unknown"
	}
	return platform, deviceType
}

func (s *Service) activeDevices() ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT COALESCE(mac, ''), COALESCE(username, ''), COALESCE(last_ip, ''), COALESCE(platform, ''), COALESCE(device_type, '') FROM device_inventory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []map[string]any
	for rows.Next() {
		var mac, username, ip, platform, deviceType string
		if err := rows.Scan(&mac, &username, &ip, &platform, &deviceType); err != nil {
			return nil, err
		}
		devices = append(devices, map[string]any{
			"mac":         mac,
			"username":    username,
			"ip":          ip,
			"platform":    platform,
			"device_type": deviceType,
		})
	}
	return devices, rows.Err()
}

var (
	jsonMarshal            = func(v any) ([]byte, error) { return json.Marshal(v) }
	jsonNewDecoder         = func(r io.Reader) *json.Decoder { return json.NewDecoder(r) }
	syncRuntimeEnforcement = func(cfg *config.Config) error { return enforcement.SyncRuntimeEnforcement(cfg) }
)
