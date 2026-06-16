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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"go.uber.org/zap"
)

const (
	complianceUnknown        = "unknown"
	complianceCompliant      = "compliant"
	complianceNonCompliant   = "non_compliant"
	highRiskProfileThreshold = 50
)

type Device struct {
	ID                    int      `json:"id"`
	MAC                   string   `json:"mac"`
	Tenant                string   `json:"tenant"`
	Username              string   `json:"username"`
	FriendlyName          string   `json:"friendly_name"`
	Ownership             string   `json:"ownership"`
	Platform              string   `json:"platform"`
	DeviceType            string   `json:"device_type"`
	UserAgent             string   `json:"user_agent"`
	Source                string   `json:"source"`
	Hostname              string   `json:"hostname"`
	DHCPClientID          string   `json:"dhcp_client_id"`
	DHCPFingerprint       string   `json:"dhcp_fingerprint"`
	LLDPChassisID         string   `json:"lldp_chassis_id"`
	LLDPPortID            string   `json:"lldp_port_id"`
	CDPDeviceID           string   `json:"cdp_device_id"`
	CDPPortID             string   `json:"cdp_port_id"`
	MACOUI                string   `json:"mac_oui"`
	RiskScore             int      `json:"risk_score"`
	RiskReasons           []string `json:"risk_reasons"`
	Managed               bool     `json:"managed"`
	Compliant             *bool    `json:"compliant,omitempty"`
	ComplianceStatus      string   `json:"compliance_status"`
	RemediationState      string   `json:"remediation_state"`
	MDMProvider           string   `json:"mdm_provider"`
	MDMDeviceID           string   `json:"mdm_device_id"`
	CertificateID         string   `json:"certificate_id"`
	CertificateSerial     string   `json:"certificate_serial"`
	CertificateSubject    string   `json:"certificate_subject"`
	CertificateValidUntil string   `json:"certificate_valid_until"`
	LastIP                string   `json:"last_ip"`
	LastSessionID         string   `json:"last_session_id"`
	FirstSeen             string   `json:"first_seen"`
	LastSeen              string   `json:"last_seen"`
	CreatedAt             string   `json:"created_at"`
	UpdatedAt             string   `json:"updated_at"`
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

type ComplianceSyncStats struct {
	Source              string `json:"source"`
	Provider            string `json:"provider"`
	TotalRecords        int    `json:"total_records"`
	ManagedRecords      int    `json:"managed_records"`
	CompliantRecords    int    `json:"compliant_records"`
	NonCompliantRecords int    `json:"non_compliant_records"`
	UnknownRecords      int    `json:"unknown_records"`
	RemediationRecords  int    `json:"remediation_records"`
}

type DHCPLeaseProfile struct {
	MAC              string
	IP               string
	Hostname         string
	ClientID         string
	Reservation      bool
	Expired          bool
	ExpiresAt        string
	RemainingSeconds int64
}

type DeviceProfileObservation struct {
	MAC             string `json:"mac"`
	IP              string `json:"ip,omitempty"`
	Username        string `json:"username,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	Source          string `json:"source,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	DHCPClientID    string `json:"dhcp_client_id,omitempty"`
	DHCPFingerprint string `json:"dhcp_fingerprint,omitempty"`
	LLDPChassisID   string `json:"lldp_chassis_id,omitempty"`
	LLDPPortID      string `json:"lldp_port_id,omitempty"`
	CDPDeviceID     string `json:"cdp_device_id,omitempty"`
	CDPPortID       string `json:"cdp_port_id,omitempty"`
}

type DeviceProfileObservationResult struct {
	Device                   *Device  `json:"device,omitempty"`
	RiskScore                int      `json:"risk_score"`
	RiskReasons              []string `json:"risk_reasons"`
	AutoQuarantinedSessions  int64    `json:"auto_quarantined_sessions"`
	ProfilePlatform          string   `json:"profile_platform,omitempty"`
	ProfileDeviceType        string   `json:"profile_device_type,omitempty"`
	ObservationStored        bool     `json:"observation_stored"`
	ObservationIgnoredReason string   `json:"observation_ignored_reason,omitempty"`
}

type LeaseProfileStats struct {
	Source                  string `json:"source"`
	TotalRecords            int    `json:"total_records"`
	ActiveRecords           int    `json:"active_records"`
	ExpiredRecords          int    `json:"expired_records"`
	ReservationRecords      int    `json:"reservation_records"`
	HostnameRecords         int    `json:"hostname_records"`
	ClientIDRecords         int    `json:"client_id_records"`
	LocallyAdministeredMACs int    `json:"locally_administered_macs"`
	HighRiskRecords         int    `json:"high_risk_records"`
	AutoQuarantinedSessions int64  `json:"auto_quarantined_sessions"`
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

func (s *Service) ObserveProfileSignals(observation DeviceProfileObservation) (*DeviceProfileObservationResult, error) {
	result := &DeviceProfileObservationResult{}
	if s == nil || s.cfg == nil {
		result.ObservationIgnoredReason = "configuration is not loaded"
		return result, nil
	}
	if !s.cfg.Onboarding.DeviceInventoryEnabled && !s.cfg.Profiling.MACInventoryEnabled && !s.cfg.Profiling.PassiveEnabled {
		result.ObservationIgnoredReason = "device inventory and profiling are disabled"
		return result, nil
	}
	mac := normalizeMAC(observation.MAC)
	if mac == "" {
		return nil, errors.New("device MAC is required")
	}
	observation.MAC = mac
	observation.Username = strings.TrimSpace(observation.Username)
	observation.IP = strings.TrimSpace(observation.IP)
	observation.SessionID = strings.TrimSpace(observation.SessionID)
	observation.UserAgent = strings.TrimSpace(observation.UserAgent)
	observation.Source = firstNonEmptyString(observation.Source, "profile-observation")
	observation.Hostname = strings.TrimSpace(observation.Hostname)
	observation.DHCPClientID = strings.TrimSpace(observation.DHCPClientID)
	observation.DHCPFingerprint = strings.TrimSpace(observation.DHCPFingerprint)
	observation.LLDPChassisID = strings.TrimSpace(observation.LLDPChassisID)
	observation.LLDPPortID = strings.TrimSpace(observation.LLDPPortID)
	observation.CDPDeviceID = strings.TrimSpace(observation.CDPDeviceID)
	observation.CDPPortID = strings.TrimSpace(observation.CDPPortID)

	platform, deviceType := fingerprintProfileObservation(observation)
	riskScore, riskReasons := profileObservationRisk(observation)
	riskReasonsJSON, err := jsonMarshal(riskReasons)
	if err != nil {
		return nil, err
	}
	tenant := s.lookupTenant(observation.Username)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.DB.Exec(`INSERT INTO device_inventory (
		mac, tenant, username, platform, device_type, user_agent, source, hostname, dhcp_client_id, dhcp_fingerprint,
		lldp_chassis_id, lldp_port_id, cdp_device_id, cdp_port_id, mac_oui, risk_score, risk_reasons_json,
		compliance_status, last_ip, last_session_id, first_seen, last_seen, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		tenant = COALESCE(excluded.tenant, device_inventory.tenant),
		username = COALESCE(excluded.username, device_inventory.username),
		platform = CASE WHEN excluded.platform <> '' AND (COALESCE(device_inventory.platform, '') = '' OR COALESCE(device_inventory.platform, '') = 'unknown') THEN excluded.platform ELSE device_inventory.platform END,
		device_type = CASE WHEN excluded.device_type <> '' AND (COALESCE(device_inventory.device_type, '') = '' OR COALESCE(device_inventory.device_type, '') = 'unknown') THEN excluded.device_type ELSE device_inventory.device_type END,
		user_agent = COALESCE(excluded.user_agent, device_inventory.user_agent),
		source = COALESCE(excluded.source, device_inventory.source),
		hostname = COALESCE(excluded.hostname, device_inventory.hostname),
		dhcp_client_id = COALESCE(excluded.dhcp_client_id, device_inventory.dhcp_client_id),
		dhcp_fingerprint = COALESCE(excluded.dhcp_fingerprint, device_inventory.dhcp_fingerprint),
		lldp_chassis_id = COALESCE(excluded.lldp_chassis_id, device_inventory.lldp_chassis_id),
		lldp_port_id = COALESCE(excluded.lldp_port_id, device_inventory.lldp_port_id),
		cdp_device_id = COALESCE(excluded.cdp_device_id, device_inventory.cdp_device_id),
		cdp_port_id = COALESCE(excluded.cdp_port_id, device_inventory.cdp_port_id),
		mac_oui = COALESCE(excluded.mac_oui, device_inventory.mac_oui),
		risk_score = excluded.risk_score,
		risk_reasons_json = excluded.risk_reasons_json,
		compliance_status = COALESCE(device_inventory.compliance_status, excluded.compliance_status),
		last_ip = COALESCE(excluded.last_ip, device_inventory.last_ip),
		last_session_id = COALESCE(excluded.last_session_id, device_inventory.last_session_id),
		last_seen = excluded.last_seen,
		updated_at = excluded.updated_at`,
		mac, nullable(tenant), nullable(observation.Username), nullable(platform), nullable(deviceType), nullable(observation.UserAgent), nullable(observation.Source),
		nullable(observation.Hostname), nullable(observation.DHCPClientID), nullable(observation.DHCPFingerprint),
		nullable(observation.LLDPChassisID), nullable(observation.LLDPPortID), nullable(observation.CDPDeviceID), nullable(observation.CDPPortID),
		nullable(macOUI(mac)), riskScore, string(riskReasonsJSON), complianceUnknown, nullable(observation.IP), nullable(observation.SessionID), now, now, now)
	if err != nil {
		return nil, err
	}
	if riskScore >= highRiskProfileThreshold && s.cfg.Profiling.PostureEnabled && s.cfg.Profiling.RemediationEnabled {
		quarantined, err := s.quarantineHighRiskProfileSessions(map[string]struct{}{mac: {}})
		if err != nil {
			return nil, err
		}
		result.AutoQuarantinedSessions = quarantined
		if quarantined > 0 {
			if err := syncRuntimeEnforcement(s.cfg); err != nil {
				return nil, err
			}
		}
	}
	device, err := s.GetDeviceByMAC(mac)
	if err != nil {
		return nil, err
	}
	result.Device = device
	result.RiskScore = riskScore
	result.RiskReasons = riskReasons
	result.ProfilePlatform = platform
	result.ProfileDeviceType = deviceType
	result.ObservationStored = true
	return result, nil
}

func (s *Service) ObserveDHCPLeaseProfiles(leases []DHCPLeaseProfile) (*LeaseProfileStats, error) {
	stats := &LeaseProfileStats{Source: "dhcp-lease"}
	if s == nil || s.cfg == nil || len(leases) == 0 {
		return stats, nil
	}
	if !s.cfg.Onboarding.DeviceInventoryEnabled && !s.cfg.Profiling.MACInventoryEnabled && !s.cfg.Profiling.PassiveEnabled {
		return stats, nil
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	highRiskMACs := map[string]struct{}{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, lease := range leases {
		mac := normalizeMAC(lease.MAC)
		if mac == "" {
			continue
		}
		stats.TotalRecords++
		if lease.Expired {
			stats.ExpiredRecords++
		} else {
			stats.ActiveRecords++
		}
		if lease.Reservation {
			stats.ReservationRecords++
		}
		hostname := strings.TrimSpace(lease.Hostname)
		if hostname != "" {
			stats.HostnameRecords++
		}
		clientID := strings.TrimSpace(lease.ClientID)
		if clientID != "" {
			stats.ClientIDRecords++
		}
		if locallyAdministeredMAC(mac) {
			stats.LocallyAdministeredMACs++
		}
		platform, deviceType := fingerprintDHCPProfile(hostname, clientID)
		riskScore, riskReasons := dhcpLeaseRisk(lease)
		if riskScore >= highRiskProfileThreshold {
			stats.HighRiskRecords++
			highRiskMACs[mac] = struct{}{}
		}
		riskReasonsJSON, err := jsonMarshal(riskReasons)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO device_inventory (
			mac, friendly_name, platform, device_type, source, hostname, dhcp_client_id, mac_oui, risk_score, risk_reasons_json,
			compliance_status, last_ip, first_seen, last_seen, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			friendly_name = CASE WHEN COALESCE(device_inventory.friendly_name, '') = '' THEN excluded.friendly_name ELSE device_inventory.friendly_name END,
			platform = CASE WHEN COALESCE(device_inventory.platform, '') = '' THEN excluded.platform ELSE device_inventory.platform END,
			device_type = CASE WHEN COALESCE(device_inventory.device_type, '') = '' OR device_inventory.device_type = 'unknown' THEN excluded.device_type ELSE device_inventory.device_type END,
			source = CASE WHEN excluded.source <> '' THEN excluded.source ELSE device_inventory.source END,
			hostname = COALESCE(excluded.hostname, device_inventory.hostname),
			dhcp_client_id = COALESCE(excluded.dhcp_client_id, device_inventory.dhcp_client_id),
			mac_oui = COALESCE(excluded.mac_oui, device_inventory.mac_oui),
			risk_score = excluded.risk_score,
			risk_reasons_json = excluded.risk_reasons_json,
			compliance_status = COALESCE(device_inventory.compliance_status, excluded.compliance_status),
			last_ip = COALESCE(excluded.last_ip, device_inventory.last_ip),
			last_seen = excluded.last_seen,
			updated_at = excluded.updated_at`,
			mac, nullable(hostname), nullable(platform), nullable(deviceType), "dhcp-lease",
			nullable(hostname), nullable(clientID), nullable(macOUI(mac)), riskScore, string(riskReasonsJSON),
			complianceUnknown, nullable(lease.IP), now, now, now)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if s.cfg.Profiling.PostureEnabled && s.cfg.Profiling.RemediationEnabled && len(highRiskMACs) > 0 {
		quarantined, err := s.quarantineHighRiskProfileSessions(highRiskMACs)
		if err != nil {
			return nil, err
		}
		stats.AutoQuarantinedSessions = quarantined
		if quarantined > 0 {
			if err := syncRuntimeEnforcement(s.cfg); err != nil {
				return nil, err
			}
		}
	}
	return stats, nil
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
	if s.cfg.Onboarding.CertificateEnrollmentEnabled {
		var (
			cert    *DeviceCertificate
			certPEM string
			keyPEM  string
			caPEM   string
		)
		switch strings.ToLower(strings.TrimSpace(s.cfg.Onboarding.CAMode)) {
		case "internal":
			cert, certPEM, keyPEM, caPEM, err = s.issueClientCertificate(device, req.Username)
		case "external":
			cert, certPEM, keyPEM, caPEM, err = s.enrollExternalClientCertificate(ctx, device, req)
		}
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
		COALESCE(hostname, ''), COALESCE(dhcp_client_id, ''), COALESCE(dhcp_fingerprint, ''),
		COALESCE(lldp_chassis_id, ''), COALESCE(lldp_port_id, ''), COALESCE(cdp_device_id, ''), COALESCE(cdp_port_id, ''),
		COALESCE(mac_oui, ''), COALESCE(risk_score, 0), COALESCE(risk_reasons_json, '[]'),
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
		COALESCE(hostname, ''), COALESCE(dhcp_client_id, ''), COALESCE(dhcp_fingerprint, ''),
		COALESCE(lldp_chassis_id, ''), COALESCE(lldp_port_id, ''), COALESCE(cdp_device_id, ''), COALESCE(cdp_port_id, ''),
		COALESCE(mac_oui, ''), COALESCE(risk_score, 0), COALESCE(risk_reasons_json, '[]'),
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
	caPEM := []byte{}
	if strings.TrimSpace(item.CAPath) != "" {
		caPEM, err = os.ReadFile(item.CAPath)
		if err != nil {
			return nil, "", "", "", err
		}
	}
	return &item, string(certPEM), string(keyPEM), string(caPEM), nil
}

func (s *Service) ApplyCompliance(records []ComplianceRecord, source, provider string) (*ComplianceSyncStats, error) {
	stats := &ComplianceSyncStats{
		Source:   strings.TrimSpace(source),
		Provider: normalizeMDMProvider(provider),
	}
	if len(records) == 0 {
		return stats, nil
	}
	tx, err := db.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, record := range records {
		mac := normalizeMAC(record.MAC)
		if mac == "" {
			continue
		}
		stats.TotalRecords++
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
			stats.ManagedRecords++
		}
		switch normalizeComplianceStatus(status) {
		case complianceCompliant:
			stats.CompliantRecords++
		case complianceNonCompliant:
			stats.NonCompliantRecords++
		default:
			stats.UnknownRecords++
		}
		if strings.TrimSpace(record.RemediationState) != "" {
			stats.RemediationRecords++
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
			nullable(record.RemediationState), nullable(normalizeMDMProvider(firstNonEmptyString(record.MDMProvider, provider))), nullable(record.MDMDeviceID), nullable(strings.TrimSpace(source)),
			time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return stats, s.applyPostureToSessions()
}

func (s *Service) SyncFromMDM(ctx context.Context) (*ComplianceSyncStats, error) {
	if s.cfg == nil {
		return &ComplianceSyncStats{Source: "mdm-sync", Provider: "generic"}, nil
	}
	if !s.cfg.Profiling.MDMSyncEnabled {
		return &ComplianceSyncStats{Source: "mdm-sync", Provider: normalizeMDMProvider(s.cfg.Profiling.MDMProvider)}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Profiling.MDMEndpoint, nil)
	if err != nil {
		return nil, err
	}
	setBearerToken(req, s.cfg.Profiling.MDMAPITokenEnv)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mdm sync returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	records, err := parseMDMComplianceRecords(normalizeMDMProvider(s.cfg.Profiling.MDMProvider), body)
	if err != nil {
		return nil, err
	}
	return s.ApplyCompliance(records, "mdm-sync", s.cfg.Profiling.MDMProvider)
}

func (s *Service) SyncFromComplianceWebhook(ctx context.Context) (*ComplianceSyncStats, error) {
	if s.cfg == nil {
		return &ComplianceSyncStats{Source: "compliance-webhook", Provider: "compliance-webhook"}, nil
	}
	if strings.TrimSpace(s.cfg.Profiling.ComplianceWebhook) == "" {
		return &ComplianceSyncStats{Source: "compliance-webhook", Provider: "compliance-webhook"}, nil
	}
	active, err := s.activeDevices()
	if err != nil {
		return nil, err
	}
	payload, err := jsonMarshal(map[string]any{"devices": active})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Profiling.ComplianceWebhook, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setBearerToken(req, s.cfg.Profiling.ComplianceTokenEnv)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("compliance webhook returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	records, err := parseComplianceWebhookRecords(body)
	if err != nil {
		return nil, err
	}
	return s.ApplyCompliance(records, "compliance-webhook", "compliance-webhook")
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
	type activeSession struct {
		ID       string
		MAC      string
		FilterID string
	}
	var activeSessions []activeSession
	for activeRows.Next() {
		var item activeSession
		if err := activeRows.Scan(&item.ID, &item.MAC, &item.FilterID); err != nil {
			return err
		}
		activeSessions = append(activeSessions, item)
	}
	if err := activeRows.Err(); err != nil {
		return err
	}
	for _, session := range activeSessions {
		mac := normalizeMAC(session.MAC)
		if nonCompliant[mac] {
			if session.FilterID != "quarantine-posture" {
				if _, err := db.DB.Exec(`UPDATE sessions SET filter_id = ?, last_activity = ? WHERE id = ?`, "quarantine-posture", time.Now(), session.ID); err != nil {
					return err
				}
			}
		} else if session.FilterID == "quarantine-posture" {
			if _, err := db.DB.Exec(`UPDATE sessions SET filter_id = NULL, last_activity = ? WHERE id = ?`, time.Now(), session.ID); err != nil {
				return err
			}
		}
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

type externalEnrollmentRequest struct {
	Username     string `json:"username"`
	DeviceMAC    string `json:"device_mac"`
	Tenant       string `json:"tenant,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	LastIP       string `json:"last_ip,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Ownership    string `json:"ownership,omitempty"`
	Platform     string `json:"platform,omitempty"`
	DeviceType   string `json:"device_type,omitempty"`
	CommonName   string `json:"common_name"`
	CSRPEM       string `json:"csr_pem"`
}

type externalEnrollmentResponse struct {
	CertificatePEM   string `json:"certificate_pem"`
	CertificateCAPEM string `json:"ca_pem"`
	SerialNumber     string `json:"serial_number"`
	CommonName       string `json:"common_name"`
	ExpiresAt        string `json:"expires_at"`
}

func (s *Service) enrollExternalClientCertificate(ctx context.Context, device *Device, req RegisterRequest) (*DeviceCertificate, string, string, string, error) {
	if strings.TrimSpace(s.cfg.Onboarding.CAEnrollmentURL) == "" {
		return nil, "", "", "", errors.New("external CA enrollment URL is required for certificate enrollment")
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", "", err
	}
	commonName := fmt.Sprintf("%s-%s", sanitizeCN(req.Username), strings.ReplaceAll(device.MAC, ":", ""))
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"AegisNAS Devices"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		return nil, "", "", "", err
	}
	csrPEM := encodePEM("CERTIFICATE REQUEST", csrDER)
	keyPEM := encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	deviceType := strings.TrimSpace(device.DeviceType)
	if deviceType == "" {
		_, deviceType = fingerprintUserAgent(req.UserAgent)
	}
	payload, err := jsonMarshal(externalEnrollmentRequest{
		Username:     req.Username,
		DeviceMAC:    device.MAC,
		Tenant:       device.Tenant,
		SessionID:    req.SessionID,
		LastIP:       req.LastIP,
		FriendlyName: req.FriendlyName,
		Ownership:    req.Ownership,
		Platform:     firstNonEmptyString(req.Platform, device.Platform),
		DeviceType:   deviceType,
		CommonName:   commonName,
		CSRPEM:       csrPEM,
	})
	if err != nil {
		return nil, "", "", "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Onboarding.CAEnrollmentURL, strings.NewReader(string(payload)))
	if err != nil {
		return nil, "", "", "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	setBearerToken(httpReq, s.cfg.Onboarding.CAEnrollmentTokenEnv)

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", "", "", fmt.Errorf("external CA enrollment returned %s", resp.Status)
	}
	var enrollment externalEnrollmentResponse
	if err := jsonNewDecoder(resp.Body).Decode(&enrollment); err != nil {
		return nil, "", "", "", err
	}
	if strings.TrimSpace(enrollment.CertificatePEM) == "" {
		return nil, "", "", "", errors.New("external CA enrollment response did not include certificate_pem")
	}
	issuedCert, err := parseCertificatePEM([]byte(enrollment.CertificatePEM))
	if err != nil {
		return nil, "", "", "", err
	}

	baseDir := filepath.Join(filepath.Dir(s.cfg.Database.Path), "device-certs")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, "", "", "", err
	}
	id := uuid.NewString()
	certPath := filepath.Join(baseDir, id+".crt")
	keyPath := filepath.Join(baseDir, id+".key")
	caPath := filepath.Join(baseDir, id+"-ca.crt")
	if err := os.WriteFile(certPath, []byte(enrollment.CertificatePEM), 0600); err != nil {
		return nil, "", "", "", err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return nil, "", "", "", err
	}
	if strings.TrimSpace(enrollment.CertificateCAPEM) != "" {
		if err := os.WriteFile(caPath, []byte(enrollment.CertificateCAPEM), 0600); err != nil {
			return nil, "", "", "", err
		}
	} else {
		caPath = ""
	}

	serial := strings.TrimSpace(enrollment.SerialNumber)
	if serial == "" {
		serial = issuedCert.SerialNumber.Text(16)
	}
	commonName = firstNonEmptyString(strings.TrimSpace(enrollment.CommonName), issuedCert.Subject.CommonName, commonName)
	expiresAt := firstNonEmptyString(strings.TrimSpace(enrollment.ExpiresAt), issuedCert.NotAfter.UTC().Format(time.RFC3339))
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.DB.Exec(`INSERT INTO device_certificates (id, device_mac, username, common_name, serial_number, cert_path, key_path, ca_path, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, device.MAC, req.Username, commonName, serial, certPath, keyPath, nullIfEmpty(caPath), now, expiresAt); err != nil {
		return nil, "", "", "", err
	}
	if _, err := db.DB.Exec(`UPDATE device_inventory
		SET certificate_serial = ?, certificate_subject = ?, certificate_valid_until = ?, updated_at = ?
		WHERE mac = ?`, serial, commonName, expiresAt, now, device.MAC); err != nil {
		return nil, "", "", "", err
	}
	device.CertificateSerial = serial
	device.CertificateSubject = commonName
	device.CertificateValidUntil = expiresAt
	return &DeviceCertificate{
		ID:         id,
		DeviceMAC:  device.MAC,
		Username:   req.Username,
		CommonName: commonName,
		Serial:     serial,
		CertPath:   certPath,
		KeyPath:    keyPath,
		CAPath:     caPath,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}, enrollment.CertificatePEM, keyPEM, enrollment.CertificateCAPEM, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDevice(row scanner) (*Device, error) {
	device := &Device{}
	var compliant sql.NullBool
	riskReasonsJSON := "[]"
	if err := row.Scan(&device.ID, &device.MAC, &device.Tenant, &device.Username, &device.FriendlyName, &device.Ownership, &device.Platform, &device.DeviceType,
		&device.UserAgent, &device.Source, &device.Hostname, &device.DHCPClientID, &device.DHCPFingerprint,
		&device.LLDPChassisID, &device.LLDPPortID, &device.CDPDeviceID, &device.CDPPortID, &device.MACOUI, &device.RiskScore, &riskReasonsJSON,
		&device.Managed, &compliant, &device.ComplianceStatus, &device.RemediationState,
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
	if err := json.Unmarshal([]byte(riskReasonsJSON), &device.RiskReasons); err != nil {
		device.RiskReasons = nil
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

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nullIfEmpty(value string) any {
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

func fingerprintDHCPProfile(hostname, clientID string) (platform, deviceType string) {
	value := strings.ToLower(strings.TrimSpace(hostname + " " + clientID))
	switch {
	case strings.Contains(value, "iphone") || strings.Contains(value, "ipad"):
		platform = "ios"
	case strings.Contains(value, "android"):
		platform = "android"
	case strings.Contains(value, "windows") || strings.Contains(value, "win-") || strings.Contains(value, "msft"):
		platform = "windows"
	case strings.Contains(value, "macbook") || strings.Contains(value, "imac") || strings.Contains(value, "macos"):
		platform = "macos"
	case strings.Contains(value, "chromebook") || strings.Contains(value, "chromeos"):
		platform = "chromeos"
	case strings.Contains(value, "linux") || strings.Contains(value, "ubuntu") || strings.Contains(value, "raspberry"):
		platform = "linux"
	}
	switch {
	case strings.Contains(value, "iphone") || strings.Contains(value, "android"):
		deviceType = "phone"
	case strings.Contains(value, "ipad") || strings.Contains(value, "tablet"):
		deviceType = "tablet"
	case strings.Contains(value, "printer"):
		deviceType = "printer"
	case strings.Contains(value, "camera"):
		deviceType = "camera"
	case strings.Contains(value, "tv") || strings.Contains(value, "roku") || strings.Contains(value, "chromecast"):
		deviceType = "media"
	case strings.Contains(value, "laptop") || strings.Contains(value, "macbook") || strings.Contains(value, "windows") || strings.Contains(value, "msft") || strings.Contains(value, "ubuntu"):
		deviceType = "laptop"
	default:
		deviceType = "unknown"
	}
	return platform, deviceType
}

func dhcpLeaseRisk(lease DHCPLeaseProfile) (int, []string) {
	score := 0
	reasons := []string{}
	if lease.Expired {
		score += 30
		reasons = append(reasons, "lease_expired")
	} else if lease.RemainingSeconds > 0 && lease.RemainingSeconds < 300 {
		score += 10
		reasons = append(reasons, "lease_expiring_soon")
	}
	if !lease.Reservation {
		score += 5
		reasons = append(reasons, "dynamic_lease")
	}
	if strings.TrimSpace(lease.Hostname) == "" {
		score += 10
		reasons = append(reasons, "missing_hostname")
	}
	if strings.TrimSpace(lease.ClientID) == "" {
		score += 5
		reasons = append(reasons, "missing_dhcp_client_id")
	}
	if locallyAdministeredMAC(lease.MAC) {
		score += 25
		reasons = append(reasons, "locally_administered_mac")
	}
	if score > 100 {
		score = 100
	}
	return score, reasons
}

func fingerprintProfileObservation(observation DeviceProfileObservation) (platform, deviceType string) {
	userAgentPlatform, userAgentType := fingerprintUserAgent(observation.UserAgent)
	dhcpPlatform, dhcpType := fingerprintDHCPProfile(observation.Hostname, strings.TrimSpace(observation.DHCPClientID+" "+observation.DHCPFingerprint))
	neighborPlatform := fingerprintNeighborPlatform(observation)

	platform = firstNonEmptyString(userAgentPlatform, dhcpPlatform, neighborPlatform)
	for _, candidate := range []string{userAgentType, dhcpType} {
		if candidate != "" && candidate != "unknown" {
			deviceType = candidate
			break
		}
	}
	if deviceType == "" && hasNeighborSignal(observation) {
		deviceType = "network-equipment"
	}
	if deviceType == "" {
		deviceType = "unknown"
	}
	return platform, deviceType
}

func profileObservationRisk(observation DeviceProfileObservation) (int, []string) {
	score := 0
	reasons := []string{}
	if locallyAdministeredMAC(observation.MAC) {
		score += 25
		reasons = append(reasons, "locally_administered_mac")
	}
	identitySignals := 0
	for _, value := range []string{
		observation.Hostname,
		observation.DHCPClientID,
		observation.DHCPFingerprint,
		observation.UserAgent,
		observation.LLDPChassisID,
		observation.CDPDeviceID,
	} {
		if strings.TrimSpace(value) != "" {
			identitySignals++
		}
	}
	if identitySignals == 0 {
		score += 20
		reasons = append(reasons, "low_identity_signal")
	}
	if strings.TrimSpace(observation.Hostname) == "" {
		score += 5
		reasons = append(reasons, "missing_hostname")
	}
	if strings.TrimSpace(observation.UserAgent) == "" {
		score += 5
		reasons = append(reasons, "missing_user_agent")
	}
	if strings.TrimSpace(observation.DHCPClientID) == "" && strings.TrimSpace(observation.DHCPFingerprint) == "" {
		score += 5
		reasons = append(reasons, "missing_dhcp_fingerprint")
	}
	userAgentPlatform, _ := fingerprintUserAgent(observation.UserAgent)
	dhcpPlatform, _ := fingerprintDHCPProfile(observation.Hostname, strings.TrimSpace(observation.DHCPClientID+" "+observation.DHCPFingerprint))
	if platformsConflict(userAgentPlatform, dhcpPlatform) {
		score += 25
		reasons = append(reasons, "profile_platform_mismatch")
	}
	if hasNeighborSignal(observation) && strings.TrimSpace(observation.Username) != "" {
		score += 15
		reasons = append(reasons, "infrastructure_neighbor_signal")
	}
	if score > 100 {
		score = 100
	}
	return score, uniqueStrings(reasons)
}

func fingerprintNeighborPlatform(observation DeviceProfileObservation) string {
	value := strings.ToLower(strings.Join([]string{
		observation.LLDPChassisID,
		observation.LLDPPortID,
		observation.CDPDeviceID,
		observation.CDPPortID,
	}, " "))
	switch {
	case strings.Contains(value, "cisco") || strings.Contains(value, "catalyst") || strings.Contains(value, "meraki"):
		return "cisco"
	case strings.Contains(value, "aruba") || strings.Contains(value, "procurve"):
		return "aruba"
	case strings.Contains(value, "juniper") || strings.Contains(value, "mist"):
		return "juniper"
	case strings.Contains(value, "ruckus"):
		return "ruckus"
	case strings.Contains(value, "fortinet") || strings.Contains(value, "fortigate"):
		return "fortinet"
	case strings.Contains(value, "mikrotik") || strings.Contains(value, "routeros"):
		return "mikrotik"
	case strings.Contains(value, "ubiquiti") || strings.Contains(value, "unifi"):
		return "unifi"
	case strings.Contains(value, "huawei"):
		return "huawei"
	case strings.Contains(value, "h3c"):
		return "h3c"
	case strings.Contains(value, "extreme"):
		return "extreme"
	default:
		return ""
	}
}

func hasNeighborSignal(observation DeviceProfileObservation) bool {
	return strings.TrimSpace(observation.LLDPChassisID) != "" ||
		strings.TrimSpace(observation.LLDPPortID) != "" ||
		strings.TrimSpace(observation.CDPDeviceID) != "" ||
		strings.TrimSpace(observation.CDPPortID) != ""
}

func platformsConflict(a, b string) bool {
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	return a != "" && b != "" && a != b
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func macOUI(mac string) string {
	parts := strings.Split(normalizeMAC(mac), ":")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ":")
}

func locallyAdministeredMAC(mac string) bool {
	parts := strings.Split(normalizeMAC(mac), ":")
	if len(parts) == 0 || len(parts[0]) == 0 {
		return false
	}
	firstOctet, err := strconv.ParseUint(parts[0], 16, 8)
	if err != nil {
		return false
	}
	return firstOctet&0x02 != 0
}

func (s *Service) quarantineHighRiskProfileSessions(highRiskMACs map[string]struct{}) (int64, error) {
	if len(highRiskMACs) == 0 {
		return 0, nil
	}
	var total int64
	now := time.Now()
	for mac := range highRiskMACs {
		result, err := db.DB.Exec(`UPDATE sessions
			SET filter_id = ?, last_activity = ?
			WHERE end_time IS NULL
				AND LOWER(COALESCE(mac, '')) = ?
				AND COALESCE(filter_id, '') <> ?`,
			"quarantine-profile-risk", now, normalizeMAC(mac), "quarantine-profile-risk")
		if err != nil {
			return total, err
		}
		affected, _ := result.RowsAffected()
		total += affected
	}
	return total, nil
}

func (s *Service) activeDevices() ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT COALESCE(mac, ''), COALESCE(username, ''), COALESCE(last_ip, ''), COALESCE(platform, ''), COALESCE(device_type, ''), COALESCE(risk_score, 0), COALESCE(compliance_status, '') FROM device_inventory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []map[string]any
	for rows.Next() {
		var mac, username, ip, platform, deviceType string
		var riskScore int
		var complianceStatus string
		if err := rows.Scan(&mac, &username, &ip, &platform, &deviceType, &riskScore, &complianceStatus); err != nil {
			return nil, err
		}
		devices = append(devices, map[string]any{
			"mac":               mac,
			"username":          username,
			"ip":                ip,
			"platform":          platform,
			"device_type":       deviceType,
			"risk_score":        riskScore,
			"compliance_status": complianceStatus,
		})
	}
	return devices, rows.Err()
}

func parseMDMComplianceRecords(provider string, body []byte) ([]ComplianceRecord, error) {
	switch normalizeMDMProvider(provider) {
	case "intune":
		return parseIntuneComplianceRecords(body)
	case "jamf":
		return parseJamfComplianceRecords(body)
	case "workspace-one", "workspace-one-like", "generic":
		fallthrough
	default:
		return parseGenericComplianceRecords(body)
	}
}

func parseComplianceWebhookRecords(body []byte) ([]ComplianceRecord, error) {
	return parseGenericComplianceRecords(body)
}

func parseGenericComplianceRecords(body []byte) ([]ComplianceRecord, error) {
	var direct []ComplianceRecord
	if err := json.Unmarshal(body, &direct); err == nil {
		return direct, nil
	}
	var envelope struct {
		Records []ComplianceRecord `json:"records"`
		Devices []ComplianceRecord `json:"devices"`
		Items   []ComplianceRecord `json:"items"`
		Results []ComplianceRecord `json:"results"`
		Value   []ComplianceRecord `json:"value"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	switch {
	case len(envelope.Records) > 0:
		return envelope.Records, nil
	case len(envelope.Devices) > 0:
		return envelope.Devices, nil
	case len(envelope.Items) > 0:
		return envelope.Items, nil
	case len(envelope.Results) > 0:
		return envelope.Results, nil
	case len(envelope.Value) > 0:
		return envelope.Value, nil
	default:
		return []ComplianceRecord{}, nil
	}
}

func parseIntuneComplianceRecords(body []byte) ([]ComplianceRecord, error) {
	var envelope struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	records := make([]ComplianceRecord, 0, len(envelope.Value))
	for _, item := range envelope.Value {
		mac := firstNonEmptyString(
			stringMap(item, "wiFiMacAddress"),
			stringMap(item, "wifiMacAddress"),
			stringMap(item, "ethernetMacAddress"),
			stringMap(item, "macAddress"),
			stringMap(item, "mac"),
		)
		if normalizeMAC(mac) == "" {
			continue
		}
		complianceState := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			stringMap(item, "complianceState"),
			stringMap(item, "compliance_status"),
		)))
		status := complianceUnknown
		compliant := false
		switch complianceState {
		case "compliant":
			status = complianceCompliant
			compliant = true
		case "noncompliant", "non_compliant", "non-compliant", "in_grace_period":
			status = complianceNonCompliant
		}
		records = append(records, ComplianceRecord{
			MAC:              mac,
			Managed:          boolMap(item, "isManaged", "managed"),
			Compliant:        compliant,
			ComplianceStatus: status,
			RemediationState: firstNonEmptyString(stringMap(item, "complianceGracePeriodExpirationDateTime"), stringMap(item, "managementState")),
			MDMProvider:      "intune",
			MDMDeviceID:      firstNonEmptyString(stringMap(item, "azureADDeviceId"), stringMap(item, "id")),
			FriendlyName:     firstNonEmptyString(stringMap(item, "deviceName"), stringMap(item, "managedDeviceName")),
			Platform:         strings.ToLower(strings.TrimSpace(firstNonEmptyString(stringMap(item, "operatingSystem"), stringMap(item, "platform")))),
		})
	}
	return records, nil
}

func parseJamfComplianceRecords(body []byte) ([]ComplianceRecord, error) {
	var envelope struct {
		Results []map[string]any `json:"results"`
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	items := envelope.Results
	if len(items) == 0 {
		items = envelope.Devices
	}
	records := make([]ComplianceRecord, 0, len(items))
	for _, item := range items {
		mac := firstNonEmptyString(
			stringMap(item, "mac_address"),
			stringMap(item, "macAddress"),
			stringMap(item, "wifi_mac_address"),
			stringMap(item, "wifiMacAddress"),
			stringMap(item, "ethernet_mac_address"),
		)
		if normalizeMAC(mac) == "" {
			continue
		}
		complianceState := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			stringMap(item, "compliance_state"),
			stringMap(item, "complianceStatus"),
			stringMap(item, "status"),
		)))
		status := complianceUnknown
		compliant := false
		switch complianceState {
		case "compliant", "managed":
			status = complianceCompliant
			compliant = true
		case "non_compliant", "non-compliant", "not_compliant", "unmanaged":
			status = complianceNonCompliant
		}
		records = append(records, ComplianceRecord{
			MAC:              mac,
			Managed:          boolMap(item, "managed", "is_managed"),
			Compliant:        compliant,
			ComplianceStatus: status,
			RemediationState: firstNonEmptyString(stringMap(item, "remediation_state"), stringMap(item, "status_reason")),
			MDMProvider:      "jamf",
			MDMDeviceID:      firstNonEmptyString(stringMap(item, "udid"), stringMap(item, "id")),
			FriendlyName:     firstNonEmptyString(stringMap(item, "device_name"), stringMap(item, "name")),
			Platform:         strings.ToLower(strings.TrimSpace(firstNonEmptyString(stringMap(item, "platform"), stringMap(item, "os_type")))),
		})
	}
	return records, nil
}

func normalizeMDMProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "generic":
		return "generic"
	case "workspace-one", "workspace-one-like":
		return "workspace-one"
	case "intune":
		return "intune"
	case "jamf":
		return "jamf"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func normalizeComplianceStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case complianceCompliant:
		return complianceCompliant
	case complianceNonCompliant:
		return complianceNonCompliant
	default:
		return complianceUnknown
	}
}

func stringMap(item map[string]any, key string) string {
	if item == nil {
		return ""
	}
	if value, ok := item[key]; ok {
		if text, ok := value.(string); ok {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func boolMap(item map[string]any, keys ...string) bool {
	for _, key := range keys {
		if item == nil {
			return false
		}
		value, ok := item[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "true", "yes", "managed", "compliant":
				return true
			}
		}
	}
	return false
}

var (
	jsonMarshal            = func(v any) ([]byte, error) { return json.Marshal(v) }
	jsonNewDecoder         = func(r io.Reader) *json.Decoder { return json.NewDecoder(r) }
	syncRuntimeEnforcement = func(cfg *config.Config) error { return enforcement.SyncRuntimeEnforcement(cfg) }
)

func setBearerToken(req *http.Request, tokenEnv string) {
	tokenEnv = strings.TrimSpace(tokenEnv)
	if req == nil || tokenEnv == "" {
		return
	}
	if token := strings.TrimSpace(os.Getenv(tokenEnv)); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}
