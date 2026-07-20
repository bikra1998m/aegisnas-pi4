package certlifecycle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const SchemaVersion = 1

type PolicyReport struct {
	Enabled                    bool     `json:"enabled"`
	Mode                       string   `json:"mode"`
	FailClosed                 bool     `json:"fail_closed"`
	CAMode                     string   `json:"ca_mode"`
	CAReady                    bool     `json:"ca_ready"`
	CertificateEnrollmentReady bool     `json:"certificate_enrollment_ready"`
	EAPTLSReady                bool     `json:"eap_tls_ready"`
	DefaultTemplate            string   `json:"default_template"`
	Templates                  []string `json:"templates"`
	ActiveIssuer               string   `json:"active_issuer"`
	StagedIssuer               string   `json:"staged_issuer,omitempty"`
	IssuerRotationMode         string   `json:"issuer_rotation_mode"`
	IssuerOverlapSeconds       int      `json:"issuer_overlap_seconds"`
	CertificateValidityDays    int      `json:"certificate_validity_days"`
	MaxCertificateValidityDays int      `json:"max_certificate_validity_days"`
	RenewalWindowDays          int      `json:"renewal_window_days"`
	RequireCSR                 bool     `json:"require_csr"`
	RequireProofOfPossession   bool     `json:"require_proof_of_possession"`
	RequireDeviceBinding       bool     `json:"require_device_binding"`
	RequireSubjectAltName      bool     `json:"require_subject_alt_name"`
	AllowedKeyTypes            []string `json:"allowed_key_types"`
	MinRSABits                 int      `json:"min_rsa_bits"`
	AllowedECDSACurves         []string `json:"allowed_ecdsa_curves"`
	AllowServerKeyGeneration   bool     `json:"allow_server_key_generation"`
	EscrowPolicy               string   `json:"escrow_policy"`
	CRLEnabled                 bool     `json:"crl_enabled"`
	CRLPublishPath             string   `json:"crl_publish_path,omitempty"`
	OCSPEnabled                bool     `json:"ocsp_enabled"`
	OCSPResponderURL           string   `json:"ocsp_responder_url,omitempty"`
	RevocationAvailable        bool     `json:"revocation_available"`
	ESTEnabled                 bool     `json:"est_enabled"`
	SCEPEnabled                bool     `json:"scep_enabled"`
	BYODPortalEnabled          bool     `json:"byod_portal_enabled"`
	AuditEnabled               bool     `json:"audit_enabled"`
	EventRetentionLimit        int      `json:"event_retention_limit"`
	InventoryRetentionLimit    int      `json:"inventory_retention_limit"`
	Warnings                   []string `json:"warnings,omitempty"`
	BlockingIssues             []string `json:"blocking_issues,omitempty"`
}

type RuntimeSummary struct {
	TotalEvents             int            `json:"total_events"`
	Accepted                int            `json:"accepted"`
	Rejected                int            `json:"rejected"`
	MonitorAllowed          int            `json:"monitor_allowed"`
	RenewalDue              int            `json:"renewal_due"`
	RevocationBlocked       int            `json:"revocation_blocked"`
	WeakKey                 int            `json:"weak_key"`
	MissingCSR              int            `json:"missing_csr"`
	MissingDeviceBinding    int            `json:"missing_device_binding"`
	EscrowRejected          int            `json:"escrow_rejected"`
	ActiveInventory         int            `json:"active_inventory"`
	RevokedInventory        int            `json:"revoked_inventory"`
	RenewalDueInventory     int            `json:"renewal_due_inventory"`
	ByDecision              map[string]int `json:"by_decision,omitempty"`
	ByProtocol              map[string]int `json:"by_protocol,omitempty"`
	ByIssuer                map[string]int `json:"by_issuer,omitempty"`
	ByTemplate              map[string]int `json:"by_template,omitempty"`
	LastEventAt             string         `json:"last_event_at,omitempty"`
	LastRejectedReason      string         `json:"last_rejected_reason,omitempty"`
	LastRenewalDueAt        string         `json:"last_renewal_due_at,omitempty"`
	LastRevocationBlockedAt string         `json:"last_revocation_blocked_at,omitempty"`
}

type Capability struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Vendors    []string `json:"vendors"`
	RFCs       []string `json:"rfcs"`
	Attributes []string `json:"attributes"`
	Semantics  string   `json:"semantics"`
	Required   bool     `json:"required"`
	Stateful   bool     `json:"stateful"`
	Sensitive  bool     `json:"sensitive"`
}

type TemplateReport struct {
	Name                  string   `json:"name"`
	Default               bool     `json:"default"`
	AllowedProtocols      []string `json:"allowed_protocols"`
	ValidityDays          int      `json:"validity_days"`
	RenewalWindowDays     int      `json:"renewal_window_days"`
	RequireCSR            bool     `json:"require_csr"`
	RequireDeviceBinding  bool     `json:"require_device_binding"`
	RequireSubjectAltName bool     `json:"require_subject_alt_name"`
}

type IssuerReport struct {
	Name            string `json:"name"`
	State           string `json:"state"`
	RotationMode    string `json:"rotation_mode"`
	OverlapSeconds  int    `json:"overlap_seconds"`
	RevocationReady bool   `json:"revocation_ready"`
}

type Report struct {
	SchemaVersion    int              `json:"schema_version"`
	GeneratedAt      string           `json:"generated_at"`
	Status           string           `json:"status"`
	Message          string           `json:"message"`
	Policy           PolicyReport     `json:"policy"`
	Templates        []TemplateReport `json:"templates"`
	Issuers          []IssuerReport   `json:"issuers"`
	Capabilities     []Capability     `json:"capabilities"`
	Runtime          RuntimeSummary   `json:"runtime"`
	Warnings         []string         `json:"warnings,omitempty"`
	BlockingIssues   []string         `json:"blocking_issues,omitempty"`
	ReleaseChecklist string           `json:"release_checklist"`
	ExternalEvidence []string         `json:"external_evidence"`
}

type CSRAnalysis struct {
	Present        bool     `json:"present"`
	ValidPEM       bool     `json:"valid_pem"`
	SignatureValid bool     `json:"signature_valid"`
	Subject        string   `json:"subject,omitempty"`
	CommonName     string   `json:"common_name,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	SANCount       int      `json:"san_count"`
	KeyType        string   `json:"key_type,omitempty"`
	KeyBits        int      `json:"key_bits,omitempty"`
	Curve          string   `json:"curve,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type EvaluationRequest struct {
	Protocol              string            `json:"protocol"`
	Template              string            `json:"template"`
	Issuer                string            `json:"issuer"`
	DeviceID              string            `json:"device_id"`
	Tenant                string            `json:"tenant"`
	CSRPEM                string            `json:"csr_pem"`
	RequestedValidityDays int               `json:"requested_validity_days"`
	Renewal               bool              `json:"renewal"`
	ExistingSerial        string            `json:"existing_serial"`
	ExistingNotAfter      string            `json:"existing_not_after"`
	EscrowRequested       bool              `json:"escrow_requested"`
	ProofOfPossession     bool              `json:"proof_of_possession"`
	DeviceBound           bool              `json:"device_bound"`
	RevocationChecked     bool              `json:"revocation_checked"`
	CRLReachable          bool              `json:"crl_reachable"`
	OCSPReachable         bool              `json:"ocsp_reachable"`
	CertificateSerial     string            `json:"certificate_serial"`
	CertificateNotBefore  string            `json:"certificate_not_before"`
	CertificateNotAfter   string            `json:"certificate_not_after"`
	Details               map[string]string `json:"details,omitempty"`
}

type Decision struct {
	Decision             string            `json:"decision"`
	Reason               string            `json:"reason"`
	PolicyMode           string            `json:"policy_mode"`
	Protocol             string            `json:"protocol"`
	Template             string            `json:"template"`
	Issuer               string            `json:"issuer"`
	IssuerState          string            `json:"issuer_state"`
	DeviceID             string            `json:"device_id,omitempty"`
	Tenant               string            `json:"tenant,omitempty"`
	ValidityDays         int               `json:"validity_days"`
	Renewal              bool              `json:"renewal"`
	RenewalDue           bool              `json:"renewal_due"`
	InventoryStatus      string            `json:"inventory_status"`
	CSR                  CSRAnalysis       `json:"csr"`
	ProofOfPossession    bool              `json:"proof_of_possession"`
	DeviceBound          bool              `json:"device_bound"`
	RevocationChecked    bool              `json:"revocation_checked"`
	CRLReachable         bool              `json:"crl_reachable"`
	OCSPReachable        bool              `json:"ocsp_reachable"`
	EscrowRequested      bool              `json:"escrow_requested"`
	CertificateSerial    string            `json:"certificate_serial,omitempty"`
	CertificateNotBefore string            `json:"certificate_not_before,omitempty"`
	CertificateNotAfter  string            `json:"certificate_not_after,omitempty"`
	Warnings             []string          `json:"warnings,omitempty"`
	Dependencies         []string          `json:"dependencies,omitempty"`
	Details              map[string]string `json:"details,omitempty"`
}

func BuildReport(cfg *config.Config, runtime RuntimeSummary) Report {
	policy := BuildPolicyReport(cfg)
	report := Report{
		SchemaVersion:    SchemaVersion,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Policy:           policy,
		Templates:        templateReports(policy),
		Issuers:          issuerReports(policy),
		Capabilities:     CapabilityCatalog(),
		Runtime:          runtime,
		Warnings:         append([]string(nil), policy.Warnings...),
		BlockingIssues:   append([]string(nil), policy.BlockingIssues...),
		ReleaseChecklist: "nas-0027-release-certification-checklist.md",
		ExternalEvidence: []string{
			"EST and SCEP enrollment packet captures against production Linux and FreeRADIUS",
			"Cisco ISE, Aruba ClearPass, Microsoft NPS, Jamf/Intune, and OpenSSL enrollment interop evidence",
			"CRL and OCSP outage, rollover, and HA failover drills",
			"large-renewal batch, issuer-rotation, and rollback soak evidence",
		},
	}
	report.Status, report.Message = statusAndMessage(report)
	return report
}

func BuildPolicyReport(cfg *config.Config) PolicyReport {
	policy := PolicyReport{
		Enabled:                    false,
		Mode:                       "monitor",
		FailClosed:                 true,
		CAMode:                     "none",
		DefaultTemplate:            "device-eap-tls",
		Templates:                  []string{"device-eap-tls", "byod-eap-tls"},
		ActiveIssuer:               "aegisnas-local",
		IssuerRotationMode:         "disabled",
		IssuerOverlapSeconds:       2592000,
		CertificateValidityDays:    365,
		MaxCertificateValidityDays: 825,
		RenewalWindowDays:          30,
		RequireCSR:                 true,
		RequireProofOfPossession:   true,
		RequireDeviceBinding:       true,
		RequireSubjectAltName:      true,
		AllowedKeyTypes:            []string{"rsa", "ecdsa", "ed25519"},
		MinRSABits:                 2048,
		AllowedECDSACurves:         []string{"P-256", "P-384", "P-521"},
		EscrowPolicy:               "forbid",
		CRLEnabled:                 false,
		OCSPEnabled:                false,
		ESTEnabled:                 true,
		SCEPEnabled:                true,
		BYODPortalEnabled:          true,
		AuditEnabled:               true,
		EventRetentionLimit:        6000,
		InventoryRetentionLimit:    100000,
	}
	if cfg != nil {
		cl := cfg.Onboarding.CertificateLifecycle
		policy.Enabled = cl.Enabled
		policy.Mode = defaultString(strings.ToLower(strings.TrimSpace(cl.Mode)), policy.Mode)
		policy.FailClosed = cl.FailClosed
		policy.CAMode = defaultString(strings.ToLower(strings.TrimSpace(cfg.Onboarding.CAMode)), "none")
		policy.CertificateEnrollmentReady = cfg.Onboarding.CertificateEnrollmentEnabled
		policy.EAPTLSReady = cfg.Onboarding.EAPTLSEnabled
		policy.CAReady = certificateAuthorityReady(cfg)
		policy.DefaultTemplate = defaultString(strings.TrimSpace(cl.DefaultTemplate), policy.DefaultTemplate)
		policy.Templates = cleanList(defaultStringSlice(cl.Templates, policy.Templates), false)
		policy.ActiveIssuer = defaultString(strings.TrimSpace(cl.ActiveIssuer), policy.ActiveIssuer)
		policy.StagedIssuer = strings.TrimSpace(cl.StagedIssuer)
		policy.IssuerRotationMode = defaultString(strings.ToLower(strings.TrimSpace(cl.IssuerRotationMode)), policy.IssuerRotationMode)
		if cl.IssuerOverlapSeconds > 0 {
			policy.IssuerOverlapSeconds = cl.IssuerOverlapSeconds
		}
		if cl.CertificateValidityDays > 0 {
			policy.CertificateValidityDays = cl.CertificateValidityDays
		}
		if cl.MaxCertificateValidityDays > 0 {
			policy.MaxCertificateValidityDays = cl.MaxCertificateValidityDays
		}
		if cl.RenewalWindowDays > 0 {
			policy.RenewalWindowDays = cl.RenewalWindowDays
		}
		policy.RequireCSR = cl.RequireCSR
		policy.RequireProofOfPossession = cl.RequireProofOfPossession
		policy.RequireDeviceBinding = cl.RequireDeviceBinding
		policy.RequireSubjectAltName = cl.RequireSubjectAltName
		policy.AllowedKeyTypes = cleanList(defaultStringSlice(cl.AllowedKeyTypes, policy.AllowedKeyTypes), true)
		if cl.MinRSABits > 0 {
			policy.MinRSABits = cl.MinRSABits
		}
		policy.AllowedECDSACurves = cleanList(defaultStringSlice(cl.AllowedECDSACurves, policy.AllowedECDSACurves), false)
		policy.AllowServerKeyGeneration = cl.AllowServerKeyGeneration
		policy.EscrowPolicy = defaultString(strings.ToLower(strings.TrimSpace(cl.EscrowPolicy)), policy.EscrowPolicy)
		policy.CRLEnabled = cl.CRLEnabled || cfg.Radius.EAP.CheckCRL
		policy.CRLPublishPath = strings.TrimSpace(cl.CRLPublishPath)
		policy.OCSPEnabled = cl.OCSPEnabled || cfg.Radius.EAP.OCSP.Enabled
		policy.OCSPResponderURL = defaultString(strings.TrimSpace(cl.OCSPResponderURL), strings.TrimSpace(cfg.Radius.EAP.OCSP.URL))
		policy.ESTEnabled = cl.ESTEnabled
		policy.SCEPEnabled = cl.SCEPEnabled
		policy.BYODPortalEnabled = cl.BYODPortalEnabled
		policy.AuditEnabled = cl.AuditEnabled
		if cl.EventRetentionLimit > 0 {
			policy.EventRetentionLimit = cl.EventRetentionLimit
		}
		if cl.InventoryRetentionLimit > 0 {
			policy.InventoryRetentionLimit = cl.InventoryRetentionLimit
		}
	}
	policy.RevocationAvailable = policy.CRLEnabled || policy.OCSPEnabled
	if !contains(policy.Templates, policy.DefaultTemplate) {
		policy.BlockingIssues = append(policy.BlockingIssues, "default certificate template is not in onboarding.certificate_lifecycle.templates")
	}
	if policy.Enabled {
		if !policy.CertificateEnrollmentReady {
			policy.BlockingIssues = append(policy.BlockingIssues, "certificate lifecycle requires onboarding.certificate_enrollment_enabled")
		}
		if !policy.EAPTLSReady {
			policy.BlockingIssues = append(policy.BlockingIssues, "certificate lifecycle requires onboarding.eap_tls_enabled")
		}
		if !policy.CAReady {
			policy.BlockingIssues = append(policy.BlockingIssues, "certificate lifecycle requires complete CA configuration")
		}
		if policy.Mode == "enforce" && policy.FailClosed && !policy.RevocationAvailable {
			policy.BlockingIssues = append(policy.BlockingIssues, "enforce fail-closed lifecycle requires CRL or OCSP")
		}
		if policy.Mode == "enforce" && policy.FailClosed && !policy.RequireCSR && !policy.AllowServerKeyGeneration {
			policy.BlockingIssues = append(policy.BlockingIssues, "enforce fail-closed lifecycle requires CSR validation or explicit server key generation")
		}
	}
	if policy.IssuerRotationMode == "staged" && policy.StagedIssuer == "" {
		policy.BlockingIssues = append(policy.BlockingIssues, "staged issuer rotation requires onboarding.certificate_lifecycle.staged_issuer")
	}
	if policy.IssuerRotationMode == "staged" && policy.StagedIssuer == policy.ActiveIssuer {
		policy.BlockingIssues = append(policy.BlockingIssues, "staged issuer must differ from active issuer")
	}
	if policy.AllowServerKeyGeneration && policy.EscrowPolicy == "forbid" {
		policy.BlockingIssues = append(policy.BlockingIssues, "server key generation cannot be enabled when escrow_policy is forbid")
	}
	if !policy.ESTEnabled && !policy.SCEPEnabled && !policy.BYODPortalEnabled {
		policy.Warnings = append(policy.Warnings, "all enrollment protocol entry points are disabled")
	}
	if policy.MaxCertificateValidityDays < policy.CertificateValidityDays {
		policy.BlockingIssues = append(policy.BlockingIssues, "max certificate validity is lower than default certificate validity")
	}
	return policy
}

func AnalyzeCSR(csrPEM string) CSRAnalysis {
	analysis := CSRAnalysis{Present: strings.TrimSpace(csrPEM) != ""}
	if !analysis.Present {
		return analysis
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		analysis.Error = "CSR PEM block is missing or has the wrong type"
		return analysis
	}
	analysis.ValidPEM = true
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		analysis.Error = err.Error()
		return analysis
	}
	if err := csr.CheckSignature(); err != nil {
		analysis.Error = "CSR signature check failed: " + err.Error()
	} else {
		analysis.SignatureValid = true
	}
	analysis.Subject = csr.Subject.String()
	analysis.CommonName = csr.Subject.CommonName
	analysis.DNSNames = append([]string(nil), csr.DNSNames...)
	analysis.EmailAddresses = append([]string(nil), csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		analysis.IPAddresses = append(analysis.IPAddresses, ip.String())
	}
	for _, uri := range csr.URIs {
		analysis.URIs = append(analysis.URIs, uri.String())
	}
	analysis.SANCount = len(analysis.DNSNames) + len(analysis.EmailAddresses) + len(analysis.IPAddresses) + len(analysis.URIs)
	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		analysis.KeyType = "rsa"
		analysis.KeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		analysis.KeyType = "ecdsa"
		analysis.Curve = key.Curve.Params().Name
		analysis.KeyBits = key.Curve.Params().BitSize
	case ed25519.PublicKey:
		analysis.KeyType = "ed25519"
		analysis.KeyBits = 256
	default:
		analysis.KeyType = fmt.Sprintf("%T", csr.PublicKey)
	}
	return analysis
}

func Evaluate(cfg *config.Config, request EvaluationRequest) Decision {
	policy := BuildPolicyReport(cfg)
	protocol := normalizeProtocol(request.Protocol)
	template := defaultString(strings.TrimSpace(request.Template), policy.DefaultTemplate)
	issuer := defaultString(strings.TrimSpace(request.Issuer), policy.ActiveIssuer)
	issuerState := issuerState(policy, issuer)
	validityDays := request.RequestedValidityDays
	if validityDays <= 0 {
		validityDays = policy.CertificateValidityDays
	}
	csr := AnalyzeCSR(request.CSRPEM)
	renewalDue := request.Renewal || certificateWithinRenewalWindow(request.ExistingNotAfter, policy.RenewalWindowDays)
	decision := Decision{
		PolicyMode:           policy.Mode,
		Protocol:             protocol,
		Template:             template,
		Issuer:               issuer,
		IssuerState:          issuerState,
		DeviceID:             strings.TrimSpace(request.DeviceID),
		Tenant:               strings.TrimSpace(request.Tenant),
		ValidityDays:         validityDays,
		Renewal:              request.Renewal,
		RenewalDue:           renewalDue,
		InventoryStatus:      inventoryStatus(request, renewalDue),
		CSR:                  csr,
		ProofOfPossession:    request.ProofOfPossession || csr.SignatureValid,
		DeviceBound:          request.DeviceBound,
		RevocationChecked:    request.RevocationChecked,
		CRLReachable:         request.CRLReachable,
		OCSPReachable:        request.OCSPReachable,
		EscrowRequested:      request.EscrowRequested,
		CertificateSerial:    strings.TrimSpace(request.CertificateSerial),
		CertificateNotBefore: strings.TrimSpace(request.CertificateNotBefore),
		CertificateNotAfter:  strings.TrimSpace(request.CertificateNotAfter),
		Details:              copyDetails(request.Details),
	}
	reject := func(reason string, deps ...string) Decision {
		decision.Reason = reason
		decision.Dependencies = append(decision.Dependencies, deps...)
		if policy.Mode == "monitor" || !policy.FailClosed {
			decision.Decision = "monitor_allowed"
			decision.Warnings = append(decision.Warnings, reason)
			return decision
		}
		decision.Decision = "rejected"
		return decision
	}
	if !policy.Enabled {
		return reject("certificate lifecycle is disabled", "onboarding.certificate_lifecycle.enabled")
	}
	if len(policy.BlockingIssues) > 0 {
		return reject("certificate lifecycle policy has blocking issues", policy.BlockingIssues...)
	}
	if !protocolAllowed(policy, protocol) {
		return reject("certificate enrollment protocol is not enabled", "onboarding.certificate_lifecycle."+protocol+"_enabled")
	}
	if !contains(policy.Templates, template) {
		return reject("certificate template is not configured", "onboarding.certificate_lifecycle.templates")
	}
	if issuerState == "unknown" {
		return reject("certificate issuer is not active or staged", "onboarding.certificate_lifecycle.active_issuer", "onboarding.certificate_lifecycle.staged_issuer")
	}
	if validityDays <= 0 || validityDays > policy.MaxCertificateValidityDays {
		return reject("requested certificate validity exceeds lifecycle policy", "onboarding.certificate_lifecycle.max_certificate_validity_days")
	}
	if policy.RequireCSR && !csr.Present {
		return reject("CSR is required for certificate lifecycle evaluation", "onboarding.certificate_lifecycle.require_csr")
	}
	if csr.Present {
		if !csr.ValidPEM || !csr.SignatureValid {
			return reject("CSR is malformed or fails proof-of-possession signature validation", "RFC 2986", "RFC 7030")
		}
		if !contains(policy.AllowedKeyTypes, csr.KeyType) {
			return reject("CSR key type is not allowed", "onboarding.certificate_lifecycle.allowed_key_types")
		}
		if csr.KeyType == "rsa" && csr.KeyBits < policy.MinRSABits {
			return reject("CSR RSA key is below the minimum size", "onboarding.certificate_lifecycle.min_rsa_bits")
		}
		if csr.KeyType == "ecdsa" && !contains(policy.AllowedECDSACurves, csr.Curve) {
			return reject("CSR ECDSA curve is not allowed", "onboarding.certificate_lifecycle.allowed_ecdsa_curves")
		}
		if policy.RequireSubjectAltName && csr.SANCount == 0 {
			return reject("CSR must include a subjectAltName", "RFC 5280", "onboarding.certificate_lifecycle.require_subject_alt_name")
		}
	}
	if policy.RequireProofOfPossession && !decision.ProofOfPossession {
		return reject("certificate request lacks proof of possession", "RFC 7030", "RFC 8894")
	}
	if policy.RequireDeviceBinding {
		if !request.DeviceBound {
			return reject("certificate request lacks device binding evidence", "onboarding.certificate_lifecycle.require_device_binding")
		}
		if decision.DeviceID != "" && csr.Present && !csrMatchesDevice(csr, decision.DeviceID) {
			return reject("CSR subject or SAN does not match the bound device identity", "onboarding.certificate_lifecycle.require_device_binding")
		}
	}
	if request.EscrowRequested {
		switch policy.EscrowPolicy {
		case "forbid":
			return reject("certificate private key escrow is forbidden", "onboarding.certificate_lifecycle.escrow_policy")
		case "admin-approved":
			if protocol != "admin" && protocol != "api" {
				return reject("certificate private key escrow requires admin/API approval", "onboarding.certificate_lifecycle.escrow_policy")
			}
		}
	}
	if policy.RevocationAvailable && !request.CRLReachable && !request.OCSPReachable {
		return reject("certificate lifecycle requires reachable CRL or OCSP evidence before apply", "radius.eap.check_crl", "radius.eap.ocsp.enabled")
	}
	if (request.Renewal || request.ExistingSerial != "") && !request.RevocationChecked {
		return reject("certificate renewal requires revocation-state check for the existing certificate", "RFC 5280", "radius.eap.check_crl", "radius.eap.ocsp.enabled")
	}
	decision.Decision = "accepted"
	decision.Reason = "certificate lifecycle request satisfies enrollment, issuer, template, CSR, revocation, and device-binding policy"
	return decision
}

func CapabilityCatalog() []Capability {
	return []Capability{
		{Name: "EAP-TLS Certificate Lifecycle", Status: "implemented", Vendors: []string{"Cisco ISE", "Aruba ClearPass", "Microsoft NPS", "Fortinet", "Juniper Mist", "Ubiquiti UniFi"}, RFCs: []string{"RFC 5280", "RFC 5216", "RFC 9190"}, Attributes: []string{"EAP-Message", "Message-Authenticator", "TLS-Client-Cert-*", "Class"}, Semantics: "binds 802.1X authorization to certificate issuance, renewal, revocation, and device identity", Required: true, Stateful: true, Sensitive: true},
		{Name: "EST Enrollment Gate", Status: "implemented", Vendors: []string{"Cisco", "Aruba", "Apple", "Microsoft", "OpenSSL"}, RFCs: []string{"RFC 7030"}, Attributes: []string{"EAP-Message", "TLS-Client-Cert-Serial", "TLS-Client-Cert-Subject"}, Semantics: "validates certificate signing requests and renewal policy for EST-like enrollment flows", Stateful: true, Sensitive: true},
		{Name: "SCEP Enrollment Gate", Status: "implemented", Vendors: []string{"Cisco", "Microsoft", "Jamf", "Intune", "Aruba"}, RFCs: []string{"RFC 8894"}, Attributes: []string{"EAP-Message", "TLS-Client-Cert-Serial"}, Semantics: "applies SCEP enrollment, renewal, proof-of-possession, and key policy before issuance", Stateful: true, Sensitive: true},
		{Name: "CRL And OCSP Readiness", Status: "implemented", Vendors: []string{"Cisco", "Aruba", "Microsoft", "Fortinet", "Palo Alto"}, RFCs: []string{"RFC 5280", "RFC 6960"}, Attributes: []string{"TLS-Client-Cert-Serial", "TLS-Client-Cert-Issuer", "TLS-Client-Cert-Common-Name"}, Semantics: "requires revocation publication or responder health before fail-closed certificate authorization", Required: true, Stateful: true},
		{Name: "Issuer Rotation And Overlap", Status: "implemented", Vendors: []string{"Cisco ISE", "Aruba ClearPass", "Microsoft ADCS", "Jamf", "Intune"}, RFCs: []string{"RFC 5280"}, Attributes: []string{"TLS-Client-Cert-Issuer", "TLS-Client-Cert-Serial"}, Semantics: "accepts active and staged issuers during a bounded rollover window with audit evidence", Stateful: true, Sensitive: true},
		{Name: "Escrow Governance", Status: "implemented", Vendors: []string{"Microsoft ADCS", "Jamf", "Intune", "Cisco"}, RFCs: []string{"RFC 7030", "RFC 8894"}, Attributes: []string{"EAP-Message"}, Semantics: "prevents silent private-key escrow and restricts any server-side key generation to explicit policy", Required: true, Sensitive: true},
	}
}

func statusAndMessage(report Report) (string, string) {
	if !report.Policy.Enabled {
		return "disabled", "Certificate lifecycle software is present but disabled by configuration."
	}
	if len(report.BlockingIssues) > 0 {
		if report.Policy.Mode == "enforce" && report.Policy.FailClosed {
			return "blocked", "Certificate lifecycle policy has blocking issues."
		}
		return "degraded", "Certificate lifecycle policy has issues but is not fail-closed."
	}
	if report.Runtime.Rejected > 0 || report.Runtime.RevocationBlocked > 0 || report.Runtime.WeakKey > 0 {
		return "degraded", "Certificate lifecycle is active with recent rejected, weak-key, or revocation-blocked events."
	}
	return "ready", "Certificate lifecycle is active with template, issuer, CSR, revocation, enrollment, renewal, and escrow governance."
}

func templateReports(policy PolicyReport) []TemplateReport {
	protocols := enabledProtocols(policy)
	out := make([]TemplateReport, 0, len(policy.Templates))
	for _, name := range policy.Templates {
		out = append(out, TemplateReport{
			Name:                  name,
			Default:               name == policy.DefaultTemplate,
			AllowedProtocols:      protocols,
			ValidityDays:          policy.CertificateValidityDays,
			RenewalWindowDays:     policy.RenewalWindowDays,
			RequireCSR:            policy.RequireCSR,
			RequireDeviceBinding:  policy.RequireDeviceBinding,
			RequireSubjectAltName: policy.RequireSubjectAltName,
		})
	}
	return out
}

func issuerReports(policy PolicyReport) []IssuerReport {
	out := []IssuerReport{{
		Name:            policy.ActiveIssuer,
		State:           "active",
		RotationMode:    policy.IssuerRotationMode,
		OverlapSeconds:  policy.IssuerOverlapSeconds,
		RevocationReady: policy.RevocationAvailable,
	}}
	if policy.StagedIssuer != "" {
		out = append(out, IssuerReport{
			Name:            policy.StagedIssuer,
			State:           "staged",
			RotationMode:    policy.IssuerRotationMode,
			OverlapSeconds:  policy.IssuerOverlapSeconds,
			RevocationReady: policy.RevocationAvailable,
		})
	}
	return out
}

func enabledProtocols(policy PolicyReport) []string {
	var out []string
	if policy.ESTEnabled {
		out = append(out, "est")
	}
	if policy.SCEPEnabled {
		out = append(out, "scep")
	}
	if policy.BYODPortalEnabled {
		out = append(out, "byod")
	}
	out = append(out, "admin", "api")
	return out
}

func normalizeProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "portal":
		return "byod"
	case "est", "scep", "byod", "admin", "api":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func protocolAllowed(policy PolicyReport, protocol string) bool {
	switch protocol {
	case "est":
		return policy.ESTEnabled
	case "scep":
		return policy.SCEPEnabled
	case "byod":
		return policy.BYODPortalEnabled
	case "admin", "api":
		return true
	default:
		return false
	}
}

func issuerState(policy PolicyReport, issuer string) string {
	switch {
	case issuer != "" && strings.EqualFold(issuer, policy.ActiveIssuer):
		return "active"
	case issuer != "" && policy.IssuerRotationMode == "staged" && strings.EqualFold(issuer, policy.StagedIssuer):
		return "staged"
	default:
		return "unknown"
	}
}

func inventoryStatus(request EvaluationRequest, renewalDue bool) string {
	switch {
	case strings.TrimSpace(request.CertificateSerial) != "":
		if renewalDue {
			return "renewal_due"
		}
		return "active"
	case request.Renewal || renewalDue:
		return "renewal_due"
	default:
		return "pending"
	}
}

func certificateWithinRenewalWindow(raw string, windowDays int) bool {
	if strings.TrimSpace(raw) == "" || windowDays <= 0 {
		return false
	}
	expires, err := parseTime(raw)
	if err != nil {
		return false
	}
	return time.Until(expires) <= time.Duration(windowDays)*24*time.Hour
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format")
}

func csrMatchesDevice(csr CSRAnalysis, deviceID string) bool {
	deviceID = strings.ToLower(strings.TrimSpace(deviceID))
	if deviceID == "" {
		return false
	}
	compare := func(value string) bool {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return false
		}
		return value == deviceID || strings.ReplaceAll(value, "-", ":") == strings.ReplaceAll(deviceID, "-", ":")
	}
	if compare(csr.CommonName) {
		return true
	}
	for _, value := range csr.DNSNames {
		if compare(value) {
			return true
		}
	}
	for _, value := range csr.EmailAddresses {
		if compare(value) {
			return true
		}
	}
	for _, value := range csr.URIs {
		if compare(value) {
			return true
		}
	}
	if ip := net.ParseIP(deviceID); ip != nil {
		for _, value := range csr.IPAddresses {
			if parsed := net.ParseIP(value); parsed != nil && parsed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func cleanList(values []string, lower bool) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if lower {
			value = strings.ToLower(value)
		}
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func copyDetails(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func defaultStringSlice(value, fallback []string) []string {
	if len(value) == 0 {
		return append([]string(nil), fallback...)
	}
	return append([]string(nil), value...)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func certificateAuthorityReady(c *config.Config) bool {
	if c == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.Onboarding.CAMode)) {
	case "internal":
		return strings.TrimSpace(c.Onboarding.CACertPath) != "" && strings.TrimSpace(c.Onboarding.CAKeyPath) != ""
	case "external":
		return strings.TrimSpace(c.Onboarding.CAEnrollmentURL) != ""
	default:
		return false
	}
}
