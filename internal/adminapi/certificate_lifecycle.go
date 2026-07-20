package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/certlifecycle"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type certificateLifecycleResponse struct {
	certlifecycle.Report
	Events    []db.CertificateLifecycleEvent         `json:"events,omitempty"`
	Inventory []db.CertificateLifecycleInventoryItem `json:"inventory,omitempty"`
}

type certificateLifecycleEvaluationRequest struct {
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
	LatencyMS             int               `json:"latency_ms"`
	Audit                 bool              `json:"audit"`
	Details               map[string]string `json:"details"`
}

func HandleGetCertificateLifecycle(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	events, err := db.ListCertificateLifecycleEvents(db.CertificateLifecycleEventFilter{
		Protocol: r.URL.Query().Get("protocol"),
		Decision: r.URL.Query().Get("decision"),
		Template: r.URL.Query().Get("template"),
		Issuer:   r.URL.Query().Get("issuer"),
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	inventory, err := db.ListCertificateLifecycleInventory(db.CertificateLifecycleInventoryFilter{
		Status: r.URL.Query().Get("status"),
		Issuer: r.URL.Query().Get("issuer"),
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeCertificateLifecycle(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := certlifecycle.BuildReport(cfg, certificateLifecycleRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, certificateLifecycleResponse{Report: report, Events: events, Inventory: inventory})
}

func HandleEvaluateCertificateLifecycle(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req certificateLifecycleEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := certlifecycle.Evaluate(cfg, certlifecycle.EvaluationRequest{
		Protocol:              req.Protocol,
		Template:              req.Template,
		Issuer:                req.Issuer,
		DeviceID:              req.DeviceID,
		Tenant:                req.Tenant,
		CSRPEM:                req.CSRPEM,
		RequestedValidityDays: req.RequestedValidityDays,
		Renewal:               req.Renewal,
		ExistingSerial:        req.ExistingSerial,
		ExistingNotAfter:      req.ExistingNotAfter,
		EscrowRequested:       req.EscrowRequested,
		ProofOfPossession:     req.ProofOfPossession,
		DeviceBound:           req.DeviceBound,
		RevocationChecked:     req.RevocationChecked,
		CRLReachable:          req.CRLReachable,
		OCSPReachable:         req.OCSPReachable,
		CertificateSerial:     req.CertificateSerial,
		CertificateNotBefore:  req.CertificateNotBefore,
		CertificateNotAfter:   req.CertificateNotAfter,
		Details:               req.Details,
	})
	audited := req.Audit && cfg.Onboarding.CertificateLifecycle.AuditEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		_ = db.RecordCertificateLifecycleEvent(certificateLifecycleEventFromDecision(decision, req, latency), cfg.Onboarding.CertificateLifecycle.EventRetentionLimit, cfg.Onboarding.CertificateLifecycle.InventoryRetentionLimit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func certificateLifecycleRuntimeSummaryFromDB(summary db.CertificateLifecycleSummary) certlifecycle.RuntimeSummary {
	return certlifecycle.RuntimeSummary{
		TotalEvents:             summary.TotalEvents,
		Accepted:                summary.Accepted,
		Rejected:                summary.Rejected,
		MonitorAllowed:          summary.MonitorAllowed,
		RenewalDue:              summary.RenewalDue,
		RevocationBlocked:       summary.RevocationBlocked,
		WeakKey:                 summary.WeakKey,
		MissingCSR:              summary.MissingCSR,
		MissingDeviceBinding:    summary.MissingDeviceBinding,
		EscrowRejected:          summary.EscrowRejected,
		ActiveInventory:         summary.ActiveInventory,
		RevokedInventory:        summary.RevokedInventory,
		RenewalDueInventory:     summary.RenewalDueInventory,
		ByDecision:              summary.ByDecision,
		ByProtocol:              summary.ByProtocol,
		ByIssuer:                summary.ByIssuer,
		ByTemplate:              summary.ByTemplate,
		LastEventAt:             summary.LastEventAt,
		LastRejectedReason:      summary.LastRejectedReason,
		LastRenewalDueAt:        summary.LastRenewalDueAt,
		LastRevocationBlockedAt: summary.LastRevocationBlockedAt,
	}
}

func certificateLifecycleEventFromDecision(decision certlifecycle.Decision, req certificateLifecycleEvaluationRequest, latency int) db.CertificateLifecycleEvent {
	details := map[string]string{}
	for key, value := range req.Details {
		key = strings.TrimSpace(key)
		if key != "" {
			details[key] = strings.TrimSpace(value)
		}
	}
	if decision.CertificateNotBefore != "" {
		details["certificate_not_before"] = decision.CertificateNotBefore
	}
	if decision.CertificateNotAfter != "" {
		details["certificate_not_after"] = decision.CertificateNotAfter
	}
	if decision.CSR.Error != "" {
		details["csr_error"] = decision.CSR.Error
	}
	return db.CertificateLifecycleEvent{
		ObservedAt:         time.Now().UTC(),
		Protocol:           decision.Protocol,
		Decision:           decision.Decision,
		Reason:             decision.Reason,
		Template:           decision.Template,
		Issuer:             decision.Issuer,
		IssuerState:        decision.IssuerState,
		Tenant:             decision.Tenant,
		DeviceIDHash:       db.HashEAPIdentity(decision.DeviceID),
		SubjectHash:        db.CertificateLifecycleSubjectHash(decision.CSR.Subject),
		SANHash:            db.CertificateLifecycleSANHash(certificateLifecycleSANValues(decision.CSR)...),
		SerialHash:         db.HashEAPIdentity(decision.CertificateSerial),
		ExistingSerialHash: db.HashEAPIdentity(req.ExistingSerial),
		Renewal:            decision.Renewal,
		RenewalDue:         decision.RenewalDue,
		InventoryStatus:    decision.InventoryStatus,
		RevocationBlocked:  decision.Decision != "accepted" && strings.Contains(strings.ToLower(decision.Reason), "revocation"),
		KeyType:            decision.CSR.KeyType,
		KeyBits:            decision.CSR.KeyBits,
		Curve:              decision.CSR.Curve,
		ValidityDays:       decision.ValidityDays,
		EscrowRequested:    decision.EscrowRequested,
		ProofOfPossession:  decision.ProofOfPossession,
		CSRPresent:         decision.CSR.Present,
		CSRValid:           decision.CSR.ValidPEM,
		CSRSignatureValid:  decision.CSR.SignatureValid,
		DeviceBound:        decision.DeviceBound,
		RevocationChecked:  decision.RevocationChecked,
		CRLReachable:       decision.CRLReachable,
		OCSPReachable:      decision.OCSPReachable,
		PolicyMode:         decision.PolicyMode,
		LatencyMS:          latency,
		Details:            details,
	}
}

func certificateLifecycleSANValues(csr certlifecycle.CSRAnalysis) []string {
	values := append([]string{}, csr.DNSNames...)
	values = append(values, csr.EmailAddresses...)
	values = append(values, csr.IPAddresses...)
	values = append(values, csr.URIs...)
	return values
}
