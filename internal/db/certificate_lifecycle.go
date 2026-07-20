package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CertificateLifecycleEvent struct {
	ID                 int64             `json:"id"`
	ObservedAt         time.Time         `json:"observed_at"`
	Protocol           string            `json:"protocol"`
	Decision           string            `json:"decision"`
	Reason             string            `json:"reason"`
	Template           string            `json:"template,omitempty"`
	Issuer             string            `json:"issuer,omitempty"`
	IssuerState        string            `json:"issuer_state,omitempty"`
	Tenant             string            `json:"tenant,omitempty"`
	DeviceIDHash       string            `json:"device_id_hash,omitempty"`
	SubjectHash        string            `json:"subject_hash,omitempty"`
	SANHash            string            `json:"san_hash,omitempty"`
	SerialHash         string            `json:"serial_hash,omitempty"`
	ExistingSerialHash string            `json:"existing_serial_hash,omitempty"`
	Renewal            bool              `json:"renewal"`
	RenewalDue         bool              `json:"renewal_due"`
	InventoryStatus    string            `json:"inventory_status,omitempty"`
	RevocationBlocked  bool              `json:"revocation_blocked"`
	KeyType            string            `json:"key_type,omitempty"`
	KeyBits            int               `json:"key_bits"`
	Curve              string            `json:"curve,omitempty"`
	ValidityDays       int               `json:"validity_days"`
	EscrowRequested    bool              `json:"escrow_requested"`
	ProofOfPossession  bool              `json:"proof_of_possession"`
	CSRPresent         bool              `json:"csr_present"`
	CSRValid           bool              `json:"csr_valid"`
	CSRSignatureValid  bool              `json:"csr_signature_valid"`
	DeviceBound        bool              `json:"device_bound"`
	RevocationChecked  bool              `json:"revocation_checked"`
	CRLReachable       bool              `json:"crl_reachable"`
	OCSPReachable      bool              `json:"ocsp_reachable"`
	PolicyMode         string            `json:"policy_mode,omitempty"`
	LatencyMS          int               `json:"latency_ms"`
	Details            map[string]string `json:"details,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
}

type CertificateLifecycleInventoryItem struct {
	CertificateKey string            `json:"certificate_key"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Status         string            `json:"status"`
	Protocol       string            `json:"protocol,omitempty"`
	Template       string            `json:"template,omitempty"`
	Issuer         string            `json:"issuer,omitempty"`
	IssuerState    string            `json:"issuer_state,omitempty"`
	Tenant         string            `json:"tenant,omitempty"`
	DeviceIDHash   string            `json:"device_id_hash,omitempty"`
	SubjectHash    string            `json:"subject_hash,omitempty"`
	SANHash        string            `json:"san_hash,omitempty"`
	SerialHash     string            `json:"serial_hash,omitempty"`
	KeyType        string            `json:"key_type,omitempty"`
	KeyBits        int               `json:"key_bits"`
	Curve          string            `json:"curve,omitempty"`
	NotBefore      *time.Time        `json:"not_before,omitempty"`
	NotAfter       *time.Time        `json:"not_after,omitempty"`
	RenewalDue     bool              `json:"renewal_due"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
	RevokeReason   string            `json:"revoke_reason,omitempty"`
	PolicyMode     string            `json:"policy_mode,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

type CertificateLifecycleEventFilter struct {
	Protocol string
	Decision string
	Template string
	Issuer   string
	Limit    int
}

type CertificateLifecycleInventoryFilter struct {
	Status string
	Issuer string
	Limit  int
}

type CertificateLifecycleSummary struct {
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
	ByDecision              map[string]int `json:"by_decision"`
	ByProtocol              map[string]int `json:"by_protocol"`
	ByIssuer                map[string]int `json:"by_issuer"`
	ByTemplate              map[string]int `json:"by_template"`
	LastEventAt             string         `json:"last_event_at,omitempty"`
	LastRejectedReason      string         `json:"last_rejected_reason,omitempty"`
	LastRenewalDueAt        string         `json:"last_renewal_due_at,omitempty"`
	LastRevocationBlockedAt string         `json:"last_revocation_blocked_at,omitempty"`
}

func RecordCertificateLifecycleEvent(event CertificateLifecycleEvent, retentionLimit, inventoryRetentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeCertificateLifecycleEvent(event)
	detailsJSON, err := json.Marshal(normalized.Details)
	if err != nil {
		return fmt.Errorf("marshal certificate lifecycle details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO certificate_lifecycle_events
		(observed_at, protocol, decision, reason, template, issuer, issuer_state, tenant, device_id_hash,
		 subject_hash, san_hash, serial_hash, existing_serial_hash, renewal, renewal_due, inventory_status,
		 revocation_blocked, key_type, key_bits, curve, validity_days, escrow_requested, proof_of_possession,
		 csr_present, csr_valid, csr_signature_valid, device_bound, revocation_checked, crl_reachable,
		 ocsp_reachable, policy_mode, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalized.ObservedAt,
		normalized.Protocol,
		normalized.Decision,
		normalized.Reason,
		emptyToNil(normalized.Template),
		emptyToNil(normalized.Issuer),
		emptyToNil(normalized.IssuerState),
		emptyToNil(normalized.Tenant),
		emptyToNil(normalized.DeviceIDHash),
		emptyToNil(normalized.SubjectHash),
		emptyToNil(normalized.SANHash),
		emptyToNil(normalized.SerialHash),
		emptyToNil(normalized.ExistingSerialHash),
		boolToSQLite(normalized.Renewal),
		boolToSQLite(normalized.RenewalDue),
		emptyToNil(normalized.InventoryStatus),
		boolToSQLite(normalized.RevocationBlocked),
		emptyToNil(normalized.KeyType),
		normalized.KeyBits,
		emptyToNil(normalized.Curve),
		normalized.ValidityDays,
		boolToSQLite(normalized.EscrowRequested),
		boolToSQLite(normalized.ProofOfPossession),
		boolToSQLite(normalized.CSRPresent),
		boolToSQLite(normalized.CSRValid),
		boolToSQLite(normalized.CSRSignatureValid),
		boolToSQLite(normalized.DeviceBound),
		boolToSQLite(normalized.RevocationChecked),
		boolToSQLite(normalized.CRLReachable),
		boolToSQLite(normalized.OCSPReachable),
		emptyToNil(normalized.PolicyMode),
		normalized.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if isMissingCertificateLifecycleTable(err) {
			return nil
		}
		return fmt.Errorf("record certificate lifecycle event: %w", err)
	}
	if shouldUpsertCertificateInventory(normalized) {
		if err := UpsertCertificateLifecycleInventory(CertificateLifecycleInventoryItem{
			CertificateKey: normalized.certificateKey(),
			UpdatedAt:      normalized.ObservedAt,
			Status:         normalized.InventoryStatus,
			Protocol:       normalized.Protocol,
			Template:       normalized.Template,
			Issuer:         normalized.Issuer,
			IssuerState:    normalized.IssuerState,
			Tenant:         normalized.Tenant,
			DeviceIDHash:   normalized.DeviceIDHash,
			SubjectHash:    normalized.SubjectHash,
			SANHash:        normalized.SANHash,
			SerialHash:     normalized.SerialHash,
			KeyType:        normalized.KeyType,
			KeyBits:        normalized.KeyBits,
			Curve:          normalized.Curve,
			NotBefore:      parseCertificateLifecycleEventTime(normalized.Details["certificate_not_before"]),
			NotAfter:       parseCertificateLifecycleEventTime(normalized.Details["certificate_not_after"]),
			RenewalDue:     normalized.RenewalDue,
			PolicyMode:     normalized.PolicyMode,
			Details:        normalized.Details,
		}, inventoryRetentionLimit); err != nil {
			return err
		}
	}
	return trimCertificateLifecycleEvents(retentionLimit)
}

func UpsertCertificateLifecycleInventory(item CertificateLifecycleInventoryItem, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeCertificateLifecycleInventoryItem(item)
	detailsJSON, err := json.Marshal(normalized.Details)
	if err != nil {
		return fmt.Errorf("marshal certificate lifecycle inventory details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO certificate_lifecycle_inventory
		(certificate_key, updated_at, status, protocol, template, issuer, issuer_state, tenant,
		 device_id_hash, subject_hash, san_hash, serial_hash, key_type, key_bits, curve, not_before,
		 not_after, renewal_due, revoked_at, revoke_reason, policy_mode, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(certificate_key) DO UPDATE SET
			updated_at=excluded.updated_at,
			status=excluded.status,
			protocol=excluded.protocol,
			template=excluded.template,
			issuer=excluded.issuer,
			issuer_state=excluded.issuer_state,
			tenant=excluded.tenant,
			device_id_hash=excluded.device_id_hash,
			subject_hash=excluded.subject_hash,
			san_hash=excluded.san_hash,
			serial_hash=excluded.serial_hash,
			key_type=excluded.key_type,
			key_bits=excluded.key_bits,
			curve=excluded.curve,
			not_before=excluded.not_before,
			not_after=excluded.not_after,
			renewal_due=excluded.renewal_due,
			revoked_at=excluded.revoked_at,
			revoke_reason=excluded.revoke_reason,
			policy_mode=excluded.policy_mode,
			details_json=excluded.details_json`,
		normalized.CertificateKey,
		normalized.UpdatedAt,
		normalized.Status,
		emptyToNil(normalized.Protocol),
		emptyToNil(normalized.Template),
		emptyToNil(normalized.Issuer),
		emptyToNil(normalized.IssuerState),
		emptyToNil(normalized.Tenant),
		emptyToNil(normalized.DeviceIDHash),
		emptyToNil(normalized.SubjectHash),
		emptyToNil(normalized.SANHash),
		emptyToNil(normalized.SerialHash),
		emptyToNil(normalized.KeyType),
		normalized.KeyBits,
		emptyToNil(normalized.Curve),
		normalized.NotBefore,
		normalized.NotAfter,
		boolToSQLite(normalized.RenewalDue),
		normalized.RevokedAt,
		emptyToNil(normalized.RevokeReason),
		emptyToNil(normalized.PolicyMode),
		string(detailsJSON),
	)
	if err != nil {
		if isMissingCertificateLifecycleTable(err) {
			return nil
		}
		return fmt.Errorf("upsert certificate lifecycle inventory: %w", err)
	}
	return trimCertificateLifecycleInventory(retentionLimit)
}

func ListCertificateLifecycleEvents(filter CertificateLifecycleEventFilter) ([]CertificateLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	clauses := []string{"1=1"}
	args := []any{}
	if protocol := strings.ToLower(strings.TrimSpace(filter.Protocol)); protocol != "" {
		clauses = append(clauses, "protocol = ?")
		args = append(args, protocol)
	}
	if decision := strings.ToLower(strings.TrimSpace(filter.Decision)); decision != "" {
		clauses = append(clauses, "decision = ?")
		args = append(args, decision)
	}
	if template := strings.TrimSpace(filter.Template); template != "" {
		clauses = append(clauses, "template = ?")
		args = append(args, template)
	}
	if issuer := strings.TrimSpace(filter.Issuer); issuer != "" {
		clauses = append(clauses, "issuer = ?")
		args = append(args, issuer)
	}
	args = append(args, boundedCertificateLifecycleLimit(filter.Limit))
	rows, err := DB.Query(`SELECT id, observed_at, protocol, decision, reason, COALESCE(template, ''),
			COALESCE(issuer, ''), COALESCE(issuer_state, ''), COALESCE(tenant, ''),
			COALESCE(device_id_hash, ''), COALESCE(subject_hash, ''), COALESCE(san_hash, ''),
			COALESCE(serial_hash, ''), COALESCE(existing_serial_hash, ''), COALESCE(renewal, 0),
			COALESCE(renewal_due, 0), COALESCE(inventory_status, ''), COALESCE(revocation_blocked, 0),
			COALESCE(key_type, ''), COALESCE(key_bits, 0), COALESCE(curve, ''), COALESCE(validity_days, 0),
			COALESCE(escrow_requested, 0), COALESCE(proof_of_possession, 0), COALESCE(csr_present, 0),
			COALESCE(csr_valid, 0), COALESCE(csr_signature_valid, 0), COALESCE(device_bound, 0),
			COALESCE(revocation_checked, 0), COALESCE(crl_reachable, 0), COALESCE(ocsp_reachable, 0),
			COALESCE(policy_mode, ''), COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM certificate_lifecycle_events
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY observed_at DESC, id DESC
		LIMIT ?`, args...)
	if err != nil {
		if isMissingCertificateLifecycleTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var events []CertificateLifecycleEvent
	for rows.Next() {
		event, err := scanCertificateLifecycleEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListCertificateLifecycleInventory(filter CertificateLifecycleInventoryFilter) ([]CertificateLifecycleInventoryItem, error) {
	if DB == nil {
		return nil, nil
	}
	clauses := []string{"1=1"}
	args := []any{}
	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if issuer := strings.TrimSpace(filter.Issuer); issuer != "" {
		clauses = append(clauses, "issuer = ?")
		args = append(args, issuer)
	}
	args = append(args, boundedCertificateLifecycleLimit(filter.Limit))
	rows, err := DB.Query(`SELECT certificate_key, updated_at, status, COALESCE(protocol, ''),
			COALESCE(template, ''), COALESCE(issuer, ''), COALESCE(issuer_state, ''), COALESCE(tenant, ''),
			COALESCE(device_id_hash, ''), COALESCE(subject_hash, ''), COALESCE(san_hash, ''),
			COALESCE(serial_hash, ''), COALESCE(key_type, ''), COALESCE(key_bits, 0), COALESCE(curve, ''),
			not_before, not_after, COALESCE(renewal_due, 0), revoked_at, COALESCE(revoke_reason, ''),
			COALESCE(policy_mode, ''), COALESCE(details_json, '{}'), created_at
		FROM certificate_lifecycle_inventory
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY updated_at DESC
		LIMIT ?`, args...)
	if err != nil {
		if isMissingCertificateLifecycleTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var items []CertificateLifecycleInventoryItem
	for rows.Next() {
		item, err := scanCertificateLifecycleInventoryItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func SummarizeCertificateLifecycle(limit int) (CertificateLifecycleSummary, error) {
	events, err := ListCertificateLifecycleEvents(CertificateLifecycleEventFilter{Limit: limit})
	if err != nil {
		return CertificateLifecycleSummary{}, err
	}
	inventory, err := ListCertificateLifecycleInventory(CertificateLifecycleInventoryFilter{Limit: limit})
	if err != nil {
		return CertificateLifecycleSummary{}, err
	}
	summary := CertificateLifecycleSummary{
		ByDecision: map[string]int{},
		ByProtocol: map[string]int{},
		ByIssuer:   map[string]int{},
		ByTemplate: map[string]int{},
	}
	for i, event := range events {
		summary.TotalEvents++
		summary.ByDecision[event.Decision]++
		summary.ByProtocol[event.Protocol]++
		if event.Issuer != "" {
			summary.ByIssuer[event.Issuer]++
		}
		if event.Template != "" {
			summary.ByTemplate[event.Template]++
		}
		switch event.Decision {
		case "accepted":
			summary.Accepted++
		case "rejected":
			summary.Rejected++
			if summary.LastRejectedReason == "" {
				summary.LastRejectedReason = event.Reason
			}
		case "monitor_allowed":
			summary.MonitorAllowed++
		}
		if event.RenewalDue {
			summary.RenewalDue++
			if summary.LastRenewalDueAt == "" {
				summary.LastRenewalDueAt = event.ObservedAt.UTC().Format(time.RFC3339)
			}
		}
		if event.Decision != "accepted" && (event.RevocationBlocked || strings.Contains(strings.ToLower(event.Reason), "revocation")) {
			summary.RevocationBlocked++
			if summary.LastRevocationBlockedAt == "" {
				summary.LastRevocationBlockedAt = event.ObservedAt.UTC().Format(time.RFC3339)
			}
		}
		reason := strings.ToLower(event.Reason)
		if strings.Contains(reason, "rsa key") || strings.Contains(reason, "key type") || strings.Contains(reason, "curve") {
			summary.WeakKey++
		}
		if strings.Contains(reason, "csr is required") {
			summary.MissingCSR++
		}
		if strings.Contains(reason, "device binding") {
			summary.MissingDeviceBinding++
		}
		if strings.Contains(reason, "escrow") {
			summary.EscrowRejected++
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	for _, item := range inventory {
		switch item.Status {
		case "active":
			summary.ActiveInventory++
		case "revoked":
			summary.RevokedInventory++
		case "renewal_due":
			summary.RenewalDueInventory++
		}
	}
	return summary, nil
}

func CertificateLifecycleSubjectHash(subject string) string {
	return HashEAPIdentity(subject)
}

func CertificateLifecycleSANHash(values ...string) string {
	var parts []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, strings.ToLower(value))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return HashEAPIdentity(strings.Join(parts, "|"))
}

func normalizeCertificateLifecycleEvent(event CertificateLifecycleEvent) CertificateLifecycleEvent {
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	event.Protocol = strings.ToLower(strings.TrimSpace(event.Protocol))
	if event.Protocol == "" {
		event.Protocol = "unknown"
	}
	event.Decision = strings.ToLower(strings.TrimSpace(event.Decision))
	if event.Decision == "" {
		event.Decision = "unknown"
	}
	event.Reason = strings.TrimSpace(event.Reason)
	event.Template = strings.TrimSpace(event.Template)
	event.Issuer = strings.TrimSpace(event.Issuer)
	event.IssuerState = strings.ToLower(strings.TrimSpace(event.IssuerState))
	event.Tenant = strings.TrimSpace(event.Tenant)
	event.InventoryStatus = strings.ToLower(strings.TrimSpace(event.InventoryStatus))
	if event.InventoryStatus == "" {
		event.InventoryStatus = "pending"
	}
	event.KeyType = strings.ToLower(strings.TrimSpace(event.KeyType))
	event.Curve = strings.TrimSpace(event.Curve)
	event.PolicyMode = strings.ToLower(strings.TrimSpace(event.PolicyMode))
	event.RevocationBlocked = event.Decision != "accepted" && (event.RevocationBlocked || strings.Contains(strings.ToLower(event.Reason), "revocation"))
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event
}

func (event CertificateLifecycleEvent) certificateKey() string {
	parts := []string{event.SerialHash, event.SubjectHash, event.SANHash, event.DeviceIDHash, event.Issuer, event.Template}
	var values []string
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		values = append(values, time.Now().UTC().Format(time.RFC3339Nano))
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "|")))
	return hex.EncodeToString(sum[:])
}

func shouldUpsertCertificateInventory(event CertificateLifecycleEvent) bool {
	return event.Decision == "accepted" || event.InventoryStatus == "active" || event.InventoryStatus == "renewal_due"
}

func normalizeCertificateLifecycleInventoryItem(item CertificateLifecycleInventoryItem) CertificateLifecycleInventoryItem {
	item.CertificateKey = strings.TrimSpace(item.CertificateKey)
	if item.CertificateKey == "" {
		sum := sha256.Sum256([]byte(strings.Join([]string{item.SerialHash, item.SubjectHash, item.SANHash, item.DeviceIDHash, time.Now().UTC().Format(time.RFC3339Nano)}, "|")))
		item.CertificateKey = hex.EncodeToString(sum[:])
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	if item.Status == "" {
		item.Status = "active"
	}
	item.Protocol = strings.ToLower(strings.TrimSpace(item.Protocol))
	item.Template = strings.TrimSpace(item.Template)
	item.Issuer = strings.TrimSpace(item.Issuer)
	item.IssuerState = strings.ToLower(strings.TrimSpace(item.IssuerState))
	item.Tenant = strings.TrimSpace(item.Tenant)
	item.KeyType = strings.ToLower(strings.TrimSpace(item.KeyType))
	item.Curve = strings.TrimSpace(item.Curve)
	item.PolicyMode = strings.ToLower(strings.TrimSpace(item.PolicyMode))
	if item.Details == nil {
		item.Details = map[string]string{}
	}
	return item
}

func scanCertificateLifecycleEvent(scanner eapMethodEventScanner) (CertificateLifecycleEvent, error) {
	var event CertificateLifecycleEvent
	var renewal, renewalDue, revocationBlocked int
	var escrow, proof, csrPresent, csrValid, csrSignature, deviceBound, revocationChecked, crlReachable, ocspReachable int
	var detailsJSON string
	if err := scanner.Scan(
		&event.ID,
		&event.ObservedAt,
		&event.Protocol,
		&event.Decision,
		&event.Reason,
		&event.Template,
		&event.Issuer,
		&event.IssuerState,
		&event.Tenant,
		&event.DeviceIDHash,
		&event.SubjectHash,
		&event.SANHash,
		&event.SerialHash,
		&event.ExistingSerialHash,
		&renewal,
		&renewalDue,
		&event.InventoryStatus,
		&revocationBlocked,
		&event.KeyType,
		&event.KeyBits,
		&event.Curve,
		&event.ValidityDays,
		&escrow,
		&proof,
		&csrPresent,
		&csrValid,
		&csrSignature,
		&deviceBound,
		&revocationChecked,
		&crlReachable,
		&ocspReachable,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return CertificateLifecycleEvent{}, err
	}
	event.Renewal = renewal != 0
	event.RenewalDue = renewalDue != 0
	event.RevocationBlocked = revocationBlocked != 0
	event.EscrowRequested = escrow != 0
	event.ProofOfPossession = proof != 0
	event.CSRPresent = csrPresent != 0
	event.CSRValid = csrValid != 0
	event.CSRSignatureValid = csrSignature != 0
	event.DeviceBound = deviceBound != 0
	event.RevocationChecked = revocationChecked != 0
	event.CRLReachable = crlReachable != 0
	event.OCSPReachable = ocspReachable != 0
	if err := json.Unmarshal([]byte(detailsJSON), &event.Details); err != nil {
		return CertificateLifecycleEvent{}, err
	}
	return event, nil
}

func scanCertificateLifecycleInventoryItem(scanner eapMethodEventScanner) (CertificateLifecycleInventoryItem, error) {
	var item CertificateLifecycleInventoryItem
	var renewalDue int
	var notBefore, notAfter, revokedAt sql.NullTime
	var detailsJSON string
	if err := scanner.Scan(
		&item.CertificateKey,
		&item.UpdatedAt,
		&item.Status,
		&item.Protocol,
		&item.Template,
		&item.Issuer,
		&item.IssuerState,
		&item.Tenant,
		&item.DeviceIDHash,
		&item.SubjectHash,
		&item.SANHash,
		&item.SerialHash,
		&item.KeyType,
		&item.KeyBits,
		&item.Curve,
		&notBefore,
		&notAfter,
		&renewalDue,
		&revokedAt,
		&item.RevokeReason,
		&item.PolicyMode,
		&detailsJSON,
		&item.CreatedAt,
	); err != nil {
		return CertificateLifecycleInventoryItem{}, err
	}
	if notBefore.Valid {
		item.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		item.NotAfter = &notAfter.Time
	}
	item.RenewalDue = renewalDue != 0
	if revokedAt.Valid {
		item.RevokedAt = &revokedAt.Time
	}
	if err := json.Unmarshal([]byte(detailsJSON), &item.Details); err != nil {
		return CertificateLifecycleInventoryItem{}, err
	}
	return item, nil
}

func trimCertificateLifecycleEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM certificate_lifecycle_events
		WHERE id NOT IN (
			SELECT id FROM certificate_lifecycle_events ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && isMissingCertificateLifecycleTable(err) {
		return nil
	}
	return err
}

func trimCertificateLifecycleInventory(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 100000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM certificate_lifecycle_inventory
		WHERE certificate_key NOT IN (
			SELECT certificate_key FROM certificate_lifecycle_inventory ORDER BY updated_at DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && isMissingCertificateLifecycleTable(err) {
		return nil
	}
	return err
}

func boundedCertificateLifecycleLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 5000 {
		return 5000
	}
	return limit
}

func isMissingCertificateLifecycleTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func parseCertificateLifecycleEventTime(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return &ts
		}
	}
	return nil
}
