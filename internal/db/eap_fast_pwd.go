package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type FASTPWDEvent struct {
	ID                       int64             `json:"id"`
	ObservedAt               time.Time         `json:"observed_at"`
	Method                   string            `json:"method"`
	Decision                 string            `json:"decision"`
	Reason                   string            `json:"reason"`
	NASIdentifier            string            `json:"nas_identifier,omitempty"`
	NASType                  string            `json:"nas_type,omitempty"`
	IdentityHash             string            `json:"identity_hash,omitempty"`
	CallingStationHash       string            `json:"calling_station_hash,omitempty"`
	IdentitySource           string            `json:"identity_source,omitempty"`
	InnerMethod              string            `json:"inner_method,omitempty"`
	CryptoBindingValid       bool              `json:"crypto_binding_valid"`
	PACPresented             bool              `json:"pac_presented"`
	PACProvisioningRequested bool              `json:"pac_provisioning_requested"`
	PACOpaqueKeyAvailable    bool              `json:"pac_opaque_key_available"`
	AnonymousProvisioning    bool              `json:"anonymous_provisioning"`
	EAPPayloadPresent        bool              `json:"eap_payload_present"`
	ProvisioningAttemptCount int               `json:"provisioning_attempt_count"`
	PasswordProofValid       bool              `json:"password_proof_valid"`
	ReplayDetected           bool              `json:"replay_detected"`
	PWDGroup                 int               `json:"pwd_group,omitempty"`
	PWDServerIDHash          string            `json:"pwd_server_id_hash,omitempty"`
	TLSVersion               string            `json:"tls_version,omitempty"`
	PolicyMode               string            `json:"policy_mode,omitempty"`
	LatencyMS                int               `json:"latency_ms"`
	Details                  map[string]string `json:"details,omitempty"`
	CreatedAt                time.Time         `json:"created_at"`
}

type FASTPWDEventFilter struct {
	Method   string
	Decision string
	NASType  string
	Limit    int
}

type FASTPWDEventSummary struct {
	TotalEvents           int            `json:"total_events"`
	Accepted              int            `json:"accepted"`
	Rejected              int            `json:"rejected"`
	MonitorAllowed        int            `json:"monitor_allowed"`
	ByMethod              map[string]int `json:"by_method"`
	ByDecision            map[string]int `json:"by_decision"`
	MissingPAC            int            `json:"missing_pac"`
	InvalidCryptoBinding  int            `json:"invalid_crypto_binding"`
	AnonymousProvisioning int            `json:"anonymous_provisioning"`
	MissingPasswordProof  int            `json:"missing_password_proof"`
	WeakPWDGroup          int            `json:"weak_pwd_group"`
	ReplayRejected        int            `json:"replay_rejected"`
	LastEventAt           string         `json:"last_event_at,omitempty"`
	LastRejectedReason    string         `json:"last_rejected_reason,omitempty"`
}

func RecordFASTPWDEvent(event FASTPWDEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	method := strings.ToLower(strings.TrimSpace(event.Method))
	if method == "" {
		method = "unknown"
	}
	decision := strings.ToLower(strings.TrimSpace(event.Decision))
	if decision == "" {
		decision = "unknown"
	}
	observedAt := event.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	details := event.Details
	if details == nil {
		details = map[string]string{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal EAP-FAST/PWD event details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO eap_fast_pwd_events
		(observed_at, method, decision, reason, nas_identifier, nas_type, identity_hash, calling_station_hash,
		 identity_source, inner_method, crypto_binding_valid, pac_presented, pac_provisioning_requested,
		 pac_opaque_key_available, anonymous_provisioning, eap_payload_present, provisioning_attempt_count,
		 password_proof_valid, replay_detected, pwd_group, pwd_server_id_hash, tls_version, policy_mode,
		 latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observedAt,
		method,
		decision,
		strings.TrimSpace(event.Reason),
		emptyToNil(strings.TrimSpace(event.NASIdentifier)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.NASType))),
		emptyToNil(strings.TrimSpace(event.IdentityHash)),
		emptyToNil(strings.TrimSpace(event.CallingStationHash)),
		emptyToNil(strings.TrimSpace(event.IdentitySource)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.InnerMethod))),
		boolToSQLite(event.CryptoBindingValid),
		boolToSQLite(event.PACPresented),
		boolToSQLite(event.PACProvisioningRequested),
		boolToSQLite(event.PACOpaqueKeyAvailable),
		boolToSQLite(event.AnonymousProvisioning),
		boolToSQLite(event.EAPPayloadPresent),
		event.ProvisioningAttemptCount,
		boolToSQLite(event.PasswordProofValid),
		boolToSQLite(event.ReplayDetected),
		event.PWDGroup,
		emptyToNil(strings.TrimSpace(event.PWDServerIDHash)),
		emptyToNil(strings.TrimSpace(event.TLSVersion)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.PolicyMode))),
		event.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil
		}
		return fmt.Errorf("record EAP-FAST/PWD event: %w", err)
	}
	return trimFASTPWDEvents(retentionLimit)
}

func ListFASTPWDEvents(filter FASTPWDEventFilter) ([]FASTPWDEvent, error) {
	if DB == nil {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}
	clauses := []string{"1=1"}
	args := []any{}
	if method := strings.ToLower(strings.TrimSpace(filter.Method)); method != "" {
		clauses = append(clauses, "method = ?")
		args = append(args, method)
	}
	if decision := strings.ToLower(strings.TrimSpace(filter.Decision)); decision != "" {
		clauses = append(clauses, "decision = ?")
		args = append(args, decision)
	}
	if nasType := strings.ToLower(strings.TrimSpace(filter.NASType)); nasType != "" {
		clauses = append(clauses, "nas_type = ?")
		args = append(args, nasType)
	}
	args = append(args, limit)
	rows, err := DB.Query(`SELECT id, observed_at, method, decision, reason, COALESCE(nas_identifier, ''),
			COALESCE(nas_type, ''), COALESCE(identity_hash, ''), COALESCE(calling_station_hash, ''),
			COALESCE(identity_source, ''), COALESCE(inner_method, ''), COALESCE(crypto_binding_valid, 0),
			COALESCE(pac_presented, 0), COALESCE(pac_provisioning_requested, 0), COALESCE(pac_opaque_key_available, 0),
			COALESCE(anonymous_provisioning, 0), COALESCE(eap_payload_present, 0), COALESCE(provisioning_attempt_count, 0),
			COALESCE(password_proof_valid, 0), COALESCE(replay_detected, 0), COALESCE(pwd_group, 0),
			COALESCE(pwd_server_id_hash, ''), COALESCE(tls_version, ''), COALESCE(policy_mode, ''),
			COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM eap_fast_pwd_events
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY observed_at DESC, id DESC
		LIMIT ?`, args...)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var events []FASTPWDEvent
	for rows.Next() {
		event, err := scanFASTPWDEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func SummarizeFASTPWDEvents(limit int) (FASTPWDEventSummary, error) {
	events, err := ListFASTPWDEvents(FASTPWDEventFilter{Limit: limit})
	if err != nil {
		return FASTPWDEventSummary{}, err
	}
	summary := FASTPWDEventSummary{
		ByMethod:   map[string]int{},
		ByDecision: map[string]int{},
	}
	for i, event := range events {
		summary.TotalEvents++
		summary.ByMethod[event.Method]++
		summary.ByDecision[event.Decision]++
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
		reason := strings.ToLower(event.Reason)
		if strings.Contains(reason, "pac is required") {
			summary.MissingPAC++
		}
		if strings.Contains(reason, "cryptobinding") || strings.Contains(reason, "crypto-binding") {
			summary.InvalidCryptoBinding++
		}
		if event.AnonymousProvisioning {
			summary.AnonymousProvisioning++
		}
		if strings.Contains(reason, "password proof") {
			summary.MissingPasswordProof++
		}
		if strings.Contains(reason, "strong group") {
			summary.WeakPWDGroup++
		}
		if event.ReplayDetected || strings.Contains(reason, "replay") {
			summary.ReplayRejected++
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	return summary, nil
}

func trimFASTPWDEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM eap_fast_pwd_events
		WHERE id NOT IN (
			SELECT id FROM eap_fast_pwd_events ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil
	}
	return err
}

func scanFASTPWDEvent(scanner eapMethodEventScanner) (FASTPWDEvent, error) {
	var event FASTPWDEvent
	var cryptoBinding, pacPresented, pacProvisioningRequested, pacOpaqueKeyAvailable int
	var anonymousProvisioning, eapPayloadPresent, passwordProofValid, replayDetected int
	var detailsJSON string
	if err := scanner.Scan(
		&event.ID,
		&event.ObservedAt,
		&event.Method,
		&event.Decision,
		&event.Reason,
		&event.NASIdentifier,
		&event.NASType,
		&event.IdentityHash,
		&event.CallingStationHash,
		&event.IdentitySource,
		&event.InnerMethod,
		&cryptoBinding,
		&pacPresented,
		&pacProvisioningRequested,
		&pacOpaqueKeyAvailable,
		&anonymousProvisioning,
		&eapPayloadPresent,
		&event.ProvisioningAttemptCount,
		&passwordProofValid,
		&replayDetected,
		&event.PWDGroup,
		&event.PWDServerIDHash,
		&event.TLSVersion,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return FASTPWDEvent{}, err
	}
	event.CryptoBindingValid = cryptoBinding != 0
	event.PACPresented = pacPresented != 0
	event.PACProvisioningRequested = pacProvisioningRequested != 0
	event.PACOpaqueKeyAvailable = pacOpaqueKeyAvailable != 0
	event.AnonymousProvisioning = anonymousProvisioning != 0
	event.EAPPayloadPresent = eapPayloadPresent != 0
	event.PasswordProofValid = passwordProofValid != 0
	event.ReplayDetected = replayDetected != 0
	if strings.TrimSpace(detailsJSON) != "" {
		_ = json.Unmarshal([]byte(detailsJSON), &event.Details)
	}
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event, nil
}
