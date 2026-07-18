package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type EAPMethodEvent struct {
	ID                          int64             `json:"id"`
	ObservedAt                  time.Time         `json:"observed_at"`
	Method                      string            `json:"method"`
	InnerMethod                 string            `json:"inner_method,omitempty"`
	Decision                    string            `json:"decision"`
	Reason                      string            `json:"reason"`
	NASIdentifier               string            `json:"nas_identifier,omitempty"`
	NASType                     string            `json:"nas_type,omitempty"`
	UserNameHash                string            `json:"user_name_hash,omitempty"`
	CallingStationHash          string            `json:"calling_station_hash,omitempty"`
	IdentitySource              string            `json:"identity_source,omitempty"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	CertificatePresented        bool              `json:"certificate_presented"`
	TLSVersion                  string            `json:"tls_version,omitempty"`
	PolicyMode                  string            `json:"policy_mode,omitempty"`
	LatencyMS                   int               `json:"latency_ms"`
	Details                     map[string]string `json:"details,omitempty"`
	CreatedAt                   time.Time         `json:"created_at"`
}

type EAPMethodEventFilter struct {
	Method   string
	Decision string
	NASType  string
	Limit    int
}

type EAPMethodEventSummary struct {
	TotalEvents        int            `json:"total_events"`
	Accepted           int            `json:"accepted"`
	Rejected           int            `json:"rejected"`
	MonitorAllowed     int            `json:"monitor_allowed"`
	Unsupported        int            `json:"unsupported"`
	ByMethod           map[string]int `json:"by_method"`
	ByDecision         map[string]int `json:"by_decision"`
	LastEventAt        string         `json:"last_event_at,omitempty"`
	LastRejectedReason string         `json:"last_rejected_reason,omitempty"`
}

func HashEAPIdentity(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func RecordEAPMethodEvent(event EAPMethodEvent, retentionLimit int) error {
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
		return fmt.Errorf("marshal EAP method event details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO eap_method_events
		(observed_at, method, inner_method, decision, reason, nas_identifier, nas_type, user_name_hash, calling_station_hash,
		 identity_source, eap_message_present, message_authenticator_present, certificate_presented, tls_version, policy_mode, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observedAt,
		method,
		emptyToNil(strings.ToLower(strings.TrimSpace(event.InnerMethod))),
		decision,
		strings.TrimSpace(event.Reason),
		emptyToNil(strings.TrimSpace(event.NASIdentifier)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.NASType))),
		emptyToNil(strings.TrimSpace(event.UserNameHash)),
		emptyToNil(strings.TrimSpace(event.CallingStationHash)),
		emptyToNil(strings.TrimSpace(event.IdentitySource)),
		boolToSQLite(event.EAPMessagePresent),
		boolToSQLite(event.MessageAuthenticatorPresent),
		boolToSQLite(event.CertificatePresented),
		emptyToNil(strings.TrimSpace(event.TLSVersion)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.PolicyMode))),
		event.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil
		}
		return fmt.Errorf("record EAP method event: %w", err)
	}
	return trimEAPMethodEvents(retentionLimit)
}

func ListEAPMethodEvents(filter EAPMethodEventFilter) ([]EAPMethodEvent, error) {
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
	rows, err := DB.Query(`SELECT id, observed_at, method, COALESCE(inner_method, ''), decision, reason,
			COALESCE(nas_identifier, ''), COALESCE(nas_type, ''), COALESCE(user_name_hash, ''), COALESCE(calling_station_hash, ''),
			COALESCE(identity_source, ''), COALESCE(eap_message_present, 0), COALESCE(message_authenticator_present, 0),
			COALESCE(certificate_presented, 0), COALESCE(tls_version, ''), COALESCE(policy_mode, ''),
			COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM eap_method_events
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
	var events []EAPMethodEvent
	for rows.Next() {
		event, err := scanEAPMethodEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func SummarizeEAPMethodEvents(limit int) (EAPMethodEventSummary, error) {
	events, err := ListEAPMethodEvents(EAPMethodEventFilter{Limit: limit})
	if err != nil {
		return EAPMethodEventSummary{}, err
	}
	summary := EAPMethodEventSummary{
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
		case "unsupported":
			summary.Unsupported++
			if summary.LastRejectedReason == "" {
				summary.LastRejectedReason = event.Reason
			}
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	return summary, nil
}

func trimEAPMethodEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM eap_method_events
		WHERE id NOT IN (
			SELECT id FROM eap_method_events ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil
	}
	return err
}

type eapMethodEventScanner interface {
	Scan(dest ...any) error
}

func scanEAPMethodEvent(scanner eapMethodEventScanner) (EAPMethodEvent, error) {
	var event EAPMethodEvent
	var eapMessage, messageAuthenticator, certificatePresented int
	var detailsJSON string
	if err := scanner.Scan(
		&event.ID,
		&event.ObservedAt,
		&event.Method,
		&event.InnerMethod,
		&event.Decision,
		&event.Reason,
		&event.NASIdentifier,
		&event.NASType,
		&event.UserNameHash,
		&event.CallingStationHash,
		&event.IdentitySource,
		&eapMessage,
		&messageAuthenticator,
		&certificatePresented,
		&event.TLSVersion,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return EAPMethodEvent{}, err
	}
	event.EAPMessagePresent = eapMessage != 0
	event.MessageAuthenticatorPresent = messageAuthenticator != 0
	event.CertificatePresented = certificatePresented != 0
	if strings.TrimSpace(detailsJSON) != "" {
		_ = json.Unmarshal([]byte(detailsJSON), &event.Details)
	}
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event, nil
}

func emptyToNil(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
