package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type TEAPChainEvent struct {
	ID                        int64             `json:"id"`
	ObservedAt                time.Time         `json:"observed_at"`
	Decision                  string            `json:"decision"`
	Reason                    string            `json:"reason"`
	ChainMode                 string            `json:"chain_mode"`
	ChainState                string            `json:"chain_state"`
	NASIdentifier             string            `json:"nas_identifier,omitempty"`
	NASType                   string            `json:"nas_type,omitempty"`
	OuterIdentityHash         string            `json:"outer_identity_hash,omitempty"`
	UserIdentityHash          string            `json:"user_identity_hash,omitempty"`
	MachineIdentityHash       string            `json:"machine_identity_hash,omitempty"`
	IdentitySource            string            `json:"identity_source,omitempty"`
	InnerMethod               string            `json:"inner_method,omitempty"`
	CryptoBindingValid        bool              `json:"crypto_binding_valid"`
	ChannelBindingPresent     bool              `json:"channel_binding_present"`
	ChannelBindingValid       bool              `json:"channel_binding_valid"`
	IdentityTypePresent       bool              `json:"identity_type_present"`
	PACPresented              bool              `json:"pac_presented"`
	PACProvisioningRequested  bool              `json:"pac_provisioning_requested"`
	EAPPayloadPresent         bool              `json:"eap_payload_present"`
	BasicPasswordAuth         bool              `json:"basic_password_auth"`
	IntermediateResultPresent bool              `json:"intermediate_result_present"`
	IntermediateResultSuccess bool              `json:"intermediate_result_success"`
	FinalResultPresent        bool              `json:"final_result_present"`
	FinalResultSuccess        bool              `json:"final_result_success"`
	StepCount                 int               `json:"step_count"`
	TLSVersion                string            `json:"tls_version,omitempty"`
	PolicyMode                string            `json:"policy_mode,omitempty"`
	LatencyMS                 int               `json:"latency_ms"`
	Details                   map[string]string `json:"details,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
}

type TEAPChainEventFilter struct {
	Decision  string
	ChainMode string
	NASType   string
	Limit     int
}

type TEAPChainEventSummary struct {
	TotalEvents            int            `json:"total_events"`
	Accepted               int            `json:"accepted"`
	Rejected               int            `json:"rejected"`
	MonitorAllowed         int            `json:"monitor_allowed"`
	ByDecision             map[string]int `json:"by_decision"`
	ByChainMode            map[string]int `json:"by_chain_mode"`
	MissingMachineIdentity int            `json:"missing_machine_identity"`
	MissingUserIdentity    int            `json:"missing_user_identity"`
	InvalidCryptoBinding   int            `json:"invalid_crypto_binding"`
	InvalidChannelBinding  int            `json:"invalid_channel_binding"`
	PACRequiredMissing     int            `json:"pac_required_missing"`
	LastEventAt            string         `json:"last_event_at,omitempty"`
	LastRejectedReason     string         `json:"last_rejected_reason,omitempty"`
}

func RecordTEAPChainEvent(event TEAPChainEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	decision := strings.ToLower(strings.TrimSpace(event.Decision))
	if decision == "" {
		decision = "unknown"
	}
	chainMode := strings.ToLower(strings.TrimSpace(event.ChainMode))
	if chainMode == "" {
		chainMode = "machine_then_user"
	}
	chainState := strings.ToLower(strings.TrimSpace(event.ChainState))
	if chainState == "" {
		chainState = "unknown"
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
		return fmt.Errorf("marshal TEAP chain event details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO eap_teap_chain_events
		(observed_at, decision, reason, chain_mode, chain_state, nas_identifier, nas_type,
		 outer_identity_hash, user_identity_hash, machine_identity_hash, identity_source, inner_method,
		 crypto_binding_valid, channel_binding_present, channel_binding_valid, identity_type_present,
		 pac_presented, pac_provisioning_requested, eap_payload_present, basic_password_auth,
		 intermediate_result_present, intermediate_result_success, final_result_present, final_result_success,
		 step_count, tls_version, policy_mode, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observedAt,
		decision,
		strings.TrimSpace(event.Reason),
		chainMode,
		chainState,
		emptyToNil(strings.TrimSpace(event.NASIdentifier)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.NASType))),
		emptyToNil(strings.TrimSpace(event.OuterIdentityHash)),
		emptyToNil(strings.TrimSpace(event.UserIdentityHash)),
		emptyToNil(strings.TrimSpace(event.MachineIdentityHash)),
		emptyToNil(strings.TrimSpace(event.IdentitySource)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.InnerMethod))),
		boolToSQLite(event.CryptoBindingValid),
		boolToSQLite(event.ChannelBindingPresent),
		boolToSQLite(event.ChannelBindingValid),
		boolToSQLite(event.IdentityTypePresent),
		boolToSQLite(event.PACPresented),
		boolToSQLite(event.PACProvisioningRequested),
		boolToSQLite(event.EAPPayloadPresent),
		boolToSQLite(event.BasicPasswordAuth),
		boolToSQLite(event.IntermediateResultPresent),
		boolToSQLite(event.IntermediateResultSuccess),
		boolToSQLite(event.FinalResultPresent),
		boolToSQLite(event.FinalResultSuccess),
		event.StepCount,
		emptyToNil(strings.TrimSpace(event.TLSVersion)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.PolicyMode))),
		event.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil
		}
		return fmt.Errorf("record TEAP chain event: %w", err)
	}
	return trimTEAPChainEvents(retentionLimit)
}

func ListTEAPChainEvents(filter TEAPChainEventFilter) ([]TEAPChainEvent, error) {
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
	if decision := strings.ToLower(strings.TrimSpace(filter.Decision)); decision != "" {
		clauses = append(clauses, "decision = ?")
		args = append(args, decision)
	}
	if chainMode := strings.ToLower(strings.TrimSpace(filter.ChainMode)); chainMode != "" {
		clauses = append(clauses, "chain_mode = ?")
		args = append(args, chainMode)
	}
	if nasType := strings.ToLower(strings.TrimSpace(filter.NASType)); nasType != "" {
		clauses = append(clauses, "nas_type = ?")
		args = append(args, nasType)
	}
	args = append(args, limit)
	rows, err := DB.Query(`SELECT id, observed_at, decision, reason, chain_mode, chain_state,
			COALESCE(nas_identifier, ''), COALESCE(nas_type, ''), COALESCE(outer_identity_hash, ''),
			COALESCE(user_identity_hash, ''), COALESCE(machine_identity_hash, ''), COALESCE(identity_source, ''),
			COALESCE(inner_method, ''), COALESCE(crypto_binding_valid, 0), COALESCE(channel_binding_present, 0),
			COALESCE(channel_binding_valid, 0), COALESCE(identity_type_present, 0), COALESCE(pac_presented, 0),
			COALESCE(pac_provisioning_requested, 0), COALESCE(eap_payload_present, 0), COALESCE(basic_password_auth, 0),
			COALESCE(intermediate_result_present, 0), COALESCE(intermediate_result_success, 0),
			COALESCE(final_result_present, 0), COALESCE(final_result_success, 0), COALESCE(step_count, 0),
			COALESCE(tls_version, ''), COALESCE(policy_mode, ''), COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM eap_teap_chain_events
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
	var events []TEAPChainEvent
	for rows.Next() {
		event, err := scanTEAPChainEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func SummarizeTEAPChainEvents(limit int) (TEAPChainEventSummary, error) {
	events, err := ListTEAPChainEvents(TEAPChainEventFilter{Limit: limit})
	if err != nil {
		return TEAPChainEventSummary{}, err
	}
	summary := TEAPChainEventSummary{
		ByDecision:  map[string]int{},
		ByChainMode: map[string]int{},
	}
	for i, event := range events {
		summary.TotalEvents++
		summary.ByDecision[event.Decision]++
		summary.ByChainMode[event.ChainMode]++
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
		lowerReason := strings.ToLower(event.Reason)
		if strings.Contains(lowerReason, "machine identity") {
			summary.MissingMachineIdentity++
		}
		if strings.Contains(lowerReason, "user identity") {
			summary.MissingUserIdentity++
		}
		if strings.Contains(lowerReason, "crypto-binding") || strings.Contains(lowerReason, "cryptobinding") {
			summary.InvalidCryptoBinding++
		}
		if strings.Contains(lowerReason, "channel-binding") {
			summary.InvalidChannelBinding++
		}
		if strings.Contains(lowerReason, "pac tlv is required") {
			summary.PACRequiredMissing++
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	return summary, nil
}

func trimTEAPChainEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM eap_teap_chain_events
		WHERE id NOT IN (
			SELECT id FROM eap_teap_chain_events ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil
	}
	return err
}

func scanTEAPChainEvent(scanner eapMethodEventScanner) (TEAPChainEvent, error) {
	var event TEAPChainEvent
	var cryptoBinding, channelBindingPresent, channelBindingValid, identityTypePresent int
	var pacPresented, pacProvisioningRequested, eapPayloadPresent, basicPasswordAuth int
	var intermediatePresent, intermediateSuccess, finalPresent, finalSuccess int
	var detailsJSON string
	if err := scanner.Scan(
		&event.ID,
		&event.ObservedAt,
		&event.Decision,
		&event.Reason,
		&event.ChainMode,
		&event.ChainState,
		&event.NASIdentifier,
		&event.NASType,
		&event.OuterIdentityHash,
		&event.UserIdentityHash,
		&event.MachineIdentityHash,
		&event.IdentitySource,
		&event.InnerMethod,
		&cryptoBinding,
		&channelBindingPresent,
		&channelBindingValid,
		&identityTypePresent,
		&pacPresented,
		&pacProvisioningRequested,
		&eapPayloadPresent,
		&basicPasswordAuth,
		&intermediatePresent,
		&intermediateSuccess,
		&finalPresent,
		&finalSuccess,
		&event.StepCount,
		&event.TLSVersion,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return TEAPChainEvent{}, err
	}
	event.CryptoBindingValid = cryptoBinding != 0
	event.ChannelBindingPresent = channelBindingPresent != 0
	event.ChannelBindingValid = channelBindingValid != 0
	event.IdentityTypePresent = identityTypePresent != 0
	event.PACPresented = pacPresented != 0
	event.PACProvisioningRequested = pacProvisioningRequested != 0
	event.EAPPayloadPresent = eapPayloadPresent != 0
	event.BasicPasswordAuth = basicPasswordAuth != 0
	event.IntermediateResultPresent = intermediatePresent != 0
	event.IntermediateResultSuccess = intermediateSuccess != 0
	event.FinalResultPresent = finalPresent != 0
	event.FinalResultSuccess = finalSuccess != 0
	if strings.TrimSpace(detailsJSON) != "" {
		_ = json.Unmarshal([]byte(detailsJSON), &event.Details)
	}
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event, nil
}
