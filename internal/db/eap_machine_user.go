package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type MachineUserCorrelationEvent struct {
	ID                        int64             `json:"id"`
	ObservedAt                time.Time         `json:"observed_at"`
	Decision                  string            `json:"decision"`
	Reason                    string            `json:"reason"`
	CorrelationKey            string            `json:"correlation_key"`
	CorrelationIDHash         string            `json:"correlation_id_hash,omitempty"`
	CorrelationMode           string            `json:"correlation_mode"`
	CorrelationState          string            `json:"correlation_state"`
	NASIdentifier             string            `json:"nas_identifier,omitempty"`
	NASType                   string            `json:"nas_type,omitempty"`
	CallingStationHash        string            `json:"calling_station_hash,omitempty"`
	MachineCallingStationHash string            `json:"machine_calling_station_hash,omitempty"`
	UserCallingStationHash    string            `json:"user_calling_station_hash,omitempty"`
	MachineNASIdentifier      string            `json:"machine_nas_identifier,omitempty"`
	UserNASIdentifier         string            `json:"user_nas_identifier,omitempty"`
	OuterIdentityHash         string            `json:"outer_identity_hash,omitempty"`
	MachineIdentityHash       string            `json:"machine_identity_hash,omitempty"`
	UserIdentityHash          string            `json:"user_identity_hash,omitempty"`
	IdentitySource            string            `json:"identity_source,omitempty"`
	MachineMethod             string            `json:"machine_method,omitempty"`
	UserMethod                string            `json:"user_method,omitempty"`
	MachineAuthenticated      bool              `json:"machine_authenticated"`
	UserAuthenticated         bool              `json:"user_authenticated"`
	SameCallingStation        bool              `json:"same_calling_station"`
	SameNAS                   bool              `json:"same_nas"`
	MachineBeforeUser         bool              `json:"machine_before_user"`
	MachineAuthAgeSeconds     int               `json:"machine_auth_age_seconds"`
	UserAuthAgeSeconds        int               `json:"user_auth_age_seconds"`
	MachineRole               string            `json:"machine_role,omitempty"`
	UserRole                  string            `json:"user_role,omitempty"`
	EffectiveRole             string            `json:"effective_role,omitempty"`
	DevicePosture             string            `json:"device_posture,omitempty"`
	ConflictDetected          bool              `json:"conflict_detected"`
	StaleMachineAuth          bool              `json:"stale_machine_auth"`
	TEAPChainComplete         bool              `json:"teap_chain_complete"`
	IdentityTypePresent       bool              `json:"identity_type_present"`
	CryptoBindingValid        bool              `json:"crypto_binding_valid"`
	ChannelBindingValid       bool              `json:"channel_binding_valid"`
	ReplayDetected            bool              `json:"replay_detected"`
	PolicyMode                string            `json:"policy_mode,omitempty"`
	LatencyMS                 int               `json:"latency_ms"`
	Details                   map[string]string `json:"details,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
}

type MachineUserCorrelationState struct {
	CorrelationKey        string            `json:"correlation_key"`
	UpdatedAt             time.Time         `json:"updated_at"`
	Decision              string            `json:"decision"`
	CorrelationState      string            `json:"correlation_state"`
	CorrelationMode       string            `json:"correlation_mode"`
	NASIdentifier         string            `json:"nas_identifier,omitempty"`
	NASType               string            `json:"nas_type,omitempty"`
	CallingStationHash    string            `json:"calling_station_hash,omitempty"`
	MachineIdentityHash   string            `json:"machine_identity_hash,omitempty"`
	UserIdentityHash      string            `json:"user_identity_hash,omitempty"`
	MachineMethod         string            `json:"machine_method,omitempty"`
	UserMethod            string            `json:"user_method,omitempty"`
	MachineAuthenticated  bool              `json:"machine_authenticated"`
	UserAuthenticated     bool              `json:"user_authenticated"`
	MachineAuthAgeSeconds int               `json:"machine_auth_age_seconds"`
	UserAuthAgeSeconds    int               `json:"user_auth_age_seconds"`
	EffectiveRole         string            `json:"effective_role,omitempty"`
	DevicePosture         string            `json:"device_posture,omitempty"`
	ConflictDetected      bool              `json:"conflict_detected"`
	StaleMachineAuth      bool              `json:"stale_machine_auth"`
	PolicyMode            string            `json:"policy_mode,omitempty"`
	Details               map[string]string `json:"details,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
}

type MachineUserCorrelationFilter struct {
	Decision        string
	CorrelationMode string
	NASType         string
	Limit           int
}

type MachineUserCorrelationSummary struct {
	TotalEvents              int            `json:"total_events"`
	Accepted                 int            `json:"accepted"`
	Rejected                 int            `json:"rejected"`
	MonitorAllowed           int            `json:"monitor_allowed"`
	Quarantined              int            `json:"quarantined"`
	ActiveCorrelations       int            `json:"active_correlations"`
	ByDecision               map[string]int `json:"by_decision"`
	ByCorrelationMode        map[string]int `json:"by_correlation_mode"`
	MissingMachineIdentity   int            `json:"missing_machine_identity"`
	MissingUserIdentity      int            `json:"missing_user_identity"`
	StaleMachineAuth         int            `json:"stale_machine_auth"`
	RoleConflict             int            `json:"role_conflict"`
	CallingStationMismatch   int            `json:"calling_station_mismatch"`
	NASMismatch              int            `json:"nas_mismatch"`
	MachineBeforeUserFailure int            `json:"machine_before_user_failure"`
	LastEventAt              string         `json:"last_event_at,omitempty"`
	LastRejectedReason       string         `json:"last_rejected_reason,omitempty"`
}

func RecordMachineUserCorrelationEvent(event MachineUserCorrelationEvent, retentionLimit, maxActive int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeMachineUserCorrelationEvent(event)
	detailsJSON, err := json.Marshal(normalized.Details)
	if err != nil {
		return fmt.Errorf("marshal machine/user correlation details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO eap_machine_user_correlations
		(observed_at, decision, reason, correlation_key, correlation_id_hash, correlation_mode, correlation_state,
		 nas_identifier, nas_type, calling_station_hash, machine_calling_station_hash, user_calling_station_hash,
		 machine_nas_identifier, user_nas_identifier, outer_identity_hash, machine_identity_hash, user_identity_hash,
		 identity_source, machine_method, user_method, machine_authenticated, user_authenticated, same_calling_station,
		 same_nas, machine_before_user, machine_auth_age_seconds, user_auth_age_seconds, machine_role, user_role,
		 effective_role, device_posture, conflict_detected, stale_machine_auth, teap_chain_complete,
		 identity_type_present, crypto_binding_valid, channel_binding_valid, replay_detected, policy_mode, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalized.ObservedAt,
		normalized.Decision,
		normalized.Reason,
		normalized.CorrelationKey,
		emptyToNil(normalized.CorrelationIDHash),
		normalized.CorrelationMode,
		normalized.CorrelationState,
		emptyToNil(normalized.NASIdentifier),
		emptyToNil(normalized.NASType),
		emptyToNil(normalized.CallingStationHash),
		emptyToNil(normalized.MachineCallingStationHash),
		emptyToNil(normalized.UserCallingStationHash),
		emptyToNil(normalized.MachineNASIdentifier),
		emptyToNil(normalized.UserNASIdentifier),
		emptyToNil(normalized.OuterIdentityHash),
		emptyToNil(normalized.MachineIdentityHash),
		emptyToNil(normalized.UserIdentityHash),
		emptyToNil(normalized.IdentitySource),
		emptyToNil(normalized.MachineMethod),
		emptyToNil(normalized.UserMethod),
		boolToSQLite(normalized.MachineAuthenticated),
		boolToSQLite(normalized.UserAuthenticated),
		boolToSQLite(normalized.SameCallingStation),
		boolToSQLite(normalized.SameNAS),
		boolToSQLite(normalized.MachineBeforeUser),
		normalized.MachineAuthAgeSeconds,
		normalized.UserAuthAgeSeconds,
		emptyToNil(normalized.MachineRole),
		emptyToNil(normalized.UserRole),
		emptyToNil(normalized.EffectiveRole),
		emptyToNil(normalized.DevicePosture),
		boolToSQLite(normalized.ConflictDetected),
		boolToSQLite(normalized.StaleMachineAuth),
		boolToSQLite(normalized.TEAPChainComplete),
		boolToSQLite(normalized.IdentityTypePresent),
		boolToSQLite(normalized.CryptoBindingValid),
		boolToSQLite(normalized.ChannelBindingValid),
		boolToSQLite(normalized.ReplayDetected),
		emptyToNil(normalized.PolicyMode),
		normalized.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if isMissingMachineUserTable(err) {
			return nil
		}
		return fmt.Errorf("record machine/user correlation event: %w", err)
	}
	if err := upsertMachineUserCorrelationState(normalized, string(detailsJSON)); err != nil {
		return err
	}
	if err := trimMachineUserCorrelationEvents(retentionLimit); err != nil {
		return err
	}
	return trimMachineUserCorrelationState(maxActive)
}

func ListMachineUserCorrelationEvents(filter MachineUserCorrelationFilter) ([]MachineUserCorrelationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	limit := boundedMachineUserLimit(filter.Limit)
	clauses := []string{"1=1"}
	args := []any{}
	if decision := strings.ToLower(strings.TrimSpace(filter.Decision)); decision != "" {
		clauses = append(clauses, "decision = ?")
		args = append(args, decision)
	}
	if mode := strings.ToLower(strings.TrimSpace(filter.CorrelationMode)); mode != "" {
		clauses = append(clauses, "correlation_mode = ?")
		args = append(args, mode)
	}
	if nasType := strings.ToLower(strings.TrimSpace(filter.NASType)); nasType != "" {
		clauses = append(clauses, "nas_type = ?")
		args = append(args, nasType)
	}
	args = append(args, limit)
	rows, err := DB.Query(`SELECT id, observed_at, decision, reason, correlation_key, COALESCE(correlation_id_hash, ''),
			correlation_mode, correlation_state, COALESCE(nas_identifier, ''), COALESCE(nas_type, ''),
			COALESCE(calling_station_hash, ''), COALESCE(machine_calling_station_hash, ''), COALESCE(user_calling_station_hash, ''),
			COALESCE(machine_nas_identifier, ''), COALESCE(user_nas_identifier, ''), COALESCE(outer_identity_hash, ''),
			COALESCE(machine_identity_hash, ''), COALESCE(user_identity_hash, ''), COALESCE(identity_source, ''),
			COALESCE(machine_method, ''), COALESCE(user_method, ''), COALESCE(machine_authenticated, 0),
			COALESCE(user_authenticated, 0), COALESCE(same_calling_station, 0), COALESCE(same_nas, 0),
			COALESCE(machine_before_user, 0), COALESCE(machine_auth_age_seconds, 0), COALESCE(user_auth_age_seconds, 0),
			COALESCE(machine_role, ''), COALESCE(user_role, ''), COALESCE(effective_role, ''), COALESCE(device_posture, ''),
			COALESCE(conflict_detected, 0), COALESCE(stale_machine_auth, 0), COALESCE(teap_chain_complete, 0),
			COALESCE(identity_type_present, 0), COALESCE(crypto_binding_valid, 0), COALESCE(channel_binding_valid, 0),
			COALESCE(replay_detected, 0), COALESCE(policy_mode, ''), COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM eap_machine_user_correlations
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY observed_at DESC, id DESC
		LIMIT ?`, args...)
	if err != nil {
		if isMissingMachineUserTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var events []MachineUserCorrelationEvent
	for rows.Next() {
		event, err := scanMachineUserCorrelationEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func ListMachineUserCorrelationState(limit int) ([]MachineUserCorrelationState, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT correlation_key, updated_at, decision, correlation_state, correlation_mode,
			COALESCE(nas_identifier, ''), COALESCE(nas_type, ''), COALESCE(calling_station_hash, ''),
			COALESCE(machine_identity_hash, ''), COALESCE(user_identity_hash, ''), COALESCE(machine_method, ''),
			COALESCE(user_method, ''), COALESCE(machine_authenticated, 0), COALESCE(user_authenticated, 0),
			COALESCE(machine_auth_age_seconds, 0), COALESCE(user_auth_age_seconds, 0), COALESCE(effective_role, ''),
			COALESCE(device_posture, ''), COALESCE(conflict_detected, 0), COALESCE(stale_machine_auth, 0),
			COALESCE(policy_mode, ''), COALESCE(details_json, '{}'), created_at
		FROM eap_machine_user_session_state
		ORDER BY updated_at DESC
		LIMIT ?`, boundedMachineUserLimit(limit))
	if err != nil {
		if isMissingMachineUserTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var states []MachineUserCorrelationState
	for rows.Next() {
		state, err := scanMachineUserCorrelationState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func SummarizeMachineUserCorrelations(limit int) (MachineUserCorrelationSummary, error) {
	events, err := ListMachineUserCorrelationEvents(MachineUserCorrelationFilter{Limit: limit})
	if err != nil {
		return MachineUserCorrelationSummary{}, err
	}
	active, err := CountMachineUserCorrelationState()
	if err != nil {
		return MachineUserCorrelationSummary{}, err
	}
	summary := MachineUserCorrelationSummary{
		ActiveCorrelations: active,
		ByDecision:         map[string]int{},
		ByCorrelationMode:  map[string]int{},
	}
	for i, event := range events {
		summary.TotalEvents++
		summary.ByDecision[event.Decision]++
		summary.ByCorrelationMode[event.CorrelationMode]++
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
		case "quarantined":
			summary.Quarantined++
		}
		reason := strings.ToLower(event.Reason)
		if strings.Contains(reason, "machine authentication evidence is required") || strings.Contains(reason, "machine identity") {
			summary.MissingMachineIdentity++
		}
		if strings.Contains(reason, "user authentication evidence is required") || strings.Contains(reason, "user identity") {
			summary.MissingUserIdentity++
		}
		if event.StaleMachineAuth || strings.Contains(reason, "machine authentication evidence is stale") {
			summary.StaleMachineAuth++
		}
		if event.ConflictDetected || strings.Contains(reason, "roles conflict") {
			summary.RoleConflict++
		}
		if strings.Contains(reason, "calling-station-id") {
			summary.CallingStationMismatch++
		}
		if strings.Contains(reason, "nas-identifier") {
			summary.NASMismatch++
		}
		if strings.Contains(reason, "precede user") || strings.Contains(reason, "transition window") {
			summary.MachineBeforeUserFailure++
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	return summary, nil
}

func CountMachineUserCorrelationState() (int, error) {
	if DB == nil {
		return 0, nil
	}
	var count int
	err := DB.QueryRow(`SELECT COUNT(*) FROM eap_machine_user_session_state`).Scan(&count)
	if err != nil && isMissingMachineUserTable(err) {
		return 0, nil
	}
	return count, err
}

func upsertMachineUserCorrelationState(event MachineUserCorrelationEvent, detailsJSON string) error {
	_, err := DB.Exec(`INSERT INTO eap_machine_user_session_state
		(correlation_key, updated_at, decision, correlation_state, correlation_mode, nas_identifier, nas_type,
		 calling_station_hash, machine_identity_hash, user_identity_hash, machine_method, user_method,
		 machine_authenticated, user_authenticated, machine_auth_age_seconds, user_auth_age_seconds,
		 effective_role, device_posture, conflict_detected, stale_machine_auth, policy_mode, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(correlation_key) DO UPDATE SET
			updated_at=excluded.updated_at,
			decision=excluded.decision,
			correlation_state=excluded.correlation_state,
			correlation_mode=excluded.correlation_mode,
			nas_identifier=excluded.nas_identifier,
			nas_type=excluded.nas_type,
			calling_station_hash=excluded.calling_station_hash,
			machine_identity_hash=excluded.machine_identity_hash,
			user_identity_hash=excluded.user_identity_hash,
			machine_method=excluded.machine_method,
			user_method=excluded.user_method,
			machine_authenticated=excluded.machine_authenticated,
			user_authenticated=excluded.user_authenticated,
			machine_auth_age_seconds=excluded.machine_auth_age_seconds,
			user_auth_age_seconds=excluded.user_auth_age_seconds,
			effective_role=excluded.effective_role,
			device_posture=excluded.device_posture,
			conflict_detected=excluded.conflict_detected,
			stale_machine_auth=excluded.stale_machine_auth,
			policy_mode=excluded.policy_mode,
			details_json=excluded.details_json`,
		event.CorrelationKey,
		event.ObservedAt,
		event.Decision,
		event.CorrelationState,
		event.CorrelationMode,
		emptyToNil(event.NASIdentifier),
		emptyToNil(event.NASType),
		emptyToNil(event.CallingStationHash),
		emptyToNil(event.MachineIdentityHash),
		emptyToNil(event.UserIdentityHash),
		emptyToNil(event.MachineMethod),
		emptyToNil(event.UserMethod),
		boolToSQLite(event.MachineAuthenticated),
		boolToSQLite(event.UserAuthenticated),
		event.MachineAuthAgeSeconds,
		event.UserAuthAgeSeconds,
		emptyToNil(event.EffectiveRole),
		emptyToNil(event.DevicePosture),
		boolToSQLite(event.ConflictDetected),
		boolToSQLite(event.StaleMachineAuth),
		emptyToNil(event.PolicyMode),
		detailsJSON,
	)
	if err != nil && isMissingMachineUserTable(err) {
		return nil
	}
	return err
}

func trimMachineUserCorrelationEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM eap_machine_user_correlations
		WHERE id NOT IN (
			SELECT id FROM eap_machine_user_correlations ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && isMissingMachineUserTable(err) {
		return nil
	}
	return err
}

func trimMachineUserCorrelationState(maxActive int) error {
	if DB == nil || maxActive < 0 {
		return nil
	}
	if maxActive == 0 {
		maxActive = 100000
	}
	_, err := DB.Exec(`DELETE FROM eap_machine_user_session_state
		WHERE correlation_key NOT IN (
			SELECT correlation_key FROM eap_machine_user_session_state ORDER BY updated_at DESC LIMIT ?
		)`, maxActive)
	if err != nil && isMissingMachineUserTable(err) {
		return nil
	}
	return err
}

func normalizeMachineUserCorrelationEvent(event MachineUserCorrelationEvent) MachineUserCorrelationEvent {
	event.Decision = strings.ToLower(strings.TrimSpace(event.Decision))
	if event.Decision == "" {
		event.Decision = "unknown"
	}
	event.CorrelationMode = strings.ToLower(strings.TrimSpace(event.CorrelationMode))
	if event.CorrelationMode == "" {
		event.CorrelationMode = "machine_then_user"
	}
	event.CorrelationState = strings.ToLower(strings.TrimSpace(event.CorrelationState))
	if event.CorrelationState == "" {
		event.CorrelationState = "unknown"
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	event.NASType = strings.ToLower(strings.TrimSpace(event.NASType))
	event.IdentitySource = strings.TrimSpace(event.IdentitySource)
	event.MachineMethod = strings.ToLower(strings.TrimSpace(event.MachineMethod))
	event.UserMethod = strings.ToLower(strings.TrimSpace(event.UserMethod))
	event.PolicyMode = strings.ToLower(strings.TrimSpace(event.PolicyMode))
	event.DevicePosture = strings.ToLower(strings.TrimSpace(event.DevicePosture))
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	event.CorrelationKey = strings.TrimSpace(event.CorrelationKey)
	if event.CorrelationKey == "" {
		event.CorrelationKey = BuildMachineUserCorrelationKey(event.CorrelationIDHash, event.MachineIdentityHash, event.UserIdentityHash, event.CallingStationHash)
	}
	return event
}

func BuildMachineUserCorrelationKey(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parts = append(parts, strings.ToLower(value))
	}
	if len(parts) == 0 {
		parts = append(parts, time.Now().UTC().Format(time.RFC3339Nano))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func scanMachineUserCorrelationEvent(scanner eapMethodEventScanner) (MachineUserCorrelationEvent, error) {
	var event MachineUserCorrelationEvent
	var machineAuthenticated, userAuthenticated, sameCalling, sameNAS, machineBefore int
	var conflictDetected, staleMachine, teapChain, identityType, cryptoBinding, channelBinding, replay int
	var detailsJSON string
	if err := scanner.Scan(
		&event.ID,
		&event.ObservedAt,
		&event.Decision,
		&event.Reason,
		&event.CorrelationKey,
		&event.CorrelationIDHash,
		&event.CorrelationMode,
		&event.CorrelationState,
		&event.NASIdentifier,
		&event.NASType,
		&event.CallingStationHash,
		&event.MachineCallingStationHash,
		&event.UserCallingStationHash,
		&event.MachineNASIdentifier,
		&event.UserNASIdentifier,
		&event.OuterIdentityHash,
		&event.MachineIdentityHash,
		&event.UserIdentityHash,
		&event.IdentitySource,
		&event.MachineMethod,
		&event.UserMethod,
		&machineAuthenticated,
		&userAuthenticated,
		&sameCalling,
		&sameNAS,
		&machineBefore,
		&event.MachineAuthAgeSeconds,
		&event.UserAuthAgeSeconds,
		&event.MachineRole,
		&event.UserRole,
		&event.EffectiveRole,
		&event.DevicePosture,
		&conflictDetected,
		&staleMachine,
		&teapChain,
		&identityType,
		&cryptoBinding,
		&channelBinding,
		&replay,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return MachineUserCorrelationEvent{}, err
	}
	event.MachineAuthenticated = machineAuthenticated != 0
	event.UserAuthenticated = userAuthenticated != 0
	event.SameCallingStation = sameCalling != 0
	event.SameNAS = sameNAS != 0
	event.MachineBeforeUser = machineBefore != 0
	event.ConflictDetected = conflictDetected != 0
	event.StaleMachineAuth = staleMachine != 0
	event.TEAPChainComplete = teapChain != 0
	event.IdentityTypePresent = identityType != 0
	event.CryptoBindingValid = cryptoBinding != 0
	event.ChannelBindingValid = channelBinding != 0
	event.ReplayDetected = replay != 0
	if err := json.Unmarshal([]byte(detailsJSON), &event.Details); err != nil {
		return MachineUserCorrelationEvent{}, err
	}
	return event, nil
}

func scanMachineUserCorrelationState(scanner eapMethodEventScanner) (MachineUserCorrelationState, error) {
	var state MachineUserCorrelationState
	var machineAuthenticated, userAuthenticated, conflictDetected, staleMachine int
	var detailsJSON string
	if err := scanner.Scan(
		&state.CorrelationKey,
		&state.UpdatedAt,
		&state.Decision,
		&state.CorrelationState,
		&state.CorrelationMode,
		&state.NASIdentifier,
		&state.NASType,
		&state.CallingStationHash,
		&state.MachineIdentityHash,
		&state.UserIdentityHash,
		&state.MachineMethod,
		&state.UserMethod,
		&machineAuthenticated,
		&userAuthenticated,
		&state.MachineAuthAgeSeconds,
		&state.UserAuthAgeSeconds,
		&state.EffectiveRole,
		&state.DevicePosture,
		&conflictDetected,
		&staleMachine,
		&state.PolicyMode,
		&detailsJSON,
		&state.CreatedAt,
	); err != nil {
		return MachineUserCorrelationState{}, err
	}
	state.MachineAuthenticated = machineAuthenticated != 0
	state.UserAuthenticated = userAuthenticated != 0
	state.ConflictDetected = conflictDetected != 0
	state.StaleMachineAuth = staleMachine != 0
	if err := json.Unmarshal([]byte(detailsJSON), &state.Details); err != nil {
		return MachineUserCorrelationState{}, err
	}
	return state, nil
}

func boundedMachineUserLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 5000 {
		return 5000
	}
	return limit
}

func isMissingMachineUserTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table")
}
