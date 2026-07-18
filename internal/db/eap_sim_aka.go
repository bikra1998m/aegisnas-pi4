package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type SIMAKAEvent struct {
	ID                      int64             `json:"id"`
	ObservedAt              time.Time         `json:"observed_at"`
	Method                  string            `json:"method"`
	Decision                string            `json:"decision"`
	Reason                  string            `json:"reason"`
	NASIdentifier           string            `json:"nas_identifier,omitempty"`
	NASType                 string            `json:"nas_type,omitempty"`
	IdentityHash            string            `json:"identity_hash,omitempty"`
	PermanentIdentityHash   string            `json:"permanent_identity_hash,omitempty"`
	PseudonymIdentityHash   string            `json:"pseudonym_identity_hash,omitempty"`
	ReauthIdentityHash      string            `json:"reauth_identity_hash,omitempty"`
	CallingStationHash      string            `json:"calling_station_hash,omitempty"`
	IdentitySource          string            `json:"identity_source,omitempty"`
	VectorProvider          string            `json:"vector_provider,omitempty"`
	VectorProviderAvailable bool              `json:"vector_provider_available"`
	VectorAvailable         bool              `json:"vector_available"`
	VectorFresh             bool              `json:"vector_fresh"`
	VectorAgeSeconds        int               `json:"vector_age_seconds"`
	TripletCount            int               `json:"triplet_count"`
	QuintupletCount         int               `json:"quintuplet_count"`
	RESValid                bool              `json:"res_valid"`
	MACValid                bool              `json:"mac_valid"`
	AUTNValid               bool              `json:"autn_valid"`
	AUTSValid               bool              `json:"auts_valid"`
	ResyncRequested         bool              `json:"resync_requested"`
	ResyncAgeSeconds        int               `json:"resync_age_seconds"`
	NetworkNameHash         string            `json:"network_name_hash,omitempty"`
	KDFValid                bool              `json:"kdf_valid"`
	ReplayDetected          bool              `json:"replay_detected"`
	PolicyMode              string            `json:"policy_mode,omitempty"`
	LatencyMS               int               `json:"latency_ms"`
	Details                 map[string]string `json:"details,omitempty"`
	CreatedAt               time.Time         `json:"created_at"`
}

type SIMAKAEventFilter struct {
	Method   string
	Decision string
	NASType  string
	Limit    int
}

type SIMAKAEventSummary struct {
	TotalEvents          int            `json:"total_events"`
	Accepted             int            `json:"accepted"`
	Rejected             int            `json:"rejected"`
	MonitorAllowed       int            `json:"monitor_allowed"`
	ByMethod             map[string]int `json:"by_method"`
	ByDecision           map[string]int `json:"by_decision"`
	MissingIdentity      int            `json:"missing_identity"`
	MissingVector        int            `json:"missing_vector"`
	StaleVector          int            `json:"stale_vector"`
	InvalidAuthenticator int            `json:"invalid_authenticator"`
	ResyncEvents         int            `json:"resync_events"`
	ReplayRejected       int            `json:"replay_rejected"`
	LastEventAt          string         `json:"last_event_at,omitempty"`
	LastRejectedReason   string         `json:"last_rejected_reason,omitempty"`
}

func RecordSIMAKAEvent(event SIMAKAEvent, retentionLimit int) error {
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
		return fmt.Errorf("marshal EAP-SIM/AKA event details: %w", err)
	}
	_, err = DB.Exec(`INSERT INTO eap_sim_aka_events
		(observed_at, method, decision, reason, nas_identifier, nas_type, identity_hash,
		 permanent_identity_hash, pseudonym_identity_hash, reauth_identity_hash, calling_station_hash,
		 identity_source, vector_provider, vector_provider_available, vector_available, vector_fresh,
		 vector_age_seconds, triplet_count, quintuplet_count, res_valid, mac_valid, autn_valid,
		 auts_valid, resync_requested, resync_age_seconds, network_name_hash, kdf_valid,
		 replay_detected, policy_mode, latency_ms, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		observedAt,
		method,
		decision,
		strings.TrimSpace(event.Reason),
		emptyToNil(strings.TrimSpace(event.NASIdentifier)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.NASType))),
		emptyToNil(strings.TrimSpace(event.IdentityHash)),
		emptyToNil(strings.TrimSpace(event.PermanentIdentityHash)),
		emptyToNil(strings.TrimSpace(event.PseudonymIdentityHash)),
		emptyToNil(strings.TrimSpace(event.ReauthIdentityHash)),
		emptyToNil(strings.TrimSpace(event.CallingStationHash)),
		emptyToNil(strings.TrimSpace(event.IdentitySource)),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.VectorProvider))),
		boolToSQLite(event.VectorProviderAvailable),
		boolToSQLite(event.VectorAvailable),
		boolToSQLite(event.VectorFresh),
		event.VectorAgeSeconds,
		event.TripletCount,
		event.QuintupletCount,
		boolToSQLite(event.RESValid),
		boolToSQLite(event.MACValid),
		boolToSQLite(event.AUTNValid),
		boolToSQLite(event.AUTSValid),
		boolToSQLite(event.ResyncRequested),
		event.ResyncAgeSeconds,
		emptyToNil(strings.TrimSpace(event.NetworkNameHash)),
		boolToSQLite(event.KDFValid),
		boolToSQLite(event.ReplayDetected),
		emptyToNil(strings.ToLower(strings.TrimSpace(event.PolicyMode))),
		event.LatencyMS,
		string(detailsJSON),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil
		}
		return fmt.Errorf("record EAP-SIM/AKA event: %w", err)
	}
	return trimSIMAKAEvents(retentionLimit)
}

func ListSIMAKAEvents(filter SIMAKAEventFilter) ([]SIMAKAEvent, error) {
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
			COALESCE(nas_type, ''), COALESCE(identity_hash, ''), COALESCE(permanent_identity_hash, ''),
			COALESCE(pseudonym_identity_hash, ''), COALESCE(reauth_identity_hash, ''),
			COALESCE(calling_station_hash, ''), COALESCE(identity_source, ''), COALESCE(vector_provider, ''),
			COALESCE(vector_provider_available, 0), COALESCE(vector_available, 0), COALESCE(vector_fresh, 0),
			COALESCE(vector_age_seconds, 0), COALESCE(triplet_count, 0), COALESCE(quintuplet_count, 0),
			COALESCE(res_valid, 0), COALESCE(mac_valid, 0), COALESCE(autn_valid, 0), COALESCE(auts_valid, 0),
			COALESCE(resync_requested, 0), COALESCE(resync_age_seconds, 0), COALESCE(network_name_hash, ''),
			COALESCE(kdf_valid, 0), COALESCE(replay_detected, 0), COALESCE(policy_mode, ''),
			COALESCE(latency_ms, 0), COALESCE(details_json, '{}'), created_at
		FROM eap_sim_aka_events
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
	var events []SIMAKAEvent
	for rows.Next() {
		event, err := scanSIMAKAEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func SummarizeSIMAKAEvents(limit int) (SIMAKAEventSummary, error) {
	events, err := ListSIMAKAEvents(SIMAKAEventFilter{Limit: limit})
	if err != nil {
		return SIMAKAEventSummary{}, err
	}
	summary := SIMAKAEventSummary{
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
		if strings.Contains(reason, "identity") && strings.Contains(reason, "required") {
			summary.MissingIdentity++
		}
		if strings.Contains(reason, "vector") && (strings.Contains(reason, "missing") || strings.Contains(reason, "unavailable")) {
			summary.MissingVector++
		}
		if strings.Contains(reason, "vector") && strings.Contains(reason, "stale") {
			summary.StaleVector++
		}
		if strings.Contains(reason, "validation failed") || strings.Contains(reason, "mac") || strings.Contains(reason, "autn") || strings.Contains(reason, "sres") {
			summary.InvalidAuthenticator++
		}
		if event.ResyncRequested || strings.Contains(reason, "resynchronization") {
			summary.ResyncEvents++
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

func trimSIMAKAEvents(retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit == 0 {
		retentionLimit = 6000
	}
	if retentionLimit < 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM eap_sim_aka_events
		WHERE id NOT IN (
			SELECT id FROM eap_sim_aka_events ORDER BY observed_at DESC, id DESC LIMIT ?
		)`, retentionLimit)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") {
		return nil
	}
	return err
}

func scanSIMAKAEvent(scanner eapMethodEventScanner) (SIMAKAEvent, error) {
	var event SIMAKAEvent
	var vectorProviderAvailable, vectorAvailable, vectorFresh int
	var resValid, macValid, autnValid, autsValid int
	var resyncRequested, kdfValid, replayDetected int
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
		&event.PermanentIdentityHash,
		&event.PseudonymIdentityHash,
		&event.ReauthIdentityHash,
		&event.CallingStationHash,
		&event.IdentitySource,
		&event.VectorProvider,
		&vectorProviderAvailable,
		&vectorAvailable,
		&vectorFresh,
		&event.VectorAgeSeconds,
		&event.TripletCount,
		&event.QuintupletCount,
		&resValid,
		&macValid,
		&autnValid,
		&autsValid,
		&resyncRequested,
		&event.ResyncAgeSeconds,
		&event.NetworkNameHash,
		&kdfValid,
		&replayDetected,
		&event.PolicyMode,
		&event.LatencyMS,
		&detailsJSON,
		&event.CreatedAt,
	); err != nil {
		return SIMAKAEvent{}, err
	}
	event.VectorProviderAvailable = vectorProviderAvailable != 0
	event.VectorAvailable = vectorAvailable != 0
	event.VectorFresh = vectorFresh != 0
	event.RESValid = resValid != 0
	event.MACValid = macValid != 0
	event.AUTNValid = autnValid != 0
	event.AUTSValid = autsValid != 0
	event.ResyncRequested = resyncRequested != 0
	event.KDFValid = kdfValid != 0
	event.ReplayDetected = replayDetected != 0
	if strings.TrimSpace(detailsJSON) != "" {
		_ = json.Unmarshal([]byte(detailsJSON), &event.Details)
	}
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event, nil
}
