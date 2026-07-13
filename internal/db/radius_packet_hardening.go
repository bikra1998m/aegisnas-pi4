package db

import (
	"encoding/json"
	"fmt"
	"strings"
)

const defaultRadiusPacketHardeningEventLimit = 6000

type RadiusPacketHardeningEvent struct {
	ID                          int            `json:"id"`
	ObservedAt                  string         `json:"observed_at"`
	SourceIP                    string         `json:"source_ip"`
	Direction                   string         `json:"direction"`
	PacketCode                  string         `json:"packet_code"`
	PacketIdentifier            int            `json:"packet_identifier"`
	Decision                    string         `json:"decision"`
	Reason                      string         `json:"reason"`
	Message                     string         `json:"message"`
	PacketLength                int            `json:"packet_length"`
	AttributeCount              int            `json:"attribute_count"`
	ProxyStateCount             int            `json:"proxy_state_count"`
	ProxyStateBytes             int            `json:"proxy_state_bytes"`
	MessageAuthenticatorPresent bool           `json:"message_authenticator_present"`
	ReplayDetected              bool           `json:"replay_detected"`
	RateLimited                 bool           `json:"rate_limited"`
	Details                     map[string]any `json:"details,omitempty"`
	CreatedAt                   string         `json:"created_at"`
}

type RadiusPacketHardeningStats struct {
	TotalEvents                 int    `json:"total_events"`
	AcceptedCount               int    `json:"accepted_count"`
	RejectedCount               int    `json:"rejected_count"`
	ReplayRejectCount           int    `json:"replay_reject_count"`
	RateLimitedRejectCount      int    `json:"rate_limited_reject_count"`
	MessageAuthenticatorRejects int    `json:"message_authenticator_rejects"`
	UnknownSourceRejects        int    `json:"unknown_source_rejects"`
	MalformedRejects            int    `json:"malformed_rejects"`
	LastEventAt                 string `json:"last_event_at"`
}

func RecordRadiusPacketHardeningEvent(event RadiusPacketHardeningEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	if retentionLimit <= 0 {
		retentionLimit = defaultRadiusPacketHardeningEventLimit
	}
	details := "{}"
	if len(event.Details) > 0 {
		payload, err := json.Marshal(event.Details)
		if err != nil {
			return err
		}
		details = string(payload)
	}
	_, err := DB.Exec(`INSERT INTO radius_packet_hardening_events (
		observed_at, source_ip, direction, packet_code, packet_identifier, decision, reason, message,
		packet_length, attribute_count, proxy_state_count, proxy_state_bytes, message_authenticator_present,
		replay_detected, rate_limited, details_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(event.ObservedAt), strings.TrimSpace(event.SourceIP), strings.TrimSpace(event.Direction),
		strings.TrimSpace(event.PacketCode), event.PacketIdentifier, strings.TrimSpace(event.Decision),
		strings.TrimSpace(event.Reason), strings.TrimSpace(event.Message), event.PacketLength, event.AttributeCount,
		event.ProxyStateCount, event.ProxyStateBytes, boolToSQLite(event.MessageAuthenticatorPresent),
		boolToSQLite(event.ReplayDetected), boolToSQLite(event.RateLimited), details)
	if err != nil {
		return fmt.Errorf("insert radius packet hardening event: %w", err)
	}
	return trimRadiusPacketHardeningEvents(retentionLimit)
}

func ListRadiusPacketHardeningEvents(limit int) ([]RadiusPacketHardeningEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, COALESCE(observed_at, ''), COALESCE(source_ip, ''), COALESCE(direction, ''),
		COALESCE(packet_code, ''), COALESCE(packet_identifier, 0), COALESCE(decision, ''), COALESCE(reason, ''),
		COALESCE(message, ''), COALESCE(packet_length, 0), COALESCE(attribute_count, 0),
		COALESCE(proxy_state_count, 0), COALESCE(proxy_state_bytes, 0), COALESCE(message_authenticator_present, 0),
		COALESCE(replay_detected, 0), COALESCE(rate_limited, 0), COALESCE(details_json, '{}'), COALESCE(created_at, '')
		FROM radius_packet_hardening_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list radius packet hardening events: %w", err)
	}
	defer rows.Close()

	var events []RadiusPacketHardeningEvent
	for rows.Next() {
		var (
			event          RadiusPacketHardeningEvent
			messageAuth    int
			replayDetected int
			rateLimited    int
			details        string
		)
		if err := rows.Scan(&event.ID, &event.ObservedAt, &event.SourceIP, &event.Direction, &event.PacketCode,
			&event.PacketIdentifier, &event.Decision, &event.Reason, &event.Message, &event.PacketLength,
			&event.AttributeCount, &event.ProxyStateCount, &event.ProxyStateBytes, &messageAuth,
			&replayDetected, &rateLimited, &details, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan radius packet hardening event: %w", err)
		}
		event.MessageAuthenticatorPresent = messageAuth == 1
		event.ReplayDetected = replayDetected == 1
		event.RateLimited = rateLimited == 1
		if strings.TrimSpace(details) != "" && details != "{}" {
			_ = json.Unmarshal([]byte(details), &event.Details)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func GetRadiusPacketHardeningStats() (RadiusPacketHardeningStats, error) {
	if DB == nil {
		return RadiusPacketHardeningStats{}, nil
	}
	var stats RadiusPacketHardeningStats
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN decision = 'accepted' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN decision = 'rejected' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN replay_detected = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN rate_limited = 1 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN reason IN ('missing_message_authenticator', 'invalid_message_authenticator') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN reason = 'unknown_source' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN reason LIKE 'malformed_%' OR reason IN ('invalid_packet_length', 'short_packet', 'oversized_packet') THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(observed_at), '')
		FROM radius_packet_hardening_events`).Scan(&stats.TotalEvents, &stats.AcceptedCount, &stats.RejectedCount,
		&stats.ReplayRejectCount, &stats.RateLimitedRejectCount, &stats.MessageAuthenticatorRejects,
		&stats.UnknownSourceRejects, &stats.MalformedRejects, &stats.LastEventAt)
	if err != nil {
		return RadiusPacketHardeningStats{}, fmt.Errorf("get radius packet hardening stats: %w", err)
	}
	return stats, nil
}

func trimRadiusPacketHardeningEvents(maxRows int) error {
	if DB == nil || maxRows <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM radius_packet_hardening_events
		WHERE id NOT IN (
			SELECT id FROM radius_packet_hardening_events ORDER BY datetime(observed_at) DESC, id DESC LIMIT ?
		)`, maxRows)
	if err != nil {
		return fmt.Errorf("trim radius packet hardening events: %w", err)
	}
	return nil
}
