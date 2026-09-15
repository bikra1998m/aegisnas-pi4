package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type PPSKLifecycleEventInput struct {
	EventID                string
	Operation              string
	Status                 string
	ConfigPath             string
	PSKFilePath            string
	HostapdConfigSHA256    string
	PSKFileSHA256          string
	PlanFingerprint        string
	SSIDCount              int
	PPSKSSIDCount          int
	ProfileCount           int
	GroupCount             int
	CredentialCount        int
	ActiveCredentialCount  int
	StagedCredentialCount  int
	RevokedCredentialCount int
	ExpiredCredentialCount int
	ControllerSyncCount    int
	DiagnosticCount        int
	SummaryJSON            string
	ReportJSON             string
	Actor                  string
}

type PPSKLifecycleEvent struct {
	ID                     int    `json:"id"`
	EventID                string `json:"event_id"`
	Operation              string `json:"operation"`
	Status                 string `json:"status"`
	ConfigPath             string `json:"config_path,omitempty"`
	PSKFilePath            string `json:"psk_file_path,omitempty"`
	HostapdConfigSHA256    string `json:"hostapd_config_sha256,omitempty"`
	PSKFileSHA256          string `json:"psk_file_sha256,omitempty"`
	PlanFingerprint        string `json:"plan_fingerprint"`
	SSIDCount              int    `json:"ssid_count"`
	PPSKSSIDCount          int    `json:"ppsk_ssid_count"`
	ProfileCount           int    `json:"profile_count"`
	GroupCount             int    `json:"group_count"`
	CredentialCount        int    `json:"credential_count"`
	ActiveCredentialCount  int    `json:"active_credential_count"`
	StagedCredentialCount  int    `json:"staged_credential_count"`
	RevokedCredentialCount int    `json:"revoked_credential_count"`
	ExpiredCredentialCount int    `json:"expired_credential_count"`
	ControllerSyncCount    int    `json:"controller_sync_count"`
	DiagnosticCount        int    `json:"diagnostic_count"`
	SummaryJSON            string `json:"summary_json"`
	ReportJSON             string `json:"report_json,omitempty"`
	Actor                  string `json:"actor,omitempty"`
	CreatedAt              string `json:"created_at"`
}

type PPSKLifecycleSummary struct {
	TotalEvents                int    `json:"total_events"`
	PreviewEvents              int    `json:"preview_events"`
	ApplyEvents                int    `json:"apply_events"`
	StatusEvents               int    `json:"status_events"`
	PreviewedCount             int    `json:"previewed_count"`
	AppliedCount               int    `json:"applied_count"`
	BlockedCount               int    `json:"blocked_count"`
	DegradedCount              int    `json:"degraded_count"`
	SkippedCount               int    `json:"skipped_count"`
	FailedCount                int    `json:"failed_count"`
	LastEventAt                string `json:"last_event_at,omitempty"`
	LastFingerprint            string `json:"last_fingerprint,omitempty"`
	LastConfigSHA256           string `json:"last_hostapd_config_sha256,omitempty"`
	LastPSKFileSHA256          string `json:"last_psk_file_sha256,omitempty"`
	LastPPSKSSIDCount          int    `json:"last_ppsk_ssid_count"`
	LastProfileCount           int    `json:"last_profile_count"`
	LastGroupCount             int    `json:"last_group_count"`
	LastCredentialCount        int    `json:"last_credential_count"`
	LastActiveCredentialCount  int    `json:"last_active_credential_count"`
	LastStagedCredentialCount  int    `json:"last_staged_credential_count"`
	LastRevokedCredentialCount int    `json:"last_revoked_credential_count"`
	LastExpiredCredentialCount int    `json:"last_expired_credential_count"`
	LastControllerSyncCount    int    `json:"last_controller_sync_count"`
}

func RecordPPSKLifecycleEvent(input PPSKLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizePPSKLifecycleOperation(input.Operation)
	input.Status = normalizePPSKLifecycleStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newPPSKLifecycleEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("PPSK lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("PPSK lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}
	_, err := DB.Exec(`INSERT INTO ppsk_lifecycle_events (
			event_id, operation, status, config_path, psk_file_path, hostapd_config_sha256, psk_file_sha256,
			plan_fingerprint, ssid_count, ppsk_ssid_count, profile_count, group_count, credential_count,
			active_credential_count, staged_credential_count, revoked_credential_count, expired_credential_count,
			controller_sync_count, diagnostic_count, summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			config_path = excluded.config_path,
			psk_file_path = excluded.psk_file_path,
			hostapd_config_sha256 = excluded.hostapd_config_sha256,
			psk_file_sha256 = excluded.psk_file_sha256,
			plan_fingerprint = excluded.plan_fingerprint,
			ssid_count = excluded.ssid_count,
			ppsk_ssid_count = excluded.ppsk_ssid_count,
			profile_count = excluded.profile_count,
			group_count = excluded.group_count,
			credential_count = excluded.credential_count,
			active_credential_count = excluded.active_credential_count,
			staged_credential_count = excluded.staged_credential_count,
			revoked_credential_count = excluded.revoked_credential_count,
			expired_credential_count = excluded.expired_credential_count,
			controller_sync_count = excluded.controller_sync_count,
			diagnostic_count = excluded.diagnostic_count,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.ConfigPath)),
		nullString(strings.TrimSpace(input.PSKFilePath)),
		nullString(strings.TrimSpace(input.HostapdConfigSHA256)),
		nullString(strings.TrimSpace(input.PSKFileSHA256)),
		strings.TrimSpace(input.PlanFingerprint),
		nonNegativeInt(input.SSIDCount),
		nonNegativeInt(input.PPSKSSIDCount),
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.GroupCount),
		nonNegativeInt(input.CredentialCount),
		nonNegativeInt(input.ActiveCredentialCount),
		nonNegativeInt(input.StagedCredentialCount),
		nonNegativeInt(input.RevokedCredentialCount),
		nonNegativeInt(input.ExpiredCredentialCount),
		nonNegativeInt(input.ControllerSyncCount),
		nonNegativeInt(input.DiagnosticCount),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record PPSK lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListPPSKLifecycleEvents(limit int) ([]PPSKLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(ppskLifecycleSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list PPSK lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []PPSKLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanPPSKLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list PPSK lifecycle rows: %w", err)
	}
	return events, nil
}

func GetPPSKLifecycleSummary() (PPSKLifecycleSummary, error) {
	if DB == nil {
		return PPSKLifecycleSummary{}, nil
	}
	var summary PPSKLifecycleSummary
	err := DB.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN operation = 'preview' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'apply' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN operation = 'status' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'previewed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(created_at), '')
		FROM ppsk_lifecycle_events`).Scan(
		&summary.TotalEvents,
		&summary.PreviewEvents,
		&summary.ApplyEvents,
		&summary.StatusEvents,
		&summary.PreviewedCount,
		&summary.AppliedCount,
		&summary.BlockedCount,
		&summary.DegradedCount,
		&summary.SkippedCount,
		&summary.FailedCount,
		&summary.LastEventAt,
	)
	if err != nil {
		if tableMissing(err) {
			return PPSKLifecycleSummary{}, nil
		}
		return PPSKLifecycleSummary{}, fmt.Errorf("summarize PPSK lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, COALESCE(hostapd_config_sha256, ''), COALESCE(psk_file_sha256, ''),
			ppsk_ssid_count, profile_count, group_count, credential_count, active_credential_count,
			staged_credential_count, revoked_credential_count, expired_credential_count, controller_sync_count
		FROM ppsk_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastConfigSHA256,
		&summary.LastPSKFileSHA256,
		&summary.LastPPSKSSIDCount,
		&summary.LastProfileCount,
		&summary.LastGroupCount,
		&summary.LastCredentialCount,
		&summary.LastActiveCredentialCount,
		&summary.LastStagedCredentialCount,
		&summary.LastRevokedCredentialCount,
		&summary.LastExpiredCredentialCount,
		&summary.LastControllerSyncCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return PPSKLifecycleSummary{}, fmt.Errorf("read latest PPSK lifecycle event: %w", err)
	}
	return summary, nil
}

func scanPPSKLifecycleEvent(scanner interface{ Scan(dest ...any) error }) (PPSKLifecycleEvent, error) {
	var event PPSKLifecycleEvent
	var configPath, pskPath, hostapdSHA, pskSHA, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&configPath,
		&pskPath,
		&hostapdSHA,
		&pskSHA,
		&event.PlanFingerprint,
		&event.SSIDCount,
		&event.PPSKSSIDCount,
		&event.ProfileCount,
		&event.GroupCount,
		&event.CredentialCount,
		&event.ActiveCredentialCount,
		&event.StagedCredentialCount,
		&event.RevokedCredentialCount,
		&event.ExpiredCredentialCount,
		&event.ControllerSyncCount,
		&event.DiagnosticCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return PPSKLifecycleEvent{}, fmt.Errorf("scan PPSK lifecycle event: %w", err)
	}
	event.ConfigPath = configPath.String
	event.PSKFilePath = pskPath.String
	event.HostapdConfigSHA256 = hostapdSHA.String
	event.PSKFileSHA256 = pskSHA.String
	event.Actor = actor.String
	return event, nil
}

func ppskLifecycleSelectSQL() string {
	return `SELECT id, event_id, operation, status, COALESCE(config_path, ''), COALESCE(psk_file_path, ''),
		COALESCE(hostapd_config_sha256, ''), COALESCE(psk_file_sha256, ''), plan_fingerprint,
		ssid_count, ppsk_ssid_count, profile_count, group_count, credential_count,
		active_credential_count, staged_credential_count, revoked_credential_count, expired_credential_count,
		controller_sync_count, diagnostic_count, summary_json, report_json, COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM ppsk_lifecycle_events`
}

func normalizePPSKLifecycleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizePPSKLifecycleStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newPPSKLifecycleEventID(input PPSKLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "wifi-ppsk-" + hex.EncodeToString(sum[:8])
	}
	return "wifi-ppsk-" + hex.EncodeToString(random[:])
}
