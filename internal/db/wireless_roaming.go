package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type WirelessRoamingLifecycleEventInput struct {
	EventID             string
	Operation           string
	Status              string
	ConfigPath          string
	HostapdConfigSHA256 string
	PlanFingerprint     string
	SSIDCount           int
	RoamingSSIDCount    int
	FTSSIDCount         int
	KSSIDCount          int
	VSSIDCount          int
	ProfileCount        int
	NeighborCount       int
	KeyRefCount         int
	StagedKeyRefCount   int
	DiagnosticCount     int
	SummaryJSON         string
	ReportJSON          string
	Actor               string
}

type WirelessRoamingLifecycleEvent struct {
	ID                  int    `json:"id"`
	EventID             string `json:"event_id"`
	Operation           string `json:"operation"`
	Status              string `json:"status"`
	ConfigPath          string `json:"config_path,omitempty"`
	HostapdConfigSHA256 string `json:"hostapd_config_sha256,omitempty"`
	PlanFingerprint     string `json:"plan_fingerprint"`
	SSIDCount           int    `json:"ssid_count"`
	RoamingSSIDCount    int    `json:"roaming_ssid_count"`
	FTSSIDCount         int    `json:"ft_ssid_count"`
	KSSIDCount          int    `json:"k_ssid_count"`
	VSSIDCount          int    `json:"v_ssid_count"`
	ProfileCount        int    `json:"profile_count"`
	NeighborCount       int    `json:"neighbor_count"`
	KeyRefCount         int    `json:"key_ref_count"`
	StagedKeyRefCount   int    `json:"staged_key_ref_count"`
	DiagnosticCount     int    `json:"diagnostic_count"`
	SummaryJSON         string `json:"summary_json"`
	ReportJSON          string `json:"report_json,omitempty"`
	Actor               string `json:"actor,omitempty"`
	CreatedAt           string `json:"created_at"`
}

type WirelessRoamingLifecycleSummary struct {
	TotalEvents          int    `json:"total_events"`
	PreviewEvents        int    `json:"preview_events"`
	ApplyEvents          int    `json:"apply_events"`
	StatusEvents         int    `json:"status_events"`
	PreviewedCount       int    `json:"previewed_count"`
	AppliedCount         int    `json:"applied_count"`
	BlockedCount         int    `json:"blocked_count"`
	DegradedCount        int    `json:"degraded_count"`
	SkippedCount         int    `json:"skipped_count"`
	FailedCount          int    `json:"failed_count"`
	LastEventAt          string `json:"last_event_at,omitempty"`
	LastFingerprint      string `json:"last_fingerprint,omitempty"`
	LastConfigSHA256     string `json:"last_hostapd_config_sha256,omitempty"`
	LastRoamingSSIDCount int    `json:"last_roaming_ssid_count"`
	LastFTSSIDCount      int    `json:"last_ft_ssid_count"`
	LastKSSIDCount       int    `json:"last_k_ssid_count"`
	LastVSSIDCount       int    `json:"last_v_ssid_count"`
	LastNeighborCount    int    `json:"last_neighbor_count"`
}

func RecordWirelessRoamingLifecycleEvent(input WirelessRoamingLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizeWirelessRoamingOperation(input.Operation)
	input.Status = normalizeWirelessRoamingStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newWirelessRoamingEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("wireless roaming lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("wireless roaming lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO wireless_roaming_lifecycle_events (
			event_id, operation, status, config_path, hostapd_config_sha256, plan_fingerprint,
			ssid_count, roaming_ssid_count, ft_ssid_count, k_ssid_count, v_ssid_count,
			profile_count, neighbor_count, key_ref_count, staged_key_ref_count, diagnostic_count,
			summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			config_path = excluded.config_path,
			hostapd_config_sha256 = excluded.hostapd_config_sha256,
			plan_fingerprint = excluded.plan_fingerprint,
			ssid_count = excluded.ssid_count,
			roaming_ssid_count = excluded.roaming_ssid_count,
			ft_ssid_count = excluded.ft_ssid_count,
			k_ssid_count = excluded.k_ssid_count,
			v_ssid_count = excluded.v_ssid_count,
			profile_count = excluded.profile_count,
			neighbor_count = excluded.neighbor_count,
			key_ref_count = excluded.key_ref_count,
			staged_key_ref_count = excluded.staged_key_ref_count,
			diagnostic_count = excluded.diagnostic_count,
			summary_json = excluded.summary_json,
			report_json = excluded.report_json,
			actor = excluded.actor`,
		input.EventID,
		input.Operation,
		input.Status,
		nullString(strings.TrimSpace(input.ConfigPath)),
		nullString(strings.TrimSpace(input.HostapdConfigSHA256)),
		strings.TrimSpace(input.PlanFingerprint),
		nonNegativeInt(input.SSIDCount),
		nonNegativeInt(input.RoamingSSIDCount),
		nonNegativeInt(input.FTSSIDCount),
		nonNegativeInt(input.KSSIDCount),
		nonNegativeInt(input.VSSIDCount),
		nonNegativeInt(input.ProfileCount),
		nonNegativeInt(input.NeighborCount),
		nonNegativeInt(input.KeyRefCount),
		nonNegativeInt(input.StagedKeyRefCount),
		nonNegativeInt(input.DiagnosticCount),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record wireless roaming lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListWirelessRoamingLifecycleEvents(limit int) ([]WirelessRoamingLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(wirelessRoamingSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list wireless roaming lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []WirelessRoamingLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanWirelessRoamingLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list wireless roaming lifecycle rows: %w", err)
	}
	return events, nil
}

func GetWirelessRoamingLifecycleSummary() (WirelessRoamingLifecycleSummary, error) {
	if DB == nil {
		return WirelessRoamingLifecycleSummary{}, nil
	}
	var summary WirelessRoamingLifecycleSummary
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
		FROM wireless_roaming_lifecycle_events`).Scan(
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
			return WirelessRoamingLifecycleSummary{}, nil
		}
		return WirelessRoamingLifecycleSummary{}, fmt.Errorf("summarize wireless roaming lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, COALESCE(hostapd_config_sha256, ''), roaming_ssid_count,
			ft_ssid_count, k_ssid_count, v_ssid_count, neighbor_count
		FROM wireless_roaming_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastConfigSHA256,
		&summary.LastRoamingSSIDCount,
		&summary.LastFTSSIDCount,
		&summary.LastKSSIDCount,
		&summary.LastVSSIDCount,
		&summary.LastNeighborCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return WirelessRoamingLifecycleSummary{}, fmt.Errorf("read latest wireless roaming lifecycle event: %w", err)
	}
	return summary, nil
}

func scanWirelessRoamingLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (WirelessRoamingLifecycleEvent, error) {
	var event WirelessRoamingLifecycleEvent
	var configPath, hostapdSHA, actor sql.NullString
	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&event.Operation,
		&event.Status,
		&configPath,
		&hostapdSHA,
		&event.PlanFingerprint,
		&event.SSIDCount,
		&event.RoamingSSIDCount,
		&event.FTSSIDCount,
		&event.KSSIDCount,
		&event.VSSIDCount,
		&event.ProfileCount,
		&event.NeighborCount,
		&event.KeyRefCount,
		&event.StagedKeyRefCount,
		&event.DiagnosticCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return WirelessRoamingLifecycleEvent{}, fmt.Errorf("scan wireless roaming lifecycle event: %w", err)
	}
	event.ConfigPath = configPath.String
	event.HostapdConfigSHA256 = hostapdSHA.String
	event.Actor = actor.String
	return event, nil
}

func wirelessRoamingSelectSQL() string {
	return `SELECT id, event_id, operation, status, COALESCE(config_path, ''),
		COALESCE(hostapd_config_sha256, ''), plan_fingerprint, ssid_count,
		roaming_ssid_count, ft_ssid_count, k_ssid_count, v_ssid_count,
		profile_count, neighbor_count, key_ref_count, staged_key_ref_count,
		diagnostic_count, summary_json, report_json, COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM wireless_roaming_lifecycle_events`
}

func normalizeWirelessRoamingOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeWirelessRoamingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newWirelessRoamingEventID(input WirelessRoamingLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "wifi-roam-" + hex.EncodeToString(sum[:8])
	}
	return "wifi-roam-" + hex.EncodeToString(random[:])
}
