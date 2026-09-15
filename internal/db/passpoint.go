package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

type PasspointLifecycleEventInput struct {
	EventID                   string
	Operation                 string
	Status                    string
	ConfigPath                string
	HostapdConfigSHA256       string
	PlanFingerprint           string
	SSIDCount                 int
	PasspointSSIDCount        int
	InterworkingSSIDCount     int
	HS20SSIDCount             int
	OSUProviderCount          int
	DomainNameCount           int
	RoamingConsortiumCount    int
	NAIRealmCount             int
	CellularNetworkCount      int
	ConnectionCapabilityCount int
	DiagnosticCount           int
	SummaryJSON               string
	ReportJSON                string
	Actor                     string
}

type PasspointLifecycleEvent struct {
	ID                        int    `json:"id"`
	EventID                   string `json:"event_id"`
	Operation                 string `json:"operation"`
	Status                    string `json:"status"`
	ConfigPath                string `json:"config_path,omitempty"`
	HostapdConfigSHA256       string `json:"hostapd_config_sha256,omitempty"`
	PlanFingerprint           string `json:"plan_fingerprint"`
	SSIDCount                 int    `json:"ssid_count"`
	PasspointSSIDCount        int    `json:"passpoint_ssid_count"`
	InterworkingSSIDCount     int    `json:"interworking_ssid_count"`
	HS20SSIDCount             int    `json:"hs20_ssid_count"`
	OSUProviderCount          int    `json:"osu_provider_count"`
	DomainNameCount           int    `json:"domain_name_count"`
	RoamingConsortiumCount    int    `json:"roaming_consortium_count"`
	NAIRealmCount             int    `json:"nai_realm_count"`
	CellularNetworkCount      int    `json:"cellular_network_count"`
	ConnectionCapabilityCount int    `json:"connection_capability_count"`
	DiagnosticCount           int    `json:"diagnostic_count"`
	SummaryJSON               string `json:"summary_json"`
	ReportJSON                string `json:"report_json,omitempty"`
	Actor                     string `json:"actor,omitempty"`
	CreatedAt                 string `json:"created_at"`
}

type PasspointLifecycleSummary struct {
	TotalEvents                   int    `json:"total_events"`
	PreviewEvents                 int    `json:"preview_events"`
	ApplyEvents                   int    `json:"apply_events"`
	StatusEvents                  int    `json:"status_events"`
	PreviewedCount                int    `json:"previewed_count"`
	AppliedCount                  int    `json:"applied_count"`
	BlockedCount                  int    `json:"blocked_count"`
	DegradedCount                 int    `json:"degraded_count"`
	SkippedCount                  int    `json:"skipped_count"`
	FailedCount                   int    `json:"failed_count"`
	LastEventAt                   string `json:"last_event_at,omitempty"`
	LastFingerprint               string `json:"last_fingerprint,omitempty"`
	LastConfigSHA256              string `json:"last_hostapd_config_sha256,omitempty"`
	LastPasspointSSIDCount        int    `json:"last_passpoint_ssid_count"`
	LastInterworkingSSIDCount     int    `json:"last_interworking_ssid_count"`
	LastHS20SSIDCount             int    `json:"last_hs20_ssid_count"`
	LastOSUProviderCount          int    `json:"last_osu_provider_count"`
	LastDomainNameCount           int    `json:"last_domain_name_count"`
	LastRoamingConsortiumCount    int    `json:"last_roaming_consortium_count"`
	LastNAIRealmCount             int    `json:"last_nai_realm_count"`
	LastCellularNetworkCount      int    `json:"last_cellular_network_count"`
	LastConnectionCapabilityCount int    `json:"last_connection_capability_count"`
}

func RecordPasspointLifecycleEvent(input PasspointLifecycleEventInput) (string, error) {
	if DB == nil {
		return "", nil
	}
	input.Operation = normalizePasspointLifecycleOperation(input.Operation)
	input.Status = normalizePasspointLifecycleStatus(input.Status)
	input.EventID = strings.TrimSpace(input.EventID)
	if input.EventID == "" {
		input.EventID = newPasspointLifecycleEventID(input)
	}
	if input.Operation == "" || input.Status == "" {
		return "", fmt.Errorf("Passpoint lifecycle operation and status are required")
	}
	if strings.TrimSpace(input.PlanFingerprint) == "" {
		return "", fmt.Errorf("Passpoint lifecycle plan fingerprint is required")
	}
	if strings.TrimSpace(input.SummaryJSON) == "" {
		input.SummaryJSON = "{}"
	}
	if strings.TrimSpace(input.ReportJSON) == "" {
		input.ReportJSON = "{}"
	}

	_, err := DB.Exec(`INSERT INTO passpoint_lifecycle_events (
			event_id, operation, status, config_path, hostapd_config_sha256, plan_fingerprint,
			ssid_count, passpoint_ssid_count, interworking_ssid_count, hs20_ssid_count,
			osu_provider_count, domain_name_count, roaming_consortium_count, nai_realm_count,
			cellular_network_count, connection_capability_count, diagnostic_count,
			summary_json, report_json, actor, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(event_id) DO UPDATE SET
			operation = excluded.operation,
			status = excluded.status,
			config_path = excluded.config_path,
			hostapd_config_sha256 = excluded.hostapd_config_sha256,
			plan_fingerprint = excluded.plan_fingerprint,
			ssid_count = excluded.ssid_count,
			passpoint_ssid_count = excluded.passpoint_ssid_count,
			interworking_ssid_count = excluded.interworking_ssid_count,
			hs20_ssid_count = excluded.hs20_ssid_count,
			osu_provider_count = excluded.osu_provider_count,
			domain_name_count = excluded.domain_name_count,
			roaming_consortium_count = excluded.roaming_consortium_count,
			nai_realm_count = excluded.nai_realm_count,
			cellular_network_count = excluded.cellular_network_count,
			connection_capability_count = excluded.connection_capability_count,
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
		nonNegativeInt(input.PasspointSSIDCount),
		nonNegativeInt(input.InterworkingSSIDCount),
		nonNegativeInt(input.HS20SSIDCount),
		nonNegativeInt(input.OSUProviderCount),
		nonNegativeInt(input.DomainNameCount),
		nonNegativeInt(input.RoamingConsortiumCount),
		nonNegativeInt(input.NAIRealmCount),
		nonNegativeInt(input.CellularNetworkCount),
		nonNegativeInt(input.ConnectionCapabilityCount),
		nonNegativeInt(input.DiagnosticCount),
		input.SummaryJSON,
		input.ReportJSON,
		nullString(strings.TrimSpace(input.Actor)),
	)
	if err != nil {
		return "", fmt.Errorf("record Passpoint lifecycle event: %w", err)
	}
	return input.EventID, nil
}

func ListPasspointLifecycleEvents(limit int) ([]PasspointLifecycleEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := DB.Query(passpointLifecycleSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list Passpoint lifecycle events: %w", err)
	}
	defer rows.Close()
	events := []PasspointLifecycleEvent{}
	for rows.Next() {
		event, scanErr := scanPasspointLifecycleEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list Passpoint lifecycle rows: %w", err)
	}
	return events, nil
}

func GetPasspointLifecycleSummary() (PasspointLifecycleSummary, error) {
	if DB == nil {
		return PasspointLifecycleSummary{}, nil
	}
	var summary PasspointLifecycleSummary
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
		FROM passpoint_lifecycle_events`).Scan(
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
			return PasspointLifecycleSummary{}, nil
		}
		return PasspointLifecycleSummary{}, fmt.Errorf("summarize Passpoint lifecycle events: %w", err)
	}
	row := DB.QueryRow(`SELECT plan_fingerprint, COALESCE(hostapd_config_sha256, ''), passpoint_ssid_count,
			interworking_ssid_count, hs20_ssid_count, osu_provider_count, domain_name_count,
			roaming_consortium_count, nai_realm_count, cellular_network_count, connection_capability_count
		FROM passpoint_lifecycle_events
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`)
	err = row.Scan(
		&summary.LastFingerprint,
		&summary.LastConfigSHA256,
		&summary.LastPasspointSSIDCount,
		&summary.LastInterworkingSSIDCount,
		&summary.LastHS20SSIDCount,
		&summary.LastOSUProviderCount,
		&summary.LastDomainNameCount,
		&summary.LastRoamingConsortiumCount,
		&summary.LastNAIRealmCount,
		&summary.LastCellularNetworkCount,
		&summary.LastConnectionCapabilityCount,
	)
	if err != nil && err != sql.ErrNoRows {
		return PasspointLifecycleSummary{}, fmt.Errorf("read latest Passpoint lifecycle event: %w", err)
	}
	return summary, nil
}

func scanPasspointLifecycleEvent(scanner interface {
	Scan(dest ...any) error
}) (PasspointLifecycleEvent, error) {
	var event PasspointLifecycleEvent
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
		&event.PasspointSSIDCount,
		&event.InterworkingSSIDCount,
		&event.HS20SSIDCount,
		&event.OSUProviderCount,
		&event.DomainNameCount,
		&event.RoamingConsortiumCount,
		&event.NAIRealmCount,
		&event.CellularNetworkCount,
		&event.ConnectionCapabilityCount,
		&event.DiagnosticCount,
		&event.SummaryJSON,
		&event.ReportJSON,
		&actor,
		&event.CreatedAt,
	)
	if err != nil {
		return PasspointLifecycleEvent{}, fmt.Errorf("scan Passpoint lifecycle event: %w", err)
	}
	event.ConfigPath = configPath.String
	event.HostapdConfigSHA256 = hostapdSHA.String
	event.Actor = actor.String
	return event, nil
}

func passpointLifecycleSelectSQL() string {
	return `SELECT id, event_id, operation, status, COALESCE(config_path, ''),
		COALESCE(hostapd_config_sha256, ''), plan_fingerprint, ssid_count,
		passpoint_ssid_count, interworking_ssid_count, hs20_ssid_count,
		osu_provider_count, domain_name_count, roaming_consortium_count,
		nai_realm_count, cellular_network_count, connection_capability_count,
		diagnostic_count, summary_json, report_json, COALESCE(actor, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM passpoint_lifecycle_events`
}

func normalizePasspointLifecycleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "status":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizePasspointLifecycleStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "previewed", "applied", "blocked", "degraded", "skipped", "failed":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "blocked"
	}
}

func newPasspointLifecycleEventID(input PasspointLifecycleEventInput) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		sum := sha256.Sum256([]byte(strings.Join([]string{input.Operation, input.Status, input.PlanFingerprint}, "\x00")))
		return "wifi-passpoint-" + hex.EncodeToString(sum[:8])
	}
	return "wifi-passpoint-" + hex.EncodeToString(random[:])
}
