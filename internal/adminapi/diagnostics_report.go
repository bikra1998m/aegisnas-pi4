package adminapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

type DiagnosticsReport struct {
	GeneratedAt       string                  `json:"generated_at"`
	ConfigPath        string                  `json:"config_path"`
	DatabasePath      string                  `json:"database_path"`
	SchemaVersion     int                     `json:"schema_version"`
	DeploymentProfile string                  `json:"deployment_profile,omitempty"`
	DeploymentForm    string                  `json:"deployment_form,omitempty"`
	HARole            string                  `json:"ha_role,omitempty"`
	Summary           DiagnosticsSummary      `json:"summary"`
	Audit             db.AuditHistoryStats    `json:"audit"`
	Network           DiagnosticsNetwork      `json:"network"`
	HighAvailability  DiagnosticsHA           `json:"high_availability"`
	Upgrade           upgrade.ReadinessReport `json:"upgrade"`
	Integrations      DiagnosticsIntegrations `json:"integrations"`
	RuntimeStatuses   []db.RuntimeStatus      `json:"runtime_statuses"`
}

type DiagnosticsSummary struct {
	Users                int            `json:"users"`
	ActiveSessions       int            `json:"active_sessions"`
	QuarantinedSessions  int            `json:"quarantined_sessions"`
	ShapedSessions       int            `json:"shaped_sessions"`
	UnacknowledgedAlerts int            `json:"unacknowledged_alerts"`
	SessionMethods       map[string]int `json:"session_methods,omitempty"`
}

type DiagnosticsNetwork struct {
	ApplyStats    db.NetworkApplyStats     `json:"apply_stats"`
	LeaseTrends   db.DHCPLeaseTrendSummary `json:"lease_trends"`
	RecoveryState *NetworkRecoveryState    `json:"recovery_state,omitempty"`
}

type DiagnosticsHA struct {
	Enabled bool              `json:"enabled"`
	Role    string            `json:"role,omitempty"`
	Stats   db.HAHistoryStats `json:"stats"`
	Runtime *db.RuntimeStatus `json:"runtime,omitempty"`
}

type DiagnosticsIntegrations struct {
	Controller            *db.RuntimeStatus             `json:"controller,omitempty"`
	SIEM                  *db.RuntimeStatus             `json:"siem,omitempty"`
	AdminSSO              *db.RuntimeStatus             `json:"admin_sso,omitempty"`
	DeviceInventory       *db.RuntimeStatus             `json:"device_inventory,omitempty"`
	MDMSync               *db.RuntimeStatus             `json:"mdm_sync,omitempty"`
	PostureChecks         *db.RuntimeStatus             `json:"posture_checks,omitempty"`
	HistoryStats          *db.IntegrationHistoryStats   `json:"history_stats,omitempty"`
	UpstreamAAA           []radius.UpstreamServerHealth `json:"upstream_aaa,omitempty"`
	UpstreamAAAProbeError string                        `json:"upstream_aaa_probe_error,omitempty"`
}

var assessDiagnosticsUpgradeReadinessFn = upgrade.AssessReadiness
var probeDiagnosticsUpstreamServersFn = radius.ProbeUpstreamServers

func HandleGetDiagnosticsReport(w http.ResponseWriter, r *http.Request) {
	report, err := buildDiagnosticsReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func HandleExportDiagnosticsReport(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		http.Error(w, "unsupported format", http.StatusBadRequest)
		return
	}

	report, err := buildDiagnosticsReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		filename := fmt.Sprintf("aegisnas-diagnostics-report-%s.json", time.Now().UTC().Format("20060102-150405Z"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		writeJSON(w, http.StatusOK, report)
		audit(r, "download_diagnostics_report", filename, "downloaded")
	case "csv":
		payload, err := diagnosticsReportCSV(report)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := fmt.Sprintf("aegisnas-diagnostics-report-%s.csv", time.Now().UTC().Format("20060102-150405Z"))
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		audit(r, "download_diagnostics_report", filename, "downloaded")
	}
}

func buildDiagnosticsReport(ctx context.Context) (DiagnosticsReport, error) {
	cfg := config.Get()
	if cfg == nil {
		return DiagnosticsReport{}, fmt.Errorf("configuration not loaded")
	}

	runtimeStatuses, err := db.GetRuntimeStatuses()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load runtime statuses: %w", err)
	}
	runtimeMap := make(map[string]db.RuntimeStatus, len(runtimeStatuses))
	for _, item := range runtimeStatuses {
		runtimeMap[item.Component] = item
	}

	schemaVersion, err := currentSchemaVersion()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load schema version: %w", err)
	}
	applyStats, err := db.GetNetworkApplyStats()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load network apply stats: %w", err)
	}
	leaseTrends, err := db.GetDHCPLeaseTrendSummary(24 * time.Hour)
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load dhcp lease trends: %w", err)
	}
	haStats, err := db.GetHAHistoryStats()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load ha stats: %w", err)
	}
	integrationHistoryStats, err := db.GetIntegrationHistoryStats()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load integration history stats: %w", err)
	}
	recoveryState, err := CurrentNetworkRecoveryState()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load network recovery state: %w", err)
	}
	auditStats, err := db.GetAuditHistoryStats()
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load audit stats: %w", err)
	}
	readiness, err := assessDiagnosticsUpgradeReadinessFn(cfg, config.Path())
	if err != nil {
		return DiagnosticsReport{}, fmt.Errorf("load upgrade readiness: %w", err)
	}

	users, _ := enforcement.CountUsers()
	activeSessions, _ := enforcement.CountActiveSessions()
	quarantinedSessions, _ := enforcement.CountQuarantinedSessions()
	unackedAlerts, _ := enforcement.CountUnacknowledgedAlerts()
	authMethods, _ := enforcement.CountSessionsByAuthMethod()
	shapedSessions := 0
	if enforcement.RuntimeShapingEnabled(cfg) {
		shapedSessions, _ = enforcement.CountShapedSessions()
	}

	upstreamStatuses, probeErr := probeDiagnosticsUpstreamServersFn(ctx, cfg)
	integrations := DiagnosticsIntegrations{
		Controller:      runtimeStatusPointer(runtimeMap, "controller_automation"),
		SIEM:            runtimeStatusPointer(runtimeMap, "siem_export"),
		AdminSSO:        runtimeStatusPointer(runtimeMap, "admin_sso"),
		DeviceInventory: runtimeStatusPointer(runtimeMap, "device_inventory"),
		MDMSync:         runtimeStatusPointer(runtimeMap, "mdm_sync"),
		PostureChecks:   runtimeStatusPointer(runtimeMap, "posture_checks"),
		HistoryStats:    &integrationHistoryStats,
		UpstreamAAA:     upstreamStatuses,
	}
	if probeErr != nil {
		integrations.UpstreamAAAProbeError = probeErr.Error()
	}

	return DiagnosticsReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		ConfigPath:        config.Path(),
		DatabasePath:      cfg.Database.Path,
		SchemaVersion:     schemaVersion,
		DeploymentProfile: cfg.Deployment.Profile,
		DeploymentForm:    cfg.Deployment.Form,
		HARole:            cfg.HighAvailability.Role,
		Summary: DiagnosticsSummary{
			Users:                users,
			ActiveSessions:       activeSessions,
			QuarantinedSessions:  quarantinedSessions,
			ShapedSessions:       shapedSessions,
			UnacknowledgedAlerts: unackedAlerts,
			SessionMethods:       authMethods,
		},
		Audit: auditStats,
		Network: DiagnosticsNetwork{
			ApplyStats:    applyStats,
			LeaseTrends:   leaseTrends,
			RecoveryState: recoveryState,
		},
		HighAvailability: DiagnosticsHA{
			Enabled: cfg.HighAvailability.Enabled,
			Role:    cfg.HighAvailability.Role,
			Stats:   haStats,
			Runtime: runtimeStatusPointer(runtimeMap, "ha_runtime"),
		},
		Upgrade:         readiness,
		Integrations:    integrations,
		RuntimeStatuses: runtimeStatuses,
	}, nil
}

func runtimeStatusPointer(statuses map[string]db.RuntimeStatus, key string) *db.RuntimeStatus {
	if statuses == nil {
		return nil
	}
	value, ok := statuses[strings.TrimSpace(key)]
	if !ok {
		return nil
	}
	copy := value
	return &copy
}

func diagnosticsReportCSV(report DiagnosticsReport) ([]byte, error) {
	buffer := &bytes.Buffer{}
	writer := csv.NewWriter(buffer)
	rows := [][]string{
		{"generated_at", report.GeneratedAt},
		{"config_path", report.ConfigPath},
		{"database_path", report.DatabasePath},
		{"schema_version", strconv.Itoa(report.SchemaVersion)},
		{"deployment_profile", report.DeploymentProfile},
		{"deployment_form", report.DeploymentForm},
		{"ha_role", report.HARole},
		{"users", strconv.Itoa(report.Summary.Users)},
		{"active_sessions", strconv.Itoa(report.Summary.ActiveSessions)},
		{"quarantined_sessions", strconv.Itoa(report.Summary.QuarantinedSessions)},
		{"shaped_sessions", strconv.Itoa(report.Summary.ShapedSessions)},
		{"unacknowledged_alerts", strconv.Itoa(report.Summary.UnacknowledgedAlerts)},
		{"audit_total_records", strconv.Itoa(report.Audit.TotalRecords)},
		{"audit_unique_users", strconv.Itoa(report.Audit.UniqueUsers)},
		{"audit_export_actions", strconv.Itoa(report.Audit.ExportActionCount)},
		{"audit_network_actions", strconv.Itoa(report.Audit.NetworkActionCount)},
		{"audit_ha_actions", strconv.Itoa(report.Audit.HAActionCount)},
		{"audit_upgrade_actions", strconv.Itoa(report.Audit.UpgradeActionCount)},
		{"network_total_records", strconv.Itoa(report.Network.ApplyStats.TotalRecords)},
		{"network_apply_success_count", strconv.Itoa(report.Network.ApplyStats.ApplySuccessCount)},
		{"network_apply_failure_count", strconv.Itoa(report.Network.ApplyStats.ApplyFailureCount)},
		{"network_rollback_count", strconv.Itoa(report.Network.ApplyStats.RollbackCount)},
		{"network_auto_rollback_count", strconv.Itoa(report.Network.ApplyStats.AutoRollbackCount)},
		{"lease_total_records", strconv.Itoa(report.Network.LeaseTrends.TotalRecords)},
		{"lease_unique_macs_window", strconv.Itoa(report.Network.LeaseTrends.UniqueMACsWindow)},
		{"lease_peak_concurrent_window", strconv.Itoa(report.Network.LeaseTrends.PeakConcurrentLeasesWindow)},
		{"ha_total_records", strconv.Itoa(report.HighAvailability.Stats.TotalRecords)},
		{"ha_failover_promotions", strconv.Itoa(report.HighAvailability.Stats.FailoverPromotions)},
		{"ha_replication_failures", strconv.Itoa(report.HighAvailability.Stats.ReplicationFailures)},
		{"integration_history_total_records", strconv.Itoa(report.Integrations.HistoryStats.TotalRecords)},
		{"integration_history_controller_events", strconv.Itoa(report.Integrations.HistoryStats.ControllerEventCount)},
		{"integration_history_controller_failures", strconv.Itoa(report.Integrations.HistoryStats.ControllerFailureCount)},
		{"integration_history_mdm_events", strconv.Itoa(report.Integrations.HistoryStats.MDMSyncEventCount)},
		{"integration_history_mdm_failures", strconv.Itoa(report.Integrations.HistoryStats.MDMSyncFailureCount)},
		{"integration_history_posture_events", strconv.Itoa(report.Integrations.HistoryStats.PostureEventCount)},
		{"integration_history_posture_failures", strconv.Itoa(report.Integrations.HistoryStats.PostureFailureCount)},
		{"upgrade_current_schema", strconv.Itoa(report.Upgrade.CurrentSchemaVersion)},
		{"upgrade_target_schema", strconv.Itoa(report.Upgrade.TargetSchemaVersion)},
		{"upgrade_config_valid", strconv.FormatBool(report.Upgrade.ConfigValid)},
		{"upgrade_rehearsal_ran", strconv.FormatBool(report.Upgrade.Rehearsal.Ran)},
		{"upgrade_rehearsal_succeeded", strconv.FormatBool(report.Upgrade.Rehearsal.Succeeded)},
	}

	methods := make([]string, 0, len(report.Summary.SessionMethods))
	for method := range report.Summary.SessionMethods {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	for _, method := range methods {
		count := report.Summary.SessionMethods[method]
		rows = append(rows, []string{"session_method_" + method, strconv.Itoa(count)})
	}

	for _, status := range report.RuntimeStatuses {
		rows = append(rows, []string{"runtime_" + status.Component, status.Status})
	}
	if report.Integrations.UpstreamAAAProbeError != "" {
		rows = append(rows, []string{"upstream_aaa_probe_error", report.Integrations.UpstreamAAAProbeError})
	}

	upstreamRows := make([][]string, 0, len(report.Integrations.UpstreamAAA))
	for _, status := range report.Integrations.UpstreamAAA {
		serverKey := strings.TrimSpace(status.Name)
		if serverKey == "" {
			serverKey = strings.TrimSpace(status.Address)
		}
		if serverKey == "" {
			serverKey = "server"
		}
		serverKey = strings.NewReplacer(" ", "_", ":", "_", "/", "_", ".", "_", "-", "_").Replace(serverKey)
		upstreamRows = append(upstreamRows, []string{"upstream_aaa_" + serverKey, status.Status})
	}
	sort.Slice(upstreamRows, func(i, j int) bool {
		return upstreamRows[i][0] < upstreamRows[j][0]
	})
	rows = append(rows, upstreamRows...)

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
