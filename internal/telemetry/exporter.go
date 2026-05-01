package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const (
	siemExportComponent = "siem_export"
	defaultSIEMInterval = 30 * time.Second
	defaultSIEMTimeout  = 15 * time.Second
	defaultSIEMBatch    = 100
)

type SIEMExporter struct {
	cfg      *config.Config
	logger   *zap.Logger
	client   *http.Client
	now      func() time.Time
	hostname string
}

type siemCursor struct {
	LastAuditID    int64
	LastAlertID    int64
	LastExportedAt string
}

type siemAuditEvent struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Details   string `json:"details"`
	Result    string `json:"result"`
	IPAddress string `json:"ip_address"`
}

type siemAlertEvent struct {
	ID           int64  `json:"id"`
	Severity     string `json:"severity"`
	Source       string `json:"source"`
	Message      string `json:"message"`
	Details      string `json:"details"`
	Acknowledged bool   `json:"acknowledged"`
	CreatedAt    string `json:"created_at"`
}

type responseValidator func(*http.Response, []byte) error

func StartSIEMExporter(ctx context.Context, interval time.Duration, cfg *config.Config, logger *zap.Logger) {
	NewSIEMExporter(cfg, logger, nil).Run(ctx, interval)
}

func NewSIEMExporter(cfg *config.Config, logger *zap.Logger, client *http.Client) *SIEMExporter {
	if logger == nil {
		logger = zap.NewNop()
	}
	if client == nil {
		client = &http.Client{Timeout: defaultSIEMTimeout}
	}
	hostname, _ := os.Hostname()
	return &SIEMExporter{
		cfg:      cfg,
		logger:   logger,
		client:   client,
		now:      time.Now,
		hostname: hostname,
	}
}

func (e *SIEMExporter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultSIEMInterval
	}
	e.runOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runOnce(ctx)
		}
	}
}

func (e *SIEMExporter) runOnce(ctx context.Context) {
	if e == nil || e.cfg == nil {
		return
	}
	if !e.cfg.Integrations.SIEM.Enabled {
		_ = db.UpsertRuntimeStatus(siemExportComponent, "disabled", "SIEM export is disabled in config", map[string]any{
			"provider":   strings.TrimSpace(e.cfg.Integrations.SIEM.Provider),
			"endpoint":   strings.TrimSpace(e.cfg.Integrations.SIEM.Endpoint),
			"batch_size": effectiveSIEMBatchSize(e.cfg),
		})
		return
	}

	token, err := e.apiKey()
	if err != nil {
		e.markDegraded(err.Error(), siemCursor{}, 0, 0)
		return
	}

	cursor, err := e.loadCursor()
	if err != nil {
		e.markDegraded(fmt.Sprintf("load cursor: %v", err), siemCursor{}, 0, 0)
		return
	}

	batchSize := effectiveSIEMBatchSize(e.cfg)
	audits, err := loadAuditBatch(cursor.LastAuditID, batchSize)
	if err != nil {
		e.markDegraded(fmt.Sprintf("load audit batch: %v", err), cursor, 0, 0)
		return
	}
	alerts, err := loadAlertBatch(cursor.LastAlertID, batchSize)
	if err != nil {
		e.markDegraded(fmt.Sprintf("load alert batch: %v", err), cursor, len(audits), 0)
		return
	}

	if len(audits) == 0 && len(alerts) == 0 {
		_ = db.UpsertRuntimeStatus(siemExportComponent, "ok", "SIEM export is idle; no new events are pending.", e.statusDetails(cursor, 0, 0))
		return
	}

	req, validate, err := e.buildRequest(ctx, token, audits, alerts)
	if err != nil {
		e.markDegraded(fmt.Sprintf("build export request: %v", err), cursor, len(audits), len(alerts))
		return
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.markDegraded(fmt.Sprintf("send export request: %v", err), cursor, len(audits), len(alerts))
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		e.markDegraded(fmt.Sprintf("read export response: %v", err), cursor, len(audits), len(alerts))
		return
	}
	if err := validate(resp, body); err != nil {
		e.markDegraded(err.Error(), cursor, len(audits), len(alerts))
		return
	}

	cursor.LastAuditID = maxAuditID(audits, cursor.LastAuditID)
	cursor.LastAlertID = maxAlertID(alerts, cursor.LastAlertID)
	cursor.LastExportedAt = e.now().UTC().Format(time.RFC3339)

	message := fmt.Sprintf("Exported %d audit logs and %d alerts to %s.", len(audits), len(alerts), strings.TrimSpace(e.cfg.Integrations.SIEM.Provider))
	if err := db.UpsertRuntimeStatus(siemExportComponent, "ok", message, e.statusDetails(cursor, len(audits), len(alerts))); err != nil {
		e.logger.Warn("failed to persist SIEM runtime status", zap.Error(err))
	}
	e.logger.Info("siem export completed",
		zap.String("provider", strings.TrimSpace(e.cfg.Integrations.SIEM.Provider)),
		zap.Int("audit_logs", len(audits)),
		zap.Int("alerts", len(alerts)),
		zap.Int64("last_audit_id", cursor.LastAuditID),
		zap.Int64("last_alert_id", cursor.LastAlertID),
	)
}

func (e *SIEMExporter) apiKey() (string, error) {
	envName := strings.TrimSpace(e.cfg.Integrations.SIEM.APIKeyEnv)
	if envName == "" {
		return "", fmt.Errorf("SIEM API key environment variable is not configured")
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return "", fmt.Errorf("SIEM API key environment variable %s is empty", envName)
	}
	return value, nil
}

func (e *SIEMExporter) loadCursor() (siemCursor, error) {
	status, err := db.GetRuntimeStatus(siemExportComponent)
	if err != nil || status == nil {
		return siemCursor{}, err
	}
	cursor := siemCursor{
		LastAuditID: detailInt64(status.Details, "last_audit_id"),
		LastAlertID: detailInt64(status.Details, "last_alert_id"),
	}
	if lastExportedAt, ok := detailString(status.Details, "last_exported_at"); ok {
		cursor.LastExportedAt = lastExportedAt
	}
	return cursor, nil
}

func (e *SIEMExporter) statusDetails(cursor siemCursor, auditCount, alertCount int) map[string]any {
	return map[string]any{
		"provider":         strings.TrimSpace(e.cfg.Integrations.SIEM.Provider),
		"endpoint":         strings.TrimSpace(e.cfg.Integrations.SIEM.Endpoint),
		"batch_size":       effectiveSIEMBatchSize(e.cfg),
		"last_audit_id":    cursor.LastAuditID,
		"last_alert_id":    cursor.LastAlertID,
		"last_exported_at": cursor.LastExportedAt,
		"exported_audits":  auditCount,
		"exported_alerts":  alertCount,
		"hostname":         e.hostname,
	}
}

func (e *SIEMExporter) markDegraded(message string, cursor siemCursor, auditCount, alertCount int) {
	if err := db.UpsertRuntimeStatus(siemExportComponent, "degraded", message, e.statusDetails(cursor, auditCount, alertCount)); err != nil {
		e.logger.Warn("failed to persist SIEM degraded status", zap.Error(err))
	}
	e.logger.Warn("siem export failed", zap.String("message", message))
}

func (e *SIEMExporter) buildRequest(ctx context.Context, token string, audits []siemAuditEvent, alerts []siemAlertEvent) (*http.Request, responseValidator, error) {
	provider := strings.TrimSpace(strings.ToLower(e.cfg.Integrations.SIEM.Provider))
	switch provider {
	case "webhook":
		return e.buildWebhookRequest(ctx, token, audits, alerts)
	case "splunk-hec":
		return e.buildSplunkRequest(ctx, token, audits, alerts)
	case "elastic":
		return e.buildElasticRequest(ctx, token, audits, alerts)
	default:
		return nil, nil, fmt.Errorf("unsupported SIEM provider %q", e.cfg.Integrations.SIEM.Provider)
	}
}

func (e *SIEMExporter) buildWebhookRequest(ctx context.Context, token string, audits []siemAuditEvent, alerts []siemAlertEvent) (*http.Request, responseValidator, error) {
	payload := map[string]any{
		"product":     "AegisNAS",
		"provider":    "webhook",
		"hostname":    e.hostname,
		"exported_at": e.now().UTC().Format(time.RFC3339),
		"counts": map[string]int{
			"audit_logs": len(audits),
			"alerts":     len(alerts),
		},
		"audit_logs": audits,
		"alerts":     alerts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(e.cfg.Integrations.SIEM.Endpoint), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-Key", token)
	req.Header.Set("User-Agent", "AegisNAS-SIEM-Exporter/1.0")
	return req, validateDefaultResponse, nil
}

func (e *SIEMExporter) buildSplunkRequest(ctx context.Context, token string, audits []siemAuditEvent, alerts []siemAlertEvent) (*http.Request, responseValidator, error) {
	var body bytes.Buffer
	writeSplunk := func(sourcetype string, event any) error {
		record := map[string]any{
			"host":       e.hostname,
			"source":     "aegisnas",
			"sourcetype": sourcetype,
			"event":      event,
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		body.Write(data)
		body.WriteByte('\n')
		return nil
	}
	for _, audit := range audits {
		if err := writeSplunk("aegisnas:audit", audit); err != nil {
			return nil, nil, err
		}
	}
	for _, alert := range alerts {
		if err := writeSplunk("aegisnas:alert", alert); err != nil {
			return nil, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(e.cfg.Integrations.SIEM.Endpoint), bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("User-Agent", "AegisNAS-SIEM-Exporter/1.0")
	return req, validateSplunkResponse, nil
}

func (e *SIEMExporter) buildElasticRequest(ctx context.Context, token string, audits []siemAuditEvent, alerts []siemAlertEvent) (*http.Request, responseValidator, error) {
	var body bytes.Buffer
	writeElastic := func(index string, event any) error {
		meta, err := json.Marshal(map[string]any{
			"index": map[string]any{
				"_index": index,
			},
		})
		if err != nil {
			return err
		}
		doc, err := json.Marshal(event)
		if err != nil {
			return err
		}
		body.Write(meta)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
		return nil
	}
	for _, audit := range audits {
		if err := writeElastic("aegisnas-audit", map[string]any{
			"product":     "AegisNAS",
			"record_type": "audit_log",
			"hostname":    e.hostname,
			"exported_at": e.now().UTC().Format(time.RFC3339),
			"event":       audit,
		}); err != nil {
			return nil, nil, err
		}
	}
	for _, alert := range alerts {
		if err := writeElastic("aegisnas-alert", map[string]any{
			"product":     "AegisNAS",
			"record_type": "alert",
			"hostname":    e.hostname,
			"exported_at": e.now().UTC().Format(time.RFC3339),
			"event":       alert,
		}); err != nil {
			return nil, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(e.cfg.Integrations.SIEM.Endpoint), bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Authorization", "ApiKey "+token)
	req.Header.Set("User-Agent", "AegisNAS-SIEM-Exporter/1.0")
	return req, validateElasticResponse, nil
}

func loadAuditBatch(afterID int64, limit int) ([]siemAuditEvent, error) {
	rows, err := db.DB.Query(`SELECT id, CAST(timestamp AS TEXT), COALESCE(user, ''), action, COALESCE(details, ''),
			COALESCE(result, ''), COALESCE(ip_address, '')
		FROM audit_logs
		WHERE id > ?
		ORDER BY id ASC
		LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []siemAuditEvent
	for rows.Next() {
		var event siemAuditEvent
		if err := rows.Scan(&event.ID, &event.Timestamp, &event.User, &event.Action, &event.Details, &event.Result, &event.IPAddress); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func loadAlertBatch(afterID int64, limit int) ([]siemAlertEvent, error) {
	rows, err := db.DB.Query(`SELECT id, severity, source, message, COALESCE(details, ''), acknowledged, CAST(created_at AS TEXT)
		FROM alerts
		WHERE id > ?
		ORDER BY id ASC
		LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []siemAlertEvent
	for rows.Next() {
		var event siemAlertEvent
		if err := rows.Scan(&event.ID, &event.Severity, &event.Source, &event.Message, &event.Details, &event.Acknowledged, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func validateDefaultResponse(resp *http.Response, body []byte) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook export failed with %s: %s", resp.Status, compactResponse(body))
}

func validateSplunkResponse(resp *http.Response, body []byte) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("splunk export failed with %s: %s", resp.Status, compactResponse(body))
	}
	var payload struct {
		Text string `json:"text"`
		Code int    `json:"code"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Code != 0 {
		return fmt.Errorf("splunk export failed with code %d: %s", payload.Code, strings.TrimSpace(payload.Text))
	}
	return nil
}

func validateElasticResponse(resp *http.Response, body []byte) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("elastic export failed with %s: %s", resp.Status, compactResponse(body))
	}
	var payload struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	if !payload.Errors {
		return nil
	}
	for _, item := range payload.Items {
		for action, result := range item {
			if result.Status >= 300 || result.Error.Reason != "" {
				return fmt.Errorf("elastic bulk %s failed with status %d: %s %s", action, result.Status, strings.TrimSpace(result.Error.Type), strings.TrimSpace(result.Error.Reason))
			}
		}
	}
	return fmt.Errorf("elastic bulk response reported errors")
}

func effectiveSIEMBatchSize(cfg *config.Config) int {
	if cfg == nil || cfg.Integrations.SIEM.BatchSize <= 0 {
		return defaultSIEMBatch
	}
	return cfg.Integrations.SIEM.BatchSize
}

func maxAuditID(events []siemAuditEvent, current int64) int64 {
	maxID := current
	for _, event := range events {
		if event.ID > maxID {
			maxID = event.ID
		}
	}
	return maxID
}

func maxAlertID(events []siemAlertEvent, current int64) int64 {
	maxID := current
	for _, event := range events {
		if event.ID > maxID {
			maxID = event.ID
		}
	}
	return maxID
}

func detailInt64(details map[string]any, key string) int64 {
	if details == nil {
		return 0
	}
	switch value := details[key].(type) {
	case float64:
		return int64(value)
	case float32:
		return int64(value)
	case int:
		return int64(value)
	case int64:
		return value
	case int32:
		return int64(value)
	case json.Number:
		number, _ := value.Int64()
		return number
	default:
		return 0
	}
}

func detailString(details map[string]any, key string) (string, bool) {
	if details == nil {
		return "", false
	}
	value, ok := details[key]
	if !ok {
		return "", false
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return "", false
	}
	return text, true
}

func compactResponse(body []byte) string {
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > 240 {
		return text[:240]
	}
	if text == "" {
		return "empty response body"
	}
	return text
}
