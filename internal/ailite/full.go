package ailite

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

const fullAIComponent = "ai_full"

type fullAIRecommendation struct {
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (a *Analyzer) RunFullAIAnalyzer(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runFullAIAnalysis()
		}
	}
}

func (a *Analyzer) runFullAIAnalysis() {
	if !a.fullAIEnabled() {
		return
	}
	if strings.TrimSpace(a.cfg.AILite.Endpoint) == "" || strings.TrimSpace(a.cfg.AILite.Model) == "" {
		message := "Full AI mode is enabled but endpoint or model is not configured"
		a.logger.Warn(message)
		_ = db.UpsertRuntimeStatus(fullAIComponent, "degraded", message, map[string]any{
			"mode":     config.EffectiveAIMode(a.cfg),
			"provider": config.EffectiveAIProvider(a.cfg),
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.fullAITimeout())
	defer cancel()

	snapshot, err := a.buildFullAIContext()
	if err != nil {
		a.logger.Warn("full AI context build failed", zap.Error(err))
		_ = db.UpsertRuntimeStatus(fullAIComponent, "degraded", err.Error(), nil)
		return
	}

	recommendations, err := a.requestFullAIRecommendations(ctx, snapshot)
	if err != nil {
		a.recordFailure()
		a.logger.Warn("full AI request failed", zap.Error(err))
		_ = db.UpsertRuntimeStatus(fullAIComponent, "degraded", err.Error(), map[string]any{
			"provider": config.EffectiveAIProvider(a.cfg),
			"model":    a.cfg.AILite.Model,
		})
		return
	}
	a.resetCircuit()

	written := 0
	for _, rec := range recommendations {
		normalized, ok := normalizeFullAIRecommendation(rec)
		if !ok {
			continue
		}
		a.addRecommendation(normalized.Severity, fullAIComponent, normalized.Confidence, normalized.Title, normalized.Description, normalized.Remediation)
		written++
	}

	_ = db.UpsertRuntimeStatus(fullAIComponent, "ok", fmt.Sprintf("Full AI analysis completed with %d candidate recommendations", written), map[string]any{
		"provider":        config.EffectiveAIProvider(a.cfg),
		"model":           a.cfg.AILite.Model,
		"recommendations": written,
	})
}

func (a *Analyzer) fullAIEnabled() bool {
	return a != nil && a.cfg != nil && a.cfg.AILite.Enabled && config.EffectiveAIMode(a.cfg) == "full"
}

func (a *Analyzer) fullAITimeout() time.Duration {
	if a == nil || a.cfg == nil || a.cfg.AILite.RequestTimeoutSeconds <= 0 {
		return 20 * time.Second
	}
	return time.Duration(a.cfg.AILite.RequestTimeoutSeconds) * time.Second
}

func (a *Analyzer) fullAILimit() int {
	if a == nil || a.cfg == nil || a.cfg.AILite.MaxInputEvents <= 0 {
		return 200
	}
	if a.cfg.AILite.MaxInputEvents > 500 {
		return 500
	}
	return a.cfg.AILite.MaxInputEvents
}

func (a *Analyzer) buildFullAIContext() (map[string]any, error) {
	limit := a.fullAILimit()

	runtimeStatuses, err := db.GetRuntimeStatuses()
	if err != nil {
		return nil, err
	}
	auditEvents, err := recentAuditEvents(limit)
	if err != nil {
		return nil, err
	}
	sessions, err := recentSessions(limit)
	if err != nil {
		return nil, err
	}
	alerts, err := recentAlerts(limit)
	if err != nil {
		return nil, err
	}
	existingRecommendations, err := recentRecommendations(25)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"product": map[string]any{
			"name": "AegisNAS",
			"role": "NAS, captive portal, RADIUS broker, policy, and session enforcement appliance",
		},
		"deployment": config.DeploymentSummary(a.cfg),
		"interfaces": map[string]any{
			"mode": a.cfg.Mode,
			"wan": map[string]any{
				"name": a.cfg.WAN.Name,
				"dhcp": a.cfg.WAN.DHCP,
			},
			"lan": map[string]any{
				"name":    a.cfg.LAN.Name,
				"address": a.cfg.LAN.Address,
			},
		},
		"radius": map[string]any{
			"upstream_enabled":        a.cfg.Radius.Upstream.Enabled,
			"pool_strategy":           a.cfg.Radius.Upstream.PoolStrategy,
			"status_check":            a.cfg.Radius.Upstream.StatusCheck,
			"max_sessions":            a.cfg.Radius.MaxSessions,
			"interim_update_seconds":  a.cfg.Radius.InterimUpdateSeconds,
			"dynamic_authorization":   a.cfg.Radius.DynamicAuth.Enabled,
			"vendor_attributes":       a.cfg.Radius.Vendor.Enabled,
			"request_timeout_seconds": a.cfg.Radius.RequestTimeoutSeconds,
		},
		"portal": map[string]any{
			"enabled":        a.cfg.Portal.Enabled,
			"radius_auth":    a.cfg.Portal.RadiusAuth,
			"local_fallback": a.cfg.Portal.LocalFallback,
		},
		"wireless": map[string]any{
			"enabled":    a.cfg.Wireless.Enabled,
			"interface":  a.cfg.Wireless.Interface,
			"ssid_count": len(a.cfg.Wireless.SSIDs),
		},
		"runtime_statuses":         runtimeStatuses,
		"recent_audit_events":      auditEvents,
		"recent_sessions":          sessions,
		"recent_alerts":            alerts,
		"existing_recommendations": existingRecommendations,
	}, nil
}

func (a *Analyzer) requestFullAIRecommendations(ctx context.Context, snapshot map[string]any) ([]fullAIRecommendation, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}

	requestBody := map[string]any{
		"model": a.cfg.AILite.Model,
		"messages": []map[string]string{
			{
				"role": "system",
				"content": strings.Join([]string{
					"You are the full AegisNAS AI analyst for a network access appliance.",
					"Use the JSON operational snapshot to produce advisory recommendations only.",
					"Do not recommend bypassing authentication, disabling audit logs, or weakening encryption.",
					"Return only JSON in this shape: {\"recommendations\":[{\"severity\":\"info|warning|critical\",\"confidence\":0.0,\"title\":\"...\",\"description\":\"...\",\"remediation\":\"...\"}]}",
					"Keep recommendations concrete, operational, and safe for an admin dashboard.",
				}, " "),
			},
			{
				"role":    "user",
				"content": string(payload),
			},
		},
		"temperature": 0.2,
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatCompletionsURL(a.cfg.AILite.Endpoint), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := fullAIAPIKey(a.cfg); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := a.remoteClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AI provider returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}

	var completion chatCompletionResponse
	if err := json.Unmarshal(responseBody, &completion); err != nil {
		return nil, err
	}
	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("AI provider returned no choices")
	}
	content := strings.TrimSpace(completion.Choices[0].Message.Content)
	if content == "" {
		return nil, fmt.Errorf("AI provider returned empty content")
	}
	return parseFullAIRecommendations(content)
}

func chatCompletionsURL(endpoint string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if strings.HasSuffix(trimmed, "/v1/chat/completions") || strings.HasSuffix(trimmed, "/chat/completions") {
		return trimmed
	}
	if strings.HasSuffix(trimmed, "/v1") {
		return trimmed + "/chat/completions"
	}
	return trimmed + "/v1/chat/completions"
}

func fullAIAPIKey(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	envName := strings.TrimSpace(cfg.AILite.APIKeyEnv)
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
}

func parseFullAIRecommendations(content string) ([]fullAIRecommendation, error) {
	content = stripJSONFence(content)
	var wrapped struct {
		Recommendations []fullAIRecommendation `json:"recommendations"`
	}
	if err := json.Unmarshal([]byte(content), &wrapped); err == nil && wrapped.Recommendations != nil {
		return wrapped.Recommendations, nil
	}

	var raw []fullAIRecommendation
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func stripJSONFence(content string) string {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "```") {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```JSON")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	return strings.TrimSpace(trimmed)
}

func normalizeFullAIRecommendation(rec fullAIRecommendation) (fullAIRecommendation, bool) {
	rec.Title = cleanAIText(rec.Title, 180)
	if rec.Title == "" {
		return fullAIRecommendation{}, false
	}
	rec.Description = cleanAIText(rec.Description, 1200)
	rec.Remediation = cleanAIText(rec.Remediation, 1200)
	switch strings.ToLower(strings.TrimSpace(rec.Severity)) {
	case "critical":
		rec.Severity = "critical"
	case "warning":
		rec.Severity = "warning"
	default:
		rec.Severity = "info"
	}
	if rec.Confidence < 0 {
		rec.Confidence = 0
	}
	if rec.Confidence > 1 {
		rec.Confidence = 1
	}
	return rec, true
}

func cleanAIText(input string, max int) string {
	value := strings.Join(strings.Fields(input), " ")
	runes := []rune(value)
	if max > 0 && len(runes) > max {
		return string(runes[:max])
	}
	return value
}

func recentAuditEvents(limit int) ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT COALESCE(user, ''), action, COALESCE(result, ''), COALESCE(details, ''), CAST(timestamp AS TEXT)
		FROM audit_logs ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var user, action, result, details, timestamp string
		if err := rows.Scan(&user, &action, &result, &details, &timestamp); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"user":      user,
			"action":    action,
			"result":    result,
			"details":   details,
			"timestamp": timestamp,
		})
	}
	return items, rows.Err()
}

func recentSessions(limit int) ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT id, username, COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''),
			COALESCE(role, ''), COALESCE(bandwidth_profile, ''), COALESCE(vlan, 0), bytes_in, bytes_out,
			CAST(start_time AS TEXT), COALESCE(CAST(end_time AS TEXT), '')
		FROM sessions ORDER BY start_time DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var id, username, mac, ip, authMethod, role, bandwidthProfile, startTime, endTime string
		var vlan int
		var bytesIn, bytesOut int64
		if err := rows.Scan(&id, &username, &mac, &ip, &authMethod, &role, &bandwidthProfile, &vlan, &bytesIn, &bytesOut, &startTime, &endTime); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"id":                id,
			"username":          username,
			"mac":               mac,
			"ip":                ip,
			"auth_method":       authMethod,
			"role":              role,
			"bandwidth_profile": bandwidthProfile,
			"vlan":              vlan,
			"bytes_in":          bytesIn,
			"bytes_out":         bytesOut,
			"start_time":        startTime,
			"end_time":          endTime,
			"active":            endTime == "",
		})
	}
	return items, rows.Err()
}

func recentAlerts(limit int) ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT severity, source, message, COALESCE(details, ''), acknowledged, CAST(created_at AS TEXT)
		FROM alerts ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var severity, source, message, details, createdAt string
		var acknowledged bool
		if err := rows.Scan(&severity, &source, &message, &details, &acknowledged, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"severity":     severity,
			"source":       source,
			"message":      message,
			"details":      details,
			"acknowledged": acknowledged,
			"created_at":   createdAt,
		})
	}
	return items, rows.Err()
}

func recentRecommendations(limit int) ([]map[string]any, error) {
	rows, err := db.DB.Query(`SELECT severity, source, confidence, title, COALESCE(description, ''), COALESCE(remediation, ''), acknowledged, CAST(created_at AS TEXT)
		FROM ai_recommendations ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []map[string]any
	for rows.Next() {
		var severity, source, title, description, remediation, createdAt string
		var confidence float64
		var acknowledged bool
		if err := rows.Scan(&severity, &source, &confidence, &title, &description, &remediation, &acknowledged, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"severity":     severity,
			"source":       source,
			"confidence":   confidence,
			"title":        title,
			"description":  description,
			"remediation":  remediation,
			"acknowledged": acknowledged,
			"created_at":   createdAt,
		})
	}
	return items, rows.Err()
}
