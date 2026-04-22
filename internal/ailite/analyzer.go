package ailite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

// Circuit breaker states
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

type Analyzer struct {
	cfg             *config.Config
	logger          *zap.Logger
	remoteClient    *http.Client
	circuitState    CircuitState
	circuitMutex    sync.RWMutex
	failureCount    int
	lastFailureTime time.Time
}

func NewAnalyzer(cfg *config.Config, logger *zap.Logger) (*Analyzer, error) {
	timeout := 5 * time.Second
	if cfg != nil && cfg.AILite.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.AILite.RequestTimeoutSeconds) * time.Second
	}
	return &Analyzer{
		cfg:          cfg,
		logger:       logger,
		remoteClient: &http.Client{Timeout: timeout},
		circuitState: CircuitClosed,
	}, nil
}

// ---------- Auth Failure Classification ----------

func (a *Analyzer) RunAuthFailureAnalyzer(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.analyzeAuthFailures()
		}
	}
}

func (a *Analyzer) analyzeAuthFailures() {
	// Query recent failed authentications from audit_logs (or RADIUS logs)
	rows, err := db.DB.Query(`SELECT user, details, timestamp FROM audit_logs 
		WHERE action = 'auth_failure' AND timestamp > datetime('now', '-1 hour')`)
	if err != nil {
		a.logger.Error("failed to query auth failures", zap.Error(err))
		return
	}
	defer rows.Close()

	failuresByUser := make(map[string]int)
	failuresByReason := make(map[string]int)

	for rows.Next() {
		var user, details string
		var ts time.Time
		rows.Scan(&user, &details, &ts)
		failuresByUser[user]++
		reason := extractFailureReason(details)
		failuresByReason[reason]++
	}

	// Generate recommendations based on patterns
	if total := sumMap(failuresByUser); total > 20 {
		a.addRecommendation("warning", "auth_failure", 0.8,
			"High rate of authentication failures",
			fmt.Sprintf("%d failures in last hour. Check for brute force attacks.", total),
			"Review logs, enable fail2ban, check RADIUS configuration.")
	}

	for user, count := range failuresByUser {
		if count > 10 {
			a.addRecommendation("warning", "auth_failure", 0.9,
				fmt.Sprintf("User '%s' has many failed logins", user),
				fmt.Sprintf("%d failed attempts in the last hour.", count),
				"Check if user is legitimate; consider temporary lockout.")
		}
	}

	if failuresByReason["invalid_password"] > 15 {
		a.addRecommendation("info", "auth_failure", 0.7,
			"Many invalid password errors",
			"High volume of incorrect password attempts.",
			"Consider strengthening password policies or CAPTCHA on portal.")
	}
}

func extractFailureReason(details string) string {
	if strings.Contains(details, "invalid password") {
		return "invalid_password"
	}
	if strings.Contains(details, "user not found") {
		return "user_not_found"
	}
	return "unknown"
}

// ---------- Session Anomaly Detection ----------

func (a *Analyzer) RunSessionAnomalyDetector(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.detectSessionAnomalies()
		}
	}
}

func (a *Analyzer) detectSessionAnomalies() {
	// Check for concurrent sessions per user > threshold (default 3)
	rows, err := db.DB.Query(`SELECT username, COUNT(*) as cnt FROM sessions 
		WHERE end_time IS NULL GROUP BY username HAVING cnt > 3`)
	if err != nil {
		a.logger.Error("session query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user string
		var count int
		rows.Scan(&user, &count)
		a.addRecommendation("warning", "session_anomaly", 0.75,
			fmt.Sprintf("User '%s' has excessive concurrent sessions", user),
			fmt.Sprintf("%d active sessions detected.", count),
			"Investigate possible credential sharing or device issues.")
	}

	// Check for unusually high bandwidth usage (requires accounting data)
	rows2, err := db.DB.Query(`SELECT username, (bytes_in+bytes_out)/1024/1024 as mb_used 
		FROM sessions WHERE start_time > datetime('now', '-1 hour') AND end_time IS NOT NULL 
		AND (bytes_in+bytes_out) > 1000*1024*1024`) // > 1GB
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var user string
			var mb int
			rows2.Scan(&user, &mb)
			a.addRecommendation("info", "session_anomaly", 0.6,
				fmt.Sprintf("User '%s' used high bandwidth", user),
				fmt.Sprintf("Transferred %d MB in last hour.", mb),
				"Check if this is expected; consider bandwidth policies.")
		}
	}
}

// ---------- Config Linting ----------

func (a *Analyzer) RunConfigLinter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.lintConfig()
		}
	}
}

func (a *Analyzer) lintConfig() {
	// Example checks:
	// 1. Ensure certificates exist for EAP if RADIUS is enabled
	if a.cfg.Radius.Enabled() {
		certFiles := []string{
			a.cfg.Radius.CertDir + "/server.crt",
			a.cfg.Radius.CertDir + "/server.key",
			a.cfg.Radius.CertDir + "/ca.crt",
		}
		for _, f := range certFiles {
			if _, err := os.Stat(f); os.IsNotExist(err) {
				a.addRecommendation("warning", "config_lint", 0.9,
					"Missing RADIUS certificate",
					fmt.Sprintf("File %s not found.", f),
					"Generate certificates for EAP or disable RADIUS if not needed.")
			}
		}
	}

	// 2. Check for duplicate VLAN IDs
	vlanIDs := make(map[int]bool)
	rows, err := db.DB.Query("SELECT vlan FROM roles WHERE vlan IS NOT NULL")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var vlan int
			rows.Scan(&vlan)
			if vlanIDs[vlan] {
				a.addRecommendation("warning", "config_lint", 0.8,
					"Duplicate VLAN assignment",
					fmt.Sprintf("VLAN %d is assigned to multiple roles.", vlan),
					"Review role VLAN assignments.")
				break
			}
			vlanIDs[vlan] = true
		}
	}
}

// ---------- Remote Webhook ----------

func (a *Analyzer) RunRemoteWebhookSender(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendPendingRecommendations()
		}
	}
}

func (a *Analyzer) sendPendingRecommendations() {
	if !a.isCircuitClosed() {
		a.logger.Debug("circuit breaker open, skipping webhook")
		return
	}

	// Fetch unacknowledged recommendations not yet sent (we need a 'sent' column)
	// For simplicity, send all unacknowledged.
	rows, err := db.DB.Query(`SELECT id, severity, title, description, remediation FROM ai_recommendations 
		WHERE acknowledged = 0 ORDER BY created_at DESC LIMIT 10`)
	if err != nil {
		a.logger.Error("failed to query recommendations", zap.Error(err))
		return
	}
	defer rows.Close()

	var recs []map[string]interface{}
	for rows.Next() {
		var id int
		var severity, title, desc, remediation string
		rows.Scan(&id, &severity, &title, &desc, &remediation)
		recs = append(recs, map[string]interface{}{
			"id":          id,
			"severity":    severity,
			"title":       title,
			"description": desc,
			"remediation": remediation,
		})
	}
	if len(recs) == 0 {
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"source":          "aegisnas-ai-lite",
		"recommendations": recs,
		"timestamp":       time.Now().UTC(),
	})

	req, err := http.NewRequest("POST", a.cfg.AILite.RemoteWebhook, bytes.NewReader(payload))
	if err != nil {
		a.logger.Error("webhook request creation failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.remoteClient.Do(req)
	if err != nil {
		a.recordFailure()
		a.logger.Warn("webhook request failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		a.recordFailure()
	} else {
		a.resetCircuit()
	}
}

func (a *Analyzer) isCircuitClosed() bool {
	a.circuitMutex.RLock()
	defer a.circuitMutex.RUnlock()
	return a.circuitState == CircuitClosed || a.circuitState == CircuitHalfOpen
}

func (a *Analyzer) recordFailure() {
	a.circuitMutex.Lock()
	defer a.circuitMutex.Unlock()
	a.failureCount++
	a.lastFailureTime = time.Now()
	if a.failureCount >= 3 {
		a.circuitState = CircuitOpen
		a.logger.Warn("circuit breaker opened due to failures")
		// Schedule half-open after timeout
		time.AfterFunc(30*time.Second, func() {
			a.circuitMutex.Lock()
			a.circuitState = CircuitHalfOpen
			a.circuitMutex.Unlock()
		})
	}
}

func (a *Analyzer) resetCircuit() {
	a.circuitMutex.Lock()
	defer a.circuitMutex.Unlock()
	a.failureCount = 0
	a.circuitState = CircuitClosed
}

// ---------- Recommendation Storage ----------

func (a *Analyzer) addRecommendation(severity, source string, confidence float64, title, description, remediation string) {
	// Avoid duplicates within a short period
	var count int
	db.DB.QueryRow(`SELECT COUNT(*) FROM ai_recommendations WHERE title = ? AND created_at > datetime('now', '-1 hour')`,
		title).Scan(&count)
	if count > 0 {
		return
	}
	_, err := db.DB.Exec(`INSERT INTO ai_recommendations (severity, source, confidence, title, description, remediation)
		VALUES (?, ?, ?, ?, ?, ?)`, severity, source, confidence, title, description, remediation)
	if err != nil {
		a.logger.Error("failed to store recommendation", zap.Error(err))
	} else {
		a.logger.Info("new recommendation", zap.String("title", title))
	}
}

// ---------- HTTP Handlers ----------

func (a *Analyzer) HandleListRecommendations(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, severity, source, confidence, title, description, remediation, acknowledged, created_at 
		FROM ai_recommendations ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var recs []map[string]interface{}
	for rows.Next() {
		var id int
		var severity, source, title, desc, remediation string
		var confidence float64
		var acknowledged bool
		var createdAt time.Time
		rows.Scan(&id, &severity, &source, &confidence, &title, &desc, &remediation, &acknowledged, &createdAt)
		recs = append(recs, map[string]interface{}{
			"id":           id,
			"severity":     severity,
			"source":       source,
			"confidence":   confidence,
			"title":        title,
			"description":  desc,
			"remediation":  remediation,
			"acknowledged": acknowledged,
			"created_at":   createdAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recs)
}

func (a *Analyzer) HandleAcknowledge(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := db.DB.Exec(`UPDATE ai_recommendations SET acknowledged = 1 WHERE id = ?`, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Analyzer) HandleRunAnalysisNow(w http.ResponseWriter, r *http.Request) {
	go func() {
		a.analyzeAuthFailures()
		a.detectSessionAnomalies()
		a.lintConfig()
		a.runFullAIAnalysis()
	}()
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "analysis started"})
}

// ---------- Helpers ----------

func sumMap(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}
