package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const FallbackPolicySchemaVersion = 1

type FallbackPolicy struct {
	SchemaVersion            int      `json:"schema_version"`
	Enabled                  bool     `json:"enabled"`
	Mode                     string   `json:"mode"`
	FailClosed               bool     `json:"fail_closed"`
	AllowPortalLocal         bool     `json:"allow_portal_local"`
	AllowLDAP                bool     `json:"allow_ldap"`
	RequireIdentityAllowlist bool     `json:"require_identity_allowlist"`
	MaxOutageSeconds         int      `json:"max_outage_seconds"`
	StalePolicySeconds       int      `json:"stale_policy_seconds"`
	RecoverySuccesses        int      `json:"recovery_successes"`
	AllowedUsers             []string `json:"allowed_users"`
	AllowedRealms            []string `json:"allowed_realms"`
	AllowedRoles             []string `json:"allowed_roles"`
	AuditEnabled             bool     `json:"audit_enabled"`
	RetentionLimit           int      `json:"retention_limit"`
}

type FallbackPolicyReport struct {
	SchemaVersion int                           `json:"schema_version"`
	Enabled       bool                          `json:"enabled"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	Policy        FallbackPolicy                `json:"policy"`
	Summary       FallbackPolicySummary         `json:"summary"`
	AuditSummary  db.RadiusFallbackEventSummary `json:"audit_summary"`
	Recent        []db.RadiusFallbackEvent      `json:"recent,omitempty"`
	RFCs          []string                      `json:"rfcs"`
	Warnings      []string                      `json:"warnings,omitempty"`
}

type FallbackPolicySummary struct {
	UpstreamEnabled       bool   `json:"upstream_enabled"`
	PortalRadiusAuth      bool   `json:"portal_radius_auth"`
	PortalLocalFallback   bool   `json:"portal_local_fallback"`
	LDAPEnabled           bool   `json:"ldap_enabled"`
	AllowedUserCount      int    `json:"allowed_user_count"`
	AllowedRealmCount     int    `json:"allowed_realm_count"`
	AllowedRoleCount      int    `json:"allowed_role_count"`
	IdentityAllowlistSet  bool   `json:"identity_allowlist_set"`
	ActiveOutage          bool   `json:"active_outage"`
	OutageStartedAt       string `json:"outage_started_at,omitempty"`
	FallbackExpiresAt     string `json:"fallback_expires_at,omitempty"`
	CurrentUpstreamStatus string `json:"current_upstream_status,omitempty"`
	RecoverySuccesses     int    `json:"recovery_successes"`
}

type FallbackEvaluationRequest struct {
	Username        string
	Role            string
	IdentitySource  string
	Source          string
	UpstreamStatus  string
	UpstreamMessage string
	OutageStartedAt time.Time
	Now             time.Time
}

type FallbackDecision struct {
	Allowed         bool              `json:"allowed"`
	Decision        string            `json:"decision"`
	Reason          string            `json:"reason"`
	Mode            string            `json:"mode"`
	FailClosed      bool              `json:"fail_closed"`
	Source          string            `json:"source"`
	IdentitySource  string            `json:"identity_source"`
	Role            string            `json:"role,omitempty"`
	Realm           string            `json:"realm,omitempty"`
	UsernameHash    string            `json:"username_hash"`
	UpstreamStatus  string            `json:"upstream_status,omitempty"`
	OutageStartedAt string            `json:"outage_started_at,omitempty"`
	ExpiresAt       string            `json:"expires_at,omitempty"`
	MonitorOnly     bool              `json:"monitor_only"`
	Details         map[string]string `json:"details,omitempty"`
}

func FallbackPolicyFromConfig(cfg *config.Config) FallbackPolicy {
	policy := FallbackPolicy{
		SchemaVersion: FallbackPolicySchemaVersion,
		Mode:          "monitor",
	}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusFallbackPolicyConfig(cfg.Radius.Upstream.FallbackPolicy)
	policy.Enabled = raw.Enabled
	policy.Mode = strings.ToLower(defaultString(raw.Mode, "monitor"))
	policy.FailClosed = raw.FailClosed
	policy.AllowPortalLocal = raw.AllowPortalLocal
	policy.AllowLDAP = raw.AllowLDAP
	policy.RequireIdentityAllowlist = raw.RequireIdentityAllowlist
	policy.MaxOutageSeconds = raw.MaxOutageSeconds
	policy.StalePolicySeconds = raw.StalePolicySeconds
	policy.RecoverySuccesses = raw.RecoverySuccesses
	policy.AllowedUsers = normalizedPolicyStrings(raw.AllowedUsers)
	policy.AllowedRealms = normalizedPolicyStrings(raw.AllowedRealms)
	policy.AllowedRoles = normalizedPolicyStrings(raw.AllowedRoles)
	policy.AuditEnabled = raw.AuditEnabled
	policy.RetentionLimit = raw.RetentionLimit
	return policy
}

func BuildFallbackPolicyReport(cfg *config.Config) FallbackPolicyReport {
	policy := FallbackPolicyFromConfig(cfg)
	report := FallbackPolicyReport{
		SchemaVersion: FallbackPolicySchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Upstream fallback policy is disabled.",
		Policy:        policy,
		RFCs:          []string{"RFC 2865", "RFC 5080", "RFC 6614"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	report.Summary = FallbackPolicySummary{
		UpstreamEnabled:      cfg.Radius.Upstream.Enabled,
		PortalRadiusAuth:     cfg.Portal.RadiusAuth,
		PortalLocalFallback:  cfg.Portal.LocalFallback,
		LDAPEnabled:          cfg.LDAP.Enabled,
		AllowedUserCount:     len(policy.AllowedUsers),
		AllowedRealmCount:    len(policy.AllowedRealms),
		AllowedRoleCount:     len(policy.AllowedRoles),
		IdentityAllowlistSet: len(policy.AllowedUsers)+len(policy.AllowedRealms)+len(policy.AllowedRoles) > 0,
		RecoverySuccesses:    policy.RecoverySuccesses,
	}
	outage := CurrentFallbackOutageSnapshot(policy, time.Now().UTC())
	report.Summary.ActiveOutage = outage.Active
	report.Summary.CurrentUpstreamStatus = outage.Status
	if !outage.StartedAt.IsZero() {
		report.Summary.OutageStartedAt = outage.StartedAt.Format(time.RFC3339)
	}
	if !outage.ExpiresAt.IsZero() {
		report.Summary.FallbackExpiresAt = outage.ExpiresAt.Format(time.RFC3339)
	}
	if db.DB != nil {
		if summary, err := db.GetRadiusFallbackEventSummary(); err == nil {
			report.AuditSummary = summary
		} else {
			report.Warnings = append(report.Warnings, err.Error())
		}
		if recent, err := db.ListRadiusFallbackEvents("", "", 25); err == nil {
			report.Recent = recent
		} else {
			report.Warnings = append(report.Warnings, err.Error())
		}
	}
	switch {
	case !cfg.Radius.Upstream.Enabled:
		report.Message = "Upstream AAA is disabled; fallback policy is idle."
	case !cfg.Portal.RadiusAuth:
		report.Message = "Portal broker auth is disabled; fallback policy is idle for portal logins."
	case !cfg.Portal.LocalFallback:
		report.Status = "ready"
		report.Message = "Portal local fallback is disabled; outage bypass is closed."
	case !policy.Enabled:
		report.Status = "degraded"
		report.Message = "Portal local fallback is enabled but fallback policy is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.upstream.fallback_policy before production upstream AAA operation.")
	case policy.RequireIdentityAllowlist && !report.Summary.IdentityAllowlistSet:
		if policy.Mode == "enforce" && policy.FailClosed {
			report.Status = "blocked"
			report.Message = "Fallback policy requires an identity allowlist but none is configured."
		} else {
			report.Status = "degraded"
			report.Message = "Fallback policy is monitoring an empty identity allowlist."
		}
		report.Warnings = append(report.Warnings, "Configure allowed_users, allowed_realms, or allowed_roles for deterministic fallback.")
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "Fallback policy is in monitor mode; decisions are audited but not enforced."
		report.Warnings = append(report.Warnings, "Use radius.upstream.fallback_policy.mode=enforce for production sign-off.")
	case !policy.FailClosed:
		report.Status = "degraded"
		report.Message = "Fallback policy enforcement is active but fail_closed is disabled."
		report.Warnings = append(report.Warnings, "Keep fail_closed=true so invalid policy state cannot silently allow fallback.")
	default:
		report.Status = "ready"
		report.Message = "Fallback policy is enforceable with bounded outage and identity controls."
	}
	if cfg.Radius.Upstream.Enabled && cfg.Portal.RadiusAuth && cfg.Portal.LocalFallback && policy.AuditEnabled && db.DB == nil {
		report.Status = worseFallbackStatus(report.Status, "blocked")
		report.Warnings = append(report.Warnings, "Database is not initialized; fallback decisions cannot be audited.")
	}
	return report
}

type FallbackOutageSnapshot struct {
	Active    bool
	Status    string
	Message   string
	StartedAt time.Time
	ExpiresAt time.Time
}

func CurrentFallbackOutageSnapshot(policy FallbackPolicy, now time.Time) FallbackOutageSnapshot {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	snapshot := FallbackOutageSnapshot{Status: "unknown"}
	if db.DB == nil {
		snapshot.Status = "unknown"
		snapshot.Message = "runtime status unavailable"
		return snapshot
	}
	status, err := db.GetRuntimeStatus("radius_broker_auth")
	if err != nil || status == nil {
		snapshot.Status = "unknown"
		snapshot.Message = "broker status has not been recorded"
		return snapshot
	}
	snapshot.Status = strings.TrimSpace(status.Status)
	snapshot.Message = strings.TrimSpace(status.Message)
	if strings.EqualFold(snapshot.Status, "ok") {
		return snapshot
	}
	snapshot.Active = true
	startedAt, parseErr := parseRuntimeTimestamp(status.UpdatedAt)
	if parseErr != nil || startedAt.IsZero() {
		startedAt = now
	}
	snapshot.StartedAt = startedAt
	snapshot.ExpiresAt = startedAt.Add(time.Duration(policy.MaxOutageSeconds) * time.Second)
	return snapshot
}

func EvaluateFallbackPolicy(cfg *config.Config, req FallbackEvaluationRequest) FallbackDecision {
	policy := FallbackPolicyFromConfig(cfg)
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	source := strings.ToLower(defaultString(req.Source, "portal"))
	identitySource := strings.ToLower(strings.TrimSpace(req.IdentitySource))
	realm := identityRealm(req.Username)
	outageStartedAt := req.OutageStartedAt
	if outageStartedAt.IsZero() {
		outage := CurrentFallbackOutageSnapshot(policy, now)
		outageStartedAt = outage.StartedAt
		if outageStartedAt.IsZero() && cfg != nil && cfg.Radius.Upstream.Enabled {
			outageStartedAt = now
		}
		if strings.TrimSpace(req.UpstreamStatus) == "" {
			req.UpstreamStatus = outage.Status
		}
		if strings.TrimSpace(req.UpstreamMessage) == "" {
			req.UpstreamMessage = outage.Message
		}
	}
	expiresAt := time.Time{}
	if !outageStartedAt.IsZero() && policy.MaxOutageSeconds > 0 {
		expiresAt = outageStartedAt.Add(time.Duration(policy.MaxOutageSeconds) * time.Second)
	}
	decision := FallbackDecision{
		Allowed:         true,
		Decision:        "allowed",
		Reason:          "fallback policy permits this identity",
		Mode:            policy.Mode,
		FailClosed:      policy.FailClosed,
		Source:          source,
		IdentitySource:  identitySource,
		Role:            strings.TrimSpace(req.Role),
		Realm:           realm,
		UsernameHash:    HashFallbackIdentity(req.Username),
		UpstreamStatus:  strings.TrimSpace(req.UpstreamStatus),
		OutageStartedAt: formatTimeRFC3339(outageStartedAt),
		ExpiresAt:       formatTimeRFC3339(expiresAt),
		Details: map[string]string{
			"upstream_message": strings.TrimSpace(req.UpstreamMessage),
		},
	}
	violations := fallbackPolicyViolations(policy, cfg, req, realm, expiresAt, now)
	if len(violations) > 0 {
		decision.Reason = strings.Join(violations, "; ")
		if policy.Mode == "enforce" && policy.FailClosed {
			decision.Allowed = false
			decision.Decision = "denied"
		} else {
			decision.MonitorOnly = true
		}
	}
	if !policy.Enabled {
		decision.Reason = "fallback policy disabled; legacy portal.local_fallback behavior applies"
		if cfg != nil && cfg.Radius.Upstream.Enabled && policy.Mode == "enforce" && policy.FailClosed {
			decision.Allowed = false
			decision.Decision = "denied"
		}
	}
	return decision
}

func RecordFallbackDecision(cfg *config.Config, decision FallbackDecision) error {
	policy := FallbackPolicyFromConfig(cfg)
	if !policy.AuditEnabled {
		return nil
	}
	if db.DB == nil {
		return nil
	}
	now := time.Now().UTC()
	observedAt := now.Format(time.RFC3339)
	return db.RecordRadiusFallbackEvent(db.RadiusFallbackEvent{
		ObservedAt:      observedAt,
		Source:          decision.Source,
		UsernameHash:    decision.UsernameHash,
		Realm:           decision.Realm,
		IdentitySource:  decision.IdentitySource,
		Role:            decision.Role,
		Decision:        decision.Decision,
		Reason:          decision.Reason,
		UpstreamStatus:  decision.UpstreamStatus,
		PolicyMode:      decision.Mode,
		FailClosed:      decision.FailClosed,
		OutageStartedAt: decision.OutageStartedAt,
		ExpiresAt:       decision.ExpiresAt,
	}, decision.Details, policy.RetentionLimit)
}

func HashFallbackIdentity(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func fallbackPolicyViolations(policy FallbackPolicy, cfg *config.Config, req FallbackEvaluationRequest, realm string, expiresAt, now time.Time) []string {
	violations := []string{}
	if cfg == nil {
		return []string{"configuration is not loaded"}
	}
	if cfg.Radius.Upstream.Enabled && !policy.Enabled {
		return []string{"fallback policy is disabled while upstream AAA is enabled"}
	}
	if !cfg.Portal.LocalFallback {
		violations = append(violations, "portal.local_fallback is disabled")
	}
	identitySource := strings.ToLower(strings.TrimSpace(req.IdentitySource))
	switch identitySource {
	case "local":
		if !policy.AllowPortalLocal {
			violations = append(violations, "local portal fallback is not allowed")
		}
	case "ldap":
		if !policy.AllowLDAP {
			violations = append(violations, "LDAP fallback is not allowed")
		}
	default:
		violations = append(violations, "identity source is not eligible for fallback")
	}
	if policy.RequireIdentityAllowlist && !fallbackIdentityAllowed(policy, req.Username, realm, req.Role) {
		violations = append(violations, "identity is not in the fallback allowlist")
	}
	if !expiresAt.IsZero() && now.After(expiresAt) {
		violations = append(violations, "fallback outage window expired")
	}
	return violations
}

func fallbackIdentityAllowed(policy FallbackPolicy, username, realm, role string) bool {
	if len(policy.AllowedUsers)+len(policy.AllowedRealms)+len(policy.AllowedRoles) == 0 {
		return false
	}
	username = strings.ToLower(strings.TrimSpace(username))
	realm = strings.ToLower(strings.TrimSpace(realm))
	role = strings.ToLower(strings.TrimSpace(role))
	if containsPolicyValue(policy.AllowedUsers, username) {
		return true
	}
	if realm != "" && containsPolicyValue(policy.AllowedRealms, realm) {
		return true
	}
	if containsPolicyValue(policy.AllowedRealms, "*") {
		return true
	}
	if role != "" && containsPolicyValue(policy.AllowedRoles, role) {
		return true
	}
	return false
}

func containsPolicyValue(values []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == needle {
			return true
		}
	}
	return false
}

func identityRealm(username string) string {
	username = strings.TrimSpace(username)
	if at := strings.LastIndex(username, "@"); at >= 0 && at+1 < len(username) {
		return strings.ToLower(strings.TrimSpace(username[at+1:]))
	}
	return ""
}

func normalizedPolicyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func parseRuntimeTimestamp(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp format %q", value)
}

func formatTimeRFC3339(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func worseFallbackStatus(current, candidate string) string {
	order := map[string]int{"ready": 1, "degraded": 2, "blocked": 3}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}
