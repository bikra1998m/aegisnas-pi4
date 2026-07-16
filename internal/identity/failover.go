package identity

import (
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/activedirectory"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const FailoverSchemaVersion = 1

type FailoverPolicy struct {
	SchemaVersion              int      `json:"schema_version"`
	Enabled                    bool     `json:"enabled"`
	Mode                       string   `json:"mode"`
	FailClosed                 bool     `json:"fail_closed"`
	SourceOrder                []string `json:"source_order"`
	MaxFailures                int      `json:"max_failures"`
	CircuitOpenSeconds         int      `json:"circuit_open_seconds"`
	StaleCacheSeconds          int      `json:"stale_cache_seconds"`
	CacheCredentials           bool     `json:"cache_credentials"`
	SplitResultPolicy          string   `json:"split_result_policy"`
	HealthCheckIntervalSeconds int      `json:"health_check_interval_seconds"`
	AuditEnabled               bool     `json:"audit_enabled"`
	RetentionLimit             int      `json:"retention_limit"`
}

type SourcePlan struct {
	Name         string                        `json:"name"`
	Type         string                        `json:"type"`
	Enabled      bool                          `json:"enabled"`
	Executable   bool                          `json:"executable"`
	Priority     int                           `json:"priority"`
	Reason       string                        `json:"reason,omitempty"`
	CircuitState db.IdentitySourceCircuitState `json:"circuit_state"`
}

type FailoverSummary struct {
	PortalRadiusAuth       bool   `json:"portal_radius_auth"`
	PortalLocalFallback    bool   `json:"portal_local_fallback"`
	LDAPEnabled            bool   `json:"ldap_enabled"`
	ActiveDirectoryEnabled bool   `json:"active_directory_enabled"`
	SourceCount            int    `json:"source_count"`
	EnabledSourceCount     int    `json:"enabled_source_count"`
	ExecutableSourceCount  int    `json:"executable_source_count"`
	OpenCircuitCount       int    `json:"open_circuit_count"`
	ClosedCircuitCount     int    `json:"closed_circuit_count"`
	CacheEnabled           bool   `json:"cache_enabled"`
	AuditEnabled           bool   `json:"audit_enabled"`
	DeterministicOrder     bool   `json:"deterministic_order"`
	LastObservedAt         string `json:"last_observed_at,omitempty"`
	LastDecision           string `json:"last_decision,omitempty"`
	LastReason             string `json:"last_reason,omitempty"`
}

type FailoverReport struct {
	SchemaVersion int                           `json:"schema_version"`
	GeneratedAt   string                        `json:"generated_at"`
	Enabled       bool                          `json:"enabled"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	Policy        FailoverPolicy                `json:"policy"`
	Summary       FailoverSummary               `json:"summary"`
	Sources       []SourcePlan                  `json:"sources"`
	AuditSummary  db.IdentitySourceEventSummary `json:"audit_summary"`
	CacheSummary  db.IdentitySourceCacheSummary `json:"cache_summary"`
	Recent        []db.IdentitySourceEvent      `json:"recent,omitempty"`
}

type EventRecord struct {
	SourceName   string
	SourceType   string
	Username     string
	Decision     string
	Reason       string
	LatencyMS    int64
	CircuitState string
	CacheUsed    bool
	Details      any
}

func FailoverPolicyFromConfig(cfg *config.Config) FailoverPolicy {
	raw := config.IdentityFailoverConfig{}
	if cfg != nil {
		raw = config.EffectiveIdentityFailoverConfig(cfg.Identity.Failover)
	}
	return FailoverPolicy{
		SchemaVersion:              FailoverSchemaVersion,
		Enabled:                    raw.Enabled,
		Mode:                       normalizeMode(raw.Mode),
		FailClosed:                 raw.FailClosed,
		SourceOrder:                normalizedSourceOrder(raw.SourceOrder),
		MaxFailures:                raw.MaxFailures,
		CircuitOpenSeconds:         raw.CircuitOpenSeconds,
		StaleCacheSeconds:          raw.StaleCacheSeconds,
		CacheCredentials:           raw.CacheCredentials,
		SplitResultPolicy:          normalizeSplitResultPolicy(raw.SplitResultPolicy),
		HealthCheckIntervalSeconds: raw.HealthCheckIntervalSeconds,
		AuditEnabled:               raw.AuditEnabled,
		RetentionLimit:             raw.RetentionLimit,
	}
}

func BuildFailoverReport(cfg *config.Config) FailoverReport {
	now := time.Now().UTC()
	policy := FailoverPolicyFromConfig(cfg)
	report := FailoverReport{
		SchemaVersion: FailoverSchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Enabled:       policy.Enabled,
		Status:        "ready",
		Policy:        policy,
	}
	report.Sources = BuildSourcePlan(cfg)
	report.Summary = FailoverSummary{
		PortalRadiusAuth:       cfg != nil && cfg.Portal.RadiusAuth,
		PortalLocalFallback:    cfg != nil && cfg.Portal.LocalFallback,
		LDAPEnabled:            cfg != nil && cfg.LDAP.Enabled,
		ActiveDirectoryEnabled: cfg != nil && cfg.ActiveDirectory.Enabled,
		SourceCount:            len(report.Sources),
		CacheEnabled:           policy.CacheCredentials,
		AuditEnabled:           policy.AuditEnabled,
		DeterministicOrder:     len(policy.SourceOrder) > 0,
	}
	for _, source := range report.Sources {
		if source.Enabled {
			report.Summary.EnabledSourceCount++
		}
		if source.Executable {
			report.Summary.ExecutableSourceCount++
		}
		if source.CircuitState.State == "open" {
			report.Summary.OpenCircuitCount++
		} else {
			report.Summary.ClosedCircuitCount++
		}
	}
	if db.DB != nil {
		if summary, err := db.GetIdentitySourceEventSummary(); err == nil {
			report.AuditSummary = summary
			report.Summary.LastObservedAt = summary.LastObservedAt
			report.Summary.LastDecision = summary.LastDecision
			report.Summary.LastReason = summary.LastReason
		}
		if cacheSummary, err := db.GetIdentitySourceCacheSummary(now); err == nil {
			report.CacheSummary = cacheSummary
		}
		if recent, err := db.ListIdentitySourceEvents("", "", 25); err == nil {
			report.Recent = recent
		}
	}

	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "Identity-source failover is disabled; portal fallback uses the legacy local then LDAP order."
	case db.DB == nil && policy.AuditEnabled:
		report.Status = "blocked"
		report.Message = "Identity-source failover audit is enabled but the database is not initialized."
	case report.Summary.ExecutableSourceCount == 0 && policy.Mode == "enforce" && policy.FailClosed:
		report.Status = "blocked"
		report.Message = "Identity-source failover is fail-closed but has no executable identity sources."
	case report.Summary.ExecutableSourceCount == 0:
		report.Status = "degraded"
		report.Message = "Identity-source failover has no executable identity sources."
	case report.Summary.OpenCircuitCount >= report.Summary.ExecutableSourceCount && policy.Mode == "enforce" && policy.FailClosed:
		report.Status = "blocked"
		report.Message = "All executable identity sources are circuit-open and fail-closed enforcement is active."
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "Identity-source failover is in monitor mode; decisions are audited while legacy behavior remains permissive."
	case !policy.FailClosed:
		report.Status = "degraded"
		report.Message = "Identity-source failover enforcement is active but fail_closed is disabled."
	default:
		report.Message = "Identity-source failover is enforceable with deterministic source order, circuit state, and audit evidence."
	}

	return report
}

func BuildSourcePlan(cfg *config.Config) []SourcePlan {
	policy := FailoverPolicyFromConfig(cfg)
	records := loadIdentitySourceRecords(cfg)
	byName := map[string]SourcePlan{}
	for _, record := range records {
		name := normalizeSourceName(record.Name)
		if name == "" {
			continue
		}
		sourceType := normalizeSourceType(record.Type, name)
		enabled := record.Enabled
		if sourceType == "local" {
			enabled = true
		}
		if sourceType == "ldap" && cfg != nil && cfg.LDAP.Enabled {
			enabled = true
		}
		if sourceType == "active_directory" && cfg != nil && cfg.ActiveDirectory.Enabled {
			enabled = true
		}
		plan := SourcePlan{
			Name:     name,
			Type:     sourceType,
			Enabled:  enabled,
			Priority: record.Priority,
		}
		plan.Executable, plan.Reason = sourceExecutable(cfg, plan)
		plan.CircuitState = circuitStateForSource(name, policy)
		if plan.CircuitState.State == "open" && policy.Mode == "enforce" {
			plan.Executable = false
			if plan.Reason == "" {
				plan.Reason = "circuit open"
			}
		}
		byName[name] = plan
	}

	ordered := []SourcePlan{}
	seen := map[string]struct{}{}
	for _, name := range policy.SourceOrder {
		name = normalizeSourceName(name)
		if name == "" {
			continue
		}
		source, ok := byName[name]
		if !ok {
			source = sourceFromName(cfg, name)
			source.CircuitState = circuitStateForSource(name, policy)
			if source.CircuitState.State == "open" && policy.Mode == "enforce" {
				source.Executable = false
				if source.Reason == "" {
					source.Reason = "circuit open"
				}
			}
		}
		ordered = append(ordered, source)
		seen[name] = struct{}{}
	}

	remaining := []SourcePlan{}
	for name, source := range byName {
		if _, ok := seen[name]; ok {
			continue
		}
		remaining = append(remaining, source)
	}
	sort.SliceStable(remaining, func(i, j int) bool {
		if remaining[i].Priority == remaining[j].Priority {
			return remaining[i].Name < remaining[j].Name
		}
		return remaining[i].Priority < remaining[j].Priority
	})
	return append(ordered, remaining...)
}

func RecordEvent(policy FailoverPolicy, event EventRecord) error {
	if !policy.AuditEnabled || db.DB == nil {
		return nil
	}
	now := time.Now().UTC()
	sourceName := normalizeSourceName(event.SourceName)
	if sourceName == "" {
		sourceName = "unknown"
	}
	sourceType := normalizeSourceType(event.SourceType, sourceName)
	circuitState := strings.ToLower(strings.TrimSpace(event.CircuitState))
	if circuitState == "" {
		circuitState = "closed"
	}
	return db.RecordIdentitySourceEvent(db.IdentitySourceEvent{
		ObservedAt:   now.Format(time.RFC3339),
		SourceName:   sourceName,
		SourceType:   sourceType,
		UsernameHash: db.HashIdentityUsername(event.Username),
		Decision:     strings.ToLower(strings.TrimSpace(event.Decision)),
		Reason:       strings.TrimSpace(event.Reason),
		LatencyMS:    event.LatencyMS,
		CircuitState: circuitState,
		CacheUsed:    event.CacheUsed,
	}, event.Details, policy.RetentionLimit)
}

func NormalizeSplitResultPolicy(value string) string {
	return normalizeSplitResultPolicy(value)
}

func normalizedSourceOrder(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		normalized := normalizeSourceName(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return []string{"local", "ldap-primary"}
	}
	return out
}

func loadIdentitySourceRecords(cfg *config.Config) []db.IdentitySourceRecord {
	if db.DB != nil {
		if records, err := db.ListIdentitySourceRecords(); err == nil && len(records) > 0 {
			return records
		}
	}
	return []db.IdentitySourceRecord{
		{Name: "local", Type: "local", Enabled: true, Priority: 0},
		{Name: "active-directory", Type: "active_directory", Enabled: cfg != nil && cfg.ActiveDirectory.Enabled, Priority: 5},
		{Name: "ldap-primary", Type: "ldap", Enabled: cfg != nil && cfg.LDAP.Enabled, Priority: 10},
	}
}

func sourceFromName(cfg *config.Config, name string) SourcePlan {
	sourceType := normalizeSourceType("", name)
	source := SourcePlan{
		Name:       name,
		Type:       sourceType,
		Enabled:    sourceType == "local" || (sourceType == "ldap" && cfg != nil && cfg.LDAP.Enabled) || (sourceType == "active_directory" && cfg != nil && cfg.ActiveDirectory.Enabled),
		Executable: false,
		Priority:   1000,
	}
	source.Executable, source.Reason = sourceExecutable(cfg, source)
	return source
}

func sourceExecutable(cfg *config.Config, source SourcePlan) (bool, string) {
	if !source.Enabled {
		return false, "source disabled"
	}
	switch source.Type {
	case "local":
		return true, ""
	case "ldap":
		if cfg == nil || !cfg.LDAP.Enabled {
			return false, "ldap disabled in config"
		}
		return true, ""
	case "active_directory":
		return activedirectory.SourceExecutable(cfg)
	default:
		return false, "source type is not executable by portal auth"
	}
}

func circuitStateForSource(name string, policy FailoverPolicy) db.IdentitySourceCircuitState {
	state := db.IdentitySourceCircuitState{SourceName: name, State: "closed"}
	if db.DB == nil || !policy.Enabled {
		return state
	}
	circuit, err := db.GetIdentitySourceCircuitState(name, policy.MaxFailures, policy.CircuitOpenSeconds, time.Now().UTC())
	if err != nil {
		return state
	}
	if circuit.State == "" {
		circuit.State = "closed"
	}
	return circuit
}

func normalizeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "enforce":
		return "enforce"
	default:
		return "monitor"
	}
}

func normalizeSplitResultPolicy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prefer_first", "prefer_success":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "deny"
	}
}

func normalizeSourceName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeSourceType(sourceType, name string) string {
	sourceType = strings.ToLower(strings.TrimSpace(sourceType))
	switch sourceType {
	case "local", "ldap", "active_directory":
		return sourceType
	}
	name = normalizeSourceName(name)
	if name == "local" || strings.HasPrefix(name, "local-") {
		return "local"
	}
	if name == "ldap" || strings.HasPrefix(name, "ldap") {
		return "ldap"
	}
	if name == "ad" || name == "active-directory" || name == "active_directory" ||
		strings.HasPrefix(name, "ad-") || strings.HasPrefix(name, "active-directory") || strings.HasPrefix(name, "active_directory") ||
		strings.Contains(name, "kerberos") || strings.Contains(name, "winbind") {
		return "active_directory"
	}
	return sourceType
}
