package activedirectory

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

const SchemaVersion = 1

type Policy struct {
	SchemaVersion              int               `json:"schema_version"`
	Enabled                    bool              `json:"enabled"`
	Mode                       string            `json:"mode"`
	FailClosed                 bool              `json:"fail_closed"`
	Domain                     string            `json:"domain"`
	Realm                      string            `json:"realm"`
	NetBIOSDomain              string            `json:"netbios_domain,omitempty"`
	LDAPURLConfigured          bool              `json:"ldap_url_configured"`
	BaseDNConfigured           bool              `json:"base_dn_configured"`
	BindDNConfigured           bool              `json:"bind_dn_configured"`
	BindPasswordRefConfigured  bool              `json:"bind_password_ref_configured"`
	RequireLDAPS               bool              `json:"require_ldaps"`
	NestedGroups               bool              `json:"nested_groups"`
	AuthMethod                 string            `json:"auth_method"`
	DefaultRole                string            `json:"default_role,omitempty"`
	GroupRoleMappings          map[string]string `json:"group_role_mappings,omitempty"`
	RequestTimeoutSeconds      int               `json:"request_timeout_seconds"`
	GroupCacheTTLSeconds       int               `json:"group_cache_ttl_seconds"`
	HealthCheckIntervalSeconds int               `json:"health_check_interval_seconds"`
	ClockSkewSeconds           int               `json:"clock_skew_seconds"`
	AuditEnabled               bool              `json:"audit_enabled"`
	RetentionLimit             int               `json:"retention_limit"`
	KerberosEnabled            bool              `json:"kerberos_enabled"`
	KerberosKeytabConfigured   bool              `json:"kerberos_keytab_configured"`
	Krb5ConfigConfigured       bool              `json:"krb5_config_configured"`
	WinbindEnabled             bool              `json:"winbind_enabled"`
	WinbindJoinRequired        bool              `json:"winbind_join_required"`
	WinbindHelperConfigured    bool              `json:"winbind_helper_configured"`
}

type Summary struct {
	SourceExecutable    bool   `json:"source_executable"`
	SourceReason        string `json:"source_reason,omitempty"`
	DomainConfigured    bool   `json:"domain_configured"`
	RealmConfigured     bool   `json:"realm_configured"`
	LDAPConfigured      bool   `json:"ldap_configured"`
	KerberosReady       bool   `json:"kerberos_ready"`
	WinbindReady        bool   `json:"winbind_ready"`
	GroupCacheEnabled   bool   `json:"group_cache_enabled"`
	LastObservedAt      string `json:"last_observed_at,omitempty"`
	LastDecision        string `json:"last_decision,omitempty"`
	LastReason          string `json:"last_reason,omitempty"`
	LastHealthCheckedAt string `json:"last_health_checked_at,omitempty"`
	LastHealthStatus    string `json:"last_health_status,omitempty"`
	LastHealthComponent string `json:"last_health_component,omitempty"`
}

type Report struct {
	SchemaVersion int                                 `json:"schema_version"`
	GeneratedAt   string                              `json:"generated_at"`
	Enabled       bool                                `json:"enabled"`
	Status        string                              `json:"status"`
	Message       string                              `json:"message"`
	Policy        Policy                              `json:"policy"`
	Summary       Summary                             `json:"summary"`
	AuditSummary  db.ActiveDirectoryEventSummary      `json:"audit_summary"`
	CacheSummary  db.ActiveDirectoryGroupCacheSummary `json:"cache_summary"`
	HealthSummary db.ActiveDirectoryHealthSummary     `json:"health_summary"`
	Recent        []db.ActiveDirectoryEvent           `json:"recent,omitempty"`
	HealthRecent  []db.ActiveDirectoryHealthCheck     `json:"health_recent,omitempty"`
}

type Result struct {
	Accepted     bool
	Username     string
	Principal    string
	Role         string
	Groups       []string
	AuthMethod   string
	ReplyMessage string
	CacheUsed    bool
}

type verifierResult struct {
	Accepted bool
	NotFound bool
	Reason   string
	Groups   []string
}

type verifier interface {
	Verify(ctx context.Context, cfg *config.Config, profile identityProfile, password string) (verifierResult, error)
}

type identityProfile struct {
	RawUsername string
	ShortName   string
	UPN         string
	Principal   string
	Domain      string
	Realm       string
}

type commandRunner func(ctx context.Context, env []string, stdin, name string, args ...string) (string, error)

var (
	verifierMu       sync.RWMutex
	verifierOverride verifier
	authOverride     func(context.Context, *config.Config, string, string, string) (*Result, error)
	runner           commandRunner = runCommand
)

func SetAuthenticateForTest(fn func(context.Context, *config.Config, string, string, string) (*Result, error)) func() {
	verifierMu.Lock()
	previous := authOverride
	authOverride = fn
	verifierMu.Unlock()
	return func() {
		verifierMu.Lock()
		authOverride = previous
		verifierMu.Unlock()
	}
}

func SetVerifierForTest(v verifier) func() {
	verifierMu.Lock()
	previous := verifierOverride
	verifierOverride = v
	verifierMu.Unlock()
	return func() {
		verifierMu.Lock()
		verifierOverride = previous
		verifierMu.Unlock()
	}
}

func SetCommandRunnerForTest(next commandRunner) func() {
	verifierMu.Lock()
	previous := runner
	runner = next
	verifierMu.Unlock()
	return func() {
		verifierMu.Lock()
		runner = previous
		verifierMu.Unlock()
	}
}

func PolicyFromConfig(cfg *config.Config) Policy {
	raw := config.ActiveDirectoryConfig{}
	defaultRole := ""
	if cfg != nil {
		raw = config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
		defaultRole = strings.TrimSpace(cfg.Policy.DefaultRole)
	}
	if strings.TrimSpace(raw.DefaultRole) != "" {
		defaultRole = strings.TrimSpace(raw.DefaultRole)
	}
	mappings := map[string]string{}
	for group, role := range raw.GroupRoleMappings {
		group = strings.TrimSpace(group)
		role = strings.TrimSpace(role)
		if group != "" && role != "" {
			mappings[group] = role
		}
	}
	return Policy{
		SchemaVersion:              SchemaVersion,
		Enabled:                    raw.Enabled,
		Mode:                       normalizeMode(raw.Mode),
		FailClosed:                 raw.FailClosed,
		Domain:                     strings.TrimSpace(raw.Domain),
		Realm:                      strings.ToUpper(strings.TrimSpace(raw.Realm)),
		NetBIOSDomain:              strings.TrimSpace(raw.NetBIOSDomain),
		LDAPURLConfigured:          strings.TrimSpace(raw.LDAPURL) != "",
		BaseDNConfigured:           strings.TrimSpace(raw.BaseDN) != "",
		BindDNConfigured:           strings.TrimSpace(raw.BindDN) != "",
		BindPasswordRefConfigured:  strings.TrimSpace(raw.BindPasswordRef) != "",
		RequireLDAPS:               raw.RequireLDAPS,
		NestedGroups:               raw.NestedGroups,
		AuthMethod:                 normalizeAuthMethod(raw.AuthMethod),
		DefaultRole:                defaultRole,
		GroupRoleMappings:          mappings,
		RequestTimeoutSeconds:      raw.RequestTimeoutSeconds,
		GroupCacheTTLSeconds:       raw.GroupCacheTTLSeconds,
		HealthCheckIntervalSeconds: raw.HealthCheckIntervalSeconds,
		ClockSkewSeconds:           raw.ClockSkewSeconds,
		AuditEnabled:               raw.AuditEnabled,
		RetentionLimit:             raw.RetentionLimit,
		KerberosEnabled:            raw.Kerberos.Enabled,
		KerberosKeytabConfigured:   strings.TrimSpace(raw.Kerberos.KeytabPath) != "",
		Krb5ConfigConfigured:       strings.TrimSpace(raw.Kerberos.Krb5ConfigPath) != "",
		WinbindEnabled:             raw.Winbind.Enabled,
		WinbindJoinRequired:        raw.Winbind.DomainJoinRequired,
		WinbindHelperConfigured:    strings.TrimSpace(raw.Winbind.AuthHelperPath) != "",
	}
}

func BuildReport(cfg *config.Config) Report {
	now := time.Now().UTC()
	policy := PolicyFromConfig(cfg)
	executable, reason := SourceExecutable(cfg)
	report := Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Enabled:       policy.Enabled,
		Status:        "ready",
		Policy:        policy,
		Summary: Summary{
			SourceExecutable:  executable,
			SourceReason:      reason,
			DomainConfigured:  policy.Domain != "",
			RealmConfigured:   policy.Realm != "",
			LDAPConfigured:    policy.LDAPURLConfigured && policy.BaseDNConfigured,
			KerberosReady:     policy.KerberosEnabled && policy.Realm != "",
			WinbindReady:      policy.WinbindEnabled && policy.Domain != "",
			GroupCacheEnabled: policy.GroupCacheTTLSeconds > 0,
		},
	}
	if db.DB != nil {
		if summary, err := db.GetActiveDirectoryEventSummary(); err == nil {
			report.AuditSummary = summary
			report.Summary.LastObservedAt = summary.LastObservedAt
			report.Summary.LastDecision = summary.LastDecision
			report.Summary.LastReason = summary.LastReason
		}
		if cacheSummary, err := db.GetActiveDirectoryGroupCacheSummary(now); err == nil {
			report.CacheSummary = cacheSummary
		}
		if healthSummary, err := db.GetActiveDirectoryHealthSummary(); err == nil {
			report.HealthSummary = healthSummary
			report.Summary.LastHealthCheckedAt = healthSummary.LastCheckedAt
			report.Summary.LastHealthStatus = healthSummary.LastStatus
			report.Summary.LastHealthComponent = healthSummary.LastComponent
		}
		if recent, err := db.ListActiveDirectoryEvents("", "", 25); err == nil {
			report.Recent = recent
		}
		if healthRecent, err := db.ListActiveDirectoryHealthChecks("", 25); err == nil {
			report.HealthRecent = healthRecent
		}
	}
	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "Active Directory identity support is disabled."
	case !executable && policy.Mode == "enforce" && policy.FailClosed:
		report.Status = "blocked"
		report.Message = "Active Directory is fail-closed but not executable: " + reason
	case !executable:
		report.Status = "degraded"
		report.Message = "Active Directory is configured but not executable: " + reason
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "Active Directory is in monitor mode; decisions are observable but not production-enforced."
	case db.DB == nil && policy.AuditEnabled:
		report.Status = "blocked"
		report.Message = "Active Directory auditing is enabled but the database is not initialized."
	default:
		report.Message = "Active Directory identity support is enforceable with bounded audit, cache, and health state."
	}
	return report
}

func SourceExecutable(cfg *config.Config) (bool, string) {
	if cfg == nil {
		return false, "configuration not loaded"
	}
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	if !raw.Enabled {
		return false, "active_directory disabled in config"
	}
	if strings.TrimSpace(raw.Domain) == "" || strings.TrimSpace(raw.Realm) == "" {
		return false, "domain and realm are required"
	}
	method := normalizeAuthMethod(raw.AuthMethod)
	switch method {
	case "ldap_bind":
		if strings.TrimSpace(raw.LDAPURL) == "" || strings.TrimSpace(raw.BaseDN) == "" {
			return false, "ldap_url and base_dn are required for ldap_bind"
		}
		return true, ""
	case "kerberos":
		if !raw.Kerberos.Enabled {
			return false, "kerberos verifier is disabled"
		}
		return true, ""
	case "winbind_helper":
		if !raw.Winbind.Enabled || strings.TrimSpace(raw.Winbind.AuthHelperPath) == "" {
			return false, "winbind helper verifier is not configured"
		}
		return true, ""
	default:
		return false, "unsupported Active Directory auth method"
	}
}

func Authenticate(ctx context.Context, cfg *config.Config, sourceName, username, password string) (*Result, error) {
	verifierMu.RLock()
	override := authOverride
	verifierMu.RUnlock()
	if override != nil {
		return override(ctx, cfg, sourceName, username, password)
	}
	policy := PolicyFromConfig(cfg)
	if !policy.Enabled {
		return &Result{Accepted: false, ReplyMessage: "Active Directory disabled"}, nil
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		recordEvent(policy, sourceName, username, "", "skipped", "username and password are required", 0, nil, false, nil)
		return &Result{Accepted: false, ReplyMessage: "username and password are required"}, nil
	}
	executable, reason := SourceExecutable(cfg)
	if !executable {
		recordEvent(policy, sourceName, username, "", "skipped", reason, 0, nil, false, nil)
		return &Result{Accepted: false, ReplyMessage: reason}, nil
	}
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	profile := normalizeIdentity(username, raw)
	started := time.Now()
	v := verifierForPolicy(policy)
	verified, err := v.Verify(ctx, cfg, profile, password)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		recordEvent(policy, sourceName, username, profile.Principal, "failed", err.Error(), latency, nil, false, map[string]any{"auth_method": policy.AuthMethod})
		return nil, err
	}
	if !verified.Accepted {
		decision := "rejected"
		if verified.NotFound {
			decision = "not_found"
		}
		if strings.TrimSpace(verified.Reason) == "" {
			verified.Reason = "invalid credentials"
		}
		recordEvent(policy, sourceName, username, profile.Principal, decision, verified.Reason, latency, verified.Groups, false, map[string]any{"auth_method": policy.AuthMethod})
		return &Result{Accepted: false, Username: username, Principal: profile.Principal, AuthMethod: "portal-active-directory-" + policy.AuthMethod, ReplyMessage: verified.Reason}, nil
	}
	groups := uniqueSorted(verified.Groups)
	cacheUsed := false
	if len(groups) == 0 && db.DB != nil {
		if cached, ok, cacheErr := db.GetActiveDirectoryGroupCache(firstSource(sourceName), username, time.Now().UTC()); cacheErr == nil && ok {
			groups = cached.Groups
			cacheUsed = true
		}
	}
	role := roleForGroups(policy, groups)
	if db.DB != nil && policy.GroupCacheTTLSeconds > 0 {
		_ = db.UpsertActiveDirectoryGroupCache(firstSource(sourceName), username, profile.Principal, policy.Domain, policy.Realm, role, groups, policy.GroupCacheTTLSeconds, time.Now().UTC())
	}
	recordEvent(policy, sourceName, username, profile.Principal, "accepted", "credentials accepted", latency, groups, cacheUsed, map[string]any{"auth_method": policy.AuthMethod})
	return &Result{
		Accepted:     true,
		Username:     username,
		Principal:    profile.Principal,
		Role:         role,
		Groups:       groups,
		AuthMethod:   "portal-active-directory-" + policy.AuthMethod,
		ReplyMessage: "Active Directory credentials accepted",
		CacheUsed:    cacheUsed,
	}, nil
}

func CheckHealth(ctx context.Context, cfg *config.Config) ([]db.ActiveDirectoryHealthCheck, error) {
	policy := PolicyFromConfig(cfg)
	raw := config.ActiveDirectoryConfig{}
	if cfg != nil {
		raw = config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	}
	now := time.Now().UTC()
	checks := []db.ActiveDirectoryHealthCheck{}
	add := func(component, status, message string, started time.Time, details map[string]any) {
		latencyMS := int64(0)
		if !started.IsZero() {
			latencyMS = time.Since(started).Milliseconds()
		}
		check := db.ActiveDirectoryHealthCheck{
			CheckedAt: now.Format(time.RFC3339),
			Domain:    policy.Domain,
			Realm:     policy.Realm,
			Component: component,
			Status:    status,
			Message:   message,
			LatencyMS: latencyMS,
		}
		checks = append(checks, check)
		if db.DB != nil && policy.AuditEnabled {
			_ = db.RecordActiveDirectoryHealthCheck(check, details, policy.RetentionLimit)
		}
	}
	if !policy.Enabled {
		add("active_directory", "degraded", "Active Directory is disabled.", time.Time{}, nil)
		return checks, nil
	}
	if executable, reason := SourceExecutable(cfg); !executable {
		add("configuration", "blocked", reason, time.Time{}, nil)
	} else {
		add("configuration", "ok", "Active Directory configuration is executable.", time.Time{}, nil)
	}
	if policy.LDAPURLConfigured {
		started := time.Now()
		host := raw.LDAPURL
		if parsedHost := ldapHost(raw.LDAPURL); parsedHost != "" {
			host = parsedHost
		}
		if host == "" {
			add("ldap_dns", "blocked", "LDAP URL host could not be parsed.", started, nil)
		} else if _, err := net.LookupHost(host); err != nil {
			add("ldap_dns", "degraded", err.Error(), started, map[string]any{"host": host})
		} else {
			add("ldap_dns", "ok", "LDAP host resolves.", started, map[string]any{"host": host})
		}
	}
	if raw.Kerberos.Enabled {
		if strings.TrimSpace(raw.Kerberos.KeytabPath) != "" {
			started := time.Now()
			if _, err := os.Stat(raw.Kerberos.KeytabPath); err != nil {
				add("kerberos_keytab", "degraded", err.Error(), started, nil)
			} else {
				add("kerberos_keytab", "ok", "Kerberos keytab is present.", started, nil)
			}
		}
		started := time.Now()
		if _, err := exec.LookPath(raw.Kerberos.KinitPath); err != nil {
			add("kerberos_kinit", "degraded", err.Error(), started, map[string]any{"path": raw.Kerberos.KinitPath})
		} else {
			add("kerberos_kinit", "ok", "kinit binary is available.", started, map[string]any{"path": raw.Kerberos.KinitPath})
		}
	}
	if raw.Winbind.Enabled {
		started := time.Now()
		output, err := commandRunnerForUse()(ctx, nil, "", raw.Winbind.WbinfoPath, "-t")
		if err != nil {
			add("winbind_trust", "degraded", strings.TrimSpace(firstNonEmpty(output, err.Error())), started, map[string]any{"path": raw.Winbind.WbinfoPath})
		} else {
			add("winbind_trust", "ok", strings.TrimSpace(firstNonEmpty(output, "winbind trust check succeeded")), started, map[string]any{"path": raw.Winbind.WbinfoPath})
		}
	}
	return checks, nil
}

type ldapBindVerifier struct{}

func (ldapBindVerifier) Verify(ctx context.Context, cfg *config.Config, profile identityProfile, password string) (verifierResult, error) {
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	serviceConn, err := dialLDAP(ctx, raw.LDAPURL, raw.RequestTimeoutSeconds)
	if err != nil {
		return verifierResult{}, err
	}
	defer serviceConn.Close()
	if strings.TrimSpace(raw.BindDN) != "" {
		bindPassword, err := resolveADBindPassword(ctx, cfg, raw)
		if err != nil {
			return verifierResult{}, err
		}
		if err := serviceConn.Bind(raw.BindDN, bindPassword); err != nil {
			return verifierResult{}, fmt.Errorf("active directory service bind: %w", err)
		}
	}
	userDN, err := findUserDN(serviceConn, raw, profile)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return verifierResult{Accepted: false, NotFound: true, Reason: "user not found"}, nil
		}
		return verifierResult{}, err
	}
	userConn, err := dialLDAP(ctx, raw.LDAPURL, raw.RequestTimeoutSeconds)
	if err != nil {
		return verifierResult{}, err
	}
	defer userConn.Close()
	if err := userConn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return verifierResult{Accepted: false, Reason: "invalid credentials"}, nil
		}
		return verifierResult{}, fmt.Errorf("active directory user bind: %w", err)
	}
	groups, err := findGroups(serviceConn, raw, profile, userDN)
	if err != nil {
		return verifierResult{}, err
	}
	return verifierResult{Accepted: true, Reason: "credentials accepted", Groups: groups}, nil
}

type kerberosVerifier struct{}

func (kerberosVerifier) Verify(ctx context.Context, cfg *config.Config, profile identityProfile, password string) (verifierResult, error) {
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	cacheDir := strings.TrimSpace(raw.Kerberos.CredentialCacheDir)
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	tempDir, err := os.MkdirTemp(cacheDir, "aegisnas-krb5-*")
	if err != nil {
		return verifierResult{}, fmt.Errorf("create kerberos credential cache: %w", err)
	}
	defer os.RemoveAll(tempDir)
	ccache := filepath.Join(tempDir, "ccache")
	env := []string{"KRB5CCNAME=FILE:" + ccache}
	if strings.TrimSpace(raw.Kerberos.Krb5ConfigPath) != "" {
		env = append(env, "KRB5_CONFIG="+strings.TrimSpace(raw.Kerberos.Krb5ConfigPath))
	}
	output, err := commandRunnerForUse()(ctx, env, password+"\n", raw.Kerberos.KinitPath, profile.Principal)
	_, _ = commandRunnerForUse()(context.Background(), env, "", raw.Kerberos.KDestroyPath, "-c", ccache)
	if err != nil {
		reason := strings.TrimSpace(firstNonEmpty(output, "kerberos credentials rejected"))
		return verifierResult{Accepted: false, Reason: reason}, nil
	}
	groups, groupErr := ldapGroupsForProfile(ctx, cfg, profile)
	if groupErr != nil {
		return verifierResult{}, groupErr
	}
	return verifierResult{Accepted: true, Reason: "kerberos credentials accepted", Groups: groups}, nil
}

type winbindHelperVerifier struct{}

func (winbindHelperVerifier) Verify(ctx context.Context, cfg *config.Config, profile identityProfile, password string) (verifierResult, error) {
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	output, err := commandRunnerForUse()(ctx, nil, password+"\n", raw.Winbind.AuthHelperPath, "--domain", profile.Domain, "--username", profile.ShortName)
	if err != nil {
		reason := strings.TrimSpace(firstNonEmpty(output, "winbind helper rejected credentials"))
		return verifierResult{Accepted: false, Reason: reason}, nil
	}
	groups := parseHelperGroups(output)
	if len(groups) == 0 {
		ldapGroups, groupErr := ldapGroupsForProfile(ctx, cfg, profile)
		if groupErr != nil {
			return verifierResult{}, groupErr
		}
		groups = ldapGroups
	}
	return verifierResult{Accepted: true, Reason: "winbind helper accepted credentials", Groups: groups}, nil
}

func verifierForPolicy(policy Policy) verifier {
	verifierMu.RLock()
	override := verifierOverride
	verifierMu.RUnlock()
	if override != nil {
		return override
	}
	switch policy.AuthMethod {
	case "kerberos":
		return kerberosVerifier{}
	case "winbind_helper":
		return winbindHelperVerifier{}
	default:
		return ldapBindVerifier{}
	}
}

func commandRunnerForUse() commandRunner {
	verifierMu.RLock()
	current := runner
	verifierMu.RUnlock()
	return current
}

func runCommand(ctx context.Context, env []string, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func dialLDAP(ctx context.Context, ldapURL string, timeoutSeconds int) (*ldap.Conn, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSeconds) * time.Second}
	options := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ldapURL)), "ldaps://") {
		options = append(options, ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	type result struct {
		conn *ldap.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ldap.DialURL(ldapURL, options...)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("active directory ldap dial: %w", res.err)
		}
		return res.conn, nil
	}
}

func findUserDN(conn *ldap.Conn, raw config.ActiveDirectoryConfig, profile identityProfile) (string, error) {
	filter := renderLDAPFilter(raw.UserFilter, profile, "")
	req := ldap.NewSearchRequest(raw.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false, filter, []string{"dn"}, nil)
	sr, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("active directory user search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return "", errors.New("user not found")
	}
	return sr.Entries[0].DN, nil
}

func findGroups(conn *ldap.Conn, raw config.ActiveDirectoryConfig, profile identityProfile, userDN string) ([]string, error) {
	filter := renderLDAPFilter(raw.GroupFilter, profile, userDN)
	req := ldap.NewSearchRequest(raw.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"cn", "distinguishedName"}, nil)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("active directory group search: %w", err)
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		if cn := strings.TrimSpace(entry.GetAttributeValue("cn")); cn != "" {
			groups = append(groups, cn)
			continue
		}
		if dn := strings.TrimSpace(entry.GetAttributeValue("distinguishedName")); dn != "" {
			groups = append(groups, dn)
		}
	}
	return uniqueSorted(groups), nil
}

func ldapGroupsForProfile(ctx context.Context, cfg *config.Config, profile identityProfile) ([]string, error) {
	raw := config.EffectiveActiveDirectoryConfig(cfg.ActiveDirectory)
	if strings.TrimSpace(raw.LDAPURL) == "" || strings.TrimSpace(raw.BaseDN) == "" {
		return nil, nil
	}
	conn, err := dialLDAP(ctx, raw.LDAPURL, raw.RequestTimeoutSeconds)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if strings.TrimSpace(raw.BindDN) != "" {
		bindPassword, err := resolveADBindPassword(ctx, cfg, raw)
		if err != nil {
			return nil, err
		}
		if err := conn.Bind(raw.BindDN, bindPassword); err != nil {
			return nil, fmt.Errorf("active directory service bind: %w", err)
		}
	}
	userDN, err := findUserDN(conn, raw, profile)
	if err != nil {
		return nil, err
	}
	return findGroups(conn, raw, profile, userDN)
}

func resolveADBindPassword(ctx context.Context, cfg *config.Config, raw config.ActiveDirectoryConfig) (string, error) {
	return secrets.ResolveConfiguredSecret(ctx, secrets.NewResolver(secrets.OptionsFromConfig(cfg)), "active_directory.bind_password", raw.BindPassword, raw.BindPasswordRef)
}

func renderLDAPFilter(template string, profile identityProfile, userDN string) string {
	filter := strings.TrimSpace(template)
	replacements := map[string]string{
		"%s": ldap.EscapeFilter(profile.RawUsername),
		"%u": ldap.EscapeFilter(profile.ShortName),
		"%p": ldap.EscapeFilter(profile.UPN),
		"%D": ldap.EscapeFilter(userDN),
	}
	for token, value := range replacements {
		filter = strings.ReplaceAll(filter, token, value)
	}
	return filter
}

func normalizeIdentity(username string, raw config.ActiveDirectoryConfig) identityProfile {
	username = strings.TrimSpace(username)
	realm := strings.ToUpper(strings.TrimSpace(raw.Realm))
	domain := strings.TrimSpace(raw.NetBIOSDomain)
	if domain == "" {
		domain = strings.TrimSpace(raw.Domain)
	}
	short := username
	if before, after, ok := strings.Cut(username, `\`); ok {
		if strings.TrimSpace(before) != "" {
			domain = strings.TrimSpace(before)
		}
		short = strings.TrimSpace(after)
	}
	upn := username
	if before, after, ok := strings.Cut(username, "@"); ok {
		short = strings.TrimSpace(before)
		if strings.TrimSpace(after) != "" {
			upn = strings.TrimSpace(before) + "@" + strings.ToLower(strings.TrimSpace(after))
			realm = strings.ToUpper(strings.TrimSpace(after))
		}
	} else if realm != "" {
		upn = short + "@" + strings.ToLower(realm)
	}
	principal := upn
	if before, after, ok := strings.Cut(upn, "@"); ok {
		principal = before + "@" + strings.ToUpper(after)
	}
	return identityProfile{
		RawUsername: username,
		ShortName:   short,
		UPN:         upn,
		Principal:   principal,
		Domain:      domain,
		Realm:       realm,
	}
}

func recordEvent(policy Policy, sourceName, username, principal, decision, reason string, latencyMS int64, groups []string, cacheUsed bool, details any) {
	if !policy.AuditEnabled || db.DB == nil {
		return
	}
	_ = db.RecordActiveDirectoryEvent(db.ActiveDirectoryEvent{
		ObservedAt:    time.Now().UTC().Format(time.RFC3339),
		Domain:        policy.Domain,
		Realm:         policy.Realm,
		SourceName:    firstSource(sourceName),
		UsernameHash:  db.HashIdentityUsername(username),
		PrincipalHash: db.HashActiveDirectoryPrincipal(principal),
		AuthMethod:    policy.AuthMethod,
		Decision:      strings.ToLower(strings.TrimSpace(decision)),
		Reason:        strings.TrimSpace(reason),
		LatencyMS:     latencyMS,
		Role:          roleForGroups(policy, groups),
		Groups:        groups,
		CacheUsed:     cacheUsed,
	}, details, policy.RetentionLimit)
}

func roleForGroups(policy Policy, groups []string) string {
	if len(policy.GroupRoleMappings) > 0 {
		byGroup := map[string]string{}
		for group, role := range policy.GroupRoleMappings {
			byGroup[strings.ToLower(strings.TrimSpace(group))] = strings.TrimSpace(role)
		}
		for _, group := range groups {
			if role := byGroup[strings.ToLower(strings.TrimSpace(group))]; role != "" {
				return role
			}
		}
	}
	if strings.TrimSpace(policy.DefaultRole) != "" {
		return strings.TrimSpace(policy.DefaultRole)
	}
	return "guest"
}

func normalizeMode(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "enforce") {
		return "enforce"
	}
	return "monitor"
}

func normalizeAuthMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "kerberos":
		return "kerberos"
	case "winbind_helper":
		return "winbind_helper"
	default:
		return "ldap_bind"
	}
}

func firstSource(sourceName string) string {
	sourceName = strings.TrimSpace(sourceName)
	if sourceName == "" {
		return "active-directory"
	}
	return strings.ToLower(sourceName)
}

func uniqueSorted(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; !ok {
			seen[key] = value
		}
	}
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func parseHelperGroups(output string) []string {
	groups := []string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "GROUP=") {
			groups = append(groups, strings.TrimSpace(line[len("GROUP="):]))
		}
	}
	return uniqueSorted(groups)
}

func ldapHost(rawURL string) string {
	withoutScheme := rawURL
	if _, after, ok := strings.Cut(rawURL, "://"); ok {
		withoutScheme = after
	}
	host := withoutScheme
	if before, _, ok := strings.Cut(withoutScheme, "/"); ok {
		host = before
	}
	if strings.Contains(host, "@") {
		_, host, _ = strings.Cut(host, "@")
	}
	if strings.Contains(host, ":") {
		parsedHost, _, err := net.SplitHostPort(host)
		if err == nil {
			host = parsedHost
		}
	}
	return strings.Trim(host, "[]")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
