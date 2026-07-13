package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const (
	ReportSchemaVersion = 1
	DefaultFileBaseDir  = "/etc/aegisnas/secrets"
	DefaultMaxBytes     = 8192
)

type Options struct {
	Enabled                     bool     `json:"enabled"`
	Providers                   []string `json:"providers"`
	FileBaseDir                 string   `json:"file_base_dir"`
	MaxSecretBytes              int      `json:"max_secret_bytes"`
	AllowInline                 bool     `json:"allow_inline"`
	ProductionRequireReferences bool     `json:"production_require_references"`
}

type Resolver struct {
	options Options
}

type Ref struct {
	Raw      string
	Provider string
	Target   string
}

type Source struct {
	Field    string `json:"field"`
	Scope    string `json:"scope"`
	Provider string `json:"provider,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Inline   bool   `json:"inline"`
	Required bool   `json:"required"`
}

type StoredSource struct {
	Field    string
	Scope    string
	Ref      string
	Inline   bool
	Required bool
}

type Inspection struct {
	Field          string `json:"field"`
	Scope          string `json:"scope"`
	Provider       string `json:"provider,omitempty"`
	RefFingerprint string `json:"ref_fingerprint,omitempty"`
	Status         string `json:"status"`
	Inline         bool   `json:"inline"`
	Required       bool   `json:"required"`
	Message        string `json:"message"`
}

type ReportSummary struct {
	TotalSources       int `json:"total_sources"`
	ReferenceCount     int `json:"reference_count"`
	InlineCount        int `json:"inline_count"`
	MissingCount       int `json:"missing_count"`
	UnsupportedCount   int `json:"unsupported_count"`
	BlockedCount       int `json:"blocked_count"`
	ProviderReadyCount int `json:"provider_ready_count"`
	ProviderErrorCount int `json:"provider_error_count"`
}

type Report struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Status        string        `json:"status"`
	Providers     []string      `json:"providers"`
	Policy        Options       `json:"policy"`
	Summary       ReportSummary `json:"summary"`
	Sources       []Inspection  `json:"sources"`
}

func OptionsFromConfig(cfg *config.Config) Options {
	opts := Options{
		Enabled:                     true,
		Providers:                   []string{"env", "file"},
		FileBaseDir:                 DefaultFileBaseDir,
		MaxSecretBytes:              DefaultMaxBytes,
		AllowInline:                 true,
		ProductionRequireReferences: true,
	}
	if cfg == nil {
		return opts
	}
	raw := cfg.Security.Secrets
	if raw.Enabled || len(raw.Providers) > 0 || raw.FileBaseDir != "" || raw.MaxSecretBytes != 0 || raw.AllowInline || raw.ProductionRequireReferences {
		opts.Enabled = raw.Enabled
		opts.AllowInline = raw.AllowInline
		opts.ProductionRequireReferences = raw.ProductionRequireReferences
		if len(raw.Providers) > 0 {
			opts.Providers = append([]string(nil), raw.Providers...)
		}
		if strings.TrimSpace(raw.FileBaseDir) != "" {
			opts.FileBaseDir = strings.TrimSpace(raw.FileBaseDir)
		}
		if raw.MaxSecretBytes > 0 {
			opts.MaxSecretBytes = raw.MaxSecretBytes
		}
	}
	return NormalizeOptions(opts)
}

func NormalizeOptions(opts Options) Options {
	if len(opts.Providers) == 0 {
		opts.Providers = []string{"env", "file"}
	}
	for i, provider := range opts.Providers {
		opts.Providers[i] = strings.ToLower(strings.TrimSpace(provider))
	}
	if strings.TrimSpace(opts.FileBaseDir) == "" {
		opts.FileBaseDir = DefaultFileBaseDir
	}
	if opts.MaxSecretBytes <= 0 {
		opts.MaxSecretBytes = DefaultMaxBytes
	}
	return opts
}

func NewResolver(opts Options) *Resolver {
	return &Resolver{options: NormalizeOptions(opts)}
}

func (r *Resolver) Options() Options {
	if r == nil {
		return NormalizeOptions(Options{})
	}
	return r.options
}

func ParseRef(raw string) (Ref, error) {
	raw = strings.TrimSpace(raw)
	scheme, target, ok := strings.Cut(raw, ":")
	if !ok || strings.TrimSpace(scheme) == "" || strings.TrimSpace(target) == "" {
		return Ref{}, fmt.Errorf("secret ref must use env:NAME or file:NAME")
	}
	ref := Ref{Raw: raw, Provider: strings.ToLower(strings.TrimSpace(scheme)), Target: strings.TrimSpace(target)}
	switch ref.Provider {
	case "env":
		if !validEnvName(ref.Target) {
			return Ref{}, fmt.Errorf("invalid environment variable name %q", ref.Target)
		}
	case "file":
		if len(ref.Target) > 4096 || strings.ContainsAny(ref.Target, "\r\n\x00") {
			return Ref{}, errors.New("invalid file secret path")
		}
	default:
		return Ref{}, fmt.Errorf("unsupported secret provider %q", ref.Provider)
	}
	return ref, nil
}

func (r *Resolver) Resolve(ctx context.Context, raw string) (string, error) {
	ref, err := ParseRef(raw)
	if err != nil {
		return "", err
	}
	if r == nil {
		r = NewResolver(Options{})
	}
	if !r.providerAllowed(ref.Provider) {
		return "", fmt.Errorf("secret provider %q is not enabled", ref.Provider)
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	switch ref.Provider {
	case "env":
		value, ok := os.LookupEnv(ref.Target)
		if !ok || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("environment secret %s is not set", ref.Target)
		}
		return sanitizeSecretValue(value, r.options.MaxSecretBytes)
	case "file":
		return r.resolveFile(ref.Target)
	default:
		return "", fmt.Errorf("unsupported secret provider %q", ref.Provider)
	}
}

func ResolveConfiguredSecret(ctx context.Context, resolver *Resolver, field, inline, ref string) (string, error) {
	inline = strings.TrimRight(inline, "\r\n")
	ref = strings.TrimSpace(ref)
	if resolver == nil {
		resolver = NewResolver(Options{})
	}
	if ref != "" {
		value, err := resolver.Resolve(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		return value, nil
	}
	if inline == "" {
		return "", nil
	}
	opts := resolver.Options()
	if opts.Enabled && !opts.AllowInline {
		return "", fmt.Errorf("%s uses inline secret material while security.secrets.allow_inline is false", field)
	}
	value, err := sanitizeSecretValue(inline, opts.MaxSecretBytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}
	return value, nil
}

func (r *Resolver) Inspect(ctx context.Context, source Source) Inspection {
	inspection := Inspection{
		Field:    source.Field,
		Scope:    source.Scope,
		Inline:   source.Inline,
		Required: source.Required,
	}
	if source.Inline {
		inspection.Status = "inline"
		inspection.Message = "inline secret material is configured"
		return inspection
	}
	ref, err := ParseRef(source.Ref)
	if err != nil {
		inspection.Status = "unsupported"
		inspection.Message = err.Error()
		return inspection
	}
	inspection.Provider = ref.Provider
	inspection.RefFingerprint = Fingerprint(source.Ref)
	if r == nil {
		r = NewResolver(Options{})
	}
	if !r.providerAllowed(ref.Provider) {
		inspection.Status = "unsupported"
		inspection.Message = "provider is not enabled"
		return inspection
	}
	if _, err := r.Resolve(ctx, source.Ref); err != nil {
		inspection.Status = "missing"
		inspection.Message = err.Error()
		return inspection
	}
	inspection.Status = "ready"
	inspection.Message = "reference resolves without exposing secret material"
	return inspection
}

func BuildReport(ctx context.Context, cfg *config.Config, stored []StoredSource) Report {
	opts := OptionsFromConfig(cfg)
	resolver := NewResolver(opts)
	sources := DiscoverConfigSources(cfg)
	for _, item := range stored {
		if strings.TrimSpace(item.Ref) != "" {
			sources = append(sources, Source{Field: item.Field, Scope: item.Scope, Ref: item.Ref, Required: item.Required})
		}
		if item.Inline {
			sources = append(sources, Source{Field: item.Field, Scope: item.Scope, Inline: true, Required: item.Required})
		}
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "ready",
		Providers:     opts.Providers,
		Policy:        opts,
	}
	for _, source := range sources {
		inspection := resolver.Inspect(ctx, source)
		report.Sources = append(report.Sources, inspection)
		report.Summary.TotalSources++
		switch inspection.Status {
		case "ready":
			report.Summary.ReferenceCount++
			report.Summary.ProviderReadyCount++
		case "inline":
			report.Summary.InlineCount++
			if opts.ProductionRequireReferences {
				report.Summary.BlockedCount++
			}
		case "missing":
			report.Summary.ReferenceCount++
			report.Summary.MissingCount++
			report.Summary.ProviderErrorCount++
			if inspection.Required {
				report.Summary.BlockedCount++
			}
		case "unsupported":
			report.Summary.UnsupportedCount++
			report.Summary.ProviderErrorCount++
			report.Summary.BlockedCount++
		default:
			report.Summary.ProviderErrorCount++
		}
	}
	if report.Summary.BlockedCount > 0 {
		report.Status = "blocked"
	} else if report.Summary.InlineCount > 0 || report.Summary.ProviderErrorCount > 0 {
		report.Status = "degraded"
	}
	return report
}

func DiscoverConfigSources(cfg *config.Config) []Source {
	if cfg == nil {
		return nil
	}
	var sources []Source
	appendPair := func(field, scope, inline, ref string, required bool) {
		if strings.TrimSpace(ref) != "" {
			sources = append(sources, Source{Field: field, Scope: scope, Ref: strings.TrimSpace(ref), Required: required})
		}
		if strings.TrimSpace(inline) != "" {
			sources = append(sources, Source{Field: field, Scope: scope, Inline: true, Required: required})
		}
	}
	appendEnv := func(field, scope, env string, required bool) {
		env = strings.TrimSpace(env)
		if env != "" {
			sources = append(sources, Source{Field: field, Scope: scope, Ref: "env:" + env, Required: required})
		}
	}

	appendPair("database.dsn", "config", cfg.Database.DSN, cfg.Database.DSNRef, strings.EqualFold(strings.TrimSpace(cfg.Database.Backend), "postgres") || strings.EqualFold(strings.TrimSpace(cfg.Database.Backend), "postgresql"))
	appendPair("radius.secret", "config", cfg.Radius.Secret, cfg.Radius.SecretRef, false)
	for i, client := range cfg.Radius.Clients {
		appendPair(fmt.Sprintf("radius.clients[%d].secret", i), "config", client.Secret, client.SecretRef, strings.EqualFold(strings.TrimSpace(client.Transport), "udp") || strings.TrimSpace(client.Transport) == "")
	}
	for i, server := range cfg.Radius.Upstream.Servers {
		appendPair(fmt.Sprintf("radius.upstream.servers[%d].secret", i), "config", server.Secret, server.SecretRef, cfg.Radius.Upstream.Enabled && (strings.EqualFold(strings.TrimSpace(server.Transport), "udp") || strings.TrimSpace(server.Transport) == ""))
		appendEnv(fmt.Sprintf("radius.upstream.servers[%d].radsec.private_key_password_env", i), "config", server.RadSec.PrivateKeyPasswordEnv, false)
	}
	appendPair("ldap.bind_password", "config", cfg.LDAP.BindPassword, cfg.LDAP.BindPasswordRef, cfg.LDAP.Enabled)
	appendEnv("radius.radsec.private_key_password_env", "config", cfg.Radius.RadSec.PrivateKeyPasswordEnv, false)
	if strings.EqualFold(strings.TrimSpace(cfg.AILite.Mode), "full") {
		appendEnv("ailite.api_key_env", "config", cfg.AILite.APIKeyEnv, true)
	}
	appendEnv("onboarding.ca_enrollment_token_env", "config", cfg.Onboarding.CAEnrollmentTokenEnv, strings.EqualFold(strings.TrimSpace(cfg.Onboarding.CAMode), "external"))
	appendEnv("profiling.mdm_api_token_env", "config", cfg.Profiling.MDMAPITokenEnv, cfg.Profiling.MDMSyncEnabled)
	appendEnv("profiling.compliance_token_env", "config", cfg.Profiling.ComplianceTokenEnv, strings.TrimSpace(cfg.Profiling.ComplianceWebhook) != "")
	appendEnv("integrations.admin_sso.client_secret_env", "config", cfg.Integrations.AdminSSO.ClientSecretEnv, cfg.Integrations.AdminSSO.Enabled)
	appendEnv("integrations.siem.api_key_env", "config", cfg.Integrations.SIEM.APIKeyEnv, cfg.Integrations.SIEM.Enabled)
	appendEnv("integrations.controller.api_token_env", "config", cfg.Integrations.Controller.APITokenEnv, cfg.Integrations.Controller.Enabled)
	appendEnv("integrations.controller.api_password_env", "config", cfg.Integrations.Controller.APIPasswordEnv, cfg.Integrations.Controller.Enabled)
	appendEnv("integrations.controller.radius_secret_env", "config", cfg.Integrations.Controller.RadiusSecretEnv, cfg.Integrations.Controller.Enabled)
	appendEnv("high_availability.replication_signing_key_env", "config", cfg.HighAvailability.ReplicationSigningKeyEnv, cfg.HighAvailability.Enabled)
	appendEnv("high_availability.replication_encryption_key_env", "config", cfg.HighAvailability.ReplicationEncryptionKeyEnv, cfg.HighAvailability.Enabled)
	appendEnv("high_availability.witness_token_env", "config", cfg.HighAvailability.WitnessTokenEnv, cfg.HighAvailability.Enabled)
	appendEnv("high_availability.witness_signing_key_env", "config", cfg.HighAvailability.WitnessSigningKeyEnv, cfg.HighAvailability.Enabled)
	return sources
}

func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func (r *Resolver) providerAllowed(provider string) bool {
	if r == nil {
		return false
	}
	if !r.options.Enabled {
		return false
	}
	for _, candidate := range r.options.Providers {
		if strings.EqualFold(strings.TrimSpace(candidate), provider) {
			return true
		}
	}
	return false
}

func (r *Resolver) resolveFile(target string) (string, error) {
	path := target
	if !filepath.IsAbs(path) {
		path = filepath.Join(r.options.FileBaseDir, path)
	}
	cleanBase, err := filepath.Abs(r.options.FileBaseDir)
	if err != nil {
		return "", fmt.Errorf("resolve secret base directory: %w", err)
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve secret file: %w", err)
	}
	if !pathWithinBase(cleanPath, cleanBase) {
		return "", fmt.Errorf("secret file is outside %s", cleanBase)
	}
	if resolvedBase, err := filepath.EvalSymlinks(cleanBase); err == nil {
		if resolvedPath, err := filepath.EvalSymlinks(cleanPath); err == nil && !pathWithinBase(resolvedPath, resolvedBase) {
			return "", fmt.Errorf("secret file symlink resolves outside %s", resolvedBase)
		}
	}
	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, int64(r.options.MaxSecretBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	return sanitizeSecretValue(string(data), r.options.MaxSecretBytes)
}

func sanitizeSecretValue(value string, maxBytes int) (string, error) {
	if strings.ContainsRune(value, 0) {
		return "", errors.New("secret contains NUL byte")
	}
	value = strings.TrimRight(value, "\r\n")
	if len([]byte(value)) == 0 {
		return "", errors.New("secret is empty")
	}
	if len([]byte(value)) > maxBytes {
		return "", fmt.Errorf("secret exceeds %d bytes", maxBytes)
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("secret contains embedded newline")
	}
	return value, nil
}

func pathWithinBase(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	if strings.EqualFold(path, base) {
		return false
	}
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func validEnvName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
		if i == 0 && r >= '0' && r <= '9' {
			return false
		}
	}
	return true
}
