package adminapi

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	supportBundleVersion   = "1"
	supportBundleLogLines  = 250
	supportBundleTimeStamp = "20060102-150405Z"
)

type supportBundleManifest struct {
	BundleVersion     string   `json:"bundle_version"`
	GeneratedAt       string   `json:"generated_at"`
	Hostname          string   `json:"hostname"`
	ConfigPath        string   `json:"config_path"`
	DatabasePath      string   `json:"database_path"`
	SchemaVersion     int      `json:"schema_version"`
	DeploymentProfile string   `json:"deployment_profile,omitempty"`
	DeploymentForm    string   `json:"deployment_form,omitempty"`
	HARole            string   `json:"ha_role,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
}

type supportBundleSummary struct {
	BundleVersion      string   `json:"bundle_version"`
	GeneratedAt        string   `json:"generated_at"`
	ConfigPath         string   `json:"config_path"`
	DatabasePath       string   `json:"database_path"`
	DeploymentProfile  string   `json:"deployment_profile,omitempty"`
	DeploymentForm     string   `json:"deployment_form,omitempty"`
	HARole             string   `json:"ha_role,omitempty"`
	ContainsSecrets    bool     `json:"contains_secrets"`
	RedactionNote      string   `json:"redaction_note"`
	ArchiveEntries     []string `json:"archive_entries"`
	APICaptures        []string `json:"api_captures"`
	RuntimeEntries     []string `json:"runtime_entries"`
	SystemCaptures     []string `json:"system_captures"`
	LogCaptures        []string `json:"log_captures"`
	UpgradeDiagnostics []string `json:"upgrade_diagnostics"`
}

type supportBundleAPICapture struct {
	archivePath string
	requestPath string
	label       string
	handler     http.HandlerFunc
}

var (
	supportBundleNow        = time.Now
	supportBundleHostname   = os.Hostname
	supportBundleRunCommand = func(name string, args ...string) (string, error) {
		cmd := exec.Command(name, args...)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
)

func HandleDownloadSupportBundle(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	payload, filename, err := buildSupportBundle(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	audit(r, "download_support_bundle", filename, "downloaded")
}

func HandleGetSupportBundleSummary(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, buildSupportBundleSummary(cfg, supportBundleNow().UTC()))
}

func buildSupportBundle(cfg *config.Config) ([]byte, string, error) {
	if cfg == nil {
		return nil, "", fmt.Errorf("configuration not loaded")
	}

	generatedAt := supportBundleNow().UTC()
	hostname, err := supportBundleHostname()
	warnings := make([]string, 0)
	if err != nil {
		hostname = "unknown"
		warnings = append(warnings, fmt.Sprintf("hostname lookup failed: %v", err))
	}

	buffer := &bytes.Buffer{}
	archive := zip.NewWriter(buffer)

	addJSON := func(name string, payload any) error {
		entry, err := archive.Create(name)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		_, err = entry.Write(append(data, '\n'))
		return err
	}

	addText := func(name, content string) error {
		entry, err := archive.Create(name)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		_, err = entry.Write([]byte(content))
		return err
	}

	addCapturedHandler := func(name, path string, handler http.HandlerFunc) {
		data, err := captureSupportBundleHandler(path, handler)
		if err != nil {
			warnings = append(warnings, err.Error())
			_ = addText("errors/"+supportBundleErrorName(name)+".txt", err.Error())
			return
		}
		entry, createErr := archive.Create(name)
		if createErr != nil {
			warnings = append(warnings, fmt.Sprintf("create archive entry %s: %v", name, createErr))
			return
		}
		_, _ = entry.Write(append(data, '\n'))
	}

	runtimeStatuses, err := db.GetRuntimeStatuses()
	if err != nil {
		return nil, "", fmt.Errorf("load runtime statuses: %w", err)
	}
	recoveryState, err := CurrentNetworkRecoveryState()
	if err != nil {
		return nil, "", fmt.Errorf("load network recovery state: %w", err)
	}
	schemaVersion, err := currentSchemaVersion()
	if err != nil {
		return nil, "", fmt.Errorf("load schema version: %w", err)
	}

	for _, capture := range supportBundleAPICaptures() {
		addCapturedHandler(capture.archivePath, capture.requestPath, capture.handler)
	}

	summary := buildSupportBundleSummary(cfg, generatedAt)
	if err := addJSON("api/support-bundle-summary.json", summary); err != nil {
		return nil, "", fmt.Errorf("write support bundle summary: %w", err)
	}

	if err := addJSON("api/system-settings-redacted.json", redactSupportBundleValue(config.SettingsSnapshot())); err != nil {
		return nil, "", fmt.Errorf("write redacted settings: %w", err)
	}
	if err := addJSON("runtime/runtime-statuses.json", runtimeStatuses); err != nil {
		return nil, "", fmt.Errorf("write runtime statuses: %w", err)
	}
	if err := addJSON("runtime/network-recovery.json", map[string]any{
		"generated_at": generatedAt.Format(time.RFC3339),
		"state":        recoveryState,
	}); err != nil {
		return nil, "", fmt.Errorf("write network recovery state: %w", err)
	}
	if err := addText("system/schema-version.txt", fmt.Sprintf("%d", schemaVersion)); err != nil {
		return nil, "", fmt.Errorf("write schema version: %w", err)
	}
	if err := addText("system/config-path.txt", config.Path()); err != nil {
		return nil, "", fmt.Errorf("write config path: %w", err)
	}
	if err := addText("system/database-path.txt", cfg.Database.Path); err != nil {
		return nil, "", fmt.Errorf("write database path: %w", err)
	}
	if err := addText("system/database-backend.txt", cfg.Database.Backend); err != nil {
		return nil, "", fmt.Errorf("write database backend: %w", err)
	}

	for _, capture := range supportBundleCommandCaptures() {
		output, cmdErr := supportBundleRunCommand(capture.name, capture.args...)
		if cmdErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s failed: %v", capture.file, cmdErr))
			if strings.TrimSpace(output) == "" {
				output = fmt.Sprintf("command failed: %v", cmdErr)
			} else {
				output = fmt.Sprintf("%s\ncommand failed: %v", strings.TrimRight(output, "\r\n"), cmdErr)
			}
		}
		if err := addText(capture.file, output); err != nil {
			return nil, "", fmt.Errorf("write %s: %w", capture.file, err)
		}
	}

	for _, unit := range supportBundleJournalUnits() {
		output, journalErr := supportBundleRunCommand("journalctl", "-u", unit, "-n", fmt.Sprint(supportBundleLogLines), "--no-pager")
		if journalErr != nil {
			warnings = append(warnings, fmt.Sprintf("journalctl for %s failed: %v", unit, journalErr))
			if strings.TrimSpace(output) == "" {
				output = fmt.Sprintf("journal capture failed: %v", journalErr)
			} else {
				output = fmt.Sprintf("%s\njournal capture failed: %v", strings.TrimRight(output, "\r\n"), journalErr)
			}
		}
		if err := addText("logs/"+unit+".log", output); err != nil {
			return nil, "", fmt.Errorf("write log capture for %s: %w", unit, err)
		}
	}

	manifest := supportBundleManifest{
		BundleVersion:     supportBundleVersion,
		GeneratedAt:       generatedAt.Format(time.RFC3339),
		Hostname:          hostname,
		ConfigPath:        config.Path(),
		DatabasePath:      cfg.Database.Path,
		SchemaVersion:     schemaVersion,
		DeploymentProfile: cfg.Deployment.Profile,
		DeploymentForm:    cfg.Deployment.Form,
		HARole:            cfg.HighAvailability.Role,
		Warnings:          warnings,
	}
	if err := addJSON("manifest.json", manifest); err != nil {
		return nil, "", fmt.Errorf("write manifest: %w", err)
	}

	if err := archive.Close(); err != nil {
		return nil, "", fmt.Errorf("close archive: %w", err)
	}

	filename := fmt.Sprintf("aegisnas-support-bundle-%s.zip", generatedAt.Format(supportBundleTimeStamp))
	return buffer.Bytes(), filename, nil
}

type supportBundleCommandCapture struct {
	file string
	name string
	args []string
}

func supportBundleCommandCaptures() []supportBundleCommandCapture {
	return []supportBundleCommandCapture{
		{file: "system/ip-addr.txt", name: "ip", args: []string{"-br", "addr"}},
		{file: "system/ip-route.txt", name: "ip", args: []string{"route", "show"}},
		{file: "system/df.txt", name: "df", args: []string{"-h"}},
		{file: "system/nft-ruleset.txt", name: "nft", args: []string{"list", "ruleset"}},
		{file: "system/service-status.txt", name: "systemctl", args: []string{"--no-pager", "--full", "status", "aegis-admin-api", "aegis-gateway", "aegis-portal", "aegis-session", "aegis-policy", "aegis-radius", "dnsmasq", "freeradius", "nftables"}},
	}
}

func supportBundleAPICaptures() []supportBundleAPICapture {
	return []supportBundleAPICapture{
		{archivePath: "api/system-status.json", requestPath: "/api/v1/system/status", label: "System runtime status", handler: HandleGetSystemStatus},
		{archivePath: "api/session-history.json", requestPath: "/api/v1/system/session-history", label: "Session and accounting history", handler: HandleListSessionHistory},
		{archivePath: "api/session-analytics.json", requestPath: "/api/v1/system/session-analytics", label: "Session activity analytics", handler: HandleGetSessionAnalytics},
		{archivePath: "api/voucher-aging-analytics.json", requestPath: "/api/v1/system/voucher-aging-analytics", label: "Voucher stock aging analytics", handler: HandleGetVoucherAgingAnalytics},
		{archivePath: "api/voucher-expiry-analytics.json", requestPath: "/api/v1/system/voucher-expiry-analytics", label: "Voucher expiry analytics", handler: HandleGetVoucherExpiryAnalytics},
		{archivePath: "api/voucher-redemption-analytics.json", requestPath: "/api/v1/system/voucher-redemption-analytics", label: "Voucher redemption analytics", handler: HandleGetVoucherRedemptionAnalytics},
		{archivePath: "api/guest-lifecycle.json", requestPath: "/api/v1/system/guest-lifecycle", label: "Guest lifecycle report", handler: HandleGetGuestLifecycle},
		{archivePath: "api/guest-rejection-analytics.json", requestPath: "/api/v1/system/guest-rejection-analytics", label: "Guest rejection analytics", handler: HandleGetGuestRejectionAnalytics},
		{archivePath: "api/guest-conversion-analytics.json", requestPath: "/api/v1/system/guest-conversion-analytics", label: "Guest conversion analytics", handler: HandleGetGuestConversionAnalytics},
		{archivePath: "api/guest-invite-analytics.json", requestPath: "/api/v1/system/guest-invite-analytics", label: "Guest invite analytics", handler: HandleGetGuestInviteAnalytics},
		{archivePath: "api/guest-delivery-analytics.json", requestPath: "/api/v1/system/guest-delivery-analytics", label: "Guest delivery analytics", handler: HandleGetGuestDeliveryAnalytics},
		{archivePath: "api/guest-delivery-failures.json", requestPath: "/api/v1/system/guest-delivery-failures", label: "Guest delivery failures", handler: HandleGetGuestDeliveryFailures},
		{archivePath: "api/guest-sponsor-analytics.json", requestPath: "/api/v1/system/guest-sponsor-analytics", label: "Guest sponsor analytics", handler: HandleGetGuestSponsorAnalytics},
		{archivePath: "api/network-preview.json", requestPath: "/api/v1/system/network-preview", label: "Managed network preview", handler: HandlePreviewNetworkServices},
		{archivePath: "api/network-observability.json", requestPath: "/api/v1/system/network-observability", label: "Network observability", handler: HandleGetNetworkObservability},
		{archivePath: "api/network-apply-history.json", requestPath: "/api/v1/system/network-apply-history", label: "Network apply history", handler: HandleListNetworkApplyHistory},
		{archivePath: "api/dhcp-lease-history.json", requestPath: "/api/v1/system/dhcp-lease-history", label: "DHCP lease history", handler: HandleListDHCPLeaseHistory},
		{archivePath: "api/upstream-aaa-history.json", requestPath: "/api/v1/system/upstream-aaa-history", label: "Upstream AAA history", handler: HandleListUpstreamAAAHistory},
		{archivePath: "api/fallback-policy.json", requestPath: "/api/v1/system/fallback-policy", label: "Upstream fallback policy", handler: HandleGetFallbackPolicy},
		{archivePath: "api/identity-failover.json", requestPath: "/api/v1/system/identity-failover", label: "Identity source failover", handler: HandleGetIdentityFailover},
		{archivePath: "api/active-directory.json", requestPath: "/api/v1/system/active-directory", label: "Active Directory identity", handler: HandleGetActiveDirectory},
		{archivePath: "api/mfa.json", requestPath: "/api/v1/system/mfa", label: "MFA challenge and OTP state", handler: HandleGetMFA},
		{archivePath: "api/webauthn.json", requestPath: "/api/v1/system/webauthn", label: "Admin WebAuthn passkey state", handler: HandleGetAdminWebAuthn},
		{archivePath: "api/eap-framework.json", requestPath: "/api/v1/system/eap-framework", label: "EAP method framework", handler: HandleGetEAPFramework},
		{archivePath: "api/eap-framework-teap.json", requestPath: "/api/v1/system/eap-framework/teap", label: "TEAP method chaining", handler: HandleGetTEAPFramework},
		{archivePath: "api/eap-framework-machine-user.json", requestPath: "/api/v1/system/eap-framework/machine-user", label: "Machine and user authentication correlation", handler: HandleGetMachineUserFramework},
		{archivePath: "api/eap-framework-fast-pwd.json", requestPath: "/api/v1/system/eap-framework/fast-pwd", label: "EAP-FAST and EAP-PWD", handler: HandleGetFASTPWDFramework},
		{archivePath: "api/eap-framework-sim-aka.json", requestPath: "/api/v1/system/eap-framework/sim-aka", label: "EAP-SIM, EAP-AKA, and EAP-AKA-prime", handler: HandleGetSIMAKAFramework},
		{archivePath: "api/certificate-lifecycle.json", requestPath: "/api/v1/system/certificate-lifecycle", label: "Enterprise certificate lifecycle", handler: HandleGetCertificateLifecycle},
		{archivePath: "api/supplicant-lifecycle.json", requestPath: "/api/v1/system/supplicant-lifecycle", label: "Password and supplicant lifecycle", handler: HandleGetSupplicantLifecycle},
		{archivePath: "api/mab.json", requestPath: "/api/v1/system/mab", label: "MAC Authentication Bypass", handler: HandleGetMAB},
		{archivePath: "api/audit-history.json", requestPath: "/api/v1/system/audit-history", label: "Audit history", handler: HandleListAuditHistory},
		{archivePath: "api/integration-history.json", requestPath: "/api/v1/system/integration-history", label: "Integration history", handler: HandleListIntegrationHistory},
		{archivePath: "api/ha-history.json", requestPath: "/api/v1/system/ha/history", label: "HA history", handler: HandleListHAHistory},
		{archivePath: "api/upgrade-readiness.json", requestPath: "/api/v1/system/upgrade-readiness", label: "Upgrade readiness", handler: HandleGetUpgradeReadiness},
		{archivePath: "api/secret-providers.json", requestPath: "/api/v1/system/secret-providers", label: "Secret provider readiness", handler: HandleGetSecretProviders},
		{archivePath: "api/database.json", requestPath: "/api/v1/system/database", label: "Database data-plane readiness", handler: HandleGetDatabaseStatus},
		{archivePath: "api/openapi.json", requestPath: "/api/v1/openapi.json", label: "OpenAPI schema", handler: HandleGetOpenAPI},
	}
}

func supportBundleJournalUnits() []string {
	return []string{
		"aegis-admin-api",
		"aegis-gateway",
		"aegis-portal",
		"aegis-session",
		"aegis-policy",
		"aegis-radius",
		"dnsmasq",
		"freeradius",
		"nftables",
	}
}

func buildSupportBundleSummary(cfg *config.Config, generatedAt time.Time) supportBundleSummary {
	summary := supportBundleSummary{
		BundleVersion:      supportBundleVersion,
		GeneratedAt:        generatedAt.Format(time.RFC3339),
		ContainsSecrets:    true,
		RedactionNote:      "Secret-like fields are redacted, but *_env and *_ref references remain visible so operators can see which external secret handles the node expects.",
		ArchiveEntries:     []string{"manifest.json", "api/support-bundle-summary.json", "api/system-settings-redacted.json", "runtime/runtime-statuses.json", "runtime/network-recovery.json", "system/schema-version.txt", "system/config-path.txt", "system/database-path.txt", "system/database-backend.txt"},
		UpgradeDiagnostics: []string{"api/upgrade-readiness.json", "api/openapi.json"},
	}
	if cfg != nil {
		summary.ConfigPath = config.Path()
		summary.DatabasePath = cfg.Database.Path
		summary.DeploymentProfile = cfg.Deployment.Profile
		summary.DeploymentForm = cfg.Deployment.Form
		summary.HARole = cfg.HighAvailability.Role
	}

	for _, capture := range supportBundleAPICaptures() {
		summary.APICaptures = append(summary.APICaptures, capture.label)
		summary.ArchiveEntries = append(summary.ArchiveEntries, capture.archivePath)
	}
	summary.RuntimeEntries = []string{"runtime/runtime-statuses.json", "runtime/network-recovery.json"}
	for _, capture := range supportBundleCommandCaptures() {
		summary.SystemCaptures = append(summary.SystemCaptures, capture.file)
		summary.ArchiveEntries = append(summary.ArchiveEntries, capture.file)
	}
	for _, unit := range supportBundleJournalUnits() {
		logPath := "logs/" + unit + ".log"
		summary.LogCaptures = append(summary.LogCaptures, logPath)
		summary.ArchiveEntries = append(summary.ArchiveEntries, logPath)
	}
	return summary
}

func captureSupportBundleHandler(path string, handler http.HandlerFunc) ([]byte, error) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code < http.StatusOK || rec.Code >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%s returned %d: %s", path, rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	return indentSupportBundleJSON(rec.Body.Bytes())
}

func indentSupportBundleJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func currentSchemaVersion() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var version int
	err := db.DB.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return version, nil
}

func supportBundleErrorName(path string) string {
	replacer := strings.NewReplacer("/", "-", ".", "-", " ", "-")
	return replacer.Replace(strings.Trim(path, "/"))
}

func redactSupportBundleValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if shouldRedactSupportBundleKey(key) {
				out[key] = "<redacted>"
				continue
			}
			out[key] = redactSupportBundleValue(child)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, child := range typed {
			out[index] = redactSupportBundleValue(child)
		}
		return out
	default:
		return value
	}
}

func shouldRedactSupportBundleKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false
	}
	if strings.HasSuffix(lower, "_env") {
		return false
	}
	if strings.HasSuffix(lower, "_ref") {
		return false
	}
	sensitiveTokens := []string{
		"password",
		"secret",
		"token",
		"private_key",
		"passphrase",
		"dsn",
		"shared_key",
		"signing_key",
		"encryption_key",
	}
	for _, token := range sensitiveTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}
