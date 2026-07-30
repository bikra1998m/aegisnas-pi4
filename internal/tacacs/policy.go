package tacacs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"go.uber.org/zap"
)

const ReportSchemaVersion = 1

type ClientIdentity struct {
	Name    string `json:"name,omitempty"`
	IP      string `json:"ip,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Model   string `json:"model,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	Known   bool   `json:"known"`
	Enabled bool   `json:"enabled"`
}

type CommandRequest struct {
	SessionID      uint32         `json:"session_id"`
	Username       string         `json:"username"`
	Role           string         `json:"role,omitempty"`
	Tenant         string         `json:"tenant,omitempty"`
	Groups         []string       `json:"groups,omitempty"`
	Client         ClientIdentity `json:"client"`
	Service        string         `json:"service,omitempty"`
	Port           string         `json:"port,omitempty"`
	RemoteAddress  string         `json:"remote_address,omitempty"`
	Command        string         `json:"command"`
	Args           []string       `json:"args,omitempty"`
	PrivilegeLevel int            `json:"privilege_level"`
	Authenticated  bool           `json:"authenticated"`
	EvaluatedAt    time.Time      `json:"evaluated_at,omitempty"`
}

type CommandDecision struct {
	SchemaVersion      int                      `json:"schema_version"`
	DecisionID         string                   `json:"decision_id"`
	EvaluatedAt        string                   `json:"evaluated_at"`
	Permit             bool                     `json:"permit"`
	Status             string                   `json:"status"`
	Reason             string                   `json:"reason"`
	MatchedCommandSet  string                   `json:"matched_command_set,omitempty"`
	PolicyEvaluationID string                   `json:"policy_evaluation_id,omitempty"`
	CommandHash        string                   `json:"command_hash"`
	Command            string                   `json:"command"`
	ResponseArgs       []string                 `json:"response_args,omitempty"`
	Warnings           []string                 `json:"warnings,omitempty"`
	PolicyResult       *policy.EvaluationResult `json:"policy_result,omitempty"`
}

type CommandSet struct {
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Enabled         bool     `json:"enabled"`
	DefaultAction   string   `json:"default_action"`
	Permit          []string `json:"permit"`
	Deny            []string `json:"deny"`
	Roles           []string `json:"roles,omitempty"`
	PrivilegeLevels []int    `json:"privilege_levels,omitempty"`
	Vendors         []string `json:"vendors,omitempty"`
	Tenants         []string `json:"tenants,omitempty"`
	Source          string   `json:"source"`
	ContentHash     string   `json:"content_hash,omitempty"`
}

type RuntimeSummary struct {
	ConfiguredClients int `json:"configured_clients"`
	EnabledClients    int `json:"enabled_clients"`
	ConfigCommandSets int `json:"config_command_sets"`
	DBCommandSets     int `json:"db_command_sets"`
	EffectiveSets     int `json:"effective_sets"`
	EnabledSets       int `json:"enabled_sets"`
	VendorProfiles    int `json:"vendor_profiles"`
}

type Report struct {
	SchemaVersion int                           `json:"schema_version"`
	GeneratedAt   string                        `json:"generated_at"`
	Enabled       bool                          `json:"enabled"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	Policy        config.TACACSConfig           `json:"policy"`
	Summary       RuntimeSummary                `json:"summary"`
	DBSummary     db.TACACSSummary              `json:"db_summary"`
	CommandSets   []CommandSet                  `json:"command_sets,omitempty"`
	RecentAuthz   []db.TACACSAuthorizationEvent `json:"recent_authorization,omitempty"`
	RecentAcct    []db.TACACSAccountingRecord   `json:"recent_accounting,omitempty"`
	Warnings      []string                      `json:"warnings,omitempty"`
	RFCs          []string                      `json:"rfcs"`
	Vendors       []string                      `json:"vendors"`
}

func BuildReport(cfg *config.Config, limit int) Report {
	effective := EffectiveConfig(nil)
	if cfg != nil {
		effective = EffectiveConfig(cfg)
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Enabled:       effective.Enabled,
		Status:        "ready",
		Message:       "TACACS+ command authorization, privilege control, and accounting evidence are available.",
		Policy:        redactTACACSConfig(effective),
		RFCs:          []string{"RFC 8907"},
		Vendors:       []string{"Cisco", "Juniper", "HPE", "Dell", "Brocade", "Extreme", "Arista"},
	}
	for _, client := range effective.Clients {
		report.Summary.ConfiguredClients++
		if client.Enabled {
			report.Summary.EnabledClients++
		}
	}
	report.Summary.ConfigCommandSets = len(effective.CommandSets)
	report.Summary.VendorProfiles = len(effective.VendorProfiles)
	sets, dbCount, warnings := EffectiveCommandSets(effective)
	report.CommandSets = sets
	report.Summary.DBCommandSets = dbCount
	report.Summary.EffectiveSets = len(sets)
	report.Warnings = append(report.Warnings, warnings...)
	for _, set := range sets {
		if set.Enabled {
			report.Summary.EnabledSets++
		}
	}
	if db.DB != nil {
		dbSummary, _ := db.SummarizeTACACS(effective.RetentionLimit)
		report.DBSummary = dbSummary
		if limit > 0 {
			authz, _ := db.ListTACACSAuthorizationEvents(limit)
			acct, _ := db.ListTACACSAccountingRecords(limit)
			report.RecentAuthz = authz
			report.RecentAcct = acct
		}
	}
	if !effective.Enabled {
		report.Status = "disabled"
		report.Message = "TACACS+ service is disabled by configuration."
		return report
	}
	if effective.RequireKnownClient && report.Summary.EnabledClients == 0 {
		report.Status = "blocked"
		report.Message = "TACACS+ requires known clients, but no enabled client is configured."
	}
	if effective.Secret == "" && effective.SecretRef == "" && report.Summary.EnabledClients == 0 {
		report.Status = "blocked"
		report.Message = "TACACS+ is enabled without any shared secret source."
	}
	if report.Summary.EnabledSets == 0 {
		report.Warnings = append(report.Warnings, "No enabled TACACS+ command set exists; authorization will fail closed.")
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if effective.AllowUnencrypted {
		report.Warnings = append(report.Warnings, "Unencrypted TACACS+ packets are allowed; use only in packet labs.")
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if effective.Mode != "enforce" && report.Status == "ready" {
		report.Status = "degraded"
		report.Warnings = append(report.Warnings, "tacacs.mode is monitor; command decisions are auditable but should be enforce for production.")
	}
	return report
}

func EvaluateCommand(ctx context.Context, cfg *config.Config, request CommandRequest, logger *zap.Logger) (CommandDecision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	effective := EffectiveConfig(cfg)
	now := request.EvaluatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	request = normalizeCommandRequest(request)
	decision := CommandDecision{
		SchemaVersion: ReportSchemaVersion,
		EvaluatedAt:   now.Format(time.RFC3339Nano),
		Command:       request.Command,
		CommandHash:   db.HashCommand(request.Command),
		Status:        "deny",
		Reason:        "default deny",
	}
	decision.DecisionID = commandDecisionID(request, now)
	if !effective.Enabled {
		decision.Reason = "TACACS+ is disabled"
		return decision, nil
	}
	if !request.Client.Known && effective.RequireKnownClient {
		decision.Reason = "unknown TACACS+ client"
		return decision, nil
	}
	if !request.Client.Enabled {
		decision.Reason = "TACACS+ client is disabled"
		return decision, nil
	}
	if request.Role == "" || request.Tenant == "" {
		role, tenant, found, err := db.LocalUserRole(request.Username)
		if err != nil {
			return decision, err
		}
		if found {
			if request.Role == "" {
				request.Role = role
			}
			if request.Tenant == "" {
				request.Tenant = tenant
			}
		}
	}
	if cfg != nil && cfg.Policy.TypedEngineEnabled {
		policyReq := commandPolicyRequest(request, now)
		result, err := policy.NewEngine(logger).EvaluateDetailed(&policyReq)
		if err != nil {
			return decision, err
		}
		decision.PolicyResult = result
		decision.PolicyEvaluationID = result.EvaluationID
		if !result.Decision.Allow && effective.FailClosed {
			decision.Reason = "typed policy denied TACACS+ command request"
			return decision, nil
		}
		if len(result.Conflicts) > 0 {
			decision.Warnings = append(decision.Warnings, result.Conflicts...)
		}
	}
	sets, _, warnings := EffectiveCommandSets(effective)
	decision.Warnings = append(decision.Warnings, warnings...)
	if len(sets) == 0 {
		decision.Reason = "no TACACS+ command sets configured"
		return decision, nil
	}
	for _, set := range sets {
		if !commandSetApplies(set, request) {
			continue
		}
		if patternMatchesAny(request.Command, set.Deny) {
			decision.Reason = "command matched deny pattern"
			decision.MatchedCommandSet = set.Name
			return decision, nil
		}
		if patternMatchesAny(request.Command, set.Permit) {
			decision.Permit = true
			decision.Status = "permit"
			decision.Reason = "command matched permit pattern"
			decision.MatchedCommandSet = set.Name
			decision.ResponseArgs = authorizationResponseArgs(request)
			return decision, nil
		}
		if set.DefaultAction == "permit" {
			decision.Permit = true
			decision.Status = "permit"
			decision.Reason = "command set default action permits command"
			decision.MatchedCommandSet = set.Name
			decision.ResponseArgs = authorizationResponseArgs(request)
			return decision, nil
		}
		if decision.MatchedCommandSet == "" {
			decision.MatchedCommandSet = set.Name
			decision.Reason = "command set default action denies command"
		}
	}
	return decision, nil
}

func EffectiveConfig(cfg *config.Config) config.TACACSConfig {
	effective := config.TACACSConfig{
		Enabled:              false,
		ListenAddress:        "0.0.0.0",
		Port:                 49,
		Mode:                 "monitor",
		FailClosed:           true,
		MaxPacketBytes:       65535,
		MaxArgs:              64,
		MaxCommandBytes:      512,
		MaxConnections:       256,
		IdleTimeoutSeconds:   300,
		ReadTimeoutSeconds:   15,
		AuditEnabled:         true,
		RetentionLimit:       10000,
		RequireKnownClient:   true,
		AllowUnencrypted:     false,
		AuthenticationSource: "local",
	}
	if cfg != nil {
		raw := cfg.TACACS
		effective.Enabled = raw.Enabled
		if strings.TrimSpace(raw.ListenAddress) != "" {
			effective.ListenAddress = strings.TrimSpace(raw.ListenAddress)
		}
		if raw.Port > 0 {
			effective.Port = raw.Port
		}
		if strings.TrimSpace(raw.Mode) != "" {
			effective.Mode = strings.ToLower(strings.TrimSpace(raw.Mode))
		}
		effective.FailClosed = raw.FailClosed
		effective.Secret = strings.TrimRight(raw.Secret, "\r\n")
		effective.SecretRef = strings.TrimSpace(raw.SecretRef)
		if raw.MaxPacketBytes > 0 {
			effective.MaxPacketBytes = raw.MaxPacketBytes
		}
		if raw.MaxArgs > 0 {
			effective.MaxArgs = raw.MaxArgs
		}
		if raw.MaxCommandBytes > 0 {
			effective.MaxCommandBytes = raw.MaxCommandBytes
		}
		if raw.MaxConnections > 0 {
			effective.MaxConnections = raw.MaxConnections
		}
		if raw.IdleTimeoutSeconds > 0 {
			effective.IdleTimeoutSeconds = raw.IdleTimeoutSeconds
		}
		if raw.ReadTimeoutSeconds > 0 {
			effective.ReadTimeoutSeconds = raw.ReadTimeoutSeconds
		}
		effective.AuditEnabled = raw.AuditEnabled
		if raw.RetentionLimit > 0 {
			effective.RetentionLimit = raw.RetentionLimit
		}
		effective.RequireKnownClient = raw.RequireKnownClient
		effective.AllowUnencrypted = raw.AllowUnencrypted
		if strings.TrimSpace(raw.AuthenticationSource) != "" {
			effective.AuthenticationSource = strings.ToLower(strings.TrimSpace(raw.AuthenticationSource))
		}
		effective.Clients = append([]config.TACACSClientConfig(nil), raw.Clients...)
		effective.CommandSets = append([]config.TACACSCommandSetConfig(nil), raw.CommandSets...)
		effective.VendorProfiles = append([]config.TACACSVendorProfile(nil), raw.VendorProfiles...)
	}
	return effective
}

func EffectiveCommandSets(cfg config.TACACSConfig) ([]CommandSet, int, []string) {
	byName := map[string]CommandSet{}
	var warnings []string
	for _, raw := range cfg.CommandSets {
		set, err := commandSetFromConfig(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("config command set %q ignored: %v", raw.Name, err))
			continue
		}
		byName[strings.ToLower(set.Name)] = set
	}
	dbSets, _ := db.ListTACACSCommandSets(false)
	dbCount := len(dbSets)
	for _, raw := range dbSets {
		set := CommandSet{
			Name:            raw.Name,
			Description:     raw.Description,
			Enabled:         raw.Enabled,
			DefaultAction:   raw.DefaultAction,
			Permit:          append([]string(nil), raw.Permit...),
			Deny:            append([]string(nil), raw.Deny...),
			Roles:           append([]string(nil), raw.Roles...),
			PrivilegeLevels: append([]int(nil), raw.PrivilegeLevels...),
			Vendors:         append([]string(nil), raw.Vendors...),
			Tenants:         append([]string(nil), raw.Tenants...),
			Source:          raw.Source,
			ContentHash:     raw.ContentHash,
		}
		byName[strings.ToLower(set.Name)] = set
	}
	out := make([]CommandSet, 0, len(byName))
	for _, set := range byName {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Enabled != out[j].Enabled {
			return out[i].Enabled
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, dbCount, warnings
}

func CommandFromArgs(args []string) string {
	var cmd string
	var cmdArgs []string
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "cmd":
			cmd = strings.TrimSpace(value)
		case "cmd-arg":
			value = strings.TrimSpace(value)
			if value != "" && value != "<cr>" {
				cmdArgs = append(cmdArgs, value)
			}
		}
	}
	parts := []string{}
	if cmd != "" {
		parts = append(parts, cmd)
	}
	parts = append(parts, cmdArgs...)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func ServiceFromArgs(args []string, fallback byte) string {
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "service") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	if fallback == AuthenServiceShell {
		return "shell"
	}
	return fmt.Sprintf("service-%d", fallback)
}

func PrivilegeFromArgs(args []string, fallback byte) int {
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "priv-lvl") {
			continue
		}
		level, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && level >= 0 && level <= 15 {
			return level
		}
	}
	level := int(fallback)
	if level < 0 {
		return 0
	}
	if level > 15 {
		return 15
	}
	return level
}

func commandSetFromConfig(raw config.TACACSCommandSetConfig) (CommandSet, error) {
	record := db.TACACSCommandSetRecord{
		Name:            raw.Name,
		Description:     raw.Description,
		Enabled:         raw.Enabled,
		DefaultAction:   raw.DefaultAction,
		Permit:          raw.Permit,
		Deny:            raw.Deny,
		Roles:           raw.Roles,
		PrivilegeLevels: raw.PrivilegeLevels,
		Vendors:         raw.Vendors,
		Tenants:         raw.Tenants,
		Source:          "config",
	}
	normalized, err := db.NormalizeTACACSCommandSetRecord(record)
	if err != nil {
		return CommandSet{}, err
	}
	return CommandSet{
		Name:            normalized.Name,
		Description:     normalized.Description,
		Enabled:         normalized.Enabled,
		DefaultAction:   normalized.DefaultAction,
		Permit:          normalized.Permit,
		Deny:            normalized.Deny,
		Roles:           normalized.Roles,
		PrivilegeLevels: normalized.PrivilegeLevels,
		Vendors:         normalized.Vendors,
		Tenants:         normalized.Tenants,
		Source:          "config",
		ContentHash:     normalized.ContentHash,
	}, nil
}

func commandSetApplies(set CommandSet, req CommandRequest) bool {
	if !set.Enabled {
		return false
	}
	if len(set.Roles) > 0 && !containsFold(set.Roles, req.Role) {
		return false
	}
	if len(set.PrivilegeLevels) > 0 && !containsInt(set.PrivilegeLevels, req.PrivilegeLevel) {
		return false
	}
	if len(set.Vendors) > 0 && !containsFold(set.Vendors, req.Client.Vendor) {
		return false
	}
	if len(set.Tenants) > 0 && !containsFold(set.Tenants, req.Tenant) && !containsFold(set.Tenants, req.Client.Tenant) {
		return false
	}
	return true
}

func patternMatchesAny(command string, patterns []string) bool {
	for _, pattern := range patterns {
		if commandGlobMatch(pattern, command) {
			return true
		}
	}
	return false
}

func commandGlobMatch(pattern, command string) bool {
	pattern = strings.TrimSpace(pattern)
	command = strings.TrimSpace(command)
	if pattern == "" || command == "" {
		return false
	}
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(command)
}

func authorizationResponseArgs(req CommandRequest) []string {
	service := strings.TrimSpace(req.Service)
	if service == "" {
		service = "shell"
	}
	args := []string{"service=" + service, fmt.Sprintf("priv-lvl=%d", req.PrivilegeLevel)}
	if req.Role != "" {
		args = append(args, "role="+req.Role)
	}
	return args
}

func commandPolicyRequest(req CommandRequest, now time.Time) policy.Request {
	return policy.Request{
		Username:       req.Username,
		Role:           req.Role,
		Tenant:         firstNonEmpty(req.Tenant, req.Client.Tenant),
		AuthMethod:     "tacacs",
		IdentitySource: "local",
		NASIdentifier:  req.Client.Name,
		NASIPAddress:   req.Client.IP,
		NASPortID:      req.Port,
		SourceIP:       req.Client.IP,
		Vendor:         req.Client.Vendor,
		Authenticated:  req.Authenticated,
		EvaluatedAt:    now,
		Attributes: map[string]string{
			"protocol":               "tacacs",
			"tacacs.command":         req.Command,
			"tacacs.command_hash":    db.HashCommand(req.Command),
			"tacacs.privilege_level": fmt.Sprint(req.PrivilegeLevel),
			"tacacs.service":         req.Service,
			"tacacs.port":            req.Port,
			"tacacs.remote_address":  req.RemoteAddress,
			"tacacs.client_known":    fmt.Sprint(req.Client.Known),
			"tacacs.client_enabled":  fmt.Sprint(req.Client.Enabled),
		},
	}
}

func normalizeCommandRequest(req CommandRequest) CommandRequest {
	req.Username = strings.TrimSpace(req.Username)
	req.Role = strings.TrimSpace(req.Role)
	req.Tenant = strings.TrimSpace(req.Tenant)
	req.Client.Name = strings.TrimSpace(req.Client.Name)
	req.Client.IP = strings.TrimSpace(req.Client.IP)
	req.Client.Vendor = strings.ToLower(strings.TrimSpace(req.Client.Vendor))
	req.Client.Model = strings.TrimSpace(req.Client.Model)
	req.Client.Tenant = strings.TrimSpace(req.Client.Tenant)
	req.Service = strings.ToLower(strings.TrimSpace(req.Service))
	req.Port = strings.TrimSpace(req.Port)
	req.RemoteAddress = strings.TrimSpace(req.RemoteAddress)
	if req.Command == "" {
		req.Command = CommandFromArgs(req.Args)
	}
	req.Command = strings.Join(strings.Fields(req.Command), " ")
	if req.PrivilegeLevel < 0 {
		req.PrivilegeLevel = 0
	}
	if req.PrivilegeLevel > 15 {
		req.PrivilegeLevel = 15
	}
	return req
}

func commandDecisionID(req CommandRequest, at time.Time) string {
	payload := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", req.SessionID, req.Username, req.Client.IP, req.Command, at.UTC().Format(time.RFC3339Nano))
	sum := sha256.Sum256([]byte(payload))
	return "tacacs-authz-" + hex.EncodeToString(sum[:])
}

func redactTACACSConfig(cfg config.TACACSConfig) config.TACACSConfig {
	cfg.Secret = ""
	for i := range cfg.Clients {
		cfg.Clients[i].Secret = ""
	}
	return cfg
}

func containsFold(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func jsonObject(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
