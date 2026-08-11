package enforcement

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

const (
	RuntimeFirewallSchemaVersion = 1
	runtimeFirewallTableName     = "aegis_runtime"
	runtimeFirewallComponent     = "runtime_firewall"
)

var runtimeFirewallExecCommand = exec.Command

type RuntimeFirewallSummary struct {
	TotalActiveSessions           int  `json:"total_active_sessions"`
	ManagedSessions               int  `json:"managed_sessions"`
	QuarantineSessions            int  `json:"quarantine_sessions"`
	IPv4Sessions                  int  `json:"ipv4_sessions"`
	IPv6Sessions                  int  `json:"ipv6_sessions"`
	PolicyCount                   int  `json:"policy_count"`
	RuleCount                     int  `json:"rule_count"`
	AppliedRuleCount              int  `json:"applied_rule_count"`
	BlockedRuleCount              int  `json:"blocked_rule_count"`
	Stateful                      bool `json:"stateful"`
	DefaultDropForManaged         bool `json:"default_drop_for_managed"`
	ExternalCertificationRequired bool `json:"external_certification_required"`
}

type RuntimeFirewallDiagnostic struct {
	Severity   string `json:"severity"`
	Code       string `json:"code"`
	SessionID  string `json:"session_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Message    string `json:"message"`
}

type RuntimeFirewallCompiledRule struct {
	SessionID  string `json:"session_id"`
	PolicyName string `json:"policy_name"`
	RuleID     string `json:"rule_id,omitempty"`
	Direction  string `json:"direction"`
	Family     string `json:"family"`
	Action     string `json:"action"`
	Line       string `json:"line"`
}

type RuntimeFirewallSessionPlan struct {
	SessionID        string                      `json:"session_id"`
	Username         string                      `json:"username,omitempty"`
	MAC              string                      `json:"mac,omitempty"`
	IPv4             string                      `json:"ipv4,omitempty"`
	IPv6             string                      `json:"ipv6,omitempty"`
	Role             string                      `json:"role,omitempty"`
	FilterID         string                      `json:"filter_id,omitempty"`
	VLAN             int                         `json:"vlan,omitempty"`
	ACLPolicyName    string                      `json:"acl_policy_name,omitempty"`
	Managed          bool                        `json:"managed"`
	Quarantined      bool                        `json:"quarantined"`
	PolicyFound      bool                        `json:"policy_found"`
	RuleCount        int                         `json:"rule_count"`
	AppliedRuleCount int                         `json:"applied_rule_count"`
	Diagnostics      []RuntimeFirewallDiagnostic `json:"diagnostics,omitempty"`
}

type RuntimeFirewallPlan struct {
	SchemaVersion        int                           `json:"schema_version"`
	Status               string                        `json:"status"`
	Message              string                        `json:"message"`
	GeneratedAt          string                        `json:"generated_at"`
	TableName            string                        `json:"table_name"`
	Ruleset              string                        `json:"ruleset"`
	RulesetFingerprint   string                        `json:"ruleset_fingerprint"`
	Summary              RuntimeFirewallSummary        `json:"summary"`
	Diagnostics          []RuntimeFirewallDiagnostic   `json:"diagnostics,omitempty"`
	Sessions             []RuntimeFirewallSessionPlan  `json:"sessions,omitempty"`
	Rules                []RuntimeFirewallCompiledRule `json:"rules,omitempty"`
	RFCs                 []string                      `json:"rfcs"`
	FreeRADIUSAttributes []string                      `json:"freeradius_attributes"`
}

type RuntimeFirewallApplyResult struct {
	SnapshotID         string              `json:"snapshot_id,omitempty"`
	PreviousSnapshotID string              `json:"previous_snapshot_id,omitempty"`
	EventID            string              `json:"event_id,omitempty"`
	Status             string              `json:"status"`
	Message            string              `json:"message"`
	Plan               RuntimeFirewallPlan `json:"plan"`
}

type RuntimeFirewallRollbackResult struct {
	SnapshotID         string              `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string              `json:"restored_snapshot_id,omitempty"`
	PreviousSnapshotID string              `json:"previous_snapshot_id,omitempty"`
	EventID            string              `json:"event_id,omitempty"`
	Status             string              `json:"status"`
	Message            string              `json:"message"`
	Plan               RuntimeFirewallPlan `json:"plan"`
}

type runtimeFirewallSession struct {
	SessionID     string
	Username      string
	MAC           string
	IP            string
	IPv6Address   string
	Role          string
	FilterID      string
	ACLPolicyName string
	VLAN          int
}

// PreviewRuntimeFirewall builds the active per-session local firewall plan without
// touching nftables. Quarantine remains fail-closed and stronger than ACL policy.
func PreviewRuntimeFirewall() (RuntimeFirewallPlan, error) {
	if db.DB == nil {
		plan := newRuntimeFirewallPlan()
		plan.Status = "ready"
		plan.Message = "Database is not initialized; no runtime firewall state is available."
		plan.Ruleset = buildRuntimeFirewallRuleset(nil)
		plan.RulesetFingerprint = fingerprintRuntimeFirewallRuleset(plan.Ruleset)
		return plan, nil
	}
	sessions, err := loadRuntimeFirewallSessions()
	if err != nil {
		return RuntimeFirewallPlan{}, err
	}
	return buildRuntimeFirewallPlan(sessions)
}

// PreviewAndRecordRuntimeFirewall builds a plan and records durable preview evidence.
func PreviewAndRecordRuntimeFirewall(actor string) (RuntimeFirewallPlan, string, error) {
	plan, err := PreviewRuntimeFirewall()
	if err != nil {
		return RuntimeFirewallPlan{}, "", err
	}
	eventID, err := recordRuntimeFirewallEvent("preview", "previewed", "", "", plan, actor, nil)
	return plan, eventID, err
}

// SyncRuntimeFirewall rebuilds the owned runtime nftables table from current active sessions.
func SyncRuntimeFirewall() error {
	if db.DB == nil {
		return nil
	}
	_, err := ApplyRuntimeFirewall("runtime-sync", "sync")
	return err
}

func ApplyRuntimeFirewall(actor string, operation string) (RuntimeFirewallApplyResult, error) {
	operation = strings.ToLower(strings.TrimSpace(operation))
	if operation == "" {
		operation = "apply"
	}
	if operation != "apply" && operation != "sync" {
		return RuntimeFirewallApplyResult{}, fmt.Errorf("runtime firewall operation %q is not supported", operation)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}

	plan, err := PreviewRuntimeFirewall()
	if err != nil {
		return RuntimeFirewallApplyResult{}, err
	}
	previousSnapshotID := activeRuntimeFirewallSnapshotID()
	if plan.Status == "blocked" {
		eventID, recordErr := recordRuntimeFirewallEvent(operation, "blocked", "", previousSnapshotID, plan, actor, map[string]any{"message": plan.Message})
		_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "down", plan.Message, runtimeFirewallStatusDetails(plan, "", previousSnapshotID, eventID))
		if recordErr != nil {
			return RuntimeFirewallApplyResult{}, recordErr
		}
		return RuntimeFirewallApplyResult{PreviousSnapshotID: previousSnapshotID, EventID: eventID, Status: "blocked", Message: plan.Message, Plan: plan}, errors.New(plan.Message)
	}

	if err := resetRuntimeFirewallTable(); err != nil {
		eventID, _ := recordRuntimeFirewallEvent(operation, "failed", "", previousSnapshotID, plan, actor, map[string]any{"error": err.Error()})
		_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "down", err.Error(), runtimeFirewallStatusDetails(plan, "", previousSnapshotID, eventID))
		return RuntimeFirewallApplyResult{PreviousSnapshotID: previousSnapshotID, EventID: eventID, Status: "failed", Message: err.Error(), Plan: plan}, err
	}
	if err := applyRuntimeFirewallRuleset(plan.Ruleset); err != nil {
		eventID, _ := recordRuntimeFirewallEvent(operation, "failed", "", previousSnapshotID, plan, actor, map[string]any{"error": err.Error()})
		_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "down", err.Error(), runtimeFirewallStatusDetails(plan, "", previousSnapshotID, eventID))
		return RuntimeFirewallApplyResult{PreviousSnapshotID: previousSnapshotID, EventID: eventID, Status: "failed", Message: err.Error(), Plan: plan}, err
	}

	status := "applied"
	runtimeStatus := "ok"
	if plan.Status == "degraded" {
		status = "degraded"
		runtimeStatus = "degraded"
	}
	now := time.Now().UTC()
	snapshotID, err := db.RecordRuntimeFirewallSnapshot(db.RuntimeFirewallSnapshotInput{
		Operation:              operation,
		Status:                 status,
		Active:                 true,
		SessionCount:           plan.Summary.TotalActiveSessions,
		ManagedSessionCount:    plan.Summary.ManagedSessions,
		QuarantineSessionCount: plan.Summary.QuarantineSessions,
		IPv4SessionCount:       plan.Summary.IPv4Sessions,
		IPv6SessionCount:       plan.Summary.IPv6Sessions,
		RuleCount:              plan.Summary.RuleCount,
		AppliedRuleCount:       plan.Summary.AppliedRuleCount,
		DiagnosticsJSON:        runtimeFirewallDiagnosticsJSON(plan.Diagnostics),
		RulesetFingerprint:     plan.RulesetFingerprint,
		RulesetText:            plan.Ruleset,
		PreviousSnapshotID:     previousSnapshotID,
		Actor:                  actor,
		AppliedAt:              &now,
	})
	if err != nil {
		return RuntimeFirewallApplyResult{}, err
	}
	eventID, err := recordRuntimeFirewallEvent(operation, status, snapshotID, previousSnapshotID, plan, actor, nil)
	if err != nil {
		return RuntimeFirewallApplyResult{}, err
	}
	_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, runtimeStatus, plan.Message, runtimeFirewallStatusDetails(plan, snapshotID, previousSnapshotID, eventID))
	return RuntimeFirewallApplyResult{
		SnapshotID:         snapshotID,
		PreviousSnapshotID: previousSnapshotID,
		EventID:            eventID,
		Status:             status,
		Message:            plan.Message,
		Plan:               plan,
	}, nil
}

func RollbackRuntimeFirewall(snapshotID string, actor string) (RuntimeFirewallRollbackResult, error) {
	if db.DB == nil {
		return RuntimeFirewallRollbackResult{}, fmt.Errorf("database is not initialized")
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	currentSnapshotID := activeRuntimeFirewallSnapshotID()
	target, found, err := selectRuntimeFirewallRollbackTarget(snapshotID, currentSnapshotID)
	if err != nil {
		return RuntimeFirewallRollbackResult{}, err
	}
	if !found {
		return RuntimeFirewallRollbackResult{}, fmt.Errorf("no runtime firewall rollback snapshot is available")
	}

	plan := newRuntimeFirewallPlan()
	plan.Status = "ready"
	plan.Message = "Runtime firewall rollback snapshot is ready."
	plan.Ruleset = target.RulesetText
	plan.RulesetFingerprint = target.RulesetFingerprint
	plan.Summary = RuntimeFirewallSummary{
		TotalActiveSessions:           target.SessionCount,
		ManagedSessions:               target.ManagedSessionCount,
		QuarantineSessions:            target.QuarantineSessionCount,
		IPv4Sessions:                  target.IPv4SessionCount,
		IPv6Sessions:                  target.IPv6SessionCount,
		RuleCount:                     target.RuleCount,
		AppliedRuleCount:              target.AppliedRuleCount,
		Stateful:                      true,
		DefaultDropForManaged:         true,
		ExternalCertificationRequired: true,
	}

	if err := resetRuntimeFirewallTable(); err != nil {
		eventID, _ := recordRuntimeFirewallEvent("rollback", "failed", target.SnapshotID, currentSnapshotID, plan, actor, map[string]any{"error": err.Error()})
		_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "down", err.Error(), runtimeFirewallStatusDetails(plan, target.SnapshotID, currentSnapshotID, eventID))
		return RuntimeFirewallRollbackResult{RestoredSnapshotID: target.SnapshotID, PreviousSnapshotID: currentSnapshotID, EventID: eventID, Status: "failed", Message: err.Error(), Plan: plan}, err
	}
	if err := applyRuntimeFirewallRuleset(target.RulesetText); err != nil {
		eventID, _ := recordRuntimeFirewallEvent("rollback", "failed", target.SnapshotID, currentSnapshotID, plan, actor, map[string]any{"error": err.Error()})
		_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "down", err.Error(), runtimeFirewallStatusDetails(plan, target.SnapshotID, currentSnapshotID, eventID))
		return RuntimeFirewallRollbackResult{RestoredSnapshotID: target.SnapshotID, PreviousSnapshotID: currentSnapshotID, EventID: eventID, Status: "failed", Message: err.Error(), Plan: plan}, err
	}

	now := time.Now().UTC()
	rollbackSnapshotID, err := db.RecordRuntimeFirewallSnapshot(db.RuntimeFirewallSnapshotInput{
		Operation:              "rollback",
		Status:                 "rolled_back",
		Active:                 true,
		SessionCount:           target.SessionCount,
		ManagedSessionCount:    target.ManagedSessionCount,
		QuarantineSessionCount: target.QuarantineSessionCount,
		IPv4SessionCount:       target.IPv4SessionCount,
		IPv6SessionCount:       target.IPv6SessionCount,
		RuleCount:              target.RuleCount,
		AppliedRuleCount:       target.AppliedRuleCount,
		DiagnosticsJSON:        target.DiagnosticsJSON,
		RulesetFingerprint:     target.RulesetFingerprint,
		RulesetText:            target.RulesetText,
		PreviousSnapshotID:     currentSnapshotID,
		Actor:                  actor,
		AppliedAt:              &now,
		RolledBackAt:           &now,
	})
	if err != nil {
		return RuntimeFirewallRollbackResult{}, err
	}
	eventID, err := recordRuntimeFirewallEvent("rollback", "rolled_back", rollbackSnapshotID, currentSnapshotID, plan, actor, map[string]any{"restored_snapshot_id": target.SnapshotID})
	if err != nil {
		return RuntimeFirewallRollbackResult{}, err
	}
	_ = db.UpsertRuntimeStatus(runtimeFirewallComponent, "ok", "Runtime firewall rollback applied", runtimeFirewallStatusDetails(plan, rollbackSnapshotID, currentSnapshotID, eventID))
	return RuntimeFirewallRollbackResult{
		SnapshotID:         rollbackSnapshotID,
		RestoredSnapshotID: target.SnapshotID,
		PreviousSnapshotID: currentSnapshotID,
		EventID:            eventID,
		Status:             "rolled_back",
		Message:            "Runtime firewall rollback applied",
		Plan:               plan,
	}, nil
}

func resetRuntimeFirewallTable() error {
	cmd := runtimeFirewallExecCommand("nft", "delete", "table", "inet", runtimeFirewallTableName)
	if out, err := cmd.CombinedOutput(); err != nil {
		output := strings.TrimSpace(string(out))
		if canIgnoreRuntimeFirewallDeleteError(output) {
			return nil
		}
		return fmt.Errorf("reset runtime firewall: %w\nOutput: %s", err, output)
	}
	return nil
}

func applyRuntimeFirewallRuleset(ruleset string) error {
	cmd := runtimeFirewallExecCommand("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply runtime firewall: %w\nOutput: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func buildRuntimeFirewallRuleset(ips []string) string {
	ipv4 := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr, ok := parseRuntimeFirewallAddress(ip)
		if !ok || !addr.Is4() {
			continue
		}
		ipv4 = append(ipv4, addr.String())
	}
	sort.Strings(ipv4)
	return renderRuntimeFirewallRuleset(ipv4, nil, nil)
}

func newRuntimeFirewallPlan() RuntimeFirewallPlan {
	return RuntimeFirewallPlan{
		SchemaVersion: RuntimeFirewallSchemaVersion,
		Status:        "ready",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		TableName:     runtimeFirewallTableName,
		Summary: RuntimeFirewallSummary{
			Stateful:                      true,
			DefaultDropForManaged:         true,
			ExternalCertificationRequired: true,
		},
		RFCs: []string{"RFC 2865", "RFC 2866", "RFC 5176"},
		FreeRADIUSAttributes: []string{
			"Filter-Id",
			"NAS-Filter-Rule",
			"AegisNAS-ACL-Name",
			"AegisNAS-ACL-Rule",
			"Cisco-AVPair",
			"Aruba-NAS-Filter-Rule",
			"IP-Downloadable-ACL-Rule",
			"Ip-Filter-Raw",
		},
	}
}

func buildRuntimeFirewallPlan(sessions []runtimeFirewallSession) (RuntimeFirewallPlan, error) {
	plan := newRuntimeFirewallPlan()
	plan.Summary.TotalActiveSessions = len(sessions)
	quarantineIPv4 := map[string]struct{}{}
	quarantineIPv6 := map[string]struct{}{}
	policyNames := map[string]struct{}{}
	policyCache := map[string]radius.StoredACLPolicy{}

	for _, session := range sessions {
		sessionPlan := RuntimeFirewallSessionPlan{
			SessionID:     session.SessionID,
			Username:      session.Username,
			MAC:           session.MAC,
			Role:          session.Role,
			FilterID:      session.FilterID,
			VLAN:          session.VLAN,
			ACLPolicyName: session.ACLPolicyName,
			Quarantined:   isQuarantined(session.Role, session.FilterID, session.VLAN),
		}
		addresses := runtimeFirewallSessionAddresses(session)
		for _, address := range addresses {
			if address.Is4() {
				if sessionPlan.IPv4 == "" {
					sessionPlan.IPv4 = address.String()
				}
				plan.Summary.IPv4Sessions++
			} else if address.Is6() {
				if sessionPlan.IPv6 == "" {
					sessionPlan.IPv6 = address.String()
				}
				plan.Summary.IPv6Sessions++
			}
		}
		if sessionPlan.Quarantined {
			plan.Summary.QuarantineSessions++
			for _, address := range addresses {
				if address.Is4() {
					quarantineIPv4[address.String()] = struct{}{}
				} else if address.Is6() {
					quarantineIPv6[address.String()] = struct{}{}
				}
			}
		}

		policyName := strings.TrimSpace(session.ACLPolicyName)
		if policyName == "" {
			plan.Sessions = append(plan.Sessions, sessionPlan)
			continue
		}
		sessionPlan.Managed = true
		plan.Summary.ManagedSessions++
		policyNames[strings.ToLower(policyName)] = struct{}{}
		if len(addresses) == 0 {
			diag := RuntimeFirewallDiagnostic{
				Severity:   "error",
				Code:       "session_address_missing",
				SessionID:  session.SessionID,
				PolicyName: policyName,
				Message:    "session has an ACL policy but no IPv4 or IPv6 address to enforce locally",
			}
			sessionPlan.Diagnostics = append(sessionPlan.Diagnostics, diag)
			plan.Diagnostics = append(plan.Diagnostics, diag)
			plan.Sessions = append(plan.Sessions, sessionPlan)
			continue
		}

		policy, ok := policyCache[strings.ToLower(policyName)]
		if !ok {
			loaded, found, err := radius.LoadACLPolicy(policyName)
			if err != nil {
				diag := RuntimeFirewallDiagnostic{Severity: "error", Code: "acl_policy_load_failed", SessionID: session.SessionID, PolicyName: policyName, Message: err.Error()}
				sessionPlan.Diagnostics = append(sessionPlan.Diagnostics, diag)
				plan.Diagnostics = append(plan.Diagnostics, diag)
				plan.Sessions = append(plan.Sessions, sessionPlan)
				continue
			}
			if !found {
				diag := RuntimeFirewallDiagnostic{Severity: "error", Code: "acl_policy_not_found", SessionID: session.SessionID, PolicyName: policyName, Message: "enabled ACL policy was not found"}
				sessionPlan.Diagnostics = append(sessionPlan.Diagnostics, diag)
				plan.Diagnostics = append(plan.Diagnostics, diag)
				plan.Sessions = append(plan.Sessions, sessionPlan)
				continue
			}
			policy = loaded
			policyCache[strings.ToLower(policyName)] = policy
		}
		sessionPlan.PolicyFound = true
		sessionPlan.RuleCount = len(policy.Rules)
		plan.Summary.RuleCount += len(policy.Rules)
		for _, policyDiag := range policy.ASTDiagnostics {
			if strings.EqualFold(policyDiag.Severity, "error") {
				diag := RuntimeFirewallDiagnostic{Severity: "error", Code: "acl_ast_diagnostic", SessionID: session.SessionID, PolicyName: policyName, Path: policyDiag.Path, Message: policyDiag.Message}
				sessionPlan.Diagnostics = append(sessionPlan.Diagnostics, diag)
				plan.Diagnostics = append(plan.Diagnostics, diag)
			}
		}
		for _, address := range addresses {
			for _, rule := range policy.Rules {
				compiled, diagnostics := compileRuntimeFirewallACLRule(session, policyName, address, rule)
				sessionPlan.Diagnostics = append(sessionPlan.Diagnostics, diagnostics...)
				plan.Diagnostics = append(plan.Diagnostics, diagnostics...)
				if len(compiled) == 0 {
					continue
				}
				sessionPlan.AppliedRuleCount += len(compiled)
				plan.Summary.AppliedRuleCount += len(compiled)
				plan.Rules = append(plan.Rules, compiled...)
			}
			defaultRules := runtimeFirewallDefaultDropRules(session.SessionID, policyName, address)
			sessionPlan.AppliedRuleCount += len(defaultRules)
			plan.Summary.AppliedRuleCount += len(defaultRules)
			plan.Rules = append(plan.Rules, defaultRules...)
		}
		plan.Sessions = append(plan.Sessions, sessionPlan)
	}
	plan.Summary.PolicyCount = len(policyNames)
	plan.Summary.BlockedRuleCount = blockedRuntimeFirewallDiagnostics(plan.Diagnostics)
	plan.Status, plan.Message = runtimeFirewallPlanStatus(plan)
	plan.Ruleset = renderRuntimeFirewallRuleset(sortedRuntimeFirewallSet(quarantineIPv4), sortedRuntimeFirewallSet(quarantineIPv6), plan.Rules)
	plan.RulesetFingerprint = fingerprintRuntimeFirewallRuleset(plan.Ruleset)
	return plan, nil
}

func renderRuntimeFirewallRuleset(quarantineIPv4, quarantineIPv6 []string, rules []RuntimeFirewallCompiledRule) string {
	var builder strings.Builder
	builder.WriteString("table inet ")
	builder.WriteString(runtimeFirewallTableName)
	builder.WriteString(" {\n")
	builder.WriteString("    set quarantine_ipv4 {\n")
	builder.WriteString("        type ipv4_addr\n")
	if len(quarantineIPv4) > 0 {
		builder.WriteString("        elements = { ")
		builder.WriteString(strings.Join(quarantineIPv4, ", "))
		builder.WriteString(" }\n")
	}
	builder.WriteString("    }\n")
	builder.WriteString("    set quarantine_ipv6 {\n")
	builder.WriteString("        type ipv6_addr\n")
	if len(quarantineIPv6) > 0 {
		builder.WriteString("        elements = { ")
		builder.WriteString(strings.Join(quarantineIPv6, ", "))
		builder.WriteString(" }\n")
	}
	builder.WriteString("    }\n")
	builder.WriteString("    chain forward {\n")
	builder.WriteString("        type filter hook forward priority -5; policy accept;\n")
	builder.WriteString("        ip saddr @quarantine_ipv4 drop\n")
	builder.WriteString("        ip daddr @quarantine_ipv4 drop\n")
	builder.WriteString("        ip6 saddr @quarantine_ipv6 drop\n")
	builder.WriteString("        ip6 daddr @quarantine_ipv6 drop\n")
	builder.WriteString("        ct state invalid drop\n")
	builder.WriteString("        ct state established,related accept\n")
	for _, rule := range rules {
		line := strings.TrimSpace(rule.Line)
		if line == "" {
			continue
		}
		builder.WriteString("        ")
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
	return builder.String()
}

func loadRuntimeFirewallSessions() ([]runtimeFirewallSession, error) {
	rows, err := db.DB.Query(`SELECT id, username, COALESCE(mac, ''), COALESCE(ip, ''),
			COALESCE(ipv6_address, ''), COALESCE(role, ''), COALESCE(filter_id, ''),
			COALESCE(acl_policy_name, ''), COALESCE(vlan, 0)
		FROM sessions
		WHERE end_time IS NULL
		ORDER BY start_time, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []runtimeFirewallSession
	for rows.Next() {
		var session runtimeFirewallSession
		if err := rows.Scan(&session.SessionID, &session.Username, &session.MAC, &session.IP, &session.IPv6Address, &session.Role, &session.FilterID, &session.ACLPolicyName, &session.VLAN); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func runtimeFirewallSessionAddresses(session runtimeFirewallSession) []netip.Addr {
	seen := map[string]struct{}{}
	var out []netip.Addr
	for _, value := range []string{session.IP, session.IPv6Address} {
		addr, ok := parseRuntimeFirewallAddress(value)
		if !ok {
			continue
		}
		key := addr.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func compileRuntimeFirewallACLRule(session runtimeFirewallSession, policyName string, sessionAddress netip.Addr, rule radius.ACLRule) ([]RuntimeFirewallCompiledRule, []RuntimeFirewallDiagnostic) {
	if rule.AddressFamily == "ipv4" && !sessionAddress.Is4() {
		return nil, nil
	}
	if rule.AddressFamily == "ipv6" && !sessionAddress.Is6() {
		return nil, nil
	}
	family := "ip"
	ruleFamily := "ipv4"
	if sessionAddress.Is6() {
		family = "ip6"
		ruleFamily = "ipv6"
	}
	protocol, protocolSelector, protoDiagnostics := runtimeFirewallProtocolSelector(rule.Protocol, sessionAddress)
	if len(protoDiagnostics) > 0 {
		return nil, withRuntimeFirewallRuleContext(protoDiagnostics, session.SessionID, policyName, rule.ID)
	}
	sourceSelector, sourceDiagnostics, sourceMatches := runtimeFirewallEndpointSelector(family, "saddr", rule.Source, sessionAddress, rule.Direction == "in")
	destinationSelector, destinationDiagnostics, destinationMatches := runtimeFirewallEndpointSelector(family, "daddr", rule.Destination, sessionAddress, rule.Direction == "out")
	diagnostics := append(sourceDiagnostics, destinationDiagnostics...)
	if !sourceMatches || !destinationMatches {
		diagnostics = append(diagnostics, RuntimeFirewallDiagnostic{
			Severity: "warning",
			Code:     "session_endpoint_mismatch",
			Message:  "ACL rule endpoint does not match this session address and was skipped",
		})
		return nil, withRuntimeFirewallRuleContext(diagnostics, session.SessionID, policyName, rule.ID)
	}
	portSelectors, portDiagnostics := runtimeFirewallPortSelectors(protocol, rule.SourcePort, rule.DestinationPort)
	if len(portDiagnostics) > 0 {
		return nil, withRuntimeFirewallRuleContext(append(diagnostics, portDiagnostics...), session.SessionID, policyName, rule.ID)
	}

	selector := sourceSelector
	if rule.Direction == "out" {
		selector = destinationSelector
	}
	parts := []string{selector}
	if rule.Direction == "in" && destinationSelector != "" {
		parts = append(parts, destinationSelector)
	}
	if rule.Direction == "out" && sourceSelector != "" {
		parts = append(parts, sourceSelector)
	}
	if protocolSelector != "" {
		parts = append(parts, protocolSelector)
	}
	parts = append(parts, portSelectors...)
	if rule.Log {
		parts = append(parts, "log", "prefix", quoteNftString("aegisnas "+safeNftCommentToken(session.SessionID)+" "))
	}
	action := "accept"
	if rule.Action == "deny" {
		action = "drop"
	}
	parts = append(parts, action, "comment", quoteNftString("aegisnas:"+safeNftCommentToken(session.SessionID)+":"+safeNftCommentToken(policyName)+":"+safeNftCommentToken(firstRuntimeFirewallString(rule.ID, strconv.Itoa(rule.Sequence)))))
	return []RuntimeFirewallCompiledRule{{
		SessionID:  session.SessionID,
		PolicyName: policyName,
		RuleID:     rule.ID,
		Direction:  rule.Direction,
		Family:     ruleFamily,
		Action:     rule.Action,
		Line:       strings.Join(parts, " "),
	}}, withRuntimeFirewallRuleContext(diagnostics, session.SessionID, policyName, rule.ID)
}

func runtimeFirewallDefaultDropRules(sessionID, policyName string, sessionAddress netip.Addr) []RuntimeFirewallCompiledRule {
	family := "ip"
	ruleFamily := "ipv4"
	if sessionAddress.Is6() {
		family = "ip6"
		ruleFamily = "ipv6"
	}
	commentBase := quoteNftString("aegisnas:" + safeNftCommentToken(sessionID) + ":" + safeNftCommentToken(policyName) + ":default")
	return []RuntimeFirewallCompiledRule{
		{SessionID: sessionID, PolicyName: policyName, RuleID: "default-in", Direction: "in", Family: ruleFamily, Action: "deny", Line: fmt.Sprintf("%s saddr %s drop comment %s", family, sessionAddress, commentBase)},
		{SessionID: sessionID, PolicyName: policyName, RuleID: "default-out", Direction: "out", Family: ruleFamily, Action: "deny", Line: fmt.Sprintf("%s daddr %s drop comment %s", family, sessionAddress, commentBase)},
	}
}

func runtimeFirewallProtocolSelector(protocol string, sessionAddress netip.Addr) (string, string, []RuntimeFirewallDiagnostic) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "ip", "ipv4", "ipv6", "any":
		return "ip", "", nil
	case "tcp", "udp":
		return strings.ToLower(strings.TrimSpace(protocol)), "meta l4proto " + strings.ToLower(strings.TrimSpace(protocol)), nil
	case "icmp":
		if sessionAddress.Is6() {
			return "icmpv6", "meta l4proto ipv6-icmp", nil
		}
		return "icmp", "ip protocol icmp", nil
	case "icmpv6", "ipv6-icmp":
		if !sessionAddress.Is6() {
			return "", "", []RuntimeFirewallDiagnostic{{Severity: "warning", Code: "protocol_family_mismatch", Message: "IPv6 ICMP rule does not apply to an IPv4 session address"}}
		}
		return "icmpv6", "meta l4proto ipv6-icmp", nil
	default:
		return "", "", []RuntimeFirewallDiagnostic{{Severity: "error", Code: "unsupported_protocol", Message: "protocol " + protocol + " is not supported by local nftables ACL compiler"}}
	}
}

func runtimeFirewallEndpointSelector(family, field, value string, sessionAddress netip.Addr, mustMatchSession bool) (string, []RuntimeFirewallDiagnostic, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "any") {
		if mustMatchSession {
			return fmt.Sprintf("%s %s %s", family, field, sessionAddress.String()), nil, true
		}
		return "", nil, true
	}
	prefix, ok := parseRuntimeFirewallPrefix(value)
	if !ok {
		return "", []RuntimeFirewallDiagnostic{{Severity: "error", Code: "invalid_address_selector", Message: "address selector " + value + " is not a valid address or prefix"}}, false
	}
	if sessionAddress.Is4() != prefix.Addr().Is4() {
		return "", []RuntimeFirewallDiagnostic{{Severity: "warning", Code: "address_family_mismatch", Message: "address selector " + value + " does not match session address family"}}, false
	}
	if mustMatchSession {
		if !prefix.Contains(sessionAddress) {
			return "", nil, false
		}
		return fmt.Sprintf("%s %s %s", family, field, sessionAddress.String()), nil, true
	}
	return fmt.Sprintf("%s %s %s", family, field, prefix.String()), nil, true
}

func runtimeFirewallPortSelectors(protocol, sourcePort, destinationPort string) ([]string, []RuntimeFirewallDiagnostic) {
	if strings.EqualFold(sourcePort, "any") {
		sourcePort = ""
	}
	if strings.EqualFold(destinationPort, "any") {
		destinationPort = ""
	}
	if sourcePort == "" && destinationPort == "" {
		return nil, nil
	}
	if protocol != "tcp" && protocol != "udp" {
		return nil, []RuntimeFirewallDiagnostic{{Severity: "error", Code: "port_requires_tcp_or_udp", Message: "source or destination ports require tcp or udp protocol"}}
	}
	var selectors []string
	if strings.TrimSpace(sourcePort) != "" {
		port, ok := normalizeRuntimeFirewallPort(sourcePort)
		if !ok {
			return nil, []RuntimeFirewallDiagnostic{{Severity: "error", Code: "invalid_source_port", Message: "source port " + sourcePort + " is invalid"}}
		}
		selectors = append(selectors, protocol+" sport "+port)
	}
	if strings.TrimSpace(destinationPort) != "" {
		port, ok := normalizeRuntimeFirewallPort(destinationPort)
		if !ok {
			return nil, []RuntimeFirewallDiagnostic{{Severity: "error", Code: "invalid_destination_port", Message: "destination port " + destinationPort + " is invalid"}}
		}
		selectors = append(selectors, protocol+" dport "+port)
	}
	return selectors, nil
}

func normalizeRuntimeFirewallPort(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if strings.Contains(value, "-") {
		parts := strings.Split(value, "-")
		if len(parts) != 2 {
			return "", false
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start < 0 || end < 0 || start > 65535 || end > 65535 || start > end {
			return "", false
		}
		return fmt.Sprintf("%d-%d", start, end), true
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 0 || port > 65535 {
		return "", false
	}
	return strconv.Itoa(port), true
}

func parseRuntimeFirewallAddress(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Addr{}, false
		}
		return prefix.Addr(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func parseRuntimeFirewallPrefix(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	return netip.PrefixFrom(addr, 128), true
}

func sortedRuntimeFirewallSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func runtimeFirewallPlanStatus(plan RuntimeFirewallPlan) (string, string) {
	errors := 0
	warnings := 0
	for _, diag := range plan.Diagnostics {
		switch strings.ToLower(diag.Severity) {
		case "error":
			errors++
		case "warning":
			warnings++
		}
	}
	if errors > 0 {
		return "blocked", fmt.Sprintf("Runtime firewall plan is blocked by %d error diagnostic(s).", errors)
	}
	if warnings > 0 {
		return "degraded", fmt.Sprintf("Runtime firewall plan is ready with %d warning diagnostic(s).", warnings)
	}
	if plan.Summary.ManagedSessions == 0 && plan.Summary.QuarantineSessions == 0 {
		return "ready", "Runtime firewall has no active managed or quarantined sessions."
	}
	return "ready", fmt.Sprintf("Runtime firewall plan covers %d managed and %d quarantined session(s).", plan.Summary.ManagedSessions, plan.Summary.QuarantineSessions)
}

func blockedRuntimeFirewallDiagnostics(diagnostics []RuntimeFirewallDiagnostic) int {
	count := 0
	for _, diag := range diagnostics {
		if strings.EqualFold(diag.Severity, "error") {
			count++
		}
	}
	return count
}

func withRuntimeFirewallRuleContext(diagnostics []RuntimeFirewallDiagnostic, sessionID, policyName, ruleID string) []RuntimeFirewallDiagnostic {
	for idx := range diagnostics {
		diagnostics[idx].SessionID = firstRuntimeFirewallString(diagnostics[idx].SessionID, sessionID)
		diagnostics[idx].PolicyName = firstRuntimeFirewallString(diagnostics[idx].PolicyName, policyName)
		diagnostics[idx].RuleID = firstRuntimeFirewallString(diagnostics[idx].RuleID, ruleID)
	}
	return diagnostics
}

func runtimeFirewallDiagnosticsJSON(diagnostics []RuntimeFirewallDiagnostic) string {
	if len(diagnostics) == 0 {
		return "[]"
	}
	data, err := json.Marshal(diagnostics)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func recordRuntimeFirewallEvent(operation, status, snapshotID, previousSnapshotID string, plan RuntimeFirewallPlan, actor string, details map[string]any) (string, error) {
	if details == nil {
		details = map[string]any{}
	}
	details["ruleset_fingerprint"] = plan.RulesetFingerprint
	details["table_name"] = plan.TableName
	detailsJSON, _ := json.Marshal(details)
	return db.RecordRuntimeFirewallEvent(db.RuntimeFirewallEventInput{
		Operation:              operation,
		Status:                 status,
		SnapshotID:             snapshotID,
		PreviousSnapshotID:     previousSnapshotID,
		SessionCount:           plan.Summary.TotalActiveSessions,
		ManagedSessionCount:    plan.Summary.ManagedSessions,
		QuarantineSessionCount: plan.Summary.QuarantineSessions,
		IPv4SessionCount:       plan.Summary.IPv4Sessions,
		IPv6SessionCount:       plan.Summary.IPv6Sessions,
		RuleCount:              plan.Summary.RuleCount,
		AppliedRuleCount:       plan.Summary.AppliedRuleCount,
		DiagnosticsJSON:        runtimeFirewallDiagnosticsJSON(plan.Diagnostics),
		DetailsJSON:            string(detailsJSON),
		Actor:                  actor,
	})
}

func activeRuntimeFirewallSnapshotID() string {
	active, found, err := db.GetActiveRuntimeFirewallSnapshot()
	if err != nil || !found {
		return ""
	}
	return active.SnapshotID
}

func selectRuntimeFirewallRollbackTarget(snapshotID, currentSnapshotID string) (db.RuntimeFirewallSnapshot, bool, error) {
	snapshotID = strings.TrimSpace(snapshotID)
	if snapshotID != "" {
		return db.GetRuntimeFirewallSnapshot(snapshotID)
	}
	snapshots, err := db.ListRuntimeFirewallSnapshots(100)
	if err != nil {
		return db.RuntimeFirewallSnapshot{}, false, err
	}
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == "" || snapshot.SnapshotID == currentSnapshotID || strings.TrimSpace(snapshot.RulesetText) == "" {
			continue
		}
		switch snapshot.Status {
		case "applied", "degraded", "rolled_back":
			return snapshot, true, nil
		}
	}
	return db.RuntimeFirewallSnapshot{}, false, nil
}

func runtimeFirewallStatusDetails(plan RuntimeFirewallPlan, snapshotID, previousSnapshotID, eventID string) map[string]any {
	return map[string]any{
		"schema_version":           RuntimeFirewallSchemaVersion,
		"table":                    runtimeFirewallTableName,
		"snapshot_id":              snapshotID,
		"previous_snapshot_id":     previousSnapshotID,
		"event_id":                 eventID,
		"ruleset_fingerprint":      plan.RulesetFingerprint,
		"managed_sessions":         plan.Summary.ManagedSessions,
		"quarantine_sessions":      plan.Summary.QuarantineSessions,
		"ipv4_sessions":            plan.Summary.IPv4Sessions,
		"ipv6_sessions":            plan.Summary.IPv6Sessions,
		"applied_rule_count":       plan.Summary.AppliedRuleCount,
		"diagnostic_count":         len(plan.Diagnostics),
		"stateful":                 true,
		"default_drop_for_managed": true,
	}
}

func fingerprintRuntimeFirewallRuleset(ruleset string) string {
	sum := sha256.Sum256([]byte(ruleset))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstRuntimeFirewallString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func quoteNftString(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func safeNftCommentToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "none"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case strings.ContainsRune("._:-", r):
			builder.WriteRune(r)
		default:
			builder.WriteRune('_')
		}
	}
	if builder.Len() == 0 {
		return "none"
	}
	return builder.String()
}

func canIgnoreRuntimeFirewallDeleteError(output string) bool {
	normalized := strings.ToLower(strings.TrimSpace(output))
	return strings.Contains(normalized, "no such file or directory")
}

func quarantinedIPs() ([]string, error) {
	rows, err := db.DB.Query(`SELECT COALESCE(ip, ''), COALESCE(role, ''), COALESCE(filter_id, ''), COALESCE(vlan, 0)
		FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	var ips []string
	for rows.Next() {
		var (
			ip       string
			role     string
			filterID string
			vlan     int
		)
		if err := rows.Scan(&ip, &role, &filterID, &vlan); err != nil {
			return nil, err
		}
		if !isQuarantined(role, filterID, vlan) {
			continue
		}
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed == nil || parsed.To4() == nil {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func isQuarantined(role, filterID string, vlan int) bool {
	if vlan == 99 {
		return true
	}
	role = strings.ToLower(strings.TrimSpace(role))
	filterID = strings.ToLower(strings.TrimSpace(filterID))
	return strings.Contains(role, "quarantine") || strings.Contains(filterID, "quarantine")
}

func SessionLooksQuarantined(role, filterID string, vlan int) bool {
	return isQuarantined(role, filterID, vlan)
}

func CountQuarantinedSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions
		WHERE end_time IS NULL
		AND (
			COALESCE(vlan, 0) = 99
			OR LOWER(COALESCE(role, '')) LIKE '%quarantine%'
			OR LOWER(COALESCE(filter_id, '')) LIKE '%quarantine%'
		)`).Scan(&count)
	return count, err
}

func CountActiveSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE end_time IS NULL`).Scan(&count)
	return count, err
}

func CountSessionsByAuthMethod() (map[string]int, error) {
	if db.DB == nil {
		return map[string]int{}, nil
	}
	rows, err := db.DB.Query(`SELECT COALESCE(auth_method, 'unknown'), COUNT(*) FROM sessions
		WHERE end_time IS NULL GROUP BY COALESCE(auth_method, 'unknown')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	methods := map[string]int{}
	for rows.Next() {
		var (
			method string
			count  int
		)
		if err := rows.Scan(&method, &count); err != nil {
			return nil, err
		}
		methods[method] = count
	}
	return methods, rows.Err()
}

func CountPendingChanges() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM config_staging WHERE applied = 0`).Scan(&count)
	return count, err
}

func CountUnacknowledgedAlerts() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acknowledged = 0`).Scan(&count)
	return count, err
}

func CountUsers() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM local_users`).Scan(&count)
	return count, err
}

func CountEnabledRadiusClients() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE enabled = 1`).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}
