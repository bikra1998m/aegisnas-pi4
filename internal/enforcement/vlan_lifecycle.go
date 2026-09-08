package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/wireless"
)

const (
	VLANLifecycleSchemaVersion = 1

	vlanLifecycleComponent = "vlan_lifecycle"
	defaultBridgePrefix    = "br-vlan"
)

var safeInterfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

type VLANLifecycleSummary struct {
	VLANCount                  int `json:"vlan_count"`
	BridgeCount                int `json:"bridge_count"`
	SubinterfaceCount          int `json:"subinterface_count"`
	StaticVLANCount            int `json:"static_vlan_count"`
	DynamicVLANCount           int `json:"dynamic_vlan_count"`
	TaggedVLANCount            int `json:"tagged_vlan_count"`
	HostapdVLANEntryCount      int `json:"hostapd_vlan_entry_count"`
	HostapdDynamicSSIDCount    int `json:"hostapd_dynamic_ssid_count"`
	HostapdFallbackSSIDCount   int `json:"hostapd_fallback_ssid_count"`
	HostapdFailClosedSSIDCount int `json:"hostapd_fail_closed_ssid_count"`
	CommandCount               int `json:"command_count"`
	CleanupCommandCount        int `json:"cleanup_command_count"`
	RollbackCommandCount       int `json:"rollback_command_count"`
	DiagnosticCount            int `json:"diagnostic_count"`
}

type VLANLifecycleDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Source   string `json:"source,omitempty"`
	Field    string `json:"field,omitempty"`
	VLAN     int    `json:"vlan,omitempty"`
}

type VLANLifecycleIntent struct {
	VLAN       int      `json:"vlan"`
	Name       string   `json:"name,omitempty"`
	Purpose    string   `json:"purpose,omitempty"`
	Bridge     string   `json:"bridge"`
	Subif      string   `json:"subinterface"`
	Dynamic    bool     `json:"dynamic"`
	Tagged     bool     `json:"tagged"`
	Hostapd    bool     `json:"hostapd"`
	Sources    []string `json:"sources"`
	Attributes []string `json:"attributes,omitempty"`
}

type VLANBridgePlan struct {
	Name    string `json:"name"`
	VLAN    int    `json:"vlan"`
	Owner   string `json:"owner"`
	Dynamic bool   `json:"dynamic"`
}

type VLANSubinterfacePlan struct {
	Name            string `json:"name"`
	ParentInterface string `json:"parent_interface"`
	VLAN            int    `json:"vlan"`
	Bridge          string `json:"bridge"`
	Tagged          bool   `json:"tagged"`
	Owner           string `json:"owner"`
}

type HostapdVLANEntry struct {
	VLAN      int    `json:"vlan"`
	Bridge    string `json:"bridge"`
	Interface string `json:"interface,omitempty"`
}

type HostapdDynamicVLANBinding struct {
	SSID                string                    `json:"ssid"`
	AuthMode            string                    `json:"auth_mode"`
	DynamicVLANMode     int                       `json:"dynamic_vlan_mode"`
	DynamicVLANModeName string                    `json:"dynamic_vlan_mode_name"`
	FallbackVLAN        int                       `json:"fallback_vlan,omitempty"`
	FallbackBridge      string                    `json:"fallback_bridge,omitempty"`
	VLANFilePath        string                    `json:"vlan_file_path"`
	VLANEntryCount      int                       `json:"vlan_entry_count"`
	Status              string                    `json:"status"`
	RadiusAttributes    []string                  `json:"radius_attributes"`
	Diagnostics         []VLANLifecycleDiagnostic `json:"diagnostics,omitempty"`
}

type VLANLifecyclePlan struct {
	SchemaVersion          int                         `json:"schema_version"`
	GeneratedAt            string                      `json:"generated_at"`
	Status                 string                      `json:"status"`
	Message                string                      `json:"message"`
	ParentInterface        string                      `json:"parent_interface"`
	HostapdVLANFilePath    string                      `json:"hostapd_vlan_file_path"`
	HostapdVLANFileText    string                      `json:"hostapd_vlan_file_text"`
	HostapdVLANFileSHA256  string                      `json:"hostapd_vlan_file_sha256,omitempty"`
	Summary                VLANLifecycleSummary        `json:"summary"`
	Diagnostics            []VLANLifecycleDiagnostic   `json:"diagnostics"`
	Intents                []VLANLifecycleIntent       `json:"intents"`
	Bridges                []VLANBridgePlan            `json:"bridges"`
	Subinterfaces          []VLANSubinterfacePlan      `json:"subinterfaces"`
	HostapdVLANEntries     []HostapdVLANEntry          `json:"hostapd_vlan_entries"`
	HostapdBindings        []HostapdDynamicVLANBinding `json:"hostapd_bindings,omitempty"`
	Commands               [][]string                  `json:"commands"`
	CommandPreview         []string                    `json:"command_preview"`
	CleanupCommands        [][]string                  `json:"cleanup_commands,omitempty"`
	CleanupCommandPreview  []string                    `json:"cleanup_command_preview,omitempty"`
	RollbackCommands       [][]string                  `json:"rollback_commands,omitempty"`
	RollbackCommandPreview []string                    `json:"rollback_command_preview,omitempty"`
	PlanFingerprint        string                      `json:"plan_fingerprint"`
	RFCs                   []string                    `json:"rfcs"`
	FreeRADIUSAttributes   []string                    `json:"freeradius_attributes"`
}

type VLANLifecycleApplyResult struct {
	Operation          string            `json:"operation"`
	Status             string            `json:"status"`
	SnapshotID         string            `json:"snapshot_id,omitempty"`
	PreviousSnapshotID string            `json:"previous_snapshot_id,omitempty"`
	EventID            string            `json:"event_id,omitempty"`
	Plan               VLANLifecyclePlan `json:"plan"`
	AppliedAt          string            `json:"applied_at,omitempty"`
	Message            string            `json:"message"`
}

type VLANLifecycleRollbackResult struct {
	Operation          string            `json:"operation"`
	Status             string            `json:"status"`
	SnapshotID         string            `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string            `json:"restored_snapshot_id,omitempty"`
	PreviousSnapshotID string            `json:"previous_snapshot_id,omitempty"`
	EventID            string            `json:"event_id,omitempty"`
	Plan               VLANLifecyclePlan `json:"plan"`
	RolledBackAt       string            `json:"rolled_back_at,omitempty"`
	Message            string            `json:"message"`
}

type vlanIntentBuilder struct {
	VLAN       int
	Name       string
	Purpose    string
	Bridge     string
	Dynamic    bool
	Tagged     bool
	Hostapd    bool
	Sources    []string
	Attributes []string
}

func PreviewVLANLifecycle(cfg *config.Config) (VLANLifecyclePlan, error) {
	if cfg == nil {
		return VLANLifecyclePlan{}, fmt.Errorf("config is required")
	}
	roles, policies, err := loadVLANPolicySources()
	if err != nil {
		return VLANLifecyclePlan{}, err
	}
	return buildVLANLifecyclePlan(cfg, roles, policies)
}

func PreviewAndRecordVLANLifecycle(cfg *config.Config, actor string) (VLANLifecyclePlan, string, error) {
	plan, err := PreviewVLANLifecycle(cfg)
	if err != nil {
		return VLANLifecyclePlan{}, "", err
	}
	eventID, err := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, "preview", vlanPlanStatusToEventStatus(plan.Status), "", "", actor, nil))
	if err != nil {
		return VLANLifecyclePlan{}, "", err
	}
	return plan, eventID, nil
}

func ApplyVLANLifecycle(cfg *config.Config, actor, operation string) (VLANLifecycleApplyResult, error) {
	operation = normalizeVLANLifecycleOperation(operation)
	if operation == "" || operation == "rollback" || operation == "preview" {
		operation = "apply"
	}
	plan, err := PreviewVLANLifecycle(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, "down", err.Error(), map[string]any{"operation": operation})
		return VLANLifecycleApplyResult{}, err
	}
	status := vlanLifecycleApplyStatus(plan.Status)
	if plan.Status == "blocked" {
		eventID, _ := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, operation, "blocked", "", "", actor, map[string]any{"blocked": true}))
		message := "VLAN lifecycle apply blocked by invalid plan"
		_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, "down", message, vlanLifecycleStatusDetails(plan, nil))
		return VLANLifecycleApplyResult{Operation: operation, Status: "blocked", EventID: eventID, Plan: plan, Message: message}, fmt.Errorf("%s", message)
	}
	if plan.Status == "skipped" {
		eventID, err := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, operation, "skipped", "", "", actor, map[string]any{"skipped": true}))
		if err != nil {
			return VLANLifecycleApplyResult{}, err
		}
		message := plan.Message
		_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, "disabled", message, vlanLifecycleStatusDetails(plan, nil))
		return VLANLifecycleApplyResult{Operation: operation, Status: "skipped", EventID: eventID, Plan: plan, Message: message}, nil
	}

	previousID := ""
	var previous *db.VLANLifecycleSnapshot
	if active, found, err := db.GetActiveVLANLifecycleSnapshot(); err == nil && found {
		previousID = active.SnapshotID
		previous = &active
	}
	if err := applyVLANLifecyclePlan(plan, previous); err != nil {
		eventID, _ := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, operation, "failed", "", previousID, actor, vlanLifecycleOperationDetails(plan, map[string]any{"error": err.Error()})))
		message := "VLAN lifecycle apply failed: " + err.Error()
		_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, "down", message, vlanLifecycleStatusDetails(plan, nil))
		return VLANLifecycleApplyResult{Operation: operation, Status: "failed", PreviousSnapshotID: previousID, EventID: eventID, Plan: plan, Message: message}, err
	}

	now := time.Now().UTC()
	snapshotID, err := db.RecordVLANLifecycleSnapshot(vlanLifecycleSnapshotInput(plan, operation, status, true, previousID, actor, &now, nil))
	if err != nil {
		return VLANLifecycleApplyResult{}, err
	}
	eventID, err := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, operation, status, snapshotID, previousID, actor, vlanLifecycleOperationDetails(plan, map[string]any{"applied_at": now.Format(time.RFC3339)})))
	if err != nil {
		return VLANLifecycleApplyResult{}, err
	}
	runtimeStatus := "ok"
	if status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("VLAN lifecycle applied %d command(s) for %d VLAN(s)", plan.Summary.CommandCount, plan.Summary.VLANCount)
	_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, runtimeStatus, message, vlanLifecycleStatusDetails(plan, map[string]any{
		"active_snapshot_id":   snapshotID,
		"previous_snapshot_id": previousID,
		"last_event_id":        eventID,
		"last_applied_at":      now.Format(time.RFC3339),
	}))
	return VLANLifecycleApplyResult{
		Operation:          operation,
		Status:             status,
		SnapshotID:         snapshotID,
		PreviousSnapshotID: previousID,
		EventID:            eventID,
		Plan:               plan,
		AppliedAt:          now.Format(time.RFC3339),
		Message:            message,
	}, nil
}

func RollbackVLANLifecycle(snapshotID, actor string) (VLANLifecycleRollbackResult, error) {
	active, activeFound, err := db.GetActiveVLANLifecycleSnapshot()
	if err != nil {
		return VLANLifecycleRollbackResult{}, err
	}
	targetID := strings.TrimSpace(snapshotID)
	if targetID == "" {
		snapshots, err := db.ListVLANLifecycleSnapshots(50)
		if err != nil {
			return VLANLifecycleRollbackResult{}, err
		}
		for _, snapshot := range snapshots {
			if activeFound && snapshot.SnapshotID == active.SnapshotID {
				continue
			}
			if snapshot.CommandText == "" && snapshot.HostapdVLANFilePath == "" {
				continue
			}
			targetID = snapshot.SnapshotID
			break
		}
	}
	if targetID == "" {
		return VLANLifecycleRollbackResult{}, fmt.Errorf("no previous VLAN lifecycle snapshot is available")
	}
	target, found, err := db.GetVLANLifecycleSnapshot(targetID)
	if err != nil {
		return VLANLifecycleRollbackResult{}, err
	}
	if !found {
		return VLANLifecycleRollbackResult{}, fmt.Errorf("VLAN lifecycle snapshot %q was not found", targetID)
	}
	commands := parseVLANLifecycleCommandText(target.CommandText)
	if len(commands) == 0 && strings.TrimSpace(target.HostapdVLANFilePath) == "" {
		return VLANLifecycleRollbackResult{}, fmt.Errorf("VLAN lifecycle snapshot %q has no restorable plan", targetID)
	}
	if err := applyVLANLifecycleArtifact(commands, target.HostapdVLANFilePath, target.HostapdVLANFileText); err != nil {
		previousID := ""
		if activeFound {
			previousID = active.SnapshotID
		}
		_, _ = db.RecordVLANLifecycleEvent(db.VLANLifecycleEventInput{
			Operation:             "rollback",
			Status:                "failed",
			SnapshotID:            target.SnapshotID,
			PreviousSnapshotID:    previousID,
			ParentInterface:       target.ParentInterface,
			VLANCount:             target.VLANCount,
			BridgeCount:           target.BridgeCount,
			SubinterfaceCount:     target.SubinterfaceCount,
			HostapdVLANEntryCount: target.HostapdVLANEntryCount,
			CommandCount:          target.CommandCount,
			DiagnosticCount:       target.DiagnosticCount,
			PlanFingerprint:       target.PlanFingerprint,
			DiagnosticsJSON:       target.DiagnosticsJSON,
			DetailsJSON:           marshalJSON(map[string]any{"error": err.Error()}),
			Actor:                 actor,
		})
		return VLANLifecycleRollbackResult{}, err
	}

	now := time.Now().UTC()
	previousID := ""
	if activeFound {
		previousID = active.SnapshotID
	}
	plan := vlanLifecyclePlanFromSnapshot(target, commands)
	rollbackSnapshotID, err := db.RecordVLANLifecycleSnapshot(vlanLifecycleSnapshotInput(plan, "rollback", "rolled_back", true, previousID, actor, &now, &now))
	if err != nil {
		return VLANLifecycleRollbackResult{}, err
	}
	eventID, err := db.RecordVLANLifecycleEvent(vlanLifecycleEventInput(plan, "rollback", "rolled_back", rollbackSnapshotID, previousID, actor, map[string]any{"restored_snapshot_id": target.SnapshotID}))
	if err != nil {
		return VLANLifecycleRollbackResult{}, err
	}
	message := fmt.Sprintf("VLAN lifecycle rolled back to snapshot %s", target.SnapshotID)
	_ = db.UpsertRuntimeStatus(vlanLifecycleComponent, "ok", message, vlanLifecycleStatusDetails(plan, map[string]any{
		"active_snapshot_id":   rollbackSnapshotID,
		"restored_snapshot_id": target.SnapshotID,
		"last_event_id":        eventID,
	}))
	return VLANLifecycleRollbackResult{
		Operation:          "rollback",
		Status:             "rolled_back",
		SnapshotID:         rollbackSnapshotID,
		RestoredSnapshotID: target.SnapshotID,
		PreviousSnapshotID: previousID,
		EventID:            eventID,
		Plan:               plan,
		RolledBackAt:       now.Format(time.RFC3339),
		Message:            message,
	}, nil
}

func buildVLANLifecyclePlan(cfg *config.Config, roleVLANs []vlanPolicySource, policyVLANs []vlanPolicySource) (VLANLifecyclePlan, error) {
	plan := VLANLifecyclePlan{
		SchemaVersion:       VLANLifecycleSchemaVersion,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		Status:              "ready",
		ParentInterface:     config.VLANLifecycleInterface(cfg),
		HostapdVLANFilePath: wireless.HostapdVLANFilePath(cfg),
		RFCs:                []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176"},
		FreeRADIUSAttributes: []string{
			"Tunnel-Type",
			"Tunnel-Medium-Type",
			"Tunnel-Private-Group-Id",
			"Egress-VLANID",
			"Cisco-AVPair",
			"Aruba-User-Vlan",
			"Ruckus-VLAN-ID",
			"Extreme-Netlogin-Vlan",
			"Extreme-Netlogin-Extended-Vlan",
			"Fortinet-Group-Name",
			"AegisNAS-VLAN",
		},
	}
	if !RuntimeVLANLifecycleEnabled(cfg) {
		plan.Status = "skipped"
		plan.Message = "Dynamic VLAN lifecycle is disabled by policy config"
		finalizeVLANLifecyclePlan(&plan)
		return plan, nil
	}
	if strings.TrimSpace(plan.ParentInterface) == "" {
		plan.Status = "blocked"
		plan.Diagnostics = append(plan.Diagnostics, VLANLifecycleDiagnostic{Severity: "error", Code: "missing_parent_interface", Message: "dynamic VLAN lifecycle requires lan.name or trunk wan.name", Field: "parent_interface"})
		finalizeVLANLifecyclePlan(&plan)
		return plan, nil
	}
	if !safeInterfaceName(plan.ParentInterface) {
		plan.Status = "blocked"
		plan.Diagnostics = append(plan.Diagnostics, VLANLifecycleDiagnostic{Severity: "error", Code: "unsafe_parent_interface", Message: "parent interface contains unsupported characters", Source: plan.ParentInterface, Field: "parent_interface"})
		finalizeVLANLifecyclePlan(&plan)
		return plan, nil
	}

	intents, diagnostics := collectVLANLifecycleIntents(cfg, roleVLANs, policyVLANs, plan.ParentInterface)
	plan.Diagnostics = append(plan.Diagnostics, diagnostics...)
	plan.Intents = intents
	for _, intent := range intents {
		plan.Bridges = append(plan.Bridges, VLANBridgePlan{Name: intent.Bridge, VLAN: intent.VLAN, Owner: "aegisnas", Dynamic: intent.Dynamic})
		plan.Subinterfaces = append(plan.Subinterfaces, VLANSubinterfacePlan{
			Name:            intent.Subif,
			ParentInterface: plan.ParentInterface,
			VLAN:            intent.VLAN,
			Bridge:          intent.Bridge,
			Tagged:          intent.Tagged,
			Owner:           "aegisnas",
		})
		if intent.Hostapd {
			plan.HostapdVLANEntries = append(plan.HostapdVLANEntries, HostapdVLANEntry{
				VLAN:      intent.VLAN,
				Bridge:    intent.Bridge,
				Interface: wireless.HostapdWirelessVLANInterface(cfg.Wireless.Interface, intent.VLAN),
			})
		}
	}
	plan.Commands = buildVLANLifecycleCommands(plan.ParentInterface, intents)
	plan.HostapdVLANFileText = renderHostapdVLANFile(plan.HostapdVLANEntries)
	plan.HostapdBindings = buildHostapdDynamicVLANBindings(cfg, plan)
	for _, binding := range plan.HostapdBindings {
		plan.Diagnostics = append(plan.Diagnostics, binding.Diagnostics...)
	}
	attachVLANLifecycleSnapshotDelta(&plan)

	switch {
	case len(plan.Intents) == 0 && len(plan.Diagnostics) == 0:
		plan.Message = "Dynamic VLAN lifecycle is enabled but no VLAN intent is configured"
	case len(plan.Intents) == 0:
		plan.Message = "Dynamic VLAN lifecycle found no valid VLAN intent"
	default:
		plan.Message = fmt.Sprintf("Dynamic VLAN lifecycle plans %d VLAN(s), %d bridge(s), and %d subinterface(s)", len(plan.Intents), len(plan.Bridges), len(plan.Subinterfaces))
	}
	for _, diagnostic := range plan.Diagnostics {
		if diagnostic.Severity == "error" {
			plan.Status = "blocked"
			break
		}
		if diagnostic.Severity == "warning" && plan.Status == "ready" {
			plan.Status = "degraded"
		}
	}
	finalizeVLANLifecyclePlan(&plan)
	return plan, nil
}

func collectVLANLifecycleIntents(cfg *config.Config, roleVLANs []vlanPolicySource, policyVLANs []vlanPolicySource, parentInterface string) ([]VLANLifecycleIntent, []VLANLifecycleDiagnostic) {
	intentMap := map[int]*vlanIntentBuilder{}
	var diagnostics []VLANLifecycleDiagnostic
	anyDynamicSSID := false
	add := func(vlan int, source, name, purpose, bridge string, dynamic, tagged, hostapd bool, attributes []string) {
		if vlan < 1 || vlan > 4094 {
			diagnostics = append(diagnostics, VLANLifecycleDiagnostic{
				Severity: "error",
				Code:     "invalid_vlan_id",
				Message:  "VLAN IDs must be in the range 1-4094",
				Source:   source,
				Field:    "vlan",
				VLAN:     vlan,
			})
			return
		}
		builder := intentMap[vlan]
		if builder == nil {
			builder = &vlanIntentBuilder{
				VLAN:    vlan,
				Name:    strings.TrimSpace(name),
				Purpose: strings.TrimSpace(purpose),
				Bridge:  defaultVLANBridge(vlan),
			}
			intentMap[vlan] = builder
		}
		if strings.TrimSpace(name) != "" && builder.Name == "" {
			builder.Name = strings.TrimSpace(name)
		}
		if strings.TrimSpace(purpose) != "" && builder.Purpose == "" {
			builder.Purpose = strings.TrimSpace(purpose)
		}
		if strings.TrimSpace(bridge) != "" {
			bridge = strings.TrimSpace(bridge)
			if builder.Bridge != defaultVLANBridge(vlan) && builder.Bridge != bridge {
				diagnostics = append(diagnostics, VLANLifecycleDiagnostic{
					Severity: "error",
					Code:     "bridge_conflict",
					Message:  fmt.Sprintf("VLAN %d is mapped to conflicting bridges %s and %s", vlan, builder.Bridge, bridge),
					Source:   source,
					Field:    "bridge",
					VLAN:     vlan,
				})
			} else {
				builder.Bridge = bridge
			}
		}
		builder.Dynamic = builder.Dynamic || dynamic
		builder.Tagged = builder.Tagged || tagged
		builder.Hostapd = builder.Hostapd || hostapd
		builder.Sources = appendUniqueLifecycleStrings(builder.Sources, source)
		builder.Attributes = appendUniqueLifecycleStrings(builder.Attributes, attributes...)
	}

	for _, vlan := range cfg.VLANs {
		add(vlan.ID, fmt.Sprintf("config.vlans:%s", firstNonEmptyString(vlan.Name, strconv.Itoa(vlan.ID))), vlan.Name, vlan.Purpose, "", false, false, false, []string{"Tunnel-Private-Group-Id"})
	}
	for i, ssid := range cfg.Wireless.SSIDs {
		source := fmt.Sprintf("wireless.ssids[%d]:%s", i, firstNonEmptyString(ssid.Name, strconv.Itoa(i)))
		if ssid.DynamicVLAN {
			anyDynamicSSID = true
		}
		if ssid.VLAN > 0 {
			add(ssid.VLAN, source, ssid.Name, "wireless", ssid.Bridge, ssid.DynamicVLAN, false, ssid.DynamicVLAN, []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"})
		}
		if ssid.DynamicVLAN && ssid.VLAN == 0 {
			diagnostics = append(diagnostics, VLANLifecycleDiagnostic{
				Severity: "info",
				Code:     "dynamic_vlan_without_fallback",
				Message:  "dynamic VLAN SSID has no fallback VLAN; hostapd will use fail-closed dynamic_vlan=2 and accept only VLANs listed in the managed VLAN file",
				Source:   source,
				Field:    "wireless.ssids.dynamic_vlan",
			})
		}
	}
	for _, source := range roleVLANs {
		add(source.VLAN, "role:"+source.Name, source.Name, "role", "", false, false, false, []string{"Tunnel-Private-Group-Id"})
	}
	for _, source := range policyVLANs {
		add(source.VLAN, "policy:"+source.Name, source.Name, "policy", "", false, false, false, []string{"Tunnel-Private-Group-Id"})
	}
	for _, mapping := range cfg.Radius.Vendor.ExtendedVLANMappings {
		pack := strings.ToLower(strings.TrimSpace(mapping.Pack))
		role := strings.TrimSpace(mapping.Role)
		if mapping.UntaggedVLAN > 0 {
			add(mapping.UntaggedVLAN, fmt.Sprintf("vendor.%s.extended_vlan:%s", pack, role), role, "vendor-untagged", "", true, false, false, []string{vendorExtendedVLANAttribute(pack)})
		}
		for _, tagged := range mapping.TaggedVLANs {
			add(tagged, fmt.Sprintf("vendor.%s.extended_vlan:%s", pack, role), role, "vendor-tagged", "", true, true, false, []string{vendorExtendedVLANAttribute(pack)})
		}
	}
	for _, pool := range cfg.Radius.VLANPolicy.Pools {
		source := fmt.Sprintf("radius.vlan_policy.pool:%s", firstNonEmptyString(pool.Name, "unnamed"))
		for _, vlan := range pool.VLANs {
			add(vlan, source, pool.Name, "vlan-pool", "", true, false, false, []string{"Tunnel-Private-Group-Id", "AegisNAS-VLAN-Pool"})
		}
	}
	for _, policy := range cfg.Radius.VLANPolicy.RolePolicies {
		role := strings.TrimSpace(policy.Role)
		source := fmt.Sprintf("radius.vlan_policy.role:%s", firstNonEmptyString(role, "default"))
		if policy.DataVLAN > 0 {
			add(policy.DataVLAN, source, role, "data-vlan", "", true, false, false, []string{"Tunnel-Private-Group-Id", "AegisNAS-Data-VLAN"})
		}
		if policy.VoiceVLAN > 0 {
			add(policy.VoiceVLAN, source, role, "voice-vlan", "", true, true, false, []string{"Egress-VLANID", "AegisNAS-Voice-VLAN"})
		}
		for _, tagged := range policy.TaggedVLANs {
			add(tagged, source, role, "tagged-vlan", "", true, true, false, []string{"Egress-VLANID", "AegisNAS-Tagged-VLAN"})
		}
		if policy.QinQ.Enabled {
			if policy.QinQ.OuterVLAN > 0 {
				add(policy.QinQ.OuterVLAN, source, role, "qinq-outer", "", true, true, false, []string{"AegisNAS-QinQ-Outer-VLAN"})
			}
			if policy.QinQ.InnerVLAN > 0 {
				add(policy.QinQ.InnerVLAN, source, role, "qinq-inner", "", true, true, false, []string{"AegisNAS-QinQ-Inner-VLAN"})
			}
		}
		if policy.FallbackVLAN > 0 {
			add(policy.FallbackVLAN, source, role, "fallback-vlan", "", true, false, false, []string{"Tunnel-Private-Group-Id", "AegisNAS-Fallback-VLAN"})
		}
		if policy.AuthFailVLAN > 0 {
			add(policy.AuthFailVLAN, source, role, "auth-fail-vlan", "", true, false, false, []string{"Tunnel-Private-Group-Id", "AegisNAS-Auth-Fail-VLAN"})
		}
	}
	if anyDynamicSSID {
		for vlan, builder := range intentMap {
			builder.Dynamic = true
			builder.Hostapd = true
			builder.Sources = appendUniqueLifecycleStrings(builder.Sources, "wireless.dynamic_vlan")
			builder.Attributes = appendUniqueLifecycleStrings(builder.Attributes, "Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id")
			intentMap[vlan] = builder
		}
	}

	intents := make([]VLANLifecycleIntent, 0, len(intentMap))
	for vlan, builder := range intentMap {
		bridge := strings.TrimSpace(builder.Bridge)
		if bridge == "" {
			bridge = defaultVLANBridge(vlan)
		}
		subif := vlanSubinterfaceName(parentInterface, vlan)
		if !safeInterfaceName(bridge) {
			diagnostics = append(diagnostics, VLANLifecycleDiagnostic{Severity: "error", Code: "unsafe_bridge_name", Message: "bridge name contains unsupported characters", Source: bridge, Field: "bridge", VLAN: vlan})
		}
		if !safeInterfaceName(subif) {
			diagnostics = append(diagnostics, VLANLifecycleDiagnostic{Severity: "error", Code: "unsafe_subinterface_name", Message: "subinterface name contains unsupported characters", Source: subif, Field: "subinterface", VLAN: vlan})
		}
		sort.Strings(builder.Sources)
		sort.Strings(builder.Attributes)
		intents = append(intents, VLANLifecycleIntent{
			VLAN:       vlan,
			Name:       builder.Name,
			Purpose:    builder.Purpose,
			Bridge:     bridge,
			Subif:      subif,
			Dynamic:    builder.Dynamic,
			Tagged:     builder.Tagged,
			Hostapd:    builder.Hostapd,
			Sources:    builder.Sources,
			Attributes: builder.Attributes,
		})
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].VLAN < intents[j].VLAN })
	return intents, diagnostics
}

func buildVLANLifecycleCommands(parentInterface string, intents []VLANLifecycleIntent) [][]string {
	if strings.TrimSpace(parentInterface) == "" {
		return nil
	}
	commands := [][]string{{"ip", "link", "set", "dev", parentInterface, "up"}}
	seenBridges := map[string]struct{}{}
	for _, intent := range intents {
		if _, ok := seenBridges[intent.Bridge]; !ok {
			commands = append(commands,
				[]string{"ip", "link", "add", "name", intent.Bridge, "type", "bridge"},
				[]string{"ip", "link", "set", "dev", intent.Bridge, "up"},
			)
			seenBridges[intent.Bridge] = struct{}{}
		}
		commands = append(commands,
			[]string{"ip", "link", "add", "link", parentInterface, "name", intent.Subif, "type", "vlan", "id", strconv.Itoa(intent.VLAN)},
			[]string{"ip", "link", "set", "dev", intent.Subif, "master", intent.Bridge},
			[]string{"ip", "link", "set", "dev", intent.Subif, "up"},
		)
	}
	return commands
}

func renderHostapdVLANFile(entries []HostapdVLANEntry) string {
	lines := []string{"# hostapd VLAN file - generated by AegisNAS"}
	sort.Slice(entries, func(i, j int) bool { return entries[i].VLAN < entries[j].VLAN })
	for _, entry := range entries {
		if entry.VLAN <= 0 || strings.TrimSpace(entry.Bridge) == "" {
			continue
		}
		fields := []string{strconv.Itoa(entry.VLAN), strings.TrimSpace(entry.Bridge)}
		if strings.TrimSpace(entry.Interface) != "" {
			fields = append(fields, strings.TrimSpace(entry.Interface))
		}
		lines = append(lines, strings.Join(fields, " "))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func buildHostapdDynamicVLANBindings(cfg *config.Config, plan VLANLifecyclePlan) []HostapdDynamicVLANBinding {
	if cfg == nil || !cfg.Wireless.Enabled {
		return nil
	}
	bindings := make([]HostapdDynamicVLANBinding, 0, len(cfg.Wireless.SSIDs))
	intentByVLAN := make(map[int]VLANLifecycleIntent, len(plan.Intents))
	for _, intent := range plan.Intents {
		intentByVLAN[intent.VLAN] = intent
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		if !ssid.DynamicVLAN {
			continue
		}
		mode := wireless.HostapdDynamicVLANMode(ssid)
		binding := HostapdDynamicVLANBinding{
			SSID:                strings.TrimSpace(ssid.Name),
			AuthMode:            strings.TrimSpace(ssid.AuthMode),
			DynamicVLANMode:     mode,
			DynamicVLANModeName: hostapdDynamicVLANModeName(mode),
			FallbackVLAN:        ssid.VLAN,
			VLANFilePath:        plan.HostapdVLANFilePath,
			VLANEntryCount:      len(plan.HostapdVLANEntries),
			Status:              "ready",
			RadiusAttributes: []string{
				"Tunnel-Type",
				"Tunnel-Medium-Type",
				"Tunnel-Private-Group-Id",
				"Egress-VLANID",
			},
		}
		if intent, ok := intentByVLAN[ssid.VLAN]; ok {
			binding.FallbackBridge = intent.Bridge
		} else if strings.TrimSpace(ssid.Bridge) != "" {
			binding.FallbackBridge = strings.TrimSpace(ssid.Bridge)
		}
		if ssid.AuthMode != "wpa2-enterprise" && ssid.AuthMode != "wpa3-enterprise" {
			binding.Status = "blocked"
			binding.Diagnostics = append(binding.Diagnostics, VLANLifecycleDiagnostic{
				Severity: "error",
				Code:     "dynamic_vlan_requires_enterprise_auth",
				Message:  "hostapd dynamic VLAN requires a WPA2/WPA3 Enterprise SSID",
				Source:   "wireless.ssid:" + firstNonEmptyString(ssid.Name, "unnamed"),
				Field:    "wireless.ssids.auth_mode",
			})
		}
		if len(plan.HostapdVLANEntries) == 0 {
			binding.Status = "blocked"
			binding.Diagnostics = append(binding.Diagnostics, VLANLifecycleDiagnostic{
				Severity: "error",
				Code:     "hostapd_vlan_file_empty",
				Message:  "dynamic VLAN SSID needs at least one configured VLAN intent before hostapd can accept VLAN assignments",
				Source:   "wireless.ssid:" + firstNonEmptyString(ssid.Name, "unnamed"),
				Field:    "hostapd_vlan_file",
			})
		}
		if ssid.VLAN == 0 && binding.Status == "ready" {
			binding.Status = "fail_closed"
			binding.Diagnostics = append(binding.Diagnostics, VLANLifecycleDiagnostic{
				Severity: "info",
				Code:     "hostapd_dynamic_vlan_fail_closed",
				Message:  "SSID has no fallback VLAN; hostapd dynamic_vlan=2 rejects sessions without a returned VLAN",
				Source:   "wireless.ssid:" + firstNonEmptyString(ssid.Name, "unnamed"),
				Field:    "wireless.ssids.vlan",
			})
		}
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].SSID < bindings[j].SSID })
	return bindings
}

func hostapdDynamicVLANModeName(mode int) string {
	switch mode {
	case 1:
		return "optional_with_fallback"
	case 2:
		return "required_fail_closed"
	default:
		return "disabled"
	}
}

func attachVLANLifecycleSnapshotDelta(plan *VLANLifecyclePlan) {
	if plan == nil || db.DB == nil {
		return
	}
	active, found, err := db.GetActiveVLANLifecycleSnapshot()
	if err != nil || !found {
		return
	}
	previous := vlanLifecyclePlanFromSnapshot(active, parseVLANLifecycleCommandText(active.CommandText))
	plan.CleanupCommands = buildVLANLifecycleCleanupCommands(previous, *plan)
	plan.RollbackCommands = buildVLANLifecycleRollbackCommands(*plan, previous)
}

func buildVLANLifecycleCleanupCommands(previous, desired VLANLifecyclePlan) [][]string {
	desiredSubinterfaces := vlanSubinterfaceSet(desired.Subinterfaces)
	desiredBridges := vlanBridgeSet(desired.Bridges)
	var commands [][]string
	for _, subif := range sortedVLANSubinterfaces(previous.Subinterfaces, true) {
		if _, keep := desiredSubinterfaces[subif.Name]; keep {
			continue
		}
		commands = append(commands,
			[]string{"ip", "link", "set", "dev", subif.Name, "down"},
			[]string{"ip", "link", "delete", subif.Name},
		)
	}
	for _, bridge := range sortedVLANBridges(previous.Bridges, true) {
		if _, keep := desiredBridges[bridge.Name]; keep {
			continue
		}
		commands = append(commands,
			[]string{"ip", "link", "set", "dev", bridge.Name, "down"},
			[]string{"ip", "link", "delete", bridge.Name, "type", "bridge"},
		)
	}
	return commands
}

func buildVLANLifecycleRollbackCommands(desired, previous VLANLifecyclePlan) [][]string {
	previousSubinterfaces := vlanSubinterfaceSet(previous.Subinterfaces)
	previousBridges := vlanBridgeSet(previous.Bridges)
	var commands [][]string
	for _, subif := range sortedVLANSubinterfaces(desired.Subinterfaces, true) {
		if _, existed := previousSubinterfaces[subif.Name]; existed {
			continue
		}
		commands = append(commands,
			[]string{"ip", "link", "set", "dev", subif.Name, "down"},
			[]string{"ip", "link", "delete", subif.Name},
		)
	}
	for _, bridge := range sortedVLANBridges(desired.Bridges, true) {
		if _, existed := previousBridges[bridge.Name]; existed {
			continue
		}
		commands = append(commands,
			[]string{"ip", "link", "set", "dev", bridge.Name, "down"},
			[]string{"ip", "link", "delete", bridge.Name, "type", "bridge"},
		)
	}
	commands = append(commands, previous.Commands...)
	return commands
}

func vlanSubinterfaceSet(values []VLANSubinterfacePlan) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func vlanBridgeSet(values []VLANBridgePlan) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value.Name)
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func sortedVLANSubinterfaces(values []VLANSubinterfacePlan, descending bool) []VLANSubinterfacePlan {
	out := append([]VLANSubinterfacePlan(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VLAN != out[j].VLAN {
			if descending {
				return out[i].VLAN > out[j].VLAN
			}
			return out[i].VLAN < out[j].VLAN
		}
		if descending {
			return out[i].Name > out[j].Name
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedVLANBridges(values []VLANBridgePlan, descending bool) []VLANBridgePlan {
	out := append([]VLANBridgePlan(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VLAN != out[j].VLAN {
			if descending {
				return out[i].VLAN > out[j].VLAN
			}
			return out[i].VLAN < out[j].VLAN
		}
		if descending {
			return out[i].Name > out[j].Name
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func applyVLANLifecyclePlan(plan VLANLifecyclePlan, previous *db.VLANLifecycleSnapshot) error {
	rollbackPath := ""
	rollbackText := ""
	if previous != nil {
		rollbackPath = previous.HostapdVLANFilePath
		rollbackText = previous.HostapdVLANFileText
	}
	return applyVLANLifecycleArtifactWithRollback(
		appendVLANLifecycleCommands(plan.Commands, plan.CleanupCommands),
		plan.HostapdVLANFilePath,
		plan.HostapdVLANFileText,
		plan.RollbackCommands,
		rollbackPath,
		rollbackText,
		runVLANLifecycleCommand,
		writeManagedFileAtomic,
	)
}

func applyVLANLifecycleArtifact(commands [][]string, vlanFilePath, vlanFileText string) error {
	return applyVLANLifecycleArtifactWithRollback(commands, vlanFilePath, vlanFileText, nil, "", "", runVLANLifecycleCommand, writeManagedFileAtomic)
}

type vlanLifecycleCommandRunner func([]string) (string, error)
type vlanLifecycleFileWriter func(string, string, os.FileMode) error

func runVLANLifecycleCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func applyVLANLifecycleArtifactWithRollback(commands [][]string, vlanFilePath, vlanFileText string, rollbackCommands [][]string, rollbackFilePath, rollbackFileText string, runner vlanLifecycleCommandRunner, writer vlanLifecycleFileWriter) error {
	if runner == nil {
		runner = runVLANLifecycleCommand
	}
	if writer == nil {
		writer = writeManagedFileAtomic
	}
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		if output, err := runner(command); err != nil {
			if canIgnoreVLANLifecycleCommandError(command, string(output)) {
				continue
			}
			rollbackErr := rollbackVLANLifecycleArtifact(rollbackCommands, rollbackFilePath, rollbackFileText, runner, writer)
			if rollbackErr != nil {
				return fmt.Errorf("%s failed: %w\nOutput: %s\nRollback: %v", strings.Join(command, " "), err, strings.TrimSpace(string(output)), rollbackErr)
			}
			return fmt.Errorf("%s failed: %w\nOutput: %s", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
		}
	}
	if strings.TrimSpace(vlanFilePath) == "" {
		return nil
	}
	if err := writer(vlanFilePath, vlanFileText, 0o600); err != nil {
		rollbackErr := rollbackVLANLifecycleArtifact(rollbackCommands, rollbackFilePath, rollbackFileText, runner, writer)
		if rollbackErr != nil {
			return fmt.Errorf("write hostapd VLAN file: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("write hostapd VLAN file: %w", err)
	}
	return nil
}

func rollbackVLANLifecycleArtifact(commands [][]string, vlanFilePath, vlanFileText string, runner vlanLifecycleCommandRunner, writer vlanLifecycleFileWriter) error {
	var failures []string
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		if output, err := runner(command); err != nil && !canIgnoreVLANLifecycleCommandError(command, output) {
			failures = append(failures, fmt.Sprintf("%s: %v %s", strings.Join(command, " "), err, strings.TrimSpace(output)))
		}
	}
	if strings.TrimSpace(vlanFilePath) != "" {
		if err := writer(vlanFilePath, vlanFileText, 0o600); err != nil {
			failures = append(failures, "restore hostapd VLAN file: "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func appendVLANLifecycleCommands(groups ...[][]string) [][]string {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	out := make([][]string, 0, total)
	for _, group := range groups {
		for _, command := range group {
			if len(command) == 0 {
				continue
			}
			copied := append([]string(nil), command...)
			out = append(out, copied)
		}
	}
	return out
}

func writeManagedFileAtomic(path, text string, perm os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("managed file path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create managed file directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".aegisnas-*")
	if err != nil {
		return fmt.Errorf("create temporary managed file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(text); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary managed file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary managed file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary managed file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace managed file: %w", err)
	}
	return nil
}

func loadVLANPolicySources() ([]vlanPolicySource, []vlanPolicySource, error) {
	if db.DB == nil {
		return nil, nil, nil
	}
	roles, err := loadVLANSources(`SELECT name, COALESCE(vlan, 0) FROM roles WHERE vlan IS NOT NULL AND vlan > 0 ORDER BY name`)
	if err != nil {
		return nil, nil, err
	}
	policies, err := loadVLANSources(`SELECT name, COALESCE(vlan, 0) FROM policy_rules WHERE enabled = 1 AND vlan IS NOT NULL AND vlan > 0 ORDER BY priority DESC, name`)
	if err != nil {
		return nil, nil, err
	}
	return roles, policies, nil
}

type vlanPolicySource struct {
	Name string
	VLAN int
}

func loadVLANSources(query string) ([]vlanPolicySource, error) {
	rows, err := db.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []vlanPolicySource
	for rows.Next() {
		var source vlanPolicySource
		if err := rows.Scan(&source.Name, &source.VLAN); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

func finalizeVLANLifecyclePlan(plan *VLANLifecyclePlan) {
	plan.Summary = VLANLifecycleSummary{}
	plan.CommandPreview = make([]string, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		plan.CommandPreview = append(plan.CommandPreview, strings.Join(command, " "))
	}
	plan.CleanupCommandPreview = make([]string, 0, len(plan.CleanupCommands))
	for _, command := range plan.CleanupCommands {
		plan.CleanupCommandPreview = append(plan.CleanupCommandPreview, strings.Join(command, " "))
	}
	plan.RollbackCommandPreview = make([]string, 0, len(plan.RollbackCommands))
	for _, command := range plan.RollbackCommands {
		plan.RollbackCommandPreview = append(plan.RollbackCommandPreview, strings.Join(command, " "))
	}
	plan.Summary.VLANCount = len(plan.Intents)
	plan.Summary.BridgeCount = len(plan.Bridges)
	plan.Summary.SubinterfaceCount = len(plan.Subinterfaces)
	plan.Summary.HostapdVLANEntryCount = len(plan.HostapdVLANEntries)
	plan.Summary.HostapdDynamicSSIDCount = len(plan.HostapdBindings)
	plan.Summary.CommandCount = len(plan.Commands)
	plan.Summary.CleanupCommandCount = len(plan.CleanupCommands)
	plan.Summary.RollbackCommandCount = len(plan.RollbackCommands)
	plan.Summary.DiagnosticCount = len(plan.Diagnostics)
	for _, intent := range plan.Intents {
		if intent.Dynamic {
			plan.Summary.DynamicVLANCount++
		} else {
			plan.Summary.StaticVLANCount++
		}
		if intent.Tagged {
			plan.Summary.TaggedVLANCount++
		}
	}
	for _, binding := range plan.HostapdBindings {
		if binding.FallbackVLAN > 0 {
			plan.Summary.HostapdFallbackSSIDCount++
		}
		if binding.DynamicVLANMode == 2 {
			plan.Summary.HostapdFailClosedSSIDCount++
		}
	}
	if strings.TrimSpace(plan.HostapdVLANFileText) != "" {
		sum := sha256.Sum256([]byte(plan.HostapdVLANFileText))
		plan.HostapdVLANFileSHA256 = "sha256:" + hex.EncodeToString(sum[:])
	}
	payload := struct {
		SchemaVersion       int                         `json:"schema_version"`
		ParentInterface     string                      `json:"parent_interface"`
		HostapdVLANFilePath string                      `json:"hostapd_vlan_file_path"`
		Intents             []VLANLifecycleIntent       `json:"intents"`
		Commands            []string                    `json:"commands"`
		CleanupCommands     []string                    `json:"cleanup_commands"`
		RollbackCommands    []string                    `json:"rollback_commands"`
		HostapdEntries      []HostapdVLANEntry          `json:"hostapd_vlan_entries"`
		HostapdBindings     []HostapdDynamicVLANBinding `json:"hostapd_bindings"`
	}{
		SchemaVersion:       plan.SchemaVersion,
		ParentInterface:     plan.ParentInterface,
		HostapdVLANFilePath: plan.HostapdVLANFilePath,
		Intents:             plan.Intents,
		Commands:            plan.CommandPreview,
		CleanupCommands:     plan.CleanupCommandPreview,
		RollbackCommands:    plan.RollbackCommandPreview,
		HostapdEntries:      plan.HostapdVLANEntries,
		HostapdBindings:     plan.HostapdBindings,
	}
	plan.PlanFingerprint = sha256JSON(payload)
}

func vlanLifecycleSnapshotInput(plan VLANLifecyclePlan, operation, status string, active bool, previousID, actor string, appliedAt, rolledBackAt *time.Time) db.VLANLifecycleSnapshotInput {
	return db.VLANLifecycleSnapshotInput{
		Operation:             operation,
		Status:                status,
		Active:                active,
		ParentInterface:       plan.ParentInterface,
		VLANCount:             plan.Summary.VLANCount,
		BridgeCount:           plan.Summary.BridgeCount,
		SubinterfaceCount:     plan.Summary.SubinterfaceCount,
		HostapdVLANEntryCount: plan.Summary.HostapdVLANEntryCount,
		CommandCount:          plan.Summary.CommandCount,
		DiagnosticCount:       len(plan.Diagnostics),
		PlanFingerprint:       plan.PlanFingerprint,
		CommandText:           strings.Join(plan.CommandPreview, "\n"),
		HostapdVLANFilePath:   plan.HostapdVLANFilePath,
		HostapdVLANFileText:   plan.HostapdVLANFileText,
		HostapdVLANFileSHA256: plan.HostapdVLANFileSHA256,
		DiagnosticsJSON:       marshalJSON(plan.Diagnostics),
		SummaryJSON:           marshalJSON(plan.Summary),
		PlanJSON:              marshalJSON(plan),
		PreviousSnapshotID:    previousID,
		Actor:                 actor,
		AppliedAt:             appliedAt,
		RolledBackAt:          rolledBackAt,
	}
}

func vlanLifecycleEventInput(plan VLANLifecyclePlan, operation, status, snapshotID, previousID, actor string, details map[string]any) db.VLANLifecycleEventInput {
	if details == nil {
		details = map[string]any{}
	}
	return db.VLANLifecycleEventInput{
		Operation:             operation,
		Status:                status,
		SnapshotID:            snapshotID,
		PreviousSnapshotID:    previousID,
		ParentInterface:       plan.ParentInterface,
		VLANCount:             plan.Summary.VLANCount,
		BridgeCount:           plan.Summary.BridgeCount,
		SubinterfaceCount:     plan.Summary.SubinterfaceCount,
		HostapdVLANEntryCount: plan.Summary.HostapdVLANEntryCount,
		CommandCount:          plan.Summary.CommandCount,
		DiagnosticCount:       len(plan.Diagnostics),
		PlanFingerprint:       plan.PlanFingerprint,
		DiagnosticsJSON:       marshalJSON(plan.Diagnostics),
		DetailsJSON:           marshalJSON(details),
		Actor:                 actor,
	}
}

func vlanLifecyclePlanFromSnapshot(snapshot db.VLANLifecycleSnapshot, commands [][]string) VLANLifecyclePlan {
	var summary VLANLifecycleSummary
	_ = json.Unmarshal([]byte(snapshot.SummaryJSON), &summary)
	var diagnostics []VLANLifecycleDiagnostic
	_ = json.Unmarshal([]byte(snapshot.DiagnosticsJSON), &diagnostics)
	preview := make([]string, 0, len(commands))
	for _, command := range commands {
		preview = append(preview, strings.Join(command, " "))
	}
	var stored VLANLifecyclePlan
	if strings.TrimSpace(snapshot.PlanJSON) != "" && json.Unmarshal([]byte(snapshot.PlanJSON), &stored) == nil && stored.SchemaVersion > 0 {
		stored.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		stored.Status = snapshot.Status
		stored.Message = "VLAN lifecycle plan restored from snapshot " + snapshot.SnapshotID
		stored.Commands = commands
		stored.CommandPreview = preview
		stored.PlanFingerprint = snapshot.PlanFingerprint
		stored.HostapdVLANFilePath = snapshot.HostapdVLANFilePath
		stored.HostapdVLANFileText = snapshot.HostapdVLANFileText
		stored.HostapdVLANFileSHA256 = snapshot.HostapdVLANFileSHA256
		return stored
	}
	return VLANLifecyclePlan{
		SchemaVersion:         VLANLifecycleSchemaVersion,
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		Status:                snapshot.Status,
		Message:               "VLAN lifecycle plan restored from snapshot " + snapshot.SnapshotID,
		ParentInterface:       snapshot.ParentInterface,
		HostapdVLANFilePath:   snapshot.HostapdVLANFilePath,
		HostapdVLANFileText:   snapshot.HostapdVLANFileText,
		HostapdVLANFileSHA256: snapshot.HostapdVLANFileSHA256,
		Summary:               summary,
		Diagnostics:           diagnostics,
		Commands:              commands,
		CommandPreview:        preview,
		PlanFingerprint:       snapshot.PlanFingerprint,
		RFCs:                  []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176"},
		FreeRADIUSAttributes:  []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "Egress-VLANID", "AegisNAS-VLAN"},
	}
}

func vlanLifecycleStatusDetails(plan VLANLifecyclePlan, extra map[string]any) map[string]any {
	details := map[string]any{
		"schema_version":                 plan.SchemaVersion,
		"parent_interface":               plan.ParentInterface,
		"status":                         plan.Status,
		"vlan_count":                     plan.Summary.VLANCount,
		"bridge_count":                   plan.Summary.BridgeCount,
		"subinterface_count":             plan.Summary.SubinterfaceCount,
		"hostapd_vlan_entry_count":       plan.Summary.HostapdVLANEntryCount,
		"hostapd_dynamic_ssid_count":     plan.Summary.HostapdDynamicSSIDCount,
		"hostapd_fail_closed_ssid_count": plan.Summary.HostapdFailClosedSSIDCount,
		"command_count":                  plan.Summary.CommandCount,
		"cleanup_command_count":          plan.Summary.CleanupCommandCount,
		"rollback_command_count":         plan.Summary.RollbackCommandCount,
		"diagnostic_count":               len(plan.Diagnostics),
		"plan_fingerprint":               plan.PlanFingerprint,
		"hostapd_vlan_file_path":         plan.HostapdVLANFilePath,
		"hostapd_vlan_file_sha256":       plan.HostapdVLANFileSHA256,
	}
	for key, value := range extra {
		details[key] = value
	}
	return details
}

func vlanLifecycleOperationDetails(plan VLANLifecyclePlan, extra map[string]any) map[string]any {
	details := map[string]any{
		"feature_id":                     HostapdVLANLifecycleFeatureID,
		"hostapd_dynamic_ssid_count":     plan.Summary.HostapdDynamicSSIDCount,
		"hostapd_fallback_ssid_count":    plan.Summary.HostapdFallbackSSIDCount,
		"hostapd_fail_closed_ssid_count": plan.Summary.HostapdFailClosedSSIDCount,
		"hostapd_vlan_entry_count":       plan.Summary.HostapdVLANEntryCount,
		"cleanup_command_count":          plan.Summary.CleanupCommandCount,
		"rollback_command_count":         plan.Summary.RollbackCommandCount,
		"hostapd_vlan_file_path":         plan.HostapdVLANFilePath,
		"hostapd_vlan_file_sha256":       plan.HostapdVLANFileSHA256,
	}
	for key, value := range extra {
		details[key] = value
	}
	return details
}

func vlanPlanStatusToEventStatus(status string) string {
	switch status {
	case "ready":
		return "previewed"
	case "degraded":
		return "degraded"
	case "blocked":
		return "blocked"
	case "skipped":
		return "skipped"
	default:
		return "previewed"
	}
}

func vlanLifecycleApplyStatus(status string) string {
	if status == "degraded" {
		return "degraded"
	}
	return "applied"
}

func parseVLANLifecycleCommandText(text string) [][]string {
	var commands [][]string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 {
			commands = append(commands, fields)
		}
	}
	return commands
}

func normalizeVLANLifecycleOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "rollback", "sync":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func RuntimeVLANLifecycleEnabled(cfg *config.Config) bool {
	return config.RuntimeVLANLifecycleEnabled(cfg)
}

func VLANLifecycleInterface(cfg *config.Config) string {
	return config.VLANLifecycleInterface(cfg)
}

func CountVLANLifecycleIntents(cfg *config.Config) (int, error) {
	plan, err := PreviewVLANLifecycle(cfg)
	if err != nil {
		return 0, err
	}
	return plan.Summary.VLANCount, nil
}

func safeInterfaceName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	return safeInterfaceNameRE.MatchString(name)
}

func defaultVLANBridge(vlan int) string {
	return fmt.Sprintf("%s%d", defaultBridgePrefix, vlan)
}

func vlanSubinterfaceName(parentInterface string, vlan int) string {
	parentInterface = strings.TrimSpace(parentInterface)
	candidate := fmt.Sprintf("%s.%d", parentInterface, vlan)
	if len(candidate) <= 15 && safeInterfaceName(candidate) {
		return candidate
	}
	sum := sha256.Sum256([]byte(parentInterface))
	return fmt.Sprintf("av%s.%d", hex.EncodeToString(sum[:])[:6], vlan)
}

func vendorExtendedVLANAttribute(pack string) string {
	switch strings.ToLower(strings.TrimSpace(pack)) {
	case productconfigs.VendorPackExtreme:
		return "Extreme-Netlogin-Extended-Vlan"
	case productconfigs.VendorPackHP:
		return "Egress-VLANID"
	default:
		return "Vendor-Extended-VLAN"
	}
}

func appendUniqueLifecycleStrings(base []string, values ...string) []string {
	seen := make(map[string]struct{}, len(base)+len(values))
	out := make([]string, 0, len(base)+len(values))
	for _, value := range base {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func canIgnoreVLANLifecycleCommandError(command []string, output string) bool {
	lower := strings.ToLower(output)
	if len(command) >= 4 && command[0] == "ip" && command[1] == "link" && command[2] == "add" {
		return strings.Contains(lower, "file exists") || strings.Contains(lower, "already exists")
	}
	if len(command) >= 4 && command[0] == "ip" && command[1] == "link" && command[2] == "set" {
		return strings.Contains(lower, "already") || strings.Contains(lower, "not master")
	}
	if len(command) >= 4 && command[0] == "ip" && command[1] == "link" && command[2] == "delete" {
		return strings.Contains(lower, "cannot find") ||
			strings.Contains(lower, "does not exist") ||
			strings.Contains(lower, "not found") ||
			strings.Contains(lower, "no such device")
	}
	return false
}
