package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/qos"
)

const (
	RuntimeQoSSchemaVersion = 1

	runtimeShaperComponent = "runtime_shaper"
	runtimeQoSComponent    = "runtime_qos_scheduler"
	runtimeIFBDevice       = "ifb-aegis0"
	defaultShaperRateKbit  = 1000000
	defaultBurstKB         = 64
	defaultCBurstKB        = 64
	defaultQoSPriority     = 4
)

type shapedSession struct {
	SessionID        string `json:"session_id"`
	Username         string `json:"username,omitempty"`
	IP               string `json:"ip,omitempty"`
	IPv6             string `json:"ipv6,omitempty"`
	BandwidthProfile string `json:"bandwidth_profile"`
	DownloadRateKbps int    `json:"download_rate_kbps"`
	UploadRateKbps   int    `json:"upload_rate_kbps"`
	BurstKB          int    `json:"burst_kb"`
}

type RuntimeQoSSummary struct {
	ProfileCount          int `json:"profile_count"`
	ClassCount            int `json:"class_count"`
	SessionCount          int `json:"session_count"`
	ShapedSessions        int `json:"shaped_sessions"`
	UnshapedSessions      int `json:"unshaped_sessions"`
	IPv4Sessions          int `json:"ipv4_sessions"`
	IPv6Sessions          int `json:"ipv6_sessions"`
	IPv6OnlySessions      int `json:"ipv6_only_sessions"`
	AggregateClassCount   int `json:"aggregate_class_count"`
	LeafClassCount        int `json:"leaf_class_count"`
	CommandCount          int `json:"command_count"`
	DiagnosticCount       int `json:"diagnostic_count"`
	DownloadAggregateKbps int `json:"download_aggregate_kbps"`
	UploadAggregateKbps   int `json:"upload_aggregate_kbps"`
}

type RuntimeQoSDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Session  string `json:"session_id,omitempty"`
	Profile  string `json:"profile,omitempty"`
	Field    string `json:"field,omitempty"`
}

type RuntimeQoSClass struct {
	Direction          string `json:"direction"`
	Kind               string `json:"kind"`
	Profile            string `json:"profile,omitempty"`
	ParentProfile      string `json:"parent_profile,omitempty"`
	ParentClassID      string `json:"parent_class_id"`
	ClassID            string `json:"class_id"`
	RateKbps           int    `json:"rate_kbps"`
	CeilKbps           int    `json:"ceil_kbps"`
	BurstKB            int    `json:"burst_kb"`
	CBurstKB           int    `json:"cburst_kb"`
	Priority           int    `json:"priority"`
	Scheduler          string `json:"scheduler"`
	LeafQdisc          string `json:"leaf_qdisc,omitempty"`
	DSCPMark           *int   `json:"dscp_mark,omitempty"`
	DSCPClassification bool   `json:"dscp_classification"`
	SessionID          string `json:"session_id,omitempty"`
	IP                 string `json:"ip,omitempty"`
	IPv6               string `json:"ipv6,omitempty"`
	AddressFamily      string `json:"address_family,omitempty"`
}

type RuntimeQoSSessionPlan struct {
	SessionID        string `json:"session_id"`
	Username         string `json:"username,omitempty"`
	IP               string `json:"ip,omitempty"`
	IPv6             string `json:"ipv6,omitempty"`
	BandwidthProfile string `json:"bandwidth_profile"`
	DownloadClassID  string `json:"download_class_id,omitempty"`
	UploadClassID    string `json:"upload_class_id,omitempty"`
	DownloadRateKbps int    `json:"download_rate_kbps"`
	UploadRateKbps   int    `json:"upload_rate_kbps"`
	Priority         int    `json:"priority"`
	Status           string `json:"status"`
	Message          string `json:"message,omitempty"`
}

type RuntimeQoSPlan struct {
	SchemaVersion        int                     `json:"schema_version"`
	GeneratedAt          string                  `json:"generated_at"`
	Status               string                  `json:"status"`
	Message              string                  `json:"message"`
	InterfaceName        string                  `json:"interface_name"`
	IFBDevice            string                  `json:"ifb_device"`
	Summary              RuntimeQoSSummary       `json:"summary"`
	Diagnostics          []RuntimeQoSDiagnostic  `json:"diagnostics"`
	Classes              []RuntimeQoSClass       `json:"classes"`
	Sessions             []RuntimeQoSSessionPlan `json:"sessions"`
	Commands             [][]string              `json:"commands"`
	CommandPreview       []string                `json:"command_preview"`
	PlanFingerprint      string                  `json:"plan_fingerprint"`
	RFCs                 []string                `json:"rfcs"`
	FreeRADIUSAttributes []string                `json:"freeradius_attributes"`
}

type RuntimeQoSApplyResult struct {
	Operation          string         `json:"operation"`
	Status             string         `json:"status"`
	SnapshotID         string         `json:"snapshot_id,omitempty"`
	PreviousSnapshotID string         `json:"previous_snapshot_id,omitempty"`
	EventID            string         `json:"event_id,omitempty"`
	Plan               RuntimeQoSPlan `json:"plan"`
	AppliedAt          string         `json:"applied_at,omitempty"`
	Message            string         `json:"message"`
}

type RuntimeQoSRollbackResult struct {
	Operation          string         `json:"operation"`
	Status             string         `json:"status"`
	SnapshotID         string         `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string         `json:"restored_snapshot_id,omitempty"`
	PreviousSnapshotID string         `json:"previous_snapshot_id,omitempty"`
	EventID            string         `json:"event_id,omitempty"`
	Plan               RuntimeQoSPlan `json:"plan"`
	RolledBackAt       string         `json:"rolled_back_at,omitempty"`
	Message            string         `json:"message"`
}

type qosProfileRuntime struct {
	Name                  string
	Parent                string
	Scheduler             string
	Priority              int
	DSCPMark              *int
	DownloadSessionRate   int
	DownloadSessionCeil   int
	UploadSessionRate     int
	UploadSessionCeil     int
	DownloadAggregateRate int
	DownloadAggregateCeil int
	UploadAggregateRate   int
	UploadAggregateCeil   int
	BurstKB               int
	CBurstKB              int
	QuantumBytes          int
	SessionCount          int
	ProfileMinor          int
	MetadataJSON          string
}

func SyncRuntimeEnforcement(cfg *config.Config) error {
	var errs []string
	if err := SyncRuntimeFirewall(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := SyncRuntimeShaping(cfg); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func SyncRuntimeShaping(cfg *config.Config) error {
	_, err := ApplyRuntimeQoS(cfg, "runtime-sync", "sync")
	return err
}

func PreviewRuntimeQoS(cfg *config.Config) (RuntimeQoSPlan, error) {
	if cfg == nil {
		return RuntimeQoSPlan{}, fmt.Errorf("config is required")
	}
	sessions, err := loadShapedSessions()
	if err != nil {
		return RuntimeQoSPlan{}, err
	}
	overrides, err := db.ListQoSSchedulerProfiles()
	if err != nil {
		return RuntimeQoSPlan{}, err
	}
	return buildRuntimeQoSPlan(cfg, sessions, overrides)
}

func PreviewAndRecordRuntimeQoS(cfg *config.Config, actor string) (RuntimeQoSPlan, string, error) {
	plan, err := PreviewRuntimeQoS(cfg)
	if err != nil {
		return RuntimeQoSPlan{}, "", err
	}
	eventID, err := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, "preview", planStatusToEventStatus(plan.Status), "", "", actor, nil))
	if err != nil {
		return RuntimeQoSPlan{}, "", err
	}
	return plan, eventID, nil
}

func ApplyRuntimeQoS(cfg *config.Config, actor, operation string) (RuntimeQoSApplyResult, error) {
	operation = normalizeRuntimeQoSOperation(operation)
	if operation == "" || operation == "rollback" || operation == "preview" {
		operation = "apply"
	}
	plan, err := PreviewRuntimeQoS(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(runtimeQoSComponent, "down", err.Error(), map[string]any{"operation": operation})
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "down", err.Error(), map[string]any{"operation": operation})
		return RuntimeQoSApplyResult{}, err
	}
	status := runtimeQoSApplyStatus(plan.Status)
	if plan.Status == "blocked" {
		eventID, _ := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, operation, "blocked", "", "", actor, map[string]any{"blocked": true}))
		message := "Runtime QoS scheduler apply blocked by invalid plan"
		_ = db.UpsertRuntimeStatus(runtimeQoSComponent, "down", message, runtimeQoSStatusDetails(plan, nil))
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "down", message, runtimeQoSStatusDetails(plan, nil))
		return RuntimeQoSApplyResult{Operation: operation, Status: "blocked", EventID: eventID, Plan: plan, Message: message}, fmt.Errorf("%s", message)
	}
	if plan.Status == "skipped" {
		eventID, err := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, operation, "skipped", "", "", actor, map[string]any{"skipped": true}))
		if err != nil {
			return RuntimeQoSApplyResult{}, err
		}
		message := plan.Message
		_ = db.UpsertRuntimeStatus(runtimeQoSComponent, "disabled", message, runtimeQoSStatusDetails(plan, nil))
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "disabled", message, runtimeQoSStatusDetails(plan, nil))
		return RuntimeQoSApplyResult{Operation: operation, Status: "skipped", EventID: eventID, Plan: plan, Message: message}, nil
	}

	previousID := ""
	if active, found, err := db.GetActiveRuntimeQoSSnapshot(); err == nil && found {
		previousID = active.SnapshotID
	}
	if err := applyRuntimeQoSCommands(plan.Commands); err != nil {
		eventID, _ := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, operation, "failed", "", previousID, actor, map[string]any{"error": err.Error()}))
		message := "Runtime QoS scheduler apply failed: " + err.Error()
		_ = db.UpsertRuntimeStatus(runtimeQoSComponent, "down", message, runtimeQoSStatusDetails(plan, nil))
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "down", message, runtimeQoSStatusDetails(plan, nil))
		return RuntimeQoSApplyResult{Operation: operation, Status: "failed", PreviousSnapshotID: previousID, EventID: eventID, Plan: plan, Message: message}, err
	}

	now := time.Now().UTC()
	snapshotID, err := db.RecordRuntimeQoSSnapshot(runtimeQoSSnapshotInput(plan, operation, status, true, previousID, actor, &now, nil))
	if err != nil {
		return RuntimeQoSApplyResult{}, err
	}
	eventID, err := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, operation, status, snapshotID, previousID, actor, map[string]any{"applied_at": now.Format(time.RFC3339)}))
	if err != nil {
		return RuntimeQoSApplyResult{}, err
	}
	runtimeStatus := "ok"
	if status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("Runtime QoS scheduler applied %d command(s) for %d shaped session(s)", plan.Summary.CommandCount, plan.Summary.ShapedSessions)
	_ = db.UpsertRuntimeStatus(runtimeQoSComponent, runtimeStatus, message, runtimeQoSStatusDetails(plan, map[string]any{
		"active_snapshot_id":   snapshotID,
		"previous_snapshot_id": previousID,
		"last_event_id":        eventID,
		"last_applied_at":      now.Format(time.RFC3339),
		"plan_fingerprint":     plan.PlanFingerprint,
	}))
	_ = db.UpsertRuntimeStatus(runtimeShaperComponent, runtimeStatus, message, runtimeQoSStatusDetails(plan, map[string]any{
		"active_snapshot_id": snapshotID,
		"last_event_id":      eventID,
	}))
	return RuntimeQoSApplyResult{
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

func RollbackRuntimeQoS(snapshotID, actor string) (RuntimeQoSRollbackResult, error) {
	active, activeFound, err := db.GetActiveRuntimeQoSSnapshot()
	if err != nil {
		return RuntimeQoSRollbackResult{}, err
	}
	targetID := strings.TrimSpace(snapshotID)
	if targetID == "" {
		snapshots, err := db.ListRuntimeQoSSnapshots(50)
		if err != nil {
			return RuntimeQoSRollbackResult{}, err
		}
		for _, snapshot := range snapshots {
			if activeFound && snapshot.SnapshotID == active.SnapshotID {
				continue
			}
			if snapshot.CommandText == "" {
				continue
			}
			targetID = snapshot.SnapshotID
			break
		}
	}
	if targetID == "" {
		return RuntimeQoSRollbackResult{}, fmt.Errorf("no previous runtime QoS snapshot is available")
	}
	target, found, err := db.GetRuntimeQoSSnapshot(targetID)
	if err != nil {
		return RuntimeQoSRollbackResult{}, err
	}
	if !found {
		return RuntimeQoSRollbackResult{}, fmt.Errorf("runtime QoS snapshot %q was not found", targetID)
	}
	commands := parseRuntimeQoSCommandText(target.CommandText)
	if len(commands) == 0 {
		return RuntimeQoSRollbackResult{}, fmt.Errorf("runtime QoS snapshot %q has no command plan", targetID)
	}
	if err := applyRuntimeQoSCommands(commands); err != nil {
		_, _ = db.RecordRuntimeQoSEvent(db.RuntimeQoSEventInput{
			Operation:          "rollback",
			Status:             "failed",
			SnapshotID:         target.SnapshotID,
			PreviousSnapshotID: active.SnapshotID,
			InterfaceName:      target.InterfaceName,
			IFBDevice:          target.IFBDevice,
			ProfileCount:       target.ProfileCount,
			ClassCount:         target.ClassCount,
			SessionCount:       target.SessionCount,
			ShapedSessionCount: target.ShapedSessionCount,
			CommandCount:       target.CommandCount,
			DiagnosticCount:    target.DiagnosticCount,
			PlanFingerprint:    target.PlanFingerprint,
			DiagnosticsJSON:    target.DiagnosticsJSON,
			DetailsJSON:        marshalJSON(map[string]any{"error": err.Error()}),
			Actor:              actor,
		})
		return RuntimeQoSRollbackResult{}, err
	}

	now := time.Now().UTC()
	previousID := ""
	if activeFound {
		previousID = active.SnapshotID
	}
	plan := runtimeQoSPlanFromSnapshot(target, commands)
	rollbackSnapshotID, err := db.RecordRuntimeQoSSnapshot(runtimeQoSSnapshotInput(plan, "rollback", "rolled_back", true, previousID, actor, &now, &now))
	if err != nil {
		return RuntimeQoSRollbackResult{}, err
	}
	eventID, err := db.RecordRuntimeQoSEvent(runtimeQoSEventInput(plan, "rollback", "rolled_back", rollbackSnapshotID, previousID, actor, map[string]any{"restored_snapshot_id": target.SnapshotID}))
	if err != nil {
		return RuntimeQoSRollbackResult{}, err
	}
	message := fmt.Sprintf("Runtime QoS scheduler rolled back to snapshot %s", target.SnapshotID)
	_ = db.UpsertRuntimeStatus(runtimeQoSComponent, "ok", message, runtimeQoSStatusDetails(plan, map[string]any{
		"active_snapshot_id":   rollbackSnapshotID,
		"restored_snapshot_id": target.SnapshotID,
		"last_event_id":        eventID,
	}))
	_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "ok", message, runtimeQoSStatusDetails(plan, map[string]any{
		"active_snapshot_id":   rollbackSnapshotID,
		"restored_snapshot_id": target.SnapshotID,
	}))
	return RuntimeQoSRollbackResult{
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

func buildRuntimeQoSPlan(cfg *config.Config, sessions []shapedSession, overrides []db.QoSSchedulerProfile) (RuntimeQoSPlan, error) {
	plan := RuntimeQoSPlan{
		SchemaVersion: RuntimeQoSSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "ready",
		InterfaceName: ShapingInterface(cfg),
		IFBDevice:     runtimeIFBDevice,
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176"},
		FreeRADIUSAttributes: []string{
			"Filter-Id",
			"Framed-IP-Address",
			"Framed-IPv6-Address",
			"Framed-IPv6-Prefix",
			"AegisNAS-Bandwidth-Profile",
			"Mikrotik-Rate-Limit",
			"Huawei-Qos-Profile-Name",
			"QoS-Profile-Down",
			"QOS-Profile-Up",
		},
	}
	if !RuntimeShapingEnabled(cfg) {
		plan.Status = "skipped"
		plan.Message = "Runtime hierarchical QoS is disabled by deployment or policy config"
		finalizeRuntimeQoSPlan(&plan)
		return plan, nil
	}
	if plan.InterfaceName == "" {
		plan.Status = "skipped"
		plan.Message = "Runtime hierarchical QoS is disabled because no downstream interface is configured"
		finalizeRuntimeQoSPlan(&plan)
		return plan, nil
	}

	profiles, shaped, sessionPlans, diagnostics := buildRuntimeQoSProfiles(sessions, overrides)
	plan.Diagnostics = append(plan.Diagnostics, diagnostics...)
	plan.Sessions = sessionPlans
	commands, classes := buildRuntimeQoSCommands(plan.InterfaceName, profiles, shaped)
	plan.Commands = commands
	plan.Classes = classes
	attachRuntimeQoSClassIDs(plan.Sessions, classes)
	plan.Summary.SessionCount = len(sessions)
	plan.Summary.ShapedSessions = len(shaped)
	plan.Summary.UnshapedSessions = len(sessions) - len(shaped)
	plan.Summary.ProfileCount = len(profiles)
	plan.Summary.ClassCount = len(classes)
	for _, class := range classes {
		switch class.Kind {
		case "aggregate":
			plan.Summary.AggregateClassCount++
		case "leaf":
			plan.Summary.LeafClassCount++
		}
		if class.Direction == "download" && class.Kind == "aggregate" {
			plan.Summary.DownloadAggregateKbps += class.CeilKbps
		}
		if class.Direction == "upload" && class.Kind == "aggregate" {
			plan.Summary.UploadAggregateKbps += class.CeilKbps
		}
	}
	for _, session := range sessions {
		if strings.TrimSpace(session.IP) != "" {
			plan.Summary.IPv4Sessions++
		}
		if strings.TrimSpace(session.IPv6) != "" {
			plan.Summary.IPv6Sessions++
		}
		if strings.TrimSpace(session.IP) == "" && strings.TrimSpace(session.IPv6) != "" {
			plan.Summary.IPv6OnlySessions++
		}
	}
	plan.Summary.CommandCount = len(commands)
	if len(shaped) == 0 && len(plan.Diagnostics) == 0 {
		plan.Message = "Runtime hierarchical QoS is configured but there are no active shaped sessions"
	} else {
		plan.Message = fmt.Sprintf("Runtime hierarchical QoS plan has %d profile(s), %d class(es), and %d shaped session(s)", len(profiles), len(classes), len(shaped))
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
	finalizeRuntimeQoSPlan(&plan)
	return plan, nil
}

func attachRuntimeQoSClassIDs(sessions []RuntimeQoSSessionPlan, classes []RuntimeQoSClass) {
	type ids struct {
		download string
		upload   string
	}
	bySession := map[string]ids{}
	for _, class := range classes {
		if class.Kind != "leaf" || class.SessionID == "" {
			continue
		}
		item := bySession[class.SessionID]
		switch class.Direction {
		case "download":
			item.download = class.ClassID
		case "upload":
			item.upload = class.ClassID
		}
		bySession[class.SessionID] = item
	}
	for i := range sessions {
		item := bySession[sessions[i].SessionID]
		sessions[i].DownloadClassID = item.download
		sessions[i].UploadClassID = item.upload
	}
}

func buildRuntimeQoSProfiles(sessions []shapedSession, overrides []db.QoSSchedulerProfile) ([]qosProfileRuntime, []shapedSession, []RuntimeQoSSessionPlan, []RuntimeQoSDiagnostic) {
	overrideMap := map[string]db.QoSSchedulerProfile{}
	for _, override := range overrides {
		overrideMap[strings.ToLower(strings.TrimSpace(override.ProfileName))] = override
	}
	profileMap := map[string]*qosProfileRuntime{}
	var shaped []shapedSession
	var sessionPlans []RuntimeQoSSessionPlan
	var diagnostics []RuntimeQoSDiagnostic
	for _, session := range sessions {
		plan := RuntimeQoSSessionPlan{
			SessionID:        session.SessionID,
			Username:         session.Username,
			IP:               session.IP,
			IPv6:             session.IPv6,
			BandwidthProfile: session.BandwidthProfile,
			Status:           "unmanaged",
		}
		if strings.TrimSpace(session.BandwidthProfile) == "" {
			plan.Message = "session has no bandwidth profile"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		session.IP = strings.TrimSpace(session.IP)
		session.IPv6 = strings.TrimSpace(session.IPv6)
		if session.IP == "" && session.IPv6 == "" {
			plan.Message = "session has no address"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		if session.IP != "" {
			ip := net.ParseIP(session.IP)
			if ip == nil || ip.To4() == nil {
				diagnostics = append(diagnostics, RuntimeQoSDiagnostic{
					Severity: "error",
					Code:     "invalid_ipv4_address",
					Message:  "runtime QoS requires a valid IPv4 address for IPv4 local tc enforcement",
					Session:  session.SessionID,
					Profile:  session.BandwidthProfile,
					Field:    "ip",
				})
				plan.Status = "blocked"
				plan.Message = "invalid IPv4 address"
				sessionPlans = append(sessionPlans, plan)
				continue
			}
			session.IP = ip.To4().String()
			plan.IP = session.IP
		}
		if session.IPv6 != "" {
			ip := net.ParseIP(session.IPv6)
			if ip == nil || ip.To4() != nil || ip.To16() == nil {
				diagnostics = append(diagnostics, RuntimeQoSDiagnostic{
					Severity: "error",
					Code:     "invalid_ipv6_address",
					Message:  "runtime QoS requires a valid IPv6 address for IPv6 local tc enforcement",
					Session:  session.SessionID,
					Profile:  session.BandwidthProfile,
					Field:    "ipv6_address",
				})
				plan.Status = "blocked"
				plan.Message = "invalid IPv6 address"
				sessionPlans = append(sessionPlans, plan)
				continue
			}
			session.IPv6 = ip.String()
			plan.IPv6 = session.IPv6
		}
		if session.IP == "" && session.IPv6 == "" {
			diagnostics = append(diagnostics, RuntimeQoSDiagnostic{
				Severity: "error",
				Code:     "missing_shaping_address",
				Message:  "runtime QoS requires at least one valid IPv4 or IPv6 address for local tc enforcement",
				Session:  session.SessionID,
				Profile:  session.BandwidthProfile,
			})
			plan.Status = "blocked"
			plan.Message = "missing shaping address"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		if session.DownloadRateKbps <= 0 || session.UploadRateKbps <= 0 {
			diagnostics = append(diagnostics, RuntimeQoSDiagnostic{
				Severity: "error",
				Code:     "invalid_bandwidth_profile_rate",
				Message:  "bandwidth profile must define positive upload and download rates",
				Session:  session.SessionID,
				Profile:  session.BandwidthProfile,
				Field:    "bandwidth_profile",
			})
			plan.Status = "blocked"
			plan.Message = "invalid bandwidth profile rate"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(session.BandwidthProfile))
		profile, ok := profileMap[key]
		if !ok {
			created := qosProfileFromSession(session, overrideMap[key])
			profileMap[key] = &created
			profile = &created
		}
		if profile.Priority < 0 || profile.Priority > 7 {
			diagnostics = append(diagnostics, RuntimeQoSDiagnostic{Severity: "error", Code: "invalid_priority", Message: "QoS priority must be between 0 and 7", Profile: profile.Name, Field: "priority"})
			plan.Status = "blocked"
			plan.Message = "invalid priority"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		if profile.Scheduler != "htb" {
			diagnostics = append(diagnostics, RuntimeQoSDiagnostic{Severity: "error", Code: "unsupported_scheduler", Message: "local hierarchical QoS currently supports htb scheduler semantics", Profile: profile.Name, Field: "scheduler"})
			plan.Status = "blocked"
			plan.Message = "unsupported scheduler"
			sessionPlans = append(sessionPlans, plan)
			continue
		}
		profile.SessionCount++
		shaped = append(shaped, session)
		plan.Status = "shaped"
		plan.DownloadRateKbps = profile.DownloadSessionCeil
		plan.UploadRateKbps = profile.UploadSessionCeil
		plan.Priority = profile.Priority
		sessionPlans = append(sessionPlans, plan)
	}

	profiles := make([]qosProfileRuntime, 0, len(profileMap))
	for _, profile := range profileMap {
		profiles = append(profiles, *profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	for i := range profiles {
		profiles[i].ProfileMinor = 10 + i
		profiles[i].DownloadAggregateCeil = aggregateCeil(profiles[i].DownloadAggregateCeil, profiles[i].DownloadSessionCeil, profiles[i].SessionCount)
		profiles[i].UploadAggregateCeil = aggregateCeil(profiles[i].UploadAggregateCeil, profiles[i].UploadSessionCeil, profiles[i].SessionCount)
		profiles[i].DownloadAggregateRate = aggregateRate(profiles[i].DownloadAggregateRate, profiles[i].DownloadAggregateCeil)
		profiles[i].UploadAggregateRate = aggregateRate(profiles[i].UploadAggregateRate, profiles[i].UploadAggregateCeil)
	}
	knownProfiles := map[string]struct{}{}
	for _, profile := range profiles {
		knownProfiles[strings.ToLower(profile.Name)] = struct{}{}
	}
	for _, profile := range profiles {
		if profile.Parent != "" {
			if _, ok := knownProfiles[strings.ToLower(profile.Parent)]; !ok {
				diagnostics = append(diagnostics, RuntimeQoSDiagnostic{Severity: "error", Code: "missing_parent_profile", Message: "QoS scheduler parent profile does not exist in the active shaped set", Profile: profile.Name, Field: "parent_profile_name"})
			}
		}
	}
	if hasQoSCycle(profiles) {
		diagnostics = append(diagnostics, RuntimeQoSDiagnostic{Severity: "error", Code: "parent_profile_cycle", Message: "QoS scheduler profile hierarchy contains a cycle", Field: "parent_profile_name"})
	}
	return profiles, shaped, sessionPlans, diagnostics
}

func qosProfileFromSession(session shapedSession, override db.QoSSchedulerProfile) qosProfileRuntime {
	priority := defaultQoSPriority
	scheduler := "htb"
	parent := ""
	burst := session.BurstKB
	if burst <= 0 {
		burst = defaultBurstKB
	}
	cburst := burst
	var dscp *int
	downloadMin := session.DownloadRateKbps
	downloadCeil := session.DownloadRateKbps
	uploadMin := session.UploadRateKbps
	uploadCeil := session.UploadRateKbps
	if override.ProfileName != "" {
		if !override.Enabled {
			return qosProfileRuntime{
				Name:                session.BandwidthProfile,
				Scheduler:           scheduler,
				Priority:            priority,
				DownloadSessionRate: downloadMin,
				DownloadSessionCeil: downloadCeil,
				UploadSessionRate:   uploadMin,
				UploadSessionCeil:   uploadCeil,
				BurstKB:             burst,
				CBurstKB:            cburst,
				MetadataJSON:        "{}",
			}
		}
		parent = strings.TrimSpace(override.ParentProfileName)
		scheduler = strings.ToLower(strings.TrimSpace(override.Scheduler))
		if scheduler == "" {
			scheduler = "htb"
		}
		priority = override.Priority
		dscp = override.DSCPMark
		if override.BurstKB > 0 {
			burst = override.BurstKB
			cburst = burst
		}
		if override.CBurstKB > 0 {
			cburst = override.CBurstKB
		}
		if override.DownloadMinRateKbps > 0 {
			downloadMin = override.DownloadMinRateKbps
		}
		if override.DownloadCeilRateKbps > 0 {
			downloadCeil = override.DownloadCeilRateKbps
		}
		if override.UploadMinRateKbps > 0 {
			uploadMin = override.UploadMinRateKbps
		}
		if override.UploadCeilRateKbps > 0 {
			uploadCeil = override.UploadCeilRateKbps
		}
	}
	return qosProfileRuntime{
		Name:                  session.BandwidthProfile,
		Parent:                parent,
		Scheduler:             scheduler,
		Priority:              priority,
		DSCPMark:              dscp,
		DownloadSessionRate:   positiveOr(downloadMin, session.DownloadRateKbps),
		DownloadSessionCeil:   maxInt(positiveOr(downloadCeil, session.DownloadRateKbps), positiveOr(downloadMin, session.DownloadRateKbps)),
		UploadSessionRate:     positiveOr(uploadMin, session.UploadRateKbps),
		UploadSessionCeil:     maxInt(positiveOr(uploadCeil, session.UploadRateKbps), positiveOr(uploadMin, session.UploadRateKbps)),
		DownloadAggregateRate: nonNegativeInt(override.DownloadMinRateKbps),
		DownloadAggregateCeil: nonNegativeInt(override.DownloadCeilRateKbps),
		UploadAggregateRate:   nonNegativeInt(override.UploadMinRateKbps),
		UploadAggregateCeil:   nonNegativeInt(override.UploadCeilRateKbps),
		BurstKB:               burst,
		CBurstKB:              cburst,
		QuantumBytes:          nonNegativeInt(override.QuantumBytes),
		MetadataJSON:          firstNonEmptyString(override.MetadataJSON, "{}"),
	}
}

func buildRuntimeQoSCommands(interfaceName string, profiles []qosProfileRuntime, sessions []shapedSession) ([][]string, []RuntimeQoSClass) {
	if strings.TrimSpace(interfaceName) == "" {
		return nil, nil
	}
	commands := [][]string{
		{"modprobe", "ifb"},
		{"ip", "link", "add", runtimeIFBDevice, "type", "ifb"},
		{"ip", "link", "set", "dev", runtimeIFBDevice, "up"},
		{"tc", "qdisc", "del", "dev", interfaceName, "root"},
		{"tc", "qdisc", "del", "dev", interfaceName, "ingress"},
		{"tc", "qdisc", "del", "dev", runtimeIFBDevice, "root"},
		{"tc", "qdisc", "replace", "dev", interfaceName, "root", "handle", "1:", "htb", "default", "999"},
		{"tc", "class", "replace", "dev", interfaceName, "parent", "1:", "classid", "1:1", "htb", "rate", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit), "ceil", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit)},
		{"tc", "class", "replace", "dev", interfaceName, "parent", "1:1", "classid", "1:999", "htb", "rate", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit), "ceil", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit)},
		{"tc", "qdisc", "replace", "dev", interfaceName, "handle", "ffff:", "ingress"},
		{"tc", "filter", "replace", "dev", interfaceName, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", runtimeIFBDevice},
		{"tc", "filter", "replace", "dev", interfaceName, "parent", "ffff:", "protocol", "ipv6", "flower", "action", "mirred", "egress", "redirect", "dev", runtimeIFBDevice},
		{"tc", "qdisc", "replace", "dev", runtimeIFBDevice, "root", "handle", "2:", "htb", "default", "999"},
		{"tc", "class", "replace", "dev", runtimeIFBDevice, "parent", "2:", "classid", "2:1", "htb", "rate", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit), "ceil", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit)},
		{"tc", "class", "replace", "dev", runtimeIFBDevice, "parent", "2:1", "classid", "2:999", "htb", "rate", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit), "ceil", qos.TCRateKbit(defaultShaperRateKbit, defaultShaperRateKbit)},
	}
	var classes []RuntimeQoSClass
	profileByName := map[string]qosProfileRuntime{}
	for _, profile := range profiles {
		profileByName[strings.ToLower(profile.Name)] = profile
		parentDownload := "1:1"
		parentUpload := "2:1"
		if profile.Parent != "" {
			if parent, ok := profileByName[strings.ToLower(profile.Parent)]; ok {
				parentDownload = fmt.Sprintf("1:%d", parent.ProfileMinor)
				parentUpload = fmt.Sprintf("2:%d", parent.ProfileMinor)
			}
		}
		commands = append(commands,
			qosHTBClassCommand(interfaceName, parentDownload, fmt.Sprintf("1:%d", profile.ProfileMinor), profile.DownloadAggregateRate, profile.DownloadAggregateCeil, profile.BurstKB, profile.CBurstKB, profile.Priority, profile.QuantumBytes),
			qosHTBClassCommand(runtimeIFBDevice, parentUpload, fmt.Sprintf("2:%d", profile.ProfileMinor), profile.UploadAggregateRate, profile.UploadAggregateCeil, profile.BurstKB, profile.CBurstKB, profile.Priority, profile.QuantumBytes),
		)
		classes = append(classes,
			RuntimeQoSClass{Direction: "download", Kind: "aggregate", Profile: profile.Name, ParentProfile: profile.Parent, ParentClassID: parentDownload, ClassID: fmt.Sprintf("1:%d", profile.ProfileMinor), RateKbps: profile.DownloadAggregateRate, CeilKbps: profile.DownloadAggregateCeil, BurstKB: profile.BurstKB, CBurstKB: profile.CBurstKB, Priority: profile.Priority, Scheduler: profile.Scheduler, DSCPMark: profile.DSCPMark, DSCPClassification: profile.DSCPMark != nil},
			RuntimeQoSClass{Direction: "upload", Kind: "aggregate", Profile: profile.Name, ParentProfile: profile.Parent, ParentClassID: parentUpload, ClassID: fmt.Sprintf("2:%d", profile.ProfileMinor), RateKbps: profile.UploadAggregateRate, CeilKbps: profile.UploadAggregateCeil, BurstKB: profile.BurstKB, CBurstKB: profile.CBurstKB, Priority: profile.Priority, Scheduler: profile.Scheduler, DSCPMark: profile.DSCPMark, DSCPClassification: profile.DSCPMark != nil},
		)
	}
	profileIndex := map[string]qosProfileRuntime{}
	for _, profile := range profiles {
		profileIndex[strings.ToLower(profile.Name)] = profile
	}
	for index, session := range sessions {
		profile, ok := profileIndex[strings.ToLower(session.BandwidthProfile)]
		if !ok {
			continue
		}
		classID := 1000 + index
		downloadClass := fmt.Sprintf("1:%d", classID)
		uploadClass := fmt.Sprintf("2:%d", classID)
		downloadParent := fmt.Sprintf("1:%d", profile.ProfileMinor)
		uploadParent := fmt.Sprintf("2:%d", profile.ProfileMinor)
		prio := strconv.Itoa(10 + profile.Priority)
		commands = append(commands,
			qosHTBClassCommand(interfaceName, downloadParent, downloadClass, profile.DownloadSessionRate, profile.DownloadSessionCeil, profile.BurstKB, profile.CBurstKB, profile.Priority, profile.QuantumBytes),
			[]string{"tc", "qdisc", "replace", "dev", interfaceName, "parent", downloadClass, "handle", fmt.Sprintf("%d:", classID), "fq_codel"},
			qosHTBClassCommand(runtimeIFBDevice, uploadParent, uploadClass, profile.UploadSessionRate, profile.UploadSessionCeil, profile.BurstKB, profile.CBurstKB, profile.Priority, profile.QuantumBytes),
			[]string{"tc", "qdisc", "replace", "dev", runtimeIFBDevice, "parent", uploadClass, "handle", fmt.Sprintf("%d:", classID+20000), "fq_codel"},
		)
		if session.IP != "" {
			commands = append(commands,
				[]string{"tc", "filter", "replace", "dev", interfaceName, "protocol", "ip", "parent", "1:", "prio", prio, "u32", "match", "ip", "dst", session.IP + "/32", "flowid", downloadClass},
				[]string{"tc", "filter", "replace", "dev", runtimeIFBDevice, "protocol", "ip", "parent", "2:", "prio", prio, "u32", "match", "ip", "src", session.IP + "/32", "flowid", uploadClass},
			)
		}
		if session.IPv6 != "" {
			commands = append(commands,
				[]string{"tc", "filter", "replace", "dev", interfaceName, "protocol", "ipv6", "parent", "1:", "prio", prio, "flower", "dst_ip", session.IPv6, "flowid", downloadClass},
				[]string{"tc", "filter", "replace", "dev", runtimeIFBDevice, "protocol", "ipv6", "parent", "2:", "prio", prio, "flower", "src_ip", session.IPv6, "flowid", uploadClass},
			)
		}
		addressFamily := runtimeQoSSessionAddressFamily(session)
		classes = append(classes,
			RuntimeQoSClass{Direction: "download", Kind: "leaf", Profile: profile.Name, ParentClassID: downloadParent, ClassID: downloadClass, RateKbps: profile.DownloadSessionRate, CeilKbps: profile.DownloadSessionCeil, BurstKB: profile.BurstKB, CBurstKB: profile.CBurstKB, Priority: profile.Priority, Scheduler: profile.Scheduler, LeafQdisc: "fq_codel", DSCPMark: profile.DSCPMark, DSCPClassification: profile.DSCPMark != nil, SessionID: session.SessionID, IP: session.IP, IPv6: session.IPv6, AddressFamily: addressFamily},
			RuntimeQoSClass{Direction: "upload", Kind: "leaf", Profile: profile.Name, ParentClassID: uploadParent, ClassID: uploadClass, RateKbps: profile.UploadSessionRate, CeilKbps: profile.UploadSessionCeil, BurstKB: profile.BurstKB, CBurstKB: profile.CBurstKB, Priority: profile.Priority, Scheduler: profile.Scheduler, LeafQdisc: "fq_codel", DSCPMark: profile.DSCPMark, DSCPClassification: profile.DSCPMark != nil, SessionID: session.SessionID, IP: session.IP, IPv6: session.IPv6, AddressFamily: addressFamily},
		)
	}
	return commands, classes
}

func qosHTBClassCommand(dev, parent, classID string, rate, ceil, burst, cburst, priority, quantum int) []string {
	cmd := []string{
		"tc", "class", "replace", "dev", dev, "parent", parent, "classid", classID, "htb",
		"rate", qos.TCRateKbit(rate, defaultShaperRateKbit),
		"ceil", qos.TCRateKbit(ceil, positiveOr(rate, defaultShaperRateKbit)),
		"burst", qos.TCBurstK(burst, defaultBurstKB),
		"cburst", qos.TCBurstK(cburst, positiveOr(burst, defaultCBurstKB)),
		"prio", strconv.Itoa(clampInt(priority, 0, 7)),
	}
	if quantum > 0 {
		cmd = append(cmd, "quantum", strconv.Itoa(quantum))
	}
	return cmd
}

func runtimeQoSSessionAddressFamily(session shapedSession) string {
	hasIPv4 := strings.TrimSpace(session.IP) != ""
	hasIPv6 := strings.TrimSpace(session.IPv6) != ""
	switch {
	case hasIPv4 && hasIPv6:
		return "dual_stack"
	case hasIPv6:
		return "ipv6"
	case hasIPv4:
		return "ipv4"
	default:
		return ""
	}
}

func applyRuntimeQoSCommands(commands [][]string) error {
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		cmd := exec.Command(command[0], command[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			if canIgnoreShaperCommandError(command, string(output)) {
				continue
			}
			return fmt.Errorf("%s failed: %w\nOutput: %s", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func loadShapedSessions() ([]shapedSession, error) {
	if db.DB == nil {
		return nil, nil
	}
	rows, err := db.DB.Query(`SELECT s.id, COALESCE(s.username, ''), COALESCE(s.ip, ''), COALESCE(s.ipv6_address, ''),
			COALESCE(s.bandwidth_profile, ''), COALESCE(bp.download_rate_kbps, 0), COALESCE(bp.upload_rate_kbps, 0), COALESCE(bp.burst_kb, 0)
		FROM sessions s
		LEFT JOIN bandwidth_profiles bp ON bp.name = s.bandwidth_profile
		WHERE s.end_time IS NULL
		ORDER BY s.start_time, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []shapedSession
	for rows.Next() {
		var session shapedSession
		if err := rows.Scan(&session.SessionID, &session.Username, &session.IP, &session.IPv6, &session.BandwidthProfile, &session.DownloadRateKbps, &session.UploadRateKbps, &session.BurstKB); err != nil {
			return nil, err
		}
		session.IP = strings.TrimSpace(session.IP)
		session.IPv6 = strings.TrimSpace(session.IPv6)
		session.BandwidthProfile = strings.TrimSpace(session.BandwidthProfile)
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func ShapingInterface(cfg *config.Config) string {
	return config.ShapingInterface(cfg)
}

func RuntimeShapingEnabled(cfg *config.Config) bool {
	return config.RuntimeShapingEnabled(cfg)
}

func CountShapedSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*)
		FROM sessions s
		JOIN bandwidth_profiles bp ON bp.name = s.bandwidth_profile
		WHERE s.end_time IS NULL
		AND (COALESCE(TRIM(s.ip), '') <> '' OR COALESCE(TRIM(s.ipv6_address), '') <> '')`).Scan(&count)
	return count, err
}

func BuildRuntimeShaperPreview(cfg *config.Config) ([]string, error) {
	plan, err := PreviewRuntimeQoS(cfg)
	if err != nil {
		return nil, err
	}
	return plan.CommandPreview, nil
}

func ClassIDForSession(index int) string {
	return strconv.Itoa(1000 + index)
}

func canIgnoreShaperCommandError(command []string, output string) bool {
	if len(command) >= 3 && command[0] == "tc" && command[1] == "qdisc" && command[2] == "del" {
		return true
	}
	if len(command) >= 4 && command[0] == "ip" && command[1] == "link" && command[2] == "add" {
		return strings.Contains(strings.ToLower(output), "file exists")
	}
	return false
}

func buildRuntimeShaperCommands(interfaceName string, sessions []shapedSession) [][]string {
	cfg := &config.Config{Policy: config.PolicyConfig{RuntimeShapingEnabled: true}, LAN: config.InterfaceConfig{Name: interfaceName}}
	plan, err := buildRuntimeQoSPlan(cfg, sessions, nil)
	if err != nil {
		return nil
	}
	return plan.Commands
}

func finalizeRuntimeQoSPlan(plan *RuntimeQoSPlan) {
	plan.CommandPreview = make([]string, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		plan.CommandPreview = append(plan.CommandPreview, strings.Join(command, " "))
	}
	plan.Summary.CommandCount = len(plan.Commands)
	plan.Summary.DiagnosticCount = len(plan.Diagnostics)
	payload := struct {
		SchemaVersion int               `json:"schema_version"`
		InterfaceName string            `json:"interface_name"`
		IFBDevice     string            `json:"ifb_device"`
		Commands      []string          `json:"commands"`
		Classes       []RuntimeQoSClass `json:"classes"`
	}{
		SchemaVersion: plan.SchemaVersion,
		InterfaceName: plan.InterfaceName,
		IFBDevice:     plan.IFBDevice,
		Commands:      plan.CommandPreview,
		Classes:       plan.Classes,
	}
	plan.PlanFingerprint = sha256JSON(payload)
}

func runtimeQoSSnapshotInput(plan RuntimeQoSPlan, operation, status string, active bool, previousID, actor string, appliedAt, rolledBackAt *time.Time) db.RuntimeQoSSnapshotInput {
	return db.RuntimeQoSSnapshotInput{
		Operation:            operation,
		Status:               status,
		Active:               active,
		InterfaceName:        plan.InterfaceName,
		IFBDevice:            plan.IFBDevice,
		ProfileCount:         plan.Summary.ProfileCount,
		ClassCount:           plan.Summary.ClassCount,
		SessionCount:         plan.Summary.SessionCount,
		ShapedSessionCount:   plan.Summary.ShapedSessions,
		UnshapedSessionCount: plan.Summary.UnshapedSessions,
		CommandCount:         plan.Summary.CommandCount,
		DiagnosticCount:      len(plan.Diagnostics),
		PlanFingerprint:      plan.PlanFingerprint,
		CommandText:          strings.Join(plan.CommandPreview, "\n"),
		DiagnosticsJSON:      marshalJSON(plan.Diagnostics),
		SummaryJSON:          marshalJSON(plan.Summary),
		PreviousSnapshotID:   previousID,
		Actor:                actor,
		AppliedAt:            appliedAt,
		RolledBackAt:         rolledBackAt,
	}
}

func runtimeQoSEventInput(plan RuntimeQoSPlan, operation, status, snapshotID, previousID, actor string, details map[string]any) db.RuntimeQoSEventInput {
	if details == nil {
		details = map[string]any{}
	}
	return db.RuntimeQoSEventInput{
		Operation:            operation,
		Status:               status,
		SnapshotID:           snapshotID,
		PreviousSnapshotID:   previousID,
		InterfaceName:        plan.InterfaceName,
		IFBDevice:            plan.IFBDevice,
		ProfileCount:         plan.Summary.ProfileCount,
		ClassCount:           plan.Summary.ClassCount,
		SessionCount:         plan.Summary.SessionCount,
		ShapedSessionCount:   plan.Summary.ShapedSessions,
		UnshapedSessionCount: plan.Summary.UnshapedSessions,
		CommandCount:         plan.Summary.CommandCount,
		DiagnosticCount:      len(plan.Diagnostics),
		PlanFingerprint:      plan.PlanFingerprint,
		DiagnosticsJSON:      marshalJSON(plan.Diagnostics),
		DetailsJSON:          marshalJSON(details),
		Actor:                actor,
	}
}

func runtimeQoSPlanFromSnapshot(snapshot db.RuntimeQoSSnapshot, commands [][]string) RuntimeQoSPlan {
	var summary RuntimeQoSSummary
	_ = json.Unmarshal([]byte(snapshot.SummaryJSON), &summary)
	var diagnostics []RuntimeQoSDiagnostic
	_ = json.Unmarshal([]byte(snapshot.DiagnosticsJSON), &diagnostics)
	preview := make([]string, 0, len(commands))
	for _, command := range commands {
		preview = append(preview, strings.Join(command, " "))
	}
	return RuntimeQoSPlan{
		SchemaVersion:        RuntimeQoSSchemaVersion,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		Status:               snapshot.Status,
		Message:              "Runtime QoS plan restored from snapshot " + snapshot.SnapshotID,
		InterfaceName:        snapshot.InterfaceName,
		IFBDevice:            snapshot.IFBDevice,
		Summary:              summary,
		Diagnostics:          diagnostics,
		Commands:             commands,
		CommandPreview:       preview,
		PlanFingerprint:      snapshot.PlanFingerprint,
		RFCs:                 []string{"RFC 2865", "RFC 2866", "RFC 2868", "RFC 5176"},
		FreeRADIUSAttributes: []string{"Filter-Id", "Framed-IP-Address", "Framed-IPv6-Address", "Framed-IPv6-Prefix", "AegisNAS-Bandwidth-Profile", "Mikrotik-Rate-Limit", "Huawei-Qos-Profile-Name"},
	}
}

func runtimeQoSStatusDetails(plan RuntimeQoSPlan, extra map[string]any) map[string]any {
	details := map[string]any{
		"schema_version":     plan.SchemaVersion,
		"interface":          plan.InterfaceName,
		"ifb_device":         plan.IFBDevice,
		"status":             plan.Status,
		"profile_count":      plan.Summary.ProfileCount,
		"class_count":        plan.Summary.ClassCount,
		"shaped_sessions":    plan.Summary.ShapedSessions,
		"unshaped_sessions":  plan.Summary.UnshapedSessions,
		"ipv4_sessions":      plan.Summary.IPv4Sessions,
		"ipv6_sessions":      plan.Summary.IPv6Sessions,
		"ipv6_only_sessions": plan.Summary.IPv6OnlySessions,
		"command_count":      plan.Summary.CommandCount,
		"diagnostic_count":   len(plan.Diagnostics),
		"plan_fingerprint":   plan.PlanFingerprint,
	}
	for key, value := range extra {
		details[key] = value
	}
	return details
}

func planStatusToEventStatus(status string) string {
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

func runtimeQoSApplyStatus(status string) string {
	if status == "degraded" {
		return "degraded"
	}
	return "applied"
}

func parseRuntimeQoSCommandText(text string) [][]string {
	var commands [][]string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 {
			commands = append(commands, fields)
		}
	}
	return commands
}

func sha256JSON(value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func marshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func normalizeRuntimeQoSOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "preview", "apply", "rollback", "sync":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func aggregateCeil(overrideCeil, sessionCeil, count int) int {
	if overrideCeil > 0 {
		return overrideCeil
	}
	return positiveOr(sessionCeil, defaultShaperRateKbit) * maxInt(count, 1)
}

func aggregateRate(overrideRate, ceil int) int {
	if overrideRate > 0 {
		return minInt(overrideRate, positiveOr(ceil, overrideRate))
	}
	return positiveOr(ceil, defaultShaperRateKbit)
}

func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func nonNegativeInt(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func hasQoSCycle(profiles []qosProfileRuntime) bool {
	parent := map[string]string{}
	for _, profile := range profiles {
		parent[strings.ToLower(profile.Name)] = strings.ToLower(strings.TrimSpace(profile.Parent))
	}
	for profile := range parent {
		seen := map[string]struct{}{}
		current := profile
		for current != "" {
			if _, ok := seen[current]; ok {
				return true
			}
			seen[current] = struct{}{}
			current = parent[current]
		}
	}
	return false
}
