package radius

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	OutboundDACHandoffSchemaVersion    = 1
	OutboundDACHandoffRuntimeComponent = "radius_dac_handoff"
	outboundDACHARuntimeComponent      = "high_availability"
	outboundDACHandoffEventRetention   = 2000
)

type OutboundDACHandoffDecision struct {
	SchemaVersion   int      `json:"schema_version"`
	Status          string   `json:"status"`
	Message         string   `json:"message"`
	Enabled         bool     `json:"enabled"`
	Mode            string   `json:"mode"`
	Role            string   `json:"role"`
	EffectiveRole   string   `json:"effective_role"`
	NodeID          string   `json:"node_id"`
	InstanceID      string   `json:"instance_id,omitempty"`
	LeaseID         string   `json:"lease_id,omitempty"`
	FencingToken    string   `json:"fencing_token,omitempty"`
	LeaseExpiresAt  string   `json:"lease_expires_at,omitempty"`
	CanSend         bool     `json:"can_send"`
	CanQueue        bool     `json:"can_queue"`
	CanReplay       bool     `json:"can_replay"`
	SplitBrainGuard bool     `json:"split_brain_guard"`
	HAStatus        string   `json:"ha_status,omitempty"`
	HAMessage       string   `json:"ha_message,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Blockers        []string `json:"blockers,omitempty"`
	RFCs            []string `json:"rfcs"`
}

type OutboundDACHandoffReport struct {
	SchemaVersion int                                `json:"schema_version"`
	Status        string                             `json:"status"`
	Message       string                             `json:"message"`
	Decision      OutboundDACHandoffDecision         `json:"decision"`
	Summary       db.OutboundDACHandoffSummary       `json:"summary"`
	Leases        []db.OutboundDACHandoffLeaseRecord `json:"leases,omitempty"`
	Events        []db.OutboundDACHandoffEventRecord `json:"events,omitempty"`
	RuntimeStatus *db.RuntimeStatus                  `json:"runtime_status,omitempty"`
	Warnings      []string                           `json:"warnings,omitempty"`
	RFCs          []string                           `json:"rfcs"`
}

func BuildOutboundDACHandoffReport(cfg *config.Config) OutboundDACHandoffReport {
	decision := evaluateOutboundDACHandoff(cfg, "status")
	report := OutboundDACHandoffReport{
		SchemaVersion: OutboundDACHandoffSchemaVersion,
		Status:        decision.Status,
		Message:       decision.Message,
		Decision:      decision,
		Warnings:      append([]string(nil), decision.Warnings...),
		RFCs:          []string{"RFC 5176"},
	}
	if db.DB == nil {
		if report.Status == "ready" {
			report.Status = "degraded"
		}
		report.Message = "Outbound DAC handoff persistence is unavailable because the database is not initialized."
		report.Warnings = append(report.Warnings, "database is not initialized")
		return report
	}
	persisted, persistErr := persistOutboundDACHandoffDecision(decision, "status")
	if persistErr != nil {
		if report.Status == "ready" {
			report.Status = "degraded"
		}
		report.Warnings = append(report.Warnings, "handoff lease persistence failed: "+persistErr.Error())
	} else if persisted.LeaseID != "" {
		report.Decision.FencingToken = persisted.FencingToken
		if report.Decision.LeaseExpiresAt == "" {
			report.Decision.LeaseExpiresAt = persisted.LeaseExpiresAt
		}
	}
	summary, err := db.GetOutboundDACHandoffSummary()
	if err != nil {
		if report.Status == "ready" {
			report.Status = "degraded"
		}
		report.Warnings = append(report.Warnings, err.Error())
	} else {
		report.Summary = summary
	}
	leases, _ := db.ListOutboundDACHandoffLeases(12)
	events, _ := db.ListOutboundDACHandoffEvents(12)
	runtime, _ := db.GetRuntimeStatus(OutboundDACHandoffRuntimeComponent)
	report.Leases = leases
	report.Events = events
	report.RuntimeStatus = runtime
	if len(decision.Blockers) > 0 {
		report.Status = "blocked"
	}
	return report
}

func evaluateOutboundDACHandoff(cfg *config.Config, operation string) OutboundDACHandoffDecision {
	now := time.Now().UTC()
	nodeID := outboundDACQueueOwner(cfg)
	instanceID := outboundDACHandoffInstanceID(nodeID)
	decision := OutboundDACHandoffDecision{
		SchemaVersion:   OutboundDACHandoffSchemaVersion,
		Status:          "ready",
		Message:         "Outbound DAC handoff is locally authorized.",
		Enabled:         false,
		Mode:            "standalone",
		Role:            "standalone",
		EffectiveRole:   "standalone",
		NodeID:          nodeID,
		InstanceID:      instanceID,
		CanSend:         true,
		CanQueue:        true,
		CanReplay:       true,
		SplitBrainGuard: false,
		RFCs:            []string{"RFC 5176"},
	}
	if cfg == nil {
		decision.Status = "blocked"
		decision.Message = "Configuration is required before outbound DAC handoff can be evaluated."
		decision.CanSend = false
		decision.CanQueue = false
		decision.CanReplay = false
		decision.Blockers = append(decision.Blockers, "configuration is required")
		return decision
	}
	if !cfg.HighAvailability.Enabled {
		return decision
	}

	role := strings.ToLower(strings.TrimSpace(cfg.HighAvailability.Role))
	if role == "" {
		role = "unknown"
	}
	effectiveRole := role
	haStatus, haMessage, haDetails := outboundDACHARuntime()
	if runtimeRole := stringFromMap(haDetails, "effective_role"); runtimeRole != "" {
		effectiveRole = strings.ToLower(strings.TrimSpace(runtimeRole))
	}
	failoverActive := boolFromMap(haDetails, "failover_active")
	leaseFor := time.Duration(cfg.HighAvailability.FailoverTimeoutSeconds) * time.Second
	if leaseFor <= 0 {
		leaseFor = 60 * time.Second
	}
	decision.Enabled = true
	decision.Mode = "cluster"
	decision.Role = role
	decision.EffectiveRole = effectiveRole
	decision.HAStatus = haStatus
	decision.HAMessage = haMessage
	decision.SplitBrainGuard = cfg.HighAvailability.SplitBrainProtectionEnabled
	decision.LeaseID = "dac-handoff-" + db.FingerprintOutboundDAC(nodeID, role)[:24]
	decision.FencingToken = "sha256:" + db.FingerprintOutboundDAC("dac-handoff", nodeID, instanceID, role, strings.TrimSpace(cfg.HighAvailability.VirtualIP))[:32]
	decision.LeaseExpiresAt = now.Add(leaseFor).Format(time.RFC3339)

	switch {
	case effectiveRole == "active":
		decision.CanSend = true
		decision.CanQueue = true
		decision.CanReplay = true
		if role == "standby" && failoverActive {
			decision.Message = "Standby is promoted by HA runtime and may own outbound DAC handoff."
		} else {
			decision.Message = "Active HA node owns outbound DAC handoff."
		}
	case role == "standby":
		decision.Status = "blocked"
		decision.Message = "Standby HA node cannot originate or replay outbound DAC until failover promotes it."
		decision.CanSend = false
		decision.CanQueue = false
		decision.CanReplay = false
		decision.Blockers = append(decision.Blockers, "high_availability.role is standby and effective_role is not active")
	case role != "active":
		decision.Status = "blocked"
		decision.Message = "High availability is enabled but role is not active or standby."
		decision.CanSend = false
		decision.CanQueue = false
		decision.CanReplay = false
		decision.Blockers = append(decision.Blockers, "high_availability.role must be active or standby")
	default:
		decision.Status = "blocked"
		decision.Message = "Outbound DAC handoff is blocked by HA role evaluation."
		decision.CanSend = false
		decision.CanQueue = false
		decision.CanReplay = false
		decision.Blockers = append(decision.Blockers, "effective HA role is not active")
	}
	if !cfg.HighAvailability.SplitBrainProtectionEnabled {
		decision.Warnings = append(decision.Warnings, "high_availability.split_brain_protection_enabled is false")
		if decision.Status == "ready" {
			decision.Status = "degraded"
		}
	}
	if haStatus == "degraded" && decision.Status == "ready" {
		decision.Status = "degraded"
		decision.Warnings = append(decision.Warnings, "high availability runtime is degraded: "+haMessage)
	}
	if operation == "send" && !decision.CanSend {
		decision.Blockers = appendUniqueString(decision.Blockers, "this node does not own the outbound DAC send lease")
	}
	if operation == "queue" && !decision.CanQueue {
		decision.Blockers = appendUniqueString(decision.Blockers, "this node does not own the outbound DAC queue lease")
	}
	if operation == "replay" && !decision.CanReplay {
		decision.Blockers = appendUniqueString(decision.Blockers, "this node does not own the outbound DAC replay lease")
	}
	if len(decision.Blockers) > 0 {
		decision.Status = "blocked"
		decision.Message = strings.Join(decision.Blockers, "; ")
	}
	return decision
}

func persistOutboundDACHandoffDecision(decision OutboundDACHandoffDecision, operation string) (db.OutboundDACHandoffLeaseRecord, error) {
	if db.DB == nil || !decision.Enabled || strings.TrimSpace(decision.LeaseID) == "" {
		return db.OutboundDACHandoffLeaseRecord{}, nil
	}
	now := time.Now().UTC()
	leaseStatus := db.OutboundDACHandoffStatusActive
	switch decision.Status {
	case "blocked":
		leaseStatus = db.OutboundDACHandoffStatusStandby
		if decision.EffectiveRole != "standby" {
			leaseStatus = db.OutboundDACHandoffStatusBlocked
		}
	case "degraded":
		leaseStatus = db.OutboundDACHandoffStatusDegraded
		if decision.CanSend || decision.CanReplay {
			leaseStatus = db.OutboundDACHandoffStatusActive
		}
	case "disabled":
		leaseStatus = db.OutboundDACHandoffStatusDisabled
	}
	var expiresAt time.Time
	if parsed, err := time.Parse(time.RFC3339, decision.LeaseExpiresAt); err == nil {
		expiresAt = parsed.UTC()
	}
	details := map[string]any{
		"operation":         strings.TrimSpace(operation),
		"mode":              decision.Mode,
		"effective_role":    decision.EffectiveRole,
		"can_send":          decision.CanSend,
		"can_queue":         decision.CanQueue,
		"can_replay":        decision.CanReplay,
		"split_brain_guard": decision.SplitBrainGuard,
		"warnings":          decision.Warnings,
		"blockers":          decision.Blockers,
		"ha_status":         decision.HAStatus,
		"ha_message":        decision.HAMessage,
	}
	lease, err := db.UpsertOutboundDACHandoffLease(db.OutboundDACHandoffLeaseInput{
		LeaseID:         decision.LeaseID,
		NodeID:          decision.NodeID,
		InstanceID:      decision.InstanceID,
		HARole:          decision.Role,
		Status:          leaseStatus,
		CanSend:         decision.CanSend,
		CanQueue:        decision.CanQueue,
		CanReplay:       decision.CanReplay,
		FencingToken:    decision.FencingToken,
		LeaseExpiresAt:  expiresAt,
		LastHeartbeatAt: now,
		Message:         decision.Message,
		Details:         details,
	})
	if err != nil {
		return lease, err
	}
	eventType := db.OutboundDACHandoffEventHeartbeat
	if len(decision.Blockers) > 0 {
		eventType = db.OutboundDACHandoffEventBlocked
	}
	eventID := "dach-" + db.FingerprintOutboundDAC(decision.NodeID, decision.LeaseID, eventType, decision.Status, strings.TrimSpace(operation), now.Format("20060102T1504"))[:24]
	_ = db.RecordOutboundDACHandoffEvent(db.OutboundDACHandoffEventCreate{
		EventID:    eventID,
		EventType:  eventType,
		Status:     leaseStatus,
		NodeID:     decision.NodeID,
		LeaseID:    decision.LeaseID,
		HARole:     decision.Role,
		Message:    decision.Message,
		Details:    details,
		ObservedAt: now,
	}, outboundDACHandoffEventRetention)
	_ = db.UpsertRuntimeStatus(OutboundDACHandoffRuntimeComponent, decision.Status, decision.Message, map[string]any{
		"node_id":           decision.NodeID,
		"instance_id":       decision.InstanceID,
		"lease_id":          decision.LeaseID,
		"role":              decision.Role,
		"effective_role":    decision.EffectiveRole,
		"can_send":          decision.CanSend,
		"can_queue":         decision.CanQueue,
		"can_replay":        decision.CanReplay,
		"split_brain_guard": decision.SplitBrainGuard,
		"operation":         strings.TrimSpace(operation),
	})
	return lease, nil
}

func outboundDACHARuntime() (string, string, map[string]any) {
	if db.DB == nil {
		return "", "", nil
	}
	runtime, err := db.GetRuntimeStatus(outboundDACHARuntimeComponent)
	if err != nil || runtime == nil {
		return "", "", nil
	}
	return runtime.Status, runtime.Message, runtime.Details
}

func outboundDACHandoffInstanceID(nodeID string) string {
	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = strings.TrimSpace(nodeID)
	}
	return hostname + ":pid-" + strconv.Itoa(os.Getpid())
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func boolFromMap(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, ok := values[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(strings.TrimSpace(existing), value) {
			return values
		}
	}
	return append(values, value)
}
