package enforcement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	SubscriberRouteExportSchemaVersion = 1
	subscriberRouteExportComponent     = "subscriber_route_export"
	defaultRouteExportArtifactPath     = "/var/lib/aegisnas/routing/subscriber-routes.frr"
	defaultRouteExportVtyshPath        = "vtysh"
)

var subscriberRouteExportExecCommand = exec.Command

type SubscriberRouteExportSummary struct {
	ProtocolCount      int  `json:"protocol_count"`
	EnabledProtocols   int  `json:"enabled_protocols"`
	RouteCount         int  `json:"route_count"`
	ExportedRoutes     int  `json:"exported_routes"`
	SuppressedRoutes   int  `json:"suppressed_routes"`
	WithdrawRouteCount int  `json:"withdraw_route_count"`
	IPv4RouteCount     int  `json:"ipv4_route_count"`
	IPv6RouteCount     int  `json:"ipv6_route_count"`
	VRFCount           int  `json:"vrf_count"`
	CommandCount       int  `json:"command_count"`
	DiagnosticCount    int  `json:"diagnostic_count"`
	ExternalApplyGated bool `json:"external_apply_gated"`
}

type SubscriberRouteExportDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	RouteKey string `json:"route_key,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	VRF      string `json:"vrf,omitempty"`
	Field    string `json:"field,omitempty"`
}

type SubscriberRouteExportProtocol struct {
	Key             string   `json:"key"`
	Protocol        string   `json:"protocol"`
	Enabled         bool     `json:"enabled"`
	VRF             string   `json:"vrf"`
	ASN             int64    `json:"asn,omitempty"`
	Instance        string   `json:"instance,omitempty"`
	RouterID        string   `json:"router_id,omitempty"`
	Area            string   `json:"area,omitempty"`
	RouteMap        string   `json:"route_map"`
	AddressFamilies []string `json:"address_families"`
	Communities     []string `json:"communities,omitempty"`
	Metric          int      `json:"metric,omitempty"`
	LocalPreference int      `json:"local_preference,omitempty"`
	MED             int      `json:"med,omitempty"`
	NextHopSelf     bool     `json:"next_hop_self"`
	RouteCount      int      `json:"route_count"`
}

type SubscriberRouteExportRoute struct {
	RouteKey          string   `json:"route_key"`
	OwnershipKey      string   `json:"ownership_key"`
	SessionID         string   `json:"session_id,omitempty"`
	AcctSessionID     string   `json:"acct_session_id,omitempty"`
	Role              string   `json:"role,omitempty"`
	VRF               string   `json:"vrf"`
	Owner             string   `json:"owner"`
	Revision          string   `json:"revision"`
	Family            string   `json:"family"`
	Destination       string   `json:"destination"`
	Gateway           string   `json:"gateway,omitempty"`
	Metric            int      `json:"metric,omitempty"`
	Preference        int      `json:"preference,omitempty"`
	Interface         string   `json:"interface,omitempty"`
	Tag               string   `json:"tag,omitempty"`
	Source            string   `json:"source,omitempty"`
	Status            string   `json:"status"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
	InstalledAt       string   `json:"installed_at,omitempty"`
	Protocols         []string `json:"protocols,omitempty"`
	Suppressed        bool     `json:"suppressed"`
	SuppressionReason string   `json:"suppression_reason,omitempty"`
}

type SubscriberRouteWithdrawal struct {
	RouteKey    string `json:"route_key"`
	VRF         string `json:"vrf"`
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Reason      string `json:"reason"`
}

type SubscriberRouteExportPlan struct {
	SchemaVersion        int                               `json:"schema_version"`
	GeneratedAt          string                            `json:"generated_at"`
	Status               string                            `json:"status"`
	Message              string                            `json:"message"`
	Driver               string                            `json:"driver"`
	ApplyEnabled         bool                              `json:"apply_enabled"`
	ArtifactPath         string                            `json:"artifact_path"`
	ArtifactSHA256       string                            `json:"artifact_sha256,omitempty"`
	ArtifactText         string                            `json:"artifact_text"`
	Summary              SubscriberRouteExportSummary      `json:"summary"`
	Diagnostics          []SubscriberRouteExportDiagnostic `json:"diagnostics,omitempty"`
	Protocols            []SubscriberRouteExportProtocol   `json:"protocols"`
	Routes               []SubscriberRouteExportRoute      `json:"routes"`
	Withdrawals          []SubscriberRouteWithdrawal       `json:"withdrawals,omitempty"`
	Commands             [][]string                        `json:"commands"`
	CommandPreview       []string                          `json:"command_preview"`
	PlanFingerprint      string                            `json:"plan_fingerprint"`
	RFCs                 []string                          `json:"rfcs"`
	FreeRADIUSAttributes []string                          `json:"freeradius_attributes"`
}

type SubscriberRouteExportApplyResult struct {
	Operation          string                    `json:"operation"`
	Status             string                    `json:"status"`
	SnapshotID         string                    `json:"snapshot_id,omitempty"`
	PreviousSnapshotID string                    `json:"previous_snapshot_id,omitempty"`
	EventID            string                    `json:"event_id,omitempty"`
	Plan               SubscriberRouteExportPlan `json:"plan"`
	AppliedAt          string                    `json:"applied_at,omitempty"`
	Message            string                    `json:"message"`
}

type SubscriberRouteExportRollbackResult struct {
	Operation          string                    `json:"operation"`
	Status             string                    `json:"status"`
	SnapshotID         string                    `json:"snapshot_id,omitempty"`
	RestoredSnapshotID string                    `json:"restored_snapshot_id,omitempty"`
	PreviousSnapshotID string                    `json:"previous_snapshot_id,omitempty"`
	EventID            string                    `json:"event_id,omitempty"`
	Plan               SubscriberRouteExportPlan `json:"plan"`
	RolledBackAt       string                    `json:"rolled_back_at,omitempty"`
	Message            string                    `json:"message"`
}

func PreviewSubscriberRouteExport(cfg *config.Config) (SubscriberRouteExportPlan, error) {
	if cfg == nil {
		return SubscriberRouteExportPlan{}, fmt.Errorf("config is required")
	}
	routeLimit := effectiveSubscriberRouteExportMaxRoutes(cfg.Radius.RoutePolicy.DynamicRouting) + 1
	ownership, err := db.ListRoutePolicyOwnershipForExport(routeLimit, "active")
	if err != nil {
		return SubscriberRouteExportPlan{}, err
	}
	active, found, err := db.GetActiveSubscriberRouteExportSnapshot()
	if err != nil {
		return SubscriberRouteExportPlan{}, err
	}
	var previous SubscriberRouteExportPlan
	if found && strings.TrimSpace(active.PlanJSON) != "" {
		_ = json.Unmarshal([]byte(active.PlanJSON), &previous)
	}
	return buildSubscriberRouteExportPlan(cfg, ownership, previous), nil
}

func PreviewAndRecordSubscriberRouteExport(cfg *config.Config, actor string) (SubscriberRouteExportPlan, string, error) {
	plan, err := PreviewSubscriberRouteExport(cfg)
	if err != nil {
		return SubscriberRouteExportPlan{}, "", err
	}
	eventID, err := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, "preview", routeExportPlanStatusToEventStatus(plan.Status), "", "", actor, nil))
	return plan, eventID, err
}

func ApplySubscriberRouteExport(cfg *config.Config, actor, operation string) (SubscriberRouteExportApplyResult, error) {
	operation = normalizeSubscriberRouteExportOperation(operation)
	if operation == "" || operation == "rollback" || operation == "preview" {
		operation = "apply"
	}
	plan, err := PreviewSubscriberRouteExport(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, "down", err.Error(), map[string]any{"operation": operation})
		return SubscriberRouteExportApplyResult{}, err
	}
	previousID := ""
	if active, found, err := db.GetActiveSubscriberRouteExportSnapshot(); err == nil && found {
		previousID = active.SnapshotID
	}
	if plan.Status == "blocked" {
		eventID, _ := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, operation, "blocked", "", previousID, actor, map[string]any{"blocked": true}))
		message := "Subscriber route export apply blocked by invalid plan"
		_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, "down", message, subscriberRouteExportStatusDetails(plan, "", previousID, eventID))
		return SubscriberRouteExportApplyResult{Operation: operation, Status: "blocked", PreviousSnapshotID: previousID, EventID: eventID, Plan: plan, Message: message}, fmt.Errorf("%s", message)
	}
	if plan.Status == "skipped" || !plan.ApplyEnabled {
		eventID, err := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, operation, "skipped", "", previousID, actor, map[string]any{"apply_enabled": plan.ApplyEnabled}))
		if err != nil {
			return SubscriberRouteExportApplyResult{}, err
		}
		message := plan.Message
		if !plan.ApplyEnabled {
			message = "Subscriber route export apply is disabled; preview artifact and route-export plan are available."
		}
		_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, "disabled", message, subscriberRouteExportStatusDetails(plan, "", previousID, eventID))
		return SubscriberRouteExportApplyResult{Operation: operation, Status: "skipped", PreviousSnapshotID: previousID, EventID: eventID, Plan: plan, Message: message}, nil
	}
	if err := applySubscriberRouteExportPlan(plan); err != nil {
		eventID, _ := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, operation, "failed", "", previousID, actor, map[string]any{"error": err.Error()}))
		message := "Subscriber route export apply failed: " + err.Error()
		_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, "down", message, subscriberRouteExportStatusDetails(plan, "", previousID, eventID))
		return SubscriberRouteExportApplyResult{Operation: operation, Status: "failed", PreviousSnapshotID: previousID, EventID: eventID, Plan: plan, Message: message}, err
	}

	now := time.Now().UTC()
	status := routeExportApplyStatus(plan.Status)
	snapshotID, err := db.RecordSubscriberRouteExportSnapshot(subscriberRouteExportSnapshotInput(plan, operation, status, true, previousID, actor, &now, nil))
	if err != nil {
		return SubscriberRouteExportApplyResult{}, err
	}
	eventID, err := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, operation, status, snapshotID, previousID, actor, map[string]any{"applied_at": now.Format(time.RFC3339)}))
	if err != nil {
		return SubscriberRouteExportApplyResult{}, err
	}
	runtimeStatus := "ok"
	if status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("Subscriber route export applied %d route(s) to %s.", plan.Summary.ExportedRoutes, plan.Driver)
	_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, runtimeStatus, message, subscriberRouteExportStatusDetails(plan, snapshotID, previousID, eventID))
	return SubscriberRouteExportApplyResult{
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

func RollbackSubscriberRouteExport(snapshotID, actor string) (SubscriberRouteExportRollbackResult, error) {
	active, activeFound, err := db.GetActiveSubscriberRouteExportSnapshot()
	if err != nil {
		return SubscriberRouteExportRollbackResult{}, err
	}
	targetID := strings.TrimSpace(snapshotID)
	if targetID == "" {
		snapshots, err := db.ListSubscriberRouteExportSnapshots(50)
		if err != nil {
			return SubscriberRouteExportRollbackResult{}, err
		}
		for _, snapshot := range snapshots {
			if activeFound && snapshot.SnapshotID == active.SnapshotID {
				continue
			}
			if strings.TrimSpace(snapshot.PlanJSON) == "" {
				continue
			}
			targetID = snapshot.SnapshotID
			break
		}
	}
	if targetID == "" {
		return SubscriberRouteExportRollbackResult{}, fmt.Errorf("no previous subscriber route export snapshot is available")
	}
	target, found, err := db.GetSubscriberRouteExportSnapshot(targetID)
	if err != nil {
		return SubscriberRouteExportRollbackResult{}, err
	}
	if !found {
		return SubscriberRouteExportRollbackResult{}, fmt.Errorf("subscriber route export snapshot %q was not found", targetID)
	}
	var plan SubscriberRouteExportPlan
	if err := json.Unmarshal([]byte(target.PlanJSON), &plan); err != nil {
		return SubscriberRouteExportRollbackResult{}, fmt.Errorf("decode subscriber route export snapshot plan: %w", err)
	}
	if strings.TrimSpace(plan.ArtifactText) == "" && strings.TrimSpace(target.ArtifactText) != "" {
		plan.ArtifactText = target.ArtifactText
	}
	if strings.TrimSpace(plan.ArtifactPath) == "" {
		plan.ArtifactPath = target.ArtifactPath
	}
	if err := applySubscriberRouteExportPlan(plan); err != nil {
		previousID := ""
		if activeFound {
			previousID = active.SnapshotID
		}
		_, _ = db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, "rollback", "failed", target.SnapshotID, previousID, actor, map[string]any{"error": err.Error()}))
		return SubscriberRouteExportRollbackResult{}, err
	}
	now := time.Now().UTC()
	previousID := ""
	if activeFound {
		previousID = active.SnapshotID
	}
	rollbackSnapshotID, err := db.RecordSubscriberRouteExportSnapshot(subscriberRouteExportSnapshotInput(plan, "rollback", "rolled_back", true, previousID, actor, &now, &now))
	if err != nil {
		return SubscriberRouteExportRollbackResult{}, err
	}
	eventID, err := db.RecordSubscriberRouteExportEvent(subscriberRouteExportEventInput(plan, "rollback", "rolled_back", rollbackSnapshotID, previousID, actor, map[string]any{"restored_snapshot_id": target.SnapshotID}))
	if err != nil {
		return SubscriberRouteExportRollbackResult{}, err
	}
	message := fmt.Sprintf("Subscriber route export rolled back to snapshot %s.", target.SnapshotID)
	_ = db.UpsertRuntimeStatus(subscriberRouteExportComponent, "ok", message, subscriberRouteExportStatusDetails(plan, rollbackSnapshotID, previousID, eventID))
	return SubscriberRouteExportRollbackResult{
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

func buildSubscriberRouteExportPlan(cfg *config.Config, ownership []db.RoutePolicyOwnershipRecord, previous SubscriberRouteExportPlan) SubscriberRouteExportPlan {
	policy := cfg.Radius.RoutePolicy.DynamicRouting
	plan := SubscriberRouteExportPlan{
		SchemaVersion: SubscriberRouteExportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        "ready",
		Driver:        effectiveSubscriberRouteExportDriver(policy.Driver),
		ApplyEnabled:  policy.ApplyEnabled,
		ArtifactPath:  effectiveSubscriberRouteExportArtifactPath(policy.ArtifactPath),
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 4271", "RFC 2328", "RFC 5340", "RFC 5176"},
		FreeRADIUSAttributes: []string{
			"Framed-Route",
			"Framed-IPv6-Route",
			"AegisNAS-VRF",
			"AegisNAS-Route-Owner",
			"AegisNAS-Route-Revision",
			"Cisco-AVPair",
			"Juniper-AV-Pair",
			"Huawei-AVpair",
			"Nokia-AVPair",
		},
	}
	if !cfg.Radius.RoutePolicy.Enabled || !policy.Enabled {
		plan.Status = "skipped"
		plan.Message = "Subscriber route export is disabled by route policy config."
		finalizeSubscriberRouteExportPlan(&plan)
		return plan
	}

	plan.Protocols = effectiveSubscriberRouteExportProtocols(policy.Protocols)
	for _, protocol := range plan.Protocols {
		plan.Summary.ProtocolCount++
		if protocol.Enabled {
			plan.Summary.EnabledProtocols++
		}
	}
	if plan.Summary.EnabledProtocols == 0 {
		plan.Status = "blocked"
		plan.Diagnostics = append(plan.Diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "no_enabled_protocol", Message: "at least one BGP, OSPF, or OSPF3 export protocol must be enabled", Field: "radius.route_policy.dynamic_routing.protocols"})
		finalizeSubscriberRouteExportPlan(&plan)
		return plan
	}

	maxRoutes := effectiveSubscriberRouteExportMaxRoutes(policy)
	if len(ownership) > maxRoutes {
		plan.Diagnostics = append(plan.Diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "too_many_routes", Message: fmt.Sprintf("active subscriber route count exceeds export limit %d", maxRoutes), Field: "route_policy_ownership"})
		ownership = ownership[:maxRoutes]
	}
	for _, record := range ownership {
		route, diagnostics := subscriberRouteFromOwnership(record)
		plan.Diagnostics = append(plan.Diagnostics, diagnostics...)
		if route.RouteKey == "" || route.Destination == "" {
			continue
		}
		if shouldSuppressSubscriberRoute(policy.Dampening, route) {
			route.Suppressed = true
			route.SuppressionReason = "route age is below dampening minimum"
			plan.Diagnostics = append(plan.Diagnostics, SubscriberRouteExportDiagnostic{Severity: "warning", Code: "route_dampened", Message: "subscriber route is temporarily suppressed by route age dampening", RouteKey: route.RouteKey, VRF: route.VRF})
		}
		if !route.Suppressed {
			route.Protocols = matchingSubscriberRouteProtocols(plan.Protocols, route)
			if len(route.Protocols) == 0 {
				route.Suppressed = true
				route.SuppressionReason = "no enabled routing protocol accepts this route family and VRF"
				plan.Diagnostics = append(plan.Diagnostics, SubscriberRouteExportDiagnostic{Severity: "warning", Code: "no_protocol_match", Message: "subscriber route has no enabled BGP/OSPF export target", RouteKey: route.RouteKey, VRF: route.VRF})
			}
		}
		plan.Routes = append(plan.Routes, route)
	}
	if suppressed := countSuppressedSubscriberRoutes(plan.Routes); policy.Dampening.MaxSuppressedRoutes > 0 && suppressed > policy.Dampening.MaxSuppressedRoutes {
		plan.Diagnostics = append(plan.Diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "too_many_suppressed_routes", Message: fmt.Sprintf("suppressed route count exceeds dampening limit %d", policy.Dampening.MaxSuppressedRoutes), Field: "radius.route_policy.dynamic_routing.dampening.max_suppressed_routes"})
	}
	attachProtocolRouteCounts(plan.Protocols, plan.Routes)
	plan.Withdrawals = computeSubscriberRouteWithdrawals(previous.Routes, plan.Routes)
	plan.ArtifactText = renderSubscriberRouteExportArtifact(plan)
	plan.Commands = buildSubscriberRouteExportCommands(plan, effectiveSubscriberRouteExportVtyshPath(policy.VtyshPath))

	switch {
	case len(plan.Routes) == 0 && len(plan.Diagnostics) == 0:
		plan.Message = "Subscriber route export is enabled but no active route ownership records are present."
	case len(plan.Routes) == 0:
		plan.Message = "Subscriber route export found no exportable subscriber routes."
	default:
		plan.Message = fmt.Sprintf("Subscriber route export plans %d active route(s), %d exported route(s), and %d withdrawal(s).", len(plan.Routes), countExportedSubscriberRoutes(plan.Routes), len(plan.Withdrawals))
	}
	if !plan.ApplyEnabled && plan.Status == "ready" {
		plan.Summary.ExternalApplyGated = true
	}
	finalizeSubscriberRouteExportPlan(&plan)
	return plan
}

func subscriberRouteFromOwnership(record db.RoutePolicyOwnershipRecord) (SubscriberRouteExportRoute, []SubscriberRouteExportDiagnostic) {
	route := SubscriberRouteExportRoute{
		RouteKey:      strings.TrimSpace(record.RouteKey),
		OwnershipKey:  strings.TrimSpace(record.OwnershipKey),
		SessionID:     strings.TrimSpace(record.SessionID),
		AcctSessionID: strings.TrimSpace(record.AcctSessionID),
		Role:          strings.TrimSpace(record.Role),
		VRF:           firstNonEmptyString(record.VRF, "default"),
		Owner:         firstNonEmptyString(record.Owner, "aegisnas"),
		Revision:      strings.TrimSpace(record.Revision),
		Family:        strings.ToLower(strings.TrimSpace(record.Family)),
		Destination:   strings.TrimSpace(record.Destination),
		Gateway:       strings.TrimSpace(record.Gateway),
		Metric:        nonNegativeInt(record.Metric),
		Preference:    nonNegativeInt(record.Preference),
		Interface:     strings.TrimSpace(record.Interface),
		Tag:           strings.TrimSpace(record.Tag),
		Source:        strings.TrimSpace(record.Source),
		Status:        strings.TrimSpace(record.Status),
		UpdatedAt:     strings.TrimSpace(record.UpdatedAt),
		InstalledAt:   strings.TrimSpace(record.InstalledAt),
	}
	var diagnostics []SubscriberRouteExportDiagnostic
	if route.Family != "ipv4" && route.Family != "ipv6" {
		diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "invalid_route_family", Message: "subscriber route family must be ipv4 or ipv6", RouteKey: route.RouteKey, Field: "family"})
		return SubscriberRouteExportRoute{}, diagnostics
	}
	prefix, err := netip.ParsePrefix(route.Destination)
	if err != nil {
		diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "invalid_route_prefix", Message: err.Error(), RouteKey: route.RouteKey, Field: "destination"})
		return SubscriberRouteExportRoute{}, diagnostics
	}
	prefix = prefix.Masked()
	if route.Family == "ipv4" && !prefix.Addr().Is4() {
		diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "route_family_mismatch", Message: "IPv4 route export cannot advertise an IPv6 prefix", RouteKey: route.RouteKey, Field: "destination"})
		return SubscriberRouteExportRoute{}, diagnostics
	}
	if route.Family == "ipv6" && !prefix.Addr().Is6() {
		diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "route_family_mismatch", Message: "IPv6 route export cannot advertise an IPv4 prefix", RouteKey: route.RouteKey, Field: "destination"})
		return SubscriberRouteExportRoute{}, diagnostics
	}
	route.Destination = prefix.String()
	if route.Gateway != "" {
		addr, err := netip.ParseAddr(route.Gateway)
		if err != nil {
			diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "invalid_gateway", Message: err.Error(), RouteKey: route.RouteKey, Field: "gateway"})
			return SubscriberRouteExportRoute{}, diagnostics
		}
		if route.Family == "ipv4" && !addr.Is4() {
			diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "gateway_family_mismatch", Message: "IPv4 route export requires an IPv4 gateway", RouteKey: route.RouteKey, Field: "gateway"})
			return SubscriberRouteExportRoute{}, diagnostics
		}
		if route.Family == "ipv6" && !addr.Is6() {
			diagnostics = append(diagnostics, SubscriberRouteExportDiagnostic{Severity: "error", Code: "gateway_family_mismatch", Message: "IPv6 route export requires an IPv6 gateway", RouteKey: route.RouteKey, Field: "gateway"})
			return SubscriberRouteExportRoute{}, diagnostics
		}
		route.Gateway = addr.String()
	}
	return route, diagnostics
}

func effectiveSubscriberRouteExportProtocols(raw []config.RadiusDynamicProtocolConfig) []SubscriberRouteExportProtocol {
	if len(raw) == 0 {
		raw = []config.RadiusDynamicProtocolConfig{
			{Protocol: "bgp", Enabled: true, VRF: "all", ASN: 65000, RouteMap: "AEGISNAS-SUBSCRIBER", AddressFamilies: []string{"ipv4", "ipv6"}, LocalPreference: 100},
		}
	}
	out := make([]SubscriberRouteExportProtocol, 0, len(raw))
	for _, protocol := range raw {
		name := strings.ToLower(strings.TrimSpace(protocol.Protocol))
		if name == "" {
			name = "bgp"
		}
		families := normalizeSubscriberRouteFamilies(protocol.AddressFamilies, name)
		vrf := strings.TrimSpace(protocol.VRF)
		if vrf == "" {
			vrf = "all"
		}
		routeMap := safeFRRName(protocol.RouteMap)
		if routeMap == "" {
			routeMap = "AEGISNAS-SUBSCRIBER"
		}
		item := SubscriberRouteExportProtocol{
			Protocol:        name,
			Enabled:         protocol.Enabled,
			VRF:             vrf,
			ASN:             protocol.ASN,
			Instance:        firstNonEmptyString(protocol.Instance, "1"),
			RouterID:        strings.TrimSpace(protocol.RouterID),
			Area:            firstNonEmptyString(protocol.Area, "0.0.0.0"),
			RouteMap:        routeMap,
			AddressFamilies: families,
			Communities:     sortedUniqueStrings(protocol.Communities),
			Metric:          nonNegativeInt(protocol.Metric),
			LocalPreference: nonNegativeInt(protocol.LocalPreference),
			MED:             nonNegativeInt(protocol.MED),
			NextHopSelf:     protocol.NextHopSelf,
		}
		item.Key = subscriberRouteProtocolKey(item)
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func normalizeSubscriberRouteFamilies(values []string, protocol string) []string {
	if len(values) == 0 {
		if protocol == "ospf" {
			return []string{"ipv4"}
		}
		if protocol == "ospf3" {
			return []string{"ipv6"}
		}
		return []string{"ipv4", "ipv6"}
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		family := strings.ToLower(strings.TrimSpace(value))
		if family == "ipv4" || family == "ipv6" {
			seen[family] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for family := range seen {
		if protocol == "ospf" && family != "ipv4" {
			continue
		}
		if protocol == "ospf3" && family != "ipv6" {
			continue
		}
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}

func matchingSubscriberRouteProtocols(protocols []SubscriberRouteExportProtocol, route SubscriberRouteExportRoute) []string {
	var matches []string
	for _, protocol := range protocols {
		if !protocol.Enabled {
			continue
		}
		if !strings.EqualFold(protocol.VRF, "all") && !strings.EqualFold(protocol.VRF, route.VRF) {
			continue
		}
		if !stringSliceContains(protocol.AddressFamilies, route.Family) {
			continue
		}
		matches = append(matches, protocol.Key)
	}
	sort.Strings(matches)
	return matches
}

func attachProtocolRouteCounts(protocols []SubscriberRouteExportProtocol, routes []SubscriberRouteExportRoute) {
	counts := map[string]int{}
	for _, route := range routes {
		if route.Suppressed {
			continue
		}
		for _, protocol := range route.Protocols {
			counts[protocol]++
		}
	}
	for i := range protocols {
		protocols[i].RouteCount = counts[protocols[i].Key]
	}
}

func computeSubscriberRouteWithdrawals(previous, desired []SubscriberRouteExportRoute) []SubscriberRouteWithdrawal {
	desiredKeys := map[string]struct{}{}
	for _, route := range desired {
		if route.Suppressed {
			continue
		}
		desiredKeys[subscriberRouteExportIdentity(route)] = struct{}{}
	}
	withdrawalKeys := map[string]struct{}{}
	var withdrawals []SubscriberRouteWithdrawal
	for _, route := range previous {
		if route.Suppressed {
			continue
		}
		key := subscriberRouteExportIdentity(route)
		if _, ok := desiredKeys[key]; ok {
			continue
		}
		if _, duplicate := withdrawalKeys[key]; duplicate {
			continue
		}
		withdrawalKeys[key] = struct{}{}
		withdrawals = append(withdrawals, SubscriberRouteWithdrawal{
			RouteKey:    route.RouteKey,
			VRF:         route.VRF,
			Family:      route.Family,
			Destination: route.Destination,
			Gateway:     route.Gateway,
			Reason:      "route no longer has active ownership",
		})
	}
	sort.SliceStable(withdrawals, func(i, j int) bool {
		return strings.Join([]string{withdrawals[i].VRF, withdrawals[i].Family, withdrawals[i].Destination, withdrawals[i].Gateway}, "|") <
			strings.Join([]string{withdrawals[j].VRF, withdrawals[j].Family, withdrawals[j].Destination, withdrawals[j].Gateway}, "|")
	})
	return withdrawals
}

func renderSubscriberRouteExportArtifact(plan SubscriberRouteExportPlan) string {
	lines := []string{
		"! AegisNAS subscriber route export",
		fmt.Sprintf("! generated_at %s", plan.GeneratedAt),
		fmt.Sprintf("! schema_version %d", plan.SchemaVersion),
	}
	exportedRoutes := activeExportedSubscriberRoutes(plan.Routes)
	for _, route := range exportedRoutes {
		lines = append(lines, renderSubscriberStaticRoute(route))
	}
	for _, protocol := range plan.Protocols {
		if !protocol.Enabled {
			continue
		}
		for _, family := range protocol.AddressFamilies {
			prefixListName := subscriberRoutePrefixListName(protocol, family)
			seq := 10
			matched := subscriberRoutesForProtocol(exportedRoutes, protocol, family)
			if len(matched) == 0 {
				continue
			}
			for _, route := range matched {
				if family == "ipv6" {
					lines = append(lines, fmt.Sprintf("ipv6 prefix-list %s seq %d permit %s", prefixListName, seq, route.Destination))
				} else {
					lines = append(lines, fmt.Sprintf("ip prefix-list %s seq %d permit %s", prefixListName, seq, route.Destination))
				}
				seq += 10
			}
			lines = append(lines, renderSubscriberRouteMap(protocol, family, prefixListName)...)
		}
		lines = append(lines, renderSubscriberProtocolExport(protocol, exportedRoutes)...)
	}
	lines = append(lines, "end", "write memory", "")
	return strings.Join(lines, "\n")
}

func buildSubscriberRouteExportCommands(plan SubscriberRouteExportPlan, vtyshPath string) [][]string {
	if plan.Driver == "file" {
		return [][]string{{"write-file", plan.ArtifactPath, plan.ArtifactSHA256}}
	}
	var commands [][]string
	for _, withdrawal := range plan.Withdrawals {
		line := renderSubscriberRouteWithdrawal(withdrawal)
		if strings.TrimSpace(line) != "" {
			commands = append(commands, []string{vtyshPath, "-c", "configure terminal", "-c", line, "-c", "end", "-c", "write memory"})
		}
	}
	for _, line := range strings.Split(plan.ArtifactText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		commands = append(commands, []string{vtyshPath, "-c", line})
	}
	return commands
}

func renderSubscriberStaticRoute(route SubscriberRouteExportRoute) string {
	gateway := firstNonEmptyString(route.Gateway, subscriberRouteNullGateway(route.Family))
	metric := firstPositiveSubscriberRouteInt(route.Metric, route.Preference)
	parts := []string{}
	if route.Family == "ipv6" {
		parts = append(parts, "ipv6", "route")
	} else {
		parts = append(parts, "ip", "route")
	}
	if !strings.EqualFold(route.VRF, "default") && strings.TrimSpace(route.VRF) != "" {
		parts = append(parts, "vrf", route.VRF)
	}
	parts = append(parts, route.Destination, gateway)
	if metric > 0 {
		parts = append(parts, strconv.Itoa(metric))
	}
	if tag := numericRouteTag(route.Tag); tag > 0 {
		parts = append(parts, "tag", strconv.Itoa(tag))
	}
	return strings.Join(parts, " ")
}

func renderSubscriberRouteWithdrawal(route SubscriberRouteWithdrawal) string {
	gateway := firstNonEmptyString(route.Gateway, subscriberRouteNullGateway(route.Family))
	parts := []string{"no"}
	if route.Family == "ipv6" {
		parts = append(parts, "ipv6", "route")
	} else {
		parts = append(parts, "ip", "route")
	}
	if !strings.EqualFold(route.VRF, "default") && strings.TrimSpace(route.VRF) != "" {
		parts = append(parts, "vrf", route.VRF)
	}
	parts = append(parts, route.Destination, gateway)
	return strings.Join(parts, " ")
}

func renderSubscriberRouteMap(protocol SubscriberRouteExportProtocol, family, prefixListName string) []string {
	routeMapName := subscriberRouteMapName(protocol, family)
	lines := []string{fmt.Sprintf("route-map %s permit 10", routeMapName)}
	if family == "ipv6" {
		lines = append(lines, fmt.Sprintf(" match ipv6 address prefix-list %s", prefixListName))
	} else {
		lines = append(lines, fmt.Sprintf(" match ip address prefix-list %s", prefixListName))
	}
	if protocol.Metric > 0 {
		lines = append(lines, fmt.Sprintf(" set metric %d", protocol.Metric))
	}
	if protocol.MED > 0 {
		lines = append(lines, fmt.Sprintf(" set metric %d", protocol.MED))
	}
	if protocol.LocalPreference > 0 && protocol.Protocol == "bgp" {
		lines = append(lines, fmt.Sprintf(" set local-preference %d", protocol.LocalPreference))
	}
	if len(protocol.Communities) > 0 && protocol.Protocol == "bgp" {
		lines = append(lines, " set community "+strings.Join(protocol.Communities, " "))
	}
	lines = append(lines, "exit")
	return lines
}

func renderSubscriberProtocolExport(protocol SubscriberRouteExportProtocol, routes []SubscriberRouteExportRoute) []string {
	var lines []string
	switch protocol.Protocol {
	case "bgp":
		vrfs := protocolVRFsForRoutes(protocol, routes)
		for _, vrf := range vrfs {
			router := fmt.Sprintf("router bgp %d", protocol.ASN)
			if !strings.EqualFold(vrf, "default") && vrf != "" {
				router += " vrf " + vrf
			}
			lines = append(lines, router)
			for _, family := range protocol.AddressFamilies {
				if len(subscriberRoutesForProtocolAndVRF(routes, protocol, family, vrf)) == 0 {
					continue
				}
				if family == "ipv6" {
					lines = append(lines, " address-family ipv6 unicast")
				} else {
					lines = append(lines, " address-family ipv4 unicast")
				}
				lines = append(lines, "  redistribute static route-map "+subscriberRouteMapName(protocol, family))
				lines = append(lines, " exit-address-family")
			}
			lines = append(lines, "exit")
		}
	case "ospf":
		vrfs := protocolVRFsForRoutes(protocol, routes)
		for _, vrf := range vrfs {
			router := "router ospf " + firstNonEmptyString(protocol.Instance, "1")
			if !strings.EqualFold(vrf, "default") && vrf != "" {
				router += " vrf " + vrf
			}
			lines = append(lines, router)
			if protocol.RouterID != "" {
				lines = append(lines, " router-id "+protocol.RouterID)
			}
			lines = append(lines, " redistribute static route-map "+subscriberRouteMapName(protocol, "ipv4"))
			lines = append(lines, "exit")
		}
	case "ospf3":
		vrfs := protocolVRFsForRoutes(protocol, routes)
		for _, vrf := range vrfs {
			router := "router ospf6 " + firstNonEmptyString(protocol.Instance, "1")
			if !strings.EqualFold(vrf, "default") && vrf != "" {
				router += " vrf " + vrf
			}
			lines = append(lines, router)
			if protocol.RouterID != "" {
				lines = append(lines, " router-id "+protocol.RouterID)
			}
			lines = append(lines, " redistribute static route-map "+subscriberRouteMapName(protocol, "ipv6"))
			lines = append(lines, "exit")
		}
	}
	return lines
}

func applySubscriberRouteExportPlan(plan SubscriberRouteExportPlan) error {
	switch plan.Driver {
	case "file":
		return writeManagedFileAtomic(plan.ArtifactPath, plan.ArtifactText, 0o640)
	case "frr-vtysh":
		for _, command := range plan.Commands {
			if len(command) == 0 {
				continue
			}
			cmd := subscriberRouteExportExecCommand(command[0], command[1:]...)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%s failed: %w\nOutput: %s", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
			}
		}
		return nil
	default:
		return fmt.Errorf("subscriber route export driver %q is unsupported", plan.Driver)
	}
}

func finalizeSubscriberRouteExportPlan(plan *SubscriberRouteExportPlan) {
	plan.CommandPreview = make([]string, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		plan.CommandPreview = append(plan.CommandPreview, strings.Join(command, " "))
	}
	plan.Summary.RouteCount = len(plan.Routes)
	plan.Summary.WithdrawRouteCount = len(plan.Withdrawals)
	plan.Summary.CommandCount = len(plan.Commands)
	plan.Summary.DiagnosticCount = len(plan.Diagnostics)
	vrfs := map[string]struct{}{}
	for _, route := range plan.Routes {
		vrfs[strings.ToLower(route.VRF)] = struct{}{}
		if route.Family == "ipv6" {
			plan.Summary.IPv6RouteCount++
		} else {
			plan.Summary.IPv4RouteCount++
		}
		if route.Suppressed {
			plan.Summary.SuppressedRoutes++
		} else {
			plan.Summary.ExportedRoutes++
		}
	}
	plan.Summary.VRFCount = len(vrfs)
	if strings.TrimSpace(plan.ArtifactText) != "" {
		sum := sha256.Sum256([]byte(plan.ArtifactText))
		plan.ArtifactSHA256 = "sha256:" + hex.EncodeToString(sum[:])
		if plan.Driver == "file" && len(plan.Commands) == 1 && len(plan.Commands[0]) == 3 && plan.Commands[0][0] == "write-file" {
			plan.Commands[0][2] = plan.ArtifactSHA256
			plan.CommandPreview[0] = strings.Join(plan.Commands[0], " ")
		}
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
	payload := struct {
		SchemaVersion int                             `json:"schema_version"`
		Driver        string                          `json:"driver"`
		ArtifactPath  string                          `json:"artifact_path"`
		Protocols     []SubscriberRouteExportProtocol `json:"protocols"`
		Routes        []SubscriberRouteExportRoute    `json:"routes"`
		Withdrawals   []SubscriberRouteWithdrawal     `json:"withdrawals"`
		ArtifactHash  string                          `json:"artifact_sha256"`
	}{
		SchemaVersion: plan.SchemaVersion,
		Driver:        plan.Driver,
		ArtifactPath:  plan.ArtifactPath,
		Protocols:     plan.Protocols,
		Routes:        plan.Routes,
		Withdrawals:   plan.Withdrawals,
		ArtifactHash:  plan.ArtifactSHA256,
	}
	plan.PlanFingerprint = sha256JSON(payload)
}

func subscriberRouteExportSnapshotInput(plan SubscriberRouteExportPlan, operation, status string, active bool, previousID, actor string, appliedAt, rolledBackAt *time.Time) db.SubscriberRouteExportSnapshotInput {
	return db.SubscriberRouteExportSnapshotInput{
		Operation:          operation,
		Status:             status,
		Active:             active,
		Driver:             plan.Driver,
		ProtocolCount:      plan.Summary.EnabledProtocols,
		RouteCount:         plan.Summary.ExportedRoutes,
		IPv4RouteCount:     plan.Summary.IPv4RouteCount,
		IPv6RouteCount:     plan.Summary.IPv6RouteCount,
		WithdrawRouteCount: plan.Summary.WithdrawRouteCount,
		CommandCount:       plan.Summary.CommandCount,
		DiagnosticCount:    plan.Summary.DiagnosticCount,
		PlanFingerprint:    plan.PlanFingerprint,
		ArtifactPath:       plan.ArtifactPath,
		ArtifactSHA256:     plan.ArtifactSHA256,
		ArtifactText:       plan.ArtifactText,
		CommandText:        strings.Join(plan.CommandPreview, "\n"),
		PlanJSON:           marshalJSON(plan),
		DiagnosticsJSON:    marshalJSON(plan.Diagnostics),
		SummaryJSON:        marshalJSON(plan.Summary),
		PreviousSnapshotID: previousID,
		Actor:              actor,
		AppliedAt:          appliedAt,
		RolledBackAt:       rolledBackAt,
	}
}

func subscriberRouteExportEventInput(plan SubscriberRouteExportPlan, operation, status, snapshotID, previousID, actor string, details map[string]any) db.SubscriberRouteExportEventInput {
	if details == nil {
		details = map[string]any{}
	}
	return db.SubscriberRouteExportEventInput{
		Operation:          operation,
		Status:             status,
		SnapshotID:         snapshotID,
		PreviousSnapshotID: previousID,
		Driver:             plan.Driver,
		ProtocolCount:      plan.Summary.EnabledProtocols,
		RouteCount:         plan.Summary.ExportedRoutes,
		IPv4RouteCount:     plan.Summary.IPv4RouteCount,
		IPv6RouteCount:     plan.Summary.IPv6RouteCount,
		WithdrawRouteCount: plan.Summary.WithdrawRouteCount,
		CommandCount:       plan.Summary.CommandCount,
		DiagnosticCount:    plan.Summary.DiagnosticCount,
		PlanFingerprint:    plan.PlanFingerprint,
		ArtifactSHA256:     plan.ArtifactSHA256,
		DiagnosticsJSON:    marshalJSON(plan.Diagnostics),
		DetailsJSON:        marshalJSON(details),
		Actor:              actor,
	}
}

func subscriberRouteExportStatusDetails(plan SubscriberRouteExportPlan, snapshotID, previousID, eventID string) map[string]any {
	return map[string]any{
		"snapshot_id":          snapshotID,
		"previous_snapshot_id": previousID,
		"event_id":             eventID,
		"driver":               plan.Driver,
		"artifact_path":        plan.ArtifactPath,
		"artifact_sha256":      plan.ArtifactSHA256,
		"plan_fingerprint":     plan.PlanFingerprint,
		"route_count":          plan.Summary.ExportedRoutes,
		"withdraw_route_count": plan.Summary.WithdrawRouteCount,
		"protocol_count":       plan.Summary.EnabledProtocols,
		"diagnostic_count":     plan.Summary.DiagnosticCount,
	}
}

func routeExportPlanStatusToEventStatus(status string) string {
	switch status {
	case "blocked":
		return "blocked"
	case "degraded":
		return "degraded"
	case "skipped":
		return "skipped"
	default:
		return "previewed"
	}
}

func routeExportApplyStatus(status string) string {
	switch status {
	case "degraded":
		return "degraded"
	default:
		return "applied"
	}
}

func normalizeSubscriberRouteExportOperation(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "apply", "sync", "preview", "rollback":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func effectiveSubscriberRouteExportDriver(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "frr-vtysh":
		return "frr-vtysh"
	default:
		return "file"
	}
}

func effectiveSubscriberRouteExportArtifactPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultRouteExportArtifactPath
	}
	return value
}

func effectiveSubscriberRouteExportVtyshPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultRouteExportVtyshPath
	}
	return value
}

func effectiveSubscriberRouteExportMaxRoutes(policy config.RadiusDynamicRoutingConfig) int {
	if policy.MaxExportedRoutes <= 0 {
		return 4096
	}
	return policy.MaxExportedRoutes
}

func shouldSuppressSubscriberRoute(dampening config.RadiusRouteDampeningConfig, route SubscriberRouteExportRoute) bool {
	if !dampening.Enabled || dampening.MinRouteAgeSeconds <= 0 {
		return false
	}
	updatedAt := parseSubscriberRouteExportTime(firstNonEmptyString(route.UpdatedAt, route.InstalledAt))
	if updatedAt.IsZero() {
		return false
	}
	return time.Since(updatedAt) < time.Duration(dampening.MinRouteAgeSeconds)*time.Second
}

func parseSubscriberRouteExportTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func subscriberRouteProtocolKey(protocol SubscriberRouteExportProtocol) string {
	return strings.Join([]string{
		strings.ToLower(protocol.Protocol),
		strings.ToLower(firstNonEmptyString(protocol.VRF, "all")),
		strings.ToLower(firstNonEmptyString(protocol.Instance, strconv.FormatInt(protocol.ASN, 10))),
		strings.Join(protocol.AddressFamilies, ","),
	}, ":")
}

func subscriberRouteExportIdentity(route SubscriberRouteExportRoute) string {
	return strings.Join([]string{strings.ToLower(route.VRF), route.Family, route.Destination, route.Gateway}, "|")
}

func subscriberRoutesForProtocol(routes []SubscriberRouteExportRoute, protocol SubscriberRouteExportProtocol, family string) []SubscriberRouteExportRoute {
	return subscriberRoutesForProtocolAndVRF(routes, protocol, family, "")
}

func subscriberRoutesForProtocolAndVRF(routes []SubscriberRouteExportRoute, protocol SubscriberRouteExportProtocol, family, vrf string) []SubscriberRouteExportRoute {
	var out []SubscriberRouteExportRoute
	for _, route := range routes {
		if route.Suppressed || route.Family != family {
			continue
		}
		if vrf != "" && !strings.EqualFold(route.VRF, vrf) {
			continue
		}
		if stringSliceContains(route.Protocols, protocol.Key) {
			out = append(out, route)
		}
	}
	return out
}

func protocolVRFsForRoutes(protocol SubscriberRouteExportProtocol, routes []SubscriberRouteExportRoute) []string {
	seen := map[string]struct{}{}
	for _, route := range routes {
		if route.Suppressed || !stringSliceContains(route.Protocols, protocol.Key) {
			continue
		}
		seen[route.VRF] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for vrf := range seen {
		out = append(out, vrf)
	}
	sort.Strings(out)
	return out
}

func activeExportedSubscriberRoutes(routes []SubscriberRouteExportRoute) []SubscriberRouteExportRoute {
	out := make([]SubscriberRouteExportRoute, 0, len(routes))
	for _, route := range routes {
		if !route.Suppressed {
			out = append(out, route)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return subscriberRouteExportIdentity(out[i]) < subscriberRouteExportIdentity(out[j])
	})
	return out
}

func countExportedSubscriberRoutes(routes []SubscriberRouteExportRoute) int {
	count := 0
	for _, route := range routes {
		if !route.Suppressed {
			count++
		}
	}
	return count
}

func countSuppressedSubscriberRoutes(routes []SubscriberRouteExportRoute) int {
	count := 0
	for _, route := range routes {
		if route.Suppressed {
			count++
		}
	}
	return count
}

func subscriberRoutePrefixListName(protocol SubscriberRouteExportProtocol, family string) string {
	return safeFRRName(strings.Join([]string{"AEGISNAS", strings.ToUpper(protocol.Protocol), strings.ToUpper(safeFRRName(protocol.VRF)), strings.ToUpper(family)}, "_"))
}

func subscriberRouteMapName(protocol SubscriberRouteExportProtocol, family string) string {
	base := safeFRRName(protocol.RouteMap)
	if base == "" {
		base = "AEGISNAS-SUBSCRIBER"
	}
	return safeFRRName(base + "-" + strings.ToUpper(family))
}

func safeFRRName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
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
		case r == '_' || r == '-' || r == '.' || r == ':':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
		if builder.Len() >= 96 {
			break
		}
	}
	return strings.Trim(builder.String(), "-_.:")
}

func subscriberRouteNullGateway(family string) string {
	if family == "ipv6" {
		return "Null0"
	}
	return "Null0"
}

func numericRouteTag(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err == nil && parsed > 0 && parsed <= 429496729 {
		return parsed
	}
	sum := sha256.Sum256([]byte(value))
	number := int(sum[0])<<16 | int(sum[1])<<8 | int(sum[2])
	if number == 0 {
		number = 1
	}
	return number
}

func sortedUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func firstPositiveSubscriberRouteInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
