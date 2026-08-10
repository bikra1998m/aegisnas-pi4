package radius

import (
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const NASCapabilityOwnershipSchemaVersion = 1

type NASCapabilityOwnershipReport struct {
	SchemaVersion int                              `json:"schema_version"`
	Status        string                           `json:"status"`
	Message       string                           `json:"message"`
	Summary       db.NASCapabilityOwnershipSummary `json:"summary"`
	Clients       []db.NASCapabilityClient         `json:"clients,omitempty"`
	SessionOwners []db.NASSessionOwnershipRecord   `json:"session_owners,omitempty"`
	Synced        int                              `json:"synced"`
	Warnings      []string                         `json:"warnings,omitempty"`
	RFCs          []string                         `json:"rfcs"`
}

type OutboundDACOwnershipDecision struct {
	SchemaVersion       int      `json:"schema_version"`
	Status              string   `json:"status"`
	Message             string   `json:"message"`
	SessionID           string   `json:"session_id,omitempty"`
	OwnershipStatus     string   `json:"ownership_status,omitempty"`
	OwnershipSource     string   `json:"ownership_source,omitempty"`
	OwnerNode           string   `json:"owner_node,omitempty"`
	OwnerResolvedFrom   string   `json:"owner_resolved_from,omitempty"`
	CapabilityHash      string   `json:"capability_hash,omitempty"`
	SupportedActions    []string `json:"supported_actions,omitempty"`
	SupportedTransports []string `json:"supported_transports,omitempty"`
	Required            []string `json:"required,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Blockers            []string `json:"blockers,omitempty"`
	RFCs                []string `json:"rfcs"`
}

func BuildNASCapabilityOwnershipReport(cfg *config.Config) NASCapabilityOwnershipReport {
	report := NASCapabilityOwnershipReport{
		SchemaVersion: NASCapabilityOwnershipSchemaVersion,
		Status:        "ready",
		Message:       "NAS capability and session ownership registry is ready.",
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6614"},
	}
	if db.DB == nil {
		report.Status = "degraded"
		report.Message = "NAS capability and ownership registry is unavailable because the database is not initialized."
		return report
	}
	synced, syncErr := db.SyncNASSessionOwnershipFromSessions(OutboundDACRuntimeComponent, 4*time.Hour, 1000)
	if syncErr != nil {
		report.Status = "degraded"
		report.Warnings = append(report.Warnings, "Session ownership sync failed: "+syncErr.Error())
	}
	report.Synced = synced
	summary, err := db.GetNASCapabilityOwnershipSummary()
	if err != nil {
		report.Status = "degraded"
		report.Message = "NAS capability ownership summary is unavailable."
		report.Warnings = append(report.Warnings, err.Error())
		return report
	}
	clients, _ := db.ListNASCapabilityClients(50)
	owners, _ := db.ListNASSessionOwnership(50)
	report.Summary = summary
	report.Clients = clients
	report.SessionOwners = owners
	report.Status = summary.Status
	report.Message = summary.Message
	if cfg != nil && config.EffectiveDynamicAuthConfig(cfg.Radius.DynamicAuth).OutboundRequireKnownClient && summary.EnabledClients == 0 {
		report.Status = "blocked"
		report.Message = "Known-client outbound DAC is required, but no NAS capability clients are enabled."
	}
	if summary.ActiveSessions > 0 && summary.OwnershipCoverage < 100 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("Session ownership coverage is %d%%.", summary.OwnershipCoverage))
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if summary.CapabilityClients == 0 && summary.EnabledClients > 0 {
		report.Warnings = append(report.Warnings, "Enabled NAS clients do not publish explicit capability JSON; defaults are used until NAS-0013 templates are assigned.")
	}
	return report
}

func evaluateOutboundDACOwnershipCapability(cfg *config.Config, request OutboundDACRequest, target OutboundDACTarget) OutboundDACOwnershipDecision {
	decision := OutboundDACOwnershipDecision{
		SchemaVersion: NASCapabilityOwnershipSchemaVersion,
		Status:        "ready",
		Message:       "NAS ownership and capability checks passed.",
		RFCs:          []string{"RFC 2865", "RFC 5176"},
	}
	if db.DB == nil {
		decision.Status = "degraded"
		decision.Message = "NAS ownership registry is unavailable."
		decision.Warnings = append(decision.Warnings, "database is not initialized")
		return decision
	}
	sessionKey := firstNonEmptyString(request.SessionID, request.AcctSessionID)
	var owner db.NASSessionOwnershipRecord
	if sessionKey != "" {
		_, _ = db.SyncNASSessionOwnershipFromSessions(OutboundDACRuntimeComponent, 4*time.Hour, 1000)
		record, err := db.LookupNASSessionOwnership(sessionKey)
		switch {
		case err == nil:
			owner = record
			decision.SessionID = record.SessionID
			decision.OwnershipStatus = record.OwnerStatus
			decision.OwnershipSource = record.OwnerSource
			decision.OwnerNode = record.OwnerNode
			decision.OwnerResolvedFrom = "nas_session_ownership"
			decision.CapabilityHash = record.CapabilityHash
			decision.SupportedActions = append([]string(nil), record.SupportedActions...)
			decision.SupportedTransports = append([]string(nil), record.SupportedTransports...)
			if record.OwnerStatus == db.NASSessionOwnershipStatusStale || record.OwnerStatus == db.NASSessionOwnershipStatusUnknown {
				decision.Warnings = append(decision.Warnings, "session ownership is "+record.OwnerStatus)
				decision.Status = "degraded"
			}
			if blocker := outboundDACOwnershipTargetConflict(record, target); blocker != "" {
				decision.Blockers = append(decision.Blockers, blocker)
			}
		case err == sql.ErrNoRows:
			decision.Warnings = append(decision.Warnings, "session_id has no ownership row; using target and NAS client capabilities only")
			decision.Status = "degraded"
		default:
			decision.Warnings = append(decision.Warnings, "session ownership lookup failed: "+err.Error())
			decision.Status = "degraded"
		}
	} else {
		decision.Status = "not_required"
		decision.Message = "No session selector was supplied; target capability checks were applied without session ownership."
	}

	capabilities, capabilityHash, supportedActions, supportedTransports, source := capabilitiesForOutboundDACTarget(cfg, target, owner)
	if decision.OwnerResolvedFrom == "" {
		decision.OwnerResolvedFrom = source
	}
	if decision.CapabilityHash == "" {
		decision.CapabilityHash = capabilityHash
	}
	if len(decision.SupportedActions) == 0 {
		decision.SupportedActions = supportedActions
	}
	if len(decision.SupportedTransports) == 0 {
		decision.SupportedTransports = supportedTransports
	}
	required := requiredOutboundDACCapabilities(request, target)
	decision.Required = required
	for _, requirement := range required {
		value, known := capabilityBoolAt(capabilities, requirement)
		switch {
		case known && !value:
			decision.Blockers = append(decision.Blockers, fmt.Sprintf("NAS capability %s is explicitly disabled", requirement))
		case !known:
			decision.Warnings = append(decision.Warnings, fmt.Sprintf("NAS capability %s was not declared; default capability policy was used", requirement))
		}
	}
	if !containsStringFold(decision.SupportedActions, request.Action) && request.Action != "" {
		decision.Blockers = append(decision.Blockers, "NAS ownership registry does not list action "+request.Action)
	}
	if request.VendorAction != "" && !containsStringFold(decision.SupportedActions, "vendor_actions") {
		decision.Blockers = append(decision.Blockers, "NAS ownership registry does not list vendor dynamic actions")
	}
	requiredTransport := outboundDACCapabilityTransport(target)
	if requiredTransport != "" && !containsStringFold(decision.SupportedTransports, requiredTransport) {
		decision.Blockers = append(decision.Blockers, "NAS ownership registry does not list transport "+requiredTransport)
	}
	if len(decision.Blockers) > 0 {
		decision.Status = "blocked"
		decision.Message = strings.Join(decision.Blockers, "; ")
	} else if len(decision.Warnings) > 0 && decision.Status == "ready" {
		decision.Status = "warned"
		decision.Message = strings.Join(decision.Warnings, "; ")
	}
	return decision
}

func enrichOutboundDACRequestFromOwnership(request OutboundDACRequest) (OutboundDACRequest, []string) {
	sessionKey := strings.TrimSpace(firstNonEmptyString(request.SessionID, request.AcctSessionID))
	if sessionKey == "" || db.DB == nil {
		return request, nil
	}
	_, _ = db.SyncNASSessionOwnershipFromSessions(OutboundDACRuntimeComponent, 4*time.Hour, 1000)
	owner, err := db.LookupNASSessionOwnership(sessionKey)
	if err != nil {
		return request, nil
	}
	warnings := []string{}
	if owner.OwnerStatus == db.NASSessionOwnershipStatusStale {
		warnings = append(warnings, "session ownership is stale; verify the NAS before sending")
	}
	if request.SessionID == "" {
		request.SessionID = owner.SessionID
	}
	if request.AcctSessionID == "" {
		request.AcctSessionID = firstNonEmptyString(owner.AcctSessionID, owner.SessionID)
	}
	targetMatchesOwner := request.TargetAddress == "" ||
		targetAddressMatches(request.TargetAddress, owner.NASIPAddress) ||
		strings.EqualFold(strings.TrimSpace(request.TargetAddress), strings.TrimSpace(owner.ShortName)) ||
		strings.EqualFold(strings.TrimSpace(request.TargetAddress), strings.TrimSpace(owner.NASIdentifier))
	if request.TargetAddress == "" {
		request.TargetAddress = owner.NASIPAddress
	}
	if targetMatchesOwner && request.NASIPAddress == "" {
		request.NASIPAddress = owner.NASIPAddress
	}
	if targetMatchesOwner && request.NASIdentifier == "" {
		request.NASIdentifier = owner.NASIdentifier
	}
	if targetMatchesOwner && request.ShortName == "" {
		request.ShortName = owner.ShortName
	}
	if targetMatchesOwner && request.NASType == "" {
		request.NASType = owner.NASType
	}
	if targetMatchesOwner && request.TargetTransport == "" {
		request.TargetTransport = owner.Transport
	}
	if request.DeliveryMode == "" || request.DeliveryMode == outboundDACDeliveryDirect {
		request.DeliveryMode = owner.DeliveryMode
	}
	if request.ProxyRoute == "" {
		request.ProxyRoute = owner.ProxyRoute
	}
	if request.ProxyRealm == "" {
		request.ProxyRealm = owner.ProxyRealm
	}
	if request.ProxyHomeServer == "" {
		request.ProxyHomeServer = owner.ProxyHomeServer
	}
	return request, warnings
}

func capabilitiesForOutboundDACTarget(cfg *config.Config, target OutboundDACTarget, owner db.NASSessionOwnershipRecord) (map[string]any, string, []string, []string, string) {
	capabilities := effectiveDefaultNASCaps(target)
	source := "default"
	if len(owner.Capabilities) > 0 {
		capabilities = mergeCapabilityMaps(capabilities, owner.Capabilities)
		source = "session_ownership"
	}
	if db.DB != nil {
		client, err := db.LookupNASCapabilityClient(target.Address, target.NASIdentifier, target.ShortName)
		if err == nil {
			capabilities = mergeCapabilityMaps(capabilities, client.Capabilities)
			source = "radius_client"
		}
	}
	if cfg != nil {
		for _, client := range configuredRadiusClients(cfg) {
			if outboundDACClientMatches(client, OutboundDACRequest{NASIdentifier: target.NASIdentifier, ShortName: target.ShortName, NASIPAddress: target.NASIPAddress}, target.Address) {
				source = firstNonEmptyString(source, "config")
				break
			}
		}
	}
	actions, transports := supportedActionsFromCapabilities(capabilities, target.Transport)
	return capabilities, db.FingerprintOutboundDAC(fmt.Sprint(capabilities), strings.Join(actions, ","), strings.Join(transports, ",")), actions, transports, source
}

func effectiveDefaultNASCaps(target OutboundDACTarget) map[string]any {
	vendorActions := outboundDACVendorActionPackSupported(strings.ToLower(strings.TrimSpace(target.NASType)))
	if strings.EqualFold(target.NASType, productconfigs.VendorPackStandard) || strings.TrimSpace(target.NASType) == "" {
		vendorActions = false
	}
	return map[string]any{
		"dynamic_authorization": map[string]any{
			"coa":            true,
			"disconnect":     true,
			"vendor_actions": vendorActions,
			"transport": map[string]any{
				"udp":    true,
				"proxy":  target.DeliveryMode == outboundDACDeliveryProxy,
				"radsec": target.Transport == "radsec",
			},
		},
		"policy": map[string]any{
			"role":       true,
			"vlan":       true,
			"filter_id":  true,
			"acl":        true,
			"qos":        true,
			"quarantine": true,
		},
	}
}

func requiredOutboundDACCapabilities(request OutboundDACRequest, target OutboundDACTarget) []string {
	required := []string{}
	switch request.Action {
	case "coa":
		required = append(required, "dynamic_authorization.coa")
	case "disconnect":
		required = append(required, "dynamic_authorization.disconnect")
	}
	if transport := outboundDACCapabilityTransport(target); transport != "" {
		required = append(required, "dynamic_authorization.transport."+transport)
	}
	if request.VendorAction != "" {
		required = append(required, "dynamic_authorization.vendor_actions")
		switch request.VendorAction {
		case "role":
			required = append(required, "policy.role")
		case "vlan":
			required = append(required, "policy.vlan")
		case "acl":
			required = append(required, "policy.acl")
		case "qos":
			required = append(required, "policy.qos")
		case "quarantine", "unquarantine":
			required = append(required, "policy.quarantine")
		}
	}
	if request.FilterID != "" {
		required = append(required, "policy.filter_id")
	}
	if request.VLAN > 0 {
		required = append(required, "policy.vlan")
	}
	return uniqueOwnershipStrings(required)
}

func outboundDACCapabilityTransport(target OutboundDACTarget) string {
	if target.DeliveryMode == outboundDACDeliveryProxy {
		return "proxy"
	}
	if strings.EqualFold(target.Transport, "radsec") {
		return "radsec"
	}
	if strings.EqualFold(target.Transport, "udp") || target.Transport == "" {
		return "udp"
	}
	return strings.ToLower(strings.TrimSpace(target.Transport))
}

func outboundDACOwnershipTargetConflict(owner db.NASSessionOwnershipRecord, target OutboundDACTarget) string {
	if owner.SessionID == "" || target.Address == "" {
		return ""
	}
	ownerTargets := []string{owner.NASIPAddress, owner.ShortName, owner.NASIdentifier}
	requestTargets := []string{target.Address, target.ShortName, target.NASIdentifier}
	for _, ownerTarget := range ownerTargets {
		if strings.TrimSpace(ownerTarget) == "" {
			continue
		}
		for _, requestTarget := range requestTargets {
			if strings.EqualFold(strings.TrimSpace(ownerTarget), strings.TrimSpace(requestTarget)) {
				return ""
			}
		}
	}
	return fmt.Sprintf("session %s is owned by NAS %s but request targets %s", owner.SessionID, firstNonEmptyString(owner.ShortName, owner.NASIPAddress, owner.NASIdentifier), target.Endpoint)
}

func supportedActionsFromCapabilities(capabilities map[string]any, transport string) ([]string, []string) {
	actions, transports := db.SupportedNASSessionOwnershipFromCapabilities(capabilities, transport)
	if capabilityBoolDefaultLocal(capabilities, "dynamic_authorization.coa", true) && !containsStringFold(actions, "coa") {
		actions = append(actions, "coa")
	}
	if capabilityBoolDefaultLocal(capabilities, "dynamic_authorization.disconnect", true) && !containsStringFold(actions, "disconnect") {
		actions = append(actions, "disconnect")
	}
	if capabilityBoolDefaultLocal(capabilities, "dynamic_authorization.transport.udp", true) && !containsStringFold(transports, "udp") {
		transports = append(transports, "udp")
	}
	sort.Strings(actions)
	sort.Strings(transports)
	return actions, transports
}

func capabilityBoolAt(capabilities map[string]any, path string) (bool, bool) {
	value, ok := capabilityValueAt(capabilities, path)
	if !ok {
		return false, false
	}
	boolValue, ok := value.(bool)
	return boolValue, ok
}

func capabilityBoolDefaultLocal(capabilities map[string]any, path string, fallback bool) bool {
	value, ok := capabilityBoolAt(capabilities, path)
	if !ok {
		return fallback
	}
	return value
}

func capabilityValueAt(capabilities map[string]any, path string) (any, bool) {
	var current any = capabilities
	for _, part := range strings.Split(path, ".") {
		node, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := node[part]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func mergeCapabilityMaps(base, overlay map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		if existing, ok := out[key].(map[string]any); ok {
			if incoming, ok := value.(map[string]any); ok {
				out[key] = mergeCapabilityMaps(existing, incoming)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func uniqueOwnershipStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[strings.ToLower(value)] {
			continue
		}
		seen[strings.ToLower(value)] = true
		out = append(out, value)
	}
	return out
}

func containsStringFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func targetAddressMatches(address, candidate string) bool {
	address = strings.TrimSpace(address)
	candidate = strings.TrimSpace(candidate)
	if address == "" || candidate == "" {
		return false
	}
	if strings.EqualFold(address, candidate) {
		return true
	}
	addressIP := net.ParseIP(address)
	candidateIP := net.ParseIP(candidate)
	return addressIP != nil && candidateIP != nil && addressIP.Equal(candidateIP)
}
