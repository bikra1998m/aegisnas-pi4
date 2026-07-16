package mab

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const SchemaVersion = 1

type Policy struct {
	SchemaVersion             int      `json:"schema_version"`
	Enabled                   bool     `json:"enabled"`
	Mode                      string   `json:"mode"`
	FailClosed                bool     `json:"fail_closed"`
	UnknownEndpointPolicy     string   `json:"unknown_endpoint_policy"`
	DefaultRole               string   `json:"default_role,omitempty"`
	GuestRole                 string   `json:"guest_role,omitempty"`
	QuarantineRole            string   `json:"quarantine_role,omitempty"`
	AllowedNASPortTypes       []string `json:"allowed_nas_port_types"`
	MACFormats                []string `json:"mac_formats"`
	PasswordPolicy            string   `json:"password_policy"`
	ProfilingLinkEnabled      bool     `json:"profiling_link_enabled"`
	EndpointInventoryFallback bool     `json:"endpoint_inventory_fallback"`
	RevalidateIntervalSeconds int      `json:"revalidate_interval_seconds"`
	CacheTTLSeconds           int      `json:"cache_ttl_seconds"`
	AuditEnabled              bool     `json:"audit_enabled"`
	RetentionLimit            int      `json:"retention_limit"`
}

type Summary struct {
	FreeRADIUSAuthorizeReady bool   `json:"freeradius_authorize_ready"`
	EndpointStoreReady       bool   `json:"endpoint_store_ready"`
	KnownEndpointCount       int    `json:"known_endpoint_count"`
	ApprovedEndpointCount    int    `json:"approved_endpoint_count"`
	QuarantinedEndpointCount int    `json:"quarantined_endpoint_count"`
	DeniedEndpointCount      int    `json:"denied_endpoint_count"`
	ProfileLinkedCount       int    `json:"profile_linked_count"`
	LastEndpointUpdate       string `json:"last_endpoint_update,omitempty"`
	LastDecision             string `json:"last_decision,omitempty"`
	LastDecisionReason       string `json:"last_decision_reason,omitempty"`
}

type Report struct {
	SchemaVersion   int                   `json:"schema_version"`
	GeneratedAt     string                `json:"generated_at"`
	Enabled         bool                  `json:"enabled"`
	Status          string                `json:"status"`
	Message         string                `json:"message"`
	Policy          Policy                `json:"policy"`
	Summary         Summary               `json:"summary"`
	EndpointSummary db.MABEndpointSummary `json:"endpoint_summary"`
	AuditSummary    db.MABEventSummary    `json:"audit_summary"`
	Recent          []db.MABEvent         `json:"recent,omitempty"`
}

type AccessRequest struct {
	Username          string `json:"username"`
	Password          string `json:"password,omitempty"`
	CallingStationID  string `json:"calling_station_id"`
	CalledStationID   string `json:"called_station_id,omitempty"`
	NASIdentifier     string `json:"nas_identifier,omitempty"`
	NASIPAddress      string `json:"nas_ip_address,omitempty"`
	NASPort           string `json:"nas_port,omitempty"`
	NASPortType       string `json:"nas_port_type,omitempty"`
	EAPMessagePresent bool   `json:"eap_message_present"`
}

type Result struct {
	Candidate        bool                 `json:"candidate"`
	Accepted         bool                 `json:"accepted"`
	Decision         string               `json:"decision"`
	State            string               `json:"state"`
	Reason           string               `json:"reason"`
	MAC              string               `json:"mac,omitempty"`
	MACHash          string               `json:"mac_hash,omitempty"`
	Role             string               `json:"role,omitempty"`
	VLAN             int                  `json:"vlan,omitempty"`
	BandwidthProfile string               `json:"bandwidth_profile,omitempty"`
	ACLPolicyName    string               `json:"acl_policy_name,omitempty"`
	Tenant           string               `json:"tenant,omitempty"`
	DeviceGroup      string               `json:"device_group,omitempty"`
	Posture          string               `json:"posture,omitempty"`
	Endpoint         *db.MABEndpoint      `json:"endpoint,omitempty"`
	Profile          *db.MABDeviceProfile `json:"profile,omitempty"`
	ReplyMessage     string               `json:"reply_message,omitempty"`
	LatencyMS        int64                `json:"latency_ms"`
	Warnings         []string             `json:"warnings,omitempty"`
}

func PolicyFromConfig(cfg *config.Config) Policy {
	raw := config.MABConfig{}
	if cfg != nil {
		raw = config.EffectiveMABConfig(cfg.MAB)
	}
	return Policy{
		SchemaVersion:             SchemaVersion,
		Enabled:                   raw.Enabled,
		Mode:                      normalizeMode(raw.Mode),
		FailClosed:                raw.FailClosed,
		UnknownEndpointPolicy:     normalizeUnknownPolicy(raw.UnknownEndpointPolicy),
		DefaultRole:               strings.TrimSpace(raw.DefaultRole),
		GuestRole:                 strings.TrimSpace(raw.GuestRole),
		QuarantineRole:            strings.TrimSpace(raw.QuarantineRole),
		AllowedNASPortTypes:       normalizeList(raw.AllowedNASPortTypes),
		MACFormats:                normalizeFormats(raw.MACFormats),
		PasswordPolicy:            normalizePasswordPolicy(raw.PasswordPolicy),
		ProfilingLinkEnabled:      raw.ProfilingLinkEnabled,
		EndpointInventoryFallback: raw.EndpointInventoryFallback,
		RevalidateIntervalSeconds: raw.RevalidateIntervalSeconds,
		CacheTTLSeconds:           raw.CacheTTLSeconds,
		AuditEnabled:              raw.AuditEnabled,
		RetentionLimit:            raw.RetentionLimit,
	}
}

func BuildReport(cfg *config.Config) Report {
	now := time.Now().UTC()
	policy := PolicyFromConfig(cfg)
	report := Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Enabled:       policy.Enabled,
		Status:        "ready",
		Policy:        policy,
		Summary: Summary{
			FreeRADIUSAuthorizeReady: policy.Enabled,
			EndpointStoreReady:       db.DB != nil,
		},
	}
	if db.DB != nil {
		if summary, err := db.GetMABEndpointSummary(); err == nil {
			report.EndpointSummary = summary
			report.Summary.KnownEndpointCount = summary.TotalEndpoints
			report.Summary.ApprovedEndpointCount = summary.ApprovedCount
			report.Summary.QuarantinedEndpointCount = summary.QuarantinedCount
			report.Summary.DeniedEndpointCount = summary.DeniedCount
			report.Summary.ProfileLinkedCount = summary.ProfileLinkedCount
			report.Summary.LastEndpointUpdate = summary.LastUpdatedAt
		}
		if audit, err := db.GetMABEventSummary(); err == nil {
			report.AuditSummary = audit
			report.Summary.LastDecision = audit.LastDecision
			report.Summary.LastDecisionReason = audit.LastReason
		}
		if recent, err := db.ListMABEvents("", "", 25); err == nil {
			report.Recent = recent
		}
	}

	switch {
	case !policy.Enabled:
		report.Status = "disabled"
		report.Message = "MAC Authentication Bypass is disabled; 802.1X and portal identity behavior is unchanged."
	case db.DB == nil:
		report.Status = "blocked"
		report.Message = "MAB requires the database for endpoint state and audit history."
	case policy.Mode == "monitor":
		report.Status = "degraded"
		report.Message = "MAB is in monitor mode; endpoint decisions are evaluated and audited but not enforced by generated policy."
	case !policy.FailClosed:
		report.Status = "degraded"
		report.Message = "MAB enforcement is active but fail_closed is disabled."
	case report.EndpointSummary.ApprovedCount == 0 && report.EndpointSummary.QuarantinedCount == 0:
		report.Status = "degraded"
		report.Message = "MAB enforcement is configured but no approved or quarantined endpoints are registered."
	default:
		report.Message = "MAB is enforceable with persistent endpoint state, profile linkage, generated FreeRADIUS entries, and audit evidence."
	}
	return report
}

func Evaluate(cfg *config.Config, req AccessRequest, recordAudit bool) Result {
	started := time.Now()
	policy := PolicyFromConfig(cfg)
	result := Result{
		Decision: "skipped",
		State:    "disabled",
		Reason:   "MAB is disabled",
	}
	if !policy.Enabled {
		return result
	}
	result.State = "candidate"
	if req.EAPMessagePresent {
		result.State = "not_mab"
		result.Reason = "EAP-Message is present; request belongs to 802.1X"
		return result
	}
	if strings.TrimSpace(req.NASPortType) != "" && !policyAllowsPortType(policy, req.NASPortType) {
		result.Decision = "unsupported"
		result.State = "unsupported_nas_port"
		result.Reason = "NAS-Port-Type is not allowed for MAB"
		result.LatencyMS = elapsedMillis(started)
		maybeRecord(cfg, policy, req, result, recordAudit)
		return result
	}
	mac := firstNormalizedMAC(req.CallingStationID, req.Username)
	if mac == "" {
		result.Decision = "rejected"
		result.State = "invalid_mac"
		result.Reason = "request does not contain a valid MAC identity"
		result.LatencyMS = elapsedMillis(started)
		maybeRecord(cfg, policy, req, applyMonitorMode(policy, result), recordAudit)
		return applyMonitorMode(policy, result)
	}
	result.Candidate = true
	result.MAC = mac
	result.MACHash = db.HashMABMAC(mac)
	if passwordPolicyRejects(policy, req, mac) {
		result.Decision = "rejected"
		result.State = "password_mismatch"
		result.Reason = "MAB password policy did not match the MAC identity"
		result.LatencyMS = elapsedMillis(started)
		result = applyMonitorMode(policy, result)
		maybeRecord(cfg, policy, req, result, recordAudit)
		return result
	}

	endpoint, found, err := lookupEndpoint(mac)
	if err != nil {
		result.Decision = failDecision(policy)
		result.State = "lookup_failed"
		result.Reason = err.Error()
		result.Role = failOpenRole(policy)
		result.Accepted = result.Decision == "fail_open"
		result.LatencyMS = elapsedMillis(started)
		result = applyMonitorMode(policy, result)
		maybeRecord(cfg, policy, req, result, recordAudit)
		return result
	}
	var profile *db.MABDeviceProfile
	if policy.EndpointInventoryFallback || policy.ProfilingLinkEnabled {
		if p, ok, err := db.GetMABDeviceProfile(mac); err == nil && ok {
			profile = &p
			result.Profile = profile
		}
	}
	if found {
		result.Endpoint = &endpoint
		endpointStatusDecision(policy, endpoint, profile, &result)
	} else {
		unknownEndpointDecision(policy, profile, &result)
	}
	result.LatencyMS = elapsedMillis(started)
	result = applyMonitorMode(policy, result)
	if result.Accepted && found {
		_ = db.TouchMABEndpoint(mac, time.Now().UTC())
	}
	maybeRecord(cfg, policy, req, result, recordAudit)
	return result
}

func MACVariants(mac string, formats []string) []string {
	normalized := db.NormalizeMABMAC(mac)
	if normalized == "" {
		return nil
	}
	normalizedFormats := normalizeFormats(formats)
	if len(normalizedFormats) == 0 {
		normalizedFormats = []string{"colon", "hyphen", "plain", "cisco-dot"}
	}
	seen := map[string]struct{}{}
	out := []string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, candidate := range []string{strings.ToLower(value), strings.ToUpper(value)} {
			if _, exists := seen[candidate]; exists {
				continue
			}
			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}
	plain := strings.ReplaceAll(normalized, ":", "")
	for _, format := range normalizedFormats {
		switch format {
		case "colon":
			add(normalized)
		case "hyphen":
			add(strings.ReplaceAll(normalized, ":", "-"))
		case "plain":
			add(plain)
		case "cisco-dot":
			add(plain[0:4] + "." + plain[4:8] + "." + plain[8:12])
		}
	}
	return out
}

func SnapshotProfile(profile *db.MABDeviceProfile) string {
	if profile == nil {
		return "{}"
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		return "{}"
	}
	return string(payload)
}

func endpointStatusDecision(policy Policy, endpoint db.MABEndpoint, profile *db.MABDeviceProfile, result *Result) {
	status := strings.ToLower(strings.TrimSpace(endpoint.Status))
	if isExpired(endpoint.ExpiresAt) {
		status = "expired"
	}
	result.State = status
	result.Role = firstNonEmpty(endpoint.Role, policy.DefaultRole)
	result.VLAN = endpoint.VLAN
	result.BandwidthProfile = strings.TrimSpace(endpoint.BandwidthProfile)
	result.ACLPolicyName = strings.TrimSpace(endpoint.ACLPolicyName)
	result.Tenant = firstNonEmpty(endpoint.Tenant, profileTenant(profile))
	result.DeviceGroup = strings.TrimSpace(endpoint.DeviceGroup)
	result.Posture = firstNonEmpty(endpoint.Posture, profilePosture(profile))
	switch status {
	case "approved":
		result.Accepted = true
		result.Decision = "accepted"
		result.Reason = "endpoint is approved for MAC Authentication Bypass"
		result.ReplyMessage = "MAB accepted"
	case "quarantined":
		result.Accepted = true
		result.Decision = "quarantined"
		result.Role = firstNonEmpty(endpoint.Role, policy.QuarantineRole, policy.DefaultRole)
		result.Reason = "endpoint is assigned to quarantine policy"
		result.ReplyMessage = "MAB quarantined"
	case "denied":
		result.Accepted = false
		result.Decision = "rejected"
		result.Reason = "endpoint is explicitly denied"
	case "expired":
		result.Accepted = false
		result.Decision = "rejected"
		result.Reason = "endpoint authorization has expired"
	default:
		result.Accepted = false
		result.Decision = "rejected"
		result.Reason = "endpoint is pending approval"
	}
}

func unknownEndpointDecision(policy Policy, profile *db.MABDeviceProfile, result *Result) {
	result.State = "unknown"
	result.Tenant = profileTenant(profile)
	result.DeviceGroup = profileDeviceGroup(profile)
	result.Posture = profilePosture(profile)
	if profile != nil && policy.ProfilingLinkEnabled {
		if profile.RiskScore >= 50 || strings.EqualFold(profile.ComplianceStatus, "non_compliant") {
			result.Accepted = true
			result.Decision = "quarantined"
			result.State = "profile_quarantine"
			result.Role = firstNonEmpty(policy.QuarantineRole, policy.DefaultRole)
			result.Reason = "unknown endpoint matched high-risk or non-compliant device profile"
			result.ReplyMessage = "MAB profile quarantine"
			return
		}
	}
	switch policy.UnknownEndpointPolicy {
	case "guest":
		result.Accepted = true
		result.Decision = "accepted"
		result.Role = firstNonEmpty(policy.GuestRole, policy.DefaultRole)
		result.Reason = "unknown endpoint placed into guest policy"
		result.ReplyMessage = "MAB guest access"
	case "quarantine":
		result.Accepted = true
		result.Decision = "quarantined"
		result.Role = firstNonEmpty(policy.QuarantineRole, policy.DefaultRole)
		result.Reason = "unknown endpoint placed into quarantine policy"
		result.ReplyMessage = "MAB quarantine access"
	case "fail_open":
		result.Accepted = true
		result.Decision = "fail_open"
		result.Role = failOpenRole(policy)
		result.Reason = "unknown endpoint accepted by explicit fail-open policy"
		result.ReplyMessage = "MAB fail-open access"
	default:
		result.Accepted = false
		result.Decision = "rejected"
		result.Reason = "unknown endpoint is denied by policy"
	}
}

func applyMonitorMode(policy Policy, result Result) Result {
	if policy.Mode != "monitor" {
		return result
	}
	if result.Candidate && !result.Accepted && (result.Decision == "rejected" || result.Decision == "unsupported") {
		result.Accepted = true
		result.Decision = "monitor_allowed"
		result.Role = firstNonEmpty(result.Role, policy.GuestRole, policy.DefaultRole)
		result.Warnings = append(result.Warnings, "monitor mode allowed a request that enforce mode would deny")
	}
	return result
}

func maybeRecord(cfg *config.Config, policy Policy, req AccessRequest, result Result, enabled bool) {
	if !enabled || !policy.AuditEnabled || db.DB == nil || result.MAC == "" {
		return
	}
	_ = db.RecordMABEvent(db.MABEvent{
		ObservedAt:       time.Now().UTC().Format(time.RFC3339),
		MAC:              result.MAC,
		NASIdentifier:    req.NASIdentifier,
		NASIPAddress:     req.NASIPAddress,
		NASPort:          req.NASPort,
		NASPortType:      req.NASPortType,
		CalledStationID:  req.CalledStationID,
		Username:         req.Username,
		Decision:         result.Decision,
		State:            result.State,
		Reason:           result.Reason,
		Role:             result.Role,
		VLAN:             result.VLAN,
		BandwidthProfile: result.BandwidthProfile,
		ACLPolicyName:    result.ACLPolicyName,
		Tenant:           result.Tenant,
		DeviceGroup:      result.DeviceGroup,
		Posture:          result.Posture,
		LatencyMS:        result.LatencyMS,
	}, map[string]any{
		"mode":                    policy.Mode,
		"fail_closed":             policy.FailClosed,
		"unknown_endpoint_policy": policy.UnknownEndpointPolicy,
		"candidate":               result.Candidate,
		"eap_message_present":     req.EAPMessagePresent,
	}, policy.RetentionLimit)
	_ = cfg
}

func lookupEndpoint(mac string) (db.MABEndpoint, bool, error) {
	if db.DB == nil {
		return db.MABEndpoint{}, false, fmt.Errorf("database not initialized")
	}
	return db.GetMABEndpoint(mac)
}

func passwordPolicyRejects(policy Policy, req AccessRequest, mac string) bool {
	switch policy.PasswordPolicy {
	case "username_equals_password":
		return db.NormalizeMABMAC(req.Username) != mac || db.NormalizeMABMAC(req.Password) != mac
	case "calling_station_id":
		return db.NormalizeMABMAC(req.CallingStationID) != mac
	default:
		return false
	}
}

func failDecision(policy Policy) string {
	if policy.FailClosed {
		return "rejected"
	}
	return "fail_open"
}

func failOpenRole(policy Policy) string {
	return firstNonEmpty(policy.GuestRole, policy.DefaultRole)
}

func firstNormalizedMAC(values ...string) string {
	for _, value := range values {
		if mac := db.NormalizeMABMAC(value); mac != "" {
			return mac
		}
	}
	return ""
}

func policyAllowsPortType(policy Policy, value string) bool {
	normalized := normalizePortType(value)
	if normalized == "" || len(policy.AllowedNASPortTypes) == 0 {
		return true
	}
	for _, allowed := range policy.AllowedNASPortTypes {
		if normalizePortType(allowed) == normalized {
			return true
		}
	}
	return false
}

func normalizeMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "enforce":
		return "enforce"
	default:
		return "monitor"
	}
}

func normalizeUnknownPolicy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "guest", "quarantine", "fail_open":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "deny"
	}
}

func normalizePasswordPolicy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "username_equals_password", "calling_station_id":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "accept_known_mac"
	}
}

func normalizeList(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeFormats(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "colon", "hyphen", "plain", "cisco-dot":
		default:
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizePortType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, " ", "-")
	switch value {
	case "wireless80211", "wireless-80211", "wireless-802.11", "ieee80211":
		return "wireless-802.11"
	case "ethernet", "ethernet-csmacd", "15":
		return "ethernet"
	default:
		return value
	}
}

func isExpired(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return !expiresAt.After(time.Now().UTC())
}

func elapsedMillis(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Milliseconds()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func profileTenant(profile *db.MABDeviceProfile) string {
	if profile == nil {
		return ""
	}
	return strings.TrimSpace(profile.Tenant)
}

func profileDeviceGroup(profile *db.MABDeviceProfile) string {
	if profile == nil {
		return ""
	}
	return firstNonEmpty(profile.DeviceType, profile.Platform)
}

func profilePosture(profile *db.MABDeviceProfile) string {
	if profile == nil {
		return ""
	}
	if strings.TrimSpace(profile.ComplianceStatus) != "" {
		return strings.TrimSpace(profile.ComplianceStatus)
	}
	if profile.Compliant != nil {
		if *profile.Compliant {
			return "compliant"
		}
		return "non_compliant"
	}
	return ""
}
