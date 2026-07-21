package adminapi

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/policy"
)

func policyRequestSummary(req policy.Request) map[string]any {
	return map[string]any{
		"role":            req.Role,
		"groups":          len(req.Groups),
		"realm":           req.Realm,
		"tenant":          req.Tenant,
		"auth_method":     req.AuthMethod,
		"identity_source": req.IdentitySource,
		"ssid":            req.SSID,
		"nas_identifier":  req.NASIdentifier,
		"nas_port_type":   req.NASPortType,
		"site":            req.Site,
		"vendor":          req.Vendor,
		"vlan":            req.VLAN,
		"posture":         req.Posture,
		"risk_score":      req.RiskScore,
		"authenticated":   req.Authenticated,
	}
}

func policyReplayRequest(req policy.Request) policy.Request {
	return policy.Request{
		Role:            safeReplayString(req.Role, 128),
		Groups:          safeReplayStrings(req.Groups, 64, 128),
		Realm:           safeReplayString(req.Realm, 128),
		Tenant:          safeReplayString(req.Tenant, 128),
		DeviceGroup:     safeReplayString(req.DeviceGroup, 128),
		AuthMethod:      safeReplayString(req.AuthMethod, 64),
		IdentitySource:  safeReplayString(req.IdentitySource, 64),
		SSID:            safeReplayString(req.SSID, 128),
		NASIdentifier:   safeReplayString(req.NASIdentifier, 128),
		NASIPAddress:    safeReplayString(req.NASIPAddress, 64),
		NASPortID:       safeReplayString(req.NASPortID, 128),
		NASPortType:     safeReplayString(req.NASPortType, 64),
		CalledStationID: safeReplayString(req.CalledStationID, 128),
		Site:            safeReplayString(req.Site, 128),
		SourceIP:        safeReplayString(req.SourceIP, 64),
		Vendor:          safeReplayString(req.Vendor, 128),
		VLAN:            req.VLAN,
		Authenticated:   req.Authenticated,
		TimeOfDay:       safeReplayString(req.TimeOfDay, 64),
		Posture:         safeReplayString(req.Posture, 128),
		RiskScore:       req.RiskScore,
		Attributes:      safeReplayAttributes(req.Attributes),
		EvaluatedAt:     req.EvaluatedAt,
	}
}

func policyRequestFromSummary(raw string) policy.Request {
	var summary map[string]any
	_ = json.Unmarshal([]byte(defaultString(raw, "{}")), &summary)
	return policy.Request{
		Role:           stringFromSummary(summary, "role"),
		Realm:          stringFromSummary(summary, "realm"),
		Tenant:         stringFromSummary(summary, "tenant"),
		AuthMethod:     stringFromSummary(summary, "auth_method"),
		IdentitySource: stringFromSummary(summary, "identity_source"),
		SSID:           stringFromSummary(summary, "ssid"),
		NASIdentifier:  stringFromSummary(summary, "nas_identifier"),
		NASPortType:    stringFromSummary(summary, "nas_port_type"),
		Site:           stringFromSummary(summary, "site"),
		Vendor:         stringFromSummary(summary, "vendor"),
		VLAN:           intFromSummary(summary, "vlan"),
		Posture:        stringFromSummary(summary, "posture"),
		RiskScore:      intFromSummary(summary, "risk_score"),
		Authenticated:  boolFromSummary(summary, "authenticated"),
	}
}

func safeReplayAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]string)
	for key, value := range attrs {
		if len(out) >= 64 {
			break
		}
		key = safeReplayString(key, 128)
		if key == "" || sensitiveReplayKey(key) {
			continue
		}
		out[key] = safeReplayString(value, 256)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sensitiveReplayKey(key string) bool {
	key = strings.ToLower(key)
	sensitive := []string{"password", "passwd", "secret", "token", "credential", "private", "key", "mschap", "challenge", "response", "cert", "cookie"}
	for _, marker := range sensitive {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func safeReplayStrings(values []string, maxItems, maxLen int) []string {
	if len(values) == 0 {
		return nil
	}
	if maxItems <= 0 || maxItems > len(values) {
		maxItems = len(values)
	}
	out := make([]string, 0, maxItems)
	for _, value := range values[:maxItems] {
		value = safeReplayString(value, maxLen)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func safeReplayString(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if maxLen > 0 && len(value) > maxLen {
		return value[:maxLen]
	}
	return value
}

func stringFromSummary(summary map[string]any, key string) string {
	if value, ok := summary[key].(string); ok {
		return value
	}
	return ""
}

func intFromSummary(summary map[string]any, key string) int {
	switch value := summary[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case string:
		parsed, _ := strconv.Atoi(value)
		return parsed
	default:
		return 0
	}
}

func boolFromSummary(summary map[string]any, key string) bool {
	if value, ok := summary[key].(bool); ok {
		return value
	}
	return false
}
