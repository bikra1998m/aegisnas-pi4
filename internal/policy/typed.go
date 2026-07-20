package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxExpressionDepth = 8
	defaultMaxExpressionNodes = 128
	defaultMaxListValues      = 128
)

type validationState struct {
	maxDepth int
	maxNodes int
	maxList  int
	nodes    int
}

var knownFieldTypes = map[string]string{
	"authenticated":      "bool",
	"username":           "string",
	"role":               "string",
	"groups":             "string_list",
	"realm":              "string",
	"tenant":             "string",
	"device_group":       "string",
	"auth_method":        "string",
	"identity_source":    "string",
	"ssid":               "string",
	"nas_identifier":     "string",
	"nas_ip_address":     "ip",
	"nas_port_id":        "string",
	"nas_port_type":      "string",
	"called_station_id":  "string",
	"calling_station_id": "string",
	"site":               "string",
	"source_ip":          "ip",
	"vendor":             "string",
	"vlan":               "number",
	"time_of_day":        "string",
	"posture":            "string",
	"risk_score":         "number",
	"hour":               "number",
	"weekday":            "string",
	"attribute":          "string",
}

func FieldCatalog() []FieldSpec {
	fields := []FieldSpec{
		{Name: "authenticated", Type: "bool", Description: "Authentication result state from the AAA flow."},
		{Name: "username", Type: "string", Description: "Normalized user or device identity."},
		{Name: "role", Type: "string", Description: "Current role before policy actions are merged."},
		{Name: "groups", Type: "string_list", Description: "Identity-source groups, including LDAP or AD groups."},
		{Name: "realm", Type: "string", Description: "RADIUS realm or identity suffix."},
		{Name: "tenant", Type: "string", Description: "Tenant boundary used for delegated policy."},
		{Name: "device_group", Type: "string", Description: "Endpoint group from profiling, inventory, or vendor attributes."},
		{Name: "auth_method", Type: "string", Description: "Authentication method such as pap, eap-tls, peap, mab, or voucher."},
		{Name: "identity_source", Type: "string", Description: "Identity provider that authenticated the request."},
		{Name: "ssid", Type: "string", Description: "Wireless LAN SSID."},
		{Name: "nas_identifier", Type: "string", Description: "NAS-Identifier from the RADIUS request."},
		{Name: "nas_ip_address", Type: "ip", Description: "NAS IPv4 or IPv6 address."},
		{Name: "nas_port_id", Type: "string", Description: "NAS-Port-Id or physical/logical access port."},
		{Name: "nas_port_type", Type: "string", Description: "NAS-Port-Type, for example ethernet or wireless-802.11."},
		{Name: "called_station_id", Type: "string", Description: "Called-Station-Id from the access request."},
		{Name: "calling_station_id", Type: "string", Description: "Calling-Station-Id, normally the client MAC address."},
		{Name: "site", Type: "string", Description: "Local site, building, or controller location."},
		{Name: "source_ip", Type: "ip", Description: "Packet source address observed by the server."},
		{Name: "vendor", Type: "string", Description: "NAS vendor or compatibility pack."},
		{Name: "vlan", Type: "number", Description: "Input VLAN context when known."},
		{Name: "posture", Type: "string", Description: "Device posture or compliance state."},
		{Name: "risk_score", Type: "number", Description: "Profiling or posture risk score."},
		{Name: "hour", Type: "number", Description: "Evaluation hour in UTC unless the caller provides evaluated_at."},
		{Name: "weekday", Type: "string", Description: "Evaluation weekday in English, lower case."},
		{Name: "attribute.<name>", Type: "string", Description: "Bounded vendor or request attribute preserved in the request attribute bag."},
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	return fields
}

func OperatorCatalog() []OperatorSpec {
	return []OperatorSpec{
		{Name: "eq", Types: []string{"string", "bool", "number"}, Description: "Matches when the field equals the value."},
		{Name: "neq", Types: []string{"string", "bool", "number"}, Description: "Matches when the field does not equal the value."},
		{Name: "in", Types: []string{"string", "number"}, Description: "Matches when the field equals one of values."},
		{Name: "not_in", Types: []string{"string", "number"}, Description: "Matches when the field equals none of values."},
		{Name: "contains", Types: []string{"string_list", "string"}, Description: "Matches when a list or string contains the value."},
		{Name: "contains_any", Types: []string{"string_list"}, Description: "Matches when a list contains at least one of values."},
		{Name: "prefix", Types: []string{"string"}, Description: "Matches when a string starts with value."},
		{Name: "suffix", Types: []string{"string"}, Description: "Matches when a string ends with value."},
		{Name: "regex", Types: []string{"string"}, Description: "Matches a bounded regular expression."},
		{Name: "cidr", Types: []string{"ip"}, Description: "Matches an IP field against one or more CIDR ranges."},
		{Name: "gt", Types: []string{"number"}, Description: "Greater-than numeric comparison."},
		{Name: "gte", Types: []string{"number"}, Description: "Greater-than-or-equal numeric comparison."},
		{Name: "lt", Types: []string{"number"}, Description: "Less-than numeric comparison."},
		{Name: "lte", Types: []string{"number"}, Description: "Less-than-or-equal numeric comparison."},
		{Name: "between", Types: []string{"number"}, Description: "Inclusive numeric range using two values."},
		{Name: "exists", Types: []string{"any"}, Description: "Matches whether the field exists."},
		{Name: "time_between", Types: []string{"string"}, Description: "Matches HH:MM-HH:MM windows against the evaluation time."},
		{Name: "true", Types: []string{"none"}, Description: "Always matches."},
		{Name: "false", Types: []string{"none"}, Description: "Never matches."},
	}
}

func CompileMatchConditions(raw json.RawMessage) (TypedExpression, bool, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return TypedExpression{Op: "true"}, false, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return TypedExpression{}, false, fmt.Errorf("decode policy expression: %w", err)
	}
	if len(doc) == 0 {
		return TypedExpression{Op: "true"}, false, nil
	}
	if expressionLooksTyped(doc) {
		var expr TypedExpression
		if err := json.Unmarshal(raw, &expr); err != nil {
			return TypedExpression{}, false, fmt.Errorf("decode typed policy expression: %w", err)
		}
		return expr, false, ValidateExpression(expr)
	}
	expr := legacyMapToExpression(doc)
	return expr, true, ValidateExpression(expr)
}

func ValidateExpression(expr TypedExpression) error {
	state := &validationState{maxDepth: defaultMaxExpressionDepth, maxNodes: defaultMaxExpressionNodes, maxList: defaultMaxListValues}
	return validateExpression(expr, "$", 0, state)
}

func EvaluateTypedExpression(expr TypedExpression, req *Request) (bool, []TraceEntry) {
	now := time.Now().UTC()
	if req != nil && !req.EvaluatedAt.IsZero() {
		now = req.EvaluatedAt.UTC()
	}
	matched, trace := evalExpression(expr, req, now, "$")
	return matched, trace
}

func PolicySetHash(rules []Rule) string {
	type normalizedRule struct {
		Name            string          `json:"name"`
		Priority        int             `json:"priority"`
		Enabled         bool            `json:"enabled"`
		MatchConditions json.RawMessage `json:"match_conditions"`
		Action          string          `json:"action"`
		VLAN            *int            `json:"vlan,omitempty"`
		Bandwidth       *string         `json:"bandwidth_profile,omitempty"`
		SessionTimeout  *int            `json:"session_timeout,omitempty"`
		IdleTimeout     *int            `json:"idle_timeout,omitempty"`
		PortalProfile   *string         `json:"portal_profile,omitempty"`
		ACLPolicyName   *string         `json:"acl_policy_name,omitempty"`
		Quarantine      bool            `json:"quarantine"`
	}
	normalized := make([]normalizedRule, 0, len(rules))
	for _, rule := range rules {
		normalized = append(normalized, normalizedRule{
			Name: rule.Name, Priority: rule.Priority, Enabled: rule.Enabled, MatchConditions: canonicalJSON(rule.MatchConditions),
			Action: strings.ToLower(strings.TrimSpace(rule.Action)), VLAN: rule.VLAN, Bandwidth: rule.BandwidthProfile,
			SessionTimeout: rule.SessionTimeout, IdleTimeout: rule.IdleTimeout, PortalProfile: rule.PortalProfile,
			ACLPolicyName: rule.ACLPolicyName, Quarantine: rule.Quarantine,
		})
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Priority == normalized[j].Priority {
			return normalized[i].Name < normalized[j].Name
		}
		return normalized[i].Priority > normalized[j].Priority
	})
	data, _ := json.Marshal(normalized)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func RequestHash(req *Request) string {
	if req == nil {
		return ""
	}
	safe := *req
	safe.Username = hashOpaque(safe.Username)
	safe.CallingStationID = hashOpaque(safe.CallingStationID)
	safe.CalledStationID = hashOpaque(safe.CalledStationID)
	safe.NASPortID = hashOpaque(safe.NASPortID)
	data, _ := json.Marshal(safe)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func NewEvaluationID(policySetHash, requestHash string, evaluatedAt time.Time) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{policySetHash, requestHash, evaluatedAt.UTC().Format(time.RFC3339Nano)}, "|")))
	return hex.EncodeToString(sum[:16])
}

func ValidateRule(rule Rule) error {
	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action == "" {
		action = "allow"
	}
	switch action {
	case "allow", "deny", "quarantine":
	default:
		return fmt.Errorf("policy action %q must be allow, deny, or quarantine", rule.Action)
	}
	_, _, err := CompileMatchConditions(rule.MatchConditions)
	return err
}

func expressionLooksTyped(doc map[string]any) bool {
	for _, key := range []string{"all", "any", "not", "field", "op"} {
		if _, ok := doc[key]; ok {
			return true
		}
	}
	return false
}

func legacyMapToExpression(doc map[string]any) TypedExpression {
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	all := make([]TypedExpression, 0, len(keys))
	for _, key := range keys {
		value := doc[key]
		field := legacyFieldName(key)
		switch typed := value.(type) {
		case []any:
			op := "in"
			if field == "groups" {
				op = "contains_any"
			}
			all = append(all, TypedExpression{Field: field, Op: op, Values: typed})
		default:
			op := "eq"
			if field == "groups" {
				op = "contains"
			}
			all = append(all, TypedExpression{Field: field, Op: op, Value: value})
		}
	}
	if len(all) == 1 {
		return all[0]
	}
	return TypedExpression{All: all}
}

func legacyFieldName(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	switch key {
	case "group":
		return "groups"
	case "nas_ip":
		return "nas_ip_address"
	case "mac":
		return "calling_station_id"
	}
	if _, ok := knownFieldTypes[key]; ok {
		return key
	}
	if strings.HasPrefix(key, "attribute.") {
		return key
	}
	return "attribute." + key
}

func validateExpression(expr TypedExpression, path string, depth int, state *validationState) error {
	if depth > state.maxDepth {
		return fmt.Errorf("%s exceeds maximum expression depth %d", path, state.maxDepth)
	}
	state.nodes++
	if state.nodes > state.maxNodes {
		return fmt.Errorf("expression exceeds maximum node count %d", state.maxNodes)
	}
	branches := 0
	if len(expr.All) > 0 {
		branches++
		if len(expr.All) > state.maxList {
			return fmt.Errorf("%s.all has too many children", path)
		}
		for i, child := range expr.All {
			if err := validateExpression(child, fmt.Sprintf("%s.all[%d]", path, i), depth+1, state); err != nil {
				return err
			}
		}
	}
	if len(expr.Any) > 0 {
		branches++
		if len(expr.Any) > state.maxList {
			return fmt.Errorf("%s.any has too many children", path)
		}
		for i, child := range expr.Any {
			if err := validateExpression(child, fmt.Sprintf("%s.any[%d]", path, i), depth+1, state); err != nil {
				return err
			}
		}
	}
	if expr.Not != nil {
		branches++
		if err := validateExpression(*expr.Not, path+".not", depth+1, state); err != nil {
			return err
		}
	}
	leaf := strings.TrimSpace(expr.Op) != "" || strings.TrimSpace(expr.Field) != ""
	if leaf {
		branches++
		if err := validateLeaf(expr, path, state); err != nil {
			return err
		}
	}
	if branches != 1 {
		return fmt.Errorf("%s must contain exactly one of all, any, not, or field/op", path)
	}
	return nil
}

func validateLeaf(expr TypedExpression, path string, state *validationState) error {
	op := normalizeOperator(expr.Op)
	if op == "" {
		return fmt.Errorf("%s.op is required", path)
	}
	if op == "true" || op == "false" {
		return nil
	}
	field := normalizeField(expr.Field)
	if field == "" {
		return fmt.Errorf("%s.field is required", path)
	}
	if !knownField(field) {
		return fmt.Errorf("%s.field %q is not supported", path, expr.Field)
	}
	switch op {
	case "eq", "neq", "contains", "prefix", "suffix", "regex", "cidr", "gt", "gte", "lt", "lte", "time_between":
		if expr.Value == nil {
			return fmt.Errorf("%s.value is required for operator %s", path, op)
		}
	case "in", "not_in", "contains_any", "between":
		if len(expr.Values) == 0 {
			return fmt.Errorf("%s.values is required for operator %s", path, op)
		}
		if len(expr.Values) > state.maxList {
			return fmt.Errorf("%s.values exceeds maximum %d", path, state.maxList)
		}
		if op == "between" && len(expr.Values) != 2 {
			return fmt.Errorf("%s.values must contain exactly two bounds for operator between", path)
		}
	case "exists":
	default:
		return fmt.Errorf("%s.op %q is not supported", path, expr.Op)
	}
	if op == "regex" {
		pattern := stringify(expr.Value)
		if len(pattern) > 256 {
			return fmt.Errorf("%s.value regex cannot exceed 256 characters", path)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("%s.value regex is invalid: %w", path, err)
		}
	}
	return nil
}

func evalExpression(expr TypedExpression, req *Request, now time.Time, path string) (bool, []TraceEntry) {
	if len(expr.All) > 0 {
		matched := true
		trace := make([]TraceEntry, 0, len(expr.All))
		for i, child := range expr.All {
			childMatched, childTrace := evalExpression(child, req, now, fmt.Sprintf("%s.all[%d]", path, i))
			trace = append(trace, childTrace...)
			if !childMatched {
				matched = false
			}
		}
		trace = append(trace, TraceEntry{Path: path, Matched: matched, Message: "all"})
		return matched, trace
	}
	if len(expr.Any) > 0 {
		matched := false
		trace := make([]TraceEntry, 0, len(expr.Any))
		for i, child := range expr.Any {
			childMatched, childTrace := evalExpression(child, req, now, fmt.Sprintf("%s.any[%d]", path, i))
			trace = append(trace, childTrace...)
			if childMatched {
				matched = true
			}
		}
		trace = append(trace, TraceEntry{Path: path, Matched: matched, Message: "any"})
		return matched, trace
	}
	if expr.Not != nil {
		childMatched, trace := evalExpression(*expr.Not, req, now, path+".not")
		matched := !childMatched
		trace = append(trace, TraceEntry{Path: path, Matched: matched, Message: "not"})
		return matched, trace
	}
	matched, entry := evalLeaf(expr, req, now, path)
	return matched, []TraceEntry{entry}
}

func evalLeaf(expr TypedExpression, req *Request, now time.Time, path string) (bool, TraceEntry) {
	op := normalizeOperator(expr.Op)
	if op == "true" {
		return true, TraceEntry{Path: path, Operator: op, Matched: true, Message: "constant true"}
	}
	if op == "false" {
		return false, TraceEntry{Path: path, Operator: op, Matched: false, Message: "constant false"}
	}
	field := normalizeField(expr.Field)
	actual, exists := fieldValue(req, field, now)
	entry := TraceEntry{Path: path, Field: field, Operator: op, Expected: expectedForTrace(expr), Actual: actual}
	if op == "exists" {
		expected := true
		if expr.Value != nil {
			expected = boolValue(expr.Value)
		}
		entry.Matched = exists == expected
		return entry.Matched, entry
	}
	if !exists {
		entry.Matched = false
		entry.Message = "field is absent"
		return false, entry
	}
	entry.Matched = compareValue(op, actual, expr, now)
	return entry.Matched, entry
}

func compareValue(op string, actual any, expr TypedExpression, now time.Time) bool {
	switch op {
	case "eq":
		return valuesEqual(actual, expr.Value)
	case "neq":
		return !valuesEqual(actual, expr.Value)
	case "in":
		return anyEqual(actual, expr.Values)
	case "not_in":
		return !anyEqual(actual, expr.Values)
	case "contains":
		return containsValue(actual, expr.Value)
	case "contains_any":
		for _, value := range expr.Values {
			if containsValue(actual, value) {
				return true
			}
		}
		return false
	case "prefix":
		return strings.HasPrefix(strings.ToLower(stringify(actual)), strings.ToLower(stringify(expr.Value)))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(stringify(actual)), strings.ToLower(stringify(expr.Value)))
	case "regex":
		re, err := regexp.Compile(stringify(expr.Value))
		return err == nil && re.MatchString(stringify(actual))
	case "cidr":
		return ipInCIDRs(stringify(actual), append([]any{expr.Value}, expr.Values...))
	case "gt", "gte", "lt", "lte":
		left, okLeft := numericValue(actual)
		right, okRight := numericValue(expr.Value)
		if !okLeft || !okRight {
			return false
		}
		switch op {
		case "gt":
			return left > right
		case "gte":
			return left >= right
		case "lt":
			return left < right
		case "lte":
			return left <= right
		}
	case "between":
		if len(expr.Values) != 2 {
			return false
		}
		left, okLeft := numericValue(actual)
		low, okLow := numericValue(expr.Values[0])
		high, okHigh := numericValue(expr.Values[1])
		return okLeft && okLow && okHigh && left >= low && left <= high
	case "time_between":
		return timeInWindow(now, stringify(expr.Value))
	}
	return false
}

func fieldValue(req *Request, field string, now time.Time) (any, bool) {
	if req == nil {
		return nil, false
	}
	switch field {
	case "authenticated":
		return req.Authenticated, true
	case "username":
		return req.Username, strings.TrimSpace(req.Username) != ""
	case "role":
		return req.Role, strings.TrimSpace(req.Role) != ""
	case "groups":
		return req.Groups, len(req.Groups) > 0
	case "realm":
		return req.Realm, strings.TrimSpace(req.Realm) != ""
	case "tenant":
		return req.Tenant, strings.TrimSpace(req.Tenant) != ""
	case "device_group":
		return req.DeviceGroup, strings.TrimSpace(req.DeviceGroup) != ""
	case "auth_method":
		return req.AuthMethod, strings.TrimSpace(req.AuthMethod) != ""
	case "identity_source":
		return req.IdentitySource, strings.TrimSpace(req.IdentitySource) != ""
	case "ssid":
		return req.SSID, strings.TrimSpace(req.SSID) != ""
	case "nas_identifier":
		return req.NASIdentifier, strings.TrimSpace(req.NASIdentifier) != ""
	case "nas_ip_address":
		return req.NASIPAddress, strings.TrimSpace(req.NASIPAddress) != ""
	case "nas_port_id":
		return req.NASPortID, strings.TrimSpace(req.NASPortID) != ""
	case "nas_port_type":
		return req.NASPortType, strings.TrimSpace(req.NASPortType) != ""
	case "called_station_id":
		return req.CalledStationID, strings.TrimSpace(req.CalledStationID) != ""
	case "calling_station_id":
		return req.CallingStationID, strings.TrimSpace(req.CallingStationID) != ""
	case "site":
		return req.Site, strings.TrimSpace(req.Site) != ""
	case "source_ip":
		return req.SourceIP, strings.TrimSpace(req.SourceIP) != ""
	case "vendor":
		return req.Vendor, strings.TrimSpace(req.Vendor) != ""
	case "vlan":
		return req.VLAN, req.VLAN > 0
	case "time_of_day":
		if strings.TrimSpace(req.TimeOfDay) != "" {
			return req.TimeOfDay, true
		}
		return now.Format("15:04"), true
	case "posture":
		return req.Posture, strings.TrimSpace(req.Posture) != ""
	case "risk_score":
		return req.RiskScore, true
	case "hour":
		return now.Hour(), true
	case "weekday":
		return strings.ToLower(now.Weekday().String()), true
	}
	if strings.HasPrefix(field, "attribute.") {
		key := strings.TrimPrefix(field, "attribute.")
		if req.Attributes == nil {
			return nil, false
		}
		if value, ok := req.Attributes[key]; ok {
			return value, strings.TrimSpace(value) != ""
		}
		lower := strings.ToLower(key)
		for attrKey, value := range req.Attributes {
			if strings.ToLower(attrKey) == lower {
				return value, strings.TrimSpace(value) != ""
			}
		}
	}
	return nil, false
}

func knownField(field string) bool {
	field = normalizeField(field)
	if strings.HasPrefix(field, "attribute.") {
		return len(strings.TrimPrefix(field, "attribute.")) > 0
	}
	_, ok := knownFieldTypes[field]
	return ok
}

func normalizeOperator(op string) string {
	return strings.ToLower(strings.TrimSpace(op))
}

func normalizeField(field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	field = strings.ReplaceAll(field, "-", "_")
	return field
}

func expectedForTrace(expr TypedExpression) any {
	if len(expr.Values) > 0 {
		return expr.Values
	}
	return expr.Value
}

func valuesEqual(left, right any) bool {
	if l, ok := numericValue(left); ok {
		if r, ok := numericValue(right); ok {
			return l == r
		}
	}
	if _, ok := left.(bool); ok {
		return boolValue(left) == boolValue(right)
	}
	return strings.EqualFold(stringify(left), stringify(right))
}

func anyEqual(actual any, values []any) bool {
	switch list := actual.(type) {
	case []string:
		for _, actualItem := range list {
			for _, value := range values {
				if valuesEqual(actualItem, value) {
					return true
				}
			}
		}
		return false
	default:
		for _, value := range values {
			if valuesEqual(actual, value) {
				return true
			}
		}
		return false
	}
}

func containsValue(actual, expected any) bool {
	switch list := actual.(type) {
	case []string:
		for _, item := range list {
			if valuesEqual(item, expected) {
				return true
			}
		}
		return false
	default:
		return strings.Contains(strings.ToLower(stringify(actual)), strings.ToLower(stringify(expected)))
	}
}

func stringify(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case json.Number:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case json.Number:
		n, err := v.Float64()
		return n, err == nil
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return n, err == nil
	default:
		n, err := strconv.ParseFloat(fmt.Sprint(v), 64)
		return n, err == nil
	}
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(v))
		return parsed
	default:
		return fmt.Sprint(v) == "true"
	}
}

func ipInCIDRs(ipText string, cidrValues []any) bool {
	ip := net.ParseIP(strings.TrimSpace(ipText))
	if ip == nil {
		return false
	}
	for _, value := range cidrValues {
		text := strings.TrimSpace(stringify(value))
		if text == "" {
			continue
		}
		if parsed := net.ParseIP(text); parsed != nil && parsed.Equal(ip) {
			return true
		}
		_, network, err := net.ParseCIDR(text)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func timeInWindow(now time.Time, window string) bool {
	parts := strings.Split(strings.TrimSpace(window), "-")
	if len(parts) != 2 {
		return false
	}
	start, okStart := parseClockMinute(parts[0])
	end, okEnd := parseClockMinute(parts[1])
	if !okStart || !okEnd {
		return false
	}
	current := now.Hour()*60 + now.Minute()
	if start <= end {
		return current >= start && current <= end
	}
	return current >= start || current <= end
}

func parseClockMinute(value string) (int, bool) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return parsed.Hour()*60 + parsed.Minute(), true
}

func canonicalJSON(raw json.RawMessage) json.RawMessage {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	data, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return data
}

func hashOpaque(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
