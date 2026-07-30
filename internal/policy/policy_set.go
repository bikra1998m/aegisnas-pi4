package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const defaultMaxPolicySetDepth = 8

func PolicySetFromRules(key, name, description string, rules []Rule) PolicySet {
	enabled := true
	copied := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		normalized := NormalizeRule(rule)
		copied = append(copied, normalized)
	}
	return PolicySet{
		SchemaVersion: PolicySetSchemaVersion,
		Key:           defaultPolicySetKey(key),
		Name:          defaultString(name, "Default Policy Set"),
		Description:   strings.TrimSpace(description),
		Enabled:       &enabled,
		Rules:         copied,
	}
}

func ParsePolicySet(raw string) (PolicySet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PolicySet{}, fmt.Errorf("policy set content is required")
	}
	var set PolicySet
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return PolicySet{}, fmt.Errorf("decode policy set: %w", err)
	}
	set = NormalizePolicySet(set)
	if err := ValidatePolicySet(set, 32); err != nil {
		return PolicySet{}, err
	}
	return set, nil
}

func NormalizePolicySet(set PolicySet) PolicySet {
	set.SchemaVersion = PolicySetSchemaVersion
	set.Key = defaultPolicySetKey(set.Key)
	set.Name = defaultString(set.Name, set.Key)
	set.Description = strings.TrimSpace(set.Description)
	set.Tenant = strings.TrimSpace(set.Tenant)
	if set.Enabled == nil {
		enabled := true
		set.Enabled = &enabled
	}
	for i := range set.Rules {
		set.Rules[i] = NormalizeRule(set.Rules[i])
	}
	for i := range set.Children {
		set.Children[i] = NormalizePolicySet(set.Children[i])
	}
	return set
}

func NormalizeRule(rule Rule) Rule {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Action = defaultString(strings.ToLower(strings.TrimSpace(rule.Action)), "allow")
	rule.MatchConditions = canonicalJSON(defaultRawJSON(rule.MatchConditions, `{"op":"true"}`))
	if rule.BandwidthProfile != nil {
		value := strings.TrimSpace(*rule.BandwidthProfile)
		if value == "" {
			rule.BandwidthProfile = nil
		} else {
			rule.BandwidthProfile = &value
		}
	}
	if rule.PortalProfile != nil {
		value := strings.TrimSpace(*rule.PortalProfile)
		if value == "" {
			rule.PortalProfile = nil
		} else {
			rule.PortalProfile = &value
		}
	}
	if rule.ACLPolicyName != nil {
		value := strings.TrimSpace(*rule.ACLPolicyName)
		if value == "" {
			rule.ACLPolicyName = nil
		} else {
			rule.ACLPolicyName = &value
		}
	}
	rule.ServiceChain = NormalizeServiceChain(rule.ServiceChain)
	return rule
}

func ValidatePolicySet(set PolicySet, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = defaultMaxPolicySetDepth
	}
	if maxDepth > 32 {
		maxDepth = 32
	}
	seen := map[string]struct{}{}
	return validatePolicySet(set, "$", 1, maxDepth, seen)
}

func FlattenPolicySet(set PolicySet, maxDepth int) ([]Rule, error) {
	set = NormalizePolicySet(set)
	if err := ValidatePolicySet(set, maxDepth); err != nil {
		return nil, err
	}
	var rules []Rule
	flattenPolicySet(set, "", boolPtrValue(set.Enabled), set.Priority, &rules)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].Name < rules[j].Name
		}
		return rules[i].Priority > rules[j].Priority
	})
	for i := range rules {
		rules[i].ID = i + 1
	}
	return rules, nil
}

func SummarizePolicySet(set PolicySet, maxDepth int) (PolicySetSummary, error) {
	set = NormalizePolicySet(set)
	if err := ValidatePolicySet(set, maxDepth); err != nil {
		return PolicySetSummary{}, err
	}
	rules, err := FlattenPolicySet(set, maxDepth)
	if err != nil {
		return PolicySetSummary{}, err
	}
	ruleCount, childCount, depth := countPolicySet(set, 1)
	return PolicySetSummary{
		SchemaVersion: PolicySetSchemaVersion,
		Key:           set.Key,
		Name:          set.Name,
		Tenant:        set.Tenant,
		RuleCount:     ruleCount,
		ChildSetCount: childCount,
		MaxDepth:      depth,
		ContentHash:   PolicySetContentHash(set),
		PolicyHash:    PolicySetHash(rules),
	}, nil
}

func PolicySetContentHash(set PolicySet) string {
	normalized := NormalizePolicySet(set)
	data, _ := json.Marshal(normalized)
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err == nil {
		data = compact.Bytes()
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ComparePolicySets(from, to PolicySet, maxDepth int) (PolicySetDiff, error) {
	fromRules, err := FlattenPolicySet(from, maxDepth)
	if err != nil {
		return PolicySetDiff{}, fmt.Errorf("from policy set: %w", err)
	}
	toRules, err := FlattenPolicySet(to, maxDepth)
	if err != nil {
		return PolicySetDiff{}, fmt.Errorf("to policy set: %w", err)
	}
	diff := PolicySetDiff{
		FromHash: PolicySetHash(fromRules),
		ToHash:   PolicySetHash(toRules),
	}
	fromByName := map[string]Rule{}
	toByName := map[string]Rule{}
	for _, rule := range fromRules {
		fromByName[rule.Name] = rule
	}
	for _, rule := range toRules {
		toByName[rule.Name] = rule
	}
	for name, toRule := range toByName {
		fromRule, ok := fromByName[name]
		if !ok {
			diff.AddedRules = append(diff.AddedRules, toRule)
			continue
		}
		if ruleHash(fromRule) != ruleHash(toRule) {
			diff.ChangedRules = append(diff.ChangedRules, PolicyRuleDiff{Name: name, From: fromRule, To: toRule})
		}
	}
	for name, fromRule := range fromByName {
		if _, ok := toByName[name]; !ok {
			diff.RemovedRules = append(diff.RemovedRules, fromRule)
		}
	}
	sort.Slice(diff.AddedRules, func(i, j int) bool { return diff.AddedRules[i].Name < diff.AddedRules[j].Name })
	sort.Slice(diff.RemovedRules, func(i, j int) bool { return diff.RemovedRules[i].Name < diff.RemovedRules[j].Name })
	sort.Slice(diff.ChangedRules, func(i, j int) bool { return diff.ChangedRules[i].Name < diff.ChangedRules[j].Name })
	return diff, nil
}

func validatePolicySet(set PolicySet, path string, depth, maxDepth int, seen map[string]struct{}) error {
	if depth > maxDepth {
		return fmt.Errorf("policy set %s exceeds maximum nesting depth %d", path, maxDepth)
	}
	if !validPolicyToken(set.Key) {
		return fmt.Errorf("policy set %s key %q is invalid", path, set.Key)
	}
	if strings.TrimSpace(set.Name) == "" {
		return fmt.Errorf("policy set %s name is required", path)
	}
	if _, ok := seen[path+"/"+set.Key]; ok {
		return fmt.Errorf("policy set %s key %q is duplicated", path, set.Key)
	}
	seen[path+"/"+set.Key] = struct{}{}
	ruleNames := map[string]struct{}{}
	for i, rule := range set.Rules {
		rulePath := fmt.Sprintf("%s.rules[%d]", path, i)
		if !validPolicyRuleName(rule.Name) {
			return fmt.Errorf("%s name %q is invalid", rulePath, rule.Name)
		}
		key := strings.ToLower(rule.Name)
		if _, ok := ruleNames[key]; ok {
			return fmt.Errorf("%s duplicates an earlier rule name in set %q", rulePath, set.Key)
		}
		ruleNames[key] = struct{}{}
		if err := ValidateRule(rule); err != nil {
			return fmt.Errorf("%s: %w", rulePath, err)
		}
	}
	childKeys := map[string]struct{}{}
	for i, child := range set.Children {
		key := strings.ToLower(strings.TrimSpace(child.Key))
		if _, ok := childKeys[key]; ok {
			return fmt.Errorf("%s.children[%d] duplicates an earlier child set key %q", path, i, child.Key)
		}
		childKeys[key] = struct{}{}
		if err := validatePolicySet(child, fmt.Sprintf("%s.children[%s]", path, child.Key), depth+1, maxDepth, seen); err != nil {
			return err
		}
	}
	return nil
}

func flattenPolicySet(set PolicySet, parentPath string, parentEnabled bool, inheritedPriority int, rules *[]Rule) {
	path := set.Key
	if parentPath != "" {
		path = parentPath + "/" + set.Key
	}
	setEnabled := parentEnabled && boolPtrValue(set.Enabled)
	priorityBase := inheritedPriority
	if parentPath != "" {
		priorityBase += set.Priority
	}
	for _, rule := range set.Rules {
		flattened := NormalizeRule(rule)
		flattened.Name = path + "/" + flattened.Name
		flattened.Priority = priorityBase + flattened.Priority
		flattened.Enabled = setEnabled && flattened.Enabled
		*rules = append(*rules, flattened)
	}
	children := append([]PolicySet(nil), set.Children...)
	sort.SliceStable(children, func(i, j int) bool {
		if children[i].Priority == children[j].Priority {
			return children[i].Key < children[j].Key
		}
		return children[i].Priority > children[j].Priority
	})
	for _, child := range children {
		flattenPolicySet(child, path, setEnabled, priorityBase, rules)
	}
}

func countPolicySet(set PolicySet, depth int) (rules int, children int, maxDepth int) {
	rules = len(set.Rules)
	children = len(set.Children)
	maxDepth = depth
	for _, child := range set.Children {
		childRules, childChildren, childDepth := countPolicySet(child, depth+1)
		rules += childRules
		children += childChildren
		if childDepth > maxDepth {
			maxDepth = childDepth
		}
	}
	return rules, children, maxDepth
}

func ruleHash(rule Rule) string {
	normalized := NormalizeRule(rule)
	data, _ := json.Marshal(normalized)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func defaultRawJSON(raw json.RawMessage, fallback string) json.RawMessage {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return json.RawMessage(fallback)
	}
	return raw
}

func defaultPolicySetKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "default"
	}
	return value
}

func boolPtrValue(value *bool) bool {
	return value == nil || *value
}

func validPolicyToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

func validPolicyRuleName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.Contains(value, "/") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ' ':
		default:
			return false
		}
	}
	return true
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
