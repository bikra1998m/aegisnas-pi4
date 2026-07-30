package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	MaxServiceChainLength      = 32
	MaxServiceIntentAttributes = 32
)

// ServiceIntent is the vendor-neutral authorization unit used by NAS-0032.
// A policy decision can activate several ordered services for one subscriber
// session, while later vendor packs decide how those services become VSAs,
// CoA requests, or controller-native operations.
type ServiceIntent struct {
	Key              string            `json:"key"`
	Name             string            `json:"name,omitempty"`
	Type             string            `json:"type,omitempty"`
	Vendor           string            `json:"vendor,omitempty"`
	VendorPack       string            `json:"vendor_pack,omitempty"`
	Action           string            `json:"action,omitempty"`
	Sequence         int               `json:"sequence"`
	Optional         bool              `json:"optional,omitempty"`
	DependsOn        []string          `json:"depends_on,omitempty"`
	Role             *string           `json:"role,omitempty"`
	VLAN             *int              `json:"vlan,omitempty"`
	BandwidthProfile *string           `json:"bandwidth_profile,omitempty"`
	ACLPolicyName    *string           `json:"acl_policy_name,omitempty"`
	PortalProfile    *string           `json:"portal_profile,omitempty"`
	FilterID         *string           `json:"filter_id,omitempty"`
	PolicyTag        *string           `json:"policy_tag,omitempty"`
	Tenant           *string           `json:"tenant,omitempty"`
	DeviceGroup      *string           `json:"device_group,omitempty"`
	AccountingClass  *string           `json:"accounting_class,omitempty"`
	SessionLimit     *int              `json:"session_limit,omitempty"`
	Attributes       map[string]string `json:"attributes,omitempty"`
}

type ServiceChainValidation struct {
	Valid        bool            `json:"valid"`
	ServiceCount int             `json:"service_count"`
	Required     int             `json:"required"`
	Optional     int             `json:"optional"`
	ChainHash    string          `json:"chain_hash,omitempty"`
	Services     []ServiceIntent `json:"services,omitempty"`
	Errors       []string        `json:"errors,omitempty"`
}

func NormalizeServiceChain(chain []ServiceIntent) []ServiceIntent {
	if len(chain) == 0 {
		return nil
	}
	out := make([]ServiceIntent, 0, len(chain))
	for i, service := range chain {
		service.Key = strings.ToLower(strings.TrimSpace(service.Key))
		service.Name = strings.TrimSpace(service.Name)
		service.Type = normalizeServiceType(service.Type)
		service.Vendor = strings.TrimSpace(service.Vendor)
		service.VendorPack = strings.ToLower(strings.TrimSpace(service.VendorPack))
		service.Action = normalizeServiceAction(service.Action)
		if service.Sequence <= 0 {
			service.Sequence = i + 1
		}
		service.DependsOn = normalizeServiceDependencies(service.DependsOn)
		service.Role = normalizeStringPtr(service.Role)
		service.BandwidthProfile = normalizeStringPtr(service.BandwidthProfile)
		service.ACLPolicyName = normalizeStringPtr(service.ACLPolicyName)
		service.PortalProfile = normalizeStringPtr(service.PortalProfile)
		service.FilterID = normalizeStringPtr(service.FilterID)
		service.PolicyTag = normalizeStringPtr(service.PolicyTag)
		service.Tenant = normalizeStringPtr(service.Tenant)
		service.DeviceGroup = normalizeStringPtr(service.DeviceGroup)
		service.AccountingClass = normalizeStringPtr(service.AccountingClass)
		service.Attributes = normalizeServiceAttributes(service.Attributes)
		out = append(out, service)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Sequence == out[j].Sequence {
			return out[i].Key < out[j].Key
		}
		return out[i].Sequence < out[j].Sequence
	})
	return out
}

func ValidateServiceChain(chain []ServiceIntent) error {
	return ValidateServiceChainWithLimit(chain, MaxServiceChainLength)
}

func ValidateServiceChainWithLimit(chain []ServiceIntent, limit int) error {
	chain = NormalizeServiceChain(chain)
	if len(chain) == 0 {
		return nil
	}
	if limit <= 0 || limit > MaxServiceChainLength {
		limit = MaxServiceChainLength
	}
	if len(chain) > limit {
		return fmt.Errorf("service_chain contains %d services, maximum is %d", len(chain), limit)
	}
	seen := map[string]ServiceIntent{}
	sequenceByKey := map[string]int{}
	for i, service := range chain {
		path := fmt.Sprintf("service_chain[%d]", i)
		if !validPolicyToken(service.Key) {
			return fmt.Errorf("%s key %q is invalid", path, service.Key)
		}
		if _, exists := seen[service.Key]; exists {
			return fmt.Errorf("%s duplicates service key %q", path, service.Key)
		}
		seen[service.Key] = service
		sequenceByKey[service.Key] = service.Sequence
		if service.Sequence < 1 || service.Sequence > 4096 {
			return fmt.Errorf("%s sequence must be between 1 and 4096", path)
		}
		if service.Type != "" && !validServiceType(service.Type) {
			return fmt.Errorf("%s type %q is invalid", path, service.Type)
		}
		if service.VendorPack != "" && !validPolicyToken(service.VendorPack) {
			return fmt.Errorf("%s vendor_pack %q is invalid", path, service.VendorPack)
		}
		if !validServiceAction(service.Action) {
			return fmt.Errorf("%s action %q is invalid", path, service.Action)
		}
		if service.VLAN != nil && (*service.VLAN < 1 || *service.VLAN > 4094) {
			return fmt.Errorf("%s vlan must be between 1 and 4094", path)
		}
		if service.SessionLimit != nil && *service.SessionLimit < 0 {
			return fmt.Errorf("%s session_limit cannot be negative", path)
		}
		if len(service.Attributes) > MaxServiceIntentAttributes {
			return fmt.Errorf("%s attributes contains %d keys, maximum is %d", path, len(service.Attributes), MaxServiceIntentAttributes)
		}
		for key, value := range service.Attributes {
			if !validServiceAttributeKey(key) {
				return fmt.Errorf("%s attributes key %q is invalid", path, key)
			}
			if len(value) > 512 {
				return fmt.Errorf("%s attributes[%q] exceeds 512 bytes", path, key)
			}
		}
	}
	for i, service := range chain {
		path := fmt.Sprintf("service_chain[%d]", i)
		for _, dependency := range service.DependsOn {
			if dependency == service.Key {
				return fmt.Errorf("%s depends on itself", path)
			}
			dependencySequence, ok := sequenceByKey[dependency]
			if !ok {
				return fmt.Errorf("%s depends on unknown service %q", path, dependency)
			}
			if dependencySequence >= service.Sequence {
				return fmt.Errorf("%s dependency %q must have a lower sequence than %q", path, dependency, service.Key)
			}
		}
	}
	return nil
}

func SummarizeServiceChain(chain []ServiceIntent) ServiceChainValidation {
	normalized := NormalizeServiceChain(chain)
	summary := ServiceChainValidation{
		ServiceCount: len(normalized),
		Services:     normalized,
		ChainHash:    ServiceChainHash(normalized),
	}
	for _, service := range normalized {
		if service.Optional {
			summary.Optional++
		} else {
			summary.Required++
		}
	}
	if err := ValidateServiceChain(normalized); err != nil {
		summary.Errors = append(summary.Errors, err.Error())
		return summary
	}
	summary.Valid = true
	return summary
}

func ServiceChainHash(chain []ServiceIntent) string {
	chain = NormalizeServiceChain(chain)
	data, _ := json.Marshal(chain)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func MergeServiceChains(current, next []ServiceIntent) []ServiceIntent {
	merged := NormalizeServiceChain(current)
	replacements := map[string]ServiceIntent{}
	for _, service := range NormalizeServiceChain(next) {
		replacements[service.Key] = service
	}
	if len(replacements) == 0 {
		return merged
	}
	out := make([]ServiceIntent, 0, len(merged)+len(replacements))
	for _, service := range merged {
		if replacement, ok := replacements[service.Key]; ok {
			out = append(out, replacement)
			delete(replacements, service.Key)
			continue
		}
		out = append(out, service)
	}
	for _, service := range replacements {
		out = append(out, service)
	}
	return NormalizeServiceChain(out)
}

func normalizeServiceDependencies(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeServiceAttributes(attrs map[string]string) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range attrs {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func normalizeServiceAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "activate"
	}
	return value
}

func validServiceAction(value string) bool {
	switch normalizeServiceAction(value) {
	case "activate", "authorize", "deactivate":
		return true
	default:
		return false
	}
}

func normalizeServiceType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validServiceType(value string) bool {
	switch normalizeServiceType(value) {
	case "access", "subscriber", "data", "voice", "video", "qos", "acl", "firewall", "captive_portal", "hotspot", "quarantine", "routing", "ipv6", "lawful_intercept", "charging", "controller":
		return true
	default:
		return false
	}
}

func validServiceAttributeKey(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.' || r == ':' || r == '/'):
		default:
			return false
		}
	}
	return true
}
