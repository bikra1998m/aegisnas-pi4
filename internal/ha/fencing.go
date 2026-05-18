package ha

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type sharedHeartbeat struct {
	NodeName       string `json:"node_name"`
	ConfiguredRole string `json:"configured_role"`
	EffectiveRole  string `json:"effective_role,omitempty"`
	VirtualIP      string `json:"virtual_ip,omitempty"`
	VIPAssigned    bool   `json:"vip_assigned"`
	PublishedAt    string `json:"published_at"`
}

type fencingResult struct {
	Enabled            bool
	Status             string
	Summary            string
	AllowPromotion     bool
	LocalWriteError    error
	PeerLoadError      error
	PeerPresent        bool
	PeerAge            time.Duration
	PeerAgeErr         error
	PeerStale          bool
	PeerHeartbeat      sharedHeartbeat
	LocalHeartbeat     sharedHeartbeat
	WitnessStatus      string
	WitnessSummary     string
	WitnessAllowed     bool
	WitnessObserved    string
	WitnessObservedAge time.Duration
	WitnessObservedErr error
	WitnessNode        string
	WitnessError       error
}

type witnessDecision struct {
	AllowPromotion    bool   `json:"allow_promotion"`
	Summary           string `json:"summary,omitempty"`
	ObservedAt        string `json:"observed_at,omitempty"`
	WitnessNode       string `json:"witness_node,omitempty"`
	Challenge         string `json:"challenge,omitempty"`
	RequestChallenge  string `json:"-"`
	ReplayStatus      string `json:"-"`
	SignatureStatus   string `json:"-"`
	SignatureRequired bool   `json:"-"`
}

type witnessEvaluation struct {
	URL            string
	Status         string
	Summary        string
	Allowed        bool
	Decision       witnessDecision
	MaxAgeSeconds  int
	ObservedAge    time.Duration
	ObservedAgeErr error
	Err            error
}

var (
	errWitnessTokenMissing      = errors.New("ha witness bearer token env is configured but not loaded")
	errWitnessSigningKeyMissing = errors.New("ha witness signing key env is configured but not loaded")
	errWitnessSignatureMissing  = errors.New("ha witness response signature is missing")
	errWitnessSignatureInvalid  = errors.New("ha witness response signature is invalid")
	errWitnessChallengeMissing  = errors.New("ha witness response challenge is missing")
	errWitnessChallengeMismatch = errors.New("ha witness response challenge does not match the request")
)

func witnessBearerToken(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	envName := strings.TrimSpace(cfg.HighAvailability.WitnessTokenEnv)
	if envName == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func witnessSigningKey(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	envName := strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv)
	if envName == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func normalizeWitnessSignature(raw string) string {
	signature := strings.TrimSpace(raw)
	signature = strings.TrimPrefix(signature, "sha256=")
	signature = strings.TrimPrefix(signature, "SHA256=")
	return strings.TrimSpace(signature)
}

func verifyWitnessSignature(cfg *config.Config, tier string, headers http.Header, body []byte) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv) == "" {
		return "disabled", nil
	}
	key := witnessSigningKey(cfg)
	if key == "" {
		return "missing", fmt.Errorf("%w %q", errWitnessSigningKeyMissing, strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv))
	}
	required := witnessTierRequiresSignature(cfg, tier)
	signature := normalizeWitnessSignature(headers.Get("X-AegisNAS-Witness-Signature"))
	if signature == "" {
		if required {
			return "missing", errWitnessSignatureMissing
		}
		return "unsigned", nil
	}
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return "invalid", fmt.Errorf("%w: decode hex: %v", errWitnessSignatureInvalid, err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := mac.Write(body); err != nil {
		return "invalid", fmt.Errorf("sign witness response: %w", err)
	}
	if !hmac.Equal(decodedSignature, mac.Sum(nil)) {
		return "invalid", errWitnessSignatureInvalid
	}
	return "verified", nil
}

func replayProtectionEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.HighAvailability.WitnessReplayProtectionEnabled
}

func witnessSignatureRequiredTiers(cfg *config.Config) ([]string, map[string]struct{}) {
	if cfg == nil {
		return nil, map[string]struct{}{}
	}
	tiers := make([]string, 0, len(cfg.HighAvailability.WitnessSignatureRequiredTiers))
	seen := make(map[string]struct{}, len(cfg.HighAvailability.WitnessSignatureRequiredTiers))
	for _, tier := range cfg.HighAvailability.WitnessSignatureRequiredTiers {
		trimmed := strings.TrimSpace(tier)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		tiers = append(tiers, trimmed)
	}
	return tiers, seen
}

func witnessTierRequiresSignature(cfg *config.Config, tier string) bool {
	if cfg == nil {
		return false
	}
	if replayProtectionEnabled(cfg) {
		return true
	}
	tier = strings.TrimSpace(tier)
	requiredTiers, requiredSet := witnessSignatureRequiredTiers(cfg)
	if len(requiredTiers) == 0 {
		return strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv) != ""
	}
	_, ok := requiredSet[tier]
	return ok
}

func witnessReplayRequiredTiers(cfg *config.Config) ([]string, map[string]struct{}) {
	if cfg == nil {
		return nil, map[string]struct{}{}
	}
	tiers := make([]string, 0, len(cfg.HighAvailability.WitnessReplayRequiredTiers))
	seen := make(map[string]struct{}, len(cfg.HighAvailability.WitnessReplayRequiredTiers))
	for _, tier := range cfg.HighAvailability.WitnessReplayRequiredTiers {
		trimmed := strings.TrimSpace(tier)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		tiers = append(tiers, trimmed)
	}
	return tiers, seen
}

func witnessChallengeEnabled(cfg *config.Config) bool {
	if replayProtectionEnabled(cfg) {
		return true
	}
	tiers, _ := witnessReplayRequiredTiers(cfg)
	return len(tiers) > 0
}

func witnessTierRequiresReplay(cfg *config.Config, tier string) bool {
	if replayProtectionEnabled(cfg) {
		return true
	}
	_, required := witnessReplayRequiredTiers(cfg)
	_, ok := required[strings.TrimSpace(tier)]
	return ok
}

func normalizeWitnessURLSet(primary string, urls []string) []string {
	normalized := make([]string, 0, len(urls)+1)
	seen := map[string]struct{}{}
	appendURL := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if _, exists := seen[trimmed]; exists {
			return
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if len(urls) > 0 {
		for _, witnessURL := range urls {
			appendURL(witnessURL)
		}
		return normalized
	}
	appendURL(primary)
	return normalized
}

func effectiveWitnessURLs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return normalizeWitnessURLSet(cfg.HighAvailability.WitnessAPIURL, cfg.HighAvailability.WitnessURLs)
}

func effectiveWitnessQuorum(cfg *config.Config, witnessCount int) int {
	if cfg == nil || witnessCount <= 0 {
		return 0
	}
	if cfg.HighAvailability.WitnessQuorum > 0 {
		return cfg.HighAvailability.WitnessQuorum
	}
	return 1
}

func effectiveWitnessWeights(cfg *config.Config, witnessURLs []string) (map[string]int, int) {
	weights := make(map[string]int, len(witnessURLs))
	total := 0
	if cfg == nil {
		return weights, total
	}
	for _, witnessURL := range witnessURLs {
		weight := 1
		if cfg.HighAvailability.WitnessWeights != nil {
			if override, ok := cfg.HighAvailability.WitnessWeights[strings.TrimSpace(witnessURL)]; ok && override > 0 {
				weight = override
			}
		}
		weights[witnessURL] = weight
		total += weight
	}
	return weights, total
}

func effectiveWitnessGroups(cfg *config.Config, witnessURLs []string) (map[string]string, []string) {
	groups := make(map[string]string, len(witnessURLs))
	distinctSet := make(map[string]struct{}, len(witnessURLs))
	distinct := make([]string, 0, len(witnessURLs))
	for _, witnessURL := range witnessURLs {
		group := strings.TrimSpace(witnessURL)
		if cfg != nil && cfg.HighAvailability.WitnessGroups != nil {
			if override, ok := cfg.HighAvailability.WitnessGroups[strings.TrimSpace(witnessURL)]; ok && strings.TrimSpace(override) != "" {
				group = strings.TrimSpace(override)
			}
		}
		groups[witnessURL] = group
		if _, exists := distinctSet[group]; exists {
			continue
		}
		distinctSet[group] = struct{}{}
		distinct = append(distinct, group)
	}
	return groups, distinct
}

func effectiveWitnessSources(cfg *config.Config, witnessURLs []string) (map[string]string, []string) {
	sources := make(map[string]string, len(witnessURLs))
	distinctSet := make(map[string]struct{}, len(witnessURLs))
	distinct := make([]string, 0, len(witnessURLs))
	for _, witnessURL := range witnessURLs {
		source := strings.TrimSpace(witnessURL)
		if cfg != nil && cfg.HighAvailability.WitnessSources != nil {
			if override, ok := cfg.HighAvailability.WitnessSources[strings.TrimSpace(witnessURL)]; ok && strings.TrimSpace(override) != "" {
				source = strings.TrimSpace(override)
			}
		}
		sources[witnessURL] = source
		if _, exists := distinctSet[source]; exists {
			continue
		}
		distinctSet[source] = struct{}{}
		distinct = append(distinct, source)
	}
	return sources, distinct
}

func effectiveWitnessConfidence(cfg *config.Config, witnessURLs []string, witnessSources map[string]string) (map[string]string, []string) {
	confidence := make(map[string]string, len(witnessURLs))
	distinctSet := make(map[string]struct{}, len(witnessURLs)+1)
	distinct := make([]string, 0, len(witnessURLs)+1)
	for _, witnessURL := range witnessURLs {
		tier := "standard"
		source := strings.TrimSpace(witnessSources[witnessURL])
		if source == "" {
			source = strings.TrimSpace(witnessURL)
		}
		if cfg != nil && cfg.HighAvailability.WitnessSourceConfidence != nil {
			if override, ok := cfg.HighAvailability.WitnessSourceConfidence[source]; ok && strings.TrimSpace(override) != "" {
				tier = strings.TrimSpace(override)
			}
		}
		confidence[witnessURL] = tier
		if _, exists := distinctSet[tier]; exists {
			continue
		}
		distinctSet[tier] = struct{}{}
		distinct = append(distinct, tier)
	}
	return confidence, distinct
}

func witnessBlockingTiers(cfg *config.Config) ([]string, map[string]struct{}) {
	if cfg == nil {
		return nil, map[string]struct{}{}
	}
	tiers := make([]string, 0, len(cfg.HighAvailability.WitnessBlockingTiers))
	seen := make(map[string]struct{}, len(cfg.HighAvailability.WitnessBlockingTiers))
	for _, tier := range cfg.HighAvailability.WitnessBlockingTiers {
		trimmed := strings.TrimSpace(tier)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		tiers = append(tiers, trimmed)
	}
	return tiers, seen
}

func effectiveWitnessTierFailureTolerance(cfg *config.Config, failedCountByTier map[string]int, defaultTolerance int) (int, map[string]int) {
	applied := make(map[string]int)
	tolerated := 0
	unmatchedFailures := 0
	for tier, count := range failedCountByTier {
		if count <= 0 {
			continue
		}
		if cfg != nil && cfg.HighAvailability.WitnessFailureToleranceByTier != nil {
			if budget, ok := cfg.HighAvailability.WitnessFailureToleranceByTier[tier]; ok {
				applied[tier] = minInt(count, maxInt(budget, 0))
				tolerated += applied[tier]
				continue
			}
		}
		unmatchedFailures += count
	}
	if unmatchedFailures > 0 && defaultTolerance > 0 {
		applied["default"] = minInt(unmatchedFailures, defaultTolerance)
		tolerated += applied["default"]
	}
	return tolerated, applied
}

func effectiveWitnessTierFailureWeightTolerance(cfg *config.Config, failedWeightByTier map[string]int, defaultTolerance int) (int, map[string]int) {
	applied := make(map[string]int)
	tolerated := 0
	unmatchedWeight := 0
	for tier, weight := range failedWeightByTier {
		if weight <= 0 {
			continue
		}
		if cfg != nil && cfg.HighAvailability.WitnessFailureWeightByTier != nil {
			if budget, ok := cfg.HighAvailability.WitnessFailureWeightByTier[tier]; ok {
				applied[tier] = minInt(weight, maxInt(budget, 0))
				tolerated += applied[tier]
				continue
			}
		}
		unmatchedWeight += weight
	}
	if unmatchedWeight > 0 && defaultTolerance > 0 {
		applied["default"] = minInt(unmatchedWeight, defaultTolerance)
		tolerated += applied["default"]
	}
	return tolerated, applied
}

func requiredWitnessSources(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	required := make([]string, 0, len(cfg.HighAvailability.WitnessRequiredSources))
	seen := make(map[string]struct{}, len(cfg.HighAvailability.WitnessRequiredSources))
	for _, source := range cfg.HighAvailability.WitnessRequiredSources {
		trimmed := strings.TrimSpace(source)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		required = append(required, trimmed)
	}
	return required
}

func requiredWitnessURLs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	required := make([]string, 0, len(cfg.HighAvailability.WitnessRequiredURLs))
	seen := make(map[string]struct{}, len(cfg.HighAvailability.WitnessRequiredURLs))
	for _, witnessURL := range cfg.HighAvailability.WitnessRequiredURLs {
		trimmed := strings.TrimSpace(witnessURL)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		required = append(required, trimmed)
	}
	return required
}

func requiredWitnessSourcesByTier(cfg *config.Config) map[string][]string {
	if cfg == nil || cfg.HighAvailability.WitnessRequiredSourcesByTier == nil {
		return nil
	}
	required := make(map[string][]string, len(cfg.HighAvailability.WitnessRequiredSourcesByTier))
	for tier, sources := range cfg.HighAvailability.WitnessRequiredSourcesByTier {
		trimmedTier := strings.TrimSpace(tier)
		if trimmedTier == "" {
			continue
		}
		seen := make(map[string]struct{}, len(sources))
		normalized := make([]string, 0, len(sources))
		for _, source := range sources {
			trimmedSource := strings.TrimSpace(source)
			if trimmedSource == "" {
				continue
			}
			if _, exists := seen[trimmedSource]; exists {
				continue
			}
			seen[trimmedSource] = struct{}{}
			normalized = append(normalized, trimmedSource)
		}
		if len(normalized) == 0 {
			continue
		}
		required[trimmedTier] = normalized
	}
	return required
}

func requiredWitnessGroupsByTier(cfg *config.Config) map[string][]string {
	if cfg == nil || cfg.HighAvailability.WitnessRequiredGroupsByTier == nil {
		return nil
	}
	required := make(map[string][]string, len(cfg.HighAvailability.WitnessRequiredGroupsByTier))
	for tier, groups := range cfg.HighAvailability.WitnessRequiredGroupsByTier {
		trimmedTier := strings.TrimSpace(tier)
		if trimmedTier == "" {
			continue
		}
		seen := make(map[string]struct{}, len(groups))
		normalized := make([]string, 0, len(groups))
		for _, group := range groups {
			trimmedGroup := strings.TrimSpace(group)
			if trimmedGroup == "" {
				continue
			}
			if _, exists := seen[trimmedGroup]; exists {
				continue
			}
			seen[trimmedGroup] = struct{}{}
			normalized = append(normalized, trimmedGroup)
		}
		if len(normalized) == 0 {
			continue
		}
		required[trimmedTier] = normalized
	}
	return required
}

func requiredWitnessURLsByTier(cfg *config.Config) map[string][]string {
	if cfg == nil || cfg.HighAvailability.WitnessRequiredURLsByTier == nil {
		return nil
	}
	required := make(map[string][]string, len(cfg.HighAvailability.WitnessRequiredURLsByTier))
	for tier, witnessURLs := range cfg.HighAvailability.WitnessRequiredURLsByTier {
		trimmedTier := strings.TrimSpace(tier)
		if trimmedTier == "" {
			continue
		}
		seen := make(map[string]struct{}, len(witnessURLs))
		normalized := make([]string, 0, len(witnessURLs))
		for _, witnessURL := range witnessURLs {
			trimmedURL := strings.TrimSpace(witnessURL)
			if trimmedURL == "" {
				continue
			}
			if _, exists := seen[trimmedURL]; exists {
				continue
			}
			seen[trimmedURL] = struct{}{}
			normalized = append(normalized, trimmedURL)
		}
		if len(normalized) == 0 {
			continue
		}
		required[trimmedTier] = normalized
	}
	return required
}

func mapKeysSorted(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func formatIntMapSorted(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, values[key]))
	}
	return parts
}

func formatStringSliceMapSorted(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, strings.Join(values[key], ",")))
	}
	return parts
}

func formatStringMapSorted(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, values[key]))
	}
	return parts
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func witnessPolicyMode(cfg *config.Config) string {
	if cfg == nil {
		return "all"
	}
	return normalizeWitnessPolicyModeValue(cfg.HighAvailability.WitnessPolicyMode)
}

func normalizeWitnessPolicyModeValue(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "all":
		return "all"
	case "any":
		return "any"
	case "group_only":
		return "group_only"
	case "source_only":
		return "source_only"
	case "url_only":
		return "url_only"
	default:
		return "all"
	}
}

func normalizeWitnessTierPolicyModeValue(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "all":
		return "all"
	case "any":
		return "any"
	case "group_only":
		return "group_only"
	case "source_only":
		return "source_only"
	case "url_only":
		return "url_only"
	default:
		return "all"
	}
}

func witnessPolicyModeByTier(cfg *config.Config) map[string]string {
	if cfg == nil || cfg.HighAvailability.WitnessPolicyModeByTier == nil {
		return nil
	}
	overrides := make(map[string]string, len(cfg.HighAvailability.WitnessPolicyModeByTier))
	for tier, mode := range cfg.HighAvailability.WitnessPolicyModeByTier {
		trimmedTier := strings.TrimSpace(tier)
		if trimmedTier == "" {
			continue
		}
		overrides[trimmedTier] = normalizeWitnessTierPolicyModeValue(mode)
	}
	return overrides
}

func effectiveWitnessPolicyModeForTier(cfg *config.Config, tier string) string {
	tier = strings.TrimSpace(tier)
	if tier != "" && cfg != nil && cfg.HighAvailability.WitnessPolicyModeByTier != nil {
		if override, ok := cfg.HighAvailability.WitnessPolicyModeByTier[tier]; ok {
			return normalizeWitnessTierPolicyModeValue(override)
		}
	}
	return "all"
}

func effectiveWitnessFailureTolerance(cfg *config.Config, witnessCount int) int {
	if cfg == nil || witnessCount <= 0 {
		return 0
	}
	tolerance := cfg.HighAvailability.WitnessFailureTolerance
	if tolerance < 0 {
		return 0
	}
	if tolerance > witnessCount {
		return witnessCount
	}
	return tolerance
}

func effectiveWitnessFailureWeightTolerance(cfg *config.Config, totalWeight int) int {
	if cfg == nil || totalWeight <= 0 {
		return 0
	}
	tolerance := cfg.HighAvailability.WitnessFailureWeightTolerance
	if tolerance < 0 {
		return 0
	}
	if tolerance > totalWeight {
		return totalWeight
	}
	return tolerance
}

func newWitnessChallenge() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate witness challenge: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func effectiveWitnessMaxAgeSeconds(cfg *config.Config, tier string) int {
	if cfg == nil {
		return 0
	}
	tier = strings.TrimSpace(tier)
	if tier != "" && cfg.HighAvailability.WitnessMaxAgeByTier != nil {
		if override, ok := cfg.HighAvailability.WitnessMaxAgeByTier[tier]; ok && override >= 0 {
			return override
		}
	}
	if cfg.HighAvailability.WitnessMaxAgeSeconds < 0 {
		return 0
	}
	return cfg.HighAvailability.WitnessMaxAgeSeconds
}

func effectiveWitnessRequiredNode(cfg *config.Config, tier string) string {
	if cfg == nil {
		return ""
	}
	tier = strings.TrimSpace(tier)
	if tier != "" && cfg.HighAvailability.WitnessRequiredNodeByTier != nil {
		if override, ok := cfg.HighAvailability.WitnessRequiredNodeByTier[tier]; ok && strings.TrimSpace(override) != "" {
			return strings.TrimSpace(override)
		}
	}
	return strings.TrimSpace(cfg.HighAvailability.WitnessRequiredNode)
}

func effectiveWitnessConfidenceForURL(cfg *config.Config, witnessURL string) string {
	witnessURL = strings.TrimSpace(witnessURL)
	if witnessURL == "" {
		return "standard"
	}
	urls := []string{witnessURL}
	sources, _ := effectiveWitnessSources(cfg, urls)
	confidence, _ := effectiveWitnessConfidence(cfg, urls, sources)
	if tier := strings.TrimSpace(confidence[witnessURL]); tier != "" {
		return tier
	}
	return "standard"
}

func evaluateWitnessDecisionPolicy(cfg *config.Config, observedAt time.Time, tier string, decision witnessDecision) witnessEvaluation {
	evaluation := witnessEvaluation{
		Status:        "ok",
		Summary:       strings.TrimSpace(decision.Summary),
		Allowed:       decision.AllowPromotion,
		Decision:      decision,
		MaxAgeSeconds: effectiveWitnessMaxAgeSeconds(cfg, tier),
	}
	if evaluation.Summary == "" {
		if decision.AllowPromotion {
			evaluation.Summary = "External HA witness allows standby promotion."
		} else {
			evaluation.Summary = "External HA witness denied standby promotion."
		}
	}
	if strings.TrimSpace(decision.ObservedAt) != "" {
		evaluation.ObservedAge, evaluation.ObservedAgeErr = witnessObservedAge(strings.TrimSpace(decision.ObservedAt), observedAt)
	}
	requiredNode := effectiveWitnessRequiredNode(cfg, tier)
	replayRequired := witnessTierRequiresReplay(cfg, tier)
	signatureRequired := witnessTierRequiresSignature(cfg, tier)
	maxWitnessAge := time.Duration(evaluation.MaxAgeSeconds) * time.Second
	switch {
	case !decision.AllowPromotion:
		evaluation.Status = "blocked"
		evaluation.Allowed = false
	case signatureRequired && decision.SignatureStatus == "missing":
		evaluation.Status = "signature_missing"
		evaluation.Summary = "External HA witness did not include the signed response required by local signature policy."
		evaluation.Err = errWitnessSignatureMissing
		evaluation.Allowed = false
	case signatureRequired && decision.SignatureStatus == "invalid":
		evaluation.Status = "signature_invalid"
		evaluation.Summary = "External HA witness signature failed local signature policy verification."
		evaluation.Err = errWitnessSignatureInvalid
		evaluation.Allowed = false
	case replayRequired && decision.ReplayStatus == "missing":
		evaluation.Status = "replay_missing"
		evaluation.Summary = "External HA witness did not echo the per-request challenge required by local replay policy."
		evaluation.Err = errWitnessChallengeMissing
		evaluation.Allowed = false
	case replayRequired && decision.ReplayStatus == "mismatch":
		evaluation.Status = "replay_mismatch"
		evaluation.Summary = "External HA witness challenge did not match the local replay policy request."
		evaluation.Err = errWitnessChallengeMismatch
		evaluation.Allowed = false
	case requiredNode != "" && !strings.EqualFold(strings.TrimSpace(decision.WitnessNode), requiredNode):
		evaluation.Status = "unexpected_node"
		evaluation.Summary = fmt.Sprintf("External HA witness %q does not match required witness node %q.", strings.TrimSpace(decision.WitnessNode), requiredNode)
		evaluation.Allowed = false
	case maxWitnessAge > 0 && strings.TrimSpace(decision.ObservedAt) == "":
		evaluation.Status = "stale"
		evaluation.Summary = "External HA witness did not include observed_at required by local freshness policy."
		evaluation.Allowed = false
	case evaluation.ObservedAgeErr != nil:
		evaluation.Status = "invalid"
		evaluation.Summary = "External HA witness observed_at timestamp is invalid."
		evaluation.Err = evaluation.ObservedAgeErr
		evaluation.Allowed = false
	case maxWitnessAge > 0 && evaluation.ObservedAge > maxWitnessAge:
		evaluation.Status = "stale"
		evaluation.Summary = fmt.Sprintf("External HA witness response is stale at %ds and exceeds the %ds freshness policy.", int(evaluation.ObservedAge.Seconds()), evaluation.MaxAgeSeconds)
		evaluation.Allowed = false
	}
	return evaluation
}

func saveSharedHeartbeat(cfg *config.Config, state sharedHeartbeat) error {
	path := sharedHeartbeatPath(cfg, state.ConfiguredRole)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("shared heartbeat path is unavailable")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal shared heartbeat: %w", err)
	}
	return writeAtomicFile(path, data, 0644)
}

func loadPeerSharedHeartbeat(cfg *config.Config) (sharedHeartbeat, bool, error) {
	var state sharedHeartbeat
	path := sharedHeartbeatPath(cfg, peerConfiguredRole(cfg))
	if strings.TrimSpace(path) == "" {
		return state, false, fmt.Errorf("peer shared heartbeat path is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, false, nil
		}
		return state, false, fmt.Errorf("read peer shared heartbeat: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return state, false, nil
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, false, fmt.Errorf("decode peer shared heartbeat: %w", err)
	}
	return state, true, nil
}

func sharedHeartbeatAge(state sharedHeartbeat, now time.Time) (time.Duration, error) {
	publishedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(state.PublishedAt))
	if err != nil {
		return 0, err
	}
	age := now.Sub(publishedAt)
	if age < 0 {
		return 0, nil
	}
	return age, nil
}

func witnessObservedAge(observedAt string, now time.Time) (time.Duration, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(observedAt))
	if err != nil {
		return 0, err
	}
	age := now.Sub(parsed)
	if age < 0 {
		return 0, nil
	}
	return age, nil
}

func fencingHeartbeatStaleAfter(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 20 * time.Second
	}
	base := cfg.HighAvailability.FailoverTimeoutSeconds
	if heartbeatFloor := cfg.HighAvailability.HeartbeatIntervalSeconds * 3; heartbeatFloor > base {
		base = heartbeatFloor
	}
	if base <= 0 {
		base = 20
	}
	return time.Duration(base) * time.Second
}

func sharedHeartbeatRootDir(cfg *config.Config) string {
	root := strings.TrimSpace(sharedStateRootDir(cfg))
	if root == "" {
		root = "/var/lib/aegisnas/ha"
	}
	return filepath.Join(root, "heartbeats")
}

func sharedHeartbeatPath(cfg *config.Config, role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return ""
	}
	return filepath.Join(sharedHeartbeatRootDir(cfg), role+".json")
}

func peerConfiguredRole(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(cfg.HighAvailability.Role)) {
	case "active":
		return "standby"
	case "standby":
		return "active"
	default:
		return ""
	}
}

func sharedStateRootDir(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.HighAvailability.SharedStateDir) != "" {
		return strings.TrimSpace(cfg.HighAvailability.SharedStateDir)
	}
	return "/var/lib/aegisnas/ha"
}

func localHeartbeatState(c *controller, observedAt time.Time) sharedHeartbeat {
	effectiveRole := strings.TrimSpace(c.cfg.HighAvailability.Role)
	if strings.EqualFold(effectiveRole, "standby") && c.vipAssigned {
		effectiveRole = "active"
	}
	return sharedHeartbeat{
		NodeName:       strings.TrimSpace(c.nodeName),
		ConfiguredRole: strings.TrimSpace(c.cfg.HighAvailability.Role),
		EffectiveRole:  effectiveRole,
		VirtualIP:      strings.TrimSpace(c.cfg.HighAvailability.VirtualIP),
		VIPAssigned:    c.vipAssigned,
		PublishedAt:    observedAt.UTC().Format(time.RFC3339),
	}
}

func (c *controller) evaluateFencing(observedAt time.Time, peerReachable, failoverActive bool, details map[string]any) fencingResult {
	result := fencingResult{
		Enabled:        c.cfg != nil && c.cfg.HighAvailability.SplitBrainProtectionEnabled,
		Status:         "disabled",
		Summary:        "Split-brain protection is disabled.",
		AllowPromotion: true,
	}
	if details == nil {
		details = map[string]any{}
	}
	details["split_brain_protection_enabled"] = result.Enabled
	details["shared_heartbeat_path"] = sharedHeartbeatPath(c.cfg, strings.TrimSpace(c.cfg.HighAvailability.Role))
	details["peer_shared_heartbeat_path"] = sharedHeartbeatPath(c.cfg, peerConfiguredRole(c.cfg))
	witnessURLs := effectiveWitnessURLs(c.cfg)
	witnessWeights, totalWitnessWeight := effectiveWitnessWeights(c.cfg, witnessURLs)
	witnessGroups, distinctWitnessGroups := effectiveWitnessGroups(c.cfg, witnessURLs)
	witnessSources, distinctWitnessSources := effectiveWitnessSources(c.cfg, witnessURLs)
	witnessConfidence, distinctWitnessConfidence := effectiveWitnessConfidence(c.cfg, witnessURLs, witnessSources)
	configuredCountByTier := make(map[string]int, len(distinctWitnessConfidence))
	configuredWeightByTier := make(map[string]int, len(distinctWitnessConfidence))
	configuredGroupsByTier := make(map[string]map[string]struct{}, len(distinctWitnessConfidence))
	configuredSourcesByTier := make(map[string]map[string]struct{}, len(distinctWitnessConfidence))
	for _, witnessURL := range witnessURLs {
		configuredCountByTier[witnessConfidence[witnessURL]]++
		configuredWeightByTier[witnessConfidence[witnessURL]] += witnessWeights[witnessURL]
		group := strings.TrimSpace(witnessGroups[witnessURL])
		if group == "" {
			group = strings.TrimSpace(witnessURL)
		}
		tierGroups := configuredGroupsByTier[witnessConfidence[witnessURL]]
		if tierGroups == nil {
			tierGroups = make(map[string]struct{})
			configuredGroupsByTier[witnessConfidence[witnessURL]] = tierGroups
		}
		tierGroups[group] = struct{}{}
		source := strings.TrimSpace(witnessSources[witnessURL])
		if source == "" {
			source = strings.TrimSpace(witnessURL)
		}
		tierSources := configuredSourcesByTier[witnessConfidence[witnessURL]]
		if tierSources == nil {
			tierSources = make(map[string]struct{})
			configuredSourcesByTier[witnessConfidence[witnessURL]] = tierSources
		}
		tierSources[source] = struct{}{}
	}
	blockingTiers, blockingTierSet := witnessBlockingTiers(c.cfg)
	requiredSources := requiredWitnessSources(c.cfg)
	requiredURLs := requiredWitnessURLs(c.cfg)
	requiredSourcesByTier := requiredWitnessSourcesByTier(c.cfg)
	requiredURLsByTier := requiredWitnessURLsByTier(c.cfg)
	requiredGroupsByTier := requiredWitnessGroupsByTier(c.cfg)
	signatureRequiredTiers, _ := witnessSignatureRequiredTiers(c.cfg)
	replayRequiredTiers, _ := witnessReplayRequiredTiers(c.cfg)
	policyMode := witnessPolicyMode(c.cfg)
	policyModeByTier := witnessPolicyModeByTier(c.cfg)
	failureTolerance := effectiveWitnessFailureTolerance(c.cfg, len(witnessURLs))
	failureWeightTolerance := effectiveWitnessFailureWeightTolerance(c.cfg, totalWitnessWeight)
	details["witness_url"] = strings.TrimSpace(c.cfg.HighAvailability.WitnessAPIURL)
	details["witness_urls"] = witnessURLs
	details["witness_quorum_required"] = effectiveWitnessQuorum(c.cfg, len(witnessURLs))
	details["witness_weight_threshold"] = c.cfg.HighAvailability.WitnessWeightThreshold
	details["witness_total_weight"] = totalWitnessWeight
	details["witness_weights"] = witnessWeights
	details["witness_groups"] = witnessGroups
	details["witness_total_group_count"] = len(distinctWitnessGroups)
	details["witness_min_distinct_groups"] = c.cfg.HighAvailability.WitnessMinDistinctGroups
	details["witness_sources"] = witnessSources
	details["witness_total_source_count"] = len(distinctWitnessSources)
	details["witness_required_sources"] = requiredSources
	details["witness_required_urls"] = requiredURLs
	details["witness_required_sources_by_tier"] = requiredSourcesByTier
	details["witness_required_urls_by_tier"] = requiredURLsByTier
	details["witness_required_groups_by_tier"] = requiredGroupsByTier
	details["witness_confidence"] = witnessConfidence
	details["witness_total_tier_count"] = len(distinctWitnessConfidence)
	details["witness_configured_count_by_tier"] = configuredCountByTier
	details["witness_configured_weight_by_tier"] = configuredWeightByTier
	configuredGroupCountByTier := make(map[string]int, len(configuredGroupsByTier))
	for tier, groups := range configuredGroupsByTier {
		configuredGroupCountByTier[tier] = len(groups)
	}
	details["witness_configured_group_count_by_tier"] = configuredGroupCountByTier
	configuredSourceCountByTier := make(map[string]int, len(configuredSourcesByTier))
	for tier, sources := range configuredSourcesByTier {
		configuredSourceCountByTier[tier] = len(sources)
	}
	details["witness_configured_source_count_by_tier"] = configuredSourceCountByTier
	details["witness_min_approvals_by_tier"] = c.cfg.HighAvailability.WitnessMinApprovalsByTier
	details["witness_min_weight_by_tier"] = c.cfg.HighAvailability.WitnessMinWeightByTier
	details["witness_min_distinct_groups_by_tier"] = c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier
	details["witness_min_distinct_sources_by_tier"] = c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier
	details["witness_required_node_by_tier"] = c.cfg.HighAvailability.WitnessRequiredNodeByTier
	details["witness_signature_required_tiers"] = signatureRequiredTiers
	details["witness_replay_required_tiers"] = replayRequiredTiers
	details["witness_blocking_tiers"] = blockingTiers
	details["witness_policy_mode"] = policyMode
	details["witness_policy_mode_by_tier"] = policyModeByTier
	details["witness_failure_tolerance"] = failureTolerance
	details["witness_failure_weight_tolerance"] = failureWeightTolerance
	details["witness_max_age_by_tier"] = c.cfg.HighAvailability.WitnessMaxAgeByTier
	details["witness_failure_tolerance_by_tier"] = c.cfg.HighAvailability.WitnessFailureToleranceByTier
	details["witness_failure_weight_tolerance_by_tier"] = c.cfg.HighAvailability.WitnessFailureWeightByTier
	details["witness_max_age_seconds"] = c.cfg.HighAvailability.WitnessMaxAgeSeconds
	details["witness_required_node"] = strings.TrimSpace(c.cfg.HighAvailability.WitnessRequiredNode)
	details["witness_replay_protection_enabled"] = replayProtectionEnabled(c.cfg)
	if strings.TrimSpace(c.cfg.HighAvailability.WitnessTokenEnv) != "" {
		details["witness_auth_status"] = "configured"
	} else {
		details["witness_auth_status"] = "disabled"
	}
	if strings.TrimSpace(c.cfg.HighAvailability.WitnessSigningKeyEnv) != "" {
		details["witness_signature_status"] = "configured"
		if len(signatureRequiredTiers) > 0 && !replayProtectionEnabled(c.cfg) {
			details["witness_signature_status"] = "tiered"
		}
	} else {
		details["witness_signature_status"] = "disabled"
	}
	if replayProtectionEnabled(c.cfg) {
		details["witness_replay_status"] = "configured"
	} else if len(replayRequiredTiers) > 0 {
		details["witness_replay_status"] = "tiered"
	} else {
		details["witness_replay_status"] = "disabled"
	}
	if !result.Enabled {
		if len(witnessURLs) > 0 {
			details["witness_status"] = "configured"
		} else {
			details["witness_status"] = "disabled"
		}
		details["fencing_status"] = result.Status
		details["fencing_summary"] = result.Summary
		details["fencing_promotion_allowed"] = result.AllowPromotion
		return result
	}

	result.LocalHeartbeat = localHeartbeatState(c, observedAt)
	if err := saveSharedHeartbeat(c.cfg, result.LocalHeartbeat); err != nil {
		result.LocalWriteError = err
		details["shared_heartbeat_error"] = err.Error()
	} else {
		details["shared_heartbeat_published_at"] = result.LocalHeartbeat.PublishedAt
	}

	result.PeerHeartbeat, result.PeerPresent, result.PeerLoadError = loadPeerSharedHeartbeat(c.cfg)
	if result.PeerLoadError != nil {
		details["peer_shared_heartbeat_error"] = result.PeerLoadError.Error()
	} else if result.PeerPresent {
		details["peer_shared_heartbeat_published_at"] = result.PeerHeartbeat.PublishedAt
		details["peer_shared_heartbeat_node"] = result.PeerHeartbeat.NodeName
		result.PeerAge, result.PeerAgeErr = sharedHeartbeatAge(result.PeerHeartbeat, observedAt.UTC())
		if result.PeerAgeErr != nil {
			details["peer_shared_heartbeat_error"] = result.PeerAgeErr.Error()
		} else {
			result.PeerStale = result.PeerAge >= fencingHeartbeatStaleAfter(c.cfg)
			details["peer_shared_heartbeat_age_seconds"] = int(result.PeerAge.Seconds())
			details["peer_shared_heartbeat_stale"] = result.PeerStale
		}
	} else {
		details["peer_shared_heartbeat_present"] = false
	}
	if result.PeerPresent {
		details["peer_shared_heartbeat_present"] = true
	}

	switch {
	case result.LocalWriteError != nil:
		result.Status = "local_write_failed"
		result.Summary = "Local shared HA heartbeat could not be published."
	case result.PeerLoadError != nil:
		result.Status = "peer_read_failed"
		result.Summary = "Peer shared HA heartbeat could not be read."
	case !result.PeerPresent:
		result.Status = "peer_missing"
		result.Summary = "Peer shared HA heartbeat is missing."
	case result.PeerAgeErr != nil:
		result.Status = "peer_invalid"
		result.Summary = "Peer shared HA heartbeat timestamp is invalid."
	case result.PeerStale:
		result.Status = "peer_stale"
		result.Summary = "Peer shared HA heartbeat is stale."
	default:
		result.Status = "peer_fresh"
		result.Summary = "Peer shared HA heartbeat is still fresh."
	}

	standbyPromotionWindow := strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") && !peerReachable && failoverActive
	if standbyPromotionWindow {
		result.AllowPromotion = result.LocalWriteError == nil &&
			result.PeerLoadError == nil &&
			result.PeerPresent &&
			result.PeerAgeErr == nil &&
			result.PeerStale
	}

	if len(witnessURLs) == 0 {
		result.WitnessStatus = "disabled"
	} else if !standbyPromotionWindow {
		result.WitnessStatus = "idle"
		if len(witnessURLs) == 1 {
			result.WitnessSummary = "External HA witness is configured and will be consulted during standby promotion."
		} else {
			result.WitnessSummary = fmt.Sprintf("%d external HA witnesses are configured and will be consulted during standby promotion.", len(witnessURLs))
		}
	} else {
		quorum := effectiveWitnessQuorum(c.cfg, len(witnessURLs))
		weightThreshold := c.cfg.HighAvailability.WitnessWeightThreshold
		groupThreshold := c.cfg.HighAvailability.WitnessMinDistinctGroups
		allowCount := 0
		allowWeight := 0
		failureCount := 0
		failureWeight := 0
		allowGroups := make(map[string]struct{}, len(witnessURLs))
		allowGroupsByTier := make(map[string]map[string]struct{}, len(distinctWitnessConfidence))
		allowSources := make(map[string]struct{}, len(witnessURLs))
		allowSourcesByTier := make(map[string]map[string]struct{}, len(distinctWitnessConfidence))
		allowURLs := make(map[string]struct{}, len(witnessURLs))
		allowURLsByTier := make(map[string]map[string]struct{}, len(distinctWitnessConfidence))
		allowCountByTier := make(map[string]int, len(distinctWitnessConfidence))
		allowWeightByTier := make(map[string]int, len(distinctWitnessConfidence))
		failedCountByTier := make(map[string]int)
		failedWeightByTier := make(map[string]int)
		witnessResults := make([]map[string]any, 0, len(witnessURLs))
		var firstFailure error
		var firstFailureSummary string
		blockingDenyTier := ""
		blockingDenyURL := ""
		blockingDenySummary := ""
		for _, witnessURL := range witnessURLs {
			confidenceTier := strings.TrimSpace(witnessConfidence[witnessURL])
			evaluation := witnessEvaluation{URL: witnessURL}
			decision, err := controllerProbeWitnessDecisionFn(c.cfg, c.client, witnessURL)
			if err != nil {
				evaluation.Status = "failed"
				evaluation.Summary = "External HA witness could not be read during standby promotion."
				evaluation.Err = err
				evaluation.MaxAgeSeconds = effectiveWitnessMaxAgeSeconds(c.cfg, confidenceTier)
			} else {
				evaluation = evaluateWitnessDecisionPolicy(c.cfg, observedAt, confidenceTier, decision)
				evaluation.URL = witnessURL
			}
			if evaluation.Allowed {
				allowCount++
				allowWeight += witnessWeights[witnessURL]
				allowCountByTier[confidenceTier]++
				allowWeightByTier[confidenceTier] += witnessWeights[witnessURL]
				allowURLs[witnessURL] = struct{}{}
				tierURLs := allowURLsByTier[confidenceTier]
				if tierURLs == nil {
					tierURLs = make(map[string]struct{})
					allowURLsByTier[confidenceTier] = tierURLs
				}
				tierURLs[witnessURL] = struct{}{}
				if group := strings.TrimSpace(witnessGroups[witnessURL]); group != "" {
					allowGroups[group] = struct{}{}
					tierGroups := allowGroupsByTier[confidenceTier]
					if tierGroups == nil {
						tierGroups = make(map[string]struct{})
						allowGroupsByTier[confidenceTier] = tierGroups
					}
					tierGroups[group] = struct{}{}
				}
				if source := strings.TrimSpace(witnessSources[witnessURL]); source != "" {
					allowSources[source] = struct{}{}
					tierSources := allowSourcesByTier[confidenceTier]
					if tierSources == nil {
						tierSources = make(map[string]struct{})
						allowSourcesByTier[confidenceTier] = tierSources
					}
					tierSources[source] = struct{}{}
				}
			} else {
				if evaluation.Err != nil {
					failureCount++
					failureWeight += witnessWeights[witnessURL]
					failedCountByTier[confidenceTier]++
					failedWeightByTier[confidenceTier] += witnessWeights[witnessURL]
					if firstFailure == nil {
						firstFailure = evaluation.Err
						firstFailureSummary = evaluation.Summary
					}
				} else if _, blocking := blockingTierSet[confidenceTier]; blocking && blockingDenyTier == "" {
					blockingDenyTier = confidenceTier
					blockingDenyURL = witnessURL
					blockingDenySummary = evaluation.Summary
				} else if firstFailureSummary == "" {
					firstFailureSummary = evaluation.Summary
				}
			}
			entry := map[string]any{
				"url":                evaluation.URL,
				"status":             evaluation.Status,
				"summary":            evaluation.Summary,
				"allow_promotion":    evaluation.Allowed,
				"weight":             witnessWeights[witnessURL],
				"group":              witnessGroups[witnessURL],
				"source":             witnessSources[witnessURL],
				"confidence_tier":    confidenceTier,
				"signature_required": decision.SignatureRequired,
				"signature_status":   strings.TrimSpace(evaluation.Decision.SignatureStatus),
				"max_age_seconds":    evaluation.MaxAgeSeconds,
				"required_node":      effectiveWitnessRequiredNode(c.cfg, confidenceTier),
				"replay_required":    witnessTierRequiresReplay(c.cfg, confidenceTier),
				"replay_status":      strings.TrimSpace(evaluation.Decision.ReplayStatus),
				"witness_node":       strings.TrimSpace(evaluation.Decision.WitnessNode),
				"observed_at":        strings.TrimSpace(evaluation.Decision.ObservedAt),
			}
			if evaluation.ObservedAgeErr == nil && strings.TrimSpace(evaluation.Decision.ObservedAt) != "" {
				entry["observed_age_seconds"] = int(evaluation.ObservedAge.Seconds())
			}
			if evaluation.Err != nil {
				entry["error"] = evaluation.Err.Error()
			}
			witnessResults = append(witnessResults, entry)
			if len(witnessURLs) == 1 {
				result.WitnessObserved = strings.TrimSpace(evaluation.Decision.ObservedAt)
				result.WitnessNode = strings.TrimSpace(evaluation.Decision.WitnessNode)
				result.WitnessObservedAge = evaluation.ObservedAge
				result.WitnessObservedErr = evaluation.ObservedAgeErr
			}
		}
		details["witness_results"] = witnessResults
		details["witness_allow_count"] = allowCount
		details["witness_total_count"] = len(witnessURLs)
		details["witness_allow_weight"] = allowWeight
		details["witness_allow_group_count"] = len(allowGroups)
		details["witness_allow_source_count"] = len(allowSources)
		allowGroupsByTierFormatted := make(map[string][]string, len(allowGroupsByTier))
		allowGroupCountByTier := make(map[string]int, len(allowGroupsByTier))
		for tier, groups := range allowGroupsByTier {
			allowGroupsByTierFormatted[tier] = mapKeysSorted(groups)
			allowGroupCountByTier[tier] = len(groups)
		}
		details["witness_allow_groups_by_tier"] = allowGroupsByTierFormatted
		details["witness_allow_group_count_by_tier"] = allowGroupCountByTier
		details["witness_allow_sources"] = mapKeysSorted(allowSources)
		details["witness_allow_urls"] = mapKeysSorted(allowURLs)
		details["witness_allow_url_count"] = len(allowURLs)
		allowURLsByTierFormatted := make(map[string][]string, len(allowURLsByTier))
		for tier, urls := range allowURLsByTier {
			allowURLsByTierFormatted[tier] = mapKeysSorted(urls)
		}
		details["witness_allow_urls_by_tier"] = allowURLsByTierFormatted
		allowSourcesByTierFormatted := make(map[string][]string, len(allowSourcesByTier))
		allowSourceCountByTier := make(map[string]int, len(allowSourcesByTier))
		for tier, sources := range allowSourcesByTier {
			allowSourcesByTierFormatted[tier] = mapKeysSorted(sources)
			allowSourceCountByTier[tier] = len(sources)
		}
		details["witness_allow_sources_by_tier"] = allowSourcesByTierFormatted
		details["witness_allow_source_count_by_tier"] = allowSourceCountByTier
		details["witness_allow_count_by_tier"] = allowCountByTier
		details["witness_allow_weight_by_tier"] = allowWeightByTier
		details["witness_failed_count"] = failureCount
		details["witness_failed_weight"] = failureWeight
		details["witness_failed_count_by_tier"] = failedCountByTier
		details["witness_failed_weight_by_tier"] = failedWeightByTier
		toleratedFailureCount, toleratedFailureCountByTier := effectiveWitnessTierFailureTolerance(c.cfg, failedCountByTier, failureTolerance)
		toleratedFailureWeight, toleratedFailureWeightByTier := effectiveWitnessTierFailureWeightTolerance(c.cfg, failedWeightByTier, failureWeightTolerance)
		details["witness_tolerated_failure_count"] = toleratedFailureCount
		details["witness_tolerated_failure_count_by_tier"] = toleratedFailureCountByTier
		details["witness_tolerated_failure_weight"] = toleratedFailureWeight
		details["witness_tolerated_failure_weight_by_tier"] = toleratedFailureWeightByTier
		effectiveQuorum := quorum
		if toleratedFailureCount > 0 {
			effectiveQuorum -= toleratedFailureCount
			if effectiveQuorum < 1 {
				effectiveQuorum = 1
			}
		}
		effectiveWeightThreshold := weightThreshold
		if toleratedFailureWeight > 0 {
			effectiveWeightThreshold -= toleratedFailureWeight
			if effectiveWeightThreshold < 0 {
				effectiveWeightThreshold = 0
			}
		}
		details["witness_effective_quorum_required"] = effectiveQuorum
		details["witness_effective_weight_threshold"] = effectiveWeightThreshold
		weightSatisfied := effectiveWeightThreshold <= 0 || allowWeight >= effectiveWeightThreshold
		tierApprovalsSatisfied := true
		missingTierApprovals := make([]string, 0)
		for tier, requiredApprovals := range c.cfg.HighAvailability.WitnessMinApprovalsByTier {
			if requiredApprovals <= 0 {
				continue
			}
			if allowCountByTier[tier] >= requiredApprovals {
				continue
			}
			tierApprovalsSatisfied = false
			missingTierApprovals = append(missingTierApprovals, fmt.Sprintf("%s %d/%d", tier, allowCountByTier[tier], requiredApprovals))
		}
		sort.Strings(missingTierApprovals)
		details["witness_tier_approval_rule_satisfied"] = tierApprovalsSatisfied
		if len(missingTierApprovals) > 0 {
			details["witness_missing_tier_approvals"] = missingTierApprovals
		}
		tierWeightSatisfied := true
		missingTierWeight := make([]string, 0)
		for tier, requiredWeight := range c.cfg.HighAvailability.WitnessMinWeightByTier {
			if requiredWeight <= 0 {
				continue
			}
			if allowWeightByTier[tier] >= requiredWeight {
				continue
			}
			tierWeightSatisfied = false
			missingTierWeight = append(missingTierWeight, fmt.Sprintf("%s %d/%d", tier, allowWeightByTier[tier], requiredWeight))
		}
		sort.Strings(missingTierWeight)
		details["witness_tier_weight_rule_satisfied"] = tierWeightSatisfied
		if len(missingTierWeight) > 0 {
			details["witness_missing_tier_weight"] = missingTierWeight
		}
		tierDistinctGroupSatisfied := true
		tierDistinctGroupMissingByTier := make(map[string]bool)
		missingTierDistinctGroups := make([]string, 0)
		for tier, requiredGroups := range c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier {
			if requiredGroups <= 0 {
				continue
			}
			observedGroups := allowGroupCountByTier[tier]
			if observedGroups >= requiredGroups {
				continue
			}
			tierDistinctGroupSatisfied = false
			tierDistinctGroupMissingByTier[tier] = true
			missingTierDistinctGroups = append(missingTierDistinctGroups, fmt.Sprintf("%s %d/%d", tier, observedGroups, requiredGroups))
		}
		sort.Strings(missingTierDistinctGroups)
		details["witness_tier_distinct_group_rule_satisfied"] = tierDistinctGroupSatisfied
		if len(missingTierDistinctGroups) > 0 {
			details["witness_missing_tier_distinct_groups"] = missingTierDistinctGroups
		}
		tierDistinctSourceSatisfied := true
		tierDistinctSourceMissingByTier := make(map[string]bool)
		missingTierDistinctSources := make([]string, 0)
		for tier, requiredSources := range c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier {
			if requiredSources <= 0 {
				continue
			}
			observedSources := allowSourceCountByTier[tier]
			if observedSources >= requiredSources {
				continue
			}
			tierDistinctSourceSatisfied = false
			tierDistinctSourceMissingByTier[tier] = true
			missingTierDistinctSources = append(missingTierDistinctSources, fmt.Sprintf("%s %d/%d", tier, observedSources, requiredSources))
		}
		sort.Strings(missingTierDistinctSources)
		details["witness_tier_distinct_source_rule_satisfied"] = tierDistinctSourceSatisfied
		if len(missingTierDistinctSources) > 0 {
			details["witness_missing_tier_distinct_sources"] = missingTierDistinctSources
		}
		tierSourceSatisfied := true
		tierSourceMissingByTier := make(map[string]bool)
		missingTierSources := make([]string, 0)
		for tier, requiredTierSources := range requiredSourcesByTier {
			if len(requiredTierSources) == 0 {
				continue
			}
			availableSources := allowSourcesByTier[tier]
			missingForTier := make([]string, 0)
			for _, source := range requiredTierSources {
				if _, ok := availableSources[source]; ok {
					continue
				}
				missingForTier = append(missingForTier, source)
			}
			if len(missingForTier) == 0 {
				continue
			}
			tierSourceSatisfied = false
			tierSourceMissingByTier[tier] = true
			sort.Strings(missingForTier)
			missingTierSources = append(missingTierSources, fmt.Sprintf("%s missing %s", tier, strings.Join(missingForTier, ",")))
		}
		sort.Strings(missingTierSources)
		details["witness_tier_source_rule_satisfied"] = tierSourceSatisfied
		if len(missingTierSources) > 0 {
			details["witness_missing_tier_sources"] = missingTierSources
		}
		tierURLSatisfied := true
		tierURLMissingByTier := make(map[string]bool)
		missingTierURLs := make([]string, 0)
		for tier, requiredTierURLs := range requiredURLsByTier {
			if len(requiredTierURLs) == 0 {
				continue
			}
			availableURLs := allowURLsByTier[tier]
			missingForTier := make([]string, 0)
			for _, requiredURL := range requiredTierURLs {
				if _, ok := availableURLs[requiredURL]; ok {
					continue
				}
				missingForTier = append(missingForTier, requiredURL)
			}
			if len(missingForTier) == 0 {
				continue
			}
			tierURLSatisfied = false
			tierURLMissingByTier[tier] = true
			sort.Strings(missingForTier)
			missingTierURLs = append(missingTierURLs, fmt.Sprintf("%s missing %s", tier, strings.Join(missingForTier, ",")))
		}
		sort.Strings(missingTierURLs)
		details["witness_tier_url_rule_satisfied"] = tierURLSatisfied
		if len(missingTierURLs) > 0 {
			details["witness_missing_tier_urls"] = missingTierURLs
		}
		tierGroupSatisfied := true
		tierGroupMissingByTier := make(map[string]bool)
		missingTierGroups := make([]string, 0)
		for tier, requiredTierGroups := range requiredGroupsByTier {
			if len(requiredTierGroups) == 0 {
				continue
			}
			availableGroups := allowGroupsByTier[tier]
			missingForTier := make([]string, 0)
			for _, group := range requiredTierGroups {
				if _, ok := availableGroups[group]; ok {
					continue
				}
				missingForTier = append(missingForTier, group)
			}
			if len(missingForTier) == 0 {
				continue
			}
			tierGroupSatisfied = false
			tierGroupMissingByTier[tier] = true
			sort.Strings(missingForTier)
			missingTierGroups = append(missingTierGroups, fmt.Sprintf("%s missing %s", tier, strings.Join(missingForTier, ",")))
		}
		sort.Strings(missingTierGroups)
		details["witness_tier_group_rule_satisfied"] = tierGroupSatisfied
		if len(missingTierGroups) > 0 {
			details["witness_missing_tier_groups"] = missingTierGroups
		}
		tierPolicyOverridesConfigured := len(policyModeByTier) > 0
		tierPolicyCandidates := make(map[string]struct{})
		for tier := range c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		for tier := range c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		for tier := range requiredSourcesByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		for tier := range requiredURLsByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		for tier := range requiredGroupsByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		for tier := range policyModeByTier {
			tierPolicyCandidates[tier] = struct{}{}
		}
		tierPolicySatisfied := true
		missingTierPolicy := make([]string, 0)
		for tier := range tierPolicyCandidates {
			mode := effectiveWitnessPolicyModeForTier(c.cfg, tier)
			groupFamilyConfigured := c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier[tier] > 0 || len(requiredGroupsByTier[tier]) > 0
			sourceFamilyConfigured := c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier[tier] > 0 || len(requiredSourcesByTier[tier]) > 0 || len(requiredURLsByTier[tier]) > 0
			groupFamilySatisfied := (!groupFamilyConfigured) || (!tierDistinctGroupMissingByTier[tier] && !tierGroupMissingByTier[tier])
			sourceFamilySatisfied := (!sourceFamilyConfigured) || (!tierDistinctSourceMissingByTier[tier] && !tierSourceMissingByTier[tier] && !tierURLMissingByTier[tier])
			tierSatisfied := true
			switch mode {
			case "any":
				switch {
				case groupFamilyConfigured && sourceFamilyConfigured:
					tierSatisfied = groupFamilySatisfied || sourceFamilySatisfied
				case groupFamilyConfigured:
					tierSatisfied = groupFamilySatisfied
				case sourceFamilyConfigured:
					tierSatisfied = sourceFamilySatisfied
				}
			case "group_only":
				tierSatisfied = groupFamilySatisfied
			case "source_only":
				tierSatisfied = sourceFamilySatisfied
			case "url_only":
				tierSatisfied = !tierURLMissingByTier[tier]
			default:
				tierSatisfied = groupFamilySatisfied && sourceFamilySatisfied
			}
			if tierSatisfied {
				continue
			}
			tierPolicySatisfied = false
			missingTierPolicy = append(missingTierPolicy, fmt.Sprintf("%s mode %s", tier, mode))
		}
		sort.Strings(missingTierPolicy)
		details["witness_tier_policy_rule_satisfied"] = tierPolicySatisfied
		if len(missingTierPolicy) > 0 {
			details["witness_missing_tier_policy"] = missingTierPolicy
		}
		groupSatisfied := groupThreshold <= 0 || len(allowGroups) >= groupThreshold
		groupConfigured := groupThreshold > 0
		sourceSatisfied := true
		sourceConfigured := len(requiredSources) > 0
		urlSatisfied := true
		urlConfigured := len(requiredURLs) > 0
		missingSources := make([]string, 0)
		if len(requiredSources) > 0 {
			for _, source := range requiredSources {
				if _, ok := allowSources[source]; ok {
					continue
				}
				sourceSatisfied = false
				missingSources = append(missingSources, source)
			}
		}
		missingURLs := make([]string, 0)
		if len(requiredURLs) > 0 {
			for _, requiredURL := range requiredURLs {
				if _, ok := allowURLs[requiredURL]; ok {
					continue
				}
				urlSatisfied = false
				missingURLs = append(missingURLs, requiredURL)
			}
		}
		details["witness_group_rule_satisfied"] = groupSatisfied
		details["witness_source_rule_satisfied"] = sourceSatisfied
		details["witness_url_rule_satisfied"] = urlSatisfied
		if len(missingURLs) > 0 {
			details["witness_missing_urls"] = missingURLs
		}
		policySatisfied := true
		policyFailureStatus := ""
		policyFailureSummary := ""
		switch policyMode {
		case "any":
			switch {
			case groupConfigured && sourceConfigured && urlConfigured:
				policySatisfied = groupSatisfied || sourceSatisfied || urlSatisfied
				if !policySatisfied {
					policyFailureStatus = "policy_any_unmet"
					policyFailureSummary = fmt.Sprintf("Witness policy mode any requires group diversity, required sources %s, or required URLs %s, but none of those rules are satisfied.", strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "))
				}
			case groupConfigured && sourceConfigured:
				policySatisfied = groupSatisfied || sourceSatisfied
				if !policySatisfied {
					policyFailureStatus = "policy_any_unmet"
					policyFailureSummary = fmt.Sprintf("Witness policy mode any requires either %d distinct groups or required sources %s, but neither rule is satisfied.", groupThreshold, strings.Join(requiredSources, ", "))
				}
			case groupConfigured && urlConfigured:
				policySatisfied = groupSatisfied || urlSatisfied
				if !policySatisfied {
					policyFailureStatus = "policy_any_unmet"
					policyFailureSummary = fmt.Sprintf("Witness policy mode any requires either %d distinct groups or required URLs %s, but neither rule is satisfied.", groupThreshold, strings.Join(requiredURLs, ", "))
				}
			case sourceConfigured && urlConfigured:
				policySatisfied = sourceSatisfied || urlSatisfied
				if !policySatisfied {
					policyFailureStatus = "policy_any_unmet"
					policyFailureSummary = fmt.Sprintf("Witness policy mode any requires either required sources %s or required URLs %s, but neither rule is satisfied.", strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "))
				}
			case groupConfigured:
				policySatisfied = groupSatisfied
				if !policySatisfied {
					policyFailureStatus = "diversity_unmet"
				}
			case sourceConfigured:
				policySatisfied = sourceSatisfied
				if !policySatisfied {
					policyFailureStatus = "source_unmet"
				}
			case urlConfigured:
				policySatisfied = urlSatisfied
				if !policySatisfied {
					policyFailureStatus = "url_unmet"
				}
			}
		case "group_only":
			policySatisfied = groupSatisfied
			if !policySatisfied {
				policyFailureStatus = "diversity_unmet"
			}
		case "source_only":
			policySatisfied = sourceSatisfied
			if !policySatisfied {
				policyFailureStatus = "source_unmet"
			}
		case "url_only":
			policySatisfied = urlSatisfied
			if !policySatisfied {
				policyFailureStatus = "url_unmet"
			}
		default:
			policySatisfied = groupSatisfied && sourceSatisfied && urlSatisfied
			if !groupSatisfied {
				policyFailureStatus = "diversity_unmet"
			} else if !sourceSatisfied {
				policyFailureStatus = "source_unmet"
			} else if !urlSatisfied {
				policyFailureStatus = "url_unmet"
			}
		}
		if blockingDenyTier != "" {
			result.WitnessAllowed = false
			result.AllowPromotion = false
			result.WitnessStatus = "blocking_deny"
			details["witness_blocking_tier_triggered"] = blockingDenyTier
			details["witness_blocking_url"] = blockingDenyURL
			if blockingDenySummary != "" {
				result.WitnessSummary = fmt.Sprintf("Witness tier %s blocked standby promotion. %s", blockingDenyTier, blockingDenySummary)
			} else {
				result.WitnessSummary = fmt.Sprintf("Witness tier %s blocked standby promotion.", blockingDenyTier)
			}
		} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && ((!tierPolicyOverridesConfigured && tierDistinctGroupSatisfied && tierDistinctSourceSatisfied && tierSourceSatisfied && tierURLSatisfied && tierGroupSatisfied) || (tierPolicyOverridesConfigured && tierPolicySatisfied)) && policySatisfied {
			result.WitnessAllowed = true
			result.AllowPromotion = result.AllowPromotion && true
			if len(witnessURLs) == 1 {
				result.WitnessStatus = "ok"
				result.WitnessSummary = witnessResults[0]["summary"].(string)
			} else {
				result.WitnessStatus = "quorum_met"
				switch {
				case (toleratedFailureCount > 0 || toleratedFailureWeight > 0) && (effectiveQuorum != quorum || effectiveWeightThreshold != weightThreshold):
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion after tolerating %d failed witness probes (weight %d); effective quorum %d/%d and effective weight threshold %d/%d satisfied.", allowCount, len(witnessURLs), failureCount, failureWeight, effectiveQuorum, quorum, effectiveWeightThreshold, weightThreshold)
				case policyMode == "any" && groupConfigured && sourceConfigured && !urlConfigured && groupSatisfied && !sourceSatisfied:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d; witness policy mode any is satisfied by group diversity (%d/%d) even though required sources %s are not all present.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), groupThreshold, strings.Join(requiredSources, ", "))
				case policyMode == "any" && groupConfigured && sourceConfigured && !urlConfigured && !groupSatisfied && sourceSatisfied:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d; witness policy mode any is satisfied by required sources %s even though group diversity is %d/%d.", allowCount, len(witnessURLs), allowWeight, strings.Join(requiredSources, ", "), len(allowGroups), groupThreshold)
				case len(c.cfg.HighAvailability.WitnessMinApprovalsByTier) > 0 || len(c.cfg.HighAvailability.WitnessMinWeightByTier) > 0 || len(c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier) > 0 || len(c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier) > 0 || len(requiredSourcesByTier) > 0 || len(requiredURLsByTier) > 0 || len(requiredGroupsByTier) > 0 || len(policyModeByTier) > 0:
					summaryParts := make([]string, 0, 2)
					if len(c.cfg.HighAvailability.WitnessMinApprovalsByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier approvals %s", strings.Join(formatIntMapSorted(c.cfg.HighAvailability.WitnessMinApprovalsByTier), ", ")))
					}
					if len(c.cfg.HighAvailability.WitnessMinWeightByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier weights %s", strings.Join(formatIntMapSorted(c.cfg.HighAvailability.WitnessMinWeightByTier), ", ")))
					}
					if len(c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier group diversity %s", strings.Join(formatIntMapSorted(c.cfg.HighAvailability.WitnessMinDistinctGroupsByTier), ", ")))
					}
					if len(c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier source diversity %s", strings.Join(formatIntMapSorted(c.cfg.HighAvailability.WitnessMinDistinctSourcesByTier), ", ")))
					}
					if len(requiredSourcesByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier sources %s", strings.Join(formatStringSliceMapSorted(requiredSourcesByTier), ", ")))
					}
					if len(requiredURLsByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier urls %s", strings.Join(formatStringSliceMapSorted(requiredURLsByTier), ", ")))
					}
					if len(requiredGroupsByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier groups %s", strings.Join(formatStringSliceMapSorted(requiredGroupsByTier), ", ")))
					}
					if len(policyModeByTier) > 0 {
						summaryParts = append(summaryParts, fmt.Sprintf("tier policy %s", strings.Join(formatStringMapSorted(policyModeByTier), ", ")))
					}
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with %s satisfied.", allowCount, len(witnessURLs), strings.Join(summaryParts, " and "))
				case weightThreshold > 0 && groupThreshold > 0 && len(requiredSources) > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d across %d distinct groups, required sources %s, and required URLs %s; quorum %d, weight threshold %d, and group threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "), quorum, weightThreshold, groupThreshold)
				case weightThreshold > 0 && len(requiredSources) > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d, required sources %s, and required URLs %s; quorum %d and weight threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "), quorum, weightThreshold)
				case groupThreshold > 0 && len(requiredSources) > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion across %d distinct groups, required sources %s, and required URLs %s; quorum %d and group threshold %d satisfied.", allowCount, len(witnessURLs), len(allowGroups), strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "), quorum, groupThreshold)
				case len(requiredSources) > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion and required sources %s and URLs %s are present; quorum %d satisfied.", allowCount, len(witnessURLs), strings.Join(requiredSources, ", "), strings.Join(requiredURLs, ", "), quorum)
				case weightThreshold > 0 && groupThreshold > 0 && len(requiredSources) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d across %d distinct groups and required sources %s; quorum %d, weight threshold %d, and group threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(requiredSources, ", "), quorum, weightThreshold, groupThreshold)
				case weightThreshold > 0 && len(requiredSources) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and required sources %s; quorum %d and weight threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, strings.Join(requiredSources, ", "), quorum, weightThreshold)
				case groupThreshold > 0 && len(requiredSources) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion across %d distinct groups and required sources %s; quorum %d and group threshold %d satisfied.", allowCount, len(witnessURLs), len(allowGroups), strings.Join(requiredSources, ", "), quorum, groupThreshold)
				case len(requiredSources) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion and required sources %s are present; quorum %d satisfied.", allowCount, len(witnessURLs), strings.Join(requiredSources, ", "), quorum)
				case weightThreshold > 0 && groupThreshold > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d across %d distinct groups and required URLs %s; quorum %d, weight threshold %d, and group threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(requiredURLs, ", "), quorum, weightThreshold, groupThreshold)
				case weightThreshold > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and required URLs %s; quorum %d and weight threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, strings.Join(requiredURLs, ", "), quorum, weightThreshold)
				case groupThreshold > 0 && len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion across %d distinct groups and required URLs %s; quorum %d and group threshold %d satisfied.", allowCount, len(witnessURLs), len(allowGroups), strings.Join(requiredURLs, ", "), quorum, groupThreshold)
				case len(requiredURLs) > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion and required URLs %s are present; quorum %d satisfied.", allowCount, len(witnessURLs), strings.Join(requiredURLs, ", "), quorum)
				case weightThreshold > 0 && groupThreshold > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d across %d distinct groups; quorum %d, weight threshold %d, and group threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), quorum, weightThreshold, groupThreshold)
				case weightThreshold > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d; quorum %d and weight threshold %d satisfied.", allowCount, len(witnessURLs), allowWeight, quorum, weightThreshold)
				case groupThreshold > 0:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion across %d distinct groups; quorum %d and group threshold %d satisfied.", allowCount, len(witnessURLs), len(allowGroups), quorum, groupThreshold)
				default:
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion; quorum %d satisfied.", allowCount, len(witnessURLs), quorum)
				}
			}
		} else {
			result.WitnessAllowed = false
			result.AllowPromotion = false
			result.WitnessError = firstFailure
			if len(witnessURLs) == 1 {
				result.WitnessStatus = fmt.Sprint(witnessResults[0]["status"])
				if firstFailureSummary != "" {
					result.WitnessSummary = firstFailureSummary
				} else {
					result.WitnessSummary = fmt.Sprint(witnessResults[0]["summary"])
				}
			} else {
				if allowCount >= effectiveQuorum && !weightSatisfied {
					result.WitnessStatus = "weight_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion but combined weight %d is below effective threshold %d (base %d). First blocking result: %s", allowCount, len(witnessURLs), allowWeight, effectiveWeightThreshold, weightThreshold, firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion but combined weight %d is below effective threshold %d (base %d).", allowCount, len(witnessURLs), allowWeight, effectiveWeightThreshold, weightThreshold)
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && !tierApprovalsSatisfied {
					result.WitnessStatus = "tier_approval_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d, but tier approvals are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), allowWeight, strings.Join(missingTierApprovals, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d, but tier approvals are unmet: %s.", allowCount, len(witnessURLs), allowWeight, strings.Join(missingTierApprovals, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && !tierWeightSatisfied {
					result.WitnessStatus = "tier_weight_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier weight floors are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierWeight, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier weight floors are unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierWeight, ", "))
					}
				} else if tierPolicyOverridesConfigured && allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && !tierPolicySatisfied {
					result.WitnessStatus = "tier_policy_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier policy overrides are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierPolicy, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier policy overrides are unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierPolicy, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && !tierDistinctGroupSatisfied {
					result.WitnessStatus = "tier_diversity_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier group diversity is unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierDistinctGroups, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier group diversity is unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierDistinctGroups, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && tierDistinctGroupSatisfied && !tierDistinctSourceSatisfied {
					result.WitnessStatus = "tier_source_diversity_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier source diversity is unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierDistinctSources, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier source diversity is unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierDistinctSources, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && tierDistinctGroupSatisfied && tierDistinctSourceSatisfied && !tierSourceSatisfied {
					result.WitnessStatus = "tier_source_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier source rules are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierSources, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier source rules are unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierSources, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && tierDistinctGroupSatisfied && tierDistinctSourceSatisfied && tierSourceSatisfied && !tierURLSatisfied {
					result.WitnessStatus = "tier_url_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier URL rules are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierURLs, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier URL rules are unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierURLs, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && tierApprovalsSatisfied && tierWeightSatisfied && tierDistinctGroupSatisfied && tierDistinctSourceSatisfied && tierSourceSatisfied && tierURLSatisfied && !tierGroupSatisfied {
					result.WitnessStatus = "tier_group_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier group rules are unmet: %s. First blocking result: %s", allowCount, len(witnessURLs), strings.Join(missingTierGroups, ", "), firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion, but tier group rules are unmet: %s.", allowCount, len(witnessURLs), strings.Join(missingTierGroups, ", "))
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && !groupSatisfied {
					result.WitnessStatus = "diversity_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d but only %d distinct groups approve; group threshold %d required. First blocking result: %s", allowCount, len(witnessURLs), allowWeight, len(allowGroups), groupThreshold, firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d but only %d distinct groups approve; group threshold %d required.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), groupThreshold)
					}
				} else if allowCount >= effectiveQuorum && weightSatisfied && !policySatisfied {
					result.WitnessStatus = policyFailureStatus
					switch policyFailureStatus {
					case "source_unmet":
						if firstFailureSummary != "" {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and %d distinct groups, but required sources %s are missing. First blocking result: %s", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(missingSources, ", "), firstFailureSummary)
						} else {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and %d distinct groups, but required sources %s are missing.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(missingSources, ", "))
						}
					case "url_unmet":
						if firstFailureSummary != "" {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and %d distinct groups, but required URLs %s are missing. First blocking result: %s", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(missingURLs, ", "), firstFailureSummary)
						} else {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d and %d distinct groups, but required URLs %s are missing.", allowCount, len(witnessURLs), allowWeight, len(allowGroups), strings.Join(missingURLs, ", "))
						}
					case "policy_any_unmet":
						if firstFailureSummary != "" {
							result.WitnessSummary = fmt.Sprintf("%s First blocking result: %s", policyFailureSummary, firstFailureSummary)
						} else {
							result.WitnessSummary = policyFailureSummary
						}
					default:
						if firstFailureSummary != "" {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion but policy mode %s is not satisfied. First blocking result: %s", allowCount, len(witnessURLs), policyMode, firstFailureSummary)
						} else {
							result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion but policy mode %s is not satisfied.", allowCount, len(witnessURLs), policyMode)
						}
					}
				} else {
					result.WitnessStatus = "quorum_unmet"
					if firstFailureSummary != "" {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d; effective quorum %d required (base %d). First blocking result: %s", allowCount, len(witnessURLs), allowWeight, effectiveQuorum, quorum, firstFailureSummary)
					} else {
						result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion with weight %d; effective quorum %d required (base %d).", allowCount, len(witnessURLs), allowWeight, effectiveQuorum, quorum)
					}
				}
			}
		}
	}

	details["witness_status"] = result.WitnessStatus
	if result.WitnessSummary != "" {
		details["witness_summary"] = result.WitnessSummary
	}
	if result.WitnessObserved != "" {
		details["witness_observed_at"] = result.WitnessObserved
	}
	if result.WitnessObserved != "" && result.WitnessObservedErr == nil {
		details["witness_observed_age_seconds"] = int(result.WitnessObservedAge.Seconds())
	}
	if result.WitnessNode != "" {
		details["witness_node"] = result.WitnessNode
	}
	if result.WitnessStatus == "ok" || result.WitnessStatus == "blocked" || result.WitnessStatus == "quorum_met" || result.WitnessStatus == "quorum_unmet" || result.WitnessStatus == "weight_unmet" || result.WitnessStatus == "diversity_unmet" || result.WitnessStatus == "source_unmet" || result.WitnessStatus == "url_unmet" || result.WitnessStatus == "policy_any_unmet" || result.WitnessStatus == "blocking_deny" || result.WitnessStatus == "tier_approval_unmet" || result.WitnessStatus == "tier_weight_unmet" || result.WitnessStatus == "tier_diversity_unmet" || result.WitnessStatus == "tier_source_diversity_unmet" || result.WitnessStatus == "tier_source_unmet" || result.WitnessStatus == "tier_group_unmet" || result.WitnessStatus == "tier_policy_unmet" {
		details["witness_allow_promotion"] = result.WitnessAllowed
	}
	if result.WitnessError != nil {
		details["witness_error"] = result.WitnessError.Error()
		if strings.TrimSpace(c.cfg.HighAvailability.WitnessTokenEnv) != "" && strings.TrimSpace(witnessBearerToken(c.cfg)) == "" {
			details["witness_auth_status"] = "missing"
		}
		if strings.TrimSpace(c.cfg.HighAvailability.WitnessSigningKeyEnv) != "" {
			switch {
			case errors.Is(result.WitnessError, errWitnessSigningKeyMissing):
				details["witness_signature_status"] = "missing"
			case errors.Is(result.WitnessError, errWitnessSignatureMissing):
				details["witness_signature_status"] = "missing"
			case errors.Is(result.WitnessError, errWitnessSignatureInvalid):
				details["witness_signature_status"] = "invalid"
			case errors.Is(result.WitnessError, errWitnessChallengeMissing):
				details["witness_replay_status"] = "missing"
			case errors.Is(result.WitnessError, errWitnessChallengeMismatch):
				details["witness_replay_status"] = "mismatch"
			}
		}
	} else {
		if strings.TrimSpace(c.cfg.HighAvailability.WitnessSigningKeyEnv) != "" {
			if len(signatureRequiredTiers) > 0 && !replayProtectionEnabled(c.cfg) {
				details["witness_signature_status"] = "tiered_verified"
			} else {
				details["witness_signature_status"] = "verified"
			}
		}
		if witnessChallengeEnabled(c.cfg) {
			details["witness_replay_status"] = "verified"
		}
	}

	if standbyPromotionWindow {
		switch {
		case result.WitnessError != nil:
			result.Status = "witness_failed"
			result.Summary = result.WitnessSummary
		case len(witnessURLs) > 0 && !result.WitnessAllowed:
			result.Status = "witness_blocked"
			result.Summary = result.WitnessSummary
		case len(witnessURLs) > 0 && result.AllowPromotion:
			result.Status = "witness_allowed"
			if len(witnessURLs) == 1 {
				result.Summary = "Peer shared HA heartbeat is stale and the external HA witness allows standby promotion."
			} else {
				result.Summary = fmt.Sprintf("Peer shared HA heartbeat is stale and %d external HA witnesses satisfy quorum.", effectiveWitnessQuorum(c.cfg, len(witnessURLs)))
			}
		}
	}

	details["fencing_status"] = result.Status
	details["fencing_summary"] = result.Summary
	details["fencing_promotion_allowed"] = result.AllowPromotion
	return result
}

func probeWitnessDecision(cfg *config.Config, client httpDoer) (witnessDecision, error) {
	witnessURLs := effectiveWitnessURLs(cfg)
	if len(witnessURLs) == 0 {
		var decision witnessDecision
		return decision, fmt.Errorf("ha witness probe requires high_availability.witness_api_url")
	}
	return probeWitnessDecisionURL(cfg, client, witnessURLs[0])
}

func probeWitnessDecisionURL(cfg *config.Config, client httpDoer, url string) (witnessDecision, error) {
	var decision witnessDecision
	if cfg == nil {
		return decision, fmt.Errorf("ha witness probe requires a config")
	}
	url = strings.TrimSpace(url)
	tier := effectiveWitnessConfidenceForURL(cfg, url)
	if url == "" {
		return decision, fmt.Errorf("ha witness probe requires high_availability.witness_api_url")
	}
	if client == nil {
		client = &http.Client{Timeout: 1500 * time.Millisecond}
	}
	if strings.TrimSpace(cfg.HighAvailability.WitnessTokenEnv) != "" && strings.TrimSpace(witnessBearerToken(cfg)) == "" {
		return decision, fmt.Errorf("ha witness bearer token env %q is configured but not loaded: %w", strings.TrimSpace(cfg.HighAvailability.WitnessTokenEnv), errWitnessTokenMissing)
	}
	if strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv) != "" && strings.TrimSpace(witnessSigningKey(cfg)) == "" {
		return decision, fmt.Errorf("ha witness signing key env %q is configured but not loaded: %w", strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv), errWitnessSigningKeyMissing)
	}
	challenge := ""
	if witnessChallengeEnabled(cfg) {
		var err error
		challenge, err = newWitnessChallenge()
		if err != nil {
			return decision, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return decision, fmt.Errorf("construct witness request: %w", err)
	}
	if token := witnessBearerToken(cfg); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if challenge != "" {
		req.Header.Set("X-AegisNAS-Witness-Challenge", challenge)
	}
	resp, err := client.Do(req)
	if err != nil {
		return decision, fmt.Errorf("probe witness: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decision, fmt.Errorf("witness returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return decision, fmt.Errorf("read witness response: %w", err)
	}
	signatureStatus, err := verifyWitnessSignature(cfg, tier, resp.Header, body)
	decision.SignatureRequired = witnessTierRequiresSignature(cfg, tier)
	decision.SignatureStatus = signatureStatus
	if err != nil {
		return decision, err
	}
	if err := json.Unmarshal(body, &decision); err != nil {
		return decision, fmt.Errorf("decode witness response: %w", err)
	}
	if challenge != "" {
		decision.RequestChallenge = challenge
		switch {
		case strings.TrimSpace(decision.Challenge) == "":
			decision.ReplayStatus = "missing"
			if replayProtectionEnabled(cfg) {
				return decision, errWitnessChallengeMissing
			}
		case strings.TrimSpace(decision.Challenge) != challenge:
			decision.ReplayStatus = "mismatch"
			if replayProtectionEnabled(cfg) {
				return decision, errWitnessChallengeMismatch
			}
		default:
			decision.ReplayStatus = "verified"
		}
	}
	return decision, nil
}
