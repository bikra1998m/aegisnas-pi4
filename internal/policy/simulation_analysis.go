package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

const PolicySimulationAnalysisSchemaVersion = 1

func AnalyzePolicySimulation(activeRules, candidateRules []Rule, samples []ReplaySample, opts SimulationAnalysisOptions, logger *zap.Logger) PolicySimulationAnalysis {
	if logger == nil {
		logger = zap.NewNop()
	}
	opts = normalizeSimulationAnalysisOptions(opts)
	if opts.MaxSamples > 0 && len(samples) > opts.MaxSamples {
		samples = samples[:opts.MaxSamples]
	}
	generatedAt := time.Now().UTC()
	analysis := PolicySimulationAnalysis{
		SchemaVersion:          PolicySimulationAnalysisSchemaVersion,
		GeneratedAt:            generatedAt.Format(time.RFC3339Nano),
		ActivePolicySetHash:    PolicySetHash(activeRules),
		CandidatePolicySetHash: PolicySetHash(candidateRules),
		SampleCount:            len(samples),
	}
	analysis.AnalysisID = newSimulationAnalysisID(analysis.ActivePolicySetHash, analysis.CandidatePolicySetHash, generatedAt, samples)

	matchedCounts := make(map[string]int)
	impactCounts := make(map[string]int)
	for i, sample := range samples {
		active := EvaluateRules(&sample.Request, activeRules, logger)
		candidate := EvaluateRules(&sample.Request, candidateRules, logger)
		analysis.ConflictCount += len(candidate.Conflicts)
		analysis.InvalidRuleCount += candidate.InvalidRuleCount
		for _, matched := range candidate.MatchedRules {
			matchedCounts[matched.Name]++
		}
		changed := changedDecisionFields(active.Decision, candidate.Decision)
		if len(changed) > 0 {
			analysis.DecisionChangeCount++
			incrementChangeCounters(&analysis, active.Decision, candidate.Decision, changed)
			if len(analysis.Deltas) < opts.MaxExamples {
				analysis.Deltas = append(analysis.Deltas, DecisionDelta{
					Index:              i,
					Source:             sample.Source,
					EvaluationID:       sample.EvaluationID,
					RequestHash:        candidate.RequestHash,
					ChangedFields:      changed,
					ActiveDecision:     active.Decision,
					CandidateDecision:  candidate.Decision,
					ActiveMatched:      active.MatchedRules,
					CandidateMatched:   candidate.MatchedRules,
					ActiveConflicts:    optionalConflicts(active.Conflicts, opts.IncludeTrace),
					CandidateConflicts: optionalConflicts(candidate.Conflicts, opts.IncludeTrace),
					Labels:             sample.Labels,
				})
			}
		}
		if opts.AnalyzeRuleImpact {
			for _, matched := range candidate.MatchedRules {
				without := removeRuleByName(candidateRules, matched.Name)
				if len(without) == len(candidateRules) {
					continue
				}
				omitted := EvaluateRules(&sample.Request, without, logger)
				if decisionFingerprint(omitted.Decision) != decisionFingerprint(candidate.Decision) {
					impactCounts[matched.Name]++
				}
			}
		}
	}
	analysis.ShadowedRules, analysis.IneffectiveRules = analyzeRuleImpact(candidateRules, matchedCounts, impactCounts, opts.AnalyzeRuleImpact)
	analysis.RiskLevel, analysis.Recommendation = classifySimulationRisk(analysis)
	return analysis
}

func normalizeSimulationAnalysisOptions(opts SimulationAnalysisOptions) SimulationAnalysisOptions {
	if opts.MaxSamples < 0 {
		opts.MaxSamples = 0
	}
	if opts.MaxExamples <= 0 || opts.MaxExamples > 100 {
		opts.MaxExamples = 25
	}
	if opts.MaxSamples > 10000 {
		opts.MaxSamples = 10000
	}
	if !opts.AnalyzeRuleImpact {
		opts.AnalyzeRuleImpact = true
	}
	return opts
}

func changedDecisionFields(active, candidate Decision) []string {
	var fields []string
	if active.Allow != candidate.Allow {
		fields = append(fields, "allow")
	}
	if active.Quarantine != candidate.Quarantine {
		fields = append(fields, "quarantine")
	}
	if stringPtrValue(active.Role) != stringPtrValue(candidate.Role) {
		fields = append(fields, "role")
	}
	if stringPtrValue(active.FilterID) != stringPtrValue(candidate.FilterID) {
		fields = append(fields, "filter_id")
	}
	if stringPtrValue(active.PolicyTag) != stringPtrValue(candidate.PolicyTag) {
		fields = append(fields, "policy_tag")
	}
	if intPtrValue(active.VLAN) != intPtrValue(candidate.VLAN) {
		fields = append(fields, "vlan")
	}
	if stringPtrValue(active.BandwidthProfile) != stringPtrValue(candidate.BandwidthProfile) {
		fields = append(fields, "bandwidth_profile")
	}
	if intPtrValue(active.SessionTimeout) != intPtrValue(candidate.SessionTimeout) {
		fields = append(fields, "session_timeout")
	}
	if intPtrValue(active.IdleTimeout) != intPtrValue(candidate.IdleTimeout) {
		fields = append(fields, "idle_timeout")
	}
	if stringPtrValue(active.PortalProfile) != stringPtrValue(candidate.PortalProfile) {
		fields = append(fields, "portal_profile")
	}
	if stringPtrValue(active.ACLPolicyName) != stringPtrValue(candidate.ACLPolicyName) {
		fields = append(fields, "acl_policy_name")
	}
	if stringPtrValue(active.DeviceGroup) != stringPtrValue(candidate.DeviceGroup) {
		fields = append(fields, "device_group")
	}
	if stringPtrValue(active.Tenant) != stringPtrValue(candidate.Tenant) {
		fields = append(fields, "tenant")
	}
	return fields
}

func incrementChangeCounters(analysis *PolicySimulationAnalysis, active, candidate Decision, fields []string) {
	if active.Allow && !candidate.Allow {
		analysis.AllowToDenyCount++
	}
	if !active.Allow && candidate.Allow {
		analysis.DenyToAllowCount++
	}
	for _, field := range fields {
		switch field {
		case "quarantine":
			analysis.QuarantineChangeCount++
		case "vlan":
			analysis.VLANChangeCount++
		case "bandwidth_profile":
			analysis.BandwidthProfileChangeCount++
		case "acl_policy_name":
			analysis.ACLPolicyChangeCount++
		case "portal_profile":
			analysis.PortalProfileChangeCount++
		case "session_timeout", "idle_timeout":
			analysis.SessionTimeoutChangeCount++
		}
	}
}

func optionalConflicts(conflicts []string, include bool) []string {
	if !include || len(conflicts) == 0 {
		return nil
	}
	return append([]string(nil), conflicts...)
}

func analyzeRuleImpact(rules []Rule, matchedCounts, impactCounts map[string]int, includeImpact bool) ([]RuleImpact, []RuleImpact) {
	seen := make(map[string]struct{})
	var shadowed []RuleImpact
	var ineffective []RuleImpact
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		item := RuleImpact{
			Name:         name,
			Priority:     rule.Priority,
			Enabled:      rule.Enabled,
			MatchedCount: matchedCounts[name],
			ImpactCount:  impactCounts[name],
		}
		switch {
		case !rule.Enabled:
			item.Reason = "rule disabled"
			shadowed = append(shadowed, item)
		case item.MatchedCount == 0:
			item.Reason = "no replay sample matched this rule"
			shadowed = append(shadowed, item)
		case includeImpact && item.ImpactCount == 0:
			item.Reason = "matched during replay but removing it did not alter final decisions"
			ineffective = append(ineffective, item)
		}
	}
	sortRuleImpacts(shadowed)
	sortRuleImpacts(ineffective)
	return shadowed, ineffective
}

func sortRuleImpacts(items []RuleImpact) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].MatchedCount == items[j].MatchedCount {
			if items[i].Priority == items[j].Priority {
				return items[i].Name < items[j].Name
			}
			return items[i].Priority > items[j].Priority
		}
		return items[i].MatchedCount < items[j].MatchedCount
	})
}

func classifySimulationRisk(analysis PolicySimulationAnalysis) (string, string) {
	if analysis.SampleCount == 0 {
		return "unknown", "No replay samples were available; run analysis with manual samples or retained policy evaluations before activation."
	}
	changePct := float64(analysis.DecisionChangeCount) / float64(analysis.SampleCount)
	switch {
	case analysis.DenyToAllowCount > 0 || analysis.ConflictCount > 0 || changePct >= 0.25:
		return "critical", "Review required before activation; candidate policy expands access, introduces conflicts, or changes at least 25% of replayed requests."
	case analysis.AllowToDenyCount > 0 || analysis.QuarantineChangeCount > 0 || changePct >= 0.10:
		return "high", "Approval should include business-owner review; candidate policy denies or quarantines previously accepted traffic or changes at least 10% of samples."
	case analysis.DecisionChangeCount > 0 || len(analysis.ShadowedRules) > 0 || len(analysis.IneffectiveRules) > 0:
		return "medium", "Candidate policy changes a bounded set of replayed requests or contains rules that need cleanup."
	default:
		return "low", "No decision changes were observed in replay samples; proceed through normal approval and external certification checks."
	}
}

func removeRuleByName(rules []Rule, name string) []Rule {
	out := make([]Rule, 0, len(rules))
	removed := false
	for _, rule := range rules {
		if !removed && strings.EqualFold(rule.Name, name) {
			removed = true
			continue
		}
		out = append(out, rule)
	}
	return out
}

func decisionFingerprint(decision Decision) string {
	data, _ := json.Marshal(struct {
		Allow            bool     `json:"allow"`
		Quarantine       bool     `json:"quarantine"`
		Role             string   `json:"role,omitempty"`
		FilterID         string   `json:"filter_id,omitempty"`
		PolicyTag        string   `json:"policy_tag,omitempty"`
		VLAN             int      `json:"vlan,omitempty"`
		BandwidthProfile string   `json:"bandwidth_profile,omitempty"`
		SessionTimeout   int      `json:"session_timeout,omitempty"`
		IdleTimeout      int      `json:"idle_timeout,omitempty"`
		PortalProfile    string   `json:"portal_profile,omitempty"`
		ACLPolicyName    string   `json:"acl_policy_name,omitempty"`
		DeviceGroup      string   `json:"device_group,omitempty"`
		Tenant           string   `json:"tenant,omitempty"`
		Notes            []string `json:"notes,omitempty"`
	}{
		Allow:            decision.Allow,
		Quarantine:       decision.Quarantine,
		Role:             stringPtrValue(decision.Role),
		FilterID:         stringPtrValue(decision.FilterID),
		PolicyTag:        stringPtrValue(decision.PolicyTag),
		VLAN:             intPtrValue(decision.VLAN),
		BandwidthProfile: stringPtrValue(decision.BandwidthProfile),
		SessionTimeout:   intPtrValue(decision.SessionTimeout),
		IdleTimeout:      intPtrValue(decision.IdleTimeout),
		PortalProfile:    stringPtrValue(decision.PortalProfile),
		ACLPolicyName:    stringPtrValue(decision.ACLPolicyName),
		DeviceGroup:      stringPtrValue(decision.DeviceGroup),
		Tenant:           stringPtrValue(decision.Tenant),
		Notes:            append([]string(nil), decision.Notes...),
	})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newSimulationAnalysisID(activeHash, candidateHash string, generatedAt time.Time, samples []ReplaySample) string {
	h := sha256.New()
	_, _ = h.Write([]byte(activeHash))
	_, _ = h.Write([]byte(candidateHash))
	_, _ = h.Write([]byte(generatedAt.Format(time.RFC3339Nano)))
	for _, sample := range samples {
		_, _ = h.Write([]byte(RequestHash(&sample.Request)))
		_, _ = h.Write([]byte(sample.Source))
		_, _ = h.Write([]byte(sample.EvaluationID))
	}
	return fmt.Sprintf("psa-%s", hex.EncodeToString(h.Sum(nil))[:24])
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func intPtrValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
