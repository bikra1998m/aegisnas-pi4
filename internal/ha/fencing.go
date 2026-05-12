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
	AllowPromotion bool   `json:"allow_promotion"`
	Summary        string `json:"summary,omitempty"`
	ObservedAt     string `json:"observed_at,omitempty"`
	WitnessNode    string `json:"witness_node,omitempty"`
	Challenge      string `json:"challenge,omitempty"`
}

type witnessEvaluation struct {
	URL            string
	Status         string
	Summary        string
	Allowed        bool
	Decision       witnessDecision
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

func verifyWitnessSignature(cfg *config.Config, headers http.Header, body []byte) error {
	if cfg == nil || strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv) == "" {
		return nil
	}
	key := witnessSigningKey(cfg)
	if key == "" {
		return fmt.Errorf("%w %q", errWitnessSigningKeyMissing, strings.TrimSpace(cfg.HighAvailability.WitnessSigningKeyEnv))
	}
	signature := normalizeWitnessSignature(headers.Get("X-AegisNAS-Witness-Signature"))
	if signature == "" {
		return errWitnessSignatureMissing
	}
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: decode hex: %v", errWitnessSignatureInvalid, err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := mac.Write(body); err != nil {
		return fmt.Errorf("sign witness response: %w", err)
	}
	if !hmac.Equal(decodedSignature, mac.Sum(nil)) {
		return errWitnessSignatureInvalid
	}
	return nil
}

func replayProtectionEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.HighAvailability.WitnessReplayProtectionEnabled
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

func newWitnessChallenge() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate witness challenge: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func evaluateWitnessDecisionPolicy(cfg *config.Config, observedAt time.Time, decision witnessDecision) witnessEvaluation {
	evaluation := witnessEvaluation{
		Status:   "ok",
		Summary:  strings.TrimSpace(decision.Summary),
		Allowed:  decision.AllowPromotion,
		Decision: decision,
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
	requiredNode := strings.TrimSpace(cfg.HighAvailability.WitnessRequiredNode)
	maxWitnessAge := time.Duration(cfg.HighAvailability.WitnessMaxAgeSeconds) * time.Second
	switch {
	case !decision.AllowPromotion:
		evaluation.Status = "blocked"
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
		evaluation.Summary = fmt.Sprintf("External HA witness response is stale at %ds and exceeds the %ds freshness policy.", int(evaluation.ObservedAge.Seconds()), cfg.HighAvailability.WitnessMaxAgeSeconds)
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
	details["witness_url"] = strings.TrimSpace(c.cfg.HighAvailability.WitnessAPIURL)
	details["witness_urls"] = witnessURLs
	details["witness_quorum_required"] = effectiveWitnessQuorum(c.cfg, len(witnessURLs))
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
	} else {
		details["witness_signature_status"] = "disabled"
	}
	if replayProtectionEnabled(c.cfg) {
		details["witness_replay_status"] = "configured"
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
		allowCount := 0
		witnessResults := make([]map[string]any, 0, len(witnessURLs))
		var firstFailure error
		var firstFailureSummary string
		for _, witnessURL := range witnessURLs {
			evaluation := witnessEvaluation{URL: witnessURL}
			decision, err := controllerProbeWitnessDecisionFn(c.cfg, c.client, witnessURL)
			if err != nil {
				evaluation.Status = "failed"
				evaluation.Summary = "External HA witness could not be read during standby promotion."
				evaluation.Err = err
			} else {
				evaluation = evaluateWitnessDecisionPolicy(c.cfg, observedAt, decision)
				evaluation.URL = witnessURL
			}
			if evaluation.Allowed {
				allowCount++
			} else if firstFailure == nil && evaluation.Err != nil {
				firstFailure = evaluation.Err
				firstFailureSummary = evaluation.Summary
			} else if firstFailureSummary == "" {
				firstFailureSummary = evaluation.Summary
			}
			entry := map[string]any{
				"url":             evaluation.URL,
				"status":          evaluation.Status,
				"summary":         evaluation.Summary,
				"allow_promotion": evaluation.Allowed,
				"witness_node":    strings.TrimSpace(evaluation.Decision.WitnessNode),
				"observed_at":     strings.TrimSpace(evaluation.Decision.ObservedAt),
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
		if allowCount >= quorum {
			result.WitnessAllowed = true
			result.AllowPromotion = result.AllowPromotion && true
			if len(witnessURLs) == 1 {
				result.WitnessStatus = "ok"
				result.WitnessSummary = witnessResults[0]["summary"].(string)
			} else {
				result.WitnessStatus = "quorum_met"
				result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion; quorum %d satisfied.", allowCount, len(witnessURLs), quorum)
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
				result.WitnessStatus = "quorum_unmet"
				if firstFailureSummary != "" {
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion; quorum %d required. First blocking result: %s", allowCount, len(witnessURLs), quorum, firstFailureSummary)
				} else {
					result.WitnessSummary = fmt.Sprintf("%d of %d external HA witnesses allow standby promotion; quorum %d required.", allowCount, len(witnessURLs), quorum)
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
	if result.WitnessStatus == "ok" || result.WitnessStatus == "blocked" || result.WitnessStatus == "quorum_met" || result.WitnessStatus == "quorum_unmet" {
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
			details["witness_signature_status"] = "verified"
		}
		if replayProtectionEnabled(c.cfg) {
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
	if replayProtectionEnabled(cfg) {
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
	if err := verifyWitnessSignature(cfg, resp.Header, body); err != nil {
		return decision, err
	}
	if err := json.Unmarshal(body, &decision); err != nil {
		return decision, fmt.Errorf("decode witness response: %w", err)
	}
	if challenge != "" {
		switch {
		case strings.TrimSpace(decision.Challenge) == "":
			return decision, errWitnessChallengeMissing
		case strings.TrimSpace(decision.Challenge) != challenge:
			return decision, errWitnessChallengeMismatch
		}
	}
	return decision, nil
}
