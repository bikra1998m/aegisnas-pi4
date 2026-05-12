package ha

import (
	"context"
	"crypto/hmac"
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
}

var (
	errWitnessTokenMissing      = errors.New("ha witness bearer token env is configured but not loaded")
	errWitnessSigningKeyMissing = errors.New("ha witness signing key env is configured but not loaded")
	errWitnessSignatureMissing  = errors.New("ha witness response signature is missing")
	errWitnessSignatureInvalid  = errors.New("ha witness response signature is invalid")
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
	details["witness_url"] = strings.TrimSpace(c.cfg.HighAvailability.WitnessAPIURL)
	details["witness_max_age_seconds"] = c.cfg.HighAvailability.WitnessMaxAgeSeconds
	details["witness_required_node"] = strings.TrimSpace(c.cfg.HighAvailability.WitnessRequiredNode)
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
	if !result.Enabled {
		if strings.TrimSpace(c.cfg.HighAvailability.WitnessAPIURL) != "" {
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

	witnessURL := strings.TrimSpace(c.cfg.HighAvailability.WitnessAPIURL)
	if witnessURL == "" {
		result.WitnessStatus = "disabled"
	} else if !standbyPromotionWindow {
		result.WitnessStatus = "idle"
		result.WitnessSummary = "External HA witness is configured and will be consulted during standby promotion."
	} else {
		decision, err := controllerProbeWitnessDecisionFn(c.cfg, c.client)
		if err != nil {
			result.WitnessStatus = "failed"
			result.WitnessSummary = "External HA witness could not be read during standby promotion."
			result.WitnessError = err
			result.AllowPromotion = false
		} else {
			result.WitnessStatus = "ok"
			result.WitnessAllowed = decision.AllowPromotion
			result.WitnessSummary = strings.TrimSpace(decision.Summary)
			result.WitnessObserved = strings.TrimSpace(decision.ObservedAt)
			result.WitnessNode = strings.TrimSpace(decision.WitnessNode)
			if result.WitnessObserved != "" {
				result.WitnessObservedAge, result.WitnessObservedErr = witnessObservedAge(result.WitnessObserved, observedAt)
			}
			if result.WitnessSummary == "" {
				if decision.AllowPromotion {
					result.WitnessSummary = "External HA witness allows standby promotion."
				} else {
					result.WitnessSummary = "External HA witness denied standby promotion."
				}
			}
			requiredNode := strings.TrimSpace(c.cfg.HighAvailability.WitnessRequiredNode)
			maxWitnessAge := time.Duration(c.cfg.HighAvailability.WitnessMaxAgeSeconds) * time.Second
			switch {
			case !decision.AllowPromotion:
				result.WitnessStatus = "blocked"
				result.AllowPromotion = false
			case requiredNode != "" && !strings.EqualFold(result.WitnessNode, requiredNode):
				result.WitnessStatus = "unexpected_node"
				result.WitnessSummary = fmt.Sprintf("External HA witness %q does not match required witness node %q.", result.WitnessNode, requiredNode)
				result.WitnessAllowed = false
				result.AllowPromotion = false
			case maxWitnessAge > 0 && result.WitnessObserved == "":
				result.WitnessStatus = "stale"
				result.WitnessSummary = "External HA witness did not include observed_at required by local freshness policy."
				result.WitnessAllowed = false
				result.AllowPromotion = false
			case result.WitnessObservedErr != nil:
				result.WitnessStatus = "invalid"
				result.WitnessSummary = "External HA witness observed_at timestamp is invalid."
				result.WitnessError = result.WitnessObservedErr
				result.WitnessAllowed = false
				result.AllowPromotion = false
			case maxWitnessAge > 0 && result.WitnessObservedAge > maxWitnessAge:
				result.WitnessStatus = "stale"
				result.WitnessSummary = fmt.Sprintf("External HA witness response is stale at %ds and exceeds the %ds freshness policy.", int(result.WitnessObservedAge.Seconds()), c.cfg.HighAvailability.WitnessMaxAgeSeconds)
				result.WitnessAllowed = false
				result.AllowPromotion = false
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
	if result.WitnessStatus == "ok" || result.WitnessStatus == "blocked" {
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
			}
		}
	} else if strings.TrimSpace(c.cfg.HighAvailability.WitnessSigningKeyEnv) != "" {
		details["witness_signature_status"] = "verified"
	}

	if standbyPromotionWindow {
		switch {
		case result.WitnessError != nil:
			result.Status = "witness_failed"
			result.Summary = result.WitnessSummary
		case witnessURL != "" && !result.WitnessAllowed:
			result.Status = "witness_blocked"
			result.Summary = result.WitnessSummary
		case witnessURL != "" && result.AllowPromotion:
			result.Status = "witness_allowed"
			result.Summary = "Peer shared HA heartbeat is stale and the external HA witness allows standby promotion."
		}
	}

	details["fencing_status"] = result.Status
	details["fencing_summary"] = result.Summary
	details["fencing_promotion_allowed"] = result.AllowPromotion
	return result
}

func probeWitnessDecision(cfg *config.Config, client httpDoer) (witnessDecision, error) {
	var decision witnessDecision
	if cfg == nil {
		return decision, fmt.Errorf("ha witness probe requires a config")
	}
	url := strings.TrimSpace(cfg.HighAvailability.WitnessAPIURL)
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
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return decision, fmt.Errorf("construct witness request: %w", err)
	}
	if token := witnessBearerToken(cfg); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	return decision, nil
}
