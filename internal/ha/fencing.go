package ha

import (
	"encoding/json"
	"fmt"
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
	Enabled         bool
	Status          string
	Summary         string
	AllowPromotion  bool
	LocalWriteError error
	PeerLoadError   error
	PeerPresent     bool
	PeerAge         time.Duration
	PeerAgeErr      error
	PeerStale       bool
	PeerHeartbeat   sharedHeartbeat
	LocalHeartbeat  sharedHeartbeat
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
	if !result.Enabled {
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

	details["fencing_status"] = result.Status
	details["fencing_summary"] = result.Summary
	details["fencing_promotion_allowed"] = result.AllowPromotion
	return result
}
