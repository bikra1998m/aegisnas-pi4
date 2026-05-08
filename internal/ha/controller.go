package ha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

type vipLease struct {
	HolderNode string `json:"holder_node"`
	HolderRole string `json:"holder_role"`
	VirtualIP  string `json:"virtual_ip"`
	Interface  string `json:"interface"`
	Priority   int    `json:"priority"`
	AcquiredAt string `json:"acquired_at"`
	RenewedAt  string `json:"renewed_at"`
	ExpiresAt  string `json:"expires_at"`
}

type vipTarget struct {
	Interface string
	Address   string
}

type controller struct {
	cfg                  *config.Config
	client               httpDoer
	logger               *zap.Logger
	now                  func() time.Time
	nodeName             string
	vipAssigned          bool
	lastHealthyAt        time.Time
	failureSince         time.Time
	peerRecoveredAt      time.Time
	lastPeerReachable    *bool
	lastEffectiveRole    string
	lastLeaseEventStatus string
	lastFencingStatus    string
	lastAnnouncementAt   string
	lastAnnouncementErr  string
	lastAnnouncementMode string
	ipRunner             func(args ...string) (string, error)
	arpingRunner         func(args ...string) (string, error)
}

var (
	controllerLoadSharedReplicationStatusFn               = LoadSharedReplicationStatus
	controllerFindStagedReplicationPackageByFingerprintFn = FindStagedReplicationPackageByContentFingerprint
	controllerStageLatestSharedReplicationPackageFn       = StageLatestSharedReplicationPackage
	controllerActivateStagedReplicationPackageFn          = ActivateStagedReplicationPackage
	controllerScheduleActivationRestartFn                 = ScheduleActivationRestart
)

func StartController(ctx context.Context, cfg *config.Config, client httpDoer, logger *zap.Logger) {
	ctrl := newController(cfg, client, logger)
	ctrl.run(ctx)
}

func newController(cfg *config.Config, client httpDoer, logger *zap.Logger) *controller {
	nodeName, _ := os.Hostname()
	if client == nil {
		client = &httpClientWithTimeout{timeout: 1500 * time.Millisecond}
	}
	return &controller{
		cfg:          cfg,
		client:       client,
		logger:       logger,
		now:          time.Now,
		nodeName:     strings.TrimSpace(nodeName),
		ipRunner:     defaultIPRunner,
		arpingRunner: defaultArpingRunner,
	}
}

func (c *controller) run(ctx context.Context) {
	c.tick()
	if c.cfg == nil || !c.cfg.HighAvailability.Enabled {
		return
	}

	interval := time.Duration(c.cfg.HighAvailability.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer c.releaseOnShutdown()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tick()
		}
	}
}

func (c *controller) tick() {
	status, message, details := ProbeStatus(c.cfg, c.client)
	if c.cfg == nil {
		c.publish(status, message, details)
		return
	}
	if !c.cfg.HighAvailability.Enabled || !highAvailabilityConfigured(c.cfg) {
		c.publish(status, message, details)
		return
	}
	now := c.now().UTC()
	peerReachable := boolDetail(details, "peer_reachable")
	if peerReachable {
		if c.lastPeerReachable == nil || !*c.lastPeerReachable {
			c.peerRecoveredAt = now
		}
		c.lastHealthyAt = now
		c.failureSince = time.Time{}
	} else if c.failureSince.IsZero() {
		c.failureSince = now
		c.peerRecoveredAt = time.Time{}
	}
	c.recordPeerHealthChange(peerReachable)

	target, targetErr := resolveVIPTarget(c.cfg)
	if targetErr != nil {
		details["virtual_ip_target_error"] = targetErr.Error()
		if c.cfg.HighAvailability.Enabled {
			status = "degraded"
			message = targetErr.Error()
		}
		c.publish(status, message, details)
		return
	}

	failoverActive := c.failoverActive(now, peerReachable)
	details["effective_role"] = strings.TrimSpace(c.cfg.HighAvailability.Role)
	if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") && c.vipAssigned {
		details["effective_role"] = "active"
	}
	details["failover_active"] = failoverActive
	details["auto_activate_enabled"] = c.cfg.HighAvailability.AutoActivateOnFailover
	details["peer_last_healthy_at"] = formatTime(c.lastHealthyAt)
	details["peer_failure_since"] = formatTime(c.failureSince)
	details["peer_recovered_at"] = formatTime(c.peerRecoveredAt)
	details["vip_interface"] = target.Interface
	details["vip_address"] = target.Address
	details["preempt_holdoff_seconds"] = c.cfg.HighAvailability.PreemptHoldoffSeconds
	c.appendAnnouncementDetails(details)
	if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") && c.cfg.HighAvailability.Preempt {
		remaining := c.preemptHoldoffRemaining(now, peerReachable)
		if remaining > 0 {
			details["preempt_status"] = "holding"
			details["preempt_holdoff_remaining_seconds"] = int((remaining + time.Second - 1) / time.Second)
			if !c.peerRecoveredAt.IsZero() {
				details["preempt_ready_at"] = c.peerRecoveredAt.Add(time.Duration(c.cfg.HighAvailability.PreemptHoldoffSeconds) * time.Second).Format(time.RFC3339)
			}
		} else {
			details["preempt_status"] = "eligible"
			details["preempt_holdoff_remaining_seconds"] = 0
		}
	} else if !c.cfg.HighAvailability.Preempt {
		details["preempt_status"] = "disabled"
	} else {
		details["preempt_status"] = "not_applicable"
	}

	fencing := c.evaluateFencing(now, peerReachable, failoverActive, details)
	c.recordFencingChange(fencing, details)
	if fencing.Enabled && (fencing.LocalWriteError != nil || fencing.PeerLoadError != nil || !fencing.PeerPresent || fencing.PeerAgeErr != nil) {
		status = "degraded"
		message = fencing.Summary
	}

	lease, leaseErr := loadLease(c.cfg)
	if leaseErr != nil {
		details["lease_error"] = leaseErr.Error()
		status = "degraded"
		message = "High availability shared lease state could not be read."
		c.publish(status, message, details)
		return
	}

	shouldHold := c.shouldHoldVIP(peerReachable, failoverActive)
	leaseAction := "idle"
	if shouldHold && strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") && !fencing.AllowPromotion {
		shouldHold = false
		leaseAction = "blocked_by_fencing"
		status = "degraded"
		message = "Standby failover is paused until peer shared-state heartbeat is stale."
		if strings.TrimSpace(fencing.Summary) != "" {
			message = fencing.Summary
		}
	}

	if shouldHold {
		activationScheduled, err := c.ensureStandbyActivationForFailover(details, now)
		if err != nil {
			details["auto_activate_status"] = "failed"
			details["auto_activate_error"] = err.Error()
			status = "degraded"
			message = "Standby failover could not activate the latest shared replication package."
			c.publish(status, message, details)
			return
		}
		if activationScheduled {
			status = "pending"
			message = "Standby activated the latest shared replication package and queued a service restart before VIP takeover."
			c.publish(status, message, details)
			return
		}

		acquired, action, updatedLease, err := c.ensureLease(lease, target, now, peerReachable)
		leaseAction = action
		if err != nil {
			details["lease_error"] = err.Error()
			status = "degraded"
			message = "High availability lease ownership could not be updated."
			c.publish(status, message, details)
			return
		}
		lease = updatedLease
		if acquired {
			if err := c.assignVIP(target); err != nil {
				details["vip_error"] = err.Error()
				status = "degraded"
				message = "Virtual IP takeover failed."
				c.publish(status, message, details)
				return
			}
			if err := c.refreshVIPAnnouncement(target, details); err != nil {
				if status == "ok" {
					status = "degraded"
				}
				message = "Virtual IP takeover succeeded, but announcement refresh failed."
			}
			if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") {
				details["effective_role"] = "active"
				if status == "ok" {
					message = "Standby node is serving the virtual IP after peer timeout."
				}
			}
			c.recordLeaseAction(action, target, details)
		} else {
			if err := c.withdrawVIP(target); err != nil && c.logger != nil {
				c.logger.Warn("failed to withdraw virtual IP while lease is owned elsewhere", zap.Error(err))
			}
			c.vipAssigned = false
			c.recordLeaseAction(action, target, details)
			if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") && !c.cfg.HighAvailability.Preempt {
				message = "Peer currently owns the virtual IP lease; local active node is waiting because preempt is disabled."
				status = "degraded"
			} else if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") {
				if remaining := c.preemptHoldoffRemaining(now, peerReachable); remaining > 0 {
					message = fmt.Sprintf("Peer currently owns the virtual IP lease; local active node is waiting %ds for preempt holdoff to expire.", int((remaining+time.Second-1)/time.Second))
					status = "degraded"
				}
			}
		}
	} else {
		if leaseAction == "idle" {
			leaseAction = "release"
		}
		if err := c.releaseLeaseIfOwned(lease); err != nil && c.logger != nil {
			c.logger.Warn("failed to release HA lease", zap.Error(err))
		}
		if err := c.withdrawVIP(target); err != nil && c.logger != nil {
			c.logger.Warn("failed to withdraw virtual IP", zap.Error(err))
		}
		c.vipAssigned = false
		details["effective_role"] = strings.TrimSpace(c.cfg.HighAvailability.Role)
		c.recordLeaseAction(leaseAction, target, details)
		if !peerReachable && c.cfg.HighAvailability.Enabled && leaseAction != "blocked_by_fencing" {
			status = "degraded"
			message = "Peer health probe failed, but failover timeout has not expired yet."
		}
	}

	if lease.HolderNode != "" {
		details["lease_holder"] = lease.HolderNode
		details["lease_holder_role"] = lease.HolderRole
		details["lease_expires_at"] = lease.ExpiresAt
		details["lease_priority"] = lease.Priority
	}
	details["lease_action"] = leaseAction
	details["vip_assigned"] = c.vipAssigned
	if c.cfg.HighAvailability.SplitBrainProtectionEnabled {
		finalHeartbeat := localHeartbeatState(c, now)
		if err := saveSharedHeartbeat(c.cfg, finalHeartbeat); err != nil {
			details["shared_heartbeat_error"] = err.Error()
			if status == "ok" {
				status = "degraded"
				message = "High availability heartbeat could not be refreshed after the latest state change."
			}
		} else {
			details["shared_heartbeat_published_at"] = finalHeartbeat.PublishedAt
		}
	}
	c.recordEffectiveRoleChange(fmt.Sprint(details["effective_role"]), details)

	c.publish(status, message, details)
}

func (c *controller) ensureStandbyActivationForFailover(details map[string]any, observedAt time.Time) (bool, error) {
	if details == nil {
		details = map[string]any{}
	}
	if !c.cfg.HighAvailability.AutoActivateOnFailover {
		details["auto_activate_status"] = "disabled"
		return false, nil
	}
	if !strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") {
		details["auto_activate_status"] = "not_applicable"
		return false, nil
	}

	shared, err := controllerLoadSharedReplicationStatusFn(c.cfg)
	if err != nil {
		return false, fmt.Errorf("load shared replication package: %w", err)
	}
	if !shared.Present {
		return false, errors.New("no shared HA replication package has been published yet")
	}
	mergeSharedReplicationDetails(details, shared, c.cfg, observedAt.UTC())
	if stale, _ := details["stale"].(bool); stale {
		details["auto_activate_status"] = "waiting_fresh"
		return false, errors.New("shared HA replication package is stale")
	}

	fingerprint := strings.TrimSpace(shared.ContentFingerprint)
	if fingerprint == "" {
		fingerprint = strings.TrimSpace(shared.PackageChecksum)
	}
	stage, found, err := controllerFindStagedReplicationPackageByFingerprintFn(c.cfg, fingerprint)
	if err != nil {
		return false, fmt.Errorf("check staged package fingerprint: %w", err)
	}
	if !found {
		stage, err = controllerStageLatestSharedReplicationPackageFn(c.cfg, "ha-auto-activate")
		if err != nil {
			return false, fmt.Errorf("stage latest shared package: %w", err)
		}
	}

	details["auto_activate_stage_id"] = stage.ID
	details["auto_activate_imported_source"] = stage.ImportedSource
	details["auto_activate_content_fingerprint"] = stage.ContentFingerprint
	if strings.TrimSpace(stage.ActivatedAt) != "" {
		details["auto_activate_status"] = "activated"
		details["auto_activate_activated_at"] = stage.ActivatedAt
		return false, nil
	}

	result, err := controllerActivateStagedReplicationPackageFn(c.cfg, stage.ID, "ha-auto-activate")
	if err != nil {
		return false, fmt.Errorf("activate staged package: %w", err)
	}
	if err := controllerScheduleActivationRestartFn(c.cfg, result, "ha-auto-activate"); err != nil {
		return false, fmt.Errorf("schedule activation restart: %w", err)
	}
	details["auto_activate_status"] = "restart_scheduled"
	details["auto_activate_restart_services"] = result.RestartServices
	return true, nil
}

func (c *controller) publish(status, message string, details map[string]any) {
	if err := db.UpsertRuntimeStatus(RuntimeComponent, status, message, details); err != nil && c.logger != nil {
		c.logger.Warn("failed to update high availability runtime status", zap.Error(err))
	}
}

func (c *controller) recordPeerHealthChange(peerReachable bool) {
	if c.lastPeerReachable == nil {
		if peerReachable {
			value := peerReachable
			c.lastPeerReachable = &value
			return
		}
	} else if *c.lastPeerReachable == peerReachable {
		return
	}
	status := "failed"
	summary := "Peer health probe failed."
	if peerReachable {
		status = "recovered"
		summary = "Peer health probe recovered."
	}
	_ = db.RecordHAHistory("peer_health", status, summary, strings.TrimSpace(c.cfg.HighAvailability.Role), "", map[string]any{
		"peer_api_url": strings.TrimSpace(c.cfg.HighAvailability.PeerAPIURL),
		"virtual_ip":   strings.TrimSpace(c.cfg.HighAvailability.VirtualIP),
	})
	value := peerReachable
	c.lastPeerReachable = &value
}

func (c *controller) recordLeaseAction(action string, target vipTarget, details map[string]any) {
	switch action {
	case "acquired", "preempted", "release", "released":
	default:
		return
	}
	status := action
	if action == "release" {
		status = "released"
	}
	if c.lastLeaseEventStatus == status {
		return
	}
	summary := "HA VIP lease updated."
	switch status {
	case "acquired":
		summary = "Local node acquired the HA VIP lease."
	case "preempted":
		summary = "Local node preempted the HA VIP lease."
	case "released":
		summary = "Local node released the HA VIP lease."
	}
	_ = db.RecordHAHistory("vip_lease", status, summary, strings.TrimSpace(c.cfg.HighAvailability.Role), "", map[string]any{
		"interface": target.Interface,
		"vip":       target.Address,
		"details":   details,
	})
	c.lastLeaseEventStatus = status
}

func (c *controller) recordEffectiveRoleChange(role string, details map[string]any) {
	role = strings.TrimSpace(role)
	if role == "" {
		return
	}
	if c.lastEffectiveRole == role {
		return
	}
	if c.lastEffectiveRole != "" {
		switch {
		case c.lastEffectiveRole == "standby" && role == "active":
			_ = db.RecordHAHistory("failover", "promoted", "Standby node promoted after peer failure.", strings.TrimSpace(c.cfg.HighAvailability.Role), "", details)
		case c.lastEffectiveRole == "active" && role == "standby":
			_ = db.RecordHAHistory("failover", "returned", "Node returned to standby role after peer recovery.", strings.TrimSpace(c.cfg.HighAvailability.Role), "", details)
		}
	}
	c.lastEffectiveRole = role
}

func (c *controller) recordFencingChange(result fencingResult, details map[string]any) {
	status := strings.TrimSpace(result.Status)
	if status == "" || c.lastFencingStatus == status {
		return
	}
	role := strings.TrimSpace(c.cfg.HighAvailability.Role)
	summary := strings.TrimSpace(result.Summary)
	if summary == "" {
		summary = "HA split-brain protection state changed."
	}
	_ = db.RecordHAHistory("fencing", status, summary, role, "", details)
	c.lastFencingStatus = status
}

func (c *controller) appendAnnouncementDetails(details map[string]any) {
	if details == nil {
		return
	}
	if strings.TrimSpace(c.lastAnnouncementMode) != "" {
		details["vip_announcement_status"] = c.lastAnnouncementMode
	}
	if strings.TrimSpace(c.lastAnnouncementAt) != "" {
		details["vip_announcement_at"] = c.lastAnnouncementAt
	}
	if strings.TrimSpace(c.lastAnnouncementErr) != "" {
		details["vip_announcement_error"] = c.lastAnnouncementErr
	}
}

func (c *controller) failoverActive(now time.Time, peerReachable bool) bool {
	if peerReachable {
		return false
	}
	if c.failureSince.IsZero() {
		return false
	}
	timeout := time.Duration(c.cfg.HighAvailability.FailoverTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return now.Sub(c.failureSince) >= timeout
}

func (c *controller) shouldHoldVIP(peerReachable, failoverActive bool) bool {
	role := strings.ToLower(strings.TrimSpace(c.cfg.HighAvailability.Role))
	switch role {
	case "active":
		return true
	case "standby":
		return !peerReachable && failoverActive
	default:
		return false
	}
}

func (c *controller) ensureLease(current vipLease, target vipTarget, now time.Time, peerReachable bool) (bool, string, vipLease, error) {
	priority := c.desiredPriority()
	if current.HolderNode == c.nodeName {
		current.HolderRole = strings.TrimSpace(c.cfg.HighAvailability.Role)
		current.VirtualIP = strings.TrimSpace(c.cfg.HighAvailability.VirtualIP)
		current.Interface = target.Interface
		current.Priority = priority
		current.RenewedAt = now.Format(time.RFC3339)
		current.ExpiresAt = now.Add(time.Duration(c.cfg.HighAvailability.FailoverTimeoutSeconds) * time.Second).Format(time.RFC3339)
		if current.AcquiredAt == "" {
			current.AcquiredAt = current.RenewedAt
		}
		return true, "renewed", current, saveLease(c.cfg, current)
	}

	expired := leaseExpired(current, now)
	if current.HolderNode == "" || expired {
		next := newLease(c, target, now, priority)
		return true, "acquired", next, saveLease(c.cfg, next)
	}

	if c.shouldPreempt(current, priority, peerReachable, now) {
		next := newLease(c, target, now, priority)
		return true, "preempted", next, saveLease(c.cfg, next)
	}

	return false, "blocked", current, nil
}

func (c *controller) shouldPreempt(current vipLease, priority int, peerReachable bool, now time.Time) bool {
	if current.HolderNode == "" {
		return true
	}
	if priority <= current.Priority {
		return false
	}
	if !c.cfg.HighAvailability.Preempt {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(c.cfg.HighAvailability.Role))
	if role == "standby" && peerReachable {
		return false
	}
	if role == "active" && c.preemptHoldoffRemaining(now, peerReachable) > 0 {
		return false
	}
	return true
}

func (c *controller) preemptHoldoffRemaining(now time.Time, peerReachable bool) time.Duration {
	if c == nil || c.cfg == nil {
		return 0
	}
	if !c.cfg.HighAvailability.Preempt || !strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") || !peerReachable {
		return 0
	}
	holdoff := time.Duration(c.cfg.HighAvailability.PreemptHoldoffSeconds) * time.Second
	if holdoff <= 0 {
		return 0
	}
	if c.peerRecoveredAt.IsZero() {
		return holdoff
	}
	remaining := holdoff - now.Sub(c.peerRecoveredAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (c *controller) desiredPriority() int {
	if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") {
		return 100
	}
	return 50
}

func (c *controller) assignVIP(target vipTarget) error {
	if err := c.runIP("addr", "replace", target.Address, "dev", target.Interface); err != nil {
		return err
	}
	c.vipAssigned = true
	return nil
}

func (c *controller) refreshVIPAnnouncement(target vipTarget, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	ipOnly := vipAddressOnly(target.Address)
	attempts := []struct {
		name string
		args []string
	}{
		{name: "reply", args: []string{"-q", "-A", "-c", "2", "-I", target.Interface, ipOnly}},
		{name: "request", args: []string{"-q", "-U", "-c", "2", "-I", target.Interface, ipOnly}},
	}
	details["vip_announcement_attempts"] = len(attempts)
	details["vip_announcement_target"] = ipOnly

	var failures []string
	for _, attempt := range attempts {
		output, err := c.runArping(attempt.args...)
		if err != nil {
			if strings.TrimSpace(output) != "" {
				failures = append(failures, fmt.Sprintf("%s: %s (%v)", attempt.name, output, err))
			} else {
				failures = append(failures, fmt.Sprintf("%s: %v", attempt.name, err))
			}
		}
	}

	c.lastAnnouncementAt = c.now().UTC().Format(time.RFC3339)
	if len(failures) == 0 {
		c.lastAnnouncementMode = "sent"
		c.lastAnnouncementErr = ""
		details["vip_announcement_status"] = "sent"
		details["vip_announcement_at"] = c.lastAnnouncementAt
		_ = db.RecordHAHistory("vip_announcement", "sent", "Sent gratuitous ARP refresh for the HA virtual IP.", strings.TrimSpace(c.cfg.HighAvailability.Role), "", map[string]any{
			"interface": target.Interface,
			"vip":       target.Address,
			"target_ip": ipOnly,
			"attempts":  len(attempts),
		})
		return nil
	}

	joined := strings.Join(failures, "; ")
	c.lastAnnouncementMode = "failed"
	c.lastAnnouncementErr = joined
	details["vip_announcement_status"] = "failed"
	details["vip_announcement_at"] = c.lastAnnouncementAt
	details["vip_announcement_error"] = joined
	_ = db.RecordHAHistory("vip_announcement", "failed", "HA VIP was assigned, but gratuitous ARP refresh failed.", strings.TrimSpace(c.cfg.HighAvailability.Role), "", map[string]any{
		"interface": target.Interface,
		"vip":       target.Address,
		"target_ip": ipOnly,
		"attempts":  len(attempts),
		"errors":    failures,
	})
	return fmt.Errorf("%s", joined)
}

func (c *controller) withdrawVIP(target vipTarget) error {
	if err := c.runIP("addr", "del", target.Address, "dev", target.Interface); err != nil {
		if isIgnorableVIPDeleteError(err) {
			return nil
		}
		return err
	}
	return nil
}

func (c *controller) releaseLeaseIfOwned(current vipLease) error {
	if current.HolderNode == "" || current.HolderNode != c.nodeName {
		return nil
	}
	return clearLease(c.cfg)
}

func (c *controller) releaseOnShutdown() {
	if c.cfg == nil || !c.cfg.HighAvailability.Enabled {
		return
	}
	target, err := resolveVIPTarget(c.cfg)
	if err == nil {
		_ = c.withdrawVIP(target)
	}
	lease, err := loadLease(c.cfg)
	if err == nil {
		_ = c.releaseLeaseIfOwned(lease)
	}
}

func (c *controller) runIP(args ...string) error {
	output, err := c.ipRunner(args...)
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return err
	}
	return fmt.Errorf("%w\nOutput: %s", err, trimmed)
}

func defaultIPRunner(args ...string) (string, error) {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func defaultArpingRunner(args ...string) (string, error) {
	cmd := exec.Command("arping", args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func (c *controller) runArping(args ...string) (string, error) {
	if c.arpingRunner == nil {
		return "", fmt.Errorf("arping runner is unavailable")
	}
	return c.arpingRunner(args...)
}

func vipAddressOnly(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(address); err == nil && ip != nil {
		return ip.String()
	}
	return address
}

func resolveVIPTarget(cfg *config.Config) (vipTarget, error) {
	vip := net.ParseIP(strings.TrimSpace(cfg.HighAvailability.VirtualIP))
	if vip == nil {
		return vipTarget{}, fmt.Errorf("high availability virtual IP is invalid")
	}
	type candidate struct {
		name    string
		address string
	}
	candidates := []candidate{}
	if strings.TrimSpace(cfg.WAN.Name) != "" && strings.TrimSpace(cfg.WAN.Address) != "" {
		candidates = append(candidates, candidate{name: strings.TrimSpace(cfg.WAN.Name), address: strings.TrimSpace(cfg.WAN.Address)})
	}
	if strings.TrimSpace(cfg.LAN.Name) != "" && strings.TrimSpace(cfg.LAN.Address) != "" {
		candidates = append(candidates, candidate{name: strings.TrimSpace(cfg.LAN.Name), address: strings.TrimSpace(cfg.LAN.Address)})
	}
	for _, iface := range cfg.Network.Interfaces {
		if !iface.Enabled || strings.TrimSpace(iface.Name) == "" || strings.TrimSpace(iface.Address) == "" {
			continue
		}
		candidates = append(candidates, candidate{name: strings.TrimSpace(iface.Name), address: strings.TrimSpace(iface.Address)})
	}
	for _, item := range candidates {
		_, subnet, err := net.ParseCIDR(item.address)
		if err != nil || subnet == nil {
			continue
		}
		if subnet.Contains(vip) {
			ones, _ := subnet.Mask.Size()
			return vipTarget{Interface: item.name, Address: fmt.Sprintf("%s/%d", vip.String(), ones)}, nil
		}
	}
	if strings.TrimSpace(cfg.LAN.Name) != "" && strings.TrimSpace(cfg.LAN.Address) != "" {
		if _, subnet, err := net.ParseCIDR(strings.TrimSpace(cfg.LAN.Address)); err == nil && subnet != nil {
			ones, _ := subnet.Mask.Size()
			return vipTarget{Interface: strings.TrimSpace(cfg.LAN.Name), Address: fmt.Sprintf("%s/%d", vip.String(), ones)}, nil
		}
	}
	if len(candidates) > 0 {
		if _, subnet, err := net.ParseCIDR(candidates[0].address); err == nil && subnet != nil {
			ones, _ := subnet.Mask.Size()
			return vipTarget{Interface: candidates[0].name, Address: fmt.Sprintf("%s/%d", vip.String(), ones)}, nil
		}
	}
	return vipTarget{}, fmt.Errorf("could not resolve a network interface for virtual IP %s", vip.String())
}

func leasePath(cfg *config.Config) string {
	root := strings.TrimSpace(cfg.HighAvailability.SharedStateDir)
	if root == "" {
		root = "/var/lib/aegisnas/ha"
	}
	return filepath.Join(root, "vip-lease.json")
}

func loadLease(cfg *config.Config) (vipLease, error) {
	var lease vipLease
	data, err := os.ReadFile(leasePath(cfg))
	if err != nil {
		if os.IsNotExist(err) {
			return lease, nil
		}
		return lease, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return lease, nil
	}
	if err := json.Unmarshal(data, &lease); err != nil {
		return lease, err
	}
	return lease, nil
}

func saveLease(cfg *config.Config, lease vipLease) error {
	path := leasePath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(lease, "", "  ")
	if err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0644); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func clearLease(cfg *config.Config) error {
	err := os.Remove(leasePath(cfg))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func newLease(c *controller, target vipTarget, now time.Time, priority int) vipLease {
	ts := now.Format(time.RFC3339)
	return vipLease{
		HolderNode: c.nodeName,
		HolderRole: strings.TrimSpace(c.cfg.HighAvailability.Role),
		VirtualIP:  strings.TrimSpace(c.cfg.HighAvailability.VirtualIP),
		Interface:  target.Interface,
		Priority:   priority,
		AcquiredAt: ts,
		RenewedAt:  ts,
		ExpiresAt:  now.Add(time.Duration(c.cfg.HighAvailability.FailoverTimeoutSeconds) * time.Second).Format(time.RFC3339),
	}
}

func leaseExpired(lease vipLease, now time.Time) bool {
	if lease.HolderNode == "" {
		return true
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(lease.ExpiresAt))
	if err != nil {
		return true
	}
	return !now.Before(expiresAt)
}

func isIgnorableVIPDeleteError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "cannot assign requested address") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "not found")
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func boolDetail(details map[string]any, key string) bool {
	if details == nil {
		return false
	}
	value, ok := details[key]
	if !ok {
		return false
	}
	flag, _ := value.(bool)
	return flag
}

type httpClientWithTimeout struct {
	timeout time.Duration
}

func (h *httpClientWithTimeout) Do(req *http.Request) (*http.Response, error) {
	client := &http.Client{Timeout: h.timeout}
	return client.Do(req)
}
