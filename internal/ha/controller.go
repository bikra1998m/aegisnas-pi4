package ha

import (
	"context"
	"encoding/json"
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
	cfg           *config.Config
	client        httpDoer
	logger        *zap.Logger
	now           func() time.Time
	nodeName      string
	vipAssigned   bool
	lastHealthyAt time.Time
	failureSince  time.Time
	ipRunner      func(args ...string) (string, error)
}

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
		cfg:      cfg,
		client:   client,
		logger:   logger,
		now:      time.Now,
		nodeName: strings.TrimSpace(nodeName),
		ipRunner: defaultIPRunner,
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
		c.lastHealthyAt = now
		c.failureSince = time.Time{}
	} else if c.failureSince.IsZero() {
		c.failureSince = now
	}

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
	details["failover_active"] = failoverActive
	details["peer_last_healthy_at"] = formatTime(c.lastHealthyAt)
	details["peer_failure_since"] = formatTime(c.failureSince)
	details["vip_interface"] = target.Interface
	details["vip_address"] = target.Address

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

	if shouldHold {
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
			if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "standby") {
				details["effective_role"] = "active"
				message = "Standby node is serving the virtual IP after peer timeout."
				status = "ok"
			}
		} else {
			if err := c.withdrawVIP(target); err != nil && c.logger != nil {
				c.logger.Warn("failed to withdraw virtual IP while lease is owned elsewhere", zap.Error(err))
			}
			c.vipAssigned = false
			if strings.EqualFold(strings.TrimSpace(c.cfg.HighAvailability.Role), "active") && !c.cfg.HighAvailability.Preempt {
				message = "Peer currently owns the virtual IP lease; local active node is waiting because preempt is disabled."
				status = "degraded"
			}
		}
	} else {
		leaseAction = "release"
		if err := c.releaseLeaseIfOwned(lease); err != nil && c.logger != nil {
			c.logger.Warn("failed to release HA lease", zap.Error(err))
		}
		if err := c.withdrawVIP(target); err != nil && c.logger != nil {
			c.logger.Warn("failed to withdraw virtual IP", zap.Error(err))
		}
		c.vipAssigned = false
		if !peerReachable && c.cfg.HighAvailability.Enabled {
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

	c.publish(status, message, details)
}

func (c *controller) publish(status, message string, details map[string]any) {
	if err := db.UpsertRuntimeStatus(RuntimeComponent, status, message, details); err != nil && c.logger != nil {
		c.logger.Warn("failed to update high availability runtime status", zap.Error(err))
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

	if c.shouldPreempt(current, priority, peerReachable) {
		next := newLease(c, target, now, priority)
		return true, "preempted", next, saveLease(c.cfg, next)
	}

	return false, "blocked", current, nil
}

func (c *controller) shouldPreempt(current vipLease, priority int, peerReachable bool) bool {
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
	return true
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
