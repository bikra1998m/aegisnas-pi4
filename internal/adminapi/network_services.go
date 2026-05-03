package adminapi

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"github.com/yourorg/aegisnas-pi4/internal/firewall"
	"github.com/yourorg/aegisnas-pi4/internal/network"
)

const dnsmasqLeasePath = "/var/lib/misc/dnsmasq.leases"

func HandleApplyNetworkServices(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	backup, err := captureNetworkSnapshot(cfg, userFromRequest(r), "pre-apply")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := network.SaveSnapshot(cfg, backup); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := network.Apply(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := applyDNSMasqConfig(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gen := firewall.NewGenerator(cfg)
	ruleset, err := gen.Generate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := firewall.ApplyRuleset(ruleset.Content); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audit(r, "apply_network_services", config.Path(), "applied")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "applied",
		"restart_required": false,
		"leases_path":      dnsmasqLeasePath,
		"backup_id":        backup.ID,
	})
}

func HandlePreviewNetworkServices(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	currentState, err := network.LoadState(network.StatePath(cfg))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	desiredState := network.DesiredState(cfg)
	diff := network.DiffState(currentState, desiredState)

	dnsmasqPreview, err := buildDNSMasqConfig(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	firewallPreview, err := buildFirewallRules(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	snapshots, err := network.ListSnapshots(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"desired_state":          desiredState,
		"current_state":          currentState,
		"diff":                   diff,
		"dnsmasq_enabled":        cfg.DHCP.Enabled,
		"dnsmasq_config":         dnsmasqPreview,
		"firewall_rules":         firewallPreview,
		"free_site_count":        len(cfg.Network.Firewall.FreeSites),
		"custom_firewall_rules":  len(cfg.Network.Firewall.Rules),
		"static_reservations":    len(cfg.DHCP.StaticLeases),
		"available_rollback_ids": snapshots,
	})
}

func HandleListDHCPLeases(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	leases, err := dnsmasq.ParseLeasesFile(dnsmasqLeasePath, time.Now(), leaseReservations(cfg))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"leases":         leases,
		"count":          len(leases),
		"dhcp_enabled":   cfg.DHCP.Enabled,
		"lease_file":     dnsmasqLeasePath,
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"static_leases":  len(cfg.DHCP.StaticLeases),
		"authoritative":  cfg.DHCP.Authoritative,
		"lease_duration": cfg.DHCP.LeaseTime,
	})
}

func HandleListNetworkSnapshots(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	snapshots, err := network.ListSnapshots(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshots": snapshots,
		"count":     len(snapshots),
	})
}

func HandleRollbackNetworkServices(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	var payload struct {
		ID string `json:"id"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &payload); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	snapshot, err := loadRollbackSnapshot(cfg, strings.TrimSpace(payload.ID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := network.ApplyState(cfg, snapshot.ManagedState); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := applyDNSMasqContent(snapshot.DNSMasqEnabled, snapshot.DNSMasqConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(snapshot.FirewallRules) != "" {
		if err := firewall.RestoreRuleset(snapshot.FirewallRules); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := network.SaveState(network.StatePath(cfg), snapshot.ManagedState); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audit(r, "rollback_network_services", snapshot.ID, "restored")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "restored",
		"rollback_id":      snapshot.ID,
		"restart_required": false,
	})
}

func applyDNSMasqConfig(cfg *config.Config) error {
	content, err := buildDNSMasqConfig(cfg)
	if err != nil {
		return err
	}
	return applyDNSMasqContent(cfg.DHCP.Enabled, content)
}

func buildDNSMasqConfig(cfg *config.Config) (string, error) {
	if !cfg.DHCP.Enabled {
		return "", nil
	}

	gen := dnsmasq.NewGenerator(cfg)
	dnsCfg, err := gen.Generate()
	if err != nil {
		return "", err
	}
	return dnsCfg.Content, nil
}

func applyDNSMasqContent(enabled bool, content string) error {
	if !enabled {
		_ = exec.Command("systemctl", "stop", "dnsmasq").Run()
		return nil
	}
	if err := os.WriteFile("/etc/dnsmasq.conf", []byte(content), 0644); err != nil {
		return fmt.Errorf("write dnsmasq.conf: %w", err)
	}
	if err := exec.Command("systemctl", "restart", "dnsmasq").Run(); err != nil {
		return fmt.Errorf("restart dnsmasq: %w", err)
	}
	return nil
}

func buildFirewallRules(cfg *config.Config) (string, error) {
	gen := firewall.NewGenerator(cfg)
	ruleset, err := gen.Generate()
	if err != nil {
		return "", err
	}
	return ruleset.Content, nil
}

func leaseReservations(cfg *config.Config) map[string]struct{} {
	values := make(map[string]struct{}, len(cfg.DHCP.StaticLeases)*2)
	for _, lease := range cfg.DHCP.StaticLeases {
		if !lease.Enabled {
			continue
		}
		mac := fmt.Sprintf("mac:%s", normalizeReservationMAC(lease.MAC))
		ip := fmt.Sprintf("ip:%s", strings.TrimSpace(lease.IP))
		values[mac] = struct{}{}
		values[ip] = struct{}{}
	}
	return values
}

func normalizeReservationMAC(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
}

func captureNetworkSnapshot(cfg *config.Config, createdBy, reason string) (network.Snapshot, error) {
	state, err := network.LoadState(network.StatePath(cfg))
	if err != nil {
		return network.Snapshot{}, err
	}
	dnsmasqContent, err := readFileIfExists("/etc/dnsmasq.conf")
	if err != nil {
		return network.Snapshot{}, err
	}
	firewallRules, err := firewall.GetCurrentRuleset()
	if err != nil {
		firewallRules = ""
	}
	dnsmasqEnabled := strings.TrimSpace(dnsmasqContent) != ""
	return network.NewSnapshot(cfg, state, dnsmasqEnabled, dnsmasqContent, firewallRules, createdBy, reason), nil
}

func readFileIfExists(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

func loadRollbackSnapshot(cfg *config.Config, id string) (network.Snapshot, error) {
	if id != "" {
		return network.LoadSnapshot(cfg, id)
	}
	snapshots, err := network.ListSnapshots(cfg)
	if err != nil {
		return network.Snapshot{}, err
	}
	if len(snapshots) == 0 {
		return network.Snapshot{}, errors.New("no rollback snapshots are available yet")
	}
	return network.LoadSnapshot(cfg, snapshots[0].ID)
}
