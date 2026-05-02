package adminapi

import (
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

func applyDNSMasqConfig(cfg *config.Config) error {
	if !cfg.DHCP.Enabled {
		_ = exec.Command("systemctl", "stop", "dnsmasq").Run()
		return nil
	}

	gen := dnsmasq.NewGenerator(cfg)
	dnsCfg, err := gen.Generate()
	if err != nil {
		return err
	}
	if err := os.WriteFile("/etc/dnsmasq.conf", []byte(dnsCfg.Content), 0644); err != nil {
		return fmt.Errorf("write dnsmasq.conf: %w", err)
	}
	if err := exec.Command("systemctl", "restart", "dnsmasq").Run(); err != nil {
		return fmt.Errorf("restart dnsmasq: %w", err)
	}
	return nil
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
