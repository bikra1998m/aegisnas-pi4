package adminapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"github.com/yourorg/aegisnas-pi4/internal/firewall"
	"github.com/yourorg/aegisnas-pi4/internal/network"
)

const dnsmasqLeasePath = "/var/lib/misc/dnsmasq.leases"

type networkApplyResult struct {
	BackupID   string                      `json:"backup_id"`
	Validation network.ValidationReport    `json:"validation"`
	Risk       network.ApplyRiskAssessment `json:"risk"`
	Recovery   *NetworkRecoveryState       `json:"recovery,omitempty"`
}

var (
	saveNetworkSnapshotFn       = network.SaveSnapshot
	applyManagedNetworkFn       = network.Apply
	applyFirewallRulesetFn      = firewall.ApplyRuleset
	restoreNetworkSnapshotFn    = restoreNetworkSnapshot
	validateAppliedNetworkFn    = validateAppliedNetworkServices
	checkLocalHealthEndpointFn  = checkLocalHealthEndpoint
	checkSystemdServiceActiveFn = checkSystemdServiceActive
	buildDNSMasqConfigFn        = buildDNSMasqConfig
	applyDNSMasqContentFn       = applyDNSMasqContent
	buildFirewallRulesFn        = buildFirewallRules
	assessApplyRiskFn           = network.AssessApplyRisk
)

func HandleApplyNetworkServices(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}

	var payload struct {
		ConfirmationText string `json:"confirmation_text"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &payload); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	result, err := applyNetworkServices(cfg, userFromRequest(r), payload.ConfirmationText)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "confirmation phrase") {
			statusCode = http.StatusBadRequest
		}
		http.Error(w, err.Error(), statusCode)
		return
	}

	audit(r, "apply_network_services", config.Path(), "applied")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "applied",
		"restart_required": false,
		"leases_path":      dnsmasqLeasePath,
		"backup_id":        result.BackupID,
		"validation":       result.Validation,
		"recovery":         result.Recovery,
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
	risk := assessApplyRiskFn(cfg, currentState, desiredState)

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
		"risk":                   risk,
		"recovery":               currentNetworkRecoveryStateForPreview(),
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
	observedAt := time.Now().UTC()
	if err := db.StoreDHCPLeaseObservations(observedAt, leaseObservationsFromCurrent(leases)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"leases":         leases,
		"count":          len(leases),
		"dhcp_enabled":   cfg.DHCP.Enabled,
		"lease_file":     dnsmasqLeasePath,
		"generated_at":   observedAt.Format(time.RFC3339),
		"static_leases":  len(cfg.DHCP.StaticLeases),
		"authoritative":  cfg.DHCP.Authoritative,
		"lease_duration": cfg.DHCP.LeaseTime,
	})
}

func HandleListDHCPLeaseHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListDHCPLeaseHistory(150)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"history":      history,
		"count":        len(history),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
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

func HandleListNetworkApplyHistory(w http.ResponseWriter, r *http.Request) {
	history, err := db.ListNetworkApplyHistory(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"history":      history,
		"count":        len(history),
		"generated_at": time.Now().UTC().Format(time.RFC3339),
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

	if err := restoreNetworkSnapshotFn(cfg, snapshot); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = db.RecordNetworkApplyHistory("rollback", "success", fmt.Sprintf("Restored rollback snapshot %s.", snapshot.ID), "", snapshot.ID, userFromRequest(r), map[string]any{
		"rollback_id": snapshot.ID,
	})
	_ = ClearPendingNetworkRecovery(fmt.Sprintf("Edge network state was rolled back to snapshot %s.", snapshot.ID), map[string]any{
		"rollback_id": snapshot.ID,
	})

	audit(r, "rollback_network_services", snapshot.ID, "restored")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "restored",
		"rollback_id":      snapshot.ID,
		"restart_required": false,
	})
}

func applyNetworkServices(cfg *config.Config, createdBy, confirmationText string) (networkApplyResult, error) {
	result := networkApplyResult{}
	if currentRecovery, err := CurrentNetworkRecoveryState(); err != nil {
		return result, err
	} else if currentRecovery != nil && currentRecovery.Pending {
		return result, fmt.Errorf("management-loss auto-revert is still pending for snapshot %s; confirm reachability or wait for rollback before applying more network changes", currentRecovery.BackupID)
	}
	currentState, err := network.LoadState(network.StatePath(cfg))
	if err != nil {
		return result, err
	}
	desiredState := network.DesiredState(cfg)
	result.Risk = assessApplyRiskFn(cfg, currentState, desiredState)
	if result.Risk.RequiresConfirmation && strings.TrimSpace(confirmationText) != result.Risk.ConfirmationPhrase {
		return result, fmt.Errorf("risky edge-network change requires confirmation phrase: %s", result.Risk.ConfirmationPhrase)
	}

	backup, err := captureNetworkSnapshot(cfg, createdBy, "pre-apply")
	if err != nil {
		return result, err
	}
	if err := saveNetworkSnapshotFn(cfg, backup); err != nil {
		return result, err
	}
	result.BackupID = backup.ID

	dnsmasqContent, err := buildDNSMasqConfigFn(cfg)
	if err != nil {
		return result, err
	}
	firewallRules, err := buildFirewallRulesFn(cfg)
	if err != nil {
		return result, err
	}

	rollbackOnFailure := func(cause error) error {
		if rollbackErr := restoreNetworkSnapshotFn(cfg, backup); rollbackErr != nil {
			_ = db.RecordNetworkApplyHistory("apply", "failed", cause.Error(), backup.ID, "", createdBy, map[string]any{
				"backup_id":       backup.ID,
				"validation":      result.Validation,
				"risk":            result.Risk,
				"rollback_status": "failed",
				"rollback_error":  rollbackErr.Error(),
			})
			return fmt.Errorf("%w; automatic rollback to snapshot %s also failed: %v", cause, backup.ID, rollbackErr)
		}
		_ = db.RecordNetworkApplyHistory("apply", "rolled_back", cause.Error(), backup.ID, backup.ID, createdBy, map[string]any{
			"backup_id":       backup.ID,
			"validation":      result.Validation,
			"risk":            result.Risk,
			"rollback_status": "success",
		})
		return fmt.Errorf("%w; automatic rollback restored snapshot %s", cause, backup.ID)
	}

	if err := applyManagedNetworkFn(cfg); err != nil {
		return result, rollbackOnFailure(fmt.Errorf("apply managed interfaces, gateways, and routes: %w", err))
	}
	if err := applyDNSMasqContentFn(cfg.DHCP.Enabled, dnsmasqContent); err != nil {
		return result, rollbackOnFailure(fmt.Errorf("apply dnsmasq configuration: %w", err))
	}
	if err := applyFirewallRulesetFn(firewallRules); err != nil {
		return result, rollbackOnFailure(fmt.Errorf("apply firewall rules: %w", err))
	}

	validation, err := validateAppliedNetworkFn(cfg)
	if err != nil {
		return result, rollbackOnFailure(fmt.Errorf("run post-apply validation: %w", err))
	}
	result.Validation = validation
	if !validation.Healthy {
		return result, rollbackOnFailure(fmt.Errorf("post-apply validation failed: %s", validation.Summary()))
	}
	if result.Risk.RequiresConfirmation {
		recovery, err := StartPendingNetworkRecovery(cfg, backup.ID, result.Risk, validation, createdBy)
		if err != nil {
			return result, rollbackOnFailure(fmt.Errorf("start management-loss auto-revert: %w", err))
		}
		result.Recovery = recovery
		return result, nil
	}
	_ = db.RecordNetworkApplyHistory("apply", "success", validation.Summary(), backup.ID, "", createdBy, map[string]any{
		"backup_id":  backup.ID,
		"validation": validation,
		"risk":       result.Risk,
	})

	return result, nil
}

func HandleConfirmNetworkRecovery(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		BackupID string `json:"backup_id"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &payload); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}
	state, err := ConfirmPendingNetworkRecovery(payload.BackupID, userFromRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "confirm_network_recovery", state.BackupID, "confirmed")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "confirmed",
		"recovery": state,
	})
}

func currentNetworkRecoveryStateForPreview() *NetworkRecoveryState {
	state, err := CurrentNetworkRecoveryState()
	if err != nil {
		return &NetworkRecoveryState{
			Status:  "degraded",
			Message: err.Error(),
		}
	}
	return state
}

func applyDNSMasqConfig(cfg *config.Config) error {
	content, err := buildDNSMasqConfigFn(cfg)
	if err != nil {
		return err
	}
	return applyDNSMasqContentFn(cfg.DHCP.Enabled, content)
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

func validateAppliedNetworkServices(cfg *config.Config) (network.ValidationReport, error) {
	report := network.ValidateState(network.DesiredState(cfg))

	if cfg.DHCP.Enabled {
		active, detail, err := checkSystemdServiceActiveFn("dnsmasq")
		if err != nil {
			report.AddCheck("service:dnsmasq", "failed", fmt.Sprintf("Could not verify dnsmasq service state: %v", err))
		} else if !active {
			report.AddCheck("service:dnsmasq", "failed", fmt.Sprintf("dnsmasq is not active after apply (%s).", detail))
		} else {
			report.AddCheck("service:dnsmasq", "ok", "dnsmasq is active after apply.")
		}
	} else {
		report.AddCheck("service:dnsmasq", "disabled", "dnsmasq is disabled in the saved config.")
	}

	healthChecks := []struct {
		name string
		port int
	}{
		{name: "admin_api", port: cfg.AdminPort},
		{name: "gateway", port: cfg.Health.Port},
		{name: "portal", port: cfg.Portal.Port},
		{name: "policy", port: cfg.Health.Port + 2},
		{name: "radius", port: cfg.Health.Port + 5},
		{name: "session", port: cfg.Health.Port + 7},
	}
	for _, item := range healthChecks {
		if err := checkLocalHealthEndpointFn(item.name, item.port); err != nil {
			report.AddCheck("health:"+item.name, "failed", err.Error())
			continue
		}
		report.AddCheck("health:"+item.name, "ok", fmt.Sprintf("%s health endpoint responded on port %d.", item.name, item.port))
	}

	return report, nil
}

func checkSystemdServiceActive(name string) (bool, string, error) {
	cmd := exec.Command("systemctl", "is-active", name)
	output, err := cmd.CombinedOutput()
	status := strings.TrimSpace(string(output))
	if err != nil {
		if status == "" {
			status = err.Error()
		}
		return false, status, nil
	}
	return status == "active", status, nil
}

func checkLocalHealthEndpoint(name string, port int) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		return fmt.Errorf("%s health endpoint on port %d did not respond: %w", name, port, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s health endpoint on port %d returned %s: %s", name, port, resp.Status, strings.TrimSpace(string(body)))
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

func leaseObservationsFromCurrent(leases []dnsmasq.Lease) []db.DHCPLeaseObservation {
	out := make([]db.DHCPLeaseObservation, 0, len(leases))
	for _, lease := range leases {
		out = append(out, db.DHCPLeaseObservation{
			MAC:              lease.MAC,
			IP:               lease.IP,
			Hostname:         lease.Hostname,
			ClientID:         lease.ClientID,
			Reservation:      lease.Reservation,
			Expired:          lease.Expired,
			ExpiresAt:        lease.ExpiresAt,
			RemainingSeconds: lease.RemainingSeconds,
		})
	}
	return out
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

func restoreNetworkSnapshot(cfg *config.Config, snapshot network.Snapshot) error {
	if err := network.ApplyState(cfg, snapshot.ManagedState); err != nil {
		return err
	}
	if err := applyDNSMasqContentFn(snapshot.DNSMasqEnabled, snapshot.DNSMasqConfig); err != nil {
		return err
	}
	if strings.TrimSpace(snapshot.FirewallRules) != "" {
		if err := firewall.RestoreRuleset(snapshot.FirewallRules); err != nil {
			return err
		}
	}
	return network.SaveState(network.StatePath(cfg), snapshot.ManagedState)
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
