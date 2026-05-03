package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type AppliedState struct {
	Interfaces []ManagedInterfaceState `json:"interfaces"`
	Gateways   []GatewayState          `json:"gateways"`
	Routes     []StaticRouteState      `json:"routes"`
}

type ManagedInterfaceState struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MTU     int    `json:"mtu"`
}

type GatewayState struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Metric    int    `json:"metric"`
}

type StaticRouteState struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

type ValidationCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type ValidationReport struct {
	Healthy bool              `json:"healthy"`
	Checks  []ValidationCheck `json:"checks"`
}

// Apply reconciles managed interfaces, default gateways, and static routes.
func Apply(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("network apply requires a config")
	}

	return ApplyState(cfg, DesiredState(cfg))
}

// ApplyState reconciles to an explicit desired state and stores it as the managed network state.
func ApplyState(cfg *config.Config, desired AppliedState) error {
	if cfg == nil {
		return errors.New("network apply requires a config")
	}

	current, err := LoadState(StatePath(cfg))
	if err != nil {
		return err
	}

	if err := removeStaleRoutes(current.Routes, desired.Routes); err != nil {
		return err
	}
	if err := removeStaleGateways(current.Gateways, desired.Gateways); err != nil {
		return err
	}
	if err := removeStaleInterfaces(current.Interfaces, desired.Interfaces); err != nil {
		return err
	}

	for _, iface := range desired.Interfaces {
		if err := applyManagedInterface(iface); err != nil {
			return err
		}
	}
	for _, gateway := range desired.Gateways {
		if err := applyGateway(gateway); err != nil {
			return err
		}
	}
	for _, route := range desired.Routes {
		if err := applyStaticRoute(route); err != nil {
			return err
		}
	}

	return SaveState(StatePath(cfg), desired)
}

func DesiredState(cfg *config.Config) AppliedState {
	state := AppliedState{}

	if strings.TrimSpace(cfg.WAN.Name) != "" && !cfg.WAN.DHCP && strings.TrimSpace(cfg.WAN.Address) != "" {
		state.Interfaces = append(state.Interfaces, ManagedInterfaceState{
			Name:    strings.TrimSpace(cfg.WAN.Name),
			Address: strings.TrimSpace(cfg.WAN.Address),
		})
	}
	if strings.TrimSpace(cfg.LAN.Name) != "" && !cfg.LAN.DHCP && strings.TrimSpace(cfg.LAN.Address) != "" {
		state.Interfaces = append(state.Interfaces, ManagedInterfaceState{
			Name:    strings.TrimSpace(cfg.LAN.Name),
			Address: strings.TrimSpace(cfg.LAN.Address),
		})
	}

	for _, iface := range cfg.Network.Interfaces {
		if !iface.Enabled {
			continue
		}
		state.Interfaces = append(state.Interfaces, ManagedInterfaceState{
			Name:    strings.TrimSpace(iface.Name),
			Address: strings.TrimSpace(iface.Address),
			MTU:     iface.MTU,
		})
	}

	if strings.TrimSpace(cfg.WAN.Gateway) != "" && !cfg.WAN.DHCP && strings.TrimSpace(cfg.WAN.Name) != "" {
		state.Gateways = append(state.Gateways, GatewayState{
			Name:      "wan-default",
			Address:   strings.TrimSpace(cfg.WAN.Gateway),
			Interface: strings.TrimSpace(cfg.WAN.Name),
			Metric:    0,
		})
	}

	for _, gateway := range cfg.Network.Gateways {
		if !gateway.Enabled || !gateway.Default {
			continue
		}
		state.Gateways = append(state.Gateways, GatewayState{
			Name:      strings.TrimSpace(gateway.Name),
			Address:   strings.TrimSpace(gateway.Address),
			Interface: strings.TrimSpace(gateway.Interface),
			Metric:    gateway.Metric,
		})
	}

	for _, route := range cfg.Network.StaticRoutes {
		if !route.Enabled {
			continue
		}
		state.Routes = append(state.Routes, StaticRouteState{
			Name:        strings.TrimSpace(route.Name),
			Destination: strings.TrimSpace(route.Destination),
			Gateway:     strings.TrimSpace(route.Gateway),
			Interface:   strings.TrimSpace(route.Interface),
			Metric:      route.Metric,
		})
	}

	return state
}

func applyManagedInterface(iface ManagedInterfaceState) error {
	if err := runIP("link", "set", "dev", iface.Name, "up"); err != nil {
		return fmt.Errorf("bring interface %s up: %w", iface.Name, err)
	}
	if iface.MTU > 0 {
		if err := runIP("link", "set", "dev", iface.Name, "mtu", fmt.Sprint(iface.MTU)); err != nil {
			return fmt.Errorf("set interface %s mtu: %w", iface.Name, err)
		}
	}
	if iface.Address != "" {
		if err := runIP("addr", "replace", iface.Address, "dev", iface.Name); err != nil {
			return fmt.Errorf("assign %s to %s: %w", iface.Address, iface.Name, err)
		}
	}
	return nil
}

func applyGateway(gateway GatewayState) error {
	args := []string{"route", "replace", "default", "via", gateway.Address, "dev", gateway.Interface}
	if gateway.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(gateway.Metric))
	}
	if err := runIP(args...); err != nil {
		return fmt.Errorf("apply gateway %s via %s: %w", gateway.Name, gateway.Address, err)
	}
	return nil
}

func applyStaticRoute(route StaticRouteState) error {
	args := []string{"route", "replace", route.Destination, "via", route.Gateway, "dev", route.Interface}
	if route.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(route.Metric))
	}
	if err := runIP(args...); err != nil {
		return fmt.Errorf("apply route %s (%s): %w", route.Name, route.Destination, err)
	}
	return nil
}

func removeStaleInterfaces(current, desired []ManagedInterfaceState) error {
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, iface := range desired {
		desiredKeys[iface.key()] = struct{}{}
	}
	for _, iface := range current {
		if _, ok := desiredKeys[iface.key()]; ok {
			continue
		}
		if iface.Address == "" {
			continue
		}
		_ = runIP("addr", "del", iface.Address, "dev", iface.Name)
	}
	return nil
}

func removeStaleGateways(current, desired []GatewayState) error {
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, gateway := range desired {
		desiredKeys[gateway.key()] = struct{}{}
	}
	for _, gateway := range current {
		if _, ok := desiredKeys[gateway.key()]; ok {
			continue
		}
		args := []string{"route", "del", "default", "via", gateway.Address, "dev", gateway.Interface}
		if gateway.Metric > 0 {
			args = append(args, "metric", fmt.Sprint(gateway.Metric))
		}
		_ = runIP(args...)
	}
	return nil
}

func removeStaleRoutes(current, desired []StaticRouteState) error {
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, route := range desired {
		desiredKeys[route.key()] = struct{}{}
	}
	for _, route := range current {
		if _, ok := desiredKeys[route.key()]; ok {
			continue
		}
		args := []string{"route", "del", route.Destination, "via", route.Gateway, "dev", route.Interface}
		if route.Metric > 0 {
			args = append(args, "metric", fmt.Sprint(route.Metric))
		}
		_ = runIP(args...)
	}
	return nil
}

func StatePath(cfg *config.Config) string {
	dir := "/var/lib/aegisnas"
	if cfg != nil && strings.TrimSpace(cfg.Database.Path) != "" {
		dir = filepath.Dir(strings.TrimSpace(cfg.Database.Path))
	}
	return filepath.Join(dir, "network-state.json")
}

func LoadState(path string) (AppliedState, error) {
	var state AppliedState
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, fmt.Errorf("read network state: %w", err)
	}
	if len(data) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("decode network state: %w", err)
	}
	return state, nil
}

func SaveState(path string, state AppliedState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create network state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode network state: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write network state: %w", err)
	}
	return nil
}

var ipCommandRunner = defaultIPCommandRunner

func runIP(args ...string) error {
	_, err := ipCommandRunner(args...)
	return err
}

func queryIP(args ...string) (string, error) {
	return ipCommandRunner(args...)
}

func defaultIPCommandRunner(args ...string) (string, error) {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return "", err
		}
		return trimmed, fmt.Errorf("%w\nOutput: %s", err, trimmed)
	}
	return strings.TrimSpace(string(output)), nil
}

func NewValidationReport() ValidationReport {
	return ValidationReport{
		Healthy: true,
		Checks:  []ValidationCheck{},
	}
}

func (report *ValidationReport) AddCheck(name, status, detail string) {
	report.Checks = append(report.Checks, ValidationCheck{
		Name:   strings.TrimSpace(name),
		Status: strings.TrimSpace(status),
		Detail: strings.TrimSpace(detail),
	})
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "error":
		report.Healthy = false
	}
}

func (report ValidationReport) Summary() string {
	if len(report.Checks) == 0 {
		return "no validation checks were recorded"
	}
	failures := make([]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		switch strings.ToLower(strings.TrimSpace(check.Status)) {
		case "failed", "error":
			failures = append(failures, strings.TrimSpace(check.Detail))
		}
	}
	if len(failures) == 0 {
		return "all validation checks passed"
	}
	sort.Strings(failures)
	return strings.Join(failures, "; ")
}

func ValidateState(state AppliedState) ValidationReport {
	report := NewValidationReport()

	for _, iface := range state.Interfaces {
		validateInterface(iface, &report)
	}
	for _, gateway := range state.Gateways {
		validateGateway(gateway, &report)
	}
	for _, route := range state.Routes {
		validateStaticRoute(route, &report)
	}

	if len(report.Checks) == 0 {
		report.AddCheck("managed_network", "ok", "No managed interfaces, gateways, or static routes are defined.")
	}
	return report
}

func validateInterface(iface ManagedInterfaceState, report *ValidationReport) {
	output, err := queryIP("addr", "show", "dev", iface.Name)
	if err != nil {
		report.AddCheck("interface:"+iface.Name, "failed", fmt.Sprintf("Could not inspect interface %s: %v", iface.Name, err))
		return
	}
	if iface.Address != "" && !strings.Contains(output, "inet "+iface.Address) {
		report.AddCheck("interface:"+iface.Name, "failed", fmt.Sprintf("Interface %s is missing address %s.", iface.Name, iface.Address))
		return
	}
	detail := fmt.Sprintf("Interface %s is present", iface.Name)
	if iface.Address != "" {
		detail += fmt.Sprintf(" with address %s", iface.Address)
	}
	report.AddCheck("interface:"+iface.Name, "ok", detail+".")
}

func validateGateway(gateway GatewayState, report *ValidationReport) {
	output, err := queryIP("route", "show", "default")
	if err != nil {
		report.AddCheck("gateway:"+gateway.Name, "failed", fmt.Sprintf("Could not inspect default routes for gateway %s: %v", gateway.Name, err))
		return
	}
	if !routeOutputContains(output, "default", gateway.Address, gateway.Interface, gateway.Metric) {
		report.AddCheck("gateway:"+gateway.Name, "failed", fmt.Sprintf("Default gateway %s via %s dev %s is not active.", gateway.Name, gateway.Address, gateway.Interface))
		return
	}
	report.AddCheck("gateway:"+gateway.Name, "ok", fmt.Sprintf("Default gateway %s via %s dev %s is active.", gateway.Name, gateway.Address, gateway.Interface))
}

func validateStaticRoute(route StaticRouteState, report *ValidationReport) {
	output, err := queryIP("route", "show", route.Destination)
	if err != nil {
		report.AddCheck("route:"+route.Name, "failed", fmt.Sprintf("Could not inspect route %s: %v", route.Name, err))
		return
	}
	if !routeOutputContains(output, route.Destination, route.Gateway, route.Interface, route.Metric) {
		report.AddCheck("route:"+route.Name, "failed", fmt.Sprintf("Static route %s for %s via %s dev %s is not active.", route.Name, route.Destination, route.Gateway, route.Interface))
		return
	}
	report.AddCheck("route:"+route.Name, "ok", fmt.Sprintf("Static route %s for %s via %s dev %s is active.", route.Name, route.Destination, route.Gateway, route.Interface))
}

func routeOutputContains(output, destination, gateway, iface string, metric int) bool {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || !strings.HasPrefix(line, destination) {
			continue
		}
		if gateway != "" && !strings.Contains(line, " via "+gateway) {
			continue
		}
		if iface != "" && !strings.Contains(line, " dev "+iface) {
			continue
		}
		if metric > 0 && !strings.Contains(line, " metric "+fmt.Sprint(metric)) {
			continue
		}
		return true
	}
	return false
}

func (iface ManagedInterfaceState) key() string {
	return strings.Join([]string{iface.Name, iface.Address, fmt.Sprint(iface.MTU)}, "|")
}

func (gateway GatewayState) key() string {
	return strings.Join([]string{gateway.Name, gateway.Address, gateway.Interface, fmt.Sprint(gateway.Metric)}, "|")
}

func (route StaticRouteState) key() string {
	return strings.Join([]string{route.Name, route.Destination, route.Gateway, route.Interface, fmt.Sprint(route.Metric)}, "|")
}
