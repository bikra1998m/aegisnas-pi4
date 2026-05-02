package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type appliedState struct {
	Interfaces []managedInterfaceState `json:"interfaces"`
	Gateways   []gatewayState          `json:"gateways"`
	Routes     []staticRouteState      `json:"routes"`
}

type managedInterfaceState struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MTU     int    `json:"mtu"`
}

type gatewayState struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Metric    int    `json:"metric"`
}

type staticRouteState struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// Apply reconciles managed interfaces, default gateways, and static routes.
func Apply(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("network apply requires a config")
	}

	desired := desiredState(cfg)
	current, err := loadState(statePath(cfg))
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

	return saveState(statePath(cfg), desired)
}

func desiredState(cfg *config.Config) appliedState {
	state := appliedState{}

	if strings.TrimSpace(cfg.WAN.Name) != "" && !cfg.WAN.DHCP && strings.TrimSpace(cfg.WAN.Address) != "" {
		state.Interfaces = append(state.Interfaces, managedInterfaceState{
			Name:    strings.TrimSpace(cfg.WAN.Name),
			Address: strings.TrimSpace(cfg.WAN.Address),
		})
	}
	if strings.TrimSpace(cfg.LAN.Name) != "" && !cfg.LAN.DHCP && strings.TrimSpace(cfg.LAN.Address) != "" {
		state.Interfaces = append(state.Interfaces, managedInterfaceState{
			Name:    strings.TrimSpace(cfg.LAN.Name),
			Address: strings.TrimSpace(cfg.LAN.Address),
		})
	}

	for _, iface := range cfg.Network.Interfaces {
		if !iface.Enabled {
			continue
		}
		state.Interfaces = append(state.Interfaces, managedInterfaceState{
			Name:    strings.TrimSpace(iface.Name),
			Address: strings.TrimSpace(iface.Address),
			MTU:     iface.MTU,
		})
	}

	if strings.TrimSpace(cfg.WAN.Gateway) != "" && !cfg.WAN.DHCP && strings.TrimSpace(cfg.WAN.Name) != "" {
		state.Gateways = append(state.Gateways, gatewayState{
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
		state.Gateways = append(state.Gateways, gatewayState{
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
		state.Routes = append(state.Routes, staticRouteState{
			Name:        strings.TrimSpace(route.Name),
			Destination: strings.TrimSpace(route.Destination),
			Gateway:     strings.TrimSpace(route.Gateway),
			Interface:   strings.TrimSpace(route.Interface),
			Metric:      route.Metric,
		})
	}

	return state
}

func applyManagedInterface(iface managedInterfaceState) error {
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

func applyGateway(gateway gatewayState) error {
	args := []string{"route", "replace", "default", "via", gateway.Address, "dev", gateway.Interface}
	if gateway.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(gateway.Metric))
	}
	if err := runIP(args...); err != nil {
		return fmt.Errorf("apply gateway %s via %s: %w", gateway.Name, gateway.Address, err)
	}
	return nil
}

func applyStaticRoute(route staticRouteState) error {
	args := []string{"route", "replace", route.Destination, "via", route.Gateway, "dev", route.Interface}
	if route.Metric > 0 {
		args = append(args, "metric", fmt.Sprint(route.Metric))
	}
	if err := runIP(args...); err != nil {
		return fmt.Errorf("apply route %s (%s): %w", route.Name, route.Destination, err)
	}
	return nil
}

func removeStaleInterfaces(current, desired []managedInterfaceState) error {
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

func removeStaleGateways(current, desired []gatewayState) error {
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

func removeStaleRoutes(current, desired []staticRouteState) error {
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

func statePath(cfg *config.Config) string {
	dir := "/var/lib/aegisnas"
	if cfg != nil && strings.TrimSpace(cfg.Database.Path) != "" {
		dir = filepath.Dir(strings.TrimSpace(cfg.Database.Path))
	}
	return filepath.Join(dir, "network-state.json")
}

func loadState(path string) (appliedState, error) {
	var state appliedState
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

func saveState(path string, state appliedState) error {
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

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\nOutput: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (iface managedInterfaceState) key() string {
	return strings.Join([]string{iface.Name, iface.Address, fmt.Sprint(iface.MTU)}, "|")
}

func (gateway gatewayState) key() string {
	return strings.Join([]string{gateway.Name, gateway.Address, gateway.Interface, fmt.Sprint(gateway.Metric)}, "|")
}

func (route staticRouteState) key() string {
	return strings.Join([]string{route.Name, route.Destination, route.Gateway, route.Interface, fmt.Sprint(route.Metric)}, "|")
}
