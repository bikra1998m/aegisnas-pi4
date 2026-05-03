package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type Snapshot struct {
	ID             string       `json:"id"`
	CreatedAt      string       `json:"created_at"`
	ManagedState   AppliedState `json:"managed_state"`
	DNSMasqEnabled bool         `json:"dnsmasq_enabled"`
	DNSMasqConfig  string       `json:"dnsmasq_config"`
	FirewallRules  string       `json:"firewall_rules"`
	CreatedBy      string       `json:"created_by,omitempty"`
	Reason         string       `json:"reason,omitempty"`
}

type SnapshotSummary struct {
	ID             string `json:"id"`
	CreatedAt      string `json:"created_at"`
	Interfaces     int    `json:"interfaces"`
	Gateways       int    `json:"gateways"`
	Routes         int    `json:"routes"`
	DNSMasqEnabled bool   `json:"dnsmasq_enabled"`
	HasFirewall    bool   `json:"has_firewall"`
	CreatedBy      string `json:"created_by,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type DiffSummary struct {
	InterfacesAdded   []string `json:"interfaces_added"`
	InterfacesRemoved []string `json:"interfaces_removed"`
	GatewaysAdded     []string `json:"gateways_added"`
	GatewaysRemoved   []string `json:"gateways_removed"`
	RoutesAdded       []string `json:"routes_added"`
	RoutesRemoved     []string `json:"routes_removed"`
}

func NewSnapshot(cfg *config.Config, managedState AppliedState, dnsmasqEnabled bool, dnsmasqConfig string, firewallRules string, createdBy, reason string) Snapshot {
	now := time.Now().UTC()
	return Snapshot{
		ID:             now.Format("20060102T150405Z"),
		CreatedAt:      now.Format(time.RFC3339),
		ManagedState:   managedState,
		DNSMasqEnabled: dnsmasqEnabled,
		DNSMasqConfig:  dnsmasqConfig,
		FirewallRules:  firewallRules,
		CreatedBy:      strings.TrimSpace(createdBy),
		Reason:         strings.TrimSpace(reason),
	}
}

func BackupDir(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(StatePath(cfg)), "network-backups")
}

func SaveSnapshot(cfg *config.Config, snapshot Snapshot) error {
	if strings.TrimSpace(snapshot.ID) == "" {
		return errors.New("snapshot id cannot be empty")
	}
	dir := BackupDir(cfg)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	path := filepath.Join(dir, snapshot.ID+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return nil
}

func LoadSnapshot(cfg *config.Config, id string) (Snapshot, error) {
	var snapshot Snapshot
	if strings.TrimSpace(id) == "" {
		return snapshot, errors.New("snapshot id cannot be empty")
	}
	data, err := os.ReadFile(filepath.Join(BackupDir(cfg), id+".json"))
	if err != nil {
		return snapshot, fmt.Errorf("read snapshot: %w", err)
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return snapshot, fmt.Errorf("decode snapshot: %w", err)
	}
	return snapshot, nil
}

func ListSnapshots(cfg *config.Config) ([]SnapshotSummary, error) {
	dir := BackupDir(cfg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []SnapshotSummary{}, nil
		}
		return nil, fmt.Errorf("read snapshot directory: %w", err)
	}
	summaries := make([]SnapshotSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		snapshot, err := LoadSnapshot(cfg, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, SnapshotSummary{
			ID:             snapshot.ID,
			CreatedAt:      snapshot.CreatedAt,
			Interfaces:     len(snapshot.ManagedState.Interfaces),
			Gateways:       len(snapshot.ManagedState.Gateways),
			Routes:         len(snapshot.ManagedState.Routes),
			DNSMasqEnabled: snapshot.DNSMasqEnabled,
			HasFirewall:    strings.TrimSpace(snapshot.FirewallRules) != "",
			CreatedBy:      snapshot.CreatedBy,
			Reason:         snapshot.Reason,
		})
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		return summaries[i].CreatedAt > summaries[j].CreatedAt
	})
	return summaries, nil
}

func DiffState(current, desired AppliedState) DiffSummary {
	return DiffSummary{
		InterfacesAdded:   diffManagedInterfaces(desired.Interfaces, current.Interfaces),
		InterfacesRemoved: diffManagedInterfaces(current.Interfaces, desired.Interfaces),
		GatewaysAdded:     diffGateways(desired.Gateways, current.Gateways),
		GatewaysRemoved:   diffGateways(current.Gateways, desired.Gateways),
		RoutesAdded:       diffRoutes(desired.Routes, current.Routes),
		RoutesRemoved:     diffRoutes(current.Routes, desired.Routes),
	}
}

func diffManagedInterfaces(left, right []ManagedInterfaceState) []string {
	rightKeys := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightKeys[item.key()] = struct{}{}
	}
	out := []string{}
	for _, item := range left {
		if _, ok := rightKeys[item.key()]; ok {
			continue
		}
		label := item.Name
		if item.Address != "" {
			label = fmt.Sprintf("%s %s", item.Name, item.Address)
		}
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func diffGateways(left, right []GatewayState) []string {
	rightKeys := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightKeys[item.key()] = struct{}{}
	}
	out := []string{}
	for _, item := range left {
		if _, ok := rightKeys[item.key()]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s via %s dev %s", item.Name, item.Address, item.Interface))
	}
	sort.Strings(out)
	return out
}

func diffRoutes(left, right []StaticRouteState) []string {
	rightKeys := make(map[string]struct{}, len(right))
	for _, item := range right {
		rightKeys[item.key()] = struct{}{}
	}
	out := []string{}
	for _, item := range left {
		if _, ok := rightKeys[item.key()]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s via %s dev %s", item.Name, item.Destination, item.Gateway, item.Interface))
	}
	sort.Strings(out)
	return out
}
