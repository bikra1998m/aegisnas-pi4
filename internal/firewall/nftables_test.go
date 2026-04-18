package firewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestGenerateTwoNIC(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		WAN: config.InterfaceConfig{
			Name: "eth0",
			DHCP: true,
		},
		LAN: config.InterfaceConfig{
			Name:    "eth1",
			Address: "192.168.1.1/24",
		},
		Health: config.HealthConfig{Port: 8080},
	}

	gen := NewGenerator(cfg)
	ruleset, err := gen.Generate()
	require.NoError(t, err)
	content := ruleset.Content

	assert.Contains(t, content, "define WAN_IF = eth0")
	assert.Contains(t, content, "define LAN_IF = eth1")
	assert.Contains(t, content, "iif $LAN_IF oif $WAN_IF accept")
	assert.Contains(t, content, "masquerade")
}

func TestGenerateTrunkMode(t *testing.T) {
	cfg := &config.Config{
		Mode: "trunk",
		WAN: config.InterfaceConfig{
			Name: "eth0",
		},
		VLANs: []config.VLANConfig{
			{ID: 20, Name: "guest", Subnet: "10.20.0.0/24", Purpose: "guest"},
			{ID: 30, Name: "corp", Subnet: "10.30.0.0/24", Purpose: "corp"},
			{ID: 40, Name: "mgmt", Subnet: "10.40.0.0/24", Purpose: "management"},
		},
		Health: config.HealthConfig{Port: 8080},
	}

	gen := NewGenerator(cfg)
	ruleset, err := gen.Generate()
	require.NoError(t, err)
	content := ruleset.Content

	assert.Contains(t, content, "define TRUNK_IF = eth0")
	assert.Contains(t, content, "VLAN_20_IF")
	assert.Contains(t, content, "VLAN_30_IF")
	assert.Contains(t, content, "iif $VLAN_20_IF oif eth0 accept")
	assert.Contains(t, content, "masquerade")
}
