package dnsmasq

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestGenerateTwoNIC(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		WAN:  config.InterfaceConfig{Name: "eth0"},
		LAN: config.InterfaceConfig{
			Name:      "eth1",
			Address:   "192.168.1.1/24",
			DHCPRange: "192.168.1.100,192.168.1.200,12h",
			Gateway:   "192.168.1.1",
		},
		Network: config.NetworkConfig{
			DNS: config.DNSConfig{
				UpstreamServers: []string{"1.1.1.1", "9.9.9.9"},
				SearchDomains:   []string{"corp.example.com"},
				LocalDomain:     "lab.example",
			},
			Firewall: config.FirewallConfig{
				FreeSites: []config.FreeSiteConfig{
					{Type: "domain", Value: "example.com", Enabled: true},
				},
			},
		},
		DHCP: config.DHCPConfig{
			Enabled:       true,
			LeaseTime:     "12h",
			Authoritative: true,
			StaticLeases: []config.DHCPStaticLeaseConfig{
				{MAC: "AA-BB-CC-DD-EE-FF", IP: "192.168.1.10", Hostname: "printer", Enabled: true},
			},
		},
		Portal: config.PortalConfig{ListenIP: "192.168.1.1"},
	}

	gen := NewGenerator(cfg)
	dnsCfg, err := gen.Generate()
	require.NoError(t, err)
	content := dnsCfg.Content

	assert.Contains(t, content, "interface=eth1")
	assert.Contains(t, content, "bind-dynamic")
	assert.Contains(t, content, "except-interface=lo")
	assert.Contains(t, content, "server=1.1.1.1")
	assert.Contains(t, content, "domain=lab.example")
	assert.Contains(t, content, "dhcp-authoritative")
	assert.Contains(t, content, "dhcp-option=option:domain-search,corp.example.com")
	assert.Contains(t, content, "server=/example.com/1.1.1.1")
	assert.Contains(t, content, "dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.10,printer")
	assert.Contains(t, content, "listen-address=192.168.1.1")
	assert.Contains(t, content, "dhcp-range=192.168.1.100,192.168.1.200,12h")
	assert.Contains(t, content, "address=/#/192.168.1.1")
}

func TestGenerateTrunkMode(t *testing.T) {
	cfg := &config.Config{
		Mode: "trunk",
		WAN:  config.InterfaceConfig{Name: "eth0"},
		VLANs: []config.VLANConfig{
			{ID: 20, Name: "guest", Subnet: "10.20.0.0/24", Gateway: "10.20.0.1"},
			{ID: 30, Name: "corp", Subnet: "10.30.0.0/24", Gateway: "10.30.0.1"},
		},
		DHCP:   config.DHCPConfig{Enabled: true, LeaseTime: "12h"},
		Portal: config.PortalConfig{ListenIP: "10.20.0.1"},
	}

	gen := NewGenerator(cfg)
	dnsCfg, err := gen.Generate()
	require.NoError(t, err)
	content := dnsCfg.Content

	assert.Contains(t, content, "bind-dynamic")
	assert.Contains(t, content, "except-interface=lo")
	assert.Contains(t, content, "interface=eth0.20")
	assert.Contains(t, content, "dhcp-range=set:guest,10.20.0.100,10.20.0.200,12h")
	assert.Contains(t, content, "interface=eth0.30")
	assert.Contains(t, content, "address=/#/10.20.0.1")
}
