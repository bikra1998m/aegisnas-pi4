package dnsmasq

import (
	"bytes"
	"fmt"
	"net"
	"text/template"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// Config represents the generated dnsmasq configuration.
type Config struct {
	Content string
}

// Generator creates dnsmasq configurations from the system config.
type Generator struct {
	cfg *config.Config
}

func NewGenerator(cfg *config.Config) *Generator {
	return &Generator{cfg: cfg}
}

// Generate produces the complete dnsmasq configuration.
func (g *Generator) Generate() (*Config, error) {
	var buf bytes.Buffer

	tmplText := `# AegisNAS dnsmasq configuration
# Generated automatically – do not edit manually

# Global options
domain-needed
bogus-priv
no-resolv
no-poll
server=8.8.8.8
server=8.8.4.4
local=/aegis.local/
expand-hosts
domain=aegis.local

# DHCP options
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
dhcp-lease-max=1000

{{- if eq .Mode "two-nic"}}
# LAN interface (two‑NIC mode)
interface={{ .LAN.Name }}
dhcp-range={{ .LAN.DHCPRange }}
dhcp-option={{ .LAN.Name }},3,{{ .LAN.Gateway }}
{{- else}}
# Trunk mode – VLAN subinterfaces
{{- range .VLANs}}
interface={{ $.WAN.Name }}.{{ .ID }}
dhcp-range=set:{{ .Name }},{{ .DHCPStart }},{{ .DHCPEnd }},{{ .LeaseTime }}
dhcp-option=tag:{{ .Name }},3,{{ .Gateway }}
{{- end}}
{{- end}}

# Captive portal redirection (wall garden)
# All HTTP traffic from unauthenticated clients redirected to portal
address=/#/{{ .PortalIP }}

# Static assignments (none by default)
# dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.100
`

	// Prepare data with defaults for missing fields
	type vlanData struct {
		ID        int
		Name      string
		DHCPStart string
		DHCPEnd   string
		LeaseTime string
		Gateway   string
	}

	data := struct {
		Mode string
		WAN  config.InterfaceConfig
		LAN  struct {
			Name      string
			DHCPRange string
			Gateway   string
		}
		VLANs    []vlanData
		PortalIP string
	}{
		Mode:     g.cfg.Mode,
		WAN:      g.cfg.WAN,
		PortalIP: g.cfg.Portal.ListenIP,
	}

	// Default portal IP if not set
	if data.PortalIP == "" {
		data.PortalIP = "10.20.0.1"
	}

	if g.cfg.Mode == "two-nic" {
		// For two‑NIC mode, use LAN subnet for DHCP
		lan := g.cfg.LAN
		data.LAN.Name = lan.Name
		// Default DHCP range if not provided via config (could be added later)
		if lan.DHCPRange == "" {
			// Assume /24 subnet from address
			ipParts := parseIPv4Parts(lan.Address)
			if len(ipParts) == 4 {
				data.LAN.DHCPRange = fmt.Sprintf("%d.%d.%d.100,%d.%d.%d.200,12h",
					ipParts[0], ipParts[1], ipParts[2],
					ipParts[0], ipParts[1], ipParts[2])
			} else {
				data.LAN.DHCPRange = "192.168.1.100,192.168.1.200,12h"
			}
		} else {
			data.LAN.DHCPRange = lan.DHCPRange
		}
		if lan.Gateway == "" {
			data.LAN.Gateway = extractGateway(lan.Address)
		} else {
			data.LAN.Gateway = lan.Gateway
		}
	} else {
		// Trunk mode: generate DHCP ranges per VLAN
		for _, v := range g.cfg.VLANs {
			vd := vlanData{
				ID:        v.ID,
				Name:      v.Name,
				LeaseTime: "12h",
			}
			// Derive DHCP range from subnet
			ip, ipnet, err := parseCIDR(v.Subnet)
			if err == nil {
				start := ip.Mask(ipnet.Mask)
				// First usable address usually .2 (gateway is .1)
				start[3] = 100
				end := ip.Mask(ipnet.Mask)
				end[3] = 200
				vd.DHCPStart = start.String()
				vd.DHCPEnd = end.String()
				gateway := ip.Mask(ipnet.Mask)
				gateway[3] = 1
				vd.Gateway = gateway.String()
			} else {
				// Fallbacks
				vd.DHCPStart = fmt.Sprintf("10.%d.0.100", v.ID)
				vd.DHCPEnd = fmt.Sprintf("10.%d.0.200", v.ID)
				vd.Gateway = fmt.Sprintf("10.%d.0.1", v.ID)
			}
			// Override with explicit config if present
			if v.DHCPStart != "" {
				vd.DHCPStart = v.DHCPStart
			}
			if v.DHCPEnd != "" {
				vd.DHCPEnd = v.DHCPEnd
			}
			if v.Gateway != "" {
				vd.Gateway = v.Gateway
			}
			data.VLANs = append(data.VLANs, vd)
		}
	}

	tmpl, err := template.New("dnsmasq").Parse(tmplText)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return &Config{Content: buf.String()}, nil
}

// Helper functions
func parseIPv4Parts(addr string) []int {
	// remove CIDR suffix
	for i, c := range addr {
		if c == '/' {
			addr = addr[:i]
			break
		}
	}
	var parts [4]int
	_, err := fmt.Sscanf(addr, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3])
	if err != nil {
		return nil
	}
	return []int{parts[0], parts[1], parts[2], parts[3]}
}

func extractGateway(addr string) string {
	parts := parseIPv4Parts(addr)
	if len(parts) == 4 {
		parts[3] = 1
		return fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], parts[2], parts[3])
	}
	return "192.168.1.1"
}

func parseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	return ip, ipnet, err
}
