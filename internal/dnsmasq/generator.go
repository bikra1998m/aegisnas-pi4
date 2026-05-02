package dnsmasq

import (
	"bytes"
	"fmt"
	"net"
	"strings"
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
# Generated automatically - do not edit manually

# Global options
bind-dynamic
except-interface=lo
domain-needed
bogus-priv
no-resolv
no-poll
{{- range .DNSServers }}
server={{ . }}
{{- end }}
local=/{{ .LocalDomain }}/
expand-hosts
domain={{ .LocalDomain }}

# DHCP options
{{- if .DHCPAuthoritative }}
dhcp-authoritative
{{- end }}
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
dhcp-lease-max=1000
{{- if .SearchDomains }}
dhcp-option=option:domain-search,{{ .SearchDomains }}
{{- end }}

{{- if eq .Mode "two-nic"}}
# LAN interface (two-NIC mode)
interface={{ .LAN.Name }}
listen-address={{ .LAN.Gateway }}
dhcp-range={{ .LAN.DHCPRange }}
dhcp-option={{ .LAN.Name }},3,{{ .LAN.Gateway }}
{{- else}}
# Trunk mode - VLAN subinterfaces
{{- range .VLANs}}
interface={{ $.WAN.Name }}.{{ .ID }}
dhcp-range=set:{{ .Name }},{{ .DHCPStart }},{{ .DHCPEnd }},{{ .LeaseTime }}
dhcp-option=tag:{{ .Name }},3,{{ .Gateway }}
{{- end}}
{{- end}}

# Captive portal redirection (wall garden)
# All HTTP traffic from unauthenticated clients redirected to portal
address=/#/{{ .PortalIP }}

{{- if .FreeSiteDomains }}
# Free sites allowed to bypass captive DNS redirection
{{- range .FreeSiteDomains }}
server=/{{ . }}/{{ $.PrimaryDNSServer }}
{{- end }}
{{- end }}

{{- if .StaticLeases }}
# Static assignments
{{- range .StaticLeases }}
dhcp-host={{ .MAC }},{{ .IP }}{{ if .Hostname }},{{ .Hostname }}{{ end }}
{{- end }}
{{- else }}
# Static assignments (none by default)
# dhcp-host=aa:bb:cc:dd:ee:ff,192.168.1.100
{{- end }}
`

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
		VLANs             []vlanData
		PortalIP          string
		DNSServers        []string
		PrimaryDNSServer  string
		LocalDomain       string
		SearchDomains     string
		FreeSiteDomains   []string
		StaticLeases      []config.DHCPStaticLeaseConfig
		DHCPAuthoritative bool
	}{
		Mode:              g.cfg.Mode,
		WAN:               g.cfg.WAN,
		PortalIP:          g.cfg.Portal.ListenIP,
		DNSServers:        normalizedDNSServers(g.cfg),
		LocalDomain:       normalizedLocalDomain(g.cfg),
		SearchDomains:     strings.Join(normalizedSearchDomains(g.cfg), ","),
		FreeSiteDomains:   enabledFreeSiteDomains(g.cfg),
		StaticLeases:      enabledStaticLeases(g.cfg),
		DHCPAuthoritative: g.cfg.DHCP.Authoritative,
	}
	if len(data.DNSServers) > 0 {
		data.PrimaryDNSServer = data.DNSServers[0]
	}

	if data.PortalIP == "" {
		data.PortalIP = "10.20.0.1"
	}

	if g.cfg.Mode == "two-nic" {
		lan := g.cfg.LAN
		data.LAN.Name = lan.Name
		if lan.DHCPRange == "" {
			ipParts := parseIPv4Parts(lan.Address)
			leaseTime := normalizedLeaseTime(g.cfg)
			if len(ipParts) == 4 {
				data.LAN.DHCPRange = fmt.Sprintf("%d.%d.%d.100,%d.%d.%d.200,%s",
					ipParts[0], ipParts[1], ipParts[2],
					ipParts[0], ipParts[1], ipParts[2],
					leaseTime)
			} else {
				data.LAN.DHCPRange = "192.168.1.100,192.168.1.200," + leaseTime
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
		for _, v := range g.cfg.VLANs {
			vd := vlanData{
				ID:        v.ID,
				Name:      v.Name,
				LeaseTime: normalizedLeaseTime(g.cfg),
			}
			ip, ipnet, err := parseCIDR(v.Subnet)
			if err == nil {
				start := ip.Mask(ipnet.Mask)
				start[3] = 100
				end := ip.Mask(ipnet.Mask)
				end[3] = 200
				vd.DHCPStart = start.String()
				vd.DHCPEnd = end.String()
				gateway := ip.Mask(ipnet.Mask)
				gateway[3] = 1
				vd.Gateway = gateway.String()
			} else {
				vd.DHCPStart = fmt.Sprintf("10.%d.0.100", v.ID)
				vd.DHCPEnd = fmt.Sprintf("10.%d.0.200", v.ID)
				vd.Gateway = fmt.Sprintf("10.%d.0.1", v.ID)
			}
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

func normalizedDNSServers(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Network.DNS.UpstreamServers) == 0 {
		return []string{"8.8.8.8", "8.8.4.4"}
	}
	servers := make([]string, 0, len(cfg.Network.DNS.UpstreamServers))
	for _, server := range cfg.Network.DNS.UpstreamServers {
		if trimmed := strings.TrimSpace(server); trimmed != "" {
			servers = append(servers, trimmed)
		}
	}
	if len(servers) == 0 {
		return []string{"8.8.8.8", "8.8.4.4"}
	}
	return servers
}

func normalizedSearchDomains(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Network.DNS.SearchDomains))
	for _, domain := range cfg.Network.DNS.SearchDomains {
		if trimmed := strings.TrimSpace(domain); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizedLocalDomain(cfg *config.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.Network.DNS.LocalDomain) == "" {
		return "aegis.local"
	}
	return strings.TrimSpace(cfg.Network.DNS.LocalDomain)
}

func normalizedLeaseTime(cfg *config.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.DHCP.LeaseTime) == "" {
		return "12h"
	}
	return strings.TrimSpace(cfg.DHCP.LeaseTime)
}

func enabledFreeSiteDomains(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	values := []string{}
	for _, site := range cfg.Network.Firewall.FreeSites {
		if !site.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(site.Type), "domain") && strings.TrimSpace(site.Value) != "" {
			values = append(values, strings.TrimSpace(site.Value))
		}
	}
	return values
}

func enabledStaticLeases(cfg *config.Config) []config.DHCPStaticLeaseConfig {
	if cfg == nil {
		return nil
	}
	leases := make([]config.DHCPStaticLeaseConfig, 0, len(cfg.DHCP.StaticLeases))
	for _, lease := range cfg.DHCP.StaticLeases {
		if !lease.Enabled {
			continue
		}
		lease.MAC = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(lease.MAC), "-", ":"))
		lease.IP = strings.TrimSpace(lease.IP)
		lease.Hostname = strings.TrimSpace(lease.Hostname)
		leases = append(leases, lease)
	}
	return leases
}

// Helper functions
func parseIPv4Parts(addr string) []int {
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
