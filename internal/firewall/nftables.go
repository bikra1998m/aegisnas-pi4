package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"text/template"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// Ruleset represents the generated nftables configuration.
type Ruleset struct {
	Content string
}

// Generator creates nftables rulesets from config.
type Generator struct {
	cfg *config.Config
}

func NewGenerator(cfg *config.Config) *Generator {
	return &Generator{cfg: cfg}
}

// Generate produces the complete nftables ruleset.
func (g *Generator) Generate() (*Ruleset, error) {
	var buf bytes.Buffer

	baseTemplate := `#!/usr/sbin/nft -f

flush ruleset

{{- if eq .Mode "two-nic"}}
define WAN_IF = {{ .WAN.Name }}
define LAN_IF = {{ .LAN.Name }}
{{- else}}
define TRUNK_IF = {{ .WAN.Name }}
{{- end}}

table inet aegis {
    {{- if eq .Mode "two-nic"}}
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        {{- range .DOSRules }}
        {{ . }}
        {{- end }}
        iif $LAN_IF tcp dport 22 accept
        iif $LAN_IF tcp dport {{ .Health.Port }} accept
        iif $LAN_IF tcp dport {{ .AdminPort }} accept
        iif $LAN_IF tcp dport {{ .Portal.Port }} accept
        iif $LAN_IF udp dport 53 accept
        iif $LAN_IF tcp dport 53 accept
        iif $LAN_IF udp dport 67 accept
        {{- range .CustomInputRules }}
        {{ . }}
        {{- end }}
        log prefix "nft-input-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        {{- range .FreeSiteForwardRules }}
        {{ . }}
        {{- end }}
        {{- range .CustomForwardRules }}
        {{ . }}
        {{- end }}
        iif $LAN_IF oif $WAN_IF accept
        log prefix "nft-forward-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oif $WAN_IF ip saddr {{ .LANSubnet }} masquerade
    }
    {{- else}}
    {{- range .VLANs}}
    define VLAN_{{ .ID }}_IF = "{{ $.WAN.Name }}.{{ .ID }}"
    {{- end}}

    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        {{- range .DOSRules }}
        {{ . }}
        {{- end }}
        {{- range .VLANs}}
        {{- if eq .Purpose "management"}}
        iif $VLAN_{{ .ID }}_IF tcp dport 22 accept
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.Health.Port }} accept
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.AdminPort }} accept
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.Portal.Port }} accept
        {{- end}}
        {{- end}}
        {{- range .VLANs}}
        {{- if ne .Purpose "management"}}
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.Portal.Port }} accept
        iif $VLAN_{{ .ID }}_IF udp dport 53 accept
        iif $VLAN_{{ .ID }}_IF tcp dport 53 accept
        iif $VLAN_{{ .ID }}_IF udp dport 67 accept
        {{- end}}
        {{- end}}
        {{- range .CustomInputRules }}
        {{ . }}
        {{- end }}
        log prefix "nft-input-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        {{- range .FreeSiteForwardRules }}
        {{ . }}
        {{- end }}
        {{- range .CustomForwardRules }}
        {{ . }}
        {{- end }}
        {{- range .VLANs}}
        {{- if eq .Purpose "guest"}}
        iif $VLAN_{{ .ID }}_IF oif {{ $.WAN.Name }} accept
        {{- else if eq .Purpose "corp"}}
        iif $VLAN_{{ .ID }}_IF oif {{ $.WAN.Name }} accept
        {{- else if eq .Purpose "management"}}
        iif $VLAN_{{ .ID }}_IF oif {{ $.WAN.Name }} accept
        {{- end}}
        {{- end}}
        log prefix "nft-forward-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        {{- range .VLANs}}
        oif {{ $.WAN.Name }} ip saddr {{ .Subnet }} masquerade
        {{- end}}
    }
    {{- end}}
}
`

	data := struct {
		Mode                 string
		WAN                  config.InterfaceConfig
		LAN                  config.InterfaceConfig
		LANSubnet            string
		VLANs                []config.VLANConfig
		Health               config.HealthConfig
		Portal               config.PortalConfig
		AdminPort            int
		CustomInputRules     []string
		CustomForwardRules   []string
		FreeSiteForwardRules []string
		DOSRules             []string
	}{
		Mode:                 g.cfg.Mode,
		WAN:                  g.cfg.WAN,
		LAN:                  g.cfg.LAN,
		VLANs:                g.cfg.VLANs,
		Health:               g.cfg.Health,
		Portal:               g.cfg.Portal,
		AdminPort:            g.cfg.AdminPort,
		CustomInputRules:     buildCustomFirewallRules(g.cfg, "input"),
		CustomForwardRules:   buildCustomFirewallRules(g.cfg, "forward"),
		FreeSiteForwardRules: buildFreeSiteRules(g.cfg),
		DOSRules:             buildDOSRules(g.cfg),
	}

	if g.cfg.Mode == "two-nic" && g.cfg.LAN.Address != "" {
		parts := strings.Split(g.cfg.LAN.Address, "/")
		if len(parts) == 2 {
			data.LANSubnet = parts[0] + "/" + parts[1]
		} else {
			data.LANSubnet = g.cfg.LAN.Address
		}
	}

	tmpl, err := template.New("nftables").Parse(baseTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return &Ruleset{Content: buf.String()}, nil
}

func buildCustomFirewallRules(cfg *config.Config, chain string) []string {
	if cfg == nil {
		return nil
	}
	out := []string{}
	for _, rule := range cfg.Network.Firewall.Rules {
		if !rule.Enabled || !strings.EqualFold(strings.TrimSpace(rule.Chain), chain) {
			continue
		}
		parts := []string{}
		if iface := strings.TrimSpace(rule.Interface); iface != "" {
			parts = append(parts, fmt.Sprintf(`iifname "%s"`, iface))
		}
		if source := strings.TrimSpace(rule.Source); source != "" {
			parts = append(parts, "ip saddr "+source)
		}
		if destination := strings.TrimSpace(rule.Destination); destination != "" {
			parts = append(parts, "ip daddr "+destination)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Protocol)) {
		case "tcp", "udp":
			parts = append(parts, fmt.Sprintf("meta l4proto %s", strings.ToLower(strings.TrimSpace(rule.Protocol))))
			if ports := formatPortMatcher(strings.TrimSpace(rule.Protocol), strings.TrimSpace(rule.Ports)); ports != "" {
				parts = append(parts, ports)
			}
		case "icmp":
			parts = append(parts, "ip protocol icmp")
		}
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action == "" {
			action = "accept"
		}
		parts = append(parts, action)
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func formatPortMatcher(protocol, raw string) string {
	if raw == "" {
		return ""
	}
	items := []string{}
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return fmt.Sprintf("%s dport %s", strings.ToLower(protocol), items[0])
	}
	return fmt.Sprintf("%s dport { %s }", strings.ToLower(protocol), strings.Join(items, ", "))
}

func buildFreeSiteRules(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := []string{}
	if cfg.Mode == "two-nic" {
		for _, site := range cfg.Network.Firewall.FreeSites {
			if site.Enabled && strings.EqualFold(strings.TrimSpace(site.Type), "cidr") {
				out = append(out, fmt.Sprintf("iif $LAN_IF ip daddr %s accept", strings.TrimSpace(site.Value)))
			}
		}
		return out
	}
	for _, vlan := range cfg.VLANs {
		for _, site := range cfg.Network.Firewall.FreeSites {
			if site.Enabled && strings.EqualFold(strings.TrimSpace(site.Type), "cidr") {
				out = append(out, fmt.Sprintf("iif $VLAN_%d_IF ip daddr %s accept", vlan.ID, strings.TrimSpace(site.Value)))
			}
		}
	}
	return out
}

func buildDOSRules(cfg *config.Config) []string {
	if cfg == nil || !cfg.Network.Firewall.DOSProtection.Enabled {
		return nil
	}
	dos := cfg.Network.Firewall.DOSProtection
	logPrefix := ""
	if dos.LogDrops {
		logPrefix = ` log prefix "aegis-dos: " level warn`
	}
	burst := dos.Burst
	if burst <= 0 {
		burst = 100
	}
	return []string{
		fmt.Sprintf("tcp flags syn limit rate over %s burst %d packets%s drop", dos.SYNRate, burst, logPrefix),
		fmt.Sprintf("ip protocol icmp limit rate over %s burst %d packets%s drop", dos.ICMPRate, burst, logPrefix),
		fmt.Sprintf("ct state new limit rate over %s burst %d packets%s drop", dos.ConnRate, burst, logPrefix),
	}
}

// ApplyRuleset writes the ruleset to a temporary file and loads it with nft.
func ApplyRuleset(ruleset string) error {
	cmd := exec.Command("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ruleset)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w\nOutput: %s", err, output)
	}
	return nil
}

// GetCurrentRuleset returns the current nftables ruleset.
func GetCurrentRuleset() (string, error) {
	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft list ruleset failed: %w", err)
	}
	return string(output), nil
}

// RestoreRuleset applies a previously saved ruleset.
func RestoreRuleset(ruleset string) error {
	return ApplyRuleset(ruleset)
}
