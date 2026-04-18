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
        # Allow SSH and admin only from LAN (management implied)
        iif $LAN_IF tcp dport 22 accept
        iif $LAN_IF tcp dport {{ .Health.Port }} accept
        iif $LAN_IF tcp dport {{ .AdminPort }} accept
        iif $LAN_IF udp dport 53 accept
        iif $LAN_IF tcp dport 53 accept
        iif $LAN_IF udp dport 67 accept
        log prefix "nft-input-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
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
        # Management VLAN has full administrative access
        {{- range .VLANs}}
        {{- if eq .Purpose "management"}}
        iif $VLAN_{{ .ID }}_IF tcp dport 22 accept
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.Health.Port }} accept
        iif $VLAN_{{ .ID }}_IF tcp dport {{ $.AdminPort }} accept
        {{- end}}
        {{- end}}
        # Allow DNS and DHCP from guest/corp VLANs (but not SSH/admin)
        {{- range .VLANs}}
        {{- if ne .Purpose "management"}}
        iif $VLAN_{{ .ID }}_IF udp dport 53 accept
        iif $VLAN_{{ .ID }}_IF tcp dport 53 accept
        iif $VLAN_{{ .ID }}_IF udp dport 67 accept
        {{- end}}
        {{- end}}
        log prefix "nft-input-drop: " level warn flags all limit rate 5/minute
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        # Guest VLAN -> WAN only (no corp access)
        {{- range .VLANs}}
        {{- if eq .Purpose "guest"}}
        iif $VLAN_{{ .ID }}_IF oif {{ $.WAN.Name }} accept
        {{- else if eq .Purpose "corp"}}
        iif $VLAN_{{ .ID }}_IF oif {{ $.WAN.Name }} accept
        # Allow corp to guest? Deny by default; add explicit rule if needed.
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

	// Prepare template data
	data := struct {
		Mode      string
		WAN       config.InterfaceConfig
		LAN       config.InterfaceConfig
		LANSubnet string
		VLANs     []config.VLANConfig
		Health    config.HealthConfig
		AdminPort int
	}{
		Mode:      g.cfg.Mode,
		WAN:       g.cfg.WAN,
		LAN:       g.cfg.LAN,
		VLANs:     g.cfg.VLANs,
		Health:    g.cfg.Health,
		AdminPort: g.cfg.AdminPort,
	}

	// Extract LAN subnet from LAN address (if present)
	if g.cfg.Mode == "two-nic" && g.cfg.LAN.Address != "" {
		parts := strings.Split(g.cfg.LAN.Address, "/")
		if len(parts) == 2 {
			data.LANSubnet = parts[0] + "/" + parts[1]
		} else {
			data.LANSubnet = g.cfg.LAN.Address // fallback
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
