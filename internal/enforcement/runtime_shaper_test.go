package enforcement

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBuildRuntimeShaperCommands(t *testing.T) {
	commands := buildRuntimeShaperCommands("eth1", []shapedSession{
		{
			SessionID:        "s1",
			IP:               "10.20.0.50",
			BandwidthProfile: "guest-basic",
			DownloadRateKbps: 2048,
			UploadRateKbps:   1024,
			BurstKB:          128,
		},
	})

	var rendered []string
	for _, command := range commands {
		rendered = append(rendered, strings.Join(command, " "))
	}
	preview := strings.Join(rendered, "\n")

	assert.Contains(t, preview, "tc qdisc replace dev eth1 root handle 1: htb default 999")
	assert.Contains(t, preview, "tc qdisc replace dev ifb-aegis0 root handle 2: htb default 999")
	assert.Contains(t, preview, "match ip dst 10.20.0.50/32 flowid 1:10")
	assert.Contains(t, preview, "match ip src 10.20.0.50/32 flowid 2:10")
	assert.Contains(t, preview, "rate 2048kbit ceil 2048kbit burst 128k cburst 128k")
	assert.Contains(t, preview, "rate 1024kbit ceil 1024kbit burst 128k cburst 128k")
}

func TestShapingInterface(t *testing.T) {
	assert.Equal(t, "eth1", ShapingInterface(&config.Config{
		Mode: "two-nic",
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: true,
		},
		LAN: config.InterfaceConfig{Name: "eth1"},
	}))
	assert.Equal(t, "eth0", ShapingInterface(&config.Config{
		Mode: "trunk",
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: true,
		},
		WAN: config.InterfaceConfig{Name: "eth0"},
	}))
	assert.Equal(t, "", ShapingInterface(&config.Config{}))
	assert.Equal(t, "", ShapingInterface(&config.Config{
		Mode: "two-nic",
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: false,
		},
		LAN: config.InterfaceConfig{Name: "eth1"},
	}))
}

func TestCanIgnoreShaperCommandError(t *testing.T) {
	assert.True(t, canIgnoreShaperCommandError([]string{"tc", "qdisc", "del", "dev", "eth1", "root"}, "RTNETLINK answers: No such file or directory"))
	assert.True(t, canIgnoreShaperCommandError([]string{"ip", "link", "add", runtimeIFBDevice, "type", "ifb"}, "RTNETLINK answers: File exists"))
	assert.False(t, canIgnoreShaperCommandError([]string{"modprobe", "ifb"}, "module missing"))
}

func TestRuntimeShapingEnabled(t *testing.T) {
	assert.True(t, RuntimeShapingEnabled(&config.Config{
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: true,
		},
	}))
	assert.False(t, RuntimeShapingEnabled(&config.Config{
		Policy: config.PolicyConfig{
			RuntimeShapingEnabled: false,
		},
	}))
}
