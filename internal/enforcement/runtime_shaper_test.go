package enforcement

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
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
	assert.Contains(t, preview, "parent 1:1 classid 1:10 htb rate 2048kbit ceil 2048kbit")
	assert.Contains(t, preview, "parent 1:10 classid 1:1000 htb rate 2048kbit ceil 2048kbit")
	assert.Contains(t, preview, "parent 2:10 classid 2:1000 htb rate 1024kbit ceil 1024kbit")
	assert.Contains(t, preview, "match ip dst 10.20.0.50/32 flowid 1:1000")
	assert.Contains(t, preview, "match ip src 10.20.0.50/32 flowid 2:1000")
	assert.Contains(t, preview, "rate 2048kbit ceil 2048kbit burst 128k cburst 128k")
	assert.Contains(t, preview, "rate 1024kbit ceil 1024kbit burst 128k cburst 128k")
}

func TestBuildRuntimeQoSPlanAppliesAggregateSchedulerOverrides(t *testing.T) {
	voiceDSCP := 46
	plan, err := buildRuntimeQoSPlan(&config.Config{
		Policy: config.PolicyConfig{RuntimeShapingEnabled: true},
		LAN:    config.InterfaceConfig{Name: "eth1"},
	}, []shapedSession{
		{SessionID: "s1", Username: "alice", IP: "10.20.0.50", BandwidthProfile: "voice", DownloadRateKbps: 2048, UploadRateKbps: 1024, BurstKB: 64},
		{SessionID: "s2", Username: "bob", IP: "10.20.0.51", BandwidthProfile: "voice", DownloadRateKbps: 2048, UploadRateKbps: 1024, BurstKB: 64},
	}, []db.QoSSchedulerProfile{
		{ProfileName: "voice", Enabled: true, Scheduler: "htb", Priority: 1, DSCPMark: &voiceDSCP, DownloadCeilRateKbps: 3000, UploadCeilRateKbps: 1500, BurstKB: 128, CBurstKB: 128},
	})
	require.NoError(t, err)
	assert.Equal(t, "ready", plan.Status)
	assert.Equal(t, 1, plan.Summary.ProfileCount)
	assert.Equal(t, 6, plan.Summary.ClassCount)
	assert.Equal(t, 2, plan.Summary.ShapedSessions)
	assert.Equal(t, 3000, plan.Summary.DownloadAggregateKbps)
	assert.Equal(t, 1500, plan.Summary.UploadAggregateKbps)
	assert.NotEmpty(t, plan.PlanFingerprint)

	preview := strings.Join(plan.CommandPreview, "\n")
	assert.Contains(t, preview, "parent 1:1 classid 1:10 htb rate 3000kbit ceil 3000kbit burst 128k cburst 128k prio 1")
	assert.Contains(t, preview, "parent 1:10 classid 1:1000 htb rate 2048kbit ceil 3000kbit")
	assert.Contains(t, preview, "parent 1:10 classid 1:1001 htb rate 2048kbit ceil 3000kbit")
	assert.Equal(t, "1:1000", plan.Sessions[0].DownloadClassID)
	assert.Equal(t, "2:1001", plan.Sessions[1].UploadClassID)
}

func TestBuildRuntimeQoSPlanShapesIPv6OnlySessions(t *testing.T) {
	plan, err := buildRuntimeQoSPlan(&config.Config{
		Policy: config.PolicyConfig{RuntimeShapingEnabled: true},
		LAN:    config.InterfaceConfig{Name: "eth1"},
	}, []shapedSession{
		{SessionID: "s-ipv6", Username: "alice", IPv6: "2001:db8::50", BandwidthProfile: "guest", DownloadRateKbps: 50000, UploadRateKbps: 20000, BurstKB: 128},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "ready", plan.Status)
	assert.Equal(t, 1, plan.Summary.ShapedSessions)
	assert.Equal(t, 0, plan.Summary.IPv4Sessions)
	assert.Equal(t, 1, plan.Summary.IPv6Sessions)
	assert.Equal(t, 1, plan.Summary.IPv6OnlySessions)
	require.Len(t, plan.Sessions, 1)
	assert.Equal(t, "shaped", plan.Sessions[0].Status)
	assert.Equal(t, "1:1000", plan.Sessions[0].DownloadClassID)
	assert.Equal(t, "2:1000", plan.Sessions[0].UploadClassID)

	preview := strings.Join(plan.CommandPreview, "\n")
	assert.Contains(t, preview, "protocol ipv6 flower action mirred egress redirect dev ifb-aegis0")
	assert.Contains(t, preview, "protocol ipv6 parent 1: prio 14 flower dst_ip 2001:db8::50 flowid 1:1000")
	assert.Contains(t, preview, "protocol ipv6 parent 2: prio 14 flower src_ip 2001:db8::50 flowid 2:1000")
	assert.NotContains(t, preview, "ipv6_shaping_deferred")
	require.Len(t, plan.Classes, 4)
	assert.Equal(t, "ipv6", plan.Classes[2].AddressFamily)
	assert.Equal(t, "2001:db8::50", plan.Classes[2].IPv6)
}

func TestBuildRuntimeQoSPlanShapesDualStackSessions(t *testing.T) {
	plan, err := buildRuntimeQoSPlan(&config.Config{
		Policy: config.PolicyConfig{RuntimeShapingEnabled: true},
		LAN:    config.InterfaceConfig{Name: "eth1"},
	}, []shapedSession{
		{SessionID: "s-dual", Username: "alice", IP: "192.0.2.50", IPv6: "2001:db8::51", BandwidthProfile: "guest", DownloadRateKbps: 50000, UploadRateKbps: 20000, BurstKB: 128},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "ready", plan.Status)
	assert.Equal(t, 1, plan.Summary.IPv4Sessions)
	assert.Equal(t, 1, plan.Summary.IPv6Sessions)
	assert.Equal(t, 0, plan.Summary.IPv6OnlySessions)
	preview := strings.Join(plan.CommandPreview, "\n")
	assert.Contains(t, preview, "match ip dst 192.0.2.50/32 flowid 1:1000")
	assert.Contains(t, preview, "flower dst_ip 2001:db8::51 flowid 1:1000")
	require.Len(t, plan.Classes, 4)
	assert.Equal(t, "dual_stack", plan.Classes[2].AddressFamily)
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
