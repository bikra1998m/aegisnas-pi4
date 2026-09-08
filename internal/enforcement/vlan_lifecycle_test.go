package enforcement

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestBuildVLANLifecyclePlanCompilesPolicyAndHostapdInventory(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Policy: config.PolicyConfig{
			RuntimeVLANLifecycleEnabled: true,
		},
		Wireless: config.WirelessConfig{
			Enabled:             true,
			Interface:           "wlan0",
			HostapdConfigPath:   "/etc/hostapd/hostapd.conf",
			HostapdVLANFilePath: "/etc/hostapd/aegisnas-vlans.conf",
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 30, Bridge: "br-corp", DynamicVLAN: true},
				{Name: "Guest", AuthMode: "captive-portal", VLAN: 20, Bridge: "br-guest"},
			},
		},
		VLANs: []config.VLANConfig{
			{ID: 20, Name: "guest", Purpose: "guest"},
			{ID: 30, Name: "corp", Purpose: "corp"},
			{ID: 40, Name: "mgmt", Purpose: "management"},
		},
		Radius: config.RadiusConfig{
			Vendor: config.RadiusVendorConfig{
				ExtendedVLANMappings: []config.RadiusVendorExtendedVLANMapping{
					{Pack: productconfigs.VendorPackExtreme, Role: "voice", UntaggedVLAN: 50, TaggedVLANs: []int{60}},
				},
			},
		},
	}

	plan, err := buildVLANLifecyclePlan(cfg,
		[]vlanPolicySource{{Name: "contractor", VLAN: 70}},
		[]vlanPolicySource{{Name: "quarantine", VLAN: 80}},
	)
	require.NoError(t, err)

	assert.Equal(t, "ready", plan.Status)
	assert.Equal(t, "eth1", plan.ParentInterface)
	assert.Equal(t, 7, plan.Summary.VLANCount)
	assert.Equal(t, 7, plan.Summary.BridgeCount)
	assert.Equal(t, 7, plan.Summary.SubinterfaceCount)
	assert.Equal(t, 7, plan.Summary.HostapdVLANEntryCount)
	assert.Equal(t, 1, plan.Summary.HostapdDynamicSSIDCount)
	assert.Equal(t, 1, plan.Summary.HostapdFallbackSSIDCount)
	assert.Equal(t, 0, plan.Summary.HostapdFailClosedSSIDCount)
	assert.Equal(t, 1, plan.Summary.TaggedVLANCount)
	require.Len(t, plan.HostapdBindings, 1)
	assert.Equal(t, "Corp", plan.HostapdBindings[0].SSID)
	assert.Equal(t, 1, plan.HostapdBindings[0].DynamicVLANMode)
	assert.Equal(t, "optional_with_fallback", plan.HostapdBindings[0].DynamicVLANModeName)
	assert.Equal(t, "br-corp", plan.HostapdBindings[0].FallbackBridge)
	assert.Contains(t, plan.HostapdVLANFileText, "30 br-corp wlan0.30")
	assert.Contains(t, plan.HostapdVLANFileText, "60 br-vlan60 wlan0.60")
	assert.Contains(t, plan.CommandPreview, "ip link add link eth1 name eth1.30 type vlan id 30")
	assert.Contains(t, plan.CommandPreview, "ip link set dev eth1.30 master br-corp")
	assert.Empty(t, plan.CleanupCommands)
	assert.Empty(t, plan.RollbackCommands)
	assert.Contains(t, plan.FreeRADIUSAttributes, "Tunnel-Private-Group-Id")
	assert.Contains(t, plan.FreeRADIUSAttributes, "Extreme-Netlogin-Extended-Vlan")
	assert.NotEmpty(t, plan.PlanFingerprint)
}

func TestBuildVLANLifecyclePlanUsesFailClosedHostapdModeWithoutFallback(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Policy: config.PolicyConfig{
			RuntimeVLANLifecycleEnabled: true,
		},
		Wireless: config.WirelessConfig{
			Enabled:             true,
			Interface:           "wlan0",
			HostapdVLANFilePath: "/etc/hostapd/aegisnas-vlans.conf",
			SSIDs: []config.SSIDConfig{
				{Name: "Corp", AuthMode: "wpa2-enterprise", DynamicVLAN: true},
			},
		},
		VLANs: []config.VLANConfig{
			{ID: 30, Name: "corp", Purpose: "corp"},
		},
	}

	plan, err := buildVLANLifecyclePlan(cfg, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, "ready", plan.Status)
	assert.Equal(t, 1, plan.Summary.HostapdDynamicSSIDCount)
	assert.Equal(t, 0, plan.Summary.HostapdFallbackSSIDCount)
	assert.Equal(t, 1, plan.Summary.HostapdFailClosedSSIDCount)
	require.Len(t, plan.HostapdBindings, 1)
	assert.Equal(t, 2, plan.HostapdBindings[0].DynamicVLANMode)
	assert.Equal(t, "required_fail_closed", plan.HostapdBindings[0].DynamicVLANModeName)
	assert.Equal(t, "fail_closed", plan.HostapdBindings[0].Status)
	assert.Contains(t, plan.HostapdVLANFileText, "30 br-vlan30 wlan0.30")
	assert.True(t, containsLifecycleDiagnostic(plan.Diagnostics, "hostapd_dynamic_vlan_fail_closed"))
	assert.False(t, containsLifecycleDiagnosticSeverity(plan.Diagnostics, "error"))
}

func TestBuildVLANLifecyclePlanBlocksInvalidVLANAndUnsafeBridge(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		LAN:  config.InterfaceConfig{Name: "eth1"},
		Policy: config.PolicyConfig{
			RuntimeVLANLifecycleEnabled: true,
		},
		Wireless: config.WirelessConfig{
			Enabled: true,
			SSIDs: []config.SSIDConfig{
				{Name: "bad", AuthMode: "wpa2-enterprise", VLAN: 4095, Bridge: "br bad"},
			},
		},
	}

	plan, err := buildVLANLifecyclePlan(cfg, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, "blocked", plan.Status)
	assert.NotEmpty(t, plan.Diagnostics)
	assert.Equal(t, "invalid_vlan_id", plan.Diagnostics[0].Code)
}

func TestBuildVLANLifecyclePlanShortensLongSubinterfaceName(t *testing.T) {
	cfg := &config.Config{
		Mode: "two-nic",
		LAN:  config.InterfaceConfig{Name: "wlx001122334455"},
		Policy: config.PolicyConfig{
			RuntimeVLANLifecycleEnabled: true,
		},
		VLANs: []config.VLANConfig{
			{ID: 4094, Name: "lab", Purpose: "certification"},
		},
	}

	plan, err := buildVLANLifecyclePlan(cfg, nil, nil)
	require.NoError(t, err)

	require.Equal(t, "ready", plan.Status)
	require.Len(t, plan.Subinterfaces, 1)
	assert.LessOrEqual(t, len(plan.Subinterfaces[0].Name), 15)
	assert.NotEqual(t, "wlx001122334455.4094", plan.Subinterfaces[0].Name)
	assert.Contains(t, plan.CommandPreview, "ip link add link wlx001122334455 name "+plan.Subinterfaces[0].Name+" type vlan id 4094")
}

func TestVLANLifecycleCleanupAndRollbackDeltas(t *testing.T) {
	previous := VLANLifecyclePlan{
		Bridges: []VLANBridgePlan{
			{Name: "br-vlan20", VLAN: 20},
			{Name: "br-vlan30", VLAN: 30},
		},
		Subinterfaces: []VLANSubinterfacePlan{
			{Name: "eth1.20", VLAN: 20},
			{Name: "eth1.30", VLAN: 30},
		},
		Commands: [][]string{{"ip", "link", "add", "link", "eth1", "name", "eth1.20", "type", "vlan", "id", "20"}},
	}
	desired := VLANLifecyclePlan{
		Bridges: []VLANBridgePlan{
			{Name: "br-vlan30", VLAN: 30},
			{Name: "br-vlan40", VLAN: 40},
		},
		Subinterfaces: []VLANSubinterfacePlan{
			{Name: "eth1.30", VLAN: 30},
			{Name: "eth1.40", VLAN: 40},
		},
	}

	cleanup := lifecycleCommandText(buildVLANLifecycleCleanupCommands(previous, desired))
	rollback := lifecycleCommandText(buildVLANLifecycleRollbackCommands(desired, previous))

	assert.Contains(t, cleanup, "ip link set dev eth1.20 down")
	assert.Contains(t, cleanup, "ip link delete eth1.20")
	assert.Contains(t, cleanup, "ip link set dev br-vlan20 down")
	assert.Contains(t, cleanup, "ip link delete br-vlan20 type bridge")
	assert.NotContains(t, cleanup, "eth1.30")
	assert.Contains(t, rollback, "ip link set dev eth1.40 down")
	assert.Contains(t, rollback, "ip link delete eth1.40")
	assert.Contains(t, rollback, "ip link delete br-vlan40 type bridge")
	assert.Contains(t, rollback, "ip link add link eth1 name eth1.20 type vlan id 20")
}

func TestApplyVLANLifecycleArtifactRollsBackOnCommandFailure(t *testing.T) {
	var ran []string
	var writes []string
	runner := func(command []string) (string, error) {
		text := strings.Join(command, " ")
		ran = append(ran, text)
		if text == "ip fail" {
			return "simulated netlink failure", fmt.Errorf("netlink failed")
		}
		return "", nil
	}
	writer := func(path, text string, _ os.FileMode) error {
		writes = append(writes, path+"="+text)
		return nil
	}

	err := applyVLANLifecycleArtifactWithRollback(
		[][]string{{"ip", "ok"}, {"ip", "fail"}, {"ip", "not-run"}},
		"/tmp/new-vlans.conf",
		"new",
		[][]string{{"ip", "rollback"}},
		"/tmp/old-vlans.conf",
		"old",
		runner,
		writer,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip fail failed")
	assert.Equal(t, []string{"ip ok", "ip fail", "ip rollback"}, ran)
	assert.Equal(t, []string{"/tmp/old-vlans.conf=old"}, writes)
}

func containsLifecycleDiagnostic(diagnostics []VLANLifecycleDiagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func containsLifecycleDiagnosticSeverity(diagnostics []VLANLifecycleDiagnostic, severity string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == severity {
			return true
		}
	}
	return false
}

func lifecycleCommandText(commands [][]string) string {
	lines := make([]string, 0, len(commands))
	for _, command := range commands {
		lines = append(lines, strings.Join(command, " "))
	}
	return strings.Join(lines, "\n")
}
