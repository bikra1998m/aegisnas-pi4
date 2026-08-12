package enforcement

import (
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
	assert.Equal(t, 1, plan.Summary.TaggedVLANCount)
	assert.Contains(t, plan.HostapdVLANFileText, "30 br-corp wlan0.30")
	assert.Contains(t, plan.HostapdVLANFileText, "60 br-vlan60 wlan0.60")
	assert.Contains(t, plan.CommandPreview, "ip link add link eth1 name eth1.30 type vlan id 30")
	assert.Contains(t, plan.CommandPreview, "ip link set dev eth1.30 master br-corp")
	assert.Contains(t, plan.FreeRADIUSAttributes, "Tunnel-Private-Group-Id")
	assert.Contains(t, plan.FreeRADIUSAttributes, "Extreme-Netlogin-Extended-Vlan")
	assert.NotEmpty(t, plan.PlanFingerprint)
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
