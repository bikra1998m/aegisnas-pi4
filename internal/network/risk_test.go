package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestAssessApplyRiskRequiresConfirmationForPrimaryConnectivityChanges(t *testing.T) {
	cfg := &config.Config{}
	cfg.LAN.Name = "ens37"
	cfg.WAN.Name = "ens33"
	cfg.WAN.DHCP = false

	current := AppliedState{
		Interfaces: []ManagedInterfaceState{
			{Name: "ens37", Address: "192.168.50.1/24"},
			{Name: "ens33", Address: "10.0.0.10/24"},
		},
		Gateways: []GatewayState{
			{Name: "wan-default", Address: "10.0.0.1", Interface: "ens33"},
		},
	}
	desired := AppliedState{
		Interfaces: []ManagedInterfaceState{
			{Name: "ens37", Address: "192.168.60.1/24"},
			{Name: "ens33", Address: "10.0.1.10/24"},
		},
		Gateways: []GatewayState{
			{Name: "wan-default", Address: "10.0.1.1", Interface: "ens33"},
		},
	}

	risk := AssessApplyRisk(cfg, current, desired)

	assert.True(t, risk.RequiresConfirmation)
	assert.Equal(t, ApplyConfirmationPhrase, risk.ConfirmationPhrase)
	assert.NotEmpty(t, risk.Items)
	assert.Contains(t, risk.Summary, "confirmation")
}

func TestAssessApplyRiskWarnsOnRouteRemovalWithoutBlocking(t *testing.T) {
	cfg := &config.Config{}

	current := AppliedState{
		Routes: []StaticRouteState{
			{Name: "branch-a", Destination: "172.16.20.0/24", Gateway: "192.168.10.254", Interface: "ens33"},
		},
	}
	desired := AppliedState{}

	risk := AssessApplyRisk(cfg, current, desired)

	assert.False(t, risk.RequiresConfirmation)
	assert.Len(t, risk.Items, 1)
	assert.Equal(t, "warning", risk.Items[0].Level)
	assert.Contains(t, risk.Items[0].Message, "Static routes will be removed")
}
