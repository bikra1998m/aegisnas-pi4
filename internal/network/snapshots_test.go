package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiffState(t *testing.T) {
	current := AppliedState{
		Interfaces: []ManagedInterfaceState{{Name: "eth1", Address: "192.168.50.1/24"}},
		Gateways:   []GatewayState{{Name: "wan-default", Address: "192.168.10.1", Interface: "eth0"}},
		Routes:     []StaticRouteState{{Name: "old", Destination: "10.10.0.0/24", Gateway: "192.168.10.2", Interface: "eth0"}},
	}
	desired := AppliedState{
		Interfaces: []ManagedInterfaceState{{Name: "eth1", Address: "192.168.50.1/24"}, {Name: "eth2.50", Address: "10.50.0.1/24"}},
		Gateways:   []GatewayState{{Name: "wan-default", Address: "192.168.10.254", Interface: "eth0"}},
		Routes:     []StaticRouteState{{Name: "branch", Destination: "172.16.20.0/24", Gateway: "192.168.10.254", Interface: "eth0"}},
	}

	diff := DiffState(current, desired)

	assert.Equal(t, []string{"eth2.50 10.50.0.1/24"}, diff.InterfacesAdded)
	assert.Empty(t, diff.InterfacesRemoved)
	assert.Equal(t, []string{"wan-default via 192.168.10.254 dev eth0"}, diff.GatewaysAdded)
	assert.Equal(t, []string{"wan-default via 192.168.10.1 dev eth0"}, diff.GatewaysRemoved)
	assert.Equal(t, []string{"branch 172.16.20.0/24 via 192.168.10.254 dev eth0"}, diff.RoutesAdded)
	assert.Equal(t, []string{"old 10.10.0.0/24 via 192.168.10.2 dev eth0"}, diff.RoutesRemoved)
}
