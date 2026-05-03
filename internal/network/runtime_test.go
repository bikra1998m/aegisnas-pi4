package network

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStateHealthy(t *testing.T) {
	originalRunner := ipCommandRunner
	defer func() { ipCommandRunner = originalRunner }()

	ipCommandRunner = func(args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "addr show dev eth1":
			return "2: eth1    inet 192.168.50.1/24 brd 192.168.50.255 scope global eth1", nil
		case "route show default":
			return "default via 192.168.10.1 dev eth0 metric 5", nil
		case "route show 172.16.20.0/24":
			return "172.16.20.0/24 via 192.168.10.254 dev eth0 metric 20", nil
		default:
			return "", fmt.Errorf("unexpected ip call: %s", strings.Join(args, " "))
		}
	}

	report := ValidateState(AppliedState{
		Interfaces: []ManagedInterfaceState{{Name: "eth1", Address: "192.168.50.1/24"}},
		Gateways:   []GatewayState{{Name: "wan-default", Address: "192.168.10.1", Interface: "eth0", Metric: 5}},
		Routes:     []StaticRouteState{{Name: "branch", Destination: "172.16.20.0/24", Gateway: "192.168.10.254", Interface: "eth0", Metric: 20}},
	})

	require.True(t, report.Healthy)
	require.Len(t, report.Checks, 3)
	assert.Equal(t, "ok", report.Checks[0].Status)
	assert.Equal(t, "all validation checks passed", report.Summary())
}

func TestValidateStateFailuresSurfaceInSummary(t *testing.T) {
	originalRunner := ipCommandRunner
	defer func() { ipCommandRunner = originalRunner }()

	ipCommandRunner = func(args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "addr show dev eth1":
			return "2: eth1    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth1", nil
		case "route show default":
			return "", nil
		default:
			return "", fmt.Errorf("unexpected ip call: %s", strings.Join(args, " "))
		}
	}

	report := ValidateState(AppliedState{
		Interfaces: []ManagedInterfaceState{{Name: "eth1", Address: "192.168.50.1/24"}},
		Gateways:   []GatewayState{{Name: "wan-default", Address: "192.168.10.1", Interface: "eth0"}},
	})

	require.False(t, report.Healthy)
	require.Len(t, report.Checks, 2)
	assert.Contains(t, report.Summary(), "Interface eth1 is missing address 192.168.50.1/24.")
	assert.Contains(t, report.Summary(), "Default gateway wan-default via 192.168.10.1 dev eth0 is not active.")
}
