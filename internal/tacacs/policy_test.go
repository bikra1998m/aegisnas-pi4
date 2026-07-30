package tacacs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestEvaluateCommandUsesDenyBeforePermit(t *testing.T) {
	cfg := &config.Config{
		TACACS: config.TACACSConfig{
			Enabled:    true,
			Mode:       "enforce",
			FailClosed: true,
			CommandSets: []config.TACACSCommandSetConfig{{
				Name:            "network-admin",
				Enabled:         true,
				DefaultAction:   "deny",
				Permit:          []string{"show *", "configure *"},
				Deny:            []string{"configure terminal"},
				Roles:           []string{"netadmin"},
				PrivilegeLevels: []int{15},
				Vendors:         []string{"cisco"},
			}},
		},
	}
	req := CommandRequest{
		Username:       "alice",
		Role:           "netadmin",
		Tenant:         "corp",
		Client:         ClientIdentity{Name: "sw1", IP: "192.0.2.10", Vendor: "cisco", Known: true, Enabled: true},
		Command:        "configure terminal",
		PrivilegeLevel: 15,
		Authenticated:  true,
	}
	decision, err := EvaluateCommand(context.Background(), cfg, req, nil)
	require.NoError(t, err)
	assert.False(t, decision.Permit)
	assert.Equal(t, "network-admin", decision.MatchedCommandSet)
	assert.Contains(t, decision.Reason, "deny pattern")
}

func TestEvaluateCommandPermitsMatchedRoleVendorPrivilege(t *testing.T) {
	cfg := &config.Config{
		TACACS: config.TACACSConfig{
			Enabled:    true,
			Mode:       "enforce",
			FailClosed: true,
			CommandSets: []config.TACACSCommandSetConfig{{
				Name:            "ops-show",
				Enabled:         true,
				DefaultAction:   "deny",
				Permit:          []string{"show *"},
				Roles:           []string{"ops"},
				PrivilegeLevels: []int{5, 15},
			}},
		},
	}
	decision, err := EvaluateCommand(context.Background(), cfg, CommandRequest{
		Username:       "bob",
		Role:           "ops",
		Tenant:         "corp",
		Client:         ClientIdentity{Name: "sw2", IP: "192.0.2.11", Vendor: "arista", Known: true, Enabled: true},
		Command:        "show interfaces status",
		PrivilegeLevel: 5,
		Authenticated:  true,
	}, nil)
	require.NoError(t, err)
	assert.True(t, decision.Permit)
	assert.Equal(t, "permit", decision.Status)
	assert.Contains(t, decision.ResponseArgs, "priv-lvl=5")
}

func TestCommandFromArgs(t *testing.T) {
	command := CommandFromArgs([]string{"service=shell", "cmd=show", "cmd-arg=ip", "cmd-arg=route", "cmd-arg=<cr>"})
	assert.Equal(t, "show ip route", command)
}

func TestPrivilegeFromArgs(t *testing.T) {
	assert.Equal(t, 15, PrivilegeFromArgs([]string{"service=shell", "priv-lvl=15"}, 1))
	assert.Equal(t, 5, PrivilegeFromArgs([]string{"service=shell", "priv-lvl=20"}, 5))
	assert.Equal(t, 15, PrivilegeFromArgs(nil, 99))
}

func TestDisabledClientRejectedAtConnection(t *testing.T) {
	cfg := &config.Config{
		TACACS: config.TACACSConfig{
			Enabled:            true,
			AllowUnencrypted:   true,
			RequireKnownClient: false,
			Clients: []config.TACACSClientConfig{{
				Name:    "disabled-sw",
				Address: "192.0.2.10",
				Enabled: false,
			}},
		},
	}
	server := NewServer(cfg, nil)
	client, secret, err := server.clientForRemote(context.Background(), "192.0.2.10")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
	assert.Equal(t, "disabled-sw", client.Name)
	assert.Empty(t, secret)
}
