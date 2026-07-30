package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidationTACACS(t *testing.T) {
	valid := TACACSConfig{
		Enabled:              true,
		Mode:                 "enforce",
		SecretRef:            "env:AEGIS_SECRET_TACACS_SHARED",
		MaxPacketBytes:       65535,
		MaxArgs:              64,
		MaxCommandBytes:      512,
		MaxConnections:       256,
		IdleTimeoutSeconds:   300,
		ReadTimeoutSeconds:   15,
		AuditEnabled:         true,
		RetentionLimit:       10000,
		RequireKnownClient:   true,
		AuthenticationSource: "local",
		Clients: []TACACSClientConfig{{
			Name:      "core-sw1",
			Address:   "192.0.2.10",
			SecretRef: "env:AEGIS_SECRET_TACACS_SW1",
			Vendor:    "cisco",
			Enabled:   true,
		}},
		CommandSets: []TACACSCommandSetConfig{{
			Name:            "ops-show",
			Enabled:         true,
			DefaultAction:   "deny",
			Permit:          []string{"show *"},
			Deny:            []string{"show running-config"},
			Roles:           []string{"ops"},
			PrivilegeLevels: []int{5, 15},
			Vendors:         []string{"cisco", "arista"},
		}},
		VendorProfiles: []TACACSVendorProfile{{
			Vendor:          "cisco",
			PrivilegeModel:  "enable-level",
			CommandServices: []string{"shell"},
			Enabled:         true,
		}},
	}
	require.NoError(t, validateTACACSConfig(valid))

	badPrivilege := valid
	badPrivilege.CommandSets = append([]TACACSCommandSetConfig(nil), valid.CommandSets...)
	badPrivilege.CommandSets[0].PrivilegeLevels = []int{16}
	assert.ErrorContains(t, validateTACACSConfig(badPrivilege), "privilege_levels")

	badPattern := valid
	badPattern.CommandSets = append([]TACACSCommandSetConfig(nil), valid.CommandSets...)
	badPattern.CommandSets[0].Permit = []string{"show\nrunning-config"}
	assert.ErrorContains(t, validateTACACSConfig(badPattern), "control character")

	noClients := valid
	noClients.Clients = nil
	assert.ErrorContains(t, validateTACACSConfig(noClients), "require_known_client")

	unknownClientSecret := valid
	unknownClientSecret.SecretRef = ""
	unknownClientSecret.Clients = []TACACSClientConfig{{
		Name:    "core-sw1",
		Address: "192.0.2.10",
		Enabled: true,
	}}
	assert.ErrorContains(t, validateTACACSConfig(unknownClientSecret), "requires secret or secret_ref")
}
