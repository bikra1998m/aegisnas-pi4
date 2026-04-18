package radius

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestGenerator(t *testing.T) {
	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Secret:   "testing123",
			AuthPort: 1812,
			AcctPort: 1813,
			Clients: []config.RadiusClient{
				{IP: "192.168.1.10", Secret: "secret1", ShortName: "ap1"},
			},
			Upstream: config.RadiusUpstreamConfig{
				Enabled:           true,
				Realm:             "aegis-upstream",
				PoolStrategy:      "fail-over",
				StatusCheck:       "status-server",
				ResponseWindow:    20,
				ZombiePeriod:      40,
				ReviveInterval:    120,
				CheckInterval:     30,
				NumAnswersToAlive: 3,
				Servers: []config.RadiusHomeServer{
					{Name: "primary", Address: "10.0.0.10", Secret: "upstream-secret"},
					{Name: "secondary", Address: "10.0.0.11", Secret: "upstream-secret-2", AuthPort: 1912, AcctPort: 1913},
				},
			},
		},
		LDAP: config.LDAPConfig{
			Enabled: false,
		},
		Database: config.DatabaseConfig{
			Path: "/var/lib/aegisnas/data.db",
		},
	}

	gen := NewGenerator(cfg)
	fullCfg, err := gen.Generate()
	require.NoError(t, err)

	assert.Contains(t, fullCfg.ClientsConf, "client ap1")
	assert.Contains(t, fullCfg.ClientsConf, "ipaddr = 192.168.1.10")
	assert.Contains(t, fullCfg.SitesDefault, "port = 1812")
	assert.Contains(t, fullCfg.ProxyConf, "home_server primary")
	assert.Contains(t, fullCfg.ProxyConf, "home_server secondary")
	assert.Contains(t, fullCfg.ProxyConf, "realm aegis-upstream")
	assert.Contains(t, fullCfg.SitesDefault, `Proxy-To-Realm := "aegis-upstream"`)
	assert.Contains(t, fullCfg.SitesInnerTunnel, `Proxy-To-Realm := "aegis-upstream"`)
}

func TestGeneratorFallsBackToConfigClientsWhenDBNotMigrated(t *testing.T) {
	tmpDB, err := os.CreateTemp("", "aegis-radius-*.db")
	require.NoError(t, err)
	tmpDB.Close()
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	defer db.Close()

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			AuthPort: 1812,
			AcctPort: 1813,
			Clients: []config.RadiusClient{
				{IP: "127.0.0.1", Secret: "testing123", ShortName: "localhost"},
			},
		},
		Database: config.DatabaseConfig{
			Path: tmpDB.Name(),
		},
	}

	gen := NewGenerator(cfg)
	fullCfg, err := gen.Generate()
	require.NoError(t, err)
	assert.Contains(t, fullCfg.ClientsConf, "client localhost")
}
