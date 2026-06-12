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
	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() {
		db.DB = previousDB
	})

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Secret:   "testing123",
			AuthPort: 1812,
			AcctPort: 1813,
			Clients: []config.RadiusClient{
				{IP: "192.168.1.10", Secret: "secret1", ShortName: "ap1", NASType: "aruba"},
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
			Vendor: config.RadiusVendorConfig{
				Enabled: true,
				Name:    "AegisNAS",
				ID:      55555,
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
	assert.Contains(t, fullCfg.ClientsConf, "nastype = aruba")
	assert.Contains(t, fullCfg.SitesDefault, "port = 1812")
	assert.Contains(t, fullCfg.ProxyConf, "home_server primary")
	assert.Contains(t, fullCfg.ProxyConf, "home_server secondary")
	assert.Contains(t, fullCfg.ProxyConf, "realm aegis-upstream")
	assert.Contains(t, fullCfg.SitesDefault, `Proxy-To-Realm := "aegis-upstream"`)
	assert.Contains(t, fullCfg.SitesInnerTunnel, `Proxy-To-Realm := "aegis-upstream"`)
	assert.Contains(t, fullCfg.Dictionary, "$INCLUDE aegisnas-vendor.dictionery")
	assert.Contains(t, fullCfg.VendorDictionary, "VENDOR AegisNAS 55555")
	assert.Contains(t, fullCfg.VendorDictionary, "ATTRIBUTE AegisNAS-Role 1 string")
	assert.Contains(t, fullCfg.VendorDictionary, "ATTRIBUTE AegisNAS-Bandwidth-Profile 2 string")
}

func TestGeneratorFallsBackToConfigClientsWhenDBNotMigrated(t *testing.T) {
	previousDB := db.DB
	tmpDB, err := os.CreateTemp("", "aegis-radius-*.db")
	require.NoError(t, err)
	tmpDB.Close()
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

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

func TestGeneratorUsesDBClientNASType(t *testing.T) {
	previousDB := db.DB
	tmpDB, err := os.CreateTemp("", "aegis-radius-db-*.db")
	require.NoError(t, err)
	tmpDB.Close()
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	require.NoError(t, db.Migrate())

	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled)
		VALUES ('aruba-controller', '10.20.0.2', 'ap-secret', 'aruba', 1)`)
	require.NoError(t, err)

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Secret:   "testing123",
			AuthPort: 1812,
			AcctPort: 1813,
		},
		Database: config.DatabaseConfig{
			Path: tmpDB.Name(),
		},
	}

	gen := NewGenerator(cfg)
	fullCfg, err := gen.Generate()
	require.NoError(t, err)

	assert.Contains(t, fullCfg.ClientsConf, "client aruba-controller")
	assert.Contains(t, fullCfg.ClientsConf, "ipaddr = 10.20.0.2")
	assert.Contains(t, fullCfg.ClientsConf, "nastype = aruba")
}

func TestGeneratorFallsBackWhenDBClientNASTypeColumnMissing(t *testing.T) {
	previousDB := db.DB
	tmpDB, err := os.CreateTemp("", "aegis-radius-legacy-*.db")
	require.NoError(t, err)
	tmpDB.Close()
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})

	_, err = db.DB.Exec(`CREATE TABLE radius_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		shortname TEXT UNIQUE NOT NULL,
		ipaddr TEXT NOT NULL,
		secret TEXT NOT NULL,
		enabled BOOLEAN DEFAULT 1
	)`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, enabled)
		VALUES ('legacy-ap', '10.20.0.3', 'ap-secret', 1)`)
	require.NoError(t, err)

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Secret:   "testing123",
			AuthPort: 1812,
			AcctPort: 1813,
		},
		Database: config.DatabaseConfig{
			Path: tmpDB.Name(),
		},
	}

	gen := NewGenerator(cfg)
	fullCfg, err := gen.Generate()
	require.NoError(t, err)

	assert.Contains(t, fullCfg.ClientsConf, "client legacy-ap")
	assert.Contains(t, fullCfg.ClientsConf, "nastype = other")
}
