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
	assert.Contains(t, fullCfg.Dictionary, "$INCLUDE dictionary.aegisnas")
	assert.Contains(t, fullCfg.VendorDictionary, "VENDOR AegisNAS 55555")
	assert.Contains(t, fullCfg.VendorDictionary, "Vendor ID source: placeholder")
	assert.Contains(t, fullCfg.VendorDictionary, "ATTRIBUTE AegisNAS-Role 1 string")
	assert.Contains(t, fullCfg.VendorDictionary, "ATTRIBUTE AegisNAS-Bandwidth-Profile 2 string")
}

func TestGeneratorRendersInboundAndOutboundRadSec(t *testing.T) {
	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = previousDB })

	cfg := &config.Config{Radius: config.RadiusConfig{
		Secret: "local-secret", AuthPort: 1812, AcctPort: 1813,
		RadSec: config.RadiusRadSecConfig{
			Enabled: true, ListenAddress: "0.0.0.0", Port: 2083,
			CertificateFile: "/radsec/server.crt", PrivateKeyFile: "/radsec/server.key",
			PrivateKeyPasswordEnv: "RADSEC_SERVER_KEY_PASSWORD", CAFile: "/radsec/ca.crt",
			CheckCRL: true, CheckAllCRL: true, CAPathReloadInterval: 3600,
			TLSMinVersion: "1.2", TLSMaxVersion: "1.3", CipherList: "DEFAULT@SECLEVEL=2",
			RadiusV11: "forbid", MaxConnections: 64, LifetimeSeconds: 86400, IdleTimeoutSeconds: 300,
		},
		Clients: []config.RadiusClient{
			{IP: "192.0.2.10", ShortName: "branch-nas", NASType: "cisco", Transport: "radsec", RadSecCertificateCN: "branch-nas.example.net"},
		},
		Upstream: config.RadiusUpstreamConfig{
			Enabled: true, Realm: "secure-realm", PoolStrategy: "fail-over", StatusCheck: "status-server",
			ResponseWindow: 20, ZombiePeriod: 40, ReviveInterval: 120, CheckInterval: 30, NumAnswersToAlive: 3,
			Servers: []config.RadiusHomeServer{{Name: "secure-aaa", Address: "203.0.113.20", Transport: "radsec", RadSec: config.RadiusRadSecPeerConfig{
				Port: 2083, ServerName: "aaa.example.net", CertificateFile: "/radsec/client.crt", PrivateKeyFile: "/radsec/client.key",
				PrivateKeyPasswordEnv: "RADSEC_CLIENT_KEY_PASSWORD", CAFile: "/radsec/ca.crt", CheckCRL: true,
				TLSMinVersion: "1.2", TLSMaxVersion: "1.3", CipherList: "DEFAULT@SECLEVEL=2", RadiusV11: "forbid",
				MaxConnections: 16, LifetimeSeconds: 86400, IdleTimeoutSeconds: 300,
			}}},
		},
	}, Database: config.DatabaseConfig{Path: "/var/lib/aegisnas/data.db"}}

	generated, err := NewGenerator(cfg).Generate()
	require.NoError(t, err)
	assert.NotContains(t, generated.ClientsConf, "branch-nas")
	assert.Contains(t, generated.RadSecSite, "type = auth+acct+coa")
	assert.Contains(t, generated.RadSecSite, "require_client_cert = yes")
	assert.Contains(t, generated.RadSecSite, "check_cert_cn = %{client:shortname}")
	assert.Contains(t, generated.RadSecSite, "shortname = branch-nas.example.net")
	assert.Contains(t, generated.RadSecSite, "private_key_password = $ENV{RADSEC_SERVER_KEY_PASSWORD}")
	assert.NotContains(t, generated.RadSecSite, "radiusv1_1")
	assert.Contains(t, generated.ProxyConf, "proto = tcp")
	assert.Contains(t, generated.ProxyConf, "secret = radsec")
	assert.Contains(t, generated.ProxyConf, "hostname = aaa.example.net")
	assert.Contains(t, generated.ProxyConf, "private_key_password = $ENV{RADSEC_CLIENT_KEY_PASSWORD}")
	assert.NotContains(t, generated.ProxyConf, "acctport = 2083")
}

func TestGeneratorEmitsRadiusV11OnlyWhenEnabled(t *testing.T) {
	cfg := &config.Config{Radius: config.RadiusConfig{AuthPort: 1812, AcctPort: 1813, RadSec: config.RadiusRadSecConfig{
		Enabled: true, ListenAddress: "::", Port: 2083, CertificateFile: "/server.crt", PrivateKeyFile: "/server.key",
		CAFile: "/ca.crt", TLSMinVersion: "1.3", TLSMaxVersion: "1.3", CipherList: "DEFAULT", RadiusV11: "require",
	}}}
	generated, err := NewGenerator(cfg).Generate()
	require.NoError(t, err)
	assert.Contains(t, generated.RadSecSite, "radiusv1_1 = require")
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

func TestGeneratorResolvesConfigSecretRefs(t *testing.T) {
	previousDB := db.DB
	db.DB = nil
	t.Cleanup(func() {
		db.DB = previousDB
	})
	t.Setenv("AEGIS_RADIUS_SECRET", "local-ref-secret")
	t.Setenv("AEGIS_UPSTREAM_SECRET", "upstream-ref-secret")

	cfg := &config.Config{
		Security: config.SecurityConfig{Secrets: config.SecretProviderConfig{Enabled: true, Providers: []string{"env"}, AllowInline: false, MaxSecretBytes: 128}},
		Radius: config.RadiusConfig{
			SecretRef: "env:AEGIS_RADIUS_SECRET",
			AuthPort:  1812,
			AcctPort:  1813,
			Clients: []config.RadiusClient{
				{IP: "192.168.1.10", SecretRef: "env:AEGIS_RADIUS_SECRET", ShortName: "ap1", NASType: "aruba"},
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
					{Name: "primary", Address: "10.0.0.10", SecretRef: "env:AEGIS_UPSTREAM_SECRET"},
				},
			},
		},
		LDAP: config.LDAPConfig{Enabled: false},
	}

	fullCfg, err := NewGenerator(cfg).Generate()
	require.NoError(t, err)
	assert.Contains(t, fullCfg.ClientsConf, "secret = local-ref-secret")
	assert.Contains(t, fullCfg.ProxyConf, "secret = upstream-ref-secret")
	assert.NotContains(t, fullCfg.ClientsConf, "env:AEGIS_RADIUS_SECRET")
}

func TestGeneratorResolvesDBClientSecretRef(t *testing.T) {
	previousDB := db.DB
	tmpDB, err := os.CreateTemp("", "aegis-radius-db-ref-*.db")
	require.NoError(t, err)
	tmpDB.Close()
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	require.NoError(t, db.Migrate())
	t.Setenv("AEGIS_DB_CLIENT_SECRET", "db-ref-secret")

	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, secret_ref, nas_type, enabled)
		VALUES ('ref-controller', '10.20.0.22', '', 'env:AEGIS_DB_CLIENT_SECRET', 'cisco', 1)`)
	require.NoError(t, err)

	cfg := &config.Config{
		Security: config.SecurityConfig{Secrets: config.SecretProviderConfig{Enabled: true, Providers: []string{"env"}, AllowInline: false, MaxSecretBytes: 128}},
		Radius:   config.RadiusConfig{SecretRef: "env:AEGIS_DB_CLIENT_SECRET", AuthPort: 1812, AcctPort: 1813},
		Database: config.DatabaseConfig{Path: tmpDB.Name()},
	}

	fullCfg, err := NewGenerator(cfg).Generate()
	require.NoError(t, err)
	assert.Contains(t, fullCfg.ClientsConf, "client ref-controller")
	assert.Contains(t, fullCfg.ClientsConf, "secret = db-ref-secret")
	assert.NotContains(t, fullCfg.ClientsConf, "env:AEGIS_DB_CLIENT_SECRET")
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

func TestGeneratorRendersLocalUserWithRoleACLPolicy(t *testing.T) {
	previousDB := db.DB
	tmpDB, err := os.CreateTemp("", "aegis-radius-acl-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpDB.Close())
	defer os.Remove(tmpDB.Name())

	require.NoError(t, db.Init(tmpDB.Name()))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Seed())

	_, err = db.DB.Exec(`INSERT INTO acl_policies (name, inbound_acl, outbound_acl, rules_json, enabled)
		VALUES ('guest-internet', 'guest-in', 'guest-out', '[{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"}]', 1)`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`UPDATE roles SET acl_policy_name = 'guest-internet' WHERE name = 'guest-basic'`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO local_users (username, password_hash, role) VALUES ('alice', '$2a$10$testhash', 'guest-basic')`)
	require.NoError(t, err)

	cfg := &config.Config{
		Radius: config.RadiusConfig{
			Secret:   "testing123",
			AuthPort: 1812,
			AcctPort: 1813,
			Vendor: config.RadiusVendorConfig{
				CompatibilityPacks: []string{"standard", "cisco", "aegisnas"},
			},
		},
		Database: config.DatabaseConfig{Path: tmpDB.Name()},
	}

	fullCfg, err := NewGenerator(cfg).Generate()
	require.NoError(t, err)
	assert.Contains(t, fullCfg.Users, `"alice" Crypt-Password := "$2a$10$testhash"`)
	assert.Contains(t, fullCfg.Users, `Filter-Id := "guest-basic",`)
	assert.Contains(t, fullCfg.Users, `Cisco-In-ACL := "guest-in",`)
	assert.Contains(t, fullCfg.Users, `Cisco-Out-ACL := "guest-out",`)
	assert.Contains(t, fullCfg.Users, `Cisco-AVPair := "ip:inacl#1=permit tcp any any eq 443",`)
	assert.Contains(t, fullCfg.Users, `AegisNAS-ACL-Name := "guest-internet",`)
	assert.NotContains(t, fullCfg.Users, `DEFAULT\tGroup`)
}
