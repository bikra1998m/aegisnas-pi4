package acceptance

import (
	"os"
	"testing"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

var (
	testCfg    *config.Config
	testDBPath string
)

func TestMain(m *testing.M) {
	// Setup temporary database
	tmpFile, err := os.CreateTemp("", "aegisnas-test-*.db")
	if err != nil {
		panic(err)
	}
	testDBPath = tmpFile.Name()
	tmpFile.Close()

	// Load test configuration
	cfg, err := config.Load("../../configs/config.example.yaml")
	if err != nil {
		cfg = &config.Config{
			Mode: "two-nic",
			Database: config.DatabaseConfig{
				Path: testDBPath,
			},
			Logging: config.LoggingConfig{
				Level:  "debug",
				Output: "stdout",
			},
			Health: config.HealthConfig{Port: 18080},
			Radius: config.RadiusConfig{
				AuthPort: 11812,
				AcctPort: 11813,
				Secret:   "testing123",
			},
			Portal: config.PortalConfig{
				Enabled:  true,
				Port:     18081,
				Branding: "Test Portal",
			},
			LDAP: config.LDAPConfig{
				Enabled:      true,
				URL:          "ldap://127.0.0.1:1389",
				BaseDN:       "dc=test,dc=com",
				BindDN:       "cn=admin,dc=test,dc=com",
				BindPassword: "admin",
				UserFilter:   "(uid=%s)",
			},
			Policy: config.PolicyConfig{
				DefaultRole: "guest-basic",
			},
			AILite: config.AILiteConfig{
				Enabled: false,
			},
		}
	}
	testCfg = cfg
	testCfg.Database.Path = testDBPath

	// Initialize database
	if err := db.Init(testDBPath); err != nil {
		panic(err)
	}
	if err := db.Migrate(); err != nil {
		panic(err)
	}
	if err := db.Seed(); err != nil {
		panic(err)
	}

	// Start mock LDAP server
	startMockLDAP()

	// Start mock RADIUS server (for accounting tests)
	startMockRADIUS()

	// Run tests
	code := m.Run()

	// Cleanup
	stopMockLDAP()
	stopMockRADIUS()
	db.Close()
	os.Remove(testDBPath)

	os.Exit(code)
}
