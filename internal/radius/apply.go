package radius

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
)

// ApplyConfig writes the generated FreeRADIUS configuration, validates it,
// and restarts the FreeRADIUS service on appliance builds.
func ApplyConfig(cfg *config.Config) error {
	if err := EnsureBootstrapCertificates(cfg.Radius.CertDir, cfg.Radius.NASIdentifier); err != nil {
		return fmt.Errorf("ensure EAP certificate material: %w", err)
	}

	gen := NewGenerator(cfg)
	fullCfg, err := gen.Generate()
	if err != nil {
		return err
	}

	raddb := ConfigDir()
	files := map[string]string{
		filepath.Join(raddb, "clients.conf"):                      fullCfg.ClientsConf,
		filepath.Join(raddb, "dictionary"):                        fullCfg.Dictionary,
		filepath.Join(raddb, VendorDictionaryFilename):            fullCfg.VendorDictionary,
		filepath.Join(raddb, "mods-enabled", "eap"):               fullCfg.EAPConf,
		filepath.Join(raddb, "mods-config", "files", "authorize"): fullCfg.Users,
		filepath.Join(raddb, "users"):                             fullCfg.Users,
		filepath.Join(raddb, "mods-enabled", "ldap"):              fullCfg.ModsLDAP,
		filepath.Join(raddb, "mods-enabled", "sql"):               fullCfg.ModsSQL,
		filepath.Join(raddb, "proxy.conf"):                        fullCfg.ProxyConf,
		filepath.Join(raddb, "sites-enabled", "default"):          fullCfg.SitesDefault,
		filepath.Join(raddb, "sites-enabled", "inner-tunnel"):     fullCfg.SitesInnerTunnel,
		filepath.Join(raddb, "sites-enabled", "aegis-radsec"):     fullCfg.RadSecSite,
	}

	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("create dir for %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	validateCmd := exec.Command("freeradius", "-XC")
	if out, err := validateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("FreeRADIUS config validation failed: %w\nOutput: %s", err, out)
	}

	restartCmd := exec.Command("systemctl", "restart", "freeradius")
	if out, err := restartCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart freeradius failed: %w\nOutput: %s", err, out)
	}

	logging.L().Info("FreeRADIUS configuration applied and service restarted")
	return nil
}

// ApplyVendorIdentityConfig applies FreeRADIUS state and restarts the AegisNAS
// broker so both packet paths switch PENs in the same maintenance operation.
func ApplyVendorIdentityConfig(cfg *config.Config) error {
	if err := ApplyConfig(cfg); err != nil {
		return err
	}
	restartCmd := exec.Command("systemctl", "restart", "aegis-radius")
	if out, err := restartCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart aegis-radius after vendor identity change: %w\nOutput: %s", err, out)
	}
	activeCmd := exec.Command("systemctl", "is-active", "--quiet", "aegis-radius")
	if out, err := activeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("aegis-radius is not active after vendor identity change: %w\nOutput: %s", err, out)
	}
	return nil
}

// ConfigDir returns the FreeRADIUS configuration directory for the appliance.
func ConfigDir() string {
	raddb := "/etc/freeradius/3.0"
	if _, err := os.Stat(raddb); os.IsNotExist(err) {
		return "/etc/freeradius"
	}
	return raddb
}
