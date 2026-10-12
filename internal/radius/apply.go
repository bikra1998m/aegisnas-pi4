package radius

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"go.uber.org/zap"
)

var (
	runSystemCommand    = func(name string, args ...string) ([]byte, error) { return exec.Command(name, args...).CombinedOutput() }
	systemdPollInterval = 2 * time.Second
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
		filepath.Join(raddb, "mods-enabled", "mschap"):            fullCfg.ModsMSCHAP,
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

	if err := restartSystemdService("freeradius", 3*time.Minute); err != nil {
		return err
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
	if err := restartSystemdService("aegis-radius", 2*time.Minute); err != nil {
		return fmt.Errorf("restart aegis-radius after vendor identity change: %w", err)
	}
	return nil
}

func restartSystemdService(service string, timeout time.Duration) error {
	output, restartErr := runSystemCommand("systemctl", "restart", service)
	activeErr := waitForSystemdServiceActive(service, timeout)
	if restartErr != nil {
		if activeErr == nil {
			logging.L().Warn("systemd restart returned an error but service recovered",
				zap.String("service", service),
				zap.Error(restartErr),
				zap.ByteString("output", output))
			return nil
		}
		return fmt.Errorf("restart %s failed: %w\nOutput: %s\nActivation: %v", service, restartErr, output, activeErr)
	}
	if activeErr != nil {
		return fmt.Errorf("%s did not become active after restart: %w\nOutput: %s", service, activeErr, output)
	}
	return nil
}

func waitForSystemdServiceActive(service string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastState string
	var lastErr error
	for {
		output, err := runSystemCommand("systemctl", "is-active", service)
		state := strings.TrimSpace(string(output))
		if err == nil && state == "active" {
			return nil
		}
		lastState = state
		lastErr = err
		if !time.Now().Before(deadline) {
			if lastState == "" {
				lastState = "unknown"
			}
			return fmt.Errorf("%s is not active after %s; last state %q: %w", service, timeout, lastState, lastErr)
		}
		if systemdPollInterval > 0 {
			time.Sleep(systemdPollInterval)
		}
	}
}

// ConfigDir returns the FreeRADIUS configuration directory for the appliance.
func ConfigDir() string {
	raddb := "/etc/freeradius/3.0"
	if _, err := os.Stat(raddb); os.IsNotExist(err) {
		return "/etc/freeradius"
	}
	return raddb
}
