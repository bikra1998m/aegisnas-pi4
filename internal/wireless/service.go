package wireless

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// WriteConfig generates and writes the hostapd configuration to the configured path.
func WriteConfig(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("config is required")
	}
	target := strings.TrimSpace(cfg.Wireless.HostapdConfigPath)
	if target == "" {
		return "", fmt.Errorf("wireless.hostapd_config_path is not configured")
	}
	text, err := GenerateHostapdConfig(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", fmt.Errorf("create hostapd config dir: %w", err)
	}
	if err := os.WriteFile(target, []byte(text), 0600); err != nil {
		return "", fmt.Errorf("write hostapd config: %w", err)
	}
	return target, nil
}

// RestartHostapd restarts the system hostapd service.
func RestartHostapd() error {
	cmd := exec.Command("systemctl", "restart", "hostapd")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart hostapd failed: %w\nOutput: %s", err, out)
	}
	return nil
}
