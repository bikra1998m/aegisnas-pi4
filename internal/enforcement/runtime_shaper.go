package enforcement

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	runtimeShaperComponent = "runtime_shaper"
	runtimeIFBDevice       = "ifb-aegis0"
	defaultShaperRateKbit  = 1000000
	defaultBurstKB         = 64
)

type shapedSession struct {
	SessionID        string
	IP               string
	BandwidthProfile string
	DownloadRateKbps int
	UploadRateKbps   int
	BurstKB          int
}

func SyncRuntimeEnforcement(cfg *config.Config) error {
	var errs []string
	if err := SyncRuntimeFirewall(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := SyncRuntimeShaping(cfg); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

func SyncRuntimeShaping(cfg *config.Config) error {
	if !RuntimeShapingEnabled(cfg) {
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "disabled", "Runtime shaping is disabled by deployment or policy config", map[string]any{
			"interface":       "",
			"shaped_sessions": 0,
			"ifb_device":      runtimeIFBDevice,
		})
		return nil
	}

	interfaceName := ShapingInterface(cfg)
	if interfaceName == "" {
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "disabled", "Runtime shaping is disabled because no downstream interface is configured", map[string]any{
			"interface":       "",
			"shaped_sessions": 0,
			"ifb_device":      runtimeIFBDevice,
		})
		return nil
	}

	sessions, err := loadShapedSessions()
	if err != nil {
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "down", err.Error(), map[string]any{
			"interface":       interfaceName,
			"shaped_sessions": 0,
			"ifb_device":      runtimeIFBDevice,
		})
		return err
	}

	if err := applyRuntimeShaper(interfaceName, sessions); err != nil {
		_ = db.UpsertRuntimeStatus(runtimeShaperComponent, "down", err.Error(), map[string]any{
			"interface":       interfaceName,
			"shaped_sessions": len(sessions),
			"ifb_device":      runtimeIFBDevice,
		})
		return err
	}

	message := "Runtime bandwidth shaping applied"
	status := "ok"
	if len(sessions) == 0 {
		message = "Runtime bandwidth shaping is configured but there are no active shaped sessions"
	}
	_ = db.UpsertRuntimeStatus(runtimeShaperComponent, status, message, map[string]any{
		"interface":       interfaceName,
		"shaped_sessions": len(sessions),
		"ifb_device":      runtimeIFBDevice,
	})
	return nil
}

func applyRuntimeShaper(interfaceName string, sessions []shapedSession) error {
	commands := buildRuntimeShaperCommands(interfaceName, sessions)
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}
		cmd := exec.Command(command[0], command[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			if canIgnoreShaperCommandError(command, string(output)) {
				continue
			}
			return fmt.Errorf("%s failed: %w\nOutput: %s", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func buildRuntimeShaperCommands(interfaceName string, sessions []shapedSession) [][]string {
	if strings.TrimSpace(interfaceName) == "" {
		return nil
	}

	commands := [][]string{
		{"modprobe", "ifb"},
		{"ip", "link", "add", runtimeIFBDevice, "type", "ifb"},
		{"ip", "link", "set", "dev", runtimeIFBDevice, "up"},
		{"tc", "qdisc", "del", "dev", interfaceName, "root"},
		{"tc", "qdisc", "del", "dev", interfaceName, "ingress"},
		{"tc", "qdisc", "del", "dev", runtimeIFBDevice, "root"},
		{"tc", "qdisc", "replace", "dev", interfaceName, "root", "handle", "1:", "htb", "default", "999"},
		{"tc", "class", "replace", "dev", interfaceName, "parent", "1:", "classid", "1:1", "htb", "rate", fmt.Sprintf("%dkbit", defaultShaperRateKbit), "ceil", fmt.Sprintf("%dkbit", defaultShaperRateKbit)},
		{"tc", "class", "replace", "dev", interfaceName, "parent", "1:1", "classid", "1:999", "htb", "rate", fmt.Sprintf("%dkbit", defaultShaperRateKbit), "ceil", fmt.Sprintf("%dkbit", defaultShaperRateKbit)},
		{"tc", "qdisc", "replace", "dev", interfaceName, "handle", "ffff:", "ingress"},
		{"tc", "filter", "replace", "dev", interfaceName, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", runtimeIFBDevice},
		{"tc", "qdisc", "replace", "dev", runtimeIFBDevice, "root", "handle", "2:", "htb", "default", "999"},
		{"tc", "class", "replace", "dev", runtimeIFBDevice, "parent", "2:", "classid", "2:1", "htb", "rate", fmt.Sprintf("%dkbit", defaultShaperRateKbit), "ceil", fmt.Sprintf("%dkbit", defaultShaperRateKbit)},
		{"tc", "class", "replace", "dev", runtimeIFBDevice, "parent", "2:1", "classid", "2:999", "htb", "rate", fmt.Sprintf("%dkbit", defaultShaperRateKbit), "ceil", fmt.Sprintf("%dkbit", defaultShaperRateKbit)},
	}

	for index, session := range sessions {
		classID := 10 + index
		burstKB := session.BurstKB
		if burstKB <= 0 {
			burstKB = defaultBurstKB
		}
		downloadRate := session.DownloadRateKbps
		if downloadRate <= 0 {
			downloadRate = defaultShaperRateKbit
		}
		uploadRate := session.UploadRateKbps
		if uploadRate <= 0 {
			uploadRate = defaultShaperRateKbit
		}

		commands = append(commands,
			[]string{"tc", "class", "replace", "dev", interfaceName, "parent", "1:1", "classid", fmt.Sprintf("1:%d", classID), "htb", "rate", fmt.Sprintf("%dkbit", downloadRate), "ceil", fmt.Sprintf("%dkbit", downloadRate), "burst", fmt.Sprintf("%dk", burstKB), "cburst", fmt.Sprintf("%dk", burstKB)},
			[]string{"tc", "filter", "replace", "dev", interfaceName, "protocol", "ip", "parent", "1:", "prio", "10", "u32", "match", "ip", "dst", session.IP + "/32", "flowid", fmt.Sprintf("1:%d", classID)},
			[]string{"tc", "class", "replace", "dev", runtimeIFBDevice, "parent", "2:1", "classid", fmt.Sprintf("2:%d", classID), "htb", "rate", fmt.Sprintf("%dkbit", uploadRate), "ceil", fmt.Sprintf("%dkbit", uploadRate), "burst", fmt.Sprintf("%dk", burstKB), "cburst", fmt.Sprintf("%dk", burstKB)},
			[]string{"tc", "filter", "replace", "dev", runtimeIFBDevice, "protocol", "ip", "parent", "2:", "prio", "10", "u32", "match", "ip", "src", session.IP + "/32", "flowid", fmt.Sprintf("2:%d", classID)},
		)
	}

	return commands
}

func loadShapedSessions() ([]shapedSession, error) {
	if db.DB == nil {
		return nil, nil
	}

	rows, err := db.DB.Query(`SELECT s.id, COALESCE(s.ip, ''), COALESCE(s.bandwidth_profile, ''), bp.download_rate_kbps, bp.upload_rate_kbps, COALESCE(bp.burst_kb, 0)
		FROM sessions s
		JOIN bandwidth_profiles bp ON bp.name = s.bandwidth_profile
		WHERE s.end_time IS NULL
		ORDER BY s.start_time, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []shapedSession
	for rows.Next() {
		var session shapedSession
		if err := rows.Scan(&session.SessionID, &session.IP, &session.BandwidthProfile, &session.DownloadRateKbps, &session.UploadRateKbps, &session.BurstKB); err != nil {
			return nil, err
		}
		session.IP = strings.TrimSpace(session.IP)
		if session.IP == "" {
			continue
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func ShapingInterface(cfg *config.Config) string {
	return config.ShapingInterface(cfg)
}

func RuntimeShapingEnabled(cfg *config.Config) bool {
	return config.RuntimeShapingEnabled(cfg)
}

func CountShapedSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*)
		FROM sessions s
		JOIN bandwidth_profiles bp ON bp.name = s.bandwidth_profile
		WHERE s.end_time IS NULL
		AND COALESCE(TRIM(s.ip), '') <> ''`).Scan(&count)
	return count, err
}

func BuildRuntimeShaperPreview(cfg *config.Config) ([]string, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	interfaceName := ShapingInterface(cfg)
	if interfaceName == "" {
		return nil, nil
	}
	sessions, err := loadShapedSessions()
	if err != nil {
		return nil, err
	}
	raw := buildRuntimeShaperCommands(interfaceName, sessions)
	preview := make([]string, 0, len(raw))
	for _, command := range raw {
		preview = append(preview, strings.Join(command, " "))
	}
	return preview, nil
}

func ClassIDForSession(index int) string {
	return strconv.Itoa(10 + index)
}

func canIgnoreShaperCommandError(command []string, output string) bool {
	if len(command) >= 3 && command[0] == "tc" && command[1] == "qdisc" && command[2] == "del" {
		return true
	}
	if len(command) >= 4 && command[0] == "ip" && command[1] == "link" && command[2] == "add" {
		return strings.Contains(strings.ToLower(output), "file exists")
	}
	return false
}
