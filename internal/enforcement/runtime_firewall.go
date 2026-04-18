package enforcement

import (
	"database/sql"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// SyncRuntimeFirewall rebuilds the dynamic quarantine table from current active sessions.
// Sessions are considered quarantined when their role or Filter-Id contains "quarantine"
// or when they are assigned to VLAN 99.
func SyncRuntimeFirewall() error {
	if db.DB == nil {
		return nil
	}
	ips, err := quarantinedIPs()
	if err != nil {
		return err
	}

	var builder strings.Builder
	builder.WriteString("delete table inet aegis_runtime\n")
	builder.WriteString("table inet aegis_runtime {\n")
	builder.WriteString("    set quarantine_ipv4 {\n")
	builder.WriteString("        type ipv4_addr\n")
	if len(ips) > 0 {
		builder.WriteString("        elements = { ")
		builder.WriteString(strings.Join(ips, ", "))
		builder.WriteString(" }\n")
	}
	builder.WriteString("    }\n")
	builder.WriteString("    chain forward {\n")
	builder.WriteString("        type filter hook forward priority -5; policy accept;\n")
	builder.WriteString("        ip saddr @quarantine_ipv4 drop\n")
	builder.WriteString("        ip daddr @quarantine_ipv4 drop\n")
	builder.WriteString("    }\n")
	builder.WriteString("}\n")

	cmd := exec.Command("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(builder.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply runtime firewall: %w\nOutput: %s", err, out)
	}
	return nil
}

func quarantinedIPs() ([]string, error) {
	rows, err := db.DB.Query(`SELECT COALESCE(ip, ''), COALESCE(role, ''), COALESCE(filter_id, ''), COALESCE(vlan, 0)
		FROM sessions WHERE end_time IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	var ips []string
	for rows.Next() {
		var (
			ip       string
			role     string
			filterID string
			vlan     int
		)
		if err := rows.Scan(&ip, &role, &filterID, &vlan); err != nil {
			return nil, err
		}
		if !isQuarantined(role, filterID, vlan) {
			continue
		}
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed == nil || parsed.To4() == nil {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func isQuarantined(role, filterID string, vlan int) bool {
	if vlan == 99 {
		return true
	}
	role = strings.ToLower(strings.TrimSpace(role))
	filterID = strings.ToLower(strings.TrimSpace(filterID))
	return strings.Contains(role, "quarantine") || strings.Contains(filterID, "quarantine")
}

func SessionLooksQuarantined(role, filterID string, vlan int) bool {
	return isQuarantined(role, filterID, vlan)
}

func CountQuarantinedSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions
		WHERE end_time IS NULL
		AND (
			COALESCE(vlan, 0) = 99
			OR LOWER(COALESCE(role, '')) LIKE '%quarantine%'
			OR LOWER(COALESCE(filter_id, '')) LIKE '%quarantine%'
		)`).Scan(&count)
	return count, err
}

func CountActiveSessions() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE end_time IS NULL`).Scan(&count)
	return count, err
}

func CountSessionsByAuthMethod() (map[string]int, error) {
	if db.DB == nil {
		return map[string]int{}, nil
	}
	rows, err := db.DB.Query(`SELECT COALESCE(auth_method, 'unknown'), COUNT(*) FROM sessions
		WHERE end_time IS NULL GROUP BY COALESCE(auth_method, 'unknown')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	methods := map[string]int{}
	for rows.Next() {
		var (
			method string
			count  int
		)
		if err := rows.Scan(&method, &count); err != nil {
			return nil, err
		}
		methods[method] = count
	}
	return methods, rows.Err()
}

func CountPendingChanges() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM config_staging WHERE applied = 0`).Scan(&count)
	return count, err
}

func CountUnacknowledgedAlerts() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acknowledged = 0`).Scan(&count)
	return count, err
}

func CountUsers() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM local_users`).Scan(&count)
	return count, err
}

func CountEnabledRadiusClients() (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	var count int
	err := db.DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE enabled = 1`).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}
