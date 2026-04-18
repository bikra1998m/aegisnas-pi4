package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func Seed() error {
	db := GetDB()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Roles
	roles := []struct {
		name, desc string
		vlan       sql.NullInt32
		bwProfile  sql.NullString
		timeout    sql.NullInt32
		idle       sql.NullInt32
		portal     sql.NullString
		priority   int
	}{
		{"guest-basic", "Guest portal user with modest timeout", sql.NullInt32{Int32: 20, Valid: true}, sql.NullString{String: "10m-down-5m-up", Valid: true}, sql.NullInt32{Int32: 3600, Valid: true}, sql.NullInt32{Int32: 600, Valid: true}, sql.NullString{String: "default-guest", Valid: true}, 10},
		{"guest-premium", "Guest portal user with higher bandwidth", sql.NullInt32{Int32: 20, Valid: true}, sql.NullString{String: "50m-down-20m-up", Valid: true}, sql.NullInt32{Int32: 7200, Valid: true}, sql.NullInt32{Int32: 1200, Valid: true}, sql.NullString{String: "default-guest", Valid: true}, 20},
		{"corp-standard", "Enterprise authenticated user", sql.NullInt32{Int32: 30, Valid: true}, sql.NullString{String: "100m-down-50m-up", Valid: true}, sql.NullInt32{Int32: 28800, Valid: true}, sql.NullInt32{Int32: 3600, Valid: true}, sql.NullString{String: "", Valid: false}, 30},
		{"admin", "Administrator role (management VLAN)", sql.NullInt32{Int32: 40, Valid: true}, sql.NullString{String: "unlimited", Valid: true}, sql.NullInt32{Int32: 0, Valid: false}, sql.NullInt32{Int32: 0, Valid: false}, sql.NullString{String: "", Valid: false}, 100},
	}

	for _, r := range roles {
		_, err := tx.Exec(`INSERT OR IGNORE INTO roles (name, description, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, priority)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			r.name, r.desc, r.vlan, r.bwProfile, r.timeout, r.idle, r.portal, r.priority)
		if err != nil {
			return fmt.Errorf("seed role %s: %w", r.name, err)
		}
	}

	// Policy Rules
	policyRules := []struct {
		name        string
		desc        string
		priority    int
		conditions  string
		action      string
		vlan        interface{}
		bwProfile   interface{}
		sessionTime interface{}
		idleTime    interface{}
		portal      interface{}
	}{
		{
			"preauth-guest",
			"Unauthenticated users redirected to portal",
			100,
			`{"authenticated": false}`,
			"allow",
			20,
			nil,
			3600,
			600,
			"default-guest",
		},
		{
			"default-authenticated",
			"Authenticated users default access",
			90,
			`{"authenticated": true}`,
			"allow",
			nil,
			nil,
			28800,
			3600,
			nil,
		},
		{
			"voucher-users",
			"Voucher-based users",
			80,
			`{"auth_method": "voucher"}`,
			"allow",
			20,
			"10m-down-5m-up",
			7200,
			600,
			nil,
		},
		{
			"deny-blacklist",
			"Blocked users",
			1000,
			`{"blacklisted": true}`,
			"deny",
			nil,
			nil,
			nil,
			nil,
			nil,
		},
		{
			"quarantine-infected",
			"Infected or suspicious clients",
			900,
			`{"quarantine": true}`,
			"quarantine",
			99,
			"1m-down-1m-up",
			1800,
			300,
			nil,
		},
		{
			"admin-full-access",
			"Admin override rule",
			2000,
			`{"role": "admin"}`,
			"allow",
			40,
			"unlimited",
			0,
			0,
			nil,
		},
	}

	for _, p := range policyRules {
		_, err := tx.Exec(`
		INSERT OR IGNORE INTO policy_rules 
		(name, description, priority, match_conditions, action, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.name,
			p.desc,
			p.priority,
			p.conditions,
			p.action,
			p.vlan,
			p.bwProfile,
			p.sessionTime,
			p.idleTime,
			p.portal,
		)
		if err != nil {
			return fmt.Errorf("seed policy rule %s: %w", p.name, err)
		}
	}

	// Bandwidth profiles
	bwProfiles := []struct {
		name     string
		down, up int
		burst    int
	}{
		{"10m-down-5m-up", 10000, 5000, 15000},
		{"50m-down-20m-up", 50000, 20000, 75000},
		{"100m-down-50m-up", 100000, 50000, 150000},
		{"unlimited", 0, 0, 0},
	}

	for _, b := range bwProfiles {
		_, err := tx.Exec(`INSERT OR IGNORE INTO bandwidth_profiles (name, download_rate_kbps, upload_rate_kbps, burst_kb)
			VALUES (?, ?, ?, ?)`, b.name, b.down, b.up, b.burst)
		if err != nil {
			return fmt.Errorf("seed bandwidth profile %s: %w", b.name, err)
		}
	}

	// Portal profile
	_, err = tx.Exec(`INSERT OR IGNORE INTO portal_profiles (name, branding, success_url, logout_url)
		VALUES ('default-guest', 'AegisNAS Guest WiFi', 'https://www.example.com', 'https://www.example.com')`)
	if err != nil {
		return fmt.Errorf("seed portal profile: %w", err)
	}

	// Identity source
	_, err = tx.Exec(`INSERT OR IGNORE INTO identity_sources (name, type, enabled, priority, config)
		VALUES ('local', 'local', 1, 10, '{}')`)
	if err != nil {
		return fmt.Errorf("seed identity source: %w", err)
	}

	// Seed LDAP identity source (disabled by default) with example group-role mapping
	_, err = tx.Exec(`INSERT OR IGNORE INTO identity_sources (name, type, enabled, priority, config)
		VALUES ('ldap-primary', 'ldap', 0, 20, '{"group_roles": {"engineering": "corp-standard", "marketing": "guest-premium"}}')`)
	if err != nil {
		return fmt.Errorf("seed ldap identity source: %w", err)
	}

	// Seed upstream RADIUS mapping source for Filter-Id / VLAN driven session shaping.
	_, err = tx.Exec(`INSERT OR IGNORE INTO identity_sources (name, type, enabled, priority, config)
		VALUES ('radius-upstream', 'radius', 0, 30, '{"filter_id_roles": {"admins": "admin", "employees": "corp-standard"}, "filter_id_bandwidth_profiles": {"premium": "100m-down-50m-up"}, "vlan_roles": {"30": "corp-standard", "40": "admin"}}')`)
	if err != nil {
		return fmt.Errorf("seed radius identity source: %w", err)
	}

	_, err = tx.Exec(`INSERT OR IGNORE INTO radius_clients (shortname, ipaddr, secret, description)
	VALUES ('localhost', '127.0.0.1', 'testing123', 'Local testing')`)
	if err != nil {
		return fmt.Errorf("seed radius client: %w", err)
	}

	var tokenCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE enabled = 1`).Scan(&tokenCount); err != nil {
		return fmt.Errorf("count api tokens: %w", err)
	}
	bootstrapToken := ""
	if tokenCount == 0 {
		bootstrapToken, err = newBootstrapToken()
		if err != nil {
			return fmt.Errorf("generate bootstrap token: %w", err)
		}
		_, err = tx.Exec(`INSERT INTO api_tokens (token, description, created_by)
			VALUES (?, 'Bootstrap admin token', 'system')`, hashAPIToken(bootstrapToken))
		if err != nil {
			return fmt.Errorf("seed api token: %w", err)
		}
		if os.Getenv("AEGIS_ADMIN_BOOTSTRAP_TOKEN") == "" {
			fmt.Printf("Generated bootstrap admin token: %s\n", bootstrapToken)
		}
	}

	var adminCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM local_users WHERE username = 'admin'`).Scan(&adminCount); err != nil {
		return fmt.Errorf("count admin user: %w", err)
	}
	if adminCount == 0 {
		if bootstrapToken == "" {
			bootstrapToken, err = newBootstrapToken()
			if err != nil {
				return fmt.Errorf("generate admin password: %w", err)
			}
			if os.Getenv("AEGIS_ADMIN_BOOTSTRAP_TOKEN") == "" {
				fmt.Printf("Generated initial admin password: %s\n", bootstrapToken)
			}
		}
		adminHash, err := bcrypt.GenerateFromPassword([]byte(bootstrapToken), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash admin password: %w", err)
		}
		_, err = tx.Exec(`INSERT INTO local_users (username, password_hash, role, full_name)
			VALUES ('admin', ?, 'admin', 'Administrator')`, string(adminHash))
	}
	if err != nil {
		return fmt.Errorf("seed admin user: %w", err)
	}

	return tx.Commit()
}

func newBootstrapToken() (string, error) {
	if token := os.Getenv("AEGIS_ADMIN_BOOTSTRAP_TOKEN"); token != "" {
		return token, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func hashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}
