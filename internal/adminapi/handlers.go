package adminapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"golang.org/x/crypto/bcrypt"
)

var configurableTables = []string{
	"roles",
	"local_users",
	"vouchers",
	"bandwidth_profiles",
	"portal_profiles",
	"policy_rules",
	"acl_policies",
	"identity_sources",
	"radius_clients",
}

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

type configSnapshot struct {
	GeneratedAt string                      `json:"generated_at"`
	Tables      map[string][]map[string]any `json:"tables"`
}

type stagedChange struct {
	ID           int
	ResourceType string
	ResourceID   string
	Operation    string
	Data         string
}

type fieldValue struct {
	Column string
	Value  any
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeBody(r *http.Request, target any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(target)
}

func userFromRequest(r *http.Request) string {
	if user, ok := r.Context().Value(userContextKey).(string); ok && user != "" {
		return user
	}
	return "unknown"
}

func auditTx(tx *sql.Tx, r *http.Request, action, details, result string) {
	_, _ = tx.Exec(`INSERT INTO audit_logs (user, action, details, result, ip_address)
		VALUES (?, ?, ?, ?, ?)`, userFromRequest(r), action, details, result, r.RemoteAddr)
}

func audit(r *http.Request, action, details, result string) {
	_, _ = db.DB.Exec(`INSERT INTO audit_logs (user, action, details, result, ip_address)
		VALUES (?, ?, ?, ?, ?)`, userFromRequest(r), action, details, result, r.RemoteAddr)
}

func stageChange(r *http.Request, resourceType, resourceID, operation string, data any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = db.DB.Exec(`INSERT INTO config_staging (resource_type, resource_id, operation, data, created_by)
		VALUES (?, ?, ?, ?, ?)`, resourceType, resourceID, operation, payload, userFromRequest(r))
	if err == nil {
		audit(r, "stage_"+operation, fmt.Sprintf("%s %s", resourceType, resourceID), "staged")
	}
	return err
}

func stageResource(w http.ResponseWriter, r *http.Request, resourceType, resourceID, operation string) {
	var payload map[string]any
	if operation != "delete" {
		if err := decodeBody(r, &payload); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		normalizePayload(resourceType, payload)
	}
	if err := stageChange(r, resourceType, resourceID, operation, payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "staged"})
}

func normalizePayload(resourceType string, payload map[string]any) {
	if resourceType == "user" {
		if password, ok := payload["password"].(string); ok && password == "" {
			delete(payload, "password")
		}
	}
	for _, key := range []string{"match_conditions", "config"} {
		if raw, ok := payload[key].(string); ok && strings.TrimSpace(raw) != "" {
			var value any
			if json.Unmarshal([]byte(raw), &value) == nil {
				payload[key] = value
			}
		}
	}
}

func captureConfigSnapshot(q queryer) (*configSnapshot, error) {
	snapshot := &configSnapshot{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Tables:      make(map[string][]map[string]any),
	}
	for _, table := range configurableTables {
		rows, err := q.Query("SELECT * FROM " + table)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", table, err)
		}
		records, err := rowsToMaps(rows)
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("snapshot %s rows: %w", table, err)
		}
		snapshot.Tables[table] = records
	}
	return snapshot, nil
}

func rowsToMaps(rows *sql.Rows) ([]map[string]any, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var records []map[string]any
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		record := make(map[string]any, len(columns))
		for i, column := range columns {
			switch v := values[i].(type) {
			case []byte:
				record[column] = string(v)
			case time.Time:
				record[column] = v.UTC().Format(time.RFC3339)
			default:
				record[column] = v
			}
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func saveConfigSnapshot(tx *sql.Tx, createdBy string) error {
	snapshot, err := captureConfigSnapshot(tx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var nextRev int
	if err := tx.QueryRow("SELECT COALESCE(MAX(revision), 0) + 1 FROM config_revisions").Scan(&nextRev); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO config_revisions (revision, config_data, checksum, created_by)
		VALUES (?, ?, ?, ?)`, nextRev, string(data), hex.EncodeToString(checksum[:]), createdBy)
	return err
}

func decodeSnapshot(data []byte) (*configSnapshot, error) {
	var snapshot configSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Tables == nil {
		return nil, fmt.Errorf("config snapshot does not contain restorable tables")
	}
	for _, table := range configurableTables {
		if _, ok := snapshot.Tables[table]; !ok {
			if table == "acl_policies" {
				snapshot.Tables[table] = []map[string]any{}
				continue
			}
			return nil, fmt.Errorf("config snapshot missing %s", table)
		}
	}
	return &snapshot, nil
}

func restoreConfigSnapshot(tx *sql.Tx, snapshot *configSnapshot) error {
	for i := len(configurableTables) - 1; i >= 0; i-- {
		if _, err := tx.Exec("DELETE FROM " + configurableTables[i]); err != nil {
			return err
		}
	}
	for _, table := range configurableTables {
		for _, row := range snapshot.Tables[table] {
			if err := insertMapRow(tx, table, row); err != nil {
				return fmt.Errorf("restore %s: %w", table, err)
			}
		}
	}
	return nil
}

func insertMapRow(tx *sql.Tx, table string, row map[string]any) error {
	columns := make([]string, 0, len(row))
	for column := range row {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	placeholders := make([]string, len(columns))
	values := make([]any, len(columns))
	for i, column := range columns {
		placeholders[i] = "?"
		values[i] = row[column]
	}
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(columns, ", "), strings.Join(placeholders, ", "))
	_, err := tx.Exec(query, values...)
	return err
}

func jsonField(value any, fallback string) (string, error) {
	if value == nil {
		return fallback, nil
	}
	if raw, ok := value.(string); ok {
		if strings.TrimSpace(raw) == "" {
			return fallback, nil
		}
		if !json.Valid([]byte(raw)) {
			return "", fmt.Errorf("invalid JSON")
		}
		return raw, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func stringValue(data map[string]any, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

func nullIfEmpty(value any) any {
	if s, ok := value.(string); ok && strings.TrimSpace(s) == "" {
		return nil
	}
	return value
}

func updateByID(tx *sql.Tx, table, id string, fields []fieldValue) error {
	if id == "" {
		return fmt.Errorf("missing id")
	}
	sets := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+1)
	for _, field := range fields {
		sets = append(sets, field.Column+" = ?")
		args = append(args, field.Value)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := tx.Exec(fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", ")), args...)
	return err
}

func applyChange(tx *sql.Tx, change stagedChange) error {
	var data map[string]any
	if change.Operation != "delete" {
		if err := json.Unmarshal([]byte(change.Data), &data); err != nil {
			return err
		}
		if data == nil {
			data = map[string]any{}
		}
	}

	switch change.ResourceType {
	case "vlan":
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO roles (name, description, vlan) VALUES (?, ?, ?)`,
				data["name"], data["description"], data["vlan"])
			return err
		case "update":
			return updateByID(tx, "roles", change.ResourceID, []fieldValue{
				{"name", data["name"]}, {"description", data["description"]}, {"vlan", data["vlan"]},
			})
		case "delete":
			_, err := tx.Exec(`DELETE FROM roles WHERE id = ?`, change.ResourceID)
			return err
		}
	case "user":
		switch change.Operation {
		case "create":
			password := stringValue(data, "password")
			if password == "" {
				return fmt.Errorf("password is required for user create")
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO local_users (username, password_hash, role, full_name, email)
				VALUES (?, ?, ?, ?, ?)`, data["username"], string(hash), data["role"], data["full_name"], data["email"])
			return err
		case "update":
			fields := []fieldValue{{"role", data["role"]}, {"full_name", data["full_name"]}, {"email", data["email"]}}
			if password := stringValue(data, "password"); password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				fields = append(fields, fieldValue{"password_hash", string(hash)})
			}
			return updateByID(tx, "local_users", change.ResourceID, fields)
		case "delete":
			_, err := tx.Exec(`DELETE FROM local_users WHERE id = ?`, change.ResourceID)
			return err
		}
	case "voucher":
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO vouchers (code, role, duration_minutes, usage_limit, expires_at)
				VALUES (?, ?, ?, ?, ?)`, data["code"], data["role"], data["duration_minutes"], data["usage_limit"], nullIfEmpty(data["expires_at"]))
			return err
		case "update":
			return updateByID(tx, "vouchers", change.ResourceID, []fieldValue{
				{"code", data["code"]}, {"role", data["role"]}, {"duration_minutes", data["duration_minutes"]},
				{"usage_limit", data["usage_limit"]}, {"expires_at", nullIfEmpty(data["expires_at"])},
			})
		case "delete":
			_, err := tx.Exec(`DELETE FROM vouchers WHERE id = ?`, change.ResourceID)
			return err
		}
	case "role":
		if err := validateACLPolicyReference(tx, stringValue(data, "acl_policy_name")); err != nil {
			return err
		}
		fields := []fieldValue{
			{"name", data["name"]}, {"description", data["description"]}, {"vlan", nullIfEmpty(data["vlan"])},
			{"bandwidth_profile", nullIfEmpty(data["bandwidth_profile"])}, {"session_timeout", nullIfEmpty(data["session_timeout"])},
			{"idle_timeout", nullIfEmpty(data["idle_timeout"])}, {"portal_profile", nullIfEmpty(data["portal_profile"])},
			{"acl_policy_name", nullIfEmpty(data["acl_policy_name"])},
			{"priority", data["priority"]},
		}
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO roles (name, description, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, priority)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, data["name"], data["description"], nullIfEmpty(data["vlan"]), nullIfEmpty(data["bandwidth_profile"]),
				nullIfEmpty(data["session_timeout"]), nullIfEmpty(data["idle_timeout"]), nullIfEmpty(data["portal_profile"]), nullIfEmpty(data["acl_policy_name"]), data["priority"])
			return err
		case "update":
			return updateByID(tx, "roles", change.ResourceID, fields)
		case "delete":
			_, err := tx.Exec(`DELETE FROM roles WHERE id = ?`, change.ResourceID)
			return err
		}
	case "policy":
		if err := validateACLPolicyReference(tx, stringValue(data, "acl_policy_name")); err != nil {
			return err
		}
		matchJSON, err := jsonField(data["match_conditions"], "{}")
		if err != nil {
			return fmt.Errorf("match_conditions: %w", err)
		}
		fields := []fieldValue{
			{"name", data["name"]}, {"description", data["description"]}, {"priority", data["priority"]},
			{"enabled", data["enabled"]}, {"match_conditions", matchJSON}, {"action", data["action"]},
			{"vlan", nullIfEmpty(data["vlan"])}, {"bandwidth_profile", nullIfEmpty(data["bandwidth_profile"])},
			{"session_timeout", nullIfEmpty(data["session_timeout"])}, {"idle_timeout", nullIfEmpty(data["idle_timeout"])},
			{"portal_profile", nullIfEmpty(data["portal_profile"])}, {"acl_policy_name", nullIfEmpty(data["acl_policy_name"])},
			{"quarantine", data["quarantine"]},
		}
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO policy_rules (name, description, priority, enabled, match_conditions, action, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, data["name"], data["description"], data["priority"], data["enabled"], matchJSON, data["action"],
				nullIfEmpty(data["vlan"]), nullIfEmpty(data["bandwidth_profile"]), nullIfEmpty(data["session_timeout"]), nullIfEmpty(data["idle_timeout"]),
				nullIfEmpty(data["portal_profile"]), nullIfEmpty(data["acl_policy_name"]), data["quarantine"])
			return err
		case "update":
			return updateByID(tx, "policy_rules", change.ResourceID, fields)
		case "delete":
			_, err := tx.Exec(`DELETE FROM policy_rules WHERE id = ?`, change.ResourceID)
			return err
		}
	case "acl_policy":
		if change.Operation == "delete" {
			if err := validateACLPolicyDelete(tx, change.ResourceID); err != nil {
				return err
			}
			_, err := tx.Exec(`DELETE FROM acl_policies WHERE id = ?`, change.ResourceID)
			return err
		}
		policy, err := parseACLPolicyPayload(data)
		if err != nil {
			return err
		}
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO acl_policies (name, description, inbound_acl, outbound_acl, rules_json, enabled)
				VALUES (?, ?, ?, ?, ?, ?)`, policy.Name, policy.Description, nullIfEmpty(policy.InboundACL), nullIfEmpty(policy.OutboundACL), policy.RulesJSON, policy.Enabled)
			return err
		case "update":
			if err := validateACLPolicyMutation(tx, change.ResourceID, policy.Name, policy.Enabled); err != nil {
				return err
			}
			return updateByID(tx, "acl_policies", change.ResourceID, []fieldValue{
				{"name", policy.Name}, {"description", policy.Description}, {"inbound_acl", nullIfEmpty(policy.InboundACL)},
				{"outbound_acl", nullIfEmpty(policy.OutboundACL)}, {"rules_json", policy.RulesJSON}, {"enabled", policy.Enabled},
				{"updated_at", time.Now().UTC()},
			})
		}
	case "identity_source":
		configJSON, err := jsonField(data["config"], "{}")
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO identity_sources (name, type, enabled, priority, config)
				VALUES (?, ?, ?, ?, ?)`, data["name"], data["type"], data["enabled"], data["priority"], configJSON)
			return err
		case "update":
			return updateByID(tx, "identity_sources", change.ResourceID, []fieldValue{
				{"name", data["name"]}, {"type", data["type"]}, {"enabled", data["enabled"]}, {"priority", data["priority"]}, {"config", configJSON},
			})
		case "delete":
			_, err := tx.Exec(`DELETE FROM identity_sources WHERE id = ?`, change.ResourceID)
			return err
		}
	case "portal_profile":
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO portal_profiles (name, branding, success_url, logout_url, terms_text)
				VALUES (?, ?, ?, ?, ?)`, data["name"], data["branding"], data["success_url"], data["logout_url"], data["terms_text"])
			return err
		case "update":
			return updateByID(tx, "portal_profiles", change.ResourceID, []fieldValue{
				{"name", data["name"]}, {"branding", data["branding"]}, {"success_url", data["success_url"]},
				{"logout_url", data["logout_url"]}, {"terms_text", data["terms_text"]},
			})
		case "delete":
			_, err := tx.Exec(`DELETE FROM portal_profiles WHERE id = ?`, change.ResourceID)
			return err
		}
	case "bandwidth_profile":
		switch change.Operation {
		case "create":
			_, err := tx.Exec(`INSERT INTO bandwidth_profiles (name, download_rate_kbps, upload_rate_kbps, burst_kb)
				VALUES (?, ?, ?, ?)`, data["name"], data["download_rate_kbps"], data["upload_rate_kbps"], data["burst_kb"])
			return err
		case "update":
			return updateByID(tx, "bandwidth_profiles", change.ResourceID, []fieldValue{
				{"name", data["name"]}, {"download_rate_kbps", data["download_rate_kbps"]},
				{"upload_rate_kbps", data["upload_rate_kbps"]}, {"burst_kb", data["burst_kb"]},
			})
		case "delete":
			_, err := tx.Exec(`DELETE FROM bandwidth_profiles WHERE id = ?`, change.ResourceID)
			return err
		}
	case "radius_client":
		shortName := strings.TrimSpace(fmt.Sprint(data["shortname"]))
		clientIP := strings.TrimSpace(fmt.Sprint(data["ip"]))
		if shortName == "" || strings.ContainsAny(shortName, " \t\r\n{}\"") {
			return fmt.Errorf("shortname is required and contains invalid FreeRADIUS configuration characters")
		}
		if net.ParseIP(clientIP) == nil {
			if _, _, err := net.ParseCIDR(clientIP); err != nil {
				return fmt.Errorf("ip must be an IPv4/IPv6 address or CIDR")
			}
		}
		transport := strings.ToLower(strings.TrimSpace(fmt.Sprint(data["transport"])))
		if transport == "" || transport == "<nil>" {
			transport = "udp"
		}
		secret := strings.TrimSpace(fmt.Sprint(data["secret"]))
		if secret == "<nil>" {
			secret = ""
		}
		secretRef := strings.TrimSpace(fmt.Sprint(data["secret_ref"]))
		if secretRef == "<nil>" {
			secretRef = ""
		}
		if secret != "" && secretRef != "" {
			return fmt.Errorf("secret and secret_ref cannot both be set")
		}
		if secretRef != "" {
			if _, err := secrets.ParseRef(secretRef); err != nil {
				return fmt.Errorf("secret_ref is invalid: %w", err)
			}
		}
		if transport == "radsec" {
			secret = "radsec"
			secretRef = ""
			if strings.TrimSpace(fmt.Sprint(data["radsec_certificate_cn"])) == "" {
				return fmt.Errorf("radsec_certificate_cn is required for a RadSec client")
			}
			if strings.ContainsAny(fmt.Sprint(data["radsec_certificate_cn"]), " \t\r\n{}\"") {
				return fmt.Errorf("radsec_certificate_cn contains invalid FreeRADIUS configuration characters")
			}
		} else if transport != "udp" {
			return fmt.Errorf("radius client transport %q is invalid", transport)
		}
		fields := []fieldValue{
			{"shortname", data["shortname"]},
			{"ipaddr", data["ip"]},
			{"nas_type", nullIfEmpty(data["nas_type"])},
			{"transport", transport},
			{"radsec_certificate_cn", nullIfEmpty(data["radsec_certificate_cn"])},
			{"radsec_certificate_issuer", nullIfEmpty(data["radsec_certificate_issuer"])},
			{"radsec_radius_v11", nullIfEmpty(data["radsec_radius_v11"])},
			{"description", nullIfEmpty(data["description"])},
			{"enabled", data["enabled"]},
		}
		switch change.Operation {
		case "create":
			if transport == "udp" && secret == "" && secretRef == "" {
				return fmt.Errorf("secret or secret_ref is required for a UDP RADIUS client")
			}
			_, err := tx.Exec(`INSERT INTO radius_clients
				(shortname, ipaddr, secret, secret_ref, nas_type, transport, radsec_certificate_cn, radsec_certificate_issuer, radsec_radius_v11, description, enabled)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, data["shortname"], data["ip"], secret, nullIfEmpty(secretRef), nullIfEmpty(data["nas_type"]),
				transport, nullIfEmpty(data["radsec_certificate_cn"]), nullIfEmpty(data["radsec_certificate_issuer"]),
				nullIfEmpty(data["radsec_radius_v11"]), nullIfEmpty(data["description"]), data["enabled"])
			return err
		case "update":
			if transport == "radsec" {
				fields = append(fields, fieldValue{"secret", secret})
				fields = append(fields, fieldValue{"secret_ref", nil})
			} else if secret != "" {
				fields = append(fields, fieldValue{"secret", secret})
				fields = append(fields, fieldValue{"secret_ref", nil})
			} else if secretRef != "" {
				fields = append(fields, fieldValue{"secret", ""})
				fields = append(fields, fieldValue{"secret_ref", secretRef})
			}
			return updateByID(tx, "radius_clients", change.ResourceID, fields)
		case "delete":
			_, err := tx.Exec(`DELETE FROM radius_clients WHERE id = ?`, change.ResourceID)
			return err
		}
	default:
		return fmt.Errorf("unsupported resource type %q", change.ResourceType)
	}
	return fmt.Errorf("unsupported operation %q for %s", change.Operation, change.ResourceType)
}

func validateACLPolicyReference(tx *sql.Tx, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM acl_policies WHERE name = ? AND enabled = 1`, name).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("ACL policy %q does not exist or is disabled", name)
	}
	return nil
}

func validateACLPolicyDelete(tx *sql.Tx, resourceID string) error {
	var name string
	if err := tx.QueryRow(`SELECT name FROM acl_policies WHERE id = ?`, resourceID).Scan(&name); err != nil {
		return err
	}
	var references int
	if err := tx.QueryRow(`SELECT
		(SELECT COUNT(*) FROM roles WHERE acl_policy_name = ?) +
		(SELECT COUNT(*) FROM policy_rules WHERE acl_policy_name = ?)`, name, name).Scan(&references); err != nil {
		return err
	}
	if references > 0 {
		return fmt.Errorf("ACL policy %q is still assigned to %d role or policy rule(s)", name, references)
	}
	return nil
}

func validateACLPolicyMutation(tx *sql.Tx, resourceID, newName string, enabled bool) error {
	var currentName string
	if err := tx.QueryRow(`SELECT name FROM acl_policies WHERE id = ?`, resourceID).Scan(&currentName); err != nil {
		return err
	}
	if enabled && strings.TrimSpace(newName) == currentName {
		return nil
	}
	var references int
	if err := tx.QueryRow(`SELECT
		(SELECT COUNT(*) FROM roles WHERE acl_policy_name = ?) +
		(SELECT COUNT(*) FROM policy_rules WHERE acl_policy_name = ?)`, currentName, currentName).Scan(&references); err != nil {
		return err
	}
	if references > 0 {
		return fmt.Errorf("ACL policy %q cannot be renamed or disabled while assigned to %d role or policy rule(s)", currentName, references)
	}
	return nil
}

func pendingChanges(tx *sql.Tx) ([]stagedChange, error) {
	rows, err := tx.Query(`SELECT id, resource_type, COALESCE(resource_id, ''), operation, COALESCE(data, '{}')
		FROM config_staging WHERE applied = 0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var changes []stagedChange
	for rows.Next() {
		var change stagedChange
		if err := rows.Scan(&change.ID, &change.ResourceType, &change.ResourceID, &change.Operation, &change.Data); err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

func rawJSON(value string) any {
	if json.Valid([]byte(value)) {
		return json.RawMessage(value)
	}
	return value
}

func HandleValidateToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "valid",
		"user":     userFromRequest(r),
		"identity": adminIdentityFromRequest(r),
	})
}

// ---------- VLAN Handlers ----------

func HandleListVLANs(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), vlan FROM roles WHERE vlan IS NOT NULL ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var vlans []map[string]any
	for rows.Next() {
		var id, vlan int
		var name, desc string
		if err := rows.Scan(&id, &name, &desc, &vlan); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vlans = append(vlans, map[string]any{"id": id, "name": name, "description": desc, "vlan": vlan})
	}
	writeJSON(w, http.StatusOK, vlans)
}

func HandleCreateVLAN(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "vlan", "", "create")
}
func HandleUpdateVLAN(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "vlan", chi.URLParam(r, "id"), "update")
}
func HandleDeleteVLAN(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "vlan", chi.URLParam(r, "id"), "delete")
}

// ---------- User Handlers ----------

func HandleListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, username, role, COALESCE(full_name, ''), COALESCE(email, '') FROM local_users ORDER BY username`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []map[string]any
	for rows.Next() {
		var id int
		var username, role, fullName, email string
		if err := rows.Scan(&id, &username, &role, &fullName, &email); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, map[string]any{"id": id, "username": username, "role": role, "full_name": fullName, "email": email})
	}
	writeJSON(w, http.StatusOK, users)
}

func HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "user", "", "create")
}
func HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "user", chi.URLParam(r, "id"), "update")
}
func HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "user", chi.URLParam(r, "id"), "delete")
}

// ---------- Voucher Handlers ----------

func HandleListVouchers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, code, role, duration_minutes, usage_limit, used_count, COALESCE(expires_at, '') FROM vouchers ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var vouchers []map[string]any
	for rows.Next() {
		var id, duration, usageLimit, usedCount int
		var code, role, expiresAt string
		if err := rows.Scan(&id, &code, &role, &duration, &usageLimit, &usedCount, &expiresAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vouchers = append(vouchers, map[string]any{
			"id": id, "code": code, "role": role, "duration_minutes": duration,
			"usage_limit": usageLimit, "used_count": usedCount, "expires_at": expiresAt,
		})
	}
	writeJSON(w, http.StatusOK, vouchers)
}

func HandleCreateVoucher(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "voucher", "", "create")
}
func HandleUpdateVoucher(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "voucher", chi.URLParam(r, "id"), "update")
}
func HandleDeleteVoucher(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "voucher", chi.URLParam(r, "id"), "delete")
}

// ---------- Role Handlers ----------

func HandleListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, priority FROM roles ORDER BY priority DESC, name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var roles []map[string]any
	for rows.Next() {
		var id, priority int
		var name, desc string
		var vlan, sessionTimeout, idleTimeout sql.NullInt64
		var bandwidthProfile, portalProfile, aclPolicyName sql.NullString
		if err := rows.Scan(&id, &name, &desc, &vlan, &bandwidthProfile, &sessionTimeout, &idleTimeout, &portalProfile, &aclPolicyName, &priority); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		role := map[string]any{"id": id, "name": name, "description": desc, "priority": priority}
		if vlan.Valid {
			role["vlan"] = vlan.Int64
		}
		if bandwidthProfile.Valid {
			role["bandwidth_profile"] = bandwidthProfile.String
		}
		if sessionTimeout.Valid {
			role["session_timeout"] = sessionTimeout.Int64
		}
		if idleTimeout.Valid {
			role["idle_timeout"] = idleTimeout.Int64
		}
		if portalProfile.Valid {
			role["portal_profile"] = portalProfile.String
		}
		if aclPolicyName.Valid {
			role["acl_policy_name"] = aclPolicyName.String
		}
		roles = append(roles, role)
	}
	writeJSON(w, http.StatusOK, roles)
}

func HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "role", "", "create")
}
func HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "role", chi.URLParam(r, "id"), "update")
}
func HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "role", chi.URLParam(r, "id"), "delete")
}

// ---------- Policy Handlers ----------

func HandleListPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(description, ''), priority, enabled, match_conditions, action, vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, acl_policy_name, quarantine FROM policy_rules ORDER BY priority DESC, name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var policies []map[string]any
	for rows.Next() {
		var id, priority int
		var name, desc, matchCond, action string
		var enabled, quarantine bool
		var vlan, sessionTimeout, idleTimeout sql.NullInt64
		var bandwidthProfile, portalProfile, aclPolicyName sql.NullString
		if err := rows.Scan(&id, &name, &desc, &priority, &enabled, &matchCond, &action, &vlan, &bandwidthProfile, &sessionTimeout, &idleTimeout, &portalProfile, &aclPolicyName, &quarantine); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		policy := map[string]any{
			"id": id, "name": name, "description": desc, "priority": priority, "enabled": enabled,
			"match_conditions": rawJSON(matchCond), "action": action, "quarantine": quarantine,
		}
		if vlan.Valid {
			policy["vlan"] = vlan.Int64
		}
		if bandwidthProfile.Valid {
			policy["bandwidth_profile"] = bandwidthProfile.String
		}
		if sessionTimeout.Valid {
			policy["session_timeout"] = sessionTimeout.Int64
		}
		if idleTimeout.Valid {
			policy["idle_timeout"] = idleTimeout.Int64
		}
		if portalProfile.Valid {
			policy["portal_profile"] = portalProfile.String
		}
		if aclPolicyName.Valid {
			policy["acl_policy_name"] = aclPolicyName.String
		}
		policies = append(policies, policy)
	}
	writeJSON(w, http.StatusOK, policies)
}

func HandleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "policy", "", "create")
}
func HandleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "policy", chi.URLParam(r, "id"), "update")
}
func HandleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "policy", chi.URLParam(r, "id"), "delete")
}

// ---------- Identity Sources ----------

func HandleListIdentitySources(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, type, enabled, priority, COALESCE(config, '{}') FROM identity_sources ORDER BY priority, name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var sources []map[string]any
	for rows.Next() {
		var id, priority int
		var name, sourceType, configJSON string
		var enabled bool
		if err := rows.Scan(&id, &name, &sourceType, &enabled, &priority, &configJSON); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sources = append(sources, map[string]any{"id": id, "name": name, "type": sourceType, "enabled": enabled, "priority": priority, "config": rawJSON(configJSON)})
	}
	writeJSON(w, http.StatusOK, sources)
}

func HandleCreateIdentitySource(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "identity_source", "", "create")
}
func HandleUpdateIdentitySource(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "identity_source", chi.URLParam(r, "id"), "update")
}
func HandleDeleteIdentitySource(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "identity_source", chi.URLParam(r, "id"), "delete")
}

// ---------- Portal Profiles ----------

func HandleListPortalProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, COALESCE(branding, ''), COALESCE(success_url, ''), COALESCE(logout_url, ''), COALESCE(terms_text, '') FROM portal_profiles ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var profiles []map[string]any
	for rows.Next() {
		var id int
		var name, branding, successURL, logoutURL, termsText string
		if err := rows.Scan(&id, &name, &branding, &successURL, &logoutURL, &termsText); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		profiles = append(profiles, map[string]any{"id": id, "name": name, "branding": branding, "success_url": successURL, "logout_url": logoutURL, "terms_text": termsText})
	}
	writeJSON(w, http.StatusOK, profiles)
}

func HandleCreatePortalProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "portal_profile", "", "create")
}
func HandleUpdatePortalProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "portal_profile", chi.URLParam(r, "id"), "update")
}
func HandleDeletePortalProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "portal_profile", chi.URLParam(r, "id"), "delete")
}

// ---------- Bandwidth Profiles ----------

func HandleListBandwidthProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, name, download_rate_kbps, upload_rate_kbps, burst_kb FROM bandwidth_profiles ORDER BY name`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var profiles []map[string]any
	for rows.Next() {
		var id, down, up, burst int
		var name string
		if err := rows.Scan(&id, &name, &down, &up, &burst); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		profiles = append(profiles, map[string]any{"id": id, "name": name, "download_rate_kbps": down, "upload_rate_kbps": up, "burst_kb": burst})
	}
	writeJSON(w, http.StatusOK, profiles)
}

func HandleCreateBandwidthProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "bandwidth_profile", "", "create")
}
func HandleUpdateBandwidthProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "bandwidth_profile", chi.URLParam(r, "id"), "update")
}
func HandleDeleteBandwidthProfile(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "bandwidth_profile", chi.URLParam(r, "id"), "delete")
}

// ---------- RADIUS Clients ----------

func HandleListRadiusClients(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, shortname, ipaddr, secret != '', COALESCE(secret_ref, ''), COALESCE(nas_type, ''), COALESCE(transport, 'udp'),
		COALESCE(radsec_certificate_cn, ''), COALESCE(radsec_certificate_issuer, ''), COALESCE(radsec_radius_v11, ''),
		COALESCE(description, ''), enabled, COALESCE(dynamic_source, 'static'), COALESCE(enrollment_id, ''),
		COALESCE(vendor, ''), COALESCE(model, ''), COALESCE(firmware_version, ''), COALESCE(serial_number, ''),
		COALESCE(lifecycle_status, 'approved'), COALESCE(last_seen_at, ''), COALESCE(owner_tenant, ''), COALESCE(template_name, '')
		FROM radius_clients ORDER BY shortname`)
	if isMissingRadiusClientSecretRefForAPI(err) {
		rows, err = db.DB.Query(`SELECT id, shortname, ipaddr, secret != '', '', COALESCE(nas_type, ''), COALESCE(transport, 'udp'),
			COALESCE(radsec_certificate_cn, ''), COALESCE(radsec_certificate_issuer, ''), COALESCE(radsec_radius_v11, ''),
			COALESCE(description, ''), enabled, 'static', '', '', '', '', '', 'approved', '', '', '' FROM radius_clients ORDER BY shortname`)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var clients []map[string]any
	for rows.Next() {
		var id int
		var shortname, ip, secretRef, nasType, transport, certificateCN, certificateIssuer, radiusV11, description string
		var dynamicSource, enrollmentID, vendor, model, firmwareVersion, serialNumber, lifecycleStatus, lastSeenAt, ownerTenant, templateName string
		var enabled, inlineSecretSet bool
		if err := rows.Scan(&id, &shortname, &ip, &inlineSecretSet, &secretRef, &nasType, &transport, &certificateCN, &certificateIssuer, &radiusV11, &description, &enabled,
			&dynamicSource, &enrollmentID, &vendor, &model, &firmwareVersion, &serialNumber, &lifecycleStatus, &lastSeenAt, &ownerTenant, &templateName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		secretRef = strings.TrimSpace(secretRef)
		clients = append(clients, map[string]any{
			"id":                        id,
			"shortname":                 shortname,
			"ip":                        ip,
			"secret_set":                inlineSecretSet || secretRef != "",
			"inline_secret_set":         inlineSecretSet,
			"secret_ref":                secretRef,
			"secret_ref_set":            secretRef != "",
			"secret_ref_fingerprint":    secretRefFingerprint(secretRef),
			"nas_type":                  nasType,
			"transport":                 transport,
			"radsec_certificate_cn":     certificateCN,
			"radsec_certificate_issuer": certificateIssuer,
			"radsec_radius_v11":         radiusV11,
			"description":               description,
			"enabled":                   enabled,
			"dynamic_source":            dynamicSource,
			"enrollment_id":             enrollmentID,
			"vendor":                    vendor,
			"model":                     model,
			"firmware_version":          firmwareVersion,
			"serial_number":             serialNumber,
			"lifecycle_status":          lifecycleStatus,
			"last_seen_at":              lastSeenAt,
			"owner_tenant":              ownerTenant,
			"template_name":             templateName,
		})
	}
	writeJSON(w, http.StatusOK, clients)
}

func isMissingRadiusClientSecretRefForAPI(err error) bool {
	if err == nil {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such column") && strings.Contains(normalized, "secret_ref")
}

func secretRefFingerprint(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	return secrets.Fingerprint(ref)
}

func HandleCreateRadiusClient(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "radius_client", "", "create")
}

func HandleUpdateRadiusClient(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "radius_client", chi.URLParam(r, "id"), "update")
}

func HandleDeleteRadiusClient(w http.ResponseWriter, r *http.Request) {
	stageResource(w, r, "radius_client", chi.URLParam(r, "id"), "delete")
}

// ---------- Sessions ----------

func HandleListSessions(w http.ResponseWriter, r *http.Request) {
	query := `SELECT id, username, COALESCE(mac, ''), COALESCE(ip, ''), COALESCE(auth_method, ''), COALESCE(vlan, 0),
		start_time, COALESCE(last_activity, ''), COALESCE(end_time, ''), bytes_in, bytes_out
		FROM sessions`
	args := []any{}
	clauses := []string{}
	if r.URL.Query().Get("active") == "true" {
		clauses = append(clauses, "end_time IS NULL")
	}
	if scopes := adminTenantScopesFromRequest(r); len(scopes) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(scopes)), ",")
		clauses = append(clauses, fmt.Sprintf(`COALESCE(
			(SELECT tenant FROM local_users WHERE username = sessions.username LIMIT 1),
			(SELECT tenant FROM device_inventory WHERE mac = sessions.mac LIMIT 1),
			''
		) IN (%s)`, placeholders))
		for _, scope := range scopes {
			args = append(args, scope)
		}
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	query += ` ORDER BY start_time DESC LIMIT 100`
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var sessions []map[string]any
	for rows.Next() {
		var id, username, mac, ip, authMethod, startTime, lastActivity, endTime string
		var vlan int
		var bytesIn, bytesOut int64
		if err := rows.Scan(&id, &username, &mac, &ip, &authMethod, &vlan, &startTime, &lastActivity, &endTime, &bytesIn, &bytesOut); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sessions = append(sessions, map[string]any{
			"id": id, "username": username, "mac": mac, "ip": ip, "auth_method": authMethod,
			"vlan": vlan, "start_time": startTime, "last_activity": lastActivity, "end_time": endTime,
			"bytes_in": bytesIn, "bytes_out": bytesOut,
		})
	}
	writeJSON(w, http.StatusOK, sessions)
}

func HandleTerminateSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if scopes := adminTenantScopesFromRequest(r); len(scopes) > 0 {
		var tenant string
		err := db.DB.QueryRow(`SELECT COALESCE(
			(SELECT tenant FROM local_users WHERE username = sessions.username LIMIT 1),
			(SELECT tenant FROM device_inventory WHERE mac = sessions.mac LIMIT 1),
			''
		) FROM sessions WHERE id = ?`, sessionID).Scan(&tenant)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if !tenantAllowed(r, tenant) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	res, err := db.DB.Exec(`UPDATE sessions SET end_time = ?, stop_reason = 'admin' WHERE id = ? AND end_time IS NULL`, time.Now(), sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	audit(r, "terminate_session", sessionID, fmt.Sprintf("%d updated", affected))
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Alerts ----------

func HandleListAlerts(w http.ResponseWriter, r *http.Request) {
	query := `SELECT id, severity, source, message, COALESCE(details, ''), acknowledged, created_at FROM alerts`
	if r.URL.Query().Get("acknowledged") == "false" {
		query += ` WHERE acknowledged = 0`
	}
	query += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := db.DB.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var alerts []map[string]any
	for rows.Next() {
		var id int
		var severity, source, message, details, createdAt string
		var acknowledged bool
		if err := rows.Scan(&id, &severity, &source, &message, &details, &acknowledged, &createdAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		alerts = append(alerts, map[string]any{"id": id, "severity": severity, "source": source, "message": message, "details": details, "acknowledged": acknowledged, "created_at": createdAt})
	}
	writeJSON(w, http.StatusOK, alerts)
}

func HandleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := db.DB.Exec(`UPDATE alerts SET acknowledged = 1 WHERE id = ?`, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "acknowledge_alert", id, "acknowledged")
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Config Revisions ----------

func HandleListConfigRevisions(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, revision, checksum, COALESCE(signature, ''), COALESCE(created_by, ''), created_at FROM config_revisions ORDER BY revision DESC LIMIT 50`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var revisions []map[string]any
	for rows.Next() {
		var id, revision int
		var checksum, signature, createdBy, createdAt string
		if err := rows.Scan(&id, &revision, &checksum, &signature, &createdBy, &createdAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		revisions = append(revisions, map[string]any{"id": id, "revision": revision, "checksum": checksum, "signature": signature, "created_by": createdBy, "created_at": createdAt})
	}
	writeJSON(w, http.StatusOK, revisions)
}

func HandleRollback(w http.ResponseWriter, r *http.Request) {
	rev, err := strconv.Atoi(chi.URLParam(r, "revision"))
	if err != nil {
		http.Error(w, "invalid revision", http.StatusBadRequest)
		return
	}
	tx, err := db.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var configData, checksum string
	err = tx.QueryRow(`SELECT config_data, checksum FROM config_revisions WHERE revision = ?`, rev).Scan(&configData, &checksum)
	if err != nil {
		http.Error(w, "revision not found", http.StatusNotFound)
		return
	}
	sum := sha256.Sum256([]byte(configData))
	if checksum != "" && checksum != hex.EncodeToString(sum[:]) {
		http.Error(w, "revision checksum mismatch", http.StatusBadRequest)
		return
	}
	snapshot, err := decodeSnapshot([]byte(configData))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := saveConfigSnapshot(tx, userFromRequest(r)); err != nil {
		http.Error(w, fmt.Sprintf("save pre-rollback snapshot: %v", err), http.StatusInternalServerError)
		return
	}
	if err := restoreConfigSnapshot(tx, snapshot); err != nil {
		http.Error(w, fmt.Sprintf("restore revision: %v", err), http.StatusInternalServerError)
		return
	}
	auditTx(tx, r, "rollback_config", fmt.Sprintf("revision %d", rev), "restored")
	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "rolled back", "revision": rev, "warning": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled back", "revision": rev})
}

// ---------- Backups ----------

func HandleExportConfig(w http.ResponseWriter, r *http.Request) {
	snapshot, err := captureConfigSnapshot(db.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="aegisnas-config-backup.json"`)
	writeJSON(w, http.StatusOK, snapshot)
}

func HandleImportConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		http.Error(w, "backup upload is too large or unreadable", http.StatusBadRequest)
		return
	}
	snapshot, err := decodeSnapshot(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid backup JSON: %v", err), http.StatusBadRequest)
		return
	}
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	if err := saveConfigSnapshot(tx, userFromRequest(r)); err != nil {
		http.Error(w, fmt.Sprintf("save pre-import snapshot: %v", err), http.StatusInternalServerError)
		return
	}
	if err := restoreConfigSnapshot(tx, snapshot); err != nil {
		http.Error(w, fmt.Sprintf("restore backup: %v", err), http.StatusInternalServerError)
		return
	}
	auditTx(tx, r, "import_config_backup", "uploaded config JSON", "restored")
	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "imported", "warning": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

// ---------- AI Recommendations ----------

func HandleListAIRecommendations(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, severity, source, confidence, title, COALESCE(description, ''), COALESCE(remediation, ''), acknowledged, created_at
		FROM ai_recommendations ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var recommendations []map[string]any
	for rows.Next() {
		var id int
		var severity, source, title, description, remediation, createdAt string
		var confidence float64
		var acknowledged bool
		if err := rows.Scan(&id, &severity, &source, &confidence, &title, &description, &remediation, &acknowledged, &createdAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		recommendations = append(recommendations, map[string]any{
			"id": id, "severity": severity, "source": source, "confidence": confidence, "title": title,
			"description": description, "remediation": remediation, "acknowledged": acknowledged, "created_at": createdAt,
		})
	}
	writeJSON(w, http.StatusOK, recommendations)
}

func HandleAcknowledgeAIRecommendation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := db.DB.Exec(`UPDATE ai_recommendations SET acknowledged = 1 WHERE id = ?`, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(r, "acknowledge_ai_recommendation", id, "acknowledged")
	w.WriteHeader(http.StatusNoContent)
}

func HandleRunAIAnalysis(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	if !cfg.AILite.Enabled {
		http.Error(w, "AI engine is disabled in config", http.StatusBadRequest)
		return
	}

	target := fmt.Sprintf("http://127.0.0.1:%d/api/v1/ai/run-analysis", cfg.Health.Port+4)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("AI engine request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(body)), resp.StatusCode)
		return
	}
	audit(r, "run_ai_analysis", target, "accepted")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "analysis started",
		"mode":   config.EffectiveAIMode(cfg),
	})
}

// ---------- Staging and Apply Workflow ----------

func HandleListStagedChanges(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(`SELECT id, resource_type, COALESCE(resource_id, ''), operation, COALESCE(data, '{}'), created_by, created_at
		FROM config_staging WHERE applied = 0 ORDER BY created_at`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var changes []map[string]any
	for rows.Next() {
		var id int
		var resourceType, resourceID, operation, data, createdBy, createdAt string
		if err := rows.Scan(&id, &resourceType, &resourceID, &operation, &data, &createdBy, &createdAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		changes = append(changes, map[string]any{
			"id": id, "resource_type": resourceType, "resource_id": resourceID, "operation": operation,
			"data": rawJSON(data), "created_by": createdBy, "created_at": createdAt,
		})
	}
	writeJSON(w, http.StatusOK, changes)
}

func HandleValidateStagedChanges(w http.ResponseWriter, r *http.Request) {
	tx, err := db.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	changes, err := pendingChanges(tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, change := range changes {
		if err := applyChange(tx, change); err != nil {
			http.Error(w, fmt.Sprintf("validation failed on %s %s: %v", change.ResourceType, change.Operation, err), http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "validation successful", "changes": len(changes)})
}

func HandleApplyChanges(w http.ResponseWriter, r *http.Request) {
	tx, err := db.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	changes, err := pendingChanges(tx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "changes": 0})
		return
	}
	if err := saveConfigSnapshot(tx, userFromRequest(r)); err != nil {
		http.Error(w, fmt.Sprintf("save snapshot: %v", err), http.StatusInternalServerError)
		return
	}
	for _, change := range changes {
		if err := applyChange(tx, change); err != nil {
			http.Error(w, fmt.Sprintf("apply failed on %s %s: %v", change.ResourceType, change.Operation, err), http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(`UPDATE config_staging SET applied = 1, applied_at = datetime('now') WHERE id = ?`, change.ID); err != nil {
			http.Error(w, fmt.Sprintf("mark staged change applied: %v", err), http.StatusInternalServerError)
			return
		}
		auditTx(tx, r, "apply_"+change.Operation, fmt.Sprintf("%s %s", change.ResourceType, change.ResourceID), "applied")
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := enforcement.SyncRuntimeEnforcement(config.Get()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "changes": len(changes), "warning": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "changes": len(changes)})
}
