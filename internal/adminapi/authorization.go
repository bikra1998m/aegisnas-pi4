package adminapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	adminRoleSuperAdmin = "super_admin"
	adminRoleOpsAdmin   = "ops_admin"
	adminRoleGuestAdmin = "guest_admin"
	adminRoleReadOnly   = "read_only"
)

const adminIdentityContextKey contextKey = "admin_identity"

type AdminIdentity struct {
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name,omitempty"`
	Role        string   `json:"role"`
	Source      string   `json:"source"`
	Tenants     []string `json:"tenants,omitempty"`
	Permissions []string `json:"permissions"`
	BreakGlass  bool     `json:"break_glass"`
}

type AdminPrincipal struct {
	ID          int      `json:"id"`
	Subject     string   `json:"subject"`
	Provider    string   `json:"provider"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Tenants     []string `json:"tenants"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`
	LastLogin   string   `json:"last_login"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type adminSessionRecord struct {
	Subject  string
	Role     string
	Source   string
	Provider string
	Tenants  []string
}

func adminIdentityFromRequest(r *http.Request) AdminIdentity {
	if value, ok := r.Context().Value(adminIdentityContextKey).(AdminIdentity); ok {
		return value
	}
	return AdminIdentity{
		Role:        adminRoleSuperAdmin,
		Source:      "break_glass",
		Permissions: permissionsForAdminRole(adminRoleSuperAdmin),
		BreakGlass:  true,
	}
}

func adminTenantScopesFromRequest(r *http.Request) []string {
	return adminIdentityFromRequest(r).Tenants
}

func isTenantScopedRequest(r *http.Request) bool {
	identity := adminIdentityFromRequest(r)
	return !identity.BreakGlass && len(identity.Tenants) > 0
}

func tenantAllowed(r *http.Request, tenant string) bool {
	identity := adminIdentityFromRequest(r)
	if identity.BreakGlass || len(identity.Tenants) == 0 {
		return true
	}
	tenant = normalizeTenant(tenant)
	if tenant == "" {
		return false
	}
	for _, scope := range identity.Tenants {
		if normalizeTenant(scope) == tenant {
			return true
		}
	}
	return false
}

func AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := adminIdentityFromRequest(r)
		if identity.BreakGlass {
			next.ServeHTTP(w, r)
			return
		}
		if authorizeRequest(identity, r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

func authorizeRequest(identity AdminIdentity, method, path string) bool {
	if identity.Role == adminRoleSuperAdmin {
		return true
	}
	path = strings.TrimSpace(path)
	method = strings.ToUpper(strings.TrimSpace(method))

	if strings.HasSuffix(path, "/auth/validate") || strings.HasSuffix(path, "/auth/logout") {
		return true
	}

	readonly := method == http.MethodGet || method == http.MethodHead

	switch {
	case strings.HasPrefix(path, "/api/v1/admin-principals"):
		return false
	case strings.HasPrefix(path, "/api/v1/system/status"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/dhcp-leases"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/dhcp-lease-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/dhcp-lease-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/upstream-aaa-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/upstream-aaa-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/upstream-aaa-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/upstream-aaa-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/audit-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/audit-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/audit-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/audit-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-analytics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-analytics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-analytics/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-analytics"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-invite-analytics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-invite-analytics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-invite-analytics/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-invite-analytics"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-conversion-analytics/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-conversion-analytics"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-conversion-analytics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-conversion-analytics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-lifecycle-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-lifecycle-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-analytics/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-failures/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-failures"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-failures-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-failures-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-analytics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-analytics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-delivery-analytics"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-sponsor-analytics/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-sponsor-analytics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-sponsor-analytics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-sponsor-analytics"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-lifecycle/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/guest-lifecycle"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/session-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/integration-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/integration-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/integration-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/integration-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/network-preview"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/network-backups"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/network-apply-history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/network-apply-history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/network-observability"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/network-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/network-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/diagnostics-exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/diagnostics-exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/diagnostics-report/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/diagnostics-report"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/support-bundle"):
		return readonly && identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-readiness-exports/download"):
		return readonly && identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-readiness-exports"):
		return readonly && identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-readiness"):
		return readonly && identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-rollback-package/inspect"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-rollback-package/restore"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/upgrade-rollback-package"):
		return readonly && identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/ha/history/export"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/ha/history"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/ha/exports/download"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/ha/exports"):
		return readonly
	case strings.HasPrefix(path, "/api/v1/system/ha/replication-package"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/ha/replication-shared"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/ha/replication-staged"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/ha/replication-stage-shared"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/ha/replication-activate"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/network-recovery"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/network-apply"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/system/network-rollback"):
		return identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/guest-registrations"):
		return readonly || identity.Role == adminRoleGuestAdmin || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/devices"):
		return readonly || identity.Role == adminRoleGuestAdmin || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/sessions"):
		return readonly || identity.Role == adminRoleGuestAdmin || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/alerts"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/ai-recommendations"):
		return readonly || identity.Role == adminRoleOpsAdmin
	case strings.HasPrefix(path, "/api/v1/config-revisions"):
		return readonly && identity.Role == adminRoleOpsAdmin
	default:
		return false
	}
}

func permissionsForAdminRole(role string) []string {
	switch strings.TrimSpace(role) {
	case adminRoleOpsAdmin:
		return []string{"status:read", "guest:manage", "device:read", "session:manage", "alert:manage", "ai:manage"}
	case adminRoleGuestAdmin:
		return []string{"status:read", "guest:manage", "device:read", "session:manage"}
	case adminRoleReadOnly:
		return []string{"status:read", "guest:read", "device:read", "session:read", "alert:read"}
	default:
		return []string{"*"}
	}
}

func resolveAdminIdentity(tokenHash, createdBy, description string) (AdminIdentity, error) {
	session, err := loadAdminSession(tokenHash)
	if err != nil {
		return AdminIdentity{}, err
	}
	if session == nil {
		subject := strings.TrimSpace(createdBy)
		if subject == "" {
			subject = strings.TrimSpace(description)
		}
		if subject == "" {
			subject = "break-glass-admin"
		}
		return AdminIdentity{
			Subject:     subject,
			DisplayName: subject,
			Role:        adminRoleSuperAdmin,
			Source:      "break_glass",
			Permissions: permissionsForAdminRole(adminRoleSuperAdmin),
			BreakGlass:  true,
		}, nil
	}
	return AdminIdentity{
		Subject:     session.Subject,
		DisplayName: session.Subject,
		Role:        session.Role,
		Source:      session.Source,
		Tenants:     session.Tenants,
		Permissions: permissionsForAdminRole(session.Role),
		BreakGlass:  false,
	}, nil
}

func loadAdminSession(tokenHash string) (*adminSessionRecord, error) {
	if db.DB == nil || strings.TrimSpace(tokenHash) == "" {
		return nil, nil
	}
	var (
		record     adminSessionRecord
		tenantsRaw string
	)
	err := db.DB.QueryRow(`SELECT subject, role, source, COALESCE(provider, ''), COALESCE(tenants, '[]')
		FROM admin_sessions
		WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > datetime('now'))`, tokenHash).
		Scan(&record.Subject, &record.Role, &record.Source, &record.Provider, &tenantsRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	record.Tenants = decodeStringArray(tenantsRaw)
	return &record, nil
}

func syncAdminPrincipalFromClaims(cfg *config.Config, provider, subject string, claims map[string]any, groups []string) (*AdminIdentity, error) {
	if db.DB == nil {
		return nil, errors.New("database is not initialized")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("admin subject is required")
	}
	existing, err := getAdminPrincipalBySubject(subject)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	role := adminRoleReadOnly
	tenants := extractTenantClaim(cfg, claims)
	if existing != nil {
		if existing.Disabled {
			return nil, errors.New("admin principal is disabled")
		}
		role = existing.Role
		if len(existing.Tenants) > 0 {
			tenants = existing.Tenants
		}
	}

	if !cfg.Governance.DelegatedAdminEnabled {
		role = adminRoleSuperAdmin
		tenants = nil
	} else {
		switch strings.TrimSpace(cfg.Governance.RBACMode) {
		case "external-groups":
			role = deriveAdminRoleFromGroups(groups)
		case "hybrid":
			if derived := deriveAdminRoleFromGroups(groups); derived != "" {
				role = derived
			}
		default:
			if existing == nil {
				role = adminRoleReadOnly
			}
		}
		if role == "" {
			role = adminRoleReadOnly
		}
		if !cfg.Governance.MultiTenantEnabled {
			tenants = nil
		}
	}

	displayName := firstNonEmpty(claimText(claims, "name"), claimText(claims, "preferred_username"), subject)
	email := firstNonEmpty(claimText(claims, "email"))

	if existing == nil {
		_, err = db.DB.Exec(`INSERT INTO admin_principals (
			subject, provider, display_name, email, role, tenants, groups_json, disabled, last_login, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'), datetime('now'))`,
			subject, nullIfEmpty(provider), nullIfEmpty(displayName), nullIfEmpty(email), role, encodeStringArray(tenants), encodeStringArray(groups))
	} else {
		_, err = db.DB.Exec(`UPDATE admin_principals
			SET provider = ?, display_name = ?, email = ?, role = ?, tenants = ?, groups_json = ?, last_login = datetime('now'), updated_at = datetime('now')
			WHERE subject = ?`,
			nullIfEmpty(provider), nullIfEmpty(displayName), nullIfEmpty(email), role, encodeStringArray(tenants), encodeStringArray(groups), subject)
	}
	if err != nil {
		return nil, err
	}

	return &AdminIdentity{
		Subject:     subject,
		DisplayName: displayName,
		Role:        role,
		Source:      provider,
		Tenants:     tenants,
		Permissions: permissionsForAdminRole(role),
	}, nil
}

func storeAdminSession(tokenHash string, identity AdminIdentity, provider string, groups []string, expiresAt time.Time) error {
	if db.DB == nil {
		return nil
	}
	_, err := db.DB.Exec(`INSERT INTO admin_sessions (
		token_hash, subject, role, source, provider, tenants, groups_json, expires_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
	ON CONFLICT(token_hash) DO UPDATE SET
		subject = excluded.subject,
		role = excluded.role,
		source = excluded.source,
		provider = excluded.provider,
		tenants = excluded.tenants,
		groups_json = excluded.groups_json,
		expires_at = excluded.expires_at`,
		tokenHash, identity.Subject, identity.Role, firstNonEmpty(identity.Source, "oidc"), nullIfEmpty(provider), encodeStringArray(identity.Tenants), encodeStringArray(groups), expiresAt.UTC())
	return err
}

func removeAdminSession(tokenHash string) {
	if db.DB == nil || strings.TrimSpace(tokenHash) == "" {
		return
	}
	_, _ = db.DB.Exec(`DELETE FROM admin_sessions WHERE token_hash = ?`, tokenHash)
}

func listAdminPrincipals() ([]AdminPrincipal, error) {
	rows, err := db.DB.Query(`SELECT id, subject, COALESCE(provider, ''), COALESCE(display_name, ''), COALESCE(email, ''),
		role, COALESCE(tenants, '[]'), COALESCE(groups_json, '[]'), disabled, COALESCE(last_login, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM admin_principals ORDER BY subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AdminPrincipal
	for rows.Next() {
		var (
			item      AdminPrincipal
			tenants   string
			groupsRaw string
		)
		if err := rows.Scan(&item.ID, &item.Subject, &item.Provider, &item.DisplayName, &item.Email, &item.Role, &tenants, &groupsRaw, &item.Disabled, &item.LastLogin, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Tenants = decodeStringArray(tenants)
		item.Groups = decodeStringArray(groupsRaw)
		items = append(items, item)
	}
	return items, rows.Err()
}

func getAdminPrincipalBySubject(subject string) (*AdminPrincipal, error) {
	var (
		item      AdminPrincipal
		tenants   string
		groupsRaw string
	)
	err := db.DB.QueryRow(`SELECT id, subject, COALESCE(provider, ''), COALESCE(display_name, ''), COALESCE(email, ''),
		role, COALESCE(tenants, '[]'), COALESCE(groups_json, '[]'), disabled, COALESCE(last_login, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM admin_principals WHERE subject = ?`, subject).
		Scan(&item.ID, &item.Subject, &item.Provider, &item.DisplayName, &item.Email, &item.Role, &tenants, &groupsRaw, &item.Disabled, &item.LastLogin, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return nil, err
	}
	item.Tenants = decodeStringArray(tenants)
	item.Groups = decodeStringArray(groupsRaw)
	return &item, nil
}

func updateAdminPrincipal(id int, role string, tenants []string, disabled bool) error {
	role = strings.TrimSpace(role)
	if !validAdminRole(role) {
		return fmt.Errorf("invalid admin role %q", role)
	}
	_, err := db.DB.Exec(`UPDATE admin_principals
		SET role = ?, tenants = ?, disabled = ?, updated_at = datetime('now')
		WHERE id = ?`, role, encodeStringArray(tenants), disabled, id)
	return err
}

func validAdminRole(role string) bool {
	switch strings.TrimSpace(role) {
	case adminRoleSuperAdmin, adminRoleOpsAdmin, adminRoleGuestAdmin, adminRoleReadOnly:
		return true
	default:
		return false
	}
}

func deriveAdminRoleFromGroups(groups []string) string {
	role := ""
	for _, group := range groups {
		name := strings.ToLower(strings.TrimSpace(group))
		switch {
		case strings.Contains(name, "super-admin") || strings.Contains(name, "super_admin") || strings.Contains(name, "aegisnas-admin"):
			return adminRoleSuperAdmin
		case strings.Contains(name, "ops-admin") || strings.Contains(name, "operations") || strings.Contains(name, "noc"):
			role = maxAdminRole(role, adminRoleOpsAdmin)
		case strings.Contains(name, "guest-admin") || strings.Contains(name, "helpdesk") || strings.Contains(name, "frontdesk"):
			role = maxAdminRole(role, adminRoleGuestAdmin)
		case strings.Contains(name, "viewer") || strings.Contains(name, "readonly") || strings.Contains(name, "read-only"):
			role = maxAdminRole(role, adminRoleReadOnly)
		}
	}
	return role
}

func maxAdminRole(current, candidate string) string {
	order := map[string]int{
		adminRoleReadOnly:   1,
		adminRoleGuestAdmin: 2,
		adminRoleOpsAdmin:   3,
		adminRoleSuperAdmin: 4,
	}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}

func extractTenantClaim(cfg *config.Config, claims map[string]any) []string {
	if cfg == nil || !cfg.Governance.MultiTenantEnabled {
		return nil
	}
	key := strings.TrimSpace(cfg.Governance.TenantClaim)
	if key == "" {
		return nil
	}
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch value := raw.(type) {
	case []any:
		var items []string
		for _, item := range value {
			if scope := normalizeTenant(fmt.Sprint(item)); scope != "" {
				items = append(items, scope)
			}
		}
		return uniqueStrings(items)
	case []string:
		return uniqueStrings(value)
	default:
		text := normalizeTenant(fmt.Sprint(value))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func normalizeTenant(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = normalizeTenant(value)
		if value == "" || value == "*" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func encodeStringArray(values []string) string {
	values = uniqueStrings(values)
	if len(values) == 0 {
		return "[]"
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

func decodeStringArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return uniqueStrings(values)
}

func claimText(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func withAdminIdentity(ctx context.Context, identity AdminIdentity) context.Context {
	return context.WithValue(ctx, adminIdentityContextKey, identity)
}
