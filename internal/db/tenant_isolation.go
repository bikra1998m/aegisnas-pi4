package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type TenantProfile struct {
	ID                  int    `json:"id,omitempty"`
	TenantKey           string `json:"tenant_key"`
	DisplayName         string `json:"display_name,omitempty"`
	Status              string `json:"status"`
	DataResidencyRegion string `json:"data_residency_region,omitempty"`
	SecretNamespace     string `json:"secret_namespace,omitempty"`
	CANamespace         string `json:"ca_namespace,omitempty"`
	DictionaryProfile   string `json:"dictionary_profile,omitempty"`
	QuotaJSON           string `json:"quota_json"`
	ControllerScopeJSON string `json:"controller_scope_json"`
	BillingAccountRef   string `json:"billing_account_ref,omitempty"`
	CreatedBy           string `json:"created_by,omitempty"`
	UpdatedBy           string `json:"updated_by,omitempty"`
	CreatedAt           string `json:"created_at,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type TenantResourceBinding struct {
	ID           int    `json:"id,omitempty"`
	Tenant       string `json:"tenant"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	OwnerKind    string `json:"owner_kind"`
	Status       string `json:"status"`
	EvidenceJSON string `json:"evidence_json"`
	CreatedBy    string `json:"created_by,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type TenantIsolationEvent struct {
	ID                 int      `json:"id,omitempty"`
	EventID            string   `json:"event_id"`
	Tenant             string   `json:"tenant,omitempty"`
	ResourceType       string   `json:"resource_type"`
	ResourceID         string   `json:"resource_id,omitempty"`
	Action             string   `json:"action"`
	Decision           string   `json:"decision"`
	Reason             string   `json:"reason,omitempty"`
	Actor              string   `json:"actor,omitempty"`
	RequestTenants     []string `json:"request_tenants,omitempty"`
	RequestTenantsJSON string   `json:"request_tenants_json,omitempty"`
	DetailsJSON        string   `json:"details_json,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
}

type TenantIsolationSummary struct {
	TenantCount            int    `json:"tenant_count"`
	ActiveTenantCount      int    `json:"active_tenant_count"`
	SuspendedTenantCount   int    `json:"suspended_tenant_count"`
	DisabledTenantCount    int    `json:"disabled_tenant_count"`
	ResourceBindingCount   int    `json:"resource_binding_count"`
	SharedResourceCount    int    `json:"shared_resource_count"`
	PolicySetTenantCount   int    `json:"policy_set_tenant_count"`
	UntenantedPolicySets   int    `json:"untenanted_policy_sets"`
	IsolationEventCount    int    `json:"isolation_event_count"`
	DeniedEventCount       int    `json:"denied_event_count"`
	MonitorEventCount      int    `json:"monitor_event_count"`
	LastEventAt            string `json:"last_event_at,omitempty"`
	LastEventDecision      string `json:"last_event_decision,omitempty"`
	LastEventResourceType  string `json:"last_event_resource_type,omitempty"`
	LastEventResourceID    string `json:"last_event_resource_id,omitempty"`
	LastPolicyActivationAt string `json:"last_policy_activation_at,omitempty"`
}

func NormalizeTenantKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "*" {
		return ""
	}
	return value
}

func UpsertTenantProfile(profile TenantProfile) (TenantProfile, error) {
	if DB == nil {
		return TenantProfile{}, fmt.Errorf("database is not initialized")
	}
	normalized, err := normalizeTenantProfile(profile)
	if err != nil {
		return TenantProfile{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = DB.Exec(`INSERT INTO tenant_profiles (
		tenant_key, display_name, status, data_residency_region, secret_namespace, ca_namespace,
		dictionary_profile, quota_json, controller_scope_json, billing_account_ref,
		created_by, updated_by, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(tenant_key) DO UPDATE SET
		display_name = excluded.display_name,
		status = excluded.status,
		data_residency_region = excluded.data_residency_region,
		secret_namespace = excluded.secret_namespace,
		ca_namespace = excluded.ca_namespace,
		dictionary_profile = excluded.dictionary_profile,
		quota_json = excluded.quota_json,
		controller_scope_json = excluded.controller_scope_json,
		billing_account_ref = excluded.billing_account_ref,
		updated_by = excluded.updated_by,
		updated_at = excluded.updated_at`,
		normalized.TenantKey, nullIfEmpty(normalized.DisplayName), normalized.Status, nullIfEmpty(normalized.DataResidencyRegion),
		nullIfEmpty(normalized.SecretNamespace), nullIfEmpty(normalized.CANamespace), nullIfEmpty(normalized.DictionaryProfile),
		defaultJSONObject(normalized.QuotaJSON), defaultJSONObject(normalized.ControllerScopeJSON), nullIfEmpty(normalized.BillingAccountRef),
		nullIfEmpty(normalized.CreatedBy), nullIfEmpty(normalized.UpdatedBy), now, now)
	if err != nil {
		return TenantProfile{}, err
	}
	return GetTenantProfile(normalized.TenantKey)
}

func GetTenantProfile(tenant string) (TenantProfile, error) {
	if DB == nil {
		return TenantProfile{}, fmt.Errorf("database is not initialized")
	}
	row := DB.QueryRow(`SELECT id, tenant_key, COALESCE(display_name, ''), status,
		COALESCE(data_residency_region, ''), COALESCE(secret_namespace, ''), COALESCE(ca_namespace, ''),
		COALESCE(dictionary_profile, ''), quota_json, controller_scope_json, COALESCE(billing_account_ref, ''),
		COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tenant_profiles WHERE tenant_key = ?`, NormalizeTenantKey(tenant))
	var profile TenantProfile
	err := row.Scan(&profile.ID, &profile.TenantKey, &profile.DisplayName, &profile.Status,
		&profile.DataResidencyRegion, &profile.SecretNamespace, &profile.CANamespace, &profile.DictionaryProfile,
		&profile.QuotaJSON, &profile.ControllerScopeJSON, &profile.BillingAccountRef,
		&profile.CreatedBy, &profile.UpdatedBy, &profile.CreatedAt, &profile.UpdatedAt)
	return profile, err
}

func ListTenantProfiles(limit int) ([]TenantProfile, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := DB.Query(`SELECT id, tenant_key, COALESCE(display_name, ''), status,
		COALESCE(data_residency_region, ''), COALESCE(secret_namespace, ''), COALESCE(ca_namespace, ''),
		COALESCE(dictionary_profile, ''), quota_json, controller_scope_json, COALESCE(billing_account_ref, ''),
		COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tenant_profiles ORDER BY tenant_key LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TenantProfile
	for rows.Next() {
		var profile TenantProfile
		if err := rows.Scan(&profile.ID, &profile.TenantKey, &profile.DisplayName, &profile.Status,
			&profile.DataResidencyRegion, &profile.SecretNamespace, &profile.CANamespace, &profile.DictionaryProfile,
			&profile.QuotaJSON, &profile.ControllerScopeJSON, &profile.BillingAccountRef,
			&profile.CreatedBy, &profile.UpdatedBy, &profile.CreatedAt, &profile.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, rows.Err()
}

func UpsertTenantResourceBinding(binding TenantResourceBinding) (TenantResourceBinding, error) {
	if DB == nil {
		return TenantResourceBinding{}, fmt.Errorf("database is not initialized")
	}
	normalized, err := normalizeTenantResourceBinding(binding)
	if err != nil {
		return TenantResourceBinding{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = DB.Exec(`INSERT INTO tenant_resource_bindings (
		tenant, resource_type, resource_id, owner_kind, status, evidence_json, created_by, updated_by, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(resource_type, resource_id) DO UPDATE SET
		tenant = excluded.tenant,
		owner_kind = excluded.owner_kind,
		status = excluded.status,
		evidence_json = excluded.evidence_json,
		updated_by = excluded.updated_by,
		updated_at = excluded.updated_at`,
		normalized.Tenant, normalized.ResourceType, normalized.ResourceID, normalized.OwnerKind, normalized.Status,
		defaultJSONObject(normalized.EvidenceJSON), nullIfEmpty(normalized.CreatedBy), nullIfEmpty(normalized.UpdatedBy), now, now)
	if err != nil {
		return TenantResourceBinding{}, err
	}
	return GetTenantResourceBinding(normalized.ResourceType, normalized.ResourceID)
}

func GetTenantResourceBinding(resourceType, resourceID string) (TenantResourceBinding, error) {
	if DB == nil {
		return TenantResourceBinding{}, fmt.Errorf("database is not initialized")
	}
	row := DB.QueryRow(`SELECT id, tenant, resource_type, resource_id, owner_kind, status, evidence_json,
		COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tenant_resource_bindings WHERE resource_type = ? AND resource_id = ?`,
		normalizeTenantResourceType(resourceType), strings.TrimSpace(resourceID))
	var binding TenantResourceBinding
	err := row.Scan(&binding.ID, &binding.Tenant, &binding.ResourceType, &binding.ResourceID, &binding.OwnerKind,
		&binding.Status, &binding.EvidenceJSON, &binding.CreatedBy, &binding.UpdatedBy, &binding.CreatedAt, &binding.UpdatedAt)
	return binding, err
}

func ListTenantResourceBindings(limit int) ([]TenantResourceBinding, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := DB.Query(`SELECT id, tenant, resource_type, resource_id, owner_kind, status, evidence_json,
		COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM tenant_resource_bindings ORDER BY tenant, resource_type, resource_id LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TenantResourceBinding
	for rows.Next() {
		var binding TenantResourceBinding
		if err := rows.Scan(&binding.ID, &binding.Tenant, &binding.ResourceType, &binding.ResourceID, &binding.OwnerKind,
			&binding.Status, &binding.EvidenceJSON, &binding.CreatedBy, &binding.UpdatedBy, &binding.CreatedAt, &binding.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, binding)
	}
	return out, rows.Err()
}

func RecordTenantIsolationEvent(record TenantIsolationEvent, retentionLimit int) error {
	if DB == nil {
		return nil
	}
	normalized := normalizeTenantIsolationEvent(record)
	requestTenantsJSON, _ := json.Marshal(normalized.RequestTenants)
	_, err := DB.Exec(`INSERT INTO tenant_isolation_events (
		event_id, tenant, resource_type, resource_id, action, decision, reason, actor, request_tenants_json, details_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(event_id) DO UPDATE SET
		decision = excluded.decision,
		reason = excluded.reason,
		details_json = excluded.details_json`,
		normalized.EventID, nullIfEmpty(normalized.Tenant), normalized.ResourceType, nullIfEmpty(normalized.ResourceID),
		normalized.Action, normalized.Decision, nullIfEmpty(normalized.Reason), nullIfEmpty(normalized.Actor),
		string(requestTenantsJSON), defaultJSONObject(normalized.DetailsJSON))
	if err != nil {
		return err
	}
	return pruneTenantIsolationEvents(retentionLimit)
}

func ListTenantIsolationEvents(limit int) ([]TenantIsolationEvent, error) {
	if DB == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(`SELECT id, event_id, COALESCE(tenant, ''), resource_type, COALESCE(resource_id, ''),
		action, decision, COALESCE(reason, ''), COALESCE(actor, ''), request_tenants_json, details_json, created_at
		FROM tenant_isolation_events ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []TenantIsolationEvent
	for rows.Next() {
		var record TenantIsolationEvent
		if err := rows.Scan(&record.ID, &record.EventID, &record.Tenant, &record.ResourceType, &record.ResourceID,
			&record.Action, &record.Decision, &record.Reason, &record.Actor, &record.RequestTenantsJSON,
			&record.DetailsJSON, &record.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(record.RequestTenantsJSON), &record.RequestTenants)
		out = append(out, record)
	}
	return out, rows.Err()
}

func SummarizeTenantIsolation() (TenantIsolationSummary, error) {
	var summary TenantIsolationSummary
	if DB == nil {
		return summary, nil
	}
	rows, err := DB.Query(`SELECT status, COUNT(*) FROM tenant_profiles GROUP BY status`)
	if err != nil {
		if !tableMissing(err) {
			return summary, err
		}
	} else {
		for rows.Next() {
			var status string
			var count int
			if err := rows.Scan(&status, &count); err != nil {
				rows.Close()
				return summary, err
			}
			summary.TenantCount += count
			switch status {
			case "active":
				summary.ActiveTenantCount = count
			case "suspended":
				summary.SuspendedTenantCount = count
			case "disabled":
				summary.DisabledTenantCount = count
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return summary, err
		}
		rows.Close()
	}
	_ = DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN owner_kind = 'shared' THEN 1 ELSE 0 END), 0) FROM tenant_resource_bindings`).Scan(&summary.ResourceBindingCount, &summary.SharedResourceCount)
	_ = DB.QueryRow(`SELECT COUNT(DISTINCT tenant) FROM policy_set_versions WHERE COALESCE(tenant, '') <> ''`).Scan(&summary.PolicySetTenantCount)
	_ = DB.QueryRow(`SELECT COUNT(*) FROM policy_set_versions WHERE COALESCE(tenant, '') = ''`).Scan(&summary.UntenantedPolicySets)
	_ = DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN decision = 'monitor' THEN 1 ELSE 0 END), 0) FROM tenant_isolation_events`).Scan(&summary.IsolationEventCount, &summary.DeniedEventCount, &summary.MonitorEventCount)
	_ = DB.QueryRow(`SELECT COALESCE(created_at, ''), COALESCE(decision, ''), COALESCE(resource_type, ''), COALESCE(resource_id, '')
		FROM tenant_isolation_events ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&summary.LastEventAt, &summary.LastEventDecision, &summary.LastEventResourceType, &summary.LastEventResourceID)
	_ = DB.QueryRow(`SELECT COALESCE(MAX(activated_at), '') FROM policy_set_versions WHERE COALESCE(tenant, '') <> ''`).Scan(&summary.LastPolicyActivationAt)
	return summary, nil
}

func TenantProfileExists(tenant string) bool {
	if DB == nil {
		return false
	}
	var count int
	err := DB.QueryRow(`SELECT COUNT(*) FROM tenant_profiles WHERE tenant_key = ? AND status = 'active'`, NormalizeTenantKey(tenant)).Scan(&count)
	return err == nil && count > 0
}

func normalizeTenantProfile(profile TenantProfile) (TenantProfile, error) {
	profile.TenantKey = NormalizeTenantKey(profile.TenantKey)
	if !validTenantKey(profile.TenantKey) {
		return profile, fmt.Errorf("tenant_key %q is invalid", profile.TenantKey)
	}
	profile.DisplayName = strings.TrimSpace(profile.DisplayName)
	profile.Status = strings.ToLower(strings.TrimSpace(profile.Status))
	if profile.Status == "" {
		profile.Status = "active"
	}
	switch profile.Status {
	case "active", "suspended", "disabled":
	default:
		return profile, fmt.Errorf("tenant status %q is invalid", profile.Status)
	}
	profile.DataResidencyRegion = normalizeTenantToken(profile.DataResidencyRegion)
	profile.SecretNamespace = normalizeTenantNamespace(profile.SecretNamespace, profile.TenantKey, "secret")
	profile.CANamespace = normalizeTenantNamespace(profile.CANamespace, profile.TenantKey, "ca")
	profile.DictionaryProfile = normalizeTenantToken(profile.DictionaryProfile)
	profile.QuotaJSON = defaultJSONObject(profile.QuotaJSON)
	profile.ControllerScopeJSON = defaultJSONObject(profile.ControllerScopeJSON)
	profile.BillingAccountRef = strings.TrimSpace(profile.BillingAccountRef)
	profile.CreatedBy = strings.TrimSpace(profile.CreatedBy)
	profile.UpdatedBy = strings.TrimSpace(profile.UpdatedBy)
	return profile, nil
}

func normalizeTenantResourceBinding(binding TenantResourceBinding) (TenantResourceBinding, error) {
	binding.Tenant = NormalizeTenantKey(binding.Tenant)
	if binding.Tenant == "" {
		return binding, fmt.Errorf("tenant is required")
	}
	binding.ResourceType = normalizeTenantResourceType(binding.ResourceType)
	if binding.ResourceType == "" {
		return binding, fmt.Errorf("resource_type is required")
	}
	binding.ResourceID = strings.TrimSpace(binding.ResourceID)
	if binding.ResourceID == "" || len(binding.ResourceID) > 256 || strings.ContainsAny(binding.ResourceID, "\x00\r\n") {
		return binding, fmt.Errorf("resource_id is invalid")
	}
	binding.OwnerKind = strings.ToLower(strings.TrimSpace(binding.OwnerKind))
	if binding.OwnerKind == "" {
		binding.OwnerKind = "tenant"
	}
	switch binding.OwnerKind {
	case "tenant", "shared":
	default:
		return binding, fmt.Errorf("owner_kind %q is invalid", binding.OwnerKind)
	}
	binding.Status = strings.ToLower(strings.TrimSpace(binding.Status))
	if binding.Status == "" {
		binding.Status = "active"
	}
	switch binding.Status {
	case "active", "retired", "blocked":
	default:
		return binding, fmt.Errorf("resource binding status %q is invalid", binding.Status)
	}
	binding.EvidenceJSON = defaultJSONObject(binding.EvidenceJSON)
	binding.CreatedBy = strings.TrimSpace(binding.CreatedBy)
	binding.UpdatedBy = strings.TrimSpace(binding.UpdatedBy)
	return binding, nil
}

func normalizeTenantIsolationEvent(record TenantIsolationEvent) TenantIsolationEvent {
	record.Tenant = NormalizeTenantKey(record.Tenant)
	record.ResourceType = normalizeTenantResourceType(record.ResourceType)
	if record.ResourceType == "" {
		record.ResourceType = "unknown"
	}
	record.ResourceID = strings.TrimSpace(record.ResourceID)
	record.Action = strings.ToLower(strings.TrimSpace(record.Action))
	if record.Action == "" {
		record.Action = "access"
	}
	record.Decision = strings.ToLower(strings.TrimSpace(record.Decision))
	switch record.Decision {
	case "allow", "deny", "monitor", "error":
	default:
		record.Decision = "error"
	}
	record.Reason = strings.TrimSpace(record.Reason)
	record.Actor = strings.TrimSpace(record.Actor)
	for i := range record.RequestTenants {
		record.RequestTenants[i] = NormalizeTenantKey(record.RequestTenants[i])
	}
	record.RequestTenants = normalizeTenantList(record.RequestTenants)
	record.DetailsJSON = defaultJSONObject(record.DetailsJSON)
	if strings.TrimSpace(record.EventID) == "" {
		record.EventID = tenantEventID(record)
	}
	return record
}

func pruneTenantIsolationEvents(retentionLimit int) error {
	if retentionLimit <= 0 || retentionLimit > 1000000 {
		retentionLimit = 10000
	}
	_, err := DB.Exec(`DELETE FROM tenant_isolation_events WHERE id NOT IN (
		SELECT id FROM tenant_isolation_events ORDER BY created_at DESC, id DESC LIMIT ?
	)`, retentionLimit)
	return err
}

func normalizeTenantList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = NormalizeTenantKey(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func validTenantKey(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func normalizeTenantToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}

func normalizeTenantResourceType(value string) string {
	return normalizeTenantToken(value)
}

func normalizeTenantNamespace(value, tenant, suffix string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = tenant + "/" + suffix
	}
	if len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
		return tenant + "/" + suffix
	}
	return value
}

func tenantEventID(record TenantIsolationEvent) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		record.Tenant,
		record.ResourceType,
		record.ResourceID,
		record.Action,
		record.Decision,
		time.Now().UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
