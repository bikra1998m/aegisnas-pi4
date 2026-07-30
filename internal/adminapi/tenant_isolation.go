package adminapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type tenantIsolationReport struct {
	SchemaVersion int                             `json:"schema_version"`
	Status        string                          `json:"status"`
	Message       string                          `json:"message"`
	Config        tenantIsolationConfigView       `json:"config"`
	Summary       db.TenantIsolationSummary       `json:"summary"`
	Tenants       []db.TenantProfile              `json:"tenants"`
	Resources     []db.TenantResourceBinding      `json:"resources"`
	RecentEvents  []db.TenantIsolationEvent       `json:"recent_events"`
	Warnings      []string                        `json:"warnings,omitempty"`
	VendorScope   []string                        `json:"vendor_scope"`
	ResourceScope []string                        `json:"resource_scope"`
	Checks        []tenantIsolationReadinessCheck `json:"checks"`
}

type tenantIsolationConfigView struct {
	MultiTenantEnabled        bool     `json:"multi_tenant_enabled"`
	DelegatedAdminEnabled     bool     `json:"delegated_admin_enabled"`
	RBACMode                  string   `json:"rbac_mode"`
	TenantClaim               string   `json:"tenant_claim,omitempty"`
	IsolationMode             string   `json:"isolation_mode"`
	FailClosed                bool     `json:"fail_closed"`
	DefaultTenant             string   `json:"default_tenant,omitempty"`
	MaxTenants                int      `json:"max_tenants"`
	TenantProfileRequired     bool     `json:"tenant_profile_required"`
	EnforcePolicySetOwnership bool     `json:"enforce_policy_set_ownership"`
	EnforceResourceOwnership  bool     `json:"enforce_resource_ownership"`
	ResourceAuditEnabled      bool     `json:"resource_audit_enabled"`
	ResourceRetentionLimit    int      `json:"resource_retention_limit"`
	SharedResourceTypes       []string `json:"shared_resource_types"`
}

type tenantIsolationReadinessCheck struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
	Required bool   `json:"required"`
}

type tenantProfileRequest struct {
	TenantKey           string         `json:"tenant_key"`
	DisplayName         string         `json:"display_name"`
	Status              string         `json:"status"`
	DataResidencyRegion string         `json:"data_residency_region"`
	SecretNamespace     string         `json:"secret_namespace"`
	CANamespace         string         `json:"ca_namespace"`
	DictionaryProfile   string         `json:"dictionary_profile"`
	Quota               map[string]any `json:"quota"`
	ControllerScope     map[string]any `json:"controller_scope"`
	BillingAccountRef   string         `json:"billing_account_ref"`
}

type tenantResourceBindingRequest struct {
	Tenant       string         `json:"tenant"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	OwnerKind    string         `json:"owner_kind"`
	Status       string         `json:"status"`
	Evidence     map[string]any `json:"evidence"`
}

type tenantIsolationEvaluateRequest struct {
	Tenant       string `json:"tenant"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
}

type tenantIsolationDecision struct {
	SchemaVersion int    `json:"schema_version"`
	Tenant        string `json:"tenant,omitempty"`
	ResourceType  string `json:"resource_type"`
	ResourceID    string `json:"resource_id,omitempty"`
	Action        string `json:"action"`
	Decision      string `json:"decision"`
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	Mode          string `json:"mode"`
}

func HandleGetTenantIsolation(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report, err := buildTenantIsolationReport(cfg, intQuery(r, "limit", 25, 1, 1000))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func HandleUpsertTenantProfile(w http.ResponseWriter, r *http.Request) {
	var payload tenantProfileRequest
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if pathTenant := strings.TrimSpace(chi.URLParam(r, "tenant")); pathTenant != "" {
		payload.TenantKey = pathTenant
	}
	tenant := db.NormalizeTenantKey(payload.TenantKey)
	if !tenantAllowed(r, tenant) {
		recordTenantIsolationDecision(r, tenant, "tenant_profile", tenant, "upsert", "deny", "tenant profile is outside admin scope")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	quotaJSON, err := marshalJSONObject(payload.Quota)
	if err != nil {
		http.Error(w, "invalid quota", http.StatusBadRequest)
		return
	}
	controllerScopeJSON, err := marshalJSONObject(payload.ControllerScope)
	if err != nil {
		http.Error(w, "invalid controller_scope", http.StatusBadRequest)
		return
	}
	actor := userFromRequest(r)
	profile, err := db.UpsertTenantProfile(db.TenantProfile{
		TenantKey:           tenant,
		DisplayName:         payload.DisplayName,
		Status:              payload.Status,
		DataResidencyRegion: payload.DataResidencyRegion,
		SecretNamespace:     payload.SecretNamespace,
		CANamespace:         payload.CANamespace,
		DictionaryProfile:   payload.DictionaryProfile,
		QuotaJSON:           quotaJSON,
		ControllerScopeJSON: controllerScopeJSON,
		BillingAccountRef:   payload.BillingAccountRef,
		CreatedBy:           actor,
		UpdatedBy:           actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	recordTenantIsolationDecision(r, tenant, "tenant_profile", tenant, "upsert", "allow", "tenant profile saved")
	audit(r, "upsert_tenant_profile", tenant, "saved")
	writeJSON(w, http.StatusOK, profile)
}

func HandleUpsertTenantResourceBinding(w http.ResponseWriter, r *http.Request) {
	var payload tenantResourceBindingRequest
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	tenant := db.NormalizeTenantKey(payload.Tenant)
	if !tenantAllowed(r, tenant) {
		recordTenantIsolationDecision(r, tenant, payload.ResourceType, payload.ResourceID, "bind", "deny", "resource binding is outside admin scope")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	evidenceJSON, err := marshalJSONObject(payload.Evidence)
	if err != nil {
		http.Error(w, "invalid evidence", http.StatusBadRequest)
		return
	}
	actor := userFromRequest(r)
	binding, err := db.UpsertTenantResourceBinding(db.TenantResourceBinding{
		Tenant:       tenant,
		ResourceType: payload.ResourceType,
		ResourceID:   payload.ResourceID,
		OwnerKind:    payload.OwnerKind,
		Status:       payload.Status,
		EvidenceJSON: evidenceJSON,
		CreatedBy:    actor,
		UpdatedBy:    actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	recordTenantIsolationDecision(r, tenant, binding.ResourceType, binding.ResourceID, "bind", "allow", "resource binding saved")
	audit(r, "upsert_tenant_resource_binding", binding.ResourceType+"/"+binding.ResourceID, "saved")
	writeJSON(w, http.StatusOK, binding)
}

func HandleEvaluateTenantIsolation(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var payload tenantIsolationEvaluateRequest
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	decision := evaluateTenantIsolation(r, cfg, payload)
	recordTenantIsolationDecision(r, decision.Tenant, decision.ResourceType, decision.ResourceID, decision.Action, decision.Decision, decision.Reason)
	status := http.StatusOK
	if !decision.Allowed && strings.EqualFold(decision.Mode, "enforce") {
		status = http.StatusForbidden
	}
	writeJSON(w, status, decision)
}

func buildTenantIsolationReport(cfg *config.Config, limit int) (tenantIsolationReport, error) {
	summary, err := db.SummarizeTenantIsolation()
	if err != nil {
		return tenantIsolationReport{}, err
	}
	tenants, err := db.ListTenantProfiles(cfg.Governance.MaxTenants)
	if err != nil {
		return tenantIsolationReport{}, err
	}
	resources, err := db.ListTenantResourceBindings(limit)
	if err != nil {
		return tenantIsolationReport{}, err
	}
	events, err := db.ListTenantIsolationEvents(limit)
	if err != nil {
		return tenantIsolationReport{}, err
	}
	report := tenantIsolationReport{
		SchemaVersion: 1,
		Config: tenantIsolationConfigView{
			MultiTenantEnabled:        cfg.Governance.MultiTenantEnabled,
			DelegatedAdminEnabled:     cfg.Governance.DelegatedAdminEnabled,
			RBACMode:                  defaultString(cfg.Governance.RBACMode, "local"),
			TenantClaim:               cfg.Governance.TenantClaim,
			IsolationMode:             effectiveTenantIsolationMode(cfg),
			FailClosed:                cfg.Governance.FailClosed,
			DefaultTenant:             db.NormalizeTenantKey(cfg.Governance.DefaultTenant),
			MaxTenants:                cfg.Governance.MaxTenants,
			TenantProfileRequired:     cfg.Governance.TenantProfileRequired,
			EnforcePolicySetOwnership: cfg.Governance.EnforcePolicySetOwnership,
			EnforceResourceOwnership:  cfg.Governance.EnforceResourceOwnership,
			ResourceAuditEnabled:      cfg.Governance.ResourceAuditEnabled,
			ResourceRetentionLimit:    cfg.Governance.ResourceRetentionLimit,
			SharedResourceTypes:       cfg.Governance.SharedResourceTypes,
		},
		Summary:       summary,
		Tenants:       tenants,
		Resources:     resources,
		RecentEvents:  events,
		VendorScope:   []string{"MSP", "Cisco", "Aruba", "Juniper Mist", "Ruckus", "Fortinet", "Meraki", "UniFi"},
		ResourceScope: []string{"policy_set", "secret_namespace", "ca_namespace", "dictionary_profile", "controller_scope", "billing_account", "nas_client", "certificate_template"},
	}
	report.Checks = tenantIsolationChecks(report)
	report.Status, report.Message = tenantIsolationStatus(report)
	return report, nil
}

func evaluateTenantIsolation(r *http.Request, cfg *config.Config, req tenantIsolationEvaluateRequest) tenantIsolationDecision {
	tenant := db.NormalizeTenantKey(req.Tenant)
	resourceType := strings.ToLower(strings.TrimSpace(req.ResourceType))
	resourceID := strings.TrimSpace(req.ResourceID)
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "access"
	}
	mode := effectiveTenantIsolationMode(cfg)
	decision := tenantIsolationDecision{
		SchemaVersion: 1,
		Tenant:        tenant,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Action:        action,
		Decision:      "allow",
		Allowed:       true,
		Reason:        "tenant isolation allows request",
		Mode:          mode,
	}
	if !cfg.Governance.MultiTenantEnabled {
		decision.Reason = "multi-tenant governance is disabled"
		return decision
	}
	if tenant == "" {
		return tenantDecisionDenied(decision, cfg, "tenant is required")
	}
	if !tenantAllowed(r, tenant) {
		return tenantDecisionDenied(decision, cfg, "tenant is outside admin scope")
	}
	if cfg.Governance.TenantProfileRequired && !db.TenantProfileExists(tenant) {
		return tenantDecisionDenied(decision, cfg, "active tenant profile is required")
	}
	if !cfg.Governance.EnforceResourceOwnership || resourceType == "" || resourceID == "" || sharedResourceTypeAllowed(cfg, resourceType) {
		return decision
	}
	binding, err := db.GetTenantResourceBinding(resourceType, resourceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return tenantDecisionDenied(decision, cfg, "resource binding is required")
		}
		return tenantDecisionErrored(decision, cfg, err.Error())
	}
	if binding.Status != "active" {
		return tenantDecisionDenied(decision, cfg, "resource binding is not active")
	}
	if binding.OwnerKind == "shared" {
		return decision
	}
	if db.NormalizeTenantKey(binding.Tenant) != tenant {
		return tenantDecisionDenied(decision, cfg, "resource belongs to another tenant")
	}
	return decision
}

func tenantIsolationChecks(report tenantIsolationReport) []tenantIsolationReadinessCheck {
	checks := []tenantIsolationReadinessCheck{
		{Key: "delegated_admin", Required: true, Status: boolCheck(report.Config.DelegatedAdminEnabled), Detail: "Delegated admin must be enabled for tenant-scoped operations."},
		{Key: "multi_tenant", Required: true, Status: boolCheck(report.Config.MultiTenantEnabled), Detail: "Multi-tenant governance must be enabled for hard tenant isolation."},
		{Key: "policy_set_ownership", Required: true, Status: boolCheck(report.Config.EnforcePolicySetOwnership), Detail: "Policy set ownership must be enforced per tenant."},
		{Key: "resource_ownership", Required: true, Status: boolCheck(report.Config.EnforceResourceOwnership), Detail: "Resource ownership bindings must be enforced per tenant."},
		{Key: "audit", Required: true, Status: boolCheck(report.Config.ResourceAuditEnabled), Detail: "Tenant isolation decisions must be audited."},
	}
	profilesStatus := "passed"
	if report.Config.TenantProfileRequired && report.Summary.ActiveTenantCount == 0 {
		profilesStatus = "blocked"
	}
	checks = append(checks, tenantIsolationReadinessCheck{Key: "tenant_profiles", Required: report.Config.TenantProfileRequired, Status: profilesStatus, Detail: "Active tenant profiles define storage, secret, CA, dictionary, quota, controller, and billing scopes."})
	modeStatus := "passed"
	if report.Config.IsolationMode != "enforce" {
		modeStatus = "degraded"
	}
	checks = append(checks, tenantIsolationReadinessCheck{Key: "enforcement_mode", Required: true, Status: modeStatus, Detail: "Production tenant isolation should run in enforce mode."})
	return checks
}

func tenantIsolationStatus(report tenantIsolationReport) (string, string) {
	if !report.Config.MultiTenantEnabled {
		return "disabled", "Multi-tenant governance is disabled."
	}
	for _, check := range report.Checks {
		if check.Required && check.Status == "blocked" {
			return "blocked", check.Detail
		}
	}
	if report.Config.IsolationMode != "enforce" {
		return "degraded", "Tenant isolation is in monitor mode."
	}
	return "passed", "Tenant isolation is enforced with profile, policy-set, resource, and audit controls."
}

func tenantDecisionDenied(decision tenantIsolationDecision, cfg *config.Config, reason string) tenantIsolationDecision {
	decision.Allowed = !strings.EqualFold(effectiveTenantIsolationMode(cfg), "enforce")
	decision.Decision = "deny"
	if decision.Allowed {
		decision.Decision = "monitor"
	}
	decision.Reason = reason
	return decision
}

func tenantDecisionErrored(decision tenantIsolationDecision, cfg *config.Config, reason string) tenantIsolationDecision {
	decision.Allowed = !cfg.Governance.FailClosed
	decision.Decision = "error"
	decision.Reason = reason
	return decision
}

func effectiveTenantIsolationMode(cfg *config.Config) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Governance.IsolationMode))
	if mode == "" {
		mode = "monitor"
	}
	return mode
}

func sharedResourceTypeAllowed(cfg *config.Config, resourceType string) bool {
	resourceType = strings.ToLower(strings.TrimSpace(resourceType))
	for _, allowed := range cfg.Governance.SharedResourceTypes {
		if strings.EqualFold(strings.TrimSpace(allowed), resourceType) {
			return true
		}
	}
	return false
}

func boolCheck(value bool) string {
	if value {
		return "passed"
	}
	return "blocked"
}

func marshalJSONObject(value map[string]any) (string, error) {
	if len(value) == 0 {
		return "{}", nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if !json.Valid(encoded) {
		return "", fmt.Errorf("invalid JSON object")
	}
	return string(encoded), nil
}
