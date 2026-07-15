package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/identity"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

type productionReadinessReport struct {
	GeneratedAt       string                            `json:"generated_at"`
	Status            string                            `json:"status"`
	Ready             bool                              `json:"ready"`
	Score             int                               `json:"score"`
	Message           string                            `json:"message"`
	DeploymentProfile string                            `json:"deployment_profile"`
	DeploymentForm    string                            `json:"deployment_form"`
	BlockingCount     int                               `json:"blocking_count"`
	WarningCount      int                               `json:"warning_count"`
	DegradedCount     int                               `json:"degraded_count"`
	PassingCount      int                               `json:"passing_count"`
	VendorIdentity    productionVendorIdentityState     `json:"vendor_identity"`
	HardwareScaling   config.HardwareScalingPlan        `json:"hardware_scaling"`
	NASProfileSummary vendorCompatibilityProfileSummary `json:"nas_profile_summary"`
	VendorRuntime     db.VendorObservabilitySummary     `json:"vendor_runtime"`
	Checks            []productionReadinessCheck        `json:"checks"`
}

type productionVendorIdentityState struct {
	Enabled                    bool     `json:"enabled"`
	Name                       string   `json:"name"`
	ConfiguredID               int      `json:"configured_id"`
	ConfiguredIDPlaceholder    bool     `json:"configured_id_placeholder"`
	IDSource                   string   `json:"id_source"`
	DictionaryFilename         string   `json:"dictionary_filename"`
	DictionaryInstallPath      string   `json:"dictionary_install_path"`
	DictionaryInclude          string   `json:"dictionary_include"`
	DictionaryDetected         bool     `json:"dictionary_detected"`
	DictionaryImportPaths      []string `json:"dictionary_import_paths,omitempty"`
	PENRegistryURL             string   `json:"pen_registry_url"`
	PENApplyURL                string   `json:"pen_apply_url"`
	ProductCompatibilityActive bool     `json:"product_compatibility_active"`
	IdentityMode               string   `json:"identity_mode"`
	AssignedOrganization       string   `json:"assigned_organization,omitempty"`
	EvidenceValid              bool     `json:"evidence_valid"`
	AssignmentActive           bool     `json:"assignment_active"`
	AssignmentRecordSHA256     string   `json:"assignment_record_sha256,omitempty"`
	LegacyIDs                  []int    `json:"legacy_ids,omitempty"`
	LegacyAcceptUntil          string   `json:"legacy_accept_until,omitempty"`
}

type productionReadinessCheck struct {
	Key            string   `json:"key"`
	Category       string   `json:"category"`
	Label          string   `json:"label"`
	Status         string   `json:"status"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
}

type productionReadinessSummary struct {
	Status        string `json:"status"`
	Ready         bool   `json:"ready"`
	Score         int    `json:"score"`
	Message       string `json:"message"`
	BlockingCount int    `json:"blocking_count"`
	WarningCount  int    `json:"warning_count"`
	DegradedCount int    `json:"degraded_count"`
	PassingCount  int    `json:"passing_count"`
}

func HandleGetProductionReadiness(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	report := buildProductionReadinessReport(cfg)
	writeJSON(w, http.StatusOK, report)
}

func buildProductionReadinessReport(cfg *config.Config) productionReadinessReport {
	report := productionReadinessReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		DeploymentProfile: config.EffectiveDeploymentProfile(cfg.Deployment.Profile),
		DeploymentForm:    config.EffectiveDeploymentForm(cfg.Deployment.Form),
		HardwareScaling:   config.EvaluateHardwareScalingPlan(cfg),
	}
	report.VendorIdentity = buildProductionVendorIdentityState(cfg)
	report.NASProfileSummary = vendorProfileSummaryForProductionReadiness(cfg)
	report.VendorRuntime = vendorRuntimeSummaryForProductionReadiness(&report)

	addProductionConfigCheck(&report, cfg)
	addProductionScalingCheck(&report)
	addProductionVendorIdentityCheck(&report)
	addProductionAttributeRegistryCheck(&report)
	addProductionVSACodecCheck(&report)
	addProductionOpaquePassThroughCheck(&report, cfg)
	addProductionRadiusPacketHardeningCheck(&report, cfg)
	addProductionDynamicNASClientsCheck(&report, cfg)
	addProductionProxyRoutingCheck(&report, cfg)
	addProductionTransportPolicyCheck(&report, cfg)
	addProductionProxyPolicyCheck(&report, cfg)
	addProductionAccountingSpoolCheck(&report, cfg)
	addProductionFallbackPolicyCheck(&report, cfg)
	addProductionIdentityFailoverCheck(&report, cfg)
	addProductionSecretProviderCheck(&report, cfg)
	addProductionDatabaseDataPlaneCheck(&report, cfg)
	addProductionDictionaryReleaseProfileCheck(&report, cfg)
	addProductionCompatibilityEvidenceCheck(&report, cfg)
	addProductionDictionaryCheck(&report)
	addProductionVendorPackCheck(&report, cfg)
	addProductionNASProfileCheck(&report)
	addProductionRadSecCheck(&report, cfg)
	addProductionFeatureCapabilityCheck(&report, cfg)
	addProductionControllerCheck(&report, cfg)
	addProductionVendorRuntimeCheck(&report)

	finalizeProductionReadinessReport(&report)
	return report
}

func addProductionRadiusPacketHardeningCheck(report *productionReadinessReport, cfg *config.Config) {
	hardening := radius.BuildPacketHardeningReport(cfg)
	status := "passed"
	switch hardening.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	if hardening.SchemaVersion != radius.PacketHardeningSchemaVersion ||
		!hardening.Policy.Enabled ||
		!hardening.Policy.FailClosed ||
		!hardening.Policy.RequireKnownSource ||
		hardening.Policy.RequireMessageAuthenticator == "never" ||
		hardening.Limits.MaxPacketBytes > 4096 ||
		hardening.Limits.ReplayWindowSeconds <= 0 ||
		hardening.Limits.PerClientRateLimitPerSecond <= 0 {
		if status == "passed" {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_packet_hardening",
		Category: "radius",
		Label:    "RADIUS Packet Hardening",
		Status:   status,
		Summary: fmt.Sprintf("Packet hardening schema %d is %s with Message-Authenticator=%s, known-source=%t, replay window=%ds, rate limit=%d/s, and %d recent hardening event(s).",
			hardening.SchemaVersion, hardening.Status, hardening.Policy.RequireMessageAuthenticator, hardening.Policy.RequireKnownSource,
			hardening.Limits.ReplayWindowSeconds, hardening.Limits.PerClientRateLimitPerSecond, hardening.RuntimeStats.TotalEvents),
		Recommendation: "Keep packet hardening enabled and fail-closed with known RADIUS clients, Message-Authenticator auto or always, replay cache, rate limits, and the NAS-0009 release checklist for external packet-capture evidence.",
		Dependencies:   []string{"radius.packet_hardening", "/api/v1/system/radius-hardening", "radius_packet_hardening_events"},
	})
}

func addProductionDynamicNASClientsCheck(report *productionReadinessReport, cfg *config.Config) {
	dynamicClients := radius.BuildDynamicNASClientReport(cfg)
	status := "passed"
	switch dynamicClients.Status {
	case "disabled":
		status = "degraded"
	case "degraded", "pending":
		status = "degraded"
	case "blocked":
		status = "blocked"
	}
	if dynamicClients.Enabled {
		if strings.TrimSpace(dynamicClients.Policy.EnrollmentTokenRef) == "" {
			status = "blocked"
		}
		if !dynamicClients.Policy.ApprovalRequired {
			status = "blocked"
		}
		if dynamicClients.Policy.DiscoveryEnabled && len(dynamicClients.Policy.DiscoveryAllowedCIDRs) == 0 {
			if status == "passed" {
				status = "degraded"
			}
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "dynamic_nas_clients",
		Category: "radius",
		Label:    "Dynamic NAS Clients And Capability Discovery",
		Status:   status,
		Summary: fmt.Sprintf("Dynamic NAS clients are %s with %d pending, %d approved, %d dynamic client(s), and %d capability template(s).",
			dynamicClients.Status, dynamicClients.Summary.PendingCount, dynamicClients.Summary.ApprovedCount,
			dynamicClients.Summary.DynamicClients, dynamicClients.Summary.CapabilityTemplates),
		Recommendation: "Keep approval required, use radius.dynamic_clients.enrollment_token_ref, restrict discovery CIDRs, approve only credential-backed clients, and complete the NAS-0013 release certification checklist before production claims.",
		Dependencies:   []string{"radius.dynamic_clients", "/api/v1/nas/enroll", "/api/v1/system/nas-clients", "nas_client_enrollments", "nas_client_capability_templates", "nas_client_events"},
	})
}

func addProductionProxyRoutingCheck(report *productionReadinessReport, cfg *config.Config) {
	routing := radius.BuildProxyRoutingReport(cfg)
	status := "passed"
	if routing.Status == "blocked" {
		status = "blocked"
	} else if routing.Status == "degraded" {
		status = "degraded"
	}
	if routing.Enabled {
		if routing.Summary.RouteCount == 0 || routing.Summary.ServerCount == 0 {
			status = "blocked"
		}
		if routing.Summary.DefaultRouteCount > 1 {
			status = "blocked"
		}
	}

	summary := "Upstream AAA proxy routing is disabled."
	if routing.Enabled {
		defaultRealm := routing.Summary.DefaultRealm
		if defaultRealm == "" {
			defaultRealm = "none"
		}
		summary = fmt.Sprintf("Proxy routing schema %d is %s with %d route(s), %d upstream server(s), and default realm %s.",
			routing.SchemaVersion, routing.Status, routing.Summary.RouteCount, routing.Summary.ServerCount, defaultRealm)
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "radius_proxy_routes",
		Category:       "radius",
		Label:          "RADIUS Proxy Route Table",
		Status:         status,
		Summary:        summary,
		Recommendation: "Use explicit radius.upstream.routes for every production realm, keep server bindings named and secret-backed, review /api/v1/system/proxy-routes before generation, and capture NAS-0010 external interoperability evidence before release sign-off.",
		Dependencies:   []string{"radius.upstream.routes", "/api/v1/system/proxy-routes", "proxy.conf", "sites-enabled/default", "sites-enabled/inner-tunnel"},
	})
}

func addProductionTransportPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	transportPolicy := radius.BuildTransportPolicyReport(cfg)
	status := "passed"
	if transportPolicy.Status == "blocked" {
		status = "blocked"
	} else if transportPolicy.Status == "degraded" {
		status = "degraded"
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !transportPolicy.Enabled || transportPolicy.Policy.Mode != "enforce" || !transportPolicy.Policy.FailClosed {
			status = "blocked"
		}
		if transportPolicy.Summary.ViolationCount > 0 {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_transport_policy",
		Category: "radius",
		Label:    "RADIUS Transport Downgrade Policy",
		Status:   status,
		Summary: fmt.Sprintf("Transport policy schema %d is %s in %s mode with %d route(s), %d mixed route(s), and %d violation(s).",
			transportPolicy.SchemaVersion, transportPolicy.Status, transportPolicy.Policy.Mode,
			transportPolicy.Summary.RouteCount, transportPolicy.Summary.MixedTransportRoutes, transportPolicy.Summary.ViolationCount),
		Recommendation: "Set radius.upstream.transport_policy.mode=enforce, keep fail_closed=true, require RadSec on sensitive routes, and explicitly approve any UDP or mixed-transport exceptions before production proxy operation.",
		Dependencies:   []string{"radius.upstream.transport_policy", "/api/v1/system/transport-policy", "proxy.conf:default_fallback=no"},
	})
}

func addProductionProxyPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	policy := radius.BuildProxyPolicyReport(cfg)
	status := "passed"
	switch policy.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		if cfg != nil && cfg.Radius.Upstream.Enabled {
			status = "degraded"
		}
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !policy.Enabled || policy.Summary.RoutePolicyCount == 0 || !policy.FreeRADIUS.LoopMarkerEnforced {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_proxy_policy",
		Category: "radius",
		Label:    "RADIUS Proxy Loop And Attribute Policy",
		Status:   status,
		Summary: fmt.Sprintf("Proxy policy schema %d is %s with %d route policy item(s), %d vendor allow selector(s), %d deny selector(s), and %d rewrite rule(s).",
			policy.SchemaVersion, policy.Status, policy.Summary.RoutePolicyCount,
			policy.Summary.AllowVendorIDCount+policy.Summary.AllowVendorAttributeCount,
			policy.Summary.DenyVendorIDCount+policy.Summary.DenyVendorAttributeCount,
			policy.Summary.RewriteRuleCount),
		Recommendation: "Keep radius.upstream.proxy_policy enabled, fail-closed, loop-marker enforced, route-scoped, and reviewed through /api/v1/system/proxy-policy before production proxy operation.",
		Dependencies:   []string{"radius.upstream.proxy_policy", "/api/v1/system/proxy-policy", "sites-enabled/default:pre-proxy", "sites-enabled/inner-tunnel:pre-proxy"},
	})
}

func addProductionAccountingSpoolCheck(report *productionReadinessReport, cfg *config.Config) {
	spool := radius.BuildAccountingSpoolReport(cfg)
	status := "passed"
	switch spool.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		if cfg != nil && cfg.Radius.Upstream.Enabled {
			status = "degraded"
		}
	}
	if cfg != nil && cfg.Radius.Upstream.Enabled {
		if !spool.Enabled || spool.Policy.MaxQueueRecords <= 0 || spool.Policy.MaxAttempts <= 0 || spool.Policy.RecordTTLSeconds <= 0 {
			status = "blocked"
		}
		if spool.Summary.QueueUtilization >= 90 || spool.Summary.PoisonCount > 0 {
			if status == "passed" {
				status = "degraded"
			}
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_accounting_spool",
		Category: "radius",
		Label:    "Durable RADIUS Accounting Spool",
		Status:   status,
		Summary: fmt.Sprintf("Accounting spool schema %d is %s with %d queued, %d retrying, %d poison, %d expired, and %d%% queue utilization.",
			spool.SchemaVersion, spool.Status, spool.Summary.QueuedCount, spool.Summary.RetryingCount,
			spool.Summary.PoisonCount, spool.Summary.ExpiredCount, spool.Summary.QueueUtilization),
		Recommendation: "Keep radius.upstream.accounting_spool enabled for proxy accounting, monitor /api/v1/system/accounting-spool, and complete the NAS-0012 release certification replay and outage drills.",
		Dependencies:   []string{"radius.upstream.accounting_spool", "/api/v1/system/accounting-spool", "/api/v1/system/accounting-spool/replay", "radius_accounting_spool", "radius_accounting_spool_attempts"},
	})
}

func addProductionFallbackPolicyCheck(report *productionReadinessReport, cfg *config.Config) {
	fallback := radius.BuildFallbackPolicyReport(cfg)
	status := "passed"
	switch fallback.Status {
	case "blocked":
		status = "blocked"
	case "degraded":
		status = "degraded"
	}
	activePortalFallback := cfg != nil && cfg.Radius.Upstream.Enabled && cfg.Portal.RadiusAuth && cfg.Portal.LocalFallback
	if activePortalFallback {
		if !fallback.Enabled || fallback.Policy.Mode != "enforce" || !fallback.Policy.FailClosed {
			status = "blocked"
		}
		if fallback.Policy.RequireIdentityAllowlist && !fallback.Summary.IdentityAllowlistSet {
			status = "blocked"
		}
		if fallback.Policy.AuditEnabled && db.DB == nil {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "radius_fallback_policy",
		Category: "radius",
		Label:    "Upstream Outage Fallback Policy",
		Status:   status,
		Summary: fmt.Sprintf("Fallback policy schema %d is %s in %s mode with local=%t ldap=%t allowlists users=%d realms=%d roles=%d and %d audited decision(s).",
			fallback.SchemaVersion, fallback.Status, fallback.Policy.Mode, fallback.Policy.AllowPortalLocal, fallback.Policy.AllowLDAP,
			fallback.Summary.AllowedUserCount, fallback.Summary.AllowedRealmCount, fallback.Summary.AllowedRoleCount, fallback.AuditSummary.TotalRecords),
		Recommendation: "Set radius.upstream.fallback_policy.mode=enforce, keep fail_closed=true, bound max_outage_seconds, configure identity allowlists, and review /api/v1/system/fallback-policy before production upstream AAA operation.",
		Dependencies:   []string{"radius.upstream.fallback_policy", "portal.radius_auth", "portal.local_fallback", "/api/v1/system/fallback-policy", "radius_fallback_events"},
	})
}

func addProductionIdentityFailoverCheck(report *productionReadinessReport, cfg *config.Config) {
	failover := identity.BuildFailoverReport(cfg)
	status := "passed"
	switch failover.Status {
	case "blocked":
		status = "blocked"
	case "degraded", "disabled":
		status = "degraded"
	}
	activePortalIdentity := cfg != nil && (cfg.Portal.Enabled || cfg.Portal.RadiusAuth || cfg.Portal.LocalFallback || cfg.LDAP.Enabled)
	if activePortalIdentity {
		if !failover.Enabled || failover.Policy.Mode != "enforce" || !failover.Policy.FailClosed {
			status = "blocked"
		}
		if failover.Summary.ExecutableSourceCount == 0 {
			status = "blocked"
		}
		if failover.Policy.AuditEnabled && db.DB == nil {
			status = "blocked"
		}
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "identity_source_failover",
		Category: "authentication",
		Label:    "Identity Source HA And Deterministic Failover",
		Status:   status,
		Summary: fmt.Sprintf("Identity failover schema %d is %s in %s mode with %d executable source(s), %d open circuit(s), cache=%t, and %d audited decision(s).",
			failover.SchemaVersion, failover.Status, failover.Policy.Mode, failover.Summary.ExecutableSourceCount,
			failover.Summary.OpenCircuitCount, failover.Policy.CacheCredentials, failover.AuditSummary.TotalRecords),
		Recommendation: "Set identity.failover.mode=enforce, keep fail_closed=true, define source_order, keep audit enabled, and review /api/v1/system/identity-failover before production authentication cutover.",
		Dependencies:   []string{"identity.failover", "identity_sources", "/api/v1/system/identity-failover", "identity_source_events", "identity_source_cache"},
	})
}

func addProductionDatabaseDataPlaneCheck(report *productionReadinessReport, cfg *config.Config) {
	statusReport := db.BuildStatusReport(cfg)
	status := "passed"
	if statusReport.Status == "blocked" {
		status = "blocked"
	} else if statusReport.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "database_data_plane",
		Category: "architecture",
		Label:    "Database Data Plane",
		Status:   status,
		Summary: fmt.Sprintf("Database backend %s is %s with schema target %d, DSN reference set=%t, TLS mode=%s, and HA-ready=%t.",
			statusReport.Active.Backend, statusReport.Status, db.LatestSchemaVersion(), statusReport.Active.DSNRefSet, statusReport.Active.SSLMode, statusReport.ReadyForHA),
		Recommendation: "Use database.backend=postgres, database.dsn_ref, TLS sslmode verify-full or verify-ca, and managed PostgreSQL backup/HA validation before enterprise production sign-off.",
		Dependencies:   []string{"database.backend", "database.dsn_ref", "database.sslmode", "/api/v1/system/database", "database_backend_events"},
	})
}

func addProductionAttributeRegistryCheck(report *productionReadinessReport) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        "The generated RADIUS attribute registry could not be validated.",
			Recommendation: "Regenerate the pinned registry, review the source diff, and rebuild the appliance.",
			Dependencies:   []string{"configs/attribute_registry"},
		})
		return
	}
	if registry.SchemaVersion != productconfigs.AttributeRegistrySchemaVersion || registry.SourceAttributeCount != 7654 || registry.SourceFileCount != 246 {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        fmt.Sprintf("Registry contract mismatch: schema %d, %d source files, %d source attributes.", registry.SchemaVersion, registry.SourceFileCount, registry.SourceAttributeCount),
			Recommendation: "Review and approve the dictionary release diff before activating the new registry.",
			Dependencies:   []string{"attribute registry source manifest"},
		})
		return
	}
	if err := registry.ValidateCompatibilityPacks(productconfigs.AegisNASVendorCompatibilityPacks()); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "blocked",
			Summary:        "Compatibility pack metadata conflicts with the generated registry: " + err.Error(),
			Recommendation: "Regenerate and review the typed registry and renderer pack declarations together.",
			Dependencies:   []string{"configs/vendor_packs.go", "configs/attribute_registry"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "attribute_registry", Category: "radius", Label: "Typed Attribute Registry", Status: "passed",
		Summary: fmt.Sprintf("FreeRADIUS %s registry schema %d validates %d source attributes with SHA-256 %s.", registry.SourceRelease, registry.SchemaVersion, registry.SourceAttributeCount, registry.SourceSHA256),
	})
}

func addProductionVSACodecCheck(report *productionReadinessReport) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "vsa_codec", Category: "radius", Label: "VSA Codec", Status: "blocked",
			Summary:        "The VSA codec cannot be validated because the generated registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance before enabling broad vendor compatibility.",
			Dependencies:   []string{"configs/attribute_registry", "internal/radius/vsa_codec.go"},
		})
		return
	}
	codec := radius.BuildVSACodecReport(registry, productconfigs.AegisNASVendorDictionaryCatalog())
	status := "passed"
	if codec.SchemaVersion != radius.VSACodecSchemaVersion || codec.Status != "ready" ||
		codec.Summary.SourceAttributeCount != registry.SourceAttributeCount ||
		codec.Summary.GroupedAttributeCount == 0 ||
		len(codec.SupportedFormats) < 9 {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "vsa_codec", Category: "radius", Label: "VSA Codec", Status: status,
		Summary: fmt.Sprintf("Codec schema %d is %s for %d registry attributes, %d grouped/OID attributes, repeated values, tags, malformed lengths, and %d vendor wire formats.",
			codec.SchemaVersion, codec.Status, codec.Summary.SourceAttributeCount, codec.Summary.GroupedAttributeCount, len(codec.SupportedFormats)),
		Recommendation: "Use /api/v1/system/vsa-codec for software readiness and the NAS-0005 release checklist for hardware/vendor certification evidence.",
		Dependencies:   []string{"internal/radius/vsa_codec.go", "configs/attribute_registry.go"},
	})
}

func addProductionOpaquePassThroughCheck(report *productionReadinessReport, cfg *config.Config) {
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "opaque_passthrough", Category: "radius", Label: "Opaque Attribute Pass-through", Status: "blocked",
			Summary:        "The opaque pass-through policy cannot be validated because the generated registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance before enabling proxy pass-through.",
			Dependencies:   []string{"configs/attribute_registry", "internal/radius/opaque_passthrough.go"},
		})
		return
	}
	reportPayload := radius.BuildOpaquePassThroughReport(registry, cfg)
	status := "passed"
	if reportPayload.Status != "ready" || reportPayload.SchemaVersion != radius.OpaquePassThroughSchemaVersion ||
		reportPayload.Policy.DefaultAction != "drop" || reportPayload.Limits.MaxAttributesPerPacket < 1 ||
		reportPayload.Limits.MaxAttributeBytes > 249 || len(reportPayload.SensitiveTypes) == 0 {
		status = "blocked"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "opaque_passthrough", Category: "radius", Label: "Opaque Attribute Pass-through", Status: status,
		Summary: fmt.Sprintf("Opaque pass-through schema %d is %s with default action %s, %d allow rule(s), %d sensitive standard type denylist entries, and %d byte total packet budget.",
			reportPayload.SchemaVersion, reportPayload.Status, reportPayload.Policy.DefaultAction, reportPayload.Summary.RuleCount, len(reportPayload.SensitiveTypes), reportPayload.Limits.MaxTotalBytesPerPacket),
		Recommendation: "Use /api/v1/system/opaque-passthrough to review the effective allowlist; real proxy and device evidence stays in the NAS-0006 release checklist.",
		Dependencies:   []string{"radius.vendor.opaque_pass_through", "internal/radius/opaque_passthrough.go"},
	})
}

func addProductionSecretProviderCheck(report *productionReadinessReport, cfg *config.Config) {
	stored, err := storedSecretSources()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "secret_providers", Category: "security", Label: "Secret Providers", Status: "blocked",
			Summary:        "Secret provider inventory cannot be read from the database.",
			Recommendation: "Run database migration and inspect /api/v1/system/secret-providers before production sign-off.",
			Dependencies:   []string{"radius_clients.secret_ref"},
		})
		return
	}
	reportPayload := secrets.BuildReport(context.Background(), cfg, stored)
	status := "passed"
	if reportPayload.Status == "blocked" {
		status = "blocked"
	} else if reportPayload.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "secret_providers", Category: "security", Label: "Secret Providers", Status: status,
		Summary: fmt.Sprintf("Secret provider schema %d is %s with %d reference(s), %d inline source(s), %d missing reference(s), and %d unsupported provider source(s).",
			reportPayload.SchemaVersion, reportPayload.Status, reportPayload.Summary.ReferenceCount, reportPayload.Summary.InlineCount, reportPayload.Summary.MissingCount, reportPayload.Summary.UnsupportedCount),
		Recommendation: "Move RADIUS, LDAP, integration, and HA secrets to env: or file: refs; keep external secret-manager rollout evidence in the NAS-0007 release checklist.",
		Dependencies:   []string{"security.secrets", "radius_clients.secret_ref", "/api/v1/system/secret-providers"},
	})
}

func addProductionDictionaryReleaseProfileCheck(report *productionReadinessReport, cfg *config.Config) {
	activeID := productconfigs.DefaultDictionaryReleaseProfileID
	if cfg != nil {
		activeID = productconfigs.EffectiveDictionaryReleaseProfileID(cfg.Radius.Vendor.DictionaryRelease)
	}
	profile, ok := productconfigs.DictionaryReleaseProfileByID(activeID)
	if !ok {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The configured dictionary release profile is not embedded in this build.",
			Recommendation: "Use the pinned release profile shipped with this appliance or install a reviewed build for the requested release.",
			Dependencies:   []string{"radius.vendor.dictionary_release"},
		})
		return
	}
	registry, err := productconfigs.BuiltInAttributeRegistry()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The dictionary release profile cannot be validated because the attribute registry is unavailable.",
			Recommendation: "Regenerate the pinned registry and rebuild the appliance.",
			Dependencies:   []string{"attribute_registry"},
		})
		return
	}
	if err := productconfigs.ValidateDictionaryReleaseProfile(profile, registry, productconfigs.AegisNASVendorCompatibilityPacks()); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "blocked",
			Summary:        "The dictionary release profile is inconsistent with the registry or compatibility packs: " + err.Error(),
			Recommendation: "Review the release profile, alias table, firmware scopes, registry hash, and compatibility pack metadata together.",
			Dependencies:   []string{"configs/dictionary_release_profiles.go", "configs/attribute_registry"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "dictionary_release_profile", Category: "radius", Label: "Dictionary Release Profile", Status: "passed",
		Summary: fmt.Sprintf("Active profile %s pins FreeRADIUS %s with %d vendor aliases, %d attribute aliases, and %d firmware scopes.", profile.ID, profile.Release, profile.VendorAliasCount, profile.AttributeAliasCount, profile.FirmwareProfileCount),
	})
}

func addProductionCompatibilityEvidenceCheck(report *productionReadinessReport, cfg *config.Config) {
	compatibility := productconfigs.AegisNASVendorCompatibilityReport()
	if cfg != nil && len(cfg.Radius.Vendor.CompatibilityPacks) > 0 {
		compatibility.ActivePacks = normalizeVendorCompatibilityPackKeys(cfg.Radius.Vendor.CompatibilityPacks)
	}
	if cfg != nil {
		vendor := cfg.Radius.Vendor
		compatibility.Catalog = productconfigs.AegisNASVendorDictionaryCatalogFor(vendor.Name, vendor.ID)
		for index := range compatibility.Packs {
			if compatibility.Packs[index].Key == productconfigs.VendorPackAegisNAS {
				compatibility.Packs[index].VendorName = strings.TrimSpace(vendor.Name)
				compatibility.Packs[index].VendorID = vendor.ID
			}
		}
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	if len(importPaths) > 0 {
		imported := productconfigs.LoadVendorDictionaryCatalog(importPaths)
		compatibility.Catalog = productconfigs.MergeVendorDictionaryCatalogs("built-in AegisNAS, "+imported.Source, compatibility.Catalog, imported)
	}
	evidence := productconfigs.BuildCompatibilityEvidenceReport(compatibility.Catalog, compatibility.Packs, compatibility.ActivePacks)
	if err := productconfigs.ValidateCompatibilityEvidenceReport(evidence); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key: "compatibility_evidence", Category: "radius", Label: "Compatibility Evidence Model", Status: "blocked",
			Summary:        "Compatibility evidence could not be validated: " + err.Error(),
			Recommendation: "Review the evidence model, registry, vendor packs, and dictionary release profile before claiming compatibility.",
			Dependencies:   []string{"configs/compatibility_evidence.go", "configs/vendor_packs.go", "configs/attribute_registry"},
		})
		return
	}
	activeBlocked := 0
	for _, record := range evidence.Records {
		if record.Active && record.SoftwareState == productconfigs.EvidenceSoftwareStateBlocked {
			activeBlocked++
		}
	}
	status := "passed"
	if activeBlocked > 0 {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{
		Key: "compatibility_evidence", Category: "radius", Label: "Compatibility Evidence Model", Status: status,
		Summary: fmt.Sprintf("Evidence schema %d tracks %d mappings: %d software-ready, %d planned, %d blocked (%d active), %d requiring external certification.",
			evidence.SchemaVersion, evidence.Summary.TotalRecords, evidence.Summary.SoftwareReadyCount, evidence.Summary.SoftwarePlannedCount, evidence.Summary.SoftwareBlockedCount, activeBlocked, evidence.Summary.ExternalRequiredCount),
		Recommendation: "Use /api/v1/system/compatibility-evidence before publishing vendor compatibility claims.",
	})
}

func addProductionRadSecCheck(report *productionReadinessReport, cfg *config.Config) {
	paths := []string{}
	if cfg.Radius.RadSec.Enabled {
		paths = append(paths, cfg.Radius.RadSec.CertificateFile, cfg.Radius.RadSec.PrivateKeyFile)
		if cfg.Radius.RadSec.CAFile != "" {
			paths = append(paths, cfg.Radius.RadSec.CAFile)
		}
		if env := strings.TrimSpace(cfg.Radius.RadSec.PrivateKeyPasswordEnv); env != "" && os.Getenv(env) == "" {
			addProductionCheck(report, productionReadinessCheck{Key: "radsec_key_environment", Category: "security", Label: "RadSec Key Password Environment", Status: "blocked", Summary: "RadSec private key password environment variable " + env + " is not set.", Recommendation: "Set the systemd service environment securely before applying RadSec configuration.", Dependencies: []string{env}})
			return
		}
	}
	peerCount := 0
	pskPeerCount := 0
	pskDependencies := []string{}
	for _, server := range cfg.Radius.Upstream.Servers {
		if !strings.EqualFold(strings.TrimSpace(server.Transport), "radsec") {
			continue
		}
		peerCount++
		if server.RadSec.PSK.Enabled {
			pskPeerCount++
			for _, ref := range []string{server.RadSec.PSK.SecretRef, server.RadSec.PSK.NextSecretRef} {
				ref = strings.TrimSpace(ref)
				if ref == "" {
					continue
				}
				if !secretRefAvailable(ref) {
					pskDependencies = append(pskDependencies, ref)
				}
			}
			continue
		}
		paths = append(paths, server.RadSec.CertificateFile, server.RadSec.PrivateKeyFile)
		if server.RadSec.CAFile != "" {
			paths = append(paths, server.RadSec.CAFile)
		}
		if env := strings.TrimSpace(server.RadSec.PrivateKeyPasswordEnv); env != "" && os.Getenv(env) == "" {
			addProductionCheck(report, productionReadinessCheck{Key: "radsec_key_environment", Category: "security", Label: "RadSec Key Password Environment", Status: "blocked", Summary: "RadSec private key password environment variable " + env + " is not set.", Recommendation: "Set the systemd service environment securely before applying RadSec configuration.", Dependencies: []string{env}})
			return
		}
	}
	if !cfg.Radius.RadSec.Enabled && peerCount == 0 {
		return
	}
	credentialReport := radius.BuildRadSecCredentialReport(cfg)
	if len(pskDependencies) > 0 {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_psk_secret_refs", Category: "security", Label: "RadSec TLS-PSK Secret References", Status: "blocked", Summary: "RadSec TLS-PSK secret references are unavailable: " + strings.Join(pskDependencies, ", "), Recommendation: "Set referenced environment variables or install referenced files before applying PSK RadSec configuration.", Dependencies: pskDependencies})
		return
	}
	missing := []string{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: "blocked", Summary: "RadSec certificate, key, or CA files are unavailable: " + strings.Join(missing, ", "), Recommendation: "Install the mTLS identity and trust files with root ownership and least-privilege service access.", Dependencies: missing})
		return
	}
	if credentialReport.Status == "blocked" {
		addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: "blocked", Summary: credentialReport.Message, Recommendation: "Review /api/v1/system/radsec-credentials and fix blocked mTLS or PSK credential state.", Dependencies: credentialReport.Warnings})
		return
	}
	status := "passed"
	if credentialReport.Status == "degraded" {
		status = "degraded"
	}
	addProductionCheck(report, productionReadinessCheck{Key: "radsec_credentials", Category: "security", Label: "RadSec Credentials", Status: status, Summary: fmt.Sprintf("RadSec credentials are configured for %d mTLS endpoint(s) and %d TLS-PSK endpoint(s).", credentialReport.Summary.MTLSEndpoints, credentialReport.Summary.PSKEndpoints), Recommendation: "Use /api/v1/system/radsec-credentials during every RadSec credential rotation."})
}

func secretRefAvailable(ref string) bool {
	scheme, value, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "env":
		return os.Getenv(strings.TrimSpace(value)) != ""
	case "file":
		info, err := os.Stat(strings.TrimSpace(value))
		return err == nil && !info.IsDir()
	default:
		return false
	}
}

func buildProductionVendorIdentityState(cfg *config.Config) productionVendorIdentityState {
	identity := productconfigs.AegisNASVendorIdentity()
	vendor := cfg.Radius.Vendor
	configuredID := vendor.ID
	idSource := identity.IDSource
	if configuredID != identity.ID {
		idSource = "config:radius.vendor.id"
	}
	importPaths := vendorDictionaryImportPaths(cfg)
	state := productionVendorIdentityState{
		Enabled:                    vendor.Enabled,
		Name:                       strings.TrimSpace(vendor.Name),
		ConfiguredID:               configuredID,
		ConfiguredIDPlaceholder:    configuredID == productconfigs.AegisNASPlaceholderVendorID,
		IDSource:                   idSource,
		DictionaryFilename:         identity.DictionaryFilename,
		DictionaryInstallPath:      productconfigs.AegisNASVendorDictionaryInstallPath(""),
		DictionaryInclude:          identity.IncludeLine,
		DictionaryDetected:         productDictionaryDetected(cfg, importPaths),
		DictionaryImportPaths:      importPaths,
		PENRegistryURL:             identity.RegistryURL,
		PENApplyURL:                identity.ApplyURL,
		ProductCompatibilityActive: normalizedProductionPackSet(vendor.CompatibilityPacks)[productconfigs.VendorPackAegisNAS],
		IdentityMode:               strings.ToLower(strings.TrimSpace(vendor.IdentityMode)),
		AssignedOrganization:       strings.TrimSpace(vendor.AssignedOrganization),
		AssignmentRecordSHA256:     strings.TrimSpace(vendor.AssignmentRecordSHA),
		LegacyIDs:                  append([]int(nil), vendor.LegacyIDs...),
		LegacyAcceptUntil:          strings.TrimSpace(vendor.LegacyAcceptUntil),
	}
	if evidence, err := config.RadiusVendorAssignmentEvidence(vendor); err == nil {
		state.EvidenceValid = evidence.Validate(vendor.ID, vendor.AssignedOrganization) == nil
	}
	if db.DB != nil {
		if assignment, err := db.ActiveVendorIdentityAssignment(db.DB); err == nil && assignment != nil {
			state.AssignmentActive = assignment.PEN == uint32(vendor.ID) && assignment.RecordSHA256 == vendor.AssignmentRecordSHA
		}
	}
	return state
}

func productDictionaryDetected(cfg *config.Config, importPaths []string) bool {
	if cfg == nil || len(importPaths) == 0 {
		return false
	}
	catalog := productconfigs.LoadVendorDictionaryCatalog(importPaths)
	vendor, ok := catalog.VendorByName(cfg.Radius.Vendor.Name)
	return ok && vendor.ID == cfg.Radius.Vendor.ID
}

func vendorProfileSummaryForProductionReadiness(cfg *config.Config) vendorCompatibilityProfileSummary {
	_, summary, err := loadVendorCompatibilityClientProfiles(cfg)
	if err != nil {
		summary.UnknownProfiles = append(summary.UnknownProfiles, "profile-read-error: "+err.Error())
	}
	return summary
}

func vendorRuntimeSummaryForProductionReadiness(report *productionReadinessReport) db.VendorObservabilitySummary {
	summary, err := db.GetVendorObservabilitySummary()
	if err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_read",
			Category:       "observability",
			Label:          "Vendor Runtime Read",
			Status:         "degraded",
			Summary:        "Vendor runtime counters could not be read: " + err.Error(),
			Recommendation: "Check the database connection before using the production readiness report as a sign-off artifact.",
		})
		return db.VendorObservabilitySummary{}
	}
	return summary
}

func addProductionConfigCheck(report *productionReadinessReport, cfg *config.Config) {
	if err := cfg.Validate(); err != nil {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "config_validation",
			Category:       "configuration",
			Label:          "Configuration Validation",
			Status:         "blocked",
			Summary:        err.Error(),
			Recommendation: "Fix configuration validation errors before production deployment.",
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "config_validation",
		Category: "configuration",
		Label:    "Configuration Validation",
		Status:   "passed",
		Summary:  "Configuration validation passes.",
	})
}

func addProductionScalingCheck(report *productionReadinessReport) {
	scaling := report.HardwareScaling
	switch {
	case !scaling.HardwareKnown:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "blocked",
			Summary:        "CPU and memory are not declared for this appliance.",
			Recommendation: "Set deployment.hardware.cpu_cores and deployment.hardware.memory_mb before production deployment.",
			Dependencies:   []string{"deployment.hardware.cpu_cores", "deployment.hardware.memory_mb"},
		})
	case !scaling.CanRunSelected:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "blocked",
			Summary:        scaling.Summary,
			Recommendation: "Lower the selected deployment profile or move to hardware that matches the selected profile.",
			Dependencies:   []string{"deployment.profile", "deployment.hardware.memory_mb", "deployment.hardware.cpu_cores", "deployment.hardware.storage_gb"},
		})
	case !scaling.StorageKnown:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "hardware_scaling",
			Category:       "deployment",
			Label:          "Hardware Scaling",
			Status:         "warned",
			Summary:        scaling.Reason,
			Recommendation: "Set deployment.hardware.storage_gb so retention and history features can be sized intentionally.",
			Dependencies:   []string{"deployment.hardware.storage_gb"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "hardware_scaling",
			Category: "deployment",
			Label:    "Hardware Scaling",
			Status:   "passed",
			Summary:  scaling.Summary,
		})
	}
}

func addProductionVendorIdentityCheck(report *productionReadinessReport) {
	identity := report.VendorIdentity
	switch {
	case !identity.Enabled:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "warned",
			Summary:        "AegisNAS product VSAs are disabled; standards-based RADIUS can deploy, but product-vendor mode is not active.",
			Recommendation: "Enable radius.vendor.enabled after receiving an IANA Private Enterprise Number if this appliance should identify as its own vendor.",
			Dependencies:   []string{"radius.vendor.enabled", "radius.vendor.id"},
		})
	case identity.ConfiguredIDPlaceholder:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "blocked",
			Summary:        fmt.Sprintf("AegisNAS product VSAs are enabled with the lab placeholder vendor ID %d.", productconfigs.AegisNASPlaceholderVendorID),
			Recommendation: "Request an IANA Private Enterprise Number, wait for publication, and use the verified Vendor Identity preview/apply workflow.",
			Dependencies:   []string{"radius.vendor.id", "vendor_identity_assignments"},
		})
	case identity.IdentityMode != "production" || !identity.EvidenceValid || !identity.AssignmentActive:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_identity",
			Category:       "vendor",
			Label:          "AegisNAS Vendor Identity",
			Status:         "blocked",
			Summary:        fmt.Sprintf("AegisNAS PEN %d does not have matching verified IANA evidence and an active assignment record.", identity.ConfiguredID),
			Recommendation: "Use the Vendor Identity preview/apply workflow after IANA assigns the PEN; do not activate arbitrary non-placeholder values.",
			Dependencies:   []string{"radius.vendor.identity_mode", "vendor_identity_assignments"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "vendor_identity",
			Category: "vendor",
			Label:    "AegisNAS Vendor Identity",
			Status:   "passed",
			Summary:  fmt.Sprintf("AegisNAS product PEN %d is verified for %s and matches the active assignment record.", identity.ConfiguredID, identity.AssignedOrganization),
		})
	}
}

func addProductionDictionaryCheck(report *productionReadinessReport) {
	identity := report.VendorIdentity
	if !identity.Enabled {
		return
	}
	if identity.DictionaryDetected {
		addProductionCheck(report, productionReadinessCheck{
			Key:      "product_dictionary",
			Category: "vendor",
			Label:    "Product Dictionary Install",
			Status:   "passed",
			Summary:  "AegisNAS product dictionary was detected in the configured FreeRADIUS dictionary imports.",
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "product_dictionary",
		Category:       "vendor",
		Label:          "Product Dictionary Install",
		Status:         "warned",
		Summary:        "AegisNAS product dictionary was not detected in the configured or standard FreeRADIUS dictionary import paths.",
		Recommendation: "Install dictionary.aegisnas and include it from the local FreeRADIUS dictionary before hardware smoke tests.",
		Dependencies:   []string{"radius.vendor.dictionary_paths", identity.DictionaryInstallPath},
	})
}

func addProductionVendorPackCheck(report *productionReadinessReport, cfg *config.Config) {
	packs := normalizedProductionPackSet(cfg.Radius.Vendor.CompatibilityPacks)
	if len(packs) == 0 {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_packs",
			Category:       "vendor",
			Label:          "Vendor Compatibility Packs",
			Status:         "blocked",
			Summary:        "No valid vendor compatibility packs are configured.",
			Recommendation: "Enable at least the standard pack and every access-device family used by this deployment.",
			Dependencies:   []string{"radius.vendor.compatibility_packs"},
		})
		return
	}
	if cfg.Radius.Vendor.Enabled && !packs[productconfigs.VendorPackAegisNAS] {
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_packs",
			Category:       "vendor",
			Label:          "Vendor Compatibility Packs",
			Status:         "warned",
			Summary:        "Product VSAs are enabled, but the aegisnas compatibility pack is not active.",
			Recommendation: "Add aegisnas to radius.vendor.compatibility_packs when access devices or upstream AAA should consume AegisNAS VSAs.",
			Dependencies:   []string{"radius.vendor.compatibility_packs"},
		})
		return
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:      "vendor_packs",
		Category: "vendor",
		Label:    "Vendor Compatibility Packs",
		Status:   "passed",
		Summary:  fmt.Sprintf("%d valid vendor compatibility pack(s) configured.", len(packs)),
	})
}

func addProductionNASProfileCheck(report *productionReadinessReport) {
	summary := report.NASProfileSummary
	switch {
	case len(summary.UnknownProfiles) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "blocked",
			Summary:        "One or more enabled RADIUS clients use unknown NAS profiles: " + strings.Join(summary.UnknownProfiles, ", "),
			Recommendation: "Set each RADIUS client nas_type to a known vendor pack or explicitly use other for standards-only clients.",
			Dependencies:   []string{"radius_clients.nas_type"},
		})
	case summary.EnabledClients == 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "warned",
			Summary:        "No enabled RADIUS clients are present in the appliance database.",
			Recommendation: "Add APs, controllers, switches, or VPN gateways before production smoke testing.",
			Dependencies:   []string{"radius_clients"},
		})
	case summary.GlobalFallbackClientCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "nas_profile_coverage",
			Category:       "vendor",
			Label:          "NAS Profile Coverage",
			Status:         "warned",
			Summary:        fmt.Sprintf("%d RADIUS client(s) use global or standards-only compatibility packs.", summary.GlobalFallbackClientCount),
			Recommendation: "Use known vendor NAS profiles for devices that need vendor-specific replies.",
			Dependencies:   []string{"radius_clients.nas_type"},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "nas_profile_coverage",
			Category: "vendor",
			Label:    "NAS Profile Coverage",
			Status:   "passed",
			Summary:  fmt.Sprintf("%d enabled RADIUS client(s) use known vendor profiles.", summary.EnabledClients),
		})
	}
}

func addProductionFeatureCapabilityCheck(report *productionReadinessReport, cfg *config.Config) {
	capabilities := config.EvaluateFeatureCapabilities(cfg)
	blocked := activeCapabilityLabels(capabilities, config.CapabilityBlocked)
	degraded := activeCapabilityLabels(capabilities, config.CapabilityDegraded)
	warned := activeCapabilityLabels(capabilities, config.CapabilityWarned)

	switch {
	case len(blocked) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "blocked",
			Summary:        "Active features are blocked by deployment, hardware, or integration readiness: " + strings.Join(blocked, ", "),
			Recommendation: "Disable blocked features or satisfy their dependencies before production deployment.",
		})
	case len(degraded) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "degraded",
			Summary:        "Active features are degraded: " + strings.Join(degraded, ", "),
			Recommendation: "Review degraded feature dependencies before treating this node as production-ready.",
		})
	case len(warned) > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "feature_capabilities",
			Category:       "features",
			Label:          "Feature Capability Gates",
			Status:         "warned",
			Summary:        "Active features have production warnings: " + strings.Join(warned, ", "),
			Recommendation: "Review warnings and confirm they match the intended deployment profile.",
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "feature_capabilities",
			Category: "features",
			Label:    "Feature Capability Gates",
			Status:   "passed",
			Summary:  "No active feature capability blockers or warnings were found.",
		})
	}
}

func addProductionControllerCheck(report *productionReadinessReport, cfg *config.Config) {
	if !cfg.Integrations.Controller.Enabled {
		return
	}
	state := buildControllerAdapterConfiguredState(cfg)
	if state.Ready {
		addProductionCheck(report, productionReadinessCheck{
			Key:      "controller_readiness",
			Category: "integrations",
			Label:    "Controller Readiness",
			Status:   "passed",
			Summary:  fmt.Sprintf("%s controller adapter is configured for %s sync.", state.Adapter, state.SyncMode),
		})
		return
	}
	dependencies := []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site"}
	recommendation := "Set endpoint, API token environment variable, and any required site or network identifier."
	if state.Normalized == "cisco" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site"}
		recommendation = "Set the Cisco ISE endpoint, API username/password environment variables, and site identifier."
	} else if state.Normalized == "aruba" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the Aruba Central endpoint, API token environment variable, group identifier, and existing RADIUS profile name."
	} else if state.Normalized == "juniper-mist" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the Mist regional API endpoint, API token environment variable, site ID, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "ruckus" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the SmartZone endpoint, API username/password environment variables, zone ID, and existing authentication service name."
	} else if state.Normalized == "fortinet" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the FortiGate endpoint, REST API token environment variable, VDOM, and existing RADIUS profile name."
	} else if state.Normalized == "mikrotik" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_username_env", "integrations.controller.api_password_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the RouterOS HTTPS endpoint, API username/password environment variables, managed-site label, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "unifi" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_profile"}
		recommendation = "Set the UniFi Network integration API base URL, API key environment variable, site ID, and existing RADIUS profile name."
	} else if state.Normalized == "meraki" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the Meraki Dashboard API v1 base URL, API key environment variable, network ID, RADIUS server, and RADIUS shared-secret environment variable."
	} else if state.Normalized == "openwifi" {
		dependencies = []string{"integrations.controller.endpoint", "integrations.controller.api_token_env", "integrations.controller.site", "integrations.controller.radius_server", "integrations.controller.radius_secret_env"}
		recommendation = "Set the OpenWiFi Gateway API v1 base URL, API key environment variable, venue UUID or AP serial number, RADIUS server, and RADIUS shared-secret environment variable."
	}
	addProductionCheck(report, productionReadinessCheck{
		Key:            "controller_readiness",
		Category:       "integrations",
		Label:          "Controller Readiness",
		Status:         "blocked",
		Summary:        "Controller automation is enabled but not ready: " + strings.Join(state.ReadinessWarnings, "; "),
		Recommendation: recommendation,
		Dependencies:   dependencies,
	})
}

func addProductionVendorRuntimeCheck(report *productionReadinessReport) {
	summary := report.VendorRuntime
	switch {
	case summary.TotalVendors == 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "warned",
			Summary:        "No vendor observability counters have been recorded yet.",
			Recommendation: "Run AP/controller authentication, accounting, CoA, and rollback smoke tests before production sign-off.",
		})
	case summary.VSAParseFailureCount > 0 || summary.CoAFailureCount > 0 || summary.DisconnectFailureCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "degraded",
			Summary:        "Vendor runtime counters include VSA parse, CoA, or disconnect failures.",
			Recommendation: "Resolve vendor runtime failures or document a deployment exception before production sign-off.",
		})
	case summary.UnsupportedAttributeCount > 0 || summary.AuthFailureCount > 0:
		addProductionCheck(report, productionReadinessCheck{
			Key:            "vendor_runtime_evidence",
			Category:       "observability",
			Label:          "Vendor Runtime Evidence",
			Status:         "warned",
			Summary:        "Vendor runtime counters include auth failures or unsupported attributes.",
			Recommendation: "Review vendor observability details and confirm failures are expected test cases.",
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "vendor_runtime_evidence",
			Category: "observability",
			Label:    "Vendor Runtime Evidence",
			Status:   "passed",
			Summary:  fmt.Sprintf("%d vendor profile(s) have clean runtime counters.", summary.TotalVendors),
		})
	}
}

func addProductionCheck(report *productionReadinessReport, check productionReadinessCheck) {
	check.Status = strings.ToLower(strings.TrimSpace(check.Status))
	check.Dependencies = uniqueSortedStrings(check.Dependencies)
	report.Checks = append(report.Checks, check)
	switch check.Status {
	case "blocked":
		report.BlockingCount++
	case "degraded":
		report.DegradedCount++
	case "warned":
		report.WarningCount++
	default:
		report.PassingCount++
	}
}

func finalizeProductionReadinessReport(report *productionReadinessReport) {
	switch {
	case report.BlockingCount > 0:
		report.Status = "blocked"
		report.Message = fmt.Sprintf("Production readiness is blocked by %d required check(s).", report.BlockingCount)
	case report.DegradedCount > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Production readiness has %d degraded check(s) that need review.", report.DegradedCount)
	case report.WarningCount > 0:
		report.Status = "warned"
		report.Message = fmt.Sprintf("Production readiness has %d warning check(s) to review before sign-off.", report.WarningCount)
	default:
		report.Status = "ready"
		report.Message = "Production readiness checks passed."
	}
	report.Ready = report.Status == "ready"
	report.Score = productionReadinessScore(report)
}

func productionReadinessScore(report *productionReadinessReport) int {
	score := 100 - report.BlockingCount*20 - report.DegradedCount*10 - report.WarningCount*5
	if score < 0 {
		return 0
	}
	return score
}

func productionReadinessSummaryFromReport(report productionReadinessReport) productionReadinessSummary {
	return productionReadinessSummary{
		Status:        report.Status,
		Ready:         report.Ready,
		Score:         report.Score,
		Message:       report.Message,
		BlockingCount: report.BlockingCount,
		WarningCount:  report.WarningCount,
		DegradedCount: report.DegradedCount,
		PassingCount:  report.PassingCount,
	}
}

func activeCapabilityLabels(capabilities []config.FeatureCapability, state string) []string {
	var labels []string
	for _, capability := range capabilities {
		if capability.Active && capability.State == state {
			labels = append(labels, capability.Label)
		}
	}
	sort.Strings(labels)
	return labels
}

func normalizedProductionPackSet(keys []string) map[string]bool {
	set := map[string]bool{}
	for _, key := range normalizeVendorCompatibilityPackKeys(keys) {
		set[key] = true
	}
	return set
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
