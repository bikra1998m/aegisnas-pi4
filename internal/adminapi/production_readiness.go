package adminapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
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
	addProductionDictionaryCheck(&report)
	addProductionVendorPackCheck(&report, cfg)
	addProductionNASProfileCheck(&report)
	addProductionFeatureCapabilityCheck(&report, cfg)
	addProductionControllerCheck(&report, cfg)
	addProductionVendorRuntimeCheck(&report)

	finalizeProductionReadinessReport(&report)
	return report
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
	return productionVendorIdentityState{
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
	}
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
			Recommendation: "Request an IANA Private Enterprise Number and set radius.vendor.id or AEGISNAS_VENDOR_ID before production VSA use.",
			Dependencies:   []string{"radius.vendor.id", productconfigs.AegisNASVendorIDEnv},
		})
	default:
		addProductionCheck(report, productionReadinessCheck{
			Key:      "vendor_identity",
			Category: "vendor",
			Label:    "AegisNAS Vendor Identity",
			Status:   "passed",
			Summary:  fmt.Sprintf("AegisNAS product vendor ID %d is not the lab placeholder.", identity.ConfiguredID),
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
