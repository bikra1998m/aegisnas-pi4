package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	ControllerEstateLifecycleSchemaVersion = 1
	ControllerEstateLifecycleFeatureID     = "NAS-0078"
)

type ControllerEstateLifecycleReport struct {
	SchemaVersion                 int                               `json:"schema_version"`
	FeatureID                     string                            `json:"feature_id"`
	Status                        string                            `json:"status"`
	Message                       string                            `json:"message"`
	GeneratedAt                   string                            `json:"generated_at"`
	SoftwareCompletionPercent     float64                           `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                              `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                            `json:"release_certification_checklist"`
	ReleaseScope                  string                            `json:"release_scope"`
	PlanFingerprint               string                            `json:"plan_fingerprint"`
	DesiredStateHash              string                            `json:"desired_state_hash,omitempty"`
	Summary                       ControllerEstateLifecycleSummary  `json:"summary"`
	SelectedAdapter               ControllerAdapterDescriptor       `json:"selected_adapter"`
	Configured                    ControllerEstateConfiguredState   `json:"configured"`
	Inventory                     []ControllerEstateInventoryObject `json:"inventory"`
	Templates                     []ControllerEstateTemplate        `json:"templates"`
	ObjectPlans                   []ControllerEstateObjectPlan      `json:"object_plans"`
	Compliance                    []ControllerEstateComplianceCheck `json:"compliance"`
	PullPreview                   *ControllerSyncPreview            `json:"pull_preview,omitempty"`
	PushPreview                   *ControllerSyncPreview            `json:"push_preview,omitempty"`
	RFCs                          []string                          `json:"rfcs"`
	Vendors                       []string                          `json:"vendors"`
	Requirements                  []string                          `json:"requirements"`
	Blockers                      []string                          `json:"blockers,omitempty"`
	Warnings                      []string                          `json:"warnings,omitempty"`
	Notes                         []string                          `json:"notes,omitempty"`
}

type ControllerEstateLifecycleSummary struct {
	ControllerEnabled        bool   `json:"controller_enabled"`
	AdapterCount             int    `json:"adapter_count"`
	NativeAdapterCount       int    `json:"native_adapter_count"`
	ContractAdapterCount     int    `json:"contract_adapter_count"`
	ConfiguredPlatform       string `json:"configured_platform"`
	ConfiguredAdapter        string `json:"configured_adapter"`
	SyncMode                 string `json:"sync_mode"`
	InventoryObjectCount     int    `json:"inventory_object_count"`
	TemplateCount            int    `json:"template_count"`
	WLANTemplateCount        int    `json:"wlan_template_count"`
	ManagedObjectCount       int    `json:"managed_object_count"`
	DeleteGuardCount         int    `json:"delete_guard_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	DriftCheckAvailable      bool   `json:"drift_check_available"`
	DesiredStateHash         string `json:"desired_state_hash,omitempty"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
}

type ControllerEstateConfiguredState struct {
	Enabled                 bool     `json:"enabled"`
	Platform                string   `json:"platform"`
	NormalizedPlatform      string   `json:"normalized_platform"`
	Adapter                 string   `json:"adapter"`
	SyncMode                string   `json:"sync_mode"`
	Endpoint                string   `json:"endpoint,omitempty"`
	Site                    string   `json:"site,omitempty"`
	SiteRequired            bool     `json:"site_required"`
	SiteConfigured          bool     `json:"site_configured"`
	EndpointSet             bool     `json:"endpoint_set"`
	TokenEnv                string   `json:"token_env,omitempty"`
	TokenPresent            bool     `json:"token_present"`
	UsernameEnv             string   `json:"username_env,omitempty"`
	UsernamePresent         bool     `json:"username_present"`
	PasswordEnv             string   `json:"password_env,omitempty"`
	PasswordPresent         bool     `json:"password_present"`
	RadiusProfile           string   `json:"radius_profile,omitempty"`
	RadiusProfileRequired   bool     `json:"radius_profile_required"`
	RadiusProfileConfigured bool     `json:"radius_profile_configured"`
	RadiusServer            string   `json:"radius_server,omitempty"`
	RadiusSecretEnv         string   `json:"radius_secret_env,omitempty"`
	RadiusSecretPresent     bool     `json:"radius_secret_present"`
	RadiusServerRequired    bool     `json:"radius_server_required"`
	RadiusServerConfigured  bool     `json:"radius_server_configured"`
	Ready                   bool     `json:"ready"`
	ReadinessWarnings       []string `json:"readiness_warnings,omitempty"`
}

type ControllerEstateInventoryObject struct {
	ID              string         `json:"id"`
	Type            string         `json:"type"`
	Name            string         `json:"name"`
	Platform        string         `json:"platform"`
	Ownership       string         `json:"ownership"`
	Status          string         `json:"status"`
	DeleteProtected bool           `json:"delete_protected"`
	External        bool           `json:"external"`
	Fingerprint     string         `json:"fingerprint"`
	Attributes      map[string]any `json:"attributes,omitempty"`
}

type ControllerEstateTemplate struct {
	ID               string         `json:"id"`
	Type             string         `json:"type"`
	Name             string         `json:"name"`
	Status           string         `json:"status"`
	AuthMode         string         `json:"auth_mode,omitempty"`
	VLAN             int            `json:"vlan,omitempty"`
	DynamicVLAN      bool           `json:"dynamic_vlan"`
	PortalProfile    string         `json:"portal_profile,omitempty"`
	RoamingProfile   string         `json:"roaming_profile,omitempty"`
	PasspointProfile string         `json:"passpoint_profile,omitempty"`
	PPSKProfile      string         `json:"ppsk_profile,omitempty"`
	BandwidthProfile string         `json:"bandwidth_profile,omitempty"`
	IdentitySource   string         `json:"identity_source,omitempty"`
	ManagedFields    []string       `json:"managed_fields,omitempty"`
	Unsupported      []string       `json:"unsupported,omitempty"`
	DeleteProtected  bool           `json:"delete_protected"`
	Fingerprint      string         `json:"fingerprint"`
	Attributes       map[string]any `json:"attributes,omitempty"`
}

type ControllerEstateObjectPlan struct {
	ID              string   `json:"id"`
	ObjectType      string   `json:"object_type"`
	ObjectName      string   `json:"object_name"`
	Operation       string   `json:"operation"`
	Status          string   `json:"status"`
	DeleteProtected bool     `json:"delete_protected"`
	Reason          string   `json:"reason"`
	DependsOn       []string `json:"depends_on,omitempty"`
}

type ControllerEstateComplianceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func PreviewControllerEstateLifecycle(cfg *config.Config) (ControllerEstateLifecycleReport, error) {
	if cfg == nil {
		return ControllerEstateLifecycleReport{}, fmt.Errorf("config is required")
	}
	controller := cfg.Integrations.Controller
	platform := normalizeControllerPlatform(controller.Platform)
	if platform == "" {
		platform = "generic"
	}
	adapter := ControllerAdapterDescriptorForPlatform(platform)
	catalog := ControllerAdapterCatalog()
	report := ControllerEstateLifecycleReport{
		SchemaVersion:                 ControllerEstateLifecycleSchemaVersion,
		FeatureID:                     ControllerEstateLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0078-release-certification-checklist.md",
		ReleaseScope:                  "Real controller firmware/API validation, AP inventory reconciliation, delete simulation on physical estates, HA failover, performance, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		SelectedAdapter:               adapter,
		Configured:                    buildControllerEstateConfiguredState(cfg, adapter),
		RFCs:                          []string{"RFC 2865", "RFC 2866", "RFC 5176", "IEEE 802.1X", "IEEE 802.11"},
		Vendors:                       controllerEstateVendors(catalog),
		Requirements: []string{
			"Controller estate inventory is represented as redacted objects with ownership, fingerprints, and delete guards",
			"WLAN templates are derived from configured SSID intent and controller adapter capabilities",
			"Preview exposes pull and push desired-state hashes without contacting or mutating controllers",
			"Apply records an auditable checkpoint and runtime status; destructive object deletes are not performed automatically",
			"Compliance checks separate software readiness from release certification that needs real hardware and third parties",
			"Secrets are represented only as environment variable names and presence booleans",
		},
		Notes: []string{
			"NAS-0078 completes software lifecycle governance for the current controller adapter estate.",
			"Controller-native object mutations continue through the existing controller-sync endpoint after operator confirmation.",
		},
	}
	report.Summary.AdapterCount = len(catalog)
	for _, descriptor := range catalog {
		if descriptor.NativePolicyPush {
			report.Summary.NativeAdapterCount++
		} else {
			report.Summary.ContractAdapterCount++
		}
	}
	report.Summary.ControllerEnabled = controller.Enabled
	report.Summary.ConfiguredPlatform = platform
	report.Summary.ConfiguredAdapter = adapter.Adapter
	report.Summary.SyncMode = firstNonEmptyControllerEstateString(controller.SyncMode, "monitor")
	report.Summary.ExternalRequirementCount = 9

	report.Inventory = buildControllerEstateInventory(cfg, adapter, report.Configured)
	report.Templates = buildControllerEstateTemplates(cfg, adapter)
	report.ObjectPlans = buildControllerEstateObjectPlans(report.Inventory, report.Templates, adapter)
	report.Compliance = buildControllerEstateCompliance(cfg, adapter, report.Configured, report.Templates)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
	}
	for _, plan := range report.ObjectPlans {
		if plan.DeleteProtected {
			report.Summary.DeleteGuardCount++
		}
		if plan.Status == "managed" || plan.Status == "ready" {
			report.Summary.ManagedObjectCount++
		}
		if plan.Status == "warning" {
			report.Warnings = append(report.Warnings, plan.Reason)
		}
	}
	for _, template := range report.Templates {
		if template.Status == "warning" {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s template has unsupported fields: %s", template.Name, strings.Join(template.Unsupported, ", ")))
		}
	}
	if controller.Enabled {
		if err := cfg.Validate(); err != nil {
			report.Blockers = append(report.Blockers, err.Error())
		}
		if preview, err := BuildControllerSyncPreview(cfg, "pull"); err == nil {
			report.PullPreview = preview
			report.Summary.DriftCheckAvailable = true
			if strings.TrimSpace(preview.DesiredStateHash) != "" {
				report.DesiredStateHash = preview.DesiredStateHash
			}
		} else {
			report.Warnings = append(report.Warnings, "controller pull preview is unavailable: "+err.Error())
		}
		if preview, err := BuildControllerSyncPreview(cfg, "push"); err == nil {
			report.PushPreview = preview
			if report.DesiredStateHash == "" {
				report.DesiredStateHash = preview.DesiredStateHash
			}
		} else {
			report.Warnings = append(report.Warnings, "controller push preview is unavailable: "+err.Error())
		}
	}
	report.Summary.InventoryObjectCount = len(report.Inventory)
	report.Summary.TemplateCount = len(report.Templates)
	report.Summary.WLANTemplateCount = len(report.Templates)
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.Summary.DesiredStateHash = report.DesiredStateHash
	report.Status = controllerEstateLifecycleStatus(report)
	report.SoftwareCompletionPercent = controllerEstateLifecycleCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = controllerEstateLifecycleMessage(report)
	report.PlanFingerprint = controllerEstateLifecycleFingerprint(report)
	return report, nil
}

func PreviewAndRecordControllerEstateLifecycle(cfg *config.Config, actor string) (ControllerEstateLifecycleReport, string, error) {
	report, err := PreviewControllerEstateLifecycle(cfg)
	if err != nil {
		return ControllerEstateLifecycleReport{}, "", err
	}
	eventID, err := recordControllerEstateLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyControllerEstateLifecycle(ctx context.Context, cfg *config.Config, actor string) (ControllerEstateLifecycleReport, string, error) {
	report, err := PreviewControllerEstateLifecycle(cfg)
	if err != nil {
		return ControllerEstateLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordControllerEstateLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		return report, eventID, fmt.Errorf("controller estate lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0078 recorded controller estate lifecycle checkpoint for %d inventory object(s), %d WLAN template(s), and %d delete guard(s).",
			report.Summary.InventoryObjectCount,
			report.Summary.WLANTemplateCount,
			report.Summary.DeleteGuardCount,
		)
	}
	eventID, err := recordControllerEstateLifecycleEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := map[string]any{
			"feature_id":                    ControllerEstateLifecycleFeatureID,
			"adapter":                       report.Summary.ConfiguredAdapter,
			"platform":                      report.Summary.ConfiguredPlatform,
			"sync_mode":                     report.Summary.SyncMode,
			"desired_state_hash":            report.DesiredStateHash,
			"plan_fingerprint":              report.PlanFingerprint,
			"inventory_object_count":        report.Summary.InventoryObjectCount,
			"wlan_template_count":           report.Summary.WLANTemplateCount,
			"delete_guard_count":            report.Summary.DeleteGuardCount,
			"compliance_check_count":        report.Summary.ComplianceCheckCount,
			"passed_check_count":            report.Summary.PassedCheckCount,
			"external_requirements":         report.Summary.ExternalRequirementCount,
			"release_checklist":             report.ReleaseCertificationChecklist,
			"controller_endpoint":           report.Configured.Endpoint,
			"controller_site":               report.Configured.Site,
			"ready_for_external_validation": report.ReadyForExternalValidation,
		}
		_ = db.RecordIntegrationHistory(controllerComponent, "ok", report.Message, details)
		_ = db.UpsertRuntimeStatus(controllerComponent, "ok", report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func buildControllerEstateConfiguredState(cfg *config.Config, adapter ControllerAdapterDescriptor) ControllerEstateConfiguredState {
	controller := cfg.Integrations.Controller
	tokenEnv := strings.TrimSpace(controller.APITokenEnv)
	usernameEnv := strings.TrimSpace(controller.APIUsernameEnv)
	passwordEnv := strings.TrimSpace(controller.APIPasswordEnv)
	platform := adapter.Platform
	state := ControllerEstateConfiguredState{
		Enabled:            controller.Enabled,
		Platform:           strings.TrimSpace(controller.Platform),
		NormalizedPlatform: platform,
		Adapter:            adapter.Adapter,
		SyncMode:           firstNonEmptyControllerEstateString(controller.SyncMode, "monitor"),
		Endpoint:           strings.TrimSpace(controller.Endpoint),
		Site:               strings.TrimSpace(controller.Site),
		SiteRequired:       adapter.RequiresSite,
		SiteConfigured:     !adapter.RequiresSite || strings.TrimSpace(controller.Site) != "",
		EndpointSet:        strings.TrimSpace(controller.Endpoint) != "",
		TokenEnv:           tokenEnv,
		TokenPresent:       tokenEnv != "" && strings.TrimSpace(os.Getenv(tokenEnv)) != "",
		UsernameEnv:        usernameEnv,
		UsernamePresent:    usernameEnv != "" && strings.TrimSpace(os.Getenv(usernameEnv)) != "",
		PasswordEnv:        passwordEnv,
		PasswordPresent:    passwordEnv != "" && strings.TrimSpace(os.Getenv(passwordEnv)) != "",
		RadiusProfile:      strings.TrimSpace(controller.RadiusProfile),
		RadiusServer:       strings.TrimSpace(controller.RadiusServer),
		RadiusSecretEnv:    strings.TrimSpace(controller.RadiusSecretEnv),
		RadiusSecretPresent: strings.TrimSpace(controller.RadiusSecretEnv) != "" &&
			strings.TrimSpace(os.Getenv(strings.TrimSpace(controller.RadiusSecretEnv))) != "",
	}
	if state.Platform == "" {
		state.Platform = platform
	}
	state.RadiusProfileRequired = (platform == "aruba" || platform == "ruckus" || platform == "fortinet" || platform == "unifi") && controllerEstateHasEnterpriseSSIDs(cfg)
	state.RadiusProfileConfigured = !state.RadiusProfileRequired || state.RadiusProfile != ""
	state.RadiusServerRequired = (platform == "juniper-mist" || platform == "mikrotik" || platform == "meraki" || platform == "openwifi") && controllerEstateHasEnterpriseSSIDs(cfg)
	state.RadiusServerConfigured = !state.RadiusServerRequired || (state.RadiusServer != "" && state.RadiusSecretEnv != "" && state.RadiusSecretPresent)
	if state.Enabled {
		if !state.EndpointSet {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "controller endpoint is not configured")
		}
		switch platform {
		case "cisco", "ruckus", "mikrotik":
			if usernameEnv == "" || passwordEnv == "" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, adapter.Label+" requires API username and password environment variables")
			} else if !state.UsernamePresent || !state.PasswordPresent {
				state.ReadinessWarnings = append(state.ReadinessWarnings, adapter.Label+" API credential environment variables are configured but not both present")
			}
		default:
			if tokenEnv == "" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "controller API token environment variable is not configured")
			} else if !state.TokenPresent {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "controller API token environment variable is configured but not present")
			}
		}
		if !state.SiteConfigured {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "selected controller platform requires a site, zone, or network identifier")
		}
		if !state.RadiusProfileConfigured {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "enterprise WLAN sync requires an existing controller RADIUS profile")
		}
		if !state.RadiusServerConfigured {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "enterprise WLAN sync requires a RADIUS server and a present shared-secret environment variable")
		}
	}
	credentialsReady := state.TokenEnv != "" && state.TokenPresent
	if platform == "cisco" || platform == "ruckus" || platform == "mikrotik" {
		credentialsReady = state.UsernamePresent && state.PasswordPresent
	}
	state.Ready = state.Enabled && state.EndpointSet && credentialsReady && state.SiteConfigured && state.RadiusProfileConfigured && state.RadiusServerConfigured
	return state
}

func buildControllerEstateInventory(cfg *config.Config, adapter ControllerAdapterDescriptor, state ControllerEstateConfiguredState) []ControllerEstateInventoryObject {
	objects := []ControllerEstateInventoryObject{
		controllerEstateInventoryObject("controller:"+adapter.Platform, "controller", adapter.Label, adapter.Platform, "external-controller", state.Enabled, true, map[string]any{
			"adapter":         adapter.Adapter,
			"endpoint":        state.Endpoint,
			"sync_mode":       state.SyncMode,
			"site":            state.Site,
			"auth_scheme":     adapter.AuthScheme,
			"native_push":     adapter.NativePolicyPush,
			"drift_detection": adapter.DriftDetection,
		}),
		controllerEstateInventoryObject("adapter-catalog:"+adapter.Adapter, "adapter", adapter.Adapter, adapter.Platform, "aegisnas", true, true, map[string]any{
			"supported_sync_modes": adapter.SupportedSyncModes,
			"wireless_profiles":    adapter.WirelessProfiles,
			"radius_profiles":      adapter.RadiusProfiles,
			"guest_portal":         adapter.GuestPortal,
			"dynamic_acl":          adapter.DynamicACL,
			"coa":                  adapter.CoA,
		}),
	}
	if state.Site != "" {
		objects = append(objects, controllerEstateInventoryObject("scope:"+state.Site, "site", state.Site, adapter.Platform, "external-controller", true, true, map[string]any{
			"site_required": state.SiteRequired,
			"sync_mode":     state.SyncMode,
		}))
	}
	if state.TokenEnv != "" || state.UsernameEnv != "" || state.RadiusSecretEnv != "" {
		objects = append(objects, controllerEstateInventoryObject("credential:"+adapter.Adapter, "credential-reference", adapter.Label+" API credentials", adapter.Platform, "secret-reference", state.Enabled, true, map[string]any{
			"token_env":             state.TokenEnv,
			"token_present":         state.TokenPresent,
			"username_env":          state.UsernameEnv,
			"username_present":      state.UsernamePresent,
			"password_env_set":      state.PasswordEnv != "",
			"password_present":      state.PasswordPresent,
			"radius_secret_env":     state.RadiusSecretEnv,
			"radius_secret_present": state.RadiusSecretPresent,
		}))
	}
	if state.RadiusProfile != "" || state.RadiusServer != "" {
		objects = append(objects, controllerEstateInventoryObject("radius:"+firstNonEmptyControllerEstateString(state.RadiusProfile, state.RadiusServer), "radius-profile", firstNonEmptyControllerEstateString(state.RadiusProfile, state.RadiusServer), adapter.Platform, "external-controller", true, true, map[string]any{
			"radius_profile": state.RadiusProfile,
			"radius_server":  state.RadiusServer,
		}))
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			name = "unnamed"
		}
		objects = append(objects, controllerEstateInventoryObject("wlan:"+name, "wlan", name, adapter.Platform, "aegisnas-policy", true, true, map[string]any{
			"auth_mode":         strings.TrimSpace(ssid.AuthMode),
			"vlan":              ssid.VLAN,
			"dynamic_vlan":      ssid.DynamicVLAN,
			"portal_profile":    strings.TrimSpace(ssid.PortalProfile),
			"identity_source":   strings.TrimSpace(ssid.IdentitySource),
			"bandwidth_profile": strings.TrimSpace(ssid.BandwidthProfile),
			"roaming_profile":   strings.TrimSpace(ssid.RoamingProfile),
			"passpoint_profile": strings.TrimSpace(ssid.PasspointProfile),
			"ppsk_profile":      strings.TrimSpace(ssid.PPSKProfile),
		}))
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return objects
}

func buildControllerEstateTemplates(cfg *config.Config, adapter ControllerAdapterDescriptor) []ControllerEstateTemplate {
	templates := make([]ControllerEstateTemplate, 0, len(cfg.Wireless.SSIDs))
	for _, ssid := range cfg.Wireless.SSIDs {
		name := strings.TrimSpace(ssid.Name)
		if name == "" {
			name = "unnamed"
		}
		template := ControllerEstateTemplate{
			ID:               "wlan:" + name,
			Type:             "wlan",
			Name:             name,
			Status:           "managed",
			AuthMode:         strings.TrimSpace(ssid.AuthMode),
			VLAN:             ssid.VLAN,
			DynamicVLAN:      ssid.DynamicVLAN,
			PortalProfile:    strings.TrimSpace(ssid.PortalProfile),
			RoamingProfile:   strings.TrimSpace(ssid.RoamingProfile),
			PasspointProfile: strings.TrimSpace(ssid.PasspointProfile),
			PPSKProfile:      strings.TrimSpace(ssid.PPSKProfile),
			BandwidthProfile: strings.TrimSpace(ssid.BandwidthProfile),
			IdentitySource:   strings.TrimSpace(ssid.IdentitySource),
			DeleteProtected:  true,
			Attributes: map[string]any{
				"hidden":           ssid.Hidden,
				"client_isolation": ssid.ClientIsolation,
				"max_clients":      ssid.MaxClients,
				"bridge":           strings.TrimSpace(ssid.Bridge),
			},
		}
		template.ManagedFields = controllerEstateManagedFields(ssid, adapter)
		template.Unsupported = controllerEstateUnsupportedFields(ssid, adapter)
		if len(template.Unsupported) > 0 {
			template.Status = "warning"
		}
		template.Fingerprint = controllerEstateHash(template)
		templates = append(templates, template)
	}
	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates
}

func buildControllerEstateObjectPlans(inventory []ControllerEstateInventoryObject, templates []ControllerEstateTemplate, adapter ControllerAdapterDescriptor) []ControllerEstateObjectPlan {
	plans := make([]ControllerEstateObjectPlan, 0, len(inventory)+len(templates)+2)
	plans = append(plans, ControllerEstateObjectPlan{
		ID:              "inventory:read:" + adapter.Adapter,
		ObjectType:      "inventory",
		ObjectName:      adapter.Label,
		Operation:       "read",
		Status:          "ready",
		DeleteProtected: true,
		Reason:          "Collect controller inventory before object reconciliation.",
	})
	for _, item := range inventory {
		plans = append(plans, ControllerEstateObjectPlan{
			ID:              "observe:" + item.ID,
			ObjectType:      item.Type,
			ObjectName:      item.Name,
			Operation:       "observe",
			Status:          "ready",
			DeleteProtected: item.DeleteProtected,
			Reason:          "Track fingerprint and ownership without destructive mutation.",
			DependsOn:       []string{"inventory:read:" + adapter.Adapter},
		})
	}
	for _, template := range templates {
		status := "managed"
		reason := "Upsert object during confirmed controller-sync push."
		if template.Status == "warning" {
			status = "warning"
			reason = "Template contains fields that the selected adapter cannot fully render yet."
		}
		plans = append(plans, ControllerEstateObjectPlan{
			ID:              "upsert:" + template.ID,
			ObjectType:      template.Type,
			ObjectName:      template.Name,
			Operation:       "upsert",
			Status:          status,
			DeleteProtected: true,
			Reason:          reason,
			DependsOn:       []string{"inventory:read:" + adapter.Adapter},
		})
	}
	plans = append(plans,
		ControllerEstateObjectPlan{
			ID:              "delete-safety:" + adapter.Adapter,
			ObjectType:      "delete-guard",
			ObjectName:      adapter.Label,
			Operation:       "protect",
			Status:          "ready",
			DeleteProtected: true,
			Reason:          "Controller estate lifecycle never deletes unknown or orphaned objects automatically.",
		},
		ControllerEstateObjectPlan{
			ID:              "rollback:checkpoint:" + adapter.Adapter,
			ObjectType:      "rollback",
			ObjectName:      adapter.Label,
			Operation:       "checkpoint",
			Status:          "ready",
			DeleteProtected: true,
			Reason:          "Apply records desired-state and compliance evidence before any external controller push.",
		},
	)
	sort.Slice(plans, func(i, j int) bool { return plans[i].ID < plans[j].ID })
	return plans
}

func buildControllerEstateCompliance(cfg *config.Config, adapter ControllerAdapterDescriptor, state ControllerEstateConfiguredState, templates []ControllerEstateTemplate) []ControllerEstateComplianceCheck {
	checks := []ControllerEstateComplianceCheck{}
	add := func(id, name, status, message string, evidence ...string) {
		checks = append(checks, ControllerEstateComplianceCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence})
	}
	if !state.Enabled {
		add("controller_enabled", "Controller enabled", "skipped", "Controller automation is disabled; NAS-0078 software is ready but inactive.")
	} else {
		add("controller_enabled", "Controller enabled", "passed", "Controller automation is enabled.")
	}
	add("adapter_catalog", "Adapter catalog", "passed", fmt.Sprintf("%s is represented in the controller adapter catalog.", adapter.Label), adapter.Adapter, adapter.Platform)
	if state.Enabled {
		if state.EndpointSet {
			add("endpoint", "Endpoint configured", "passed", "Controller endpoint is configured.", state.Endpoint)
		} else {
			add("endpoint", "Endpoint configured", "blocked", "Controller endpoint is required before lifecycle apply.")
		}
		if adapter.RequiresSite && !state.SiteConfigured {
			add("site_scope", "Site scope", "blocked", "Selected controller platform requires integrations.controller.site.")
		} else {
			add("site_scope", "Site scope", "passed", "Controller site scope is valid for the selected platform.", state.Site)
		}
		if len(state.ReadinessWarnings) > 0 {
			add("credential_references", "Credential references", "warning", strings.Join(state.ReadinessWarnings, "; "))
		} else {
			add("credential_references", "Credential references", "passed", "Controller credential references are present and redacted.")
		}
	}
	if len(templates) > 0 {
		add("wlan_templates", "WLAN templates", "passed", fmt.Sprintf("%d WLAN template(s) are derived from configured SSIDs.", len(templates)))
	} else {
		add("wlan_templates", "WLAN templates", "warning", "No SSID templates are configured for controller estate management.")
	}
	unsupportedCount := 0
	for _, template := range templates {
		unsupportedCount += len(template.Unsupported)
	}
	if unsupportedCount == 0 {
		add("template_capabilities", "Template capabilities", "passed", "Selected adapter can represent the configured WLAN template fields in software evidence.")
	} else {
		add("template_capabilities", "Template capabilities", "warning", fmt.Sprintf("%d template field(s) require external adapter or vendor API certification.", unsupportedCount))
	}
	if adapter.DriftDetection {
		add("drift_preview", "Drift preview", "passed", "Adapter supports desired-state hash and pull preview for drift detection.")
	} else {
		add("drift_preview", "Drift preview", "warning", "Adapter does not advertise drift detection.")
	}
	add("delete_safety", "Delete safety", "passed", "Unknown and orphaned controller objects are observed and protected from automatic delete.")
	add("rollback_checkpoint", "Rollback checkpoint", "passed", "Apply records lifecycle evidence for rollback and audit before external push.")
	add("firmware_cluster", "Firmware and cluster certification", "passed", "External firmware, AP model, cluster, and HA proof is tracked in the NAS-0078 release certification checklist.")
	if cfg.Integrations.Controller.Enabled && cfg.Wireless.Enabled {
		add("ownership_boundary", "Ownership boundary", "blocked", "Controller automation and local-radio hostapd cannot own WLAN enforcement at the same time.")
	}
	return checks
}

func controllerEstateManagedFields(ssid config.SSIDConfig, adapter ControllerAdapterDescriptor) []string {
	fields := []string{"name", "auth_mode", "vlan", "identity_source"}
	if ssid.DynamicVLAN {
		fields = append(fields, "dynamic_vlan")
	}
	if strings.TrimSpace(ssid.BandwidthProfile) != "" {
		fields = append(fields, "bandwidth_profile")
	}
	if strings.TrimSpace(ssid.PortalProfile) != "" && adapter.GuestPortal {
		fields = append(fields, "portal_profile")
	}
	if strings.TrimSpace(ssid.RoamingProfile) != "" && adapter.WirelessProfiles {
		fields = append(fields, "roaming_profile")
	}
	if strings.TrimSpace(ssid.PasspointProfile) != "" && adapter.WirelessProfiles {
		fields = append(fields, "passpoint_profile")
	}
	if strings.TrimSpace(ssid.PPSKProfile) != "" && adapter.WirelessProfiles {
		fields = append(fields, "ppsk_profile")
	}
	sort.Strings(fields)
	return fields
}

func controllerEstateUnsupportedFields(ssid config.SSIDConfig, adapter ControllerAdapterDescriptor) []string {
	var unsupported []string
	if strings.TrimSpace(ssid.PortalProfile) != "" && !adapter.GuestPortal {
		unsupported = append(unsupported, "portal_profile")
	}
	if strings.TrimSpace(ssid.RoamingProfile) != "" && !adapter.WirelessProfiles {
		unsupported = append(unsupported, "roaming_profile")
	}
	if strings.TrimSpace(ssid.PasspointProfile) != "" && !adapter.WirelessProfiles {
		unsupported = append(unsupported, "passpoint_profile")
	}
	if strings.TrimSpace(ssid.PPSKProfile) != "" && !adapter.WirelessProfiles {
		unsupported = append(unsupported, "ppsk_profile")
	}
	if ssid.Hidden && !adapter.WirelessProfiles {
		unsupported = append(unsupported, "hidden")
	}
	sort.Strings(unsupported)
	return unsupported
}

func controllerEstateInventoryObject(id, typ, name, platform, ownership string, active, deleteProtected bool, attrs map[string]any) ControllerEstateInventoryObject {
	status := "ready"
	if !active {
		status = "inactive"
	}
	item := ControllerEstateInventoryObject{
		ID:              id,
		Type:            typ,
		Name:            name,
		Platform:        platform,
		Ownership:       ownership,
		Status:          status,
		DeleteProtected: deleteProtected,
		External:        strings.Contains(ownership, "external"),
		Attributes:      attrs,
	}
	item.Fingerprint = controllerEstateHash(item)
	return item
}

func recordControllerEstateLifecycleEvent(report ControllerEstateLifecycleReport, operation, actor string) (string, error) {
	status := report.Status
	switch operation {
	case "preview":
		if status == "ready" || status == "degraded" {
			status = "previewed"
		}
	case "apply":
		if status == "ready" || status == "degraded" {
			status = "applied"
		}
	}
	return db.RecordControllerEstateLifecycleEvent(db.ControllerEstateLifecycleEventInput{
		Operation:                operation,
		Status:                   status,
		Adapter:                  report.Summary.ConfiguredAdapter,
		Platform:                 report.Summary.ConfiguredPlatform,
		Endpoint:                 report.Configured.Endpoint,
		Site:                     report.Configured.Site,
		SyncMode:                 report.Summary.SyncMode,
		DesiredStateHash:         report.DesiredStateHash,
		PlanFingerprint:          report.PlanFingerprint,
		InventoryObjectCount:     report.Summary.InventoryObjectCount,
		TemplateCount:            report.Summary.TemplateCount,
		WLANTemplateCount:        report.Summary.WLANTemplateCount,
		ManagedObjectCount:       report.Summary.ManagedObjectCount,
		DeleteGuardCount:         report.Summary.DeleteGuardCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              marshalControllerEstateJSON(report.Summary),
		ReportJSON:               marshalControllerEstateJSON(report),
		Actor:                    actor,
	})
}

func controllerEstateLifecycleStatus(report ControllerEstateLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.ControllerEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func controllerEstateLifecycleCompletion(report ControllerEstateLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func controllerEstateLifecycleMessage(report ControllerEstateLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0078 software is ready; controller estate lifecycle is not active in this configuration."
	case "blocked":
		return "NAS-0078 controller estate lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0078 plans %d inventory object(s) and %d WLAN template(s) with warnings; review external certification scope.", report.Summary.InventoryObjectCount, report.Summary.WLANTemplateCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0078 plans %d inventory object(s), %d WLAN template(s), %d delete guard(s), and %d compliance check(s).",
			report.Summary.InventoryObjectCount,
			report.Summary.WLANTemplateCount,
			report.Summary.DeleteGuardCount,
			report.Summary.ComplianceCheckCount,
		)
	}
}

func controllerEstateLifecycleFingerprint(report ControllerEstateLifecycleReport) string {
	payload := struct {
		FeatureID        string
		DesiredStateHash string
		Summary          ControllerEstateLifecycleSummary
		Configured       ControllerEstateConfiguredState
		Inventory        []ControllerEstateInventoryObject
		Templates        []ControllerEstateTemplate
		ObjectPlans      []ControllerEstateObjectPlan
		Compliance       []ControllerEstateComplianceCheck
	}{
		FeatureID:        report.FeatureID,
		DesiredStateHash: report.DesiredStateHash,
		Summary:          report.Summary,
		Configured:       report.Configured,
		Inventory:        report.Inventory,
		Templates:        report.Templates,
		ObjectPlans:      report.ObjectPlans,
		Compliance:       report.Compliance,
	}
	return controllerEstateHash(payload)
}

func controllerEstateHash(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func marshalControllerEstateJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func controllerEstateHasEnterpriseSSIDs(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise", "wpa3-enterprise":
			return true
		}
	}
	return false
}

func controllerEstateVendors(catalog []ControllerAdapterDescriptor) []string {
	vendors := make([]string, 0, len(catalog))
	for _, descriptor := range catalog {
		vendors = append(vendors, descriptor.Label)
	}
	sort.Strings(vendors)
	return vendors
}

func firstNonEmptyControllerEstateString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
