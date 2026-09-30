package enforcement

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	CWAPortalLifecycleSchemaVersion = 1
	CWAPortalLifecycleFeatureID     = "NAS-0081"
	cwaPortalLifecycleComponent     = "cwa_portal_lifecycle"
)

type CWAPortalLifecycleReport struct {
	SchemaVersion                 int                         `json:"schema_version"`
	FeatureID                     string                      `json:"feature_id"`
	Status                        string                      `json:"status"`
	Message                       string                      `json:"message"`
	GeneratedAt                   string                      `json:"generated_at"`
	SoftwareCompletionPercent     float64                     `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                        `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                      `json:"release_certification_checklist"`
	ReleaseScope                  string                      `json:"release_scope"`
	PlanFingerprint               string                      `json:"plan_fingerprint"`
	Summary                       CWAPortalLifecycleSummary   `json:"summary"`
	RFC8910API                    CWARFC8910APIReport         `json:"rfc8910_api"`
	GuestSSIDs                    []CWAGuestSSIDReport        `json:"guest_ssids"`
	WalledGarden                  []CWAWalledGardenReport     `json:"walled_garden"`
	ControllerPolicies            []CWAControllerPolicyReport `json:"controller_policies"`
	RedirectRules                 []CWARedirectRuleReport     `json:"redirect_rules"`
	CoAActions                    []CWACoAActionReport        `json:"coa_actions"`
	Compliance                    []CWAPortalComplianceCheck  `json:"compliance"`
	Standards                     []string                    `json:"standards"`
	Vendors                       []string                    `json:"vendors"`
	Requirements                  []string                    `json:"requirements"`
	Blockers                      []string                    `json:"blockers,omitempty"`
	Warnings                      []string                    `json:"warnings,omitempty"`
	Notes                         []string                    `json:"notes,omitempty"`
}

type CWAPortalLifecycleSummary struct {
	CWAEnabled               bool   `json:"cwa_enabled"`
	PortalEnabled            bool   `json:"portal_enabled"`
	WirelessEnabled          bool   `json:"wireless_enabled"`
	ControllerEnabled        bool   `json:"controller_enabled"`
	DynamicAuthEnabled       bool   `json:"dynamic_auth_enabled"`
	RFC8910APIEnabled        bool   `json:"rfc8910_api_enabled"`
	HTTPSRequired            bool   `json:"https_required"`
	SessionBindingRequired   bool   `json:"session_binding_required"`
	PerSessionWalledGarden   bool   `json:"per_session_walled_garden"`
	CoAAfterAuthentication   bool   `json:"coa_after_authentication"`
	ControllerRedirect       bool   `json:"controller_redirect_enabled"`
	Mode                     string `json:"mode"`
	PortalBaseURL            string `json:"portal_base_url,omitempty"`
	CaptiveAPIPath           string `json:"captive_api_path,omitempty"`
	ControllerPlatform       string `json:"controller_platform,omitempty"`
	GuestSSIDCount           int    `json:"guest_ssid_count"`
	WalledGardenCount        int    `json:"walled_garden_count"`
	RequiredGardenCount      int    `json:"required_garden_count"`
	ControllerPolicyCount    int    `json:"controller_policy_count"`
	RedirectRuleCount        int    `json:"redirect_rule_count"`
	CoAActionCount           int    `json:"coa_action_count"`
	ComplianceCheckCount     int    `json:"compliance_check_count"`
	PassedCheckCount         int    `json:"passed_check_count"`
	WarningCount             int    `json:"warning_count"`
	BlockerCount             int    `json:"blocker_count"`
	ExternalRequirementCount int    `json:"external_requirement_count"`
}

type CWARFC8910APIReport struct {
	Enabled          bool              `json:"enabled"`
	Status           string            `json:"status"`
	Reason           string            `json:"reason"`
	EndpointPath     string            `json:"endpoint_path"`
	EndpointURL      string            `json:"endpoint_url"`
	UserPortalURL    string            `json:"user_portal_url"`
	VenueInfoURL     string            `json:"venue_info_url,omitempty"`
	CanExtendSession bool              `json:"can_extend_session"`
	Payload          map[string]any    `json:"payload"`
	Headers          map[string]string `json:"headers"`
}

type CWAGuestSSIDReport struct {
	Name             string `json:"name"`
	Bridge           string `json:"bridge,omitempty"`
	PortalProfile    string `json:"portal_profile,omitempty"`
	BandwidthProfile string `json:"bandwidth_profile,omitempty"`
	DynamicVLAN      bool   `json:"dynamic_vlan"`
	ClientIsolation  bool   `json:"client_isolation"`
	Status           string `json:"status"`
	Reason           string `json:"reason"`
}

type CWAWalledGardenReport struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Ports    []int  `json:"ports,omitempty"`
	Required bool   `json:"required"`
	Source   string `json:"source"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

type CWAControllerPolicyReport struct {
	Name           string         `json:"name"`
	Vendor         string         `json:"vendor,omitempty"`
	Platform       string         `json:"platform,omitempty"`
	SSID           string         `json:"ssid,omitempty"`
	ProfileName    string         `json:"profile_name,omitempty"`
	RedirectACL    string         `json:"redirect_acl,omitempty"`
	PreAuthRole    string         `json:"pre_auth_role,omitempty"`
	PostAuthRole   string         `json:"post_auth_role,omitempty"`
	CoAAction      string         `json:"coa_action,omitempty"`
	ControllerSync bool           `json:"controller_sync"`
	Status         string         `json:"status"`
	Reason         string         `json:"reason"`
	Payload        map[string]any `json:"payload,omitempty"`
}

type CWARedirectRuleReport struct {
	ID            string `json:"id"`
	SSID          string `json:"ssid"`
	PortalProfile string `json:"portal_profile,omitempty"`
	RedirectURL   string `json:"redirect_url"`
	PreAuthRole   string `json:"pre_auth_role"`
	PostAuthRole  string `json:"post_auth_role"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
}

type CWACoAActionReport struct {
	ID        string   `json:"id"`
	Action    string   `json:"action"`
	Trigger   string   `json:"trigger"`
	Standards []string `json:"standards"`
	Vendors   []string `json:"vendors"`
	Status    string   `json:"status"`
	Reason    string   `json:"reason"`
}

type CWAPortalComplianceCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func CWAPortalLifecycleComponent() string {
	return cwaPortalLifecycleComponent
}

func PreviewCWAPortalLifecycle(cfg *config.Config) (CWAPortalLifecycleReport, error) {
	if cfg == nil {
		return CWAPortalLifecycleReport{}, fmt.Errorf("config is required")
	}
	cwa := cfg.Portal.CWA
	portalBaseURL := cwaPortalBaseURL(cfg)
	apiPath := cwaCaptiveAPIPath(cwa.CaptiveAPIPath)
	report := CWAPortalLifecycleReport{
		SchemaVersion:                 CWAPortalLifecycleSchemaVersion,
		FeatureID:                     CWAPortalLifecycleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0081-release-certification-checklist.md",
		ReleaseScope:                  "Live Cisco/Aruba/Ruckus/Fortinet/Meraki/UniFi/Mist controller CWA redirect, AP firmware behavior, DHCP/RA RFC 8910 advertisement, HTTPS certificate trust, packet captures, HA, scale, soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards: []string{
			"RFC 2865",
			"RFC 2866",
			"RFC 5176",
			"RFC 7710",
			"RFC 8910",
			"RFC 8908",
			"IEEE 802.1X",
			"IEEE 802.11",
		},
		Vendors: []string{"Cisco", "Aruba", "Ruckus", "Fortinet", "Meraki", "UniFi", "Juniper Mist", "Cambium", "MikroTik", "OpenWiFi", "hostapd"},
		Requirements: []string{
			"captive clients receive a deterministic portal API endpoint and portal URL",
			"guest SSIDs are mapped to session-scoped redirect and post-auth roles",
			"walled-garden entries are explicit, bounded, and separately mark required system access",
			"controller redirect policies are previewed with vendor/platform ownership before mutation",
			"post-auth CoA or Disconnect behavior is gated by RFC 5176 dynamic authorization readiness",
			"all preview/apply operations persist signed evidence and runtime status",
		},
		Notes: []string{
			"NAS-0081 completes software governance for safe controller CWA and per-session portal workflows.",
			"Live controller/API mutation and DHCP/RA option advertisement proof remain release certification evidence.",
		},
	}
	report.Summary = CWAPortalLifecycleSummary{
		CWAEnabled:               cwa.Enabled,
		PortalEnabled:            cfg.Portal.Enabled,
		WirelessEnabled:          cfg.Wireless.Enabled,
		ControllerEnabled:        cfg.Integrations.Controller.Enabled,
		DynamicAuthEnabled:       cfg.Radius.DynamicAuth.Enabled,
		RFC8910APIEnabled:        cwa.RFC8910APIEnabled,
		HTTPSRequired:            cwa.HTTPSRequired,
		SessionBindingRequired:   cwa.SessionBindingRequired,
		PerSessionWalledGarden:   cwa.PerSessionWalledGarden,
		CoAAfterAuthentication:   cwa.CoAAfterAuthentication,
		ControllerRedirect:       cwa.ControllerRedirectEnabled,
		Mode:                     cwaEffectiveMode(cwa.Mode),
		PortalBaseURL:            portalBaseURL,
		CaptiveAPIPath:           apiPath,
		ControllerPlatform:       strings.TrimSpace(cfg.Integrations.Controller.Platform),
		ExternalRequirementCount: 8,
	}
	if report.Summary.ControllerPlatform == "" {
		report.Summary.ControllerPlatform = "local"
	}
	if !cwa.Enabled {
		report.RFC8910API = cwaBuildRFC8910APIReport(cfg, portalBaseURL, apiPath)
		report.Status = "skipped"
		report.Message = "NAS-0081 software is ready; CWA portal lifecycle is not active in this configuration."
		report.PlanFingerprint = cwaPortalFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}
	report.RFC8910API = cwaBuildRFC8910APIReport(cfg, portalBaseURL, apiPath)
	report.GuestSSIDs = cwaBuildGuestSSIDs(cfg)
	report.WalledGarden = cwaBuildWalledGarden(cfg, portalBaseURL, apiPath)
	report.ControllerPolicies = cwaBuildControllerPolicies(cfg, &report)
	report.RedirectRules = cwaBuildRedirectRules(cfg, portalBaseURL)
	report.CoAActions = cwaBuildCoAActions(cfg, &report)
	report.Summary.GuestSSIDCount = len(report.GuestSSIDs)
	report.Summary.WalledGardenCount = len(report.WalledGarden)
	report.Summary.ControllerPolicyCount = len(report.ControllerPolicies)
	report.Summary.RedirectRuleCount = len(report.RedirectRules)
	report.Summary.CoAActionCount = len(report.CoAActions)
	for _, entry := range report.WalledGarden {
		if entry.Required {
			report.Summary.RequiredGardenCount++
		}
	}
	report.Compliance = cwaBuildCompliance(cfg, &report)
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
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.Status = cwaPortalStatus(report)
	report.SoftwareCompletionPercent = cwaPortalCompletion(report)
	report.ReadyForExternalValidation = report.Status != "blocked"
	report.Message = cwaPortalMessage(report)
	report.PlanFingerprint = cwaPortalFingerprint(report)
	return report, nil
}

func PreviewAndRecordCWAPortalLifecycle(cfg *config.Config, actor string) (CWAPortalLifecycleReport, string, error) {
	report, err := PreviewCWAPortalLifecycle(cfg)
	if err != nil {
		return CWAPortalLifecycleReport{}, "", err
	}
	eventID, err := recordCWAPortalLifecycleEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyCWAPortalLifecycle(ctx context.Context, cfg *config.Config, actor string) (CWAPortalLifecycleReport, string, error) {
	report, err := PreviewCWAPortalLifecycle(cfg)
	if err != nil {
		return CWAPortalLifecycleReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordCWAPortalLifecycleEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(cwaPortalLifecycleComponent, "down", report.Message, cwaPortalRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("CWA portal lifecycle apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0081 recorded CWA portal lifecycle for %d guest SSID(s), %d walled-garden item(s), %d controller policy item(s), %d redirect rule(s), and %d CoA action(s).",
			report.Summary.GuestSSIDCount,
			report.Summary.WalledGardenCount,
			report.Summary.ControllerPolicyCount,
			report.Summary.RedirectRuleCount,
			report.Summary.CoAActionCount,
		)
	}
	eventID, err := recordCWAPortalLifecycleEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := cwaPortalRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if len(report.Warnings) > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(cwaPortalLifecycleComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(cwaPortalLifecycleComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordCWAPortalLifecycleEvent(report CWAPortalLifecycleReport, operation, actor string) (string, error) {
	status := report.Status
	switch operation {
	case "preview":
		if status == "ready" || status == "degraded" {
			status = "previewed"
		}
	case "apply":
		if status == "ready" || status == "degraded" || status == "applied" {
			status = "applied"
		}
	}
	return db.RecordCWAPortalLifecycleEvent(db.CWAPortalLifecycleEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		PortalBaseURL:            report.Summary.PortalBaseURL,
		ControllerPlatform:       report.Summary.ControllerPlatform,
		GuestSSIDCount:           report.Summary.GuestSSIDCount,
		WalledGardenCount:        report.Summary.WalledGardenCount,
		ControllerPolicyCount:    report.Summary.ControllerPolicyCount,
		RedirectRuleCount:        report.Summary.RedirectRuleCount,
		CoAActionCount:           report.Summary.CoAActionCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              marshalJSON(report.Summary),
		ReportJSON:               marshalJSON(report),
		Actor:                    actor,
	})
}

func cwaBuildRFC8910APIReport(cfg *config.Config, portalBaseURL, apiPath string) CWARFC8910APIReport {
	endpointURL := strings.TrimRight(portalBaseURL, "/") + apiPath
	userPortalURL := strings.TrimRight(portalBaseURL, "/") + "/"
	payload := map[string]any{
		"captive":            true,
		"user-portal-url":    userPortalURL,
		"can-extend-session": false,
	}
	if strings.TrimSpace(cfg.Portal.CWA.VenueInfoURL) != "" {
		payload["venue-info-url"] = strings.TrimSpace(cfg.Portal.CWA.VenueInfoURL)
	}
	status := "ready"
	reason := "RFC 8910 captive portal API payload is deterministic and safe for unauthenticated clients."
	if !cfg.Portal.CWA.RFC8910APIEnabled {
		status = "disabled"
		reason = "RFC 8910 captive portal API is disabled by configuration."
	}
	if cfg.Portal.CWA.HTTPSRequired && !strings.HasPrefix(strings.ToLower(endpointURL), "https://") {
		status = "blocked"
		reason = "RFC 8910 endpoint must use HTTPS when portal.cwa.https_required is true."
	}
	return CWARFC8910APIReport{
		Enabled:          cfg.Portal.CWA.RFC8910APIEnabled,
		Status:           status,
		Reason:           reason,
		EndpointPath:     apiPath,
		EndpointURL:      endpointURL,
		UserPortalURL:    userPortalURL,
		VenueInfoURL:     strings.TrimSpace(cfg.Portal.CWA.VenueInfoURL),
		CanExtendSession: false,
		Payload:          payload,
		Headers: map[string]string{
			"Content-Type":  "application/captive+json",
			"Cache-Control": "no-store",
		},
	}
}

func cwaBuildGuestSSIDs(cfg *config.Config) []CWAGuestSSIDReport {
	reports := []CWAGuestSSIDReport{}
	for _, ssid := range cfg.Wireless.SSIDs {
		if !strings.EqualFold(strings.TrimSpace(ssid.AuthMode), "captive-portal") {
			continue
		}
		status := "ready"
		reason := "Captive-portal SSID is eligible for CWA redirect and post-auth policy."
		if !ssid.ClientIsolation {
			status = "warning"
			reason = "Client isolation is recommended for captive guest WLANs."
		}
		reports = append(reports, CWAGuestSSIDReport{
			Name:             strings.TrimSpace(ssid.Name),
			Bridge:           strings.TrimSpace(ssid.Bridge),
			PortalProfile:    strings.TrimSpace(ssid.PortalProfile),
			BandwidthProfile: strings.TrimSpace(ssid.BandwidthProfile),
			DynamicVLAN:      ssid.DynamicVLAN,
			ClientIsolation:  ssid.ClientIsolation,
			Status:           status,
			Reason:           reason,
		})
	}
	sort.SliceStable(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })
	return reports
}

func cwaBuildWalledGarden(cfg *config.Config, portalBaseURL, apiPath string) []CWAWalledGardenReport {
	items := []CWAWalledGardenReport{}
	add := func(item CWAWalledGardenReport) {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Value) == "" {
			return
		}
		if item.Type == "" {
			item.Type = "domain"
		}
		if item.Status == "" {
			item.Status = "ready"
		}
		items = append(items, item)
	}
	if parsed, err := url.Parse(portalBaseURL); err == nil && parsed.Hostname() != "" {
		add(CWAWalledGardenReport{
			Name:     "portal-origin",
			Type:     "host",
			Value:    parsed.Hostname(),
			Ports:    cwaPortalPorts(parsed.Scheme),
			Required: true,
			Source:   "system",
			Status:   "ready",
			Reason:   "Captive clients must reach the AegisNAS portal origin before authentication.",
		})
	}
	add(CWAWalledGardenReport{
		Name:     "rfc8910-api",
		Type:     "url",
		Value:    strings.TrimRight(portalBaseURL, "/") + apiPath,
		Ports:    []int{443},
		Required: true,
		Source:   "system",
		Status:   "ready",
		Reason:   "Captive clients must reach the RFC 8910 API endpoint.",
	})
	for _, entry := range cfg.Portal.CWA.WalledGarden {
		ports := append([]int(nil), entry.Ports...)
		sort.Ints(ports)
		add(CWAWalledGardenReport{
			Name:     strings.TrimSpace(entry.Name),
			Type:     cwaEffectiveGardenType(entry.Type),
			Value:    strings.TrimSpace(entry.Value),
			Ports:    ports,
			Required: entry.Required,
			Source:   "operator",
			Status:   "ready",
			Reason:   "Operator-declared pre-auth reachability intent.",
		})
	}
	return items
}

func cwaBuildControllerPolicies(cfg *config.Config, report *CWAPortalLifecycleReport) []CWAControllerPolicyReport {
	policies := []CWAControllerPolicyReport{}
	for _, policy := range cfg.Portal.CWA.ControllerPolicies {
		if !policy.Enabled {
			continue
		}
		platform := strings.TrimSpace(cwaFirstNonEmpty(policy.Platform, policy.Vendor, cfg.Integrations.Controller.Platform, "generic"))
		status := "ready"
		reason := "Controller CWA policy is modeled as safe desired state."
		if cfg.Portal.CWA.ControllerRedirectEnabled && !cfg.Integrations.Controller.Enabled {
			status = "blocked"
			reason = "Controller redirect policy requires integrations.controller.enabled."
		} else if policy.ControllerSync && !cfg.Integrations.Controller.Enabled {
			status = "warning"
			reason = "Controller sync is requested but controller integration is disabled."
		}
		policies = append(policies, CWAControllerPolicyReport{
			Name:           strings.TrimSpace(policy.Name),
			Vendor:         strings.TrimSpace(policy.Vendor),
			Platform:       platform,
			SSID:           strings.TrimSpace(policy.SSID),
			ProfileName:    strings.TrimSpace(policy.ProfileName),
			RedirectACL:    strings.TrimSpace(policy.RedirectACL),
			PreAuthRole:    strings.TrimSpace(policy.PreAuthRole),
			PostAuthRole:   strings.TrimSpace(policy.PostAuthRole),
			CoAAction:      cwaEffectiveCoAAction(policy.CoAAction),
			ControllerSync: policy.ControllerSync,
			Status:         status,
			Reason:         reason,
			Payload: map[string]any{
				"portal_api":       report.RFC8910API.EndpointURL,
				"user_portal_url":  report.RFC8910API.UserPortalURL,
				"radius_profile":   strings.TrimSpace(cfg.Integrations.Controller.RadiusProfile),
				"radius_server":    strings.TrimSpace(cfg.Integrations.Controller.RadiusServer),
				"controller_site":  strings.TrimSpace(cfg.Integrations.Controller.Site),
				"release_evidence": report.ReleaseCertificationChecklist,
			},
		})
	}
	return policies
}

func cwaBuildRedirectRules(cfg *config.Config, portalBaseURL string) []CWARedirectRuleReport {
	rules := []CWARedirectRuleReport{}
	for _, ssid := range cwaBuildGuestSSIDs(cfg) {
		redirectURL := strings.TrimRight(portalBaseURL, "/") + "/?ssid=" + url.QueryEscape(ssid.Name) + "&client_mac={calling_station_id}&session_id={acct_session_id}"
		preAuthRole := "cwa-preauth"
		if ssid.PortalProfile != "" {
			preAuthRole = ssid.PortalProfile + "-preauth"
		}
		postAuthRole := cwaFirstNonEmpty(ssid.PortalProfile, cfg.Policy.DefaultRole, "guest")
		rules = append(rules, CWARedirectRuleReport{
			ID:            "cwa-" + cwaSlug(ssid.Name),
			SSID:          ssid.Name,
			PortalProfile: ssid.PortalProfile,
			RedirectURL:   redirectURL,
			PreAuthRole:   preAuthRole,
			PostAuthRole:  postAuthRole,
			Status:        "ready",
			Reason:        "Per-session redirect URL includes Calling-Station-Id and accounting session placeholders.",
		})
	}
	return rules
}

func cwaBuildCoAActions(cfg *config.Config, report *CWAPortalLifecycleReport) []CWACoAActionReport {
	if !cfg.Portal.CWA.CoAAfterAuthentication {
		return nil
	}
	status := "ready"
	reason := "RFC 5176 CoA reauth can move a client from pre-auth redirect to post-auth policy."
	if !cfg.Radius.DynamicAuth.Enabled {
		status = "blocked"
		reason = "radius.dynamic_auth.enabled is required for post-auth CWA CoA."
	}
	vendors := []string{"Cisco", "Aruba", "Ruckus", "Fortinet", "Meraki", "UniFi", "Mist"}
	actions := []CWACoAActionReport{{
		ID:        "post-auth-reauth",
		Action:    "reauth",
		Trigger:   "portal-authentication-success",
		Standards: []string{"RFC 5176"},
		Vendors:   vendors,
		Status:    status,
		Reason:    reason,
	}}
	if report.Summary.Mode == "enforce" && cfg.Portal.CWA.FailClosed {
		actions = append(actions, CWACoAActionReport{
			ID:        "failed-session-disconnect",
			Action:    "disconnect",
			Trigger:   "portal-session-binding-failure",
			Standards: []string{"RFC 5176"},
			Vendors:   vendors,
			Status:    status,
			Reason:    "Fail-closed CWA can disconnect sessions that fail binding or ownership validation.",
		})
	}
	return actions
}

func cwaBuildCompliance(cfg *config.Config, report *CWAPortalLifecycleReport) []CWAPortalComplianceCheck {
	checks := []CWAPortalComplianceCheck{}
	add := func(id, name, status, message string, evidence ...string) {
		checks = append(checks, CWAPortalComplianceCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence})
	}
	if cfg.Portal.Enabled {
		add("portal-enabled", "Portal Service", "passed", "Captive portal service is enabled.")
	} else {
		add("portal-enabled", "Portal Service", "blocked", "portal.enabled is required for CWA.")
	}
	if len(report.GuestSSIDs) > 0 {
		add("guest-ssid", "Guest SSID", "passed", fmt.Sprintf("%d captive-portal SSID(s) are declared.", len(report.GuestSSIDs)))
	} else {
		status := "warning"
		if report.Summary.Mode == "enforce" && cfg.Portal.CWA.FailClosed {
			status = "blocked"
		}
		add("guest-ssid", "Guest SSID", status, "Add at least one wireless SSID with auth_mode=captive-portal before CWA rollout.")
	}
	if report.RFC8910API.Status == "ready" {
		add("rfc8910-api", "RFC 8910 API", "passed", "RFC 8910 API payload and endpoint are available.", report.RFC8910API.EndpointURL)
	} else if report.RFC8910API.Status == "disabled" {
		add("rfc8910-api", "RFC 8910 API", "warning", "Enable portal.cwa.rfc8910_api_enabled before client OS captive portal detection claims.")
	} else {
		add("rfc8910-api", "RFC 8910 API", "blocked", report.RFC8910API.Reason)
	}
	if !cfg.Portal.CWA.HTTPSRequired || strings.HasPrefix(strings.ToLower(report.RFC8910API.EndpointURL), "https://") {
		add("https", "HTTPS", "passed", "Portal API HTTPS requirement is satisfied.")
	} else {
		add("https", "HTTPS", "blocked", "CWA HTTPS requirement is enabled but the portal API URL is not HTTPS.")
	}
	if cfg.Portal.CWA.SessionBindingRequired {
		add("session-binding", "Session Binding", "passed", "Redirect URLs bind to Calling-Station-Id and Acct-Session-Id placeholders.")
	} else {
		add("session-binding", "Session Binding", "warning", "Enable session binding before enterprise CWA claims.")
	}
	if len(report.WalledGarden) > 0 {
		add("walled-garden", "Walled Garden", "passed", fmt.Sprintf("%d walled-garden item(s) are declared.", len(report.WalledGarden)))
	} else {
		add("walled-garden", "Walled Garden", "blocked", "CWA requires at least portal/API pre-auth reachability.")
	}
	if cfg.Portal.CWA.ControllerRedirectEnabled {
		if cfg.Integrations.Controller.Enabled {
			add("controller-redirect", "Controller Redirect", "passed", "Controller redirect intent has a configured controller integration.")
		} else {
			add("controller-redirect", "Controller Redirect", "blocked", "Controller redirect requires integrations.controller.enabled.")
		}
	} else {
		add("controller-redirect", "Controller Redirect", "passed", "Local CWA redirect mode is selected; controller redirect remains disabled.")
	}
	if cfg.Portal.CWA.CoAAfterAuthentication {
		if cfg.Radius.DynamicAuth.Enabled {
			add("coa-handoff", "CoA Handoff", "passed", "RFC 5176 dynamic authorization is enabled for post-auth policy change.")
		} else {
			add("coa-handoff", "CoA Handoff", "blocked", "Enable radius.dynamic_auth.enabled for post-auth CWA CoA.")
		}
	}
	add("external-certification", "External Certification", "passed", "Live controller/AP redirect, DHCP/RA advertisement, packet capture, HA, scale, soak, security, and customer proof are tracked outside software completion.", report.ReleaseCertificationChecklist)
	return checks
}

func cwaPortalStatus(report CWAPortalLifecycleReport) string {
	if len(report.Blockers) > 0 {
		return "blocked"
	}
	if !report.Summary.CWAEnabled {
		return "skipped"
	}
	if len(report.Warnings) > 0 {
		return "degraded"
	}
	return "ready"
}

func cwaPortalCompletion(report CWAPortalLifecycleReport) float64 {
	if report.Status == "blocked" || report.Status == "failed" {
		return 0
	}
	return 100
}

func cwaPortalMessage(report CWAPortalLifecycleReport) string {
	switch report.Status {
	case "skipped":
		return "NAS-0081 software is ready; CWA portal lifecycle is not active in this configuration."
	case "blocked":
		return "NAS-0081 CWA portal lifecycle is blocked by the current configuration."
	case "degraded":
		return fmt.Sprintf("NAS-0081 plans %d guest SSID(s), %d walled-garden item(s), %d controller policy item(s), %d redirect rule(s), and %d CoA action(s) with warnings.",
			report.Summary.GuestSSIDCount, report.Summary.WalledGardenCount, report.Summary.ControllerPolicyCount, report.Summary.RedirectRuleCount, report.Summary.CoAActionCount)
	case "applied":
		return report.Message
	default:
		return fmt.Sprintf("NAS-0081 plans %d guest SSID(s), %d walled-garden item(s), %d controller policy item(s), %d redirect rule(s), and %d CoA action(s).",
			report.Summary.GuestSSIDCount, report.Summary.WalledGardenCount, report.Summary.ControllerPolicyCount, report.Summary.RedirectRuleCount, report.Summary.CoAActionCount)
	}
}

func cwaPortalFingerprint(report CWAPortalLifecycleReport) string {
	payload := struct {
		FeatureID          string
		Summary            CWAPortalLifecycleSummary
		RFC8910API         CWARFC8910APIReport
		GuestSSIDs         []CWAGuestSSIDReport
		WalledGarden       []CWAWalledGardenReport
		ControllerPolicies []CWAControllerPolicyReport
		RedirectRules      []CWARedirectRuleReport
		CoAActions         []CWACoAActionReport
	}{
		FeatureID:          report.FeatureID,
		Summary:            report.Summary,
		RFC8910API:         report.RFC8910API,
		GuestSSIDs:         report.GuestSSIDs,
		WalledGarden:       report.WalledGarden,
		ControllerPolicies: report.ControllerPolicies,
		RedirectRules:      report.RedirectRules,
		CoAActions:         report.CoAActions,
	}
	return sha256JSON(payload)
}

func cwaPortalRuntimeDetails(report CWAPortalLifecycleReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                    CWAPortalLifecycleFeatureID,
		"event_id":                      eventID,
		"plan_fingerprint":              report.PlanFingerprint,
		"mode":                          report.Summary.Mode,
		"portal_base_url":               report.Summary.PortalBaseURL,
		"controller_platform":           report.Summary.ControllerPlatform,
		"guest_ssid_count":              report.Summary.GuestSSIDCount,
		"walled_garden_count":           report.Summary.WalledGardenCount,
		"controller_policy_count":       report.Summary.ControllerPolicyCount,
		"redirect_rule_count":           report.Summary.RedirectRuleCount,
		"coa_action_count":              report.Summary.CoAActionCount,
		"compliance_check_count":        report.Summary.ComplianceCheckCount,
		"passed_check_count":            report.Summary.PassedCheckCount,
		"release_checklist":             report.ReleaseCertificationChecklist,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}
}

func cwaPortalBaseURL(cfg *config.Config) string {
	if strings.TrimSpace(cfg.Portal.CWA.PortalBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(cfg.Portal.CWA.PortalBaseURL), "/")
	}
	host := strings.TrimSpace(cfg.Portal.ListenIP)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if cfg.Portal.CWA.HTTPSRequired {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, cfg.Portal.Port)
}

func cwaCaptiveAPIPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/captive-portal/api"
	}
	if !strings.HasPrefix(value, "/") {
		return "/" + value
	}
	return value
}

func cwaEffectiveMode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "monitor"
	}
	return value
}

func cwaEffectiveGardenType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "domain"
	}
	return value
}

func cwaEffectiveCoAAction(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "reauth"
	}
	return value
}

func cwaPortalPorts(scheme string) []int {
	if strings.EqualFold(scheme, "https") {
		return []int{443}
	}
	return []int{80}
}

func cwaFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cwaSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", "\\", "-", ":", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "ssid"
	}
	return value
}
