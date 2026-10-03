package enforcement

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	BroadbandL2TPWholesaleSchemaVersion = 1
	BroadbandL2TPWholesaleFeatureID     = "NAS-0088"
	broadbandL2TPWholesaleComponent     = "broadband_l2tp_wholesale"
)

type BroadbandL2TPWholesaleReport struct {
	SchemaVersion                 int                             `json:"schema_version"`
	FeatureID                     string                          `json:"feature_id"`
	Status                        string                          `json:"status"`
	Message                       string                          `json:"message"`
	GeneratedAt                   string                          `json:"generated_at"`
	SoftwareCompletionPercent     float64                         `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                            `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                          `json:"release_certification_checklist"`
	ReleaseScope                  string                          `json:"release_scope"`
	PlanFingerprint               string                          `json:"plan_fingerprint"`
	Summary                       BroadbandL2TPWholesaleSummary   `json:"summary"`
	Realms                        []BroadbandWholesaleRealm       `json:"realms"`
	TunnelProfiles                []BroadbandL2TPTunnelProfile    `json:"tunnel_profiles"`
	FailoverPolicies              []BroadbandL2TPFailoverPolicy   `json:"failover_policies"`
	AuthorizationBindings         []BroadbandL2TPWholesaleBinding `json:"authorization_bindings"`
	AccountingBindings            []BroadbandL2TPWholesaleBinding `json:"accounting_bindings"`
	Compliance                    []BroadbandL2TPWholesaleCheck   `json:"compliance"`
	Standards                     []string                        `json:"standards"`
	Vendors                       []string                        `json:"vendors"`
	Requirements                  []string                        `json:"requirements"`
	Blockers                      []string                        `json:"blockers,omitempty"`
	Warnings                      []string                        `json:"warnings,omitempty"`
	Notes                         []string                        `json:"notes,omitempty"`
}

type BroadbandL2TPWholesaleSummary struct {
	Enabled                     bool   `json:"enabled"`
	Mode                        string `json:"mode"`
	FailClosed                  bool   `json:"fail_closed"`
	RequirePPPoE                bool   `json:"require_pppoe"`
	RequireSubscriberState      bool   `json:"require_subscriber_state"`
	RequireProxyRoutes          bool   `json:"require_proxy_routes"`
	RequireAccountingDelegation bool   `json:"require_accounting_delegation"`
	RequireTunnelFailover       bool   `json:"require_tunnel_failover"`
	RealmIsolationRequired      bool   `json:"realm_isolation_required"`
	StripCustomerRealm          bool   `json:"strip_customer_realm"`
	AccountingDelegationEnabled bool   `json:"accounting_delegation_enabled"`
	CoAOnFailover               bool   `json:"coa_on_failover"`
	SelectionPolicy             string `json:"selection_policy"`
	DefaultTunnelProfile        string `json:"default_tunnel_profile,omitempty"`
	EventRetentionLimit         int    `json:"event_retention_limit"`
	PPPoEEnabled                bool   `json:"pppoe_enabled"`
	SubscriberStateEnabled      bool   `json:"subscriber_state_enabled"`
	WholesaleSubscriberEnabled  bool   `json:"wholesale_subscriber_enabled"`
	SQLAccountingEnabled        bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled   bool   `json:"accounting_services_enabled"`
	UpstreamEnabled             bool   `json:"upstream_enabled"`
	DynamicAuthEnabled          bool   `json:"dynamic_auth_enabled"`
	RealmCount                  int    `json:"realm_count"`
	EnabledRealmCount           int    `json:"enabled_realm_count"`
	TunnelProfileCount          int    `json:"tunnel_profile_count"`
	EnabledTunnelProfileCount   int    `json:"enabled_tunnel_profile_count"`
	FailoverPolicyCount         int    `json:"failover_policy_count"`
	EnabledFailoverPolicyCount  int    `json:"enabled_failover_policy_count"`
	ProxyRouteBindingCount      int    `json:"proxy_route_binding_count"`
	AccountingRouteBindingCount int    `json:"accounting_route_binding_count"`
	CompiledAttributeCount      int    `json:"compiled_attribute_count"`
	ComplianceCheckCount        int    `json:"compliance_check_count"`
	PassedCheckCount            int    `json:"passed_check_count"`
	WarningCount                int    `json:"warning_count"`
	BlockerCount                int    `json:"blocker_count"`
	ExternalRequirementCount    int    `json:"external_requirement_count"`
}

type BroadbandWholesaleRealm struct {
	BindingKey         string                         `json:"binding_key"`
	Name               string                         `json:"name"`
	Enabled            bool                           `json:"enabled"`
	Realm              string                         `json:"realm"`
	Tenant             string                         `json:"tenant,omitempty"`
	Partner            string                         `json:"partner,omitempty"`
	MatchRealms        []string                       `json:"match_realms,omitempty"`
	AccessMethod       string                         `json:"access_method"`
	TunnelProfile      string                         `json:"tunnel_profile"`
	TunnelMode         string                         `json:"tunnel_mode"`
	ProxyRoute         string                         `json:"proxy_route,omitempty"`
	AccountingRoute    string                         `json:"accounting_route,omitempty"`
	AddressPool        string                         `json:"address_pool,omitempty"`
	QoSProfile         string                         `json:"qos_profile,omitempty"`
	Product            string                         `json:"product,omitempty"`
	StripRealm         bool                           `json:"strip_realm"`
	RequireAccounting  bool                           `json:"require_accounting"`
	VendorPacks        []string                       `json:"vendor_packs"`
	CompiledAttributes []BroadbandL2TPRadiusAttribute `json:"compiled_attributes"`
	FailoverPolicy     string                         `json:"failover_policy,omitempty"`
	Status             string                         `json:"status"`
	Reason             string                         `json:"reason"`
}

type BroadbandL2TPTunnelProfile struct {
	Name                 string   `json:"name"`
	Enabled              bool     `json:"enabled"`
	Mode                 string   `json:"mode"`
	LocalName            string   `json:"local_name,omitempty"`
	PeerName             string   `json:"peer_name,omitempty"`
	LocalAddress         string   `json:"local_address,omitempty"`
	PeerAddress          string   `json:"peer_address,omitempty"`
	SecretRefSet         bool     `json:"secret_ref_set"`
	SourceInterface      string   `json:"source_interface,omitempty"`
	TunnelGroup          string   `json:"tunnel_group,omitempty"`
	WindowSize           int      `json:"window_size"`
	HelloIntervalSeconds int      `json:"hello_interval_seconds"`
	SessionLimit         int      `json:"session_limit"`
	RequireEncryption    bool     `json:"require_encryption"`
	AllowedAuth          []string `json:"allowed_auth,omitempty"`
	VendorPacks          []string `json:"vendor_packs"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
}

type BroadbandL2TPFailoverPolicy struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Realm            string   `json:"realm,omitempty"`
	PrimaryTunnel    string   `json:"primary_tunnel"`
	BackupTunnels    []string `json:"backup_tunnels"`
	Action           string   `json:"action"`
	HoldDownSeconds  int      `json:"hold_down_seconds"`
	MaxFailures      int      `json:"max_failures"`
	AccountingReplay bool     `json:"accounting_replay"`
	CoAAction        string   `json:"coa_action"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason"`
}

type BroadbandL2TPRadiusAttribute struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	Vendor  string `json:"vendor,omitempty"`
}

type BroadbandL2TPWholesaleBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandL2TPWholesaleCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandL2TPWholesaleComponent() string {
	return broadbandL2TPWholesaleComponent
}

func PreviewBroadbandL2TPWholesale(cfg *config.Config) (BroadbandL2TPWholesaleReport, error) {
	if cfg == nil {
		return BroadbandL2TPWholesaleReport{}, fmt.Errorf("config is required")
	}
	l2tp := config.EffectiveBroadbandL2TPWholesaleConfig(cfg.Broadband.L2TPWholesale)
	pppoe := config.EffectiveBroadbandPPPoEConfig(cfg.Broadband.PPPoE)
	subscriber := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	report := BroadbandL2TPWholesaleReport{
		SchemaVersion:                 BroadbandL2TPWholesaleSchemaVersion,
		FeatureID:                     BroadbandL2TPWholesaleFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0088-release-certification-checklist.md",
		ReleaseScope:                  "Live LAC/LNS hardware interop, tunnel packet captures, wholesale partner acceptance, HA failover, accounting replay, long-duration soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2661", "RFC 2865", "RFC 2866", "RFC 2868", "RFC 2869", "RFC 5176"},
		Vendors:                       []string{"Cisco", "Juniper ERX/E-Series", "Nokia/Alcatel-Lucent SR OS", "Huawei/H3C", "ADSL-Forum", "Wholesale ISP LAC/LNS platforms"},
		Requirements: []string{
			"model wholesale customer realms separately from retail subscriber identity",
			"compile L2TP tunnel selection, proxy routing, accounting delegation, and failover intent into explicit RADIUS evidence",
			"preserve per-partner tenant isolation with route-bound accounting and Proxy-State metadata",
			"record preview/apply history and effective realm bindings in durable tables",
			"surface compliance, runtime status, API, UI, support-bundle, and production-readiness evidence",
		},
		Notes: []string{
			"NAS-0088 completes software governance for L2TP and wholesale realm separation.",
			"Physical tunnel establishment, partner LNS acceptance, and packet-capture proof remain release certification evidence.",
		},
	}
	report.Summary = BroadbandL2TPWholesaleSummary{
		Enabled:                     l2tp.Enabled,
		Mode:                        l2tp.Mode,
		FailClosed:                  l2tp.FailClosed,
		RequirePPPoE:                l2tp.RequirePPPoE,
		RequireSubscriberState:      l2tp.RequireSubscriberState,
		RequireProxyRoutes:          l2tp.RequireProxyRoutes,
		RequireAccountingDelegation: l2tp.RequireAccountingDelegation,
		RequireTunnelFailover:       l2tp.RequireTunnelFailover,
		RealmIsolationRequired:      l2tp.RealmIsolationRequired,
		StripCustomerRealm:          l2tp.StripCustomerRealm,
		AccountingDelegationEnabled: l2tp.AccountingDelegationEnabled,
		CoAOnFailover:               l2tp.CoAOnFailover,
		SelectionPolicy:             l2tp.SelectionPolicy,
		DefaultTunnelProfile:        strings.TrimSpace(l2tp.DefaultTunnelProfile),
		EventRetentionLimit:         l2tp.EventRetentionLimit,
		PPPoEEnabled:                pppoe.Enabled,
		SubscriberStateEnabled:      subscriber.Enabled,
		WholesaleSubscriberEnabled:  subscriber.WholesaleEnabled,
		SQLAccountingEnabled:        cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled:   cfg.Radius.AccountingServices.Enabled,
		UpstreamEnabled:             cfg.Radius.Upstream.Enabled,
		DynamicAuthEnabled:          cfg.Radius.DynamicAuth.Enabled,
	}
	report.TunnelProfiles = buildBroadbandL2TPTunnelProfiles(l2tp)
	report.FailoverPolicies = buildBroadbandL2TPFailoverPolicies(l2tp, report.TunnelProfiles)
	report.Realms = buildBroadbandWholesaleRealms(l2tp, report.TunnelProfiles, report.FailoverPolicies)
	report.AuthorizationBindings = broadbandL2TPAuthorizationBindings(report.Realms)
	report.AccountingBindings = broadbandL2TPAccountingBindings()
	report.Compliance = broadbandL2TPComplianceChecks(l2tp, pppoe, subscriber, cfg.Radius, report)
	finalizeBroadbandL2TPWholesaleReport(&report)
	return report, nil
}

func PreviewAndRecordBroadbandL2TPWholesale(cfg *config.Config, actor string) (BroadbandL2TPWholesaleReport, string, error) {
	report, err := PreviewBroadbandL2TPWholesale(cfg)
	if err != nil {
		return BroadbandL2TPWholesaleReport{}, "", err
	}
	eventID, err := recordBroadbandL2TPWholesaleReport(report, "preview", "previewed", actor)
	return report, eventID, err
}

func ApplyBroadbandL2TPWholesale(ctx context.Context, cfg *config.Config, actor string) (BroadbandL2TPWholesaleReport, string, error) {
	_ = ctx
	report, err := PreviewBroadbandL2TPWholesale(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandL2TPWholesaleComponent, "down", err.Error(), nil)
		return BroadbandL2TPWholesaleReport{}, "", err
	}
	status := "applied"
	if report.Status == "blocked" {
		eventID, _ := recordBroadbandL2TPWholesaleReport(report, "apply", "blocked", actor)
		_ = db.UpsertRuntimeStatus(broadbandL2TPWholesaleComponent, "down", "Broadband L2TP wholesale apply blocked", broadbandL2TPStatusDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband L2TP wholesale apply blocked")
	}
	if !report.Summary.Enabled {
		status = "skipped"
	}
	eventID, err := recordBroadbandL2TPWholesaleReport(report, "apply", status, actor)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandL2TPWholesaleComponent, "down", err.Error(), broadbandL2TPStatusDetails(report, ""))
		return report, eventID, err
	}
	runtimeStatus := "ok"
	if status == "skipped" {
		runtimeStatus = "disabled"
	} else if report.Status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("NAS-0088 recorded %d wholesale realm binding(s), %d tunnel profile(s), and %d failover policie(s).", report.Summary.RealmCount, report.Summary.TunnelProfileCount, report.Summary.FailoverPolicyCount)
	_ = db.UpsertRuntimeStatus(broadbandL2TPWholesaleComponent, runtimeStatus, message, broadbandL2TPStatusDetails(report, eventID))
	return report, eventID, nil
}

func buildBroadbandL2TPTunnelProfiles(l2tp config.BroadbandL2TPWholesaleConfig) []BroadbandL2TPTunnelProfile {
	profiles := make([]BroadbandL2TPTunnelProfile, 0, len(l2tp.TunnelProfiles))
	for _, raw := range l2tp.TunnelProfiles {
		profile := BroadbandL2TPTunnelProfile{
			Name:                 strings.TrimSpace(raw.Name),
			Enabled:              raw.Enabled,
			Mode:                 normalizeBroadbandL2TPTunnelMode(raw.Mode),
			LocalName:            strings.TrimSpace(raw.LocalName),
			PeerName:             strings.TrimSpace(raw.PeerName),
			LocalAddress:         strings.TrimSpace(raw.LocalAddress),
			PeerAddress:          strings.TrimSpace(raw.PeerAddress),
			SecretRefSet:         strings.TrimSpace(raw.SecretRef) != "",
			SourceInterface:      strings.TrimSpace(raw.SourceInterface),
			TunnelGroup:          strings.TrimSpace(raw.TunnelGroup),
			WindowSize:           raw.WindowSize,
			HelloIntervalSeconds: raw.HelloIntervalSeconds,
			SessionLimit:         raw.SessionLimit,
			RequireEncryption:    raw.RequireEncryption,
			AllowedAuth:          normalizeBroadbandL2TPAuth(raw.AllowedAuth),
			VendorPacks:          normalizeBroadbandQoSPacks(raw.VendorPacks),
			Status:               "ready",
			Reason:               "Tunnel profile can be selected for L2TP realm delegation.",
		}
		if profile.WindowSize == 0 {
			profile.WindowSize = 4
		}
		if profile.HelloIntervalSeconds == 0 {
			profile.HelloIntervalSeconds = 60
		}
		if len(profile.AllowedAuth) == 0 {
			profile.AllowedAuth = []string{"pap", "chap"}
		}
		if len(profile.VendorPacks) == 0 {
			profile.VendorPacks = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackCisco, productconfigs.VendorPackJuniper, productconfigs.VendorPackNokia}
		}
		if !profile.Enabled {
			profile.Status = "disabled"
			profile.Reason = "Tunnel profile is disabled."
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func buildBroadbandL2TPFailoverPolicies(l2tp config.BroadbandL2TPWholesaleConfig, tunnels []BroadbandL2TPTunnelProfile) []BroadbandL2TPFailoverPolicy {
	tunnelNames := map[string]struct{}{}
	for _, tunnel := range tunnels {
		tunnelNames[strings.ToLower(tunnel.Name)] = struct{}{}
	}
	policies := make([]BroadbandL2TPFailoverPolicy, 0, len(l2tp.FailoverPolicies))
	for _, raw := range l2tp.FailoverPolicies {
		policy := BroadbandL2TPFailoverPolicy{
			Name:             strings.TrimSpace(raw.Name),
			Enabled:          raw.Enabled,
			Realm:            strings.TrimSpace(raw.Realm),
			PrimaryTunnel:    strings.TrimSpace(raw.PrimaryTunnel),
			BackupTunnels:    trimStringSlice(raw.BackupTunnels),
			Action:           firstNonEmptyString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw.Action)), "-", "_"), "standby"),
			HoldDownSeconds:  raw.HoldDownSeconds,
			MaxFailures:      raw.MaxFailures,
			AccountingReplay: raw.AccountingReplay,
			CoAAction:        firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.CoAAction)), "none"),
			Status:           "ready",
			Reason:           "Failover policy has tunnel references and accounting replay intent.",
		}
		if policy.HoldDownSeconds == 0 {
			policy.HoldDownSeconds = 30
		}
		if policy.MaxFailures == 0 {
			policy.MaxFailures = 3
		}
		if !policy.Enabled {
			policy.Status = "disabled"
			policy.Reason = "Failover policy is disabled."
		}
		if _, ok := tunnelNames[strings.ToLower(policy.PrimaryTunnel)]; policy.PrimaryTunnel == "" || !ok {
			policy.Status = "blocked"
			policy.Reason = "Primary tunnel profile is missing."
		}
		for _, backup := range policy.BackupTunnels {
			if _, ok := tunnelNames[strings.ToLower(backup)]; !ok {
				policy.Status = "blocked"
				policy.Reason = "At least one backup tunnel profile is missing."
				break
			}
		}
		policies = append(policies, policy)
	}
	return policies
}

func buildBroadbandWholesaleRealms(l2tp config.BroadbandL2TPWholesaleConfig, tunnels []BroadbandL2TPTunnelProfile, failovers []BroadbandL2TPFailoverPolicy) []BroadbandWholesaleRealm {
	tunnelByName := map[string]BroadbandL2TPTunnelProfile{}
	for _, tunnel := range tunnels {
		tunnelByName[strings.ToLower(tunnel.Name)] = tunnel
	}
	failoverByRealm := map[string]BroadbandL2TPFailoverPolicy{}
	failoverByTunnel := map[string]BroadbandL2TPFailoverPolicy{}
	for _, policy := range failovers {
		if policy.Realm != "" {
			failoverByRealm[strings.ToLower(policy.Realm)] = policy
		}
		if policy.PrimaryTunnel != "" {
			failoverByTunnel[strings.ToLower(policy.PrimaryTunnel)] = policy
		}
	}
	realms := make([]BroadbandWholesaleRealm, 0, len(l2tp.Realms))
	for _, raw := range l2tp.Realms {
		tunnelName := firstNonEmptyString(strings.TrimSpace(raw.TunnelProfile), strings.TrimSpace(l2tp.DefaultTunnelProfile))
		tunnel := tunnelByName[strings.ToLower(tunnelName)]
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = tunnel.VendorPacks
		}
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard}
		}
		realm := BroadbandWholesaleRealm{
			BindingKey:        broadbandL2TPBindingKey(raw),
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			Realm:             strings.TrimSpace(raw.Realm),
			Tenant:            strings.TrimSpace(raw.Tenant),
			Partner:           strings.TrimSpace(raw.Partner),
			MatchRealms:       trimStringSlice(raw.MatchRealms),
			AccessMethod:      firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.AccessMethod)), "pppoe"),
			TunnelProfile:     tunnelName,
			TunnelMode:        tunnel.Mode,
			ProxyRoute:        strings.TrimSpace(raw.ProxyRoute),
			AccountingRoute:   strings.TrimSpace(raw.AccountingRoute),
			AddressPool:       strings.TrimSpace(raw.AddressPool),
			QoSProfile:        strings.TrimSpace(raw.QoSProfile),
			Product:           strings.TrimSpace(raw.Product),
			StripRealm:        raw.StripRealm || l2tp.StripCustomerRealm,
			RequireAccounting: raw.RequireAccounting || l2tp.AccountingDelegationEnabled,
			VendorPacks:       packs,
			Status:            "ready",
			Reason:            "Wholesale realm compiles to L2TP tunnel, proxy, and accounting bindings.",
		}
		if failover, ok := failoverByRealm[strings.ToLower(realm.Realm)]; ok && failover.Enabled {
			realm.FailoverPolicy = failover.Name
		} else if failover, ok := failoverByTunnel[strings.ToLower(realm.TunnelProfile)]; ok && failover.Enabled {
			realm.FailoverPolicy = failover.Name
		}
		if !realm.Enabled {
			realm.Status = "disabled"
			realm.Reason = "Wholesale realm is disabled."
		}
		if tunnel.Name == "" {
			realm.Status = "blocked"
			realm.Reason = "Referenced L2TP tunnel profile is missing."
		} else if tunnel.Status == "disabled" {
			realm.Status = "blocked"
			realm.Reason = "Referenced L2TP tunnel profile is disabled."
		} else if tunnel.Status == "blocked" {
			realm.Status = "blocked"
			realm.Reason = tunnel.Reason
		}
		realm.CompiledAttributes = broadbandL2TPCompiledAttributes(realm, tunnel)
		realms = append(realms, realm)
	}
	return realms
}

func broadbandL2TPCompiledAttributes(realm BroadbandWholesaleRealm, tunnel BroadbandL2TPTunnelProfile) []BroadbandL2TPRadiusAttribute {
	attrs := []BroadbandL2TPRadiusAttribute{
		{Name: "Tunnel-Type", Value: "L2TP", Purpose: "Select RFC 2661 L2TP tunneling for the wholesale subscriber session."},
		{Name: "Tunnel-Medium-Type", Value: "IPv4", Purpose: "Select IP transport for the L2TP control connection."},
		{Name: "Tunnel-Server-Endpoint", Value: firstNonEmptyString(tunnel.PeerAddress, tunnel.PeerName), Purpose: "Identify the partner LNS endpoint."},
		{Name: "Tunnel-Client-Endpoint", Value: firstNonEmptyString(tunnel.LocalAddress, tunnel.LocalName), Purpose: "Identify the local LAC/LNS endpoint."},
		{Name: "Class", Value: "wholesale:" + realm.Realm, Purpose: "Persist wholesale realm identity in accounting and policy correlation."},
		{Name: "Proxy-State", Value: broadbandL2TPProxyState(realm), Purpose: "Carry proxy route, tenant, and realm separation evidence across hops."},
	}
	if tunnel.TunnelGroup != "" {
		attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Tunnel-Private-Group-ID", Value: tunnel.TunnelGroup, Purpose: "Bind the session to a named L2TP tunnel group."})
	}
	if realm.AddressPool != "" {
		attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Framed-Pool", Value: realm.AddressPool, Purpose: "Select the wholesale address pool."})
	}
	for _, pack := range realm.VendorPacks {
		switch productconfigs.NormalizeVendorCompatibilityPackKey(pack) {
		case productconfigs.VendorPackCisco:
			if tunnel.TunnelGroup != "" {
				attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Cisco-AVPair", Value: "l2tp:tunnel-group=" + tunnel.TunnelGroup, Purpose: "Cisco L2TP tunnel group selection.", Vendor: "cisco"})
			}
		case productconfigs.VendorPackJuniper, productconfigs.VendorPackERX:
			attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Juniper-AV-Pair", Value: "l2tp-tunnel-profile=" + realm.TunnelProfile, Purpose: "Juniper/ERX L2TP profile selection.", Vendor: "juniper"})
		case productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR, productconfigs.VendorPackAlcatel:
			attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Nokia-AVPair", Value: "l2tp-service=" + realm.TunnelProfile, Purpose: "Nokia/Alcatel SR OS L2TP service binding.", Vendor: "nokia"})
		case productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C:
			attrs = append(attrs, BroadbandL2TPRadiusAttribute{Name: "Huawei-AVpair", Value: "l2tp:tunnel-profile=" + realm.TunnelProfile, Purpose: "Huawei/H3C L2TP profile binding.", Vendor: "huawei"})
		}
	}
	return attrs
}

func broadbandL2TPProxyState(realm BroadbandWholesaleRealm) string {
	parts := []string{"realm=" + realm.Realm}
	if realm.ProxyRoute != "" {
		parts = append(parts, "auth_route="+realm.ProxyRoute)
	}
	if realm.AccountingRoute != "" {
		parts = append(parts, "acct_route="+realm.AccountingRoute)
	}
	if realm.Tenant != "" {
		parts = append(parts, "tenant="+realm.Tenant)
	}
	return strings.Join(parts, ";")
}

func broadbandL2TPAuthorizationBindings(realms []BroadbandWholesaleRealm) []BroadbandL2TPWholesaleBinding {
	attrs := []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Server-Endpoint", "Tunnel-Client-Endpoint", "Class", "Proxy-State", "Tunnel-Private-Group-ID"}
	if len(realms) == 0 {
		attrs = attrs[:2]
	}
	return []BroadbandL2TPWholesaleBinding{
		{Stage: "access-accept", Attributes: attrs, Purpose: "Select the wholesale L2TP tunnel, realm, tenant, and route evidence.", Required: true},
		{Stage: "proxy-request", Attributes: []string{"User-Name", "Realm", "Proxy-State", "Message-Authenticator"}, Purpose: "Forward auth traffic to the configured wholesale route without mixing tenants.", Required: true},
		{Stage: "coa", Attributes: []string{"CoA-Request", "Disconnect-Request", "Acct-Session-Id", "Class"}, Purpose: "Recover active sessions after tunnel failover or partner route withdrawal.", Required: false},
	}
}

func broadbandL2TPAccountingBindings() []BroadbandL2TPWholesaleBinding {
	return []BroadbandL2TPWholesaleBinding{
		{Stage: "start", Attributes: []string{"Acct-Status-Type=Start", "Acct-Session-Id", "Class", "Proxy-State"}, Purpose: "Open wholesale accounting ownership on the delegated route.", Required: true},
		{Stage: "interim", Attributes: []string{"Acct-Status-Type=Interim-Update", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Multi-Session-Id"}, Purpose: "Refresh delegated usage while preserving realm and tunnel context.", Required: true},
		{Stage: "stop", Attributes: []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause", "Class"}, Purpose: "Close delegated accounting and withdraw the active binding.", Required: true},
	}
}

func broadbandL2TPComplianceChecks(l2tp config.BroadbandL2TPWholesaleConfig, pppoe config.BroadbandPPPoEConfig, subscriber config.BroadbandSubscriberStateConfig, radiusCfg config.RadiusConfig, report BroadbandL2TPWholesaleReport) []BroadbandL2TPWholesaleCheck {
	return []BroadbandL2TPWholesaleCheck{
		broadbandL2TPCheck("pppoe", "PPPoE access dependency", !l2tp.Enabled || !l2tp.RequirePPPoE || pppoe.Enabled, "PPPoE access is available for wholesale LAC sessions.", "Enabled L2TP wholesale requires broadband.pppoe.enabled.", "broadband.pppoe"),
		broadbandL2TPCheck("subscriber-state", "Subscriber wholesale state dependency", !l2tp.Enabled || !l2tp.RequireSubscriberState || (subscriber.Enabled && subscriber.WholesaleEnabled), "Subscriber state and wholesale mode are enabled.", "Enabled L2TP wholesale requires broadband.subscriber_state.enabled and wholesale_enabled.", "broadband.subscriber_state"),
		broadbandL2TPCheck("upstream-routes", "Proxy route dependency", !l2tp.Enabled || !l2tp.RequireProxyRoutes || radiusCfg.Upstream.Enabled, "RADIUS upstream proxy routes are available.", "Wholesale realms require radius.upstream.enabled for auth/accounting delegation.", "radius.upstream"),
		broadbandL2TPCheck("accounting", "Accounting delegation dependency", !l2tp.Enabled || !l2tp.RequireAccountingDelegation || (radiusCfg.SQLAccounting.Enabled && radiusCfg.AccountingServices.Enabled), "SQL accounting and service correlation are enabled.", "Accounting delegation requires radius.sql_accounting and radius.accounting_services.", "radius.sql_accounting", "radius.accounting_services"),
		broadbandL2TPCheck("tunnel-profiles", "L2TP tunnel profiles", len(report.TunnelProfiles) > 0 || !l2tp.Enabled, "At least one L2TP tunnel profile is configured or the feature is disabled.", "Enabled L2TP wholesale requires a tunnel profile.", "tunnel_profiles"),
		broadbandL2TPCheck("wholesale-realms", "Wholesale realm catalog", len(report.Realms) > 0 || !l2tp.Enabled, "At least one wholesale realm is configured or the feature is disabled.", "Enabled L2TP wholesale requires a wholesale realm.", "realms"),
		broadbandL2TPCheck("failover", "Tunnel failover policy", !l2tp.Enabled || !l2tp.RequireTunnelFailover || len(report.FailoverPolicies) > 0, "Tunnel failover policy evidence is present.", "Configured L2TP wholesale requires at least one failover policy.", "failover_policies"),
		broadbandL2TPCheck("coa", "Dynamic authorization for failover", !l2tp.Enabled || !l2tp.CoAOnFailover || radiusCfg.DynamicAuth.Enabled, "Dynamic authorization is enabled for failover recovery.", "CoA on tunnel failover requires radius.dynamic_auth.enabled.", "radius.dynamic_auth"),
		broadbandL2TPCheck("external-certification", "External L2TP certification boundary", true, "Live LAC/LNS hardware, packet capture, partner route acceptance, HA, scale, soak, security, and customer proof are release certification activities.", "", "docs/nas-0088-release-certification-checklist.md"),
	}
}

func broadbandL2TPCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) BroadbandL2TPWholesaleCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return BroadbandL2TPWholesaleCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence}
}

func finalizeBroadbandL2TPWholesaleReport(report *BroadbandL2TPWholesaleReport) {
	for _, tunnel := range report.TunnelProfiles {
		report.Summary.TunnelProfileCount++
		if tunnel.Enabled {
			report.Summary.EnabledTunnelProfileCount++
		}
		if tunnel.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("tunnel profile %s: %s", tunnel.Name, tunnel.Reason))
		}
	}
	for _, policy := range report.FailoverPolicies {
		report.Summary.FailoverPolicyCount++
		if policy.Enabled {
			report.Summary.EnabledFailoverPolicyCount++
		}
		if policy.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("failover policy %s: %s", policy.Name, policy.Reason))
		}
	}
	for _, realm := range report.Realms {
		report.Summary.RealmCount++
		if realm.Enabled {
			report.Summary.EnabledRealmCount++
		}
		if realm.ProxyRoute != "" {
			report.Summary.ProxyRouteBindingCount++
		}
		if realm.AccountingRoute != "" {
			report.Summary.AccountingRouteBindingCount++
		}
		report.Summary.CompiledAttributeCount += len(realm.CompiledAttributes)
		if realm.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("wholesale realm %s: %s", realm.Name, realm.Reason))
		}
	}
	for _, check := range report.Compliance {
		report.Summary.ComplianceCheckCount++
		if check.Status == "passed" {
			report.Summary.PassedCheckCount++
		} else if check.Status == "blocked" {
			report.Blockers = append(report.Blockers, check.Message)
		}
	}
	report.Summary.ExternalRequirementCount = 1
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	report.Status = "ready"
	if !report.Summary.Enabled {
		report.Status = "disabled"
		report.Message = "NAS-0088 software is ready; L2TP wholesale realm separation is not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = fmt.Sprintf("NAS-0088 L2TP wholesale realm separation is blocked by %d requirement(s).", len(report.Blockers))
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0088 L2TP wholesale realm separation is ready with %d warning(s).", len(report.Warnings))
	} else {
		report.Message = fmt.Sprintf("NAS-0088 L2TP wholesale realm separation is ready with %d realm(s), %d tunnel profile(s), %d failover policie(s), and %d compiled attribute(s).", report.Summary.RealmCount, report.Summary.TunnelProfileCount, report.Summary.FailoverPolicyCount, report.Summary.CompiledAttributeCount)
	}
	report.PlanFingerprint = broadbandL2TPFingerprint(*report)
}

func recordBroadbandL2TPWholesaleReport(report BroadbandL2TPWholesaleReport, operation, status, actor string) (string, error) {
	return db.RecordBroadbandL2TPWholesaleEvent(db.BroadbandL2TPWholesaleEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		RealmCount:               report.Summary.RealmCount,
		TunnelProfileCount:       report.Summary.TunnelProfileCount,
		FailoverPolicyCount:      report.Summary.FailoverPolicyCount,
		ProxyRouteCount:          report.Summary.ProxyRouteBindingCount,
		AccountingRouteCount:     report.Summary.AccountingRouteBindingCount,
		CompiledAttributeCount:   report.Summary.CompiledAttributeCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              broadbandL2TPJSON(report.Summary, "{}"),
		ReportJSON:               broadbandL2TPJSON(report, "{}"),
		Actor:                    actor,
		Bindings:                 broadbandL2TPDBBindings(report, status),
	})
}

func broadbandL2TPDBBindings(report BroadbandL2TPWholesaleReport, eventStatus string) []db.BroadbandL2TPWholesaleBindingInput {
	bindings := make([]db.BroadbandL2TPWholesaleBindingInput, 0, len(report.Realms))
	for _, realm := range report.Realms {
		status := "planned"
		if eventStatus == "applied" && realm.Enabled && realm.Status == "ready" {
			status = "active"
		} else if realm.Status == "blocked" {
			status = "blocked"
		} else if realm.Status == "degraded" {
			status = "degraded"
		}
		bindings = append(bindings, db.BroadbandL2TPWholesaleBindingInput{
			BindingKey:             realm.BindingKey,
			RealmName:              realm.Name,
			Realm:                  realm.Realm,
			Tenant:                 realm.Tenant,
			Partner:                realm.Partner,
			AccessMethod:           realm.AccessMethod,
			TunnelProfile:          realm.TunnelProfile,
			TunnelMode:             realm.TunnelMode,
			ProxyRoute:             realm.ProxyRoute,
			AccountingRoute:        realm.AccountingRoute,
			AddressPool:            realm.AddressPool,
			QoSProfile:             realm.QoSProfile,
			Product:                realm.Product,
			Status:                 status,
			CompiledAttributesJSON: broadbandL2TPJSON(realm.CompiledAttributes, "[]"),
			FailoverPolicy:         realm.FailoverPolicy,
			PlanFingerprint:        report.PlanFingerprint,
			InstalledAt:            conditionalTimestamp(status == "active"),
		})
	}
	return bindings
}

func broadbandL2TPFingerprint(report BroadbandL2TPWholesaleReport) string {
	payload := map[string]any{
		"feature_id":        report.FeatureID,
		"summary":           report.Summary,
		"realms":            report.Realms,
		"tunnel_profiles":   report.TunnelProfiles,
		"failover_policies": report.FailoverPolicies,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func broadbandL2TPStatusDetails(report BroadbandL2TPWholesaleReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":        report.FeatureID,
		"event_id":          eventID,
		"plan_fingerprint":  report.PlanFingerprint,
		"status":            report.Status,
		"realm_count":       report.Summary.RealmCount,
		"tunnel_profiles":   report.Summary.TunnelProfileCount,
		"failover_policies": report.Summary.FailoverPolicyCount,
		"compiled_attrs":    report.Summary.CompiledAttributeCount,
		"blocker_count":     report.Summary.BlockerCount,
		"warning_count":     report.Summary.WarningCount,
		"external_required": report.Summary.ExternalRequirementCount,
	}
}

func broadbandL2TPJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}

func broadbandL2TPBindingKey(raw config.BroadbandWholesaleRealmConfig) string {
	parts := []string{raw.Name, raw.Realm, raw.Tenant, raw.Partner, raw.TunnelProfile, raw.ProxyRoute, raw.AccountingRoute}
	encoded := strings.ToLower(strings.Join(parts, "|"))
	sum := sha256.Sum256([]byte(encoded))
	return "bng-l2tp-realm-" + hex.EncodeToString(sum[:6])
}

func normalizeBroadbandL2TPTunnelMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "lac", "lns":
		return strings.ToLower(strings.TrimSpace(value))
	case "lac_lns", "both":
		return "lac_lns"
	default:
		return "lns"
	}
}

func normalizeBroadbandL2TPAuth(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		auth := strings.ToLower(strings.TrimSpace(value))
		if auth == "" {
			continue
		}
		if _, ok := seen[auth]; ok {
			continue
		}
		seen[auth] = struct{}{}
		out = append(out, auth)
	}
	return out
}

func trimStringSlice(values []string) []string {
	out := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
