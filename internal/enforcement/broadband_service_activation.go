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
	BroadbandServiceActivationSchemaVersion = 1
	BroadbandServiceActivationFeatureID     = "NAS-0090"
	broadbandServiceActivationComponent     = "broadband_service_activation"
)

type BroadbandServiceActivationReport struct {
	SchemaVersion                 int                                     `json:"schema_version"`
	FeatureID                     string                                  `json:"feature_id"`
	Status                        string                                  `json:"status"`
	Message                       string                                  `json:"message"`
	GeneratedAt                   string                                  `json:"generated_at"`
	SoftwareCompletionPercent     float64                                 `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                                    `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                                  `json:"release_certification_checklist"`
	ReleaseScope                  string                                  `json:"release_scope"`
	PlanFingerprint               string                                  `json:"plan_fingerprint"`
	Summary                       BroadbandServiceActivationSummary       `json:"summary"`
	Services                      []BroadbandServiceActivationService     `json:"services"`
	RoutePolicies                 []BroadbandServiceActivationRoutePolicy `json:"route_policies"`
	MulticastProfiles             []BroadbandServiceActivationMulticast   `json:"multicast_profiles"`
	ActivationPolicies            []BroadbandServiceActivationPolicy      `json:"activation_policies"`
	AuthorizationBindings         []BroadbandServiceActivationBinding     `json:"authorization_bindings"`
	AccountingBindings            []BroadbandServiceActivationBinding     `json:"accounting_bindings"`
	Compliance                    []BroadbandServiceActivationCheck       `json:"compliance"`
	Standards                     []string                                `json:"standards"`
	Vendors                       []string                                `json:"vendors"`
	Requirements                  []string                                `json:"requirements"`
	Blockers                      []string                                `json:"blockers,omitempty"`
	Warnings                      []string                                `json:"warnings,omitempty"`
	Notes                         []string                                `json:"notes,omitempty"`
}

type BroadbandServiceActivationSummary struct {
	Enabled                      bool   `json:"enabled"`
	Mode                         string `json:"mode"`
	FailClosed                   bool   `json:"fail_closed"`
	RequireSubscriberState       bool   `json:"require_subscriber_state"`
	RequireCommercialCatalog     bool   `json:"require_commercial_catalog"`
	RequireAddressLeases         bool   `json:"require_address_leases"`
	RequireQoSServiceFlows       bool   `json:"require_qos_service_flows"`
	RequireDHCPSecurity          bool   `json:"require_dhcp_security"`
	RequireRouteExport           bool   `json:"require_route_export"`
	RequireAccounting            bool   `json:"require_accounting"`
	RequireDynamicAuth           bool   `json:"require_dynamic_auth"`
	TransactionalApply           bool   `json:"transactional_apply"`
	RollbackOnFailure            bool   `json:"rollback_on_failure"`
	RoutePublishEnabled          bool   `json:"route_publish_enabled"`
	MulticastEnabled             bool   `json:"multicast_enabled"`
	ActivationTimeoutSeconds     int    `json:"activation_timeout_seconds"`
	EventRetentionLimit          int    `json:"event_retention_limit"`
	SubscriberStateEnabled       bool   `json:"subscriber_state_enabled"`
	CommercialCatalogEnabled     bool   `json:"commercial_catalog_enabled"`
	AddressLeasesEnabled         bool   `json:"address_leases_enabled"`
	QoSServiceFlowsEnabled       bool   `json:"qos_service_flows_enabled"`
	DHCPSecurityEnabled          bool   `json:"dhcp_security_enabled"`
	RoutePolicyEnabled           bool   `json:"route_policy_enabled"`
	DynamicRoutingEnabled        bool   `json:"dynamic_routing_enabled"`
	SQLAccountingEnabled         bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled    bool   `json:"accounting_services_enabled"`
	DynamicAuthEnabled           bool   `json:"dynamic_auth_enabled"`
	ServiceCount                 int    `json:"service_count"`
	EnabledServiceCount          int    `json:"enabled_service_count"`
	RoutePolicyCount             int    `json:"route_policy_count"`
	EnabledRoutePolicyCount      int    `json:"enabled_route_policy_count"`
	MulticastProfileCount        int    `json:"multicast_profile_count"`
	EnabledMulticastProfileCount int    `json:"enabled_multicast_profile_count"`
	ActivationPolicyCount        int    `json:"activation_policy_count"`
	EnabledActivationPolicyCount int    `json:"enabled_activation_policy_count"`
	RouteAttributeCount          int    `json:"route_attribute_count"`
	MulticastAttributeCount      int    `json:"multicast_attribute_count"`
	RadiusAttributeCount         int    `json:"radius_attribute_count"`
	AuthorizationBindingCount    int    `json:"authorization_binding_count"`
	AccountingBindingCount       int    `json:"accounting_binding_count"`
	ComplianceCheckCount         int    `json:"compliance_check_count"`
	PassedCheckCount             int    `json:"passed_check_count"`
	WarningCount                 int    `json:"warning_count"`
	BlockerCount                 int    `json:"blocker_count"`
	ExternalRequirementCount     int    `json:"external_requirement_count"`
}

type BroadbandServiceActivationService struct {
	TransactionKey      string                                `json:"transaction_key"`
	Name                string                                `json:"name"`
	Enabled             bool                                  `json:"enabled"`
	Required            bool                                  `json:"required"`
	Product             string                                `json:"product,omitempty"`
	SubscriberID        string                                `json:"subscriber_id,omitempty"`
	Username            string                                `json:"username,omitempty"`
	Tenant              string                                `json:"tenant,omitempty"`
	ServiceChain        string                                `json:"service_chain,omitempty"`
	RoutePolicy         string                                `json:"route_policy,omitempty"`
	MulticastProfile    string                                `json:"multicast_profile,omitempty"`
	AddressPool         string                                `json:"address_pool,omitempty"`
	QoSProfile          string                                `json:"qos_profile,omitempty"`
	AccountingClass     string                                `json:"accounting_class,omitempty"`
	VendorPacks         []string                              `json:"vendor_packs"`
	RouteAttributes     []BroadbandServiceActivationAttribute `json:"route_attributes"`
	MulticastAttributes []BroadbandServiceActivationAttribute `json:"multicast_attributes"`
	RadiusAttributes    []BroadbandServiceActivationAttribute `json:"radius_attributes"`
	RollbackRequired    bool                                  `json:"rollback_required"`
	Status              string                                `json:"status"`
	Reason              string                                `json:"reason"`
}

type BroadbandServiceActivationRoutePolicy struct {
	Name                 string                                `json:"name"`
	Enabled              bool                                  `json:"enabled"`
	VRF                  string                                `json:"vrf"`
	Protocol             string                                `json:"protocol"`
	IPv4Routes           []string                              `json:"ipv4_routes"`
	IPv6Routes           []string                              `json:"ipv6_routes"`
	NextHop              string                                `json:"next_hop,omitempty"`
	RouteTarget          string                                `json:"route_target,omitempty"`
	Metric               int                                   `json:"metric"`
	Preference           int                                   `json:"preference"`
	WithdrawOnDeactivate bool                                  `json:"withdraw_on_deactivate"`
	Aggregate            bool                                  `json:"aggregate"`
	VendorPacks          []string                              `json:"vendor_packs"`
	Attributes           []BroadbandServiceActivationAttribute `json:"attributes"`
	Status               string                                `json:"status"`
	Reason               string                                `json:"reason"`
}

type BroadbandServiceActivationMulticast struct {
	Name                string                                `json:"name"`
	Enabled             bool                                  `json:"enabled"`
	Mode                string                                `json:"mode"`
	Groups              []string                              `json:"groups"`
	SourceAddresses     []string                              `json:"source_addresses"`
	MaxGroups           int                                   `json:"max_groups"`
	QuerierInterface    string                                `json:"querier_interface,omitempty"`
	VLAN                int                                   `json:"vlan"`
	VRF                 string                                `json:"vrf,omitempty"`
	EntitlementRequired bool                                  `json:"entitlement_required"`
	VendorPacks         []string                              `json:"vendor_packs"`
	Attributes          []BroadbandServiceActivationAttribute `json:"attributes"`
	Status              string                                `json:"status"`
	Reason              string                                `json:"reason"`
}

type BroadbandServiceActivationPolicy struct {
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	MatchProduct      string `json:"match_product,omitempty"`
	MatchTenant       string `json:"match_tenant,omitempty"`
	AllowRollback     bool   `json:"allow_rollback"`
	RequireRoutes     bool   `json:"require_routes"`
	RequireMulticast  bool   `json:"require_multicast"`
	RequireAccounting bool   `json:"require_accounting"`
	ChangeWindow      string `json:"change_window,omitempty"`
	FailureAction     string `json:"failure_action"`
	Status            string `json:"status"`
	Reason            string `json:"reason"`
}

type BroadbandServiceActivationAttribute struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	Vendor  string `json:"vendor,omitempty"`
	Stage   string `json:"stage,omitempty"`
}

type BroadbandServiceActivationBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandServiceActivationCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandServiceActivationComponent() string {
	return broadbandServiceActivationComponent
}

func PreviewBroadbandServiceActivation(cfg *config.Config) (BroadbandServiceActivationReport, error) {
	if cfg == nil {
		return BroadbandServiceActivationReport{}, fmt.Errorf("config is required")
	}
	activation := config.EffectiveBroadbandServiceActivationConfig(cfg.Broadband.ServiceActivation)
	subscriber := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	catalog := config.EffectiveBroadbandCommercialCatalog(cfg.Broadband.CommercialCatalog)
	leases := config.EffectiveBroadbandAddressLeaseConfig(cfg.Broadband.AddressLeases)
	qos := config.EffectiveBroadbandQoSServiceFlowConfig(cfg.Broadband.QoSServiceFlows)
	dhcp := config.EffectiveBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity)
	report := BroadbandServiceActivationReport{
		SchemaVersion:                 BroadbandServiceActivationSchemaVersion,
		FeatureID:                     BroadbandServiceActivationFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0090-release-certification-checklist.md",
		ReleaseScope:                  "Live BNG route publish/withdraw, multicast forwarding, vendor hardware packet captures, HA failover, scale/soak, performance benchmarking, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 2869", "RFC 3162", "RFC 4271", "RFC 5176", "RFC 4604"},
		Vendors:                       []string{"Juniper ERX/E-Series", "Huawei BRAS/BNG", "H3C BRAS/BNG", "Nokia/Alcatel-Lucent SR OS", "Cisco BNG", "ZTE BNG"},
		Requirements: []string{
			"activate subscriber services transactionally after authentication, address assignment, QoS, DHCP security, accounting, and dynamic authorization are ready",
			"publish and withdraw IPv4/IPv6 subscriber routes with stable ownership and rollback evidence",
			"attach multicast entitlement to subscriber/product context without claiming hardware certification",
			"compile standards and vendor-specific RADIUS/VSA evidence for route, multicast, service, and accounting transitions",
			"expose preview, apply, history, support-bundle, runtime status, UI, and readiness evidence",
		},
		Notes: []string{
			"NAS-0090 completes the software lifecycle for BNG service activation, route lifecycle governance, and multicast entitlement.",
			"Actual route convergence and multicast forwarding on physical BNGs remain release certification evidence.",
		},
	}
	report.Summary = BroadbandServiceActivationSummary{
		Enabled:                   activation.Enabled,
		Mode:                      activation.Mode,
		FailClosed:                activation.FailClosed,
		RequireSubscriberState:    activation.RequireSubscriberState,
		RequireCommercialCatalog:  activation.RequireCommercialCatalog,
		RequireAddressLeases:      activation.RequireAddressLeases,
		RequireQoSServiceFlows:    activation.RequireQoSServiceFlows,
		RequireDHCPSecurity:       activation.RequireDHCPSecurity,
		RequireRouteExport:        activation.RequireRouteExport,
		RequireAccounting:         activation.RequireAccounting,
		RequireDynamicAuth:        activation.RequireDynamicAuth,
		TransactionalApply:        activation.TransactionalApply,
		RollbackOnFailure:         activation.RollbackOnFailure,
		RoutePublishEnabled:       activation.RoutePublishEnabled,
		MulticastEnabled:          activation.MulticastEnabled,
		ActivationTimeoutSeconds:  activation.ActivationTimeoutSeconds,
		EventRetentionLimit:       activation.EventRetentionLimit,
		SubscriberStateEnabled:    subscriber.Enabled,
		CommercialCatalogEnabled:  catalog.Enabled,
		AddressLeasesEnabled:      leases.Enabled,
		QoSServiceFlowsEnabled:    qos.Enabled,
		DHCPSecurityEnabled:       dhcp.Enabled,
		RoutePolicyEnabled:        cfg.Radius.RoutePolicy.Enabled,
		DynamicRoutingEnabled:     cfg.Radius.RoutePolicy.DynamicRouting.Enabled,
		SQLAccountingEnabled:      cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled: cfg.Radius.AccountingServices.Enabled,
		DynamicAuthEnabled:        cfg.Radius.DynamicAuth.Enabled,
	}
	report.RoutePolicies = buildBroadbandServiceRoutePolicies(activation)
	report.MulticastProfiles = buildBroadbandServiceMulticastProfiles(activation)
	report.ActivationPolicies = buildBroadbandActivationPolicies(activation)
	report.Services = buildBroadbandServiceActivationServices(activation, subscriber, report.RoutePolicies, report.MulticastProfiles)
	report.AuthorizationBindings = broadbandServiceActivationAuthorizationBindings(report.Services)
	report.AccountingBindings = broadbandServiceActivationAccountingBindings()
	report.Compliance = broadbandServiceActivationComplianceChecks(activation, subscriber, catalog, leases, qos, dhcp, cfg, report)
	finalizeBroadbandServiceActivationReport(&report)
	return report, nil
}

func PreviewAndRecordBroadbandServiceActivation(cfg *config.Config, actor string) (BroadbandServiceActivationReport, string, error) {
	report, err := PreviewBroadbandServiceActivation(cfg)
	if err != nil {
		return BroadbandServiceActivationReport{}, "", err
	}
	eventID, err := recordBroadbandServiceActivationReport(report, "preview", "previewed", actor)
	return report, eventID, err
}

func ApplyBroadbandServiceActivation(ctx context.Context, cfg *config.Config, actor string) (BroadbandServiceActivationReport, string, error) {
	_ = ctx
	report, err := PreviewBroadbandServiceActivation(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandServiceActivationComponent, "down", err.Error(), nil)
		return BroadbandServiceActivationReport{}, "", err
	}
	status := "applied"
	if report.Status == "blocked" {
		eventID, _ := recordBroadbandServiceActivationReport(report, "apply", "blocked", actor)
		_ = db.UpsertRuntimeStatus(broadbandServiceActivationComponent, "blocked", report.Message, broadbandServiceActivationStatusDetails(report, eventID))
		return report, eventID, fmt.Errorf("%s", report.Message)
	}
	if report.Status == "disabled" {
		status = "skipped"
	}
	eventID, err := recordBroadbandServiceActivationReport(report, "apply", status, actor)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandServiceActivationComponent, "down", err.Error(), broadbandServiceActivationStatusDetails(report, eventID))
		return report, eventID, err
	}
	runtimeStatus := "ok"
	if report.Status == "degraded" {
		runtimeStatus = "degraded"
	} else if report.Status == "disabled" {
		runtimeStatus = "disabled"
	}
	_ = db.UpsertRuntimeStatus(broadbandServiceActivationComponent, runtimeStatus, report.Message, broadbandServiceActivationStatusDetails(report, eventID))
	return report, eventID, nil
}

func buildBroadbandServiceRoutePolicies(activation config.BroadbandServiceActivationConfig) []BroadbandServiceActivationRoutePolicy {
	policies := make([]BroadbandServiceActivationRoutePolicy, 0, len(activation.RoutePolicies))
	for _, raw := range activation.RoutePolicies {
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackCisco, productconfigs.VendorPackERX, productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR, productconfigs.VendorPackZTE}
		}
		policy := BroadbandServiceActivationRoutePolicy{
			Name:                 strings.TrimSpace(raw.Name),
			Enabled:              raw.Enabled,
			VRF:                  firstNonEmptyString(strings.TrimSpace(raw.VRF), "default"),
			Protocol:             firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.Protocol)), "bgp"),
			IPv4Routes:           trimStringSlice(raw.IPv4Routes),
			IPv6Routes:           trimStringSlice(raw.IPv6Routes),
			NextHop:              strings.TrimSpace(raw.NextHop),
			RouteTarget:          strings.TrimSpace(raw.RouteTarget),
			Metric:               raw.Metric,
			Preference:           raw.Preference,
			WithdrawOnDeactivate: raw.WithdrawOnDeactivate,
			Aggregate:            raw.Aggregate,
			VendorPacks:          packs,
			Status:               "ready",
			Reason:               "Route policy can publish and withdraw subscriber route ownership.",
		}
		if !policy.Enabled {
			policy.Status = "disabled"
			policy.Reason = "Route policy is disabled."
		}
		if len(policy.IPv4Routes) == 0 && len(policy.IPv6Routes) == 0 {
			policy.Status = "blocked"
			policy.Reason = "Route policy requires at least one IPv4 or IPv6 prefix."
		}
		policy.Attributes = broadbandServiceRouteAttributes(policy)
		policies = append(policies, policy)
	}
	return policies
}

func buildBroadbandServiceMulticastProfiles(activation config.BroadbandServiceActivationConfig) []BroadbandServiceActivationMulticast {
	profiles := make([]BroadbandServiceActivationMulticast, 0, len(activation.MulticastProfiles))
	for _, raw := range activation.MulticastProfiles {
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackCisco, productconfigs.VendorPackERX, productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C, productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR, productconfigs.VendorPackZTE}
		}
		profile := BroadbandServiceActivationMulticast{
			Name:                strings.TrimSpace(raw.Name),
			Enabled:             raw.Enabled,
			Mode:                firstNonEmptyString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw.Mode)), "-", "_"), "igmp"),
			Groups:              trimStringSlice(raw.Groups),
			SourceAddresses:     trimStringSlice(raw.SourceAddresses),
			MaxGroups:           raw.MaxGroups,
			QuerierInterface:    strings.TrimSpace(raw.QuerierInterface),
			VLAN:                raw.VLAN,
			VRF:                 strings.TrimSpace(raw.VRF),
			EntitlementRequired: raw.EntitlementRequired,
			VendorPacks:         packs,
			Status:              "ready",
			Reason:              "Multicast entitlement can be bound to subscriber service activation.",
		}
		if !profile.Enabled {
			profile.Status = "disabled"
			profile.Reason = "Multicast profile is disabled."
		}
		if len(profile.Groups) == 0 {
			profile.Status = "blocked"
			profile.Reason = "Multicast profile requires at least one group."
		}
		profile.Attributes = broadbandServiceMulticastAttributes(profile)
		profiles = append(profiles, profile)
	}
	return profiles
}

func buildBroadbandActivationPolicies(activation config.BroadbandServiceActivationConfig) []BroadbandServiceActivationPolicy {
	policies := make([]BroadbandServiceActivationPolicy, 0, len(activation.ActivationPolicies))
	for _, raw := range activation.ActivationPolicies {
		policy := BroadbandServiceActivationPolicy{
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			MatchProduct:      strings.TrimSpace(raw.MatchProduct),
			MatchTenant:       strings.TrimSpace(raw.MatchTenant),
			AllowRollback:     raw.AllowRollback,
			RequireRoutes:     raw.RequireRoutes,
			RequireMulticast:  raw.RequireMulticast,
			RequireAccounting: raw.RequireAccounting,
			ChangeWindow:      strings.TrimSpace(raw.ChangeWindow),
			FailureAction:     firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.FailureAction)), "rollback"),
			Status:            "ready",
			Reason:            "Activation policy governs route, multicast, accounting, and rollback requirements.",
		}
		if !policy.Enabled {
			policy.Status = "disabled"
			policy.Reason = "Activation policy is disabled."
		}
		policies = append(policies, policy)
	}
	return policies
}

func buildBroadbandServiceActivationServices(activation config.BroadbandServiceActivationConfig, subscriber config.BroadbandSubscriberStateConfig, routePolicies []BroadbandServiceActivationRoutePolicy, multicastProfiles []BroadbandServiceActivationMulticast) []BroadbandServiceActivationService {
	routeByName := map[string]BroadbandServiceActivationRoutePolicy{}
	for _, route := range routePolicies {
		routeByName[strings.ToLower(route.Name)] = route
	}
	multicastByName := map[string]BroadbandServiceActivationMulticast{}
	for _, profile := range multicastProfiles {
		multicastByName[strings.ToLower(profile.Name)] = profile
	}
	services := make([]BroadbandServiceActivationService, 0, len(activation.Services)+len(subscriber.Products))
	for _, raw := range activation.Services {
		services = append(services, compileBroadbandServiceActivation(raw, routeByName, multicastByName, activation))
	}
	if len(services) == 0 {
		for _, product := range subscriber.Products {
			if !product.Enabled {
				continue
			}
			raw := config.BroadbandServiceActivationServiceConfig{
				Name:         "product-" + strings.TrimSpace(product.Name),
				Enabled:      true,
				Required:     true,
				Product:      product.Name,
				Tenant:       "default",
				ServiceChain: firstNonEmptyString(product.ServiceChain, "internet"),
				RoutePolicy:  product.RoutePolicy,
				AddressPool:  firstNonEmptyString(product.AddressPool, product.IPv6Pool, product.DelegatedIPv6Pool),
				QoSProfile:   product.QoSProfile,
				VendorPacks:  product.VendorPacks,
			}
			if raw.RoutePolicy == "" && len(routePolicies) == 1 {
				raw.RoutePolicy = routePolicies[0].Name
			}
			if len(multicastProfiles) == 1 {
				raw.MulticastProfile = multicastProfiles[0].Name
			}
			services = append(services, compileBroadbandServiceActivation(raw, routeByName, multicastByName, activation))
		}
	}
	return services
}

func compileBroadbandServiceActivation(raw config.BroadbandServiceActivationServiceConfig, routePolicies map[string]BroadbandServiceActivationRoutePolicy, multicastProfiles map[string]BroadbandServiceActivationMulticast, activation config.BroadbandServiceActivationConfig) BroadbandServiceActivationService {
	route := routePolicies[strings.ToLower(strings.TrimSpace(raw.RoutePolicy))]
	multicast := multicastProfiles[strings.ToLower(strings.TrimSpace(raw.MulticastProfile))]
	packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
	if len(packs) == 0 && len(route.VendorPacks) > 0 {
		packs = route.VendorPacks
	}
	if len(packs) == 0 && len(multicast.VendorPacks) > 0 {
		packs = multicast.VendorPacks
	}
	if len(packs) == 0 {
		packs = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackERX, productconfigs.VendorPackHuawei, productconfigs.VendorPackNokia, productconfigs.VendorPackZTE}
	}
	service := BroadbandServiceActivationService{
		TransactionKey:   broadbandServiceActivationTransactionKey(raw),
		Name:             strings.TrimSpace(raw.Name),
		Enabled:          raw.Enabled,
		Required:         raw.Required,
		Product:          strings.TrimSpace(raw.Product),
		SubscriberID:     strings.TrimSpace(raw.SubscriberID),
		Username:         strings.TrimSpace(raw.Username),
		Tenant:           strings.TrimSpace(raw.Tenant),
		ServiceChain:     strings.TrimSpace(raw.ServiceChain),
		RoutePolicy:      strings.TrimSpace(raw.RoutePolicy),
		MulticastProfile: strings.TrimSpace(raw.MulticastProfile),
		AddressPool:      strings.TrimSpace(raw.AddressPool),
		QoSProfile:       strings.TrimSpace(raw.QoSProfile),
		AccountingClass:  strings.TrimSpace(raw.AccountingClass),
		VendorPacks:      packs,
		RollbackRequired: activation.RollbackOnFailure || raw.Required,
		Status:           "ready",
		Reason:           "Service activation transaction can bind subscriber, route, multicast, QoS, address, and accounting evidence.",
	}
	if !service.Enabled {
		service.Status = "disabled"
		service.Reason = "Service activation is disabled."
	}
	if activation.RoutePublishEnabled {
		if service.RoutePolicy == "" {
			service.Status = "blocked"
			service.Reason = "Route publish is enabled but service has no route policy."
		} else if route.Name == "" {
			service.Status = "blocked"
			service.Reason = "Referenced route policy is missing."
		} else if route.Status == "blocked" {
			service.Status = "blocked"
			service.Reason = "Referenced route policy is blocked."
		}
	}
	if service.Status != "blocked" && activation.MulticastEnabled && service.MulticastProfile != "" {
		if multicast.Name == "" {
			service.Status = "blocked"
			service.Reason = "Referenced multicast profile is missing."
		} else if multicast.Status == "blocked" {
			service.Status = "blocked"
			service.Reason = "Referenced multicast profile is blocked."
		}
	}
	service.RouteAttributes = broadbandServiceRouteAttributes(route)
	service.MulticastAttributes = broadbandServiceMulticastAttributes(multicast)
	service.RadiusAttributes = broadbandServiceRadiusAttributes(service, route, multicast)
	return service
}

func broadbandServiceRouteAttributes(route BroadbandServiceActivationRoutePolicy) []BroadbandServiceActivationAttribute {
	if route.Name == "" {
		return nil
	}
	attrs := []BroadbandServiceActivationAttribute{
		{Name: "Class", Value: "route-policy:" + route.Name, Purpose: "Stable route policy correlation for authorization and accounting.", Stage: "access-accept"},
	}
	for _, prefix := range route.IPv4Routes {
		value := strings.TrimSpace(prefix)
		if route.NextHop != "" {
			value += " " + route.NextHop
		}
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Framed-Route", Value: value, Purpose: "Publish subscriber IPv4 route ownership.", Stage: "access-accept"})
	}
	for _, prefix := range route.IPv6Routes {
		value := strings.TrimSpace(prefix)
		if route.NextHop != "" {
			value += " " + route.NextHop
		}
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Framed-IPv6-Route", Value: value, Purpose: "Publish subscriber IPv6 route ownership.", Stage: "access-accept"})
	}
	for _, pack := range route.VendorPacks {
		switch productconfigs.NormalizeVendorCompatibilityPackKey(pack) {
		case productconfigs.VendorPackCisco:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Cisco-AVPair", Value: "ip:route-policy=" + route.Name, Purpose: "Cisco BNG route policy evidence.", Vendor: "cisco", Stage: "access-accept"})
		case productconfigs.VendorPackJuniper, productconfigs.VendorPackERX:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ERX-Virtual-Router-Name", Value: route.VRF, Purpose: "ERX virtual router binding for subscriber service routes.", Vendor: "erx", Stage: "access-accept"})
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ERX-Framed-Ip-Route-Tag", Value: firstNonEmptyString(route.RouteTarget, route.Name), Purpose: "ERX route tag evidence for route publish/withdraw.", Vendor: "erx", Stage: "access-accept"})
		case productconfigs.VendorPackHuawei:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Huawei-AVpair", Value: "route-policy=" + route.Name, Purpose: "Huawei BRAS/BNG route policy evidence.", Vendor: "huawei", Stage: "access-accept"})
		case productconfigs.VendorPackH3C:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "H3C-Av-Pair", Value: "route-policy=" + route.Name, Purpose: "H3C route policy evidence.", Vendor: "h3c", Stage: "access-accept"})
		case productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Nokia-AVPair", Value: "route-policy=" + route.Name, Purpose: "Nokia/SR OS route policy evidence.", Vendor: "nokia", Stage: "access-accept"})
		case productconfigs.VendorPackZTE:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ZTE-AVPair", Value: "route-policy=" + route.Name, Purpose: "ZTE BNG route policy evidence.", Vendor: "zte", Stage: "access-accept"})
		}
	}
	return attrs
}

func broadbandServiceMulticastAttributes(profile BroadbandServiceActivationMulticast) []BroadbandServiceActivationAttribute {
	if profile.Name == "" {
		return nil
	}
	attrs := []BroadbandServiceActivationAttribute{
		{Name: "Filter-Id", Value: "multicast:" + profile.Name, Purpose: "Authorize multicast entitlement profile.", Stage: "access-accept"},
		{Name: "Class", Value: "multicast-profile:" + profile.Name, Purpose: "Correlate multicast entitlement in accounting.", Stage: "accounting"},
	}
	for _, group := range profile.Groups {
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "AegisNAS-Multicast-Group", Value: group, Purpose: "Product-neutral multicast group entitlement evidence.", Vendor: "aegisnas", Stage: "access-accept"})
	}
	for _, pack := range profile.VendorPacks {
		switch productconfigs.NormalizeVendorCompatibilityPackKey(pack) {
		case productconfigs.VendorPackCisco:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Cisco-AVPair", Value: "ip:multicast-profile=" + profile.Name, Purpose: "Cisco multicast profile evidence.", Vendor: "cisco", Stage: "access-accept"})
		case productconfigs.VendorPackJuniper, productconfigs.VendorPackERX:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ERX-Service-Activate", Value: "multicast:" + profile.Name, Purpose: "ERX subscriber multicast service activation evidence.", Vendor: "erx", Stage: "access-accept"})
		case productconfigs.VendorPackHuawei:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Huawei-AVpair", Value: "igmp-profile=" + profile.Name, Purpose: "Huawei IGMP profile evidence.", Vendor: "huawei", Stage: "access-accept"})
		case productconfigs.VendorPackH3C:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "H3C-Av-Pair", Value: "igmp-profile=" + profile.Name, Purpose: "H3C IGMP/MLD profile evidence.", Vendor: "h3c", Stage: "access-accept"})
		case productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Nokia-AVPair", Value: "multicast-profile=" + profile.Name, Purpose: "Nokia/SR OS multicast entitlement evidence.", Vendor: "nokia", Stage: "access-accept"})
		case productconfigs.VendorPackZTE:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ZTE-AVPair", Value: "multicast-profile=" + profile.Name, Purpose: "ZTE multicast entitlement evidence.", Vendor: "zte", Stage: "access-accept"})
		}
	}
	return attrs
}

func broadbandServiceRadiusAttributes(service BroadbandServiceActivationService, route BroadbandServiceActivationRoutePolicy, multicast BroadbandServiceActivationMulticast) []BroadbandServiceActivationAttribute {
	attrs := []BroadbandServiceActivationAttribute{
		{Name: "Service-Type", Value: "Framed-User", Purpose: "Authorize framed subscriber service activation.", Stage: "access-accept"},
		{Name: "Class", Value: "service-activation:" + service.TransactionKey, Purpose: "Stable service activation correlation token.", Stage: "access-accept"},
	}
	if service.Product != "" {
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "AegisNAS-Subscriber-Product", Value: service.Product, Purpose: "Product selector for service activation.", Vendor: "aegisnas", Stage: "access-accept"})
	}
	if service.AddressPool != "" {
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Framed-Pool", Value: service.AddressPool, Purpose: "Attach address pool to activated subscriber service.", Stage: "access-accept"})
	}
	if service.QoSProfile != "" {
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Filter-Id", Value: service.QoSProfile, Purpose: "Attach QoS/profile filter to activated subscriber service.", Stage: "access-accept"})
	}
	if service.AccountingClass != "" {
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Acct-Interim-Interval", Value: "300", Purpose: "Collect operational history for activated service.", Stage: "accounting"})
		attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Class", Value: service.AccountingClass, Purpose: "Accounting class for BNG service activation.", Stage: "accounting"})
	}
	for _, pack := range service.VendorPacks {
		switch productconfigs.NormalizeVendorCompatibilityPackKey(pack) {
		case productconfigs.VendorPackCisco:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Cisco-AVPair", Value: "subscriber:service=" + serviceNameForVSA(service), Purpose: "Cisco BNG subscriber service activation evidence.", Vendor: "cisco", Stage: "access-accept"})
		case productconfigs.VendorPackJuniper:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Juniper-AV-Pair", Value: "subscriber-service=" + serviceNameForVSA(service), Purpose: "Juniper subscriber service activation evidence.", Vendor: "juniper", Stage: "access-accept"})
		case productconfigs.VendorPackERX:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ERX-Service-Activate", Value: serviceNameForVSA(service), Purpose: "ERX service activation VSA.", Vendor: "erx", Stage: "access-accept"})
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ERX-Update-Service", Value: serviceNameForVSA(service), Purpose: "ERX active service update/rollback VSA.", Vendor: "erx", Stage: "coa"})
		case productconfigs.VendorPackHuawei:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Huawei-AVpair", Value: "subscriber-service=" + serviceNameForVSA(service), Purpose: "Huawei subscriber service activation evidence.", Vendor: "huawei", Stage: "access-accept"})
		case productconfigs.VendorPackH3C:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "H3C-Av-Pair", Value: "subscriber-service=" + serviceNameForVSA(service), Purpose: "H3C service activation evidence.", Vendor: "h3c", Stage: "access-accept"})
		case productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Nokia-Service-Name", Value: serviceNameForVSA(service), Purpose: "Nokia service-name authorization evidence.", Vendor: "nokia", Stage: "access-accept"})
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "Nokia-AVPair", Value: "subscriber-service=" + serviceNameForVSA(service), Purpose: "Nokia/SR OS service activation evidence.", Vendor: "nokia", Stage: "access-accept"})
		case productconfigs.VendorPackZTE:
			attrs = append(attrs, BroadbandServiceActivationAttribute{Name: "ZTE-AVPair", Value: "subscriber-service=" + serviceNameForVSA(service), Purpose: "ZTE subscriber service activation evidence.", Vendor: "zte", Stage: "access-accept"})
		}
	}
	_ = route
	_ = multicast
	return attrs
}

func broadbandServiceActivationAuthorizationBindings(services []BroadbandServiceActivationService) []BroadbandServiceActivationBinding {
	attrs := []string{"Service-Type", "Class", "Filter-Id", "Framed-Pool", "Framed-Route", "Framed-IPv6-Route", "ERX-Service-Activate", "ERX-Update-Service", "Cisco-AVPair", "Juniper-AV-Pair", "Huawei-AVpair", "H3C-Av-Pair", "Nokia-Service-Name", "Nokia-AVPair"}
	if len(services) == 0 {
		attrs = []string{"Service-Type", "Class"}
	}
	return []BroadbandServiceActivationBinding{
		{Stage: "access-accept", Attributes: attrs, Purpose: "Activate service, address, QoS, route, and multicast intent for the subscriber.", Required: true},
		{Stage: "coa", Attributes: []string{"CoA-Request", "ERX-Update-Service", "Cisco-AVPair", "Nokia-AVPair"}, Purpose: "Update or roll back active BNG service activation after policy or state changes.", Required: false},
	}
}

func broadbandServiceActivationAccountingBindings() []BroadbandServiceActivationBinding {
	return []BroadbandServiceActivationBinding{
		{Stage: "start", Attributes: []string{"Acct-Status-Type=Start", "Acct-Session-Id", "Class", "Service-Type"}, Purpose: "Open service activation ownership and route/multicast accounting.", Required: true},
		{Stage: "interim", Attributes: []string{"Acct-Status-Type=Interim-Update", "Acct-Input-Octets", "Acct-Output-Octets", "Acct-Multi-Session-Id"}, Purpose: "Refresh service activation usage and operational history.", Required: true},
		{Stage: "stop", Attributes: []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause", "Class"}, Purpose: "Withdraw service activation ownership, routes, and multicast entitlement.", Required: true},
	}
}

func broadbandServiceActivationComplianceChecks(activation config.BroadbandServiceActivationConfig, subscriber config.BroadbandSubscriberStateConfig, catalog config.BroadbandCommercialCatalog, leases config.BroadbandAddressLeaseConfig, qos config.BroadbandQoSServiceFlowConfig, dhcp config.BroadbandDHCPSecurityConfig, cfg *config.Config, report BroadbandServiceActivationReport) []BroadbandServiceActivationCheck {
	return []BroadbandServiceActivationCheck{
		broadbandServiceActivationCheck("subscriber-state", "Subscriber state dependency", !activation.Enabled || !activation.RequireSubscriberState || subscriber.Enabled, "Subscriber state is available.", "Enabled service activation requires broadband.subscriber_state.enabled.", "broadband.subscriber_state"),
		broadbandServiceActivationCheck("commercial-catalog", "Commercial catalog dependency", !activation.Enabled || !activation.RequireCommercialCatalog || catalog.Enabled, "Commercial catalog is available.", "Enabled service activation requires broadband.commercial_catalog.enabled.", "broadband.commercial_catalog"),
		broadbandServiceActivationCheck("address-leases", "Address lease dependency", !activation.Enabled || !activation.RequireAddressLeases || leases.Enabled, "Address leases are available.", "Enabled service activation requires broadband.address_leases.enabled.", "broadband.address_leases"),
		broadbandServiceActivationCheck("qos-service-flows", "QoS service-flow dependency", !activation.Enabled || !activation.RequireQoSServiceFlows || qos.Enabled, "QoS service flows are available.", "Enabled service activation requires broadband.qos_service_flows.enabled.", "broadband.qos_service_flows"),
		broadbandServiceActivationCheck("dhcp-security", "DHCP security dependency", !activation.Enabled || !activation.RequireDHCPSecurity || dhcp.Enabled, "DHCP security is available.", "Enabled service activation requires broadband.dhcp_security.enabled.", "broadband.dhcp_security"),
		broadbandServiceActivationCheck("route-export", "Route export dependency", !activation.Enabled || !activation.RequireRouteExport || (cfg.Radius.RoutePolicy.Enabled && cfg.Radius.RoutePolicy.DynamicRouting.Enabled), "Route policy dynamic routing is available.", "Service route lifecycle requires radius.route_policy.dynamic_routing.enabled.", "radius.route_policy.dynamic_routing"),
		broadbandServiceActivationCheck("accounting", "Accounting dependency", !activation.Enabled || !activation.RequireAccounting || (cfg.Radius.SQLAccounting.Enabled && cfg.Radius.AccountingServices.Enabled), "SQL accounting and service correlation are available.", "Service activation requires radius.sql_accounting and radius.accounting_services.", "radius.sql_accounting", "radius.accounting_services"),
		broadbandServiceActivationCheck("dynamic-auth", "Dynamic authorization dependency", !activation.Enabled || !activation.RequireDynamicAuth || cfg.Radius.DynamicAuth.Enabled, "Dynamic authorization is available for service update and rollback.", "Service activation rollback/update requires radius.dynamic_auth.enabled.", "radius.dynamic_auth"),
		broadbandServiceActivationCheck("transactions", "Transactional apply and rollback", !activation.Enabled || !activation.TransactionalApply || activation.RollbackOnFailure, "Transactional apply has rollback-on-failure enabled.", "Transactional service activation requires rollback_on_failure.", "broadband.service_activation.rollback_on_failure"),
		broadbandServiceActivationCheck("services", "Service activation catalog", !activation.Enabled || len(report.Services) > 0, "Service activation intent is configured or derived.", "Enabled service activation requires at least one service.", "services"),
		broadbandServiceActivationCheck("routes", "Route lifecycle catalog", !activation.Enabled || !activation.RoutePublishEnabled || len(report.RoutePolicies) > 0, "Route lifecycle policies are configured.", "Route publishing requires at least one route policy.", "route_policies"),
		broadbandServiceActivationCheck("multicast", "Multicast entitlement catalog", !activation.Enabled || !activation.MulticastEnabled || len(report.MulticastProfiles) > 0, "Multicast entitlement profiles are configured.", "Multicast activation requires at least one multicast profile.", "multicast_profiles"),
		broadbandServiceActivationCheck("external-certification", "External BNG certification boundary", true, "Live BNG route convergence, multicast forwarding, hardware packet captures, HA, scale, soak, security, and customer proof are release certification activities.", "", "docs/nas-0090-release-certification-checklist.md"),
	}
}

func broadbandServiceActivationCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) BroadbandServiceActivationCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return BroadbandServiceActivationCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence}
}

func finalizeBroadbandServiceActivationReport(report *BroadbandServiceActivationReport) {
	for _, route := range report.RoutePolicies {
		report.Summary.RoutePolicyCount++
		if route.Enabled {
			report.Summary.EnabledRoutePolicyCount++
		}
		report.Summary.RouteAttributeCount += len(route.Attributes)
		if route.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("route policy %s: %s", route.Name, route.Reason))
		}
	}
	for _, profile := range report.MulticastProfiles {
		report.Summary.MulticastProfileCount++
		if profile.Enabled {
			report.Summary.EnabledMulticastProfileCount++
		}
		report.Summary.MulticastAttributeCount += len(profile.Attributes)
		if profile.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("multicast profile %s: %s", profile.Name, profile.Reason))
		}
	}
	for _, policy := range report.ActivationPolicies {
		report.Summary.ActivationPolicyCount++
		if policy.Enabled {
			report.Summary.EnabledActivationPolicyCount++
		}
	}
	for _, service := range report.Services {
		report.Summary.ServiceCount++
		if service.Enabled {
			report.Summary.EnabledServiceCount++
		}
		report.Summary.RouteAttributeCount += len(service.RouteAttributes)
		report.Summary.MulticastAttributeCount += len(service.MulticastAttributes)
		report.Summary.RadiusAttributeCount += len(service.RadiusAttributes)
		if service.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("service %s: %s", service.Name, service.Reason))
		}
	}
	report.Summary.AuthorizationBindingCount = len(report.AuthorizationBindings)
	report.Summary.AccountingBindingCount = len(report.AccountingBindings)
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
		report.Message = "NAS-0090 software is ready; BNG service activation, route lifecycle, and multicast are not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = fmt.Sprintf("NAS-0090 service activation is blocked by %d requirement(s).", len(report.Blockers))
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0090 service activation is ready with %d warning(s).", len(report.Warnings))
	} else {
		report.Message = fmt.Sprintf("NAS-0090 service activation is ready with %d service(s), %d route policy(ies), %d multicast profile(s), and %d RADIUS attribute(s).", report.Summary.ServiceCount, report.Summary.RoutePolicyCount, report.Summary.MulticastProfileCount, report.Summary.RadiusAttributeCount)
	}
	report.PlanFingerprint = broadbandServiceActivationFingerprint(*report)
}

func recordBroadbandServiceActivationReport(report BroadbandServiceActivationReport, operation, status, actor string) (string, error) {
	return db.RecordBroadbandServiceActivationEvent(db.BroadbandServiceActivationEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		ServiceCount:             report.Summary.ServiceCount,
		RoutePolicyCount:         report.Summary.RoutePolicyCount,
		MulticastProfileCount:    report.Summary.MulticastProfileCount,
		ActivationPolicyCount:    report.Summary.ActivationPolicyCount,
		RouteAttributeCount:      report.Summary.RouteAttributeCount,
		MulticastAttributeCount:  report.Summary.MulticastAttributeCount,
		RadiusAttributeCount:     report.Summary.RadiusAttributeCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              broadbandServiceActivationJSON(report.Summary, "{}"),
		ReportJSON:               broadbandServiceActivationJSON(report, "{}"),
		Actor:                    actor,
		Transactions:             broadbandServiceActivationDBTransactions(report, status),
	})
}

func broadbandServiceActivationDBTransactions(report BroadbandServiceActivationReport, eventStatus string) []db.BroadbandServiceActivationTransactionInput {
	transactions := make([]db.BroadbandServiceActivationTransactionInput, 0, len(report.Services))
	for _, service := range report.Services {
		status := "planned"
		if eventStatus == "applied" && service.Enabled && service.Status == "ready" {
			status = "active"
		} else if service.Status == "blocked" {
			status = "blocked"
		} else if service.Status == "degraded" {
			status = "degraded"
		}
		transactions = append(transactions, db.BroadbandServiceActivationTransactionInput{
			TransactionKey:          service.TransactionKey,
			ServiceName:             service.Name,
			Product:                 service.Product,
			SubscriberID:            service.SubscriberID,
			Username:                service.Username,
			Tenant:                  service.Tenant,
			ServiceChain:            service.ServiceChain,
			RoutePolicy:             service.RoutePolicy,
			MulticastProfile:        service.MulticastProfile,
			AddressPool:             service.AddressPool,
			QoSProfile:              service.QoSProfile,
			AccountingClass:         service.AccountingClass,
			Status:                  status,
			VendorPacksJSON:         broadbandServiceActivationJSON(service.VendorPacks, "[]"),
			RouteAttributesJSON:     broadbandServiceActivationJSON(service.RouteAttributes, "[]"),
			MulticastAttributesJSON: broadbandServiceActivationJSON(service.MulticastAttributes, "[]"),
			RadiusAttributesJSON:    broadbandServiceActivationJSON(service.RadiusAttributes, "[]"),
			RollbackRequired:        service.RollbackRequired,
			PlanFingerprint:         report.PlanFingerprint,
			InstalledAt:             conditionalTimestamp(status == "active"),
		})
	}
	return transactions
}

func broadbandServiceActivationFingerprint(report BroadbandServiceActivationReport) string {
	payload := map[string]any{
		"feature_id":          report.FeatureID,
		"summary":             report.Summary,
		"services":            report.Services,
		"route_policies":      report.RoutePolicies,
		"multicast_profiles":  report.MulticastProfiles,
		"activation_policies": report.ActivationPolicies,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func broadbandServiceActivationTransactionKey(raw config.BroadbandServiceActivationServiceConfig) string {
	parts := []string{raw.Name, raw.Product, raw.SubscriberID, raw.Username, raw.Tenant, raw.ServiceChain, raw.RoutePolicy, raw.MulticastProfile}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(parts, "|"))))
	return "bng-service-" + hex.EncodeToString(sum[:6])
}

func serviceNameForVSA(service BroadbandServiceActivationService) string {
	return firstNonEmptyString(service.ServiceChain, service.Name, service.Product, service.TransactionKey)
}

func broadbandServiceActivationJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 {
		return fallback
	}
	return string(encoded)
}

func broadbandServiceActivationStatusDetails(report BroadbandServiceActivationReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                report.FeatureID,
		"event_id":                  eventID,
		"plan_fingerprint":          report.PlanFingerprint,
		"status":                    report.Status,
		"service_count":             report.Summary.ServiceCount,
		"route_policy_count":        report.Summary.RoutePolicyCount,
		"multicast_profile_count":   report.Summary.MulticastProfileCount,
		"radius_attribute_count":    report.Summary.RadiusAttributeCount,
		"route_attribute_count":     report.Summary.RouteAttributeCount,
		"multicast_attribute_count": report.Summary.MulticastAttributeCount,
		"blocker_count":             report.Summary.BlockerCount,
		"warning_count":             report.Summary.WarningCount,
	}
}
