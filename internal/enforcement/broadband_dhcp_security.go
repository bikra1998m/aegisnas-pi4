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
	BroadbandDHCPSecuritySchemaVersion = 1
	BroadbandDHCPSecurityFeatureID     = "NAS-0089"
	broadbandDHCPSecurityComponent     = "broadband_dhcp_security"
)

type BroadbandDHCPSecurityReport struct {
	SchemaVersion                 int                              `json:"schema_version"`
	FeatureID                     string                           `json:"feature_id"`
	Status                        string                           `json:"status"`
	Message                       string                           `json:"message"`
	GeneratedAt                   string                           `json:"generated_at"`
	SoftwareCompletionPercent     float64                          `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                             `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                           `json:"release_certification_checklist"`
	ReleaseScope                  string                           `json:"release_scope"`
	PlanFingerprint               string                           `json:"plan_fingerprint"`
	Summary                       BroadbandDHCPSecuritySummary     `json:"summary"`
	RelayAgents                   []BroadbandDHCPRelayAgent        `json:"relay_agents"`
	Ports                         []BroadbandDHCPSecurityPort      `json:"ports"`
	Option82Rules                 []BroadbandDHCPOption82Rule      `json:"option82_rules"`
	SourceGuardPolicies           []BroadbandDHCPSourceGuardPolicy `json:"source_guard_policies"`
	RADIUSCorrelation             []BroadbandDHCPRADIUSCorrelation `json:"radius_correlation"`
	Compliance                    []BroadbandDHCPSecurityCheck     `json:"compliance"`
	Standards                     []string                         `json:"standards"`
	Vendors                       []string                         `json:"vendors"`
	Requirements                  []string                         `json:"requirements"`
	Blockers                      []string                         `json:"blockers,omitempty"`
	Warnings                      []string                         `json:"warnings,omitempty"`
	Notes                         []string                         `json:"notes,omitempty"`
}

type BroadbandDHCPSecuritySummary struct {
	Enabled                    bool   `json:"enabled"`
	Mode                       string `json:"mode"`
	FailClosed                 bool   `json:"fail_closed"`
	RequireDHCP                bool   `json:"require_dhcp"`
	RequireSubscriberState     bool   `json:"require_subscriber_state"`
	RequireAddressLeases       bool   `json:"require_address_leases"`
	RequireAccounting          bool   `json:"require_accounting"`
	RequireDynamicAuth         bool   `json:"require_dynamic_auth"`
	RelayEnabled               bool   `json:"relay_enabled"`
	SnoopingEnabled            bool   `json:"snooping_enabled"`
	SourceGuardEnabled         bool   `json:"source_guard_enabled"`
	Option82Required           bool   `json:"option82_required"`
	DropUnknownBindings        bool   `json:"drop_unknown_bindings"`
	TrustedUplinkRequired      bool   `json:"trusted_uplink_required"`
	Option82Policy             string `json:"option82_policy"`
	BindingRetentionSeconds    int    `json:"binding_retention_seconds"`
	ViolationHoldDownSeconds   int    `json:"violation_hold_down_seconds"`
	EventRetentionLimit        int    `json:"event_retention_limit"`
	DHCPEnabled                bool   `json:"dhcp_enabled"`
	SubscriberStateEnabled     bool   `json:"subscriber_state_enabled"`
	AddressLeasesEnabled       bool   `json:"address_leases_enabled"`
	SQLAccountingEnabled       bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled  bool   `json:"accounting_services_enabled"`
	DynamicAuthEnabled         bool   `json:"dynamic_auth_enabled"`
	RelayAgentCount            int    `json:"relay_agent_count"`
	EnabledRelayAgentCount     int    `json:"enabled_relay_agent_count"`
	PortCount                  int    `json:"port_count"`
	EnabledPortCount           int    `json:"enabled_port_count"`
	TrustedPortCount           int    `json:"trusted_port_count"`
	Option82RuleCount          int    `json:"option82_rule_count"`
	EnabledOption82RuleCount   int    `json:"enabled_option82_rule_count"`
	SourceGuardPolicyCount     int    `json:"source_guard_policy_count"`
	EnabledSourceGuardPolicies int    `json:"enabled_source_guard_policy_count"`
	RADIUSCorrelationCount     int    `json:"radius_correlation_count"`
	CompiledOptionCount        int    `json:"compiled_option_count"`
	ComplianceCheckCount       int    `json:"compliance_check_count"`
	PassedCheckCount           int    `json:"passed_check_count"`
	WarningCount               int    `json:"warning_count"`
	BlockerCount               int    `json:"blocker_count"`
	ExternalRequirementCount   int    `json:"external_requirement_count"`
}

type BroadbandDHCPRelayAgent struct {
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Interface         string   `json:"interface"`
	VLAN              int      `json:"vlan"`
	GatewayAddress    string   `json:"gateway_address,omitempty"`
	ServerGroup       string   `json:"server_group,omitempty"`
	VRF               string   `json:"vrf,omitempty"`
	CircuitIDTemplate string   `json:"circuit_id_template,omitempty"`
	RemoteIDTemplate  string   `json:"remote_id_template,omitempty"`
	AppendOption82    bool     `json:"append_option82"`
	ReplaceOption82   bool     `json:"replace_option82"`
	Trusted           bool     `json:"trusted"`
	MaxClients        int      `json:"max_clients"`
	VendorPacks       []string `json:"vendor_packs"`
	Status            string   `json:"status"`
	Reason            string   `json:"reason"`
}

type BroadbandDHCPSecurityPort struct {
	BindingKey        string                `json:"binding_key"`
	Name              string                `json:"name"`
	Enabled           bool                  `json:"enabled"`
	Interface         string                `json:"interface"`
	VLAN              int                   `json:"vlan"`
	Role              string                `json:"role"`
	Trusted           bool                  `json:"trusted"`
	CircuitID         string                `json:"circuit_id,omitempty"`
	RemoteID          string                `json:"remote_id,omitempty"`
	SubscriberProduct string                `json:"subscriber_product,omitempty"`
	Tenant            string                `json:"tenant,omitempty"`
	MaxLeases         int                   `json:"max_leases"`
	RelayAgent        string                `json:"relay_agent,omitempty"`
	SourceGuardPolicy string                `json:"source_guard_policy,omitempty"`
	VendorPacks       []string              `json:"vendor_packs"`
	CompiledOptions   []BroadbandDHCPOption `json:"compiled_options"`
	Status            string                `json:"status"`
	Reason            string                `json:"reason"`
}

type BroadbandDHCPOption82Rule struct {
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	MatchInterface    string   `json:"match_interface,omitempty"`
	MatchVLAN         int      `json:"match_vlan"`
	CircuitIDTemplate string   `json:"circuit_id_template,omitempty"`
	RemoteIDTemplate  string   `json:"remote_id_template,omitempty"`
	Action            string   `json:"action"`
	RequireRemoteID   bool     `json:"require_remote_id"`
	VendorPacks       []string `json:"vendor_packs"`
	Status            string   `json:"status"`
	Reason            string   `json:"reason"`
}

type BroadbandDHCPSourceGuardPolicy struct {
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Mode              string   `json:"mode"`
	Interfaces        []string `json:"interfaces"`
	VLANs             []int    `json:"vlans"`
	AllowUnknown      bool     `json:"allow_unknown"`
	MaxBindings       int      `json:"max_bindings"`
	IPv6Enabled       bool     `json:"ipv6_enabled"`
	ActionOnViolation string   `json:"action_on_violation"`
	CoAAction         string   `json:"coa_action"`
	Status            string   `json:"status"`
	Reason            string   `json:"reason"`
}

type BroadbandDHCPRADIUSCorrelation struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	Source           string   `json:"source"`
	Attributes       []string `json:"attributes"`
	AccountingStages []string `json:"accounting_stages"`
	Purpose          string   `json:"purpose"`
	Status           string   `json:"status"`
}

type BroadbandDHCPOption struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Purpose string `json:"purpose"`
	Vendor  string `json:"vendor,omitempty"`
}

type BroadbandDHCPSecurityCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandDHCPSecurityComponent() string {
	return broadbandDHCPSecurityComponent
}

func PreviewBroadbandDHCPSecurity(cfg *config.Config) (BroadbandDHCPSecurityReport, error) {
	if cfg == nil {
		return BroadbandDHCPSecurityReport{}, fmt.Errorf("config is required")
	}
	security := config.EffectiveBroadbandDHCPSecurityConfig(cfg.Broadband.DHCPSecurity)
	subscriber := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	leases := config.EffectiveBroadbandAddressLeaseConfig(cfg.Broadband.AddressLeases)
	report := BroadbandDHCPSecurityReport{
		SchemaVersion:                 BroadbandDHCPSecuritySchemaVersion,
		FeatureID:                     BroadbandDHCPSecurityFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0089-release-certification-checklist.md",
		ReleaseScope:                  "Live DHCP relay/snooping switch or OLT validation, Option 82 packet captures, IP source-guard enforcement, HA failover, scale/soak, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2131", "RFC 3046", "RFC 2865", "RFC 2866", "RFC 5176", "RFC 8415"},
		Vendors:                       []string{"Cisco", "Juniper", "Nokia/Alcatel-Lucent", "Huawei/H3C", "Calix", "Adtran", "DHCP relay/snooping access-node vendors"},
		Requirements: []string{
			"model trusted and untrusted DHCP relay/snooping ports with stable Option 82 identity",
			"compile circuit-id, remote-id, relay-agent, and source-guard bindings into durable operational evidence",
			"correlate DHCP bindings with subscriber state, address leases, accounting, and dynamic authorization",
			"fail closed in enforce mode when relay, trusted uplink, Option 82, or source-guard prerequisites are missing",
			"expose API, UI, support-bundle, runtime status, and production-readiness evidence without claiming hardware certification",
		},
		Notes: []string{
			"NAS-0089 completes software governance for DHCP relay, snooping, Option 82, and IP source guard.",
			"Physical access-node enforcement remains release certification evidence.",
		},
	}
	report.Summary = BroadbandDHCPSecuritySummary{
		Enabled:                   security.Enabled,
		Mode:                      security.Mode,
		FailClosed:                security.FailClosed,
		RequireDHCP:               security.RequireDHCP,
		RequireSubscriberState:    security.RequireSubscriberState,
		RequireAddressLeases:      security.RequireAddressLeases,
		RequireAccounting:         security.RequireAccounting,
		RequireDynamicAuth:        security.RequireDynamicAuth,
		RelayEnabled:              security.RelayEnabled,
		SnoopingEnabled:           security.SnoopingEnabled,
		SourceGuardEnabled:        security.SourceGuardEnabled,
		Option82Required:          security.Option82Required,
		DropUnknownBindings:       security.DropUnknownBindings,
		TrustedUplinkRequired:     security.TrustedUplinkRequired,
		Option82Policy:            security.Option82Policy,
		BindingRetentionSeconds:   security.BindingRetentionSeconds,
		ViolationHoldDownSeconds:  security.ViolationHoldDownSeconds,
		EventRetentionLimit:       security.EventRetentionLimit,
		DHCPEnabled:               cfg.DHCP.Enabled,
		SubscriberStateEnabled:    subscriber.Enabled,
		AddressLeasesEnabled:      leases.Enabled,
		SQLAccountingEnabled:      cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled: cfg.Radius.AccountingServices.Enabled,
		DynamicAuthEnabled:        cfg.Radius.DynamicAuth.Enabled,
	}
	report.RelayAgents = buildBroadbandDHCPRelayAgents(security)
	report.SourceGuardPolicies = buildBroadbandDHCPSourceGuardPolicies(security)
	report.Option82Rules = buildBroadbandDHCPOption82Rules(security)
	report.Ports = buildBroadbandDHCPSecurityPorts(security, report.RelayAgents, report.SourceGuardPolicies, report.Option82Rules)
	report.RADIUSCorrelation = buildBroadbandDHCPRADIUSCorrelation(security)
	report.Compliance = broadbandDHCPSecurityComplianceChecks(security, cfg, subscriber, leases, report)
	finalizeBroadbandDHCPSecurityReport(&report)
	return report, nil
}

func PreviewAndRecordBroadbandDHCPSecurity(cfg *config.Config, actor string) (BroadbandDHCPSecurityReport, string, error) {
	report, err := PreviewBroadbandDHCPSecurity(cfg)
	if err != nil {
		return BroadbandDHCPSecurityReport{}, "", err
	}
	eventID, err := recordBroadbandDHCPSecurityReport(report, "preview", "previewed", actor)
	return report, eventID, err
}

func ApplyBroadbandDHCPSecurity(ctx context.Context, cfg *config.Config, actor string) (BroadbandDHCPSecurityReport, string, error) {
	_ = ctx
	report, err := PreviewBroadbandDHCPSecurity(cfg)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandDHCPSecurityComponent, "down", err.Error(), nil)
		return BroadbandDHCPSecurityReport{}, "", err
	}
	status := "applied"
	if report.Status == "blocked" {
		eventID, _ := recordBroadbandDHCPSecurityReport(report, "apply", "blocked", actor)
		_ = db.UpsertRuntimeStatus(broadbandDHCPSecurityComponent, "down", "Broadband DHCP security apply blocked", broadbandDHCPStatusDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband DHCP security apply blocked")
	}
	if !report.Summary.Enabled {
		status = "skipped"
	}
	eventID, err := recordBroadbandDHCPSecurityReport(report, "apply", status, actor)
	if err != nil {
		_ = db.UpsertRuntimeStatus(broadbandDHCPSecurityComponent, "down", err.Error(), broadbandDHCPStatusDetails(report, ""))
		return report, eventID, err
	}
	runtimeStatus := "ok"
	if status == "skipped" {
		runtimeStatus = "disabled"
	} else if report.Status == "degraded" {
		runtimeStatus = "degraded"
	}
	message := fmt.Sprintf("NAS-0089 recorded %d DHCP security port binding(s), %d relay agent(s), and %d Option 82 rule(s).", report.Summary.PortCount, report.Summary.RelayAgentCount, report.Summary.Option82RuleCount)
	_ = db.UpsertRuntimeStatus(broadbandDHCPSecurityComponent, runtimeStatus, message, broadbandDHCPStatusDetails(report, eventID))
	return report, eventID, nil
}

func buildBroadbandDHCPRelayAgents(security config.BroadbandDHCPSecurityConfig) []BroadbandDHCPRelayAgent {
	relays := make([]BroadbandDHCPRelayAgent, 0, len(security.RelayAgents))
	for _, raw := range security.RelayAgents {
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackCisco, productconfigs.VendorPackJuniper, productconfigs.VendorPackHuawei, productconfigs.VendorPackAlcatelESAM}
		}
		relay := BroadbandDHCPRelayAgent{
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			Interface:         strings.TrimSpace(raw.Interface),
			VLAN:              raw.VLAN,
			GatewayAddress:    strings.TrimSpace(raw.GatewayAddress),
			ServerGroup:       strings.TrimSpace(raw.ServerGroup),
			VRF:               strings.TrimSpace(raw.VRF),
			CircuitIDTemplate: strings.TrimSpace(raw.CircuitIDTemplate),
			RemoteIDTemplate:  strings.TrimSpace(raw.RemoteIDTemplate),
			AppendOption82:    raw.AppendOption82 || (!raw.ReplaceOption82 && security.Option82Policy == "append"),
			ReplaceOption82:   raw.ReplaceOption82 || security.Option82Policy == "replace",
			Trusted:           raw.Trusted,
			MaxClients:        raw.MaxClients,
			VendorPacks:       packs,
			Status:            "ready",
			Reason:            "DHCP relay agent can stamp Option 82 and forward subscriber DHCP traffic.",
		}
		if !relay.Enabled {
			relay.Status = "disabled"
			relay.Reason = "Relay agent is disabled."
		}
		relays = append(relays, relay)
	}
	return relays
}

func buildBroadbandDHCPSourceGuardPolicies(security config.BroadbandDHCPSecurityConfig) []BroadbandDHCPSourceGuardPolicy {
	policies := make([]BroadbandDHCPSourceGuardPolicy, 0, len(security.SourceGuardPolicies))
	for _, raw := range security.SourceGuardPolicies {
		policy := BroadbandDHCPSourceGuardPolicy{
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			Mode:              firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.Mode)), "monitor"),
			Interfaces:        trimStringSlice(raw.Interfaces),
			VLANs:             append([]int(nil), raw.VLANs...),
			AllowUnknown:      raw.AllowUnknown,
			MaxBindings:       raw.MaxBindings,
			IPv6Enabled:       raw.IPv6Enabled,
			ActionOnViolation: firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.ActionOnViolation)), "log"),
			CoAAction:         firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.CoAAction)), "none"),
			Status:            "ready",
			Reason:            "Source guard policy can correlate DHCP bindings with subscriber address ownership.",
		}
		if !policy.Enabled {
			policy.Status = "disabled"
			policy.Reason = "Source guard policy is disabled."
		}
		policies = append(policies, policy)
	}
	return policies
}

func buildBroadbandDHCPOption82Rules(security config.BroadbandDHCPSecurityConfig) []BroadbandDHCPOption82Rule {
	rules := make([]BroadbandDHCPOption82Rule, 0, len(security.Option82Rules))
	for _, raw := range security.Option82Rules {
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard, productconfigs.VendorPackCisco, productconfigs.VendorPackHuawei, productconfigs.VendorPackAlcatelESAM}
		}
		rule := BroadbandDHCPOption82Rule{
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			MatchInterface:    strings.TrimSpace(raw.MatchInterface),
			MatchVLAN:         raw.MatchVLAN,
			CircuitIDTemplate: strings.TrimSpace(raw.CircuitIDTemplate),
			RemoteIDTemplate:  strings.TrimSpace(raw.RemoteIDTemplate),
			Action:            firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.Action)), security.Option82Policy),
			RequireRemoteID:   raw.RequireRemoteID,
			VendorPacks:       packs,
			Status:            "ready",
			Reason:            "Option 82 rule can stamp or verify relay agent circuit and remote identifiers.",
		}
		if !rule.Enabled {
			rule.Status = "disabled"
			rule.Reason = "Option 82 rule is disabled."
		}
		rules = append(rules, rule)
	}
	return rules
}

func buildBroadbandDHCPSecurityPorts(security config.BroadbandDHCPSecurityConfig, relays []BroadbandDHCPRelayAgent, policies []BroadbandDHCPSourceGuardPolicy, rules []BroadbandDHCPOption82Rule) []BroadbandDHCPSecurityPort {
	relayByInterface := map[string]string{}
	for _, relay := range relays {
		if relay.Enabled && relay.Interface != "" {
			relayByInterface[strings.ToLower(relay.Interface)] = relay.Name
		}
	}
	policyByName := map[string]BroadbandDHCPSourceGuardPolicy{}
	for _, policy := range policies {
		policyByName[strings.ToLower(policy.Name)] = policy
	}
	ruleByInterface := map[string]BroadbandDHCPOption82Rule{}
	for _, rule := range rules {
		if rule.Enabled && rule.MatchInterface != "" {
			ruleByInterface[strings.ToLower(rule.MatchInterface)] = rule
		}
	}
	ports := make([]BroadbandDHCPSecurityPort, 0, len(security.Ports))
	for _, raw := range security.Ports {
		packs := normalizeBroadbandQoSPacks(raw.VendorPacks)
		if len(packs) == 0 {
			packs = []string{productconfigs.VendorPackStandard}
		}
		port := BroadbandDHCPSecurityPort{
			BindingKey:        broadbandDHCPBindingKey(raw),
			Name:              strings.TrimSpace(raw.Name),
			Enabled:           raw.Enabled,
			Interface:         strings.TrimSpace(raw.Interface),
			VLAN:              raw.VLAN,
			Role:              firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.Role)), "access"),
			Trusted:           raw.Trusted,
			CircuitID:         strings.TrimSpace(raw.CircuitID),
			RemoteID:          strings.TrimSpace(raw.RemoteID),
			SubscriberProduct: strings.TrimSpace(raw.SubscriberProduct),
			Tenant:            strings.TrimSpace(raw.Tenant),
			MaxLeases:         raw.MaxLeases,
			SourceGuardPolicy: strings.TrimSpace(raw.SourceGuardPolicy),
			VendorPacks:       packs,
			Status:            "ready",
			Reason:            "DHCP snooping binding can correlate Option 82, lease, subscriber, and source guard state.",
		}
		if port.RelayAgent == "" {
			port.RelayAgent = relayByInterface[strings.ToLower(port.Interface)]
		}
		if port.CircuitID == "" {
			port.CircuitID = fmt.Sprintf("%s:%d", port.Interface, port.VLAN)
		}
		if port.SourceGuardPolicy == "" && len(policies) == 1 {
			port.SourceGuardPolicy = policies[0].Name
		}
		if !port.Enabled {
			port.Status = "disabled"
			port.Reason = "DHCP security port is disabled."
		}
		if security.SourceGuardEnabled && !port.Trusted && port.SourceGuardPolicy == "" {
			port.Status = "blocked"
			port.Reason = "Untrusted access port requires a source guard policy."
		} else if port.SourceGuardPolicy != "" {
			if policy, ok := policyByName[strings.ToLower(port.SourceGuardPolicy)]; ok && policy.Status == "disabled" {
				port.Status = "blocked"
				port.Reason = "Referenced source guard policy is disabled."
			}
		}
		rule := ruleByInterface[strings.ToLower(port.Interface)]
		port.CompiledOptions = broadbandDHCPCompiledOptions(port, rule, security)
		ports = append(ports, port)
	}
	return ports
}

func broadbandDHCPCompiledOptions(port BroadbandDHCPSecurityPort, rule BroadbandDHCPOption82Rule, security config.BroadbandDHCPSecurityConfig) []BroadbandDHCPOption {
	circuitID := firstNonEmptyString(port.CircuitID, rule.CircuitIDTemplate, fmt.Sprintf("%s:%d", port.Interface, port.VLAN))
	remoteID := firstNonEmptyString(port.RemoteID, rule.RemoteIDTemplate, port.Tenant, "aegisnas")
	options := []BroadbandDHCPOption{
		{Name: "DHCP-Relay-Agent-Information", Value: "enabled", Purpose: "RFC 3046 relay-agent information option is governed for this binding."},
		{Name: "Agent-Circuit-Id", Value: circuitID, Purpose: "Circuit identifier used for subscriber, lease, and accounting correlation."},
		{Name: "Agent-Remote-Id", Value: remoteID, Purpose: "Remote identifier used for access-node or tenant correlation."},
		{Name: "Class", Value: "dhcp-security:" + port.BindingKey, Purpose: "Stable RADIUS/accounting correlation token for the DHCP binding."},
	}
	if port.SubscriberProduct != "" {
		options = append(options, BroadbandDHCPOption{Name: "AegisNAS-Subscriber-Product", Value: port.SubscriberProduct, Purpose: "Product hint for subscriber-service and address-lease correlation.", Vendor: "aegisnas"})
	}
	for _, pack := range port.VendorPacks {
		switch productconfigs.NormalizeVendorCompatibilityPackKey(pack) {
		case productconfigs.VendorPackCisco:
			options = append(options, BroadbandDHCPOption{Name: "Cisco-AVPair", Value: "dhcp-option82=" + circuitID, Purpose: "Cisco DHCP snooping/Option 82 policy evidence.", Vendor: "cisco"})
		case productconfigs.VendorPackJuniper, productconfigs.VendorPackERX:
			options = append(options, BroadbandDHCPOption{Name: "Juniper-AV-Pair", Value: "dhcp-option-82=" + circuitID, Purpose: "Juniper/ERX relay-agent information evidence.", Vendor: "juniper"})
		case productconfigs.VendorPackHuawei, productconfigs.VendorPackH3C:
			options = append(options, BroadbandDHCPOption{Name: "Huawei-AVpair", Value: "dhcp-option82=" + circuitID, Purpose: "Huawei/H3C DHCP relay/snooping evidence.", Vendor: "huawei"})
		case productconfigs.VendorPackAlcatelESAM, productconfigs.VendorPackNokia, productconfigs.VendorPackALUSR:
			options = append(options, BroadbandDHCPOption{Name: "Nokia-AVPair", Value: "dhcp-option82=" + circuitID, Purpose: "Nokia/Alcatel DHCP relay information evidence.", Vendor: "nokia"})
		}
	}
	if security.SourceGuardEnabled {
		options = append(options, BroadbandDHCPOption{Name: "Source-Guard", Value: firstNonEmptyString(port.SourceGuardPolicy, "default"), Purpose: "Bind IP/MAC/port enforcement to the DHCP lease owner."})
	}
	return options
}

func buildBroadbandDHCPRADIUSCorrelation(security config.BroadbandDHCPSecurityConfig) []BroadbandDHCPRADIUSCorrelation {
	if len(security.RADIUSCorrelation) == 0 {
		return []BroadbandDHCPRADIUSCorrelation{
			{Name: "option82-accounting", Enabled: true, Source: "option82", Attributes: []string{"Class", "NAS-Port-Id", "Calling-Station-Id"}, AccountingStages: []string{"start", "interim", "stop"}, Purpose: "Carry DHCP binding identity into accounting and support workflows.", Status: "ready"},
		}
	}
	items := make([]BroadbandDHCPRADIUSCorrelation, 0, len(security.RADIUSCorrelation))
	for _, raw := range security.RADIUSCorrelation {
		item := BroadbandDHCPRADIUSCorrelation{
			Name:             strings.TrimSpace(raw.Name),
			Enabled:          raw.Enabled,
			Source:           firstNonEmptyString(strings.ToLower(strings.TrimSpace(raw.Source)), "option82"),
			Attributes:       trimStringSlice(raw.Attributes),
			AccountingStages: trimStringSlice(raw.AccountingStages),
			Purpose:          "Correlate DHCP security bindings with RADIUS authorization and accounting.",
			Status:           "ready",
		}
		if len(item.Attributes) == 0 {
			item.Attributes = []string{"Class", "NAS-Port-Id"}
		}
		if len(item.AccountingStages) == 0 {
			item.AccountingStages = []string{"start", "interim", "stop"}
		}
		if !item.Enabled {
			item.Status = "disabled"
		}
		items = append(items, item)
	}
	return items
}

func broadbandDHCPSecurityComplianceChecks(security config.BroadbandDHCPSecurityConfig, cfg *config.Config, subscriber config.BroadbandSubscriberStateConfig, leases config.BroadbandAddressLeaseConfig, report BroadbandDHCPSecurityReport) []BroadbandDHCPSecurityCheck {
	return []BroadbandDHCPSecurityCheck{
		broadbandDHCPCheck("dhcp", "DHCP service dependency", !security.Enabled || !security.RequireDHCP || cfg.DHCP.Enabled, "DHCP service is available for relay and lease correlation.", "Enabled DHCP security requires dhcp.enabled.", "dhcp.enabled"),
		broadbandDHCPCheck("subscriber-state", "Subscriber state dependency", !security.Enabled || !security.RequireSubscriberState || subscriber.Enabled, "Subscriber state is available for binding correlation.", "Enabled DHCP security requires broadband.subscriber_state.enabled.", "broadband.subscriber_state"),
		broadbandDHCPCheck("address-leases", "Address lease dependency", !security.Enabled || !security.RequireAddressLeases || leases.Enabled, "Address lease lifecycle is available for source guard ownership.", "Enabled DHCP security requires broadband.address_leases.enabled.", "broadband.address_leases"),
		broadbandDHCPCheck("accounting", "Accounting correlation dependency", !security.Enabled || !security.RequireAccounting || (cfg.Radius.SQLAccounting.Enabled && cfg.Radius.AccountingServices.Enabled), "SQL accounting and service correlation are available.", "DHCP binding accounting requires radius.sql_accounting and radius.accounting_services.", "radius.sql_accounting", "radius.accounting_services"),
		broadbandDHCPCheck("dynamic-auth", "Dynamic authorization recovery", !security.Enabled || !security.RequireDynamicAuth || cfg.Radius.DynamicAuth.Enabled, "Dynamic authorization is available for source-guard recovery.", "Source guard recovery requires radius.dynamic_auth.enabled.", "radius.dynamic_auth"),
		broadbandDHCPCheck("relay-agents", "DHCP relay agents", !security.Enabled || !security.RelayEnabled || len(report.RelayAgents) > 0, "Relay-agent evidence is present or relay is disabled.", "DHCP relay enforcement requires at least one relay agent.", "relay_agents"),
		broadbandDHCPCheck("trusted-ports", "Trusted uplink ports", !security.Enabled || !security.TrustedUplinkRequired || broadbandDHCPSecurityTrustedPortCount(report.Ports) > 0, "At least one trusted port is present or trusted uplink gating is disabled.", "Trusted uplink enforcement requires at least one trusted port.", "ports"),
		broadbandDHCPCheck("option82", "Option 82 policy", !security.Enabled || !security.Option82Required || len(report.Option82Rules) > 0, "Option 82 rule evidence is present or requirement is disabled.", "Option 82 enforcement requires at least one rule.", "option82_rules", "RFC 3046"),
		broadbandDHCPCheck("source-guard", "IP source guard policy", !security.Enabled || !security.SourceGuardEnabled || len(report.SourceGuardPolicies) > 0, "Source guard policy evidence is present or disabled.", "Source guard enforcement requires at least one policy.", "source_guard_policies"),
		broadbandDHCPCheck("external-certification", "External DHCP security certification boundary", true, "Live switch/OLT DHCP relay, snooping, Option 82, source guard, HA, scale, soak, security, and customer proof are release certification activities.", "", "docs/nas-0089-release-certification-checklist.md"),
	}
}

func broadbandDHCPSecurityTrustedPortCount(ports []BroadbandDHCPSecurityPort) int {
	count := 0
	for _, port := range ports {
		if port.Enabled && port.Trusted {
			count++
		}
	}
	return count
}

func broadbandDHCPCheck(id, name string, passed bool, passMessage, failMessage string, evidence ...string) BroadbandDHCPSecurityCheck {
	status := "passed"
	message := passMessage
	if !passed {
		status = "blocked"
		message = failMessage
	}
	return BroadbandDHCPSecurityCheck{ID: id, Name: name, Status: status, Message: message, Evidence: evidence}
}

func finalizeBroadbandDHCPSecurityReport(report *BroadbandDHCPSecurityReport) {
	for _, relay := range report.RelayAgents {
		report.Summary.RelayAgentCount++
		if relay.Enabled {
			report.Summary.EnabledRelayAgentCount++
		}
		if relay.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("relay agent %s: %s", relay.Name, relay.Reason))
		}
	}
	for _, policy := range report.SourceGuardPolicies {
		report.Summary.SourceGuardPolicyCount++
		if policy.Enabled {
			report.Summary.EnabledSourceGuardPolicies++
		}
		if policy.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("source guard policy %s: %s", policy.Name, policy.Reason))
		}
	}
	for _, rule := range report.Option82Rules {
		report.Summary.Option82RuleCount++
		if rule.Enabled {
			report.Summary.EnabledOption82RuleCount++
		}
		if rule.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("Option 82 rule %s: %s", rule.Name, rule.Reason))
		}
	}
	for _, port := range report.Ports {
		report.Summary.PortCount++
		if port.Enabled {
			report.Summary.EnabledPortCount++
		}
		if port.Trusted {
			report.Summary.TrustedPortCount++
		}
		report.Summary.CompiledOptionCount += len(port.CompiledOptions)
		if port.Status == "blocked" {
			report.Blockers = append(report.Blockers, fmt.Sprintf("DHCP security port %s: %s", port.Name, port.Reason))
		}
	}
	for _, item := range report.RADIUSCorrelation {
		if item.Enabled {
			report.Summary.RADIUSCorrelationCount++
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
		report.Message = "NAS-0089 software is ready; DHCP relay, snooping, Option 82, and IP source guard are not active in this configuration."
	} else if len(report.Blockers) > 0 {
		report.Status = "blocked"
		report.Message = fmt.Sprintf("NAS-0089 DHCP security is blocked by %d requirement(s).", len(report.Blockers))
	} else if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0089 DHCP security is ready with %d warning(s).", len(report.Warnings))
	} else {
		report.Message = fmt.Sprintf("NAS-0089 DHCP security is ready with %d relay agent(s), %d port binding(s), %d Option 82 rule(s), and %d source guard policy(ies).", report.Summary.RelayAgentCount, report.Summary.PortCount, report.Summary.Option82RuleCount, report.Summary.SourceGuardPolicyCount)
	}
	report.PlanFingerprint = broadbandDHCPFingerprint(*report)
}

func recordBroadbandDHCPSecurityReport(report BroadbandDHCPSecurityReport, operation, status, actor string) (string, error) {
	return db.RecordBroadbandDHCPSecurityEvent(db.BroadbandDHCPSecurityEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		RelayAgentCount:          report.Summary.RelayAgentCount,
		PortCount:                report.Summary.PortCount,
		TrustedPortCount:         report.Summary.TrustedPortCount,
		Option82RuleCount:        report.Summary.Option82RuleCount,
		SourceGuardPolicyCount:   report.Summary.SourceGuardPolicyCount,
		RADIUSCorrelationCount:   report.Summary.RADIUSCorrelationCount,
		CompiledOptionCount:      report.Summary.CompiledOptionCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              broadbandDHCPJSON(report.Summary, "{}"),
		ReportJSON:               broadbandDHCPJSON(report, "{}"),
		Actor:                    actor,
		Bindings:                 broadbandDHCPDBBindings(report, status),
	})
}

func broadbandDHCPDBBindings(report BroadbandDHCPSecurityReport, eventStatus string) []db.BroadbandDHCPSecurityBindingInput {
	bindings := make([]db.BroadbandDHCPSecurityBindingInput, 0, len(report.Ports))
	for _, port := range report.Ports {
		status := "planned"
		if eventStatus == "applied" && port.Enabled && port.Status == "ready" {
			status = "active"
		} else if port.Status == "blocked" {
			status = "blocked"
		} else if port.Status == "degraded" {
			status = "degraded"
		}
		bindings = append(bindings, db.BroadbandDHCPSecurityBindingInput{
			BindingKey:          port.BindingKey,
			PortName:            port.Name,
			Interface:           port.Interface,
			VLAN:                port.VLAN,
			Role:                port.Role,
			Trusted:             port.Trusted,
			CircuitID:           port.CircuitID,
			RemoteID:            port.RemoteID,
			SubscriberProduct:   port.SubscriberProduct,
			Tenant:              port.Tenant,
			RelayAgent:          port.RelayAgent,
			SourceGuardPolicy:   port.SourceGuardPolicy,
			Status:              status,
			CompiledOptionsJSON: broadbandDHCPJSON(port.CompiledOptions, "[]"),
			PlanFingerprint:     report.PlanFingerprint,
			InstalledAt:         installedAtForBroadbandDHCPStatus(eventStatus, status),
		})
	}
	return bindings
}

func installedAtForBroadbandDHCPStatus(eventStatus, bindingStatus string) string {
	if eventStatus == "applied" && bindingStatus == "active" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return ""
}

func broadbandDHCPBindingKey(port config.BroadbandDHCPSecurityPortConfig) string {
	raw := strings.Join([]string{strings.TrimSpace(port.Name), strings.TrimSpace(port.Interface), fmt.Sprint(port.VLAN), strings.TrimSpace(port.CircuitID), strings.TrimSpace(port.RemoteID)}, "|")
	sum := sha256.Sum256([]byte(raw))
	return "bdhcp-" + hex.EncodeToString(sum[:])[:20]
}

func broadbandDHCPFingerprint(report BroadbandDHCPSecurityReport) string {
	payload := struct {
		Summary           BroadbandDHCPSecuritySummary     `json:"summary"`
		RelayAgents       []BroadbandDHCPRelayAgent        `json:"relay_agents"`
		Ports             []BroadbandDHCPSecurityPort      `json:"ports"`
		Option82Rules     []BroadbandDHCPOption82Rule      `json:"option82_rules"`
		SourceGuard       []BroadbandDHCPSourceGuardPolicy `json:"source_guard_policies"`
		RADIUSCorrelation []BroadbandDHCPRADIUSCorrelation `json:"radius_correlation"`
	}{report.Summary, report.RelayAgents, report.Ports, report.Option82Rules, report.SourceGuardPolicies, report.RADIUSCorrelation}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func broadbandDHCPJSON(value any, fallback string) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fallback
	}
	return string(data)
}

func broadbandDHCPStatusDetails(report BroadbandDHCPSecurityReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":            report.FeatureID,
		"event_id":              eventID,
		"status":                report.Status,
		"plan_fingerprint":      report.PlanFingerprint,
		"relay_agent_count":     report.Summary.RelayAgentCount,
		"port_count":            report.Summary.PortCount,
		"trusted_port_count":    report.Summary.TrustedPortCount,
		"option82_rule_count":   report.Summary.Option82RuleCount,
		"source_guard_policies": report.Summary.SourceGuardPolicyCount,
		"compiled_option_count": report.Summary.CompiledOptionCount,
		"blocker_count":         report.Summary.BlockerCount,
		"warning_count":         report.Summary.WarningCount,
	}
}
