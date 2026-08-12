package radius

import (
	"fmt"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	layehradius "layeh.com/radius"
)

const OutboundDACVendorActionSchemaVersion = 1

var outboundDACVendorActionPacks = []string{
	productconfigs.VendorPackCisco,
	productconfigs.VendorPackAruba,
	productconfigs.VendorPackJuniper,
	productconfigs.VendorPackRuckus,
	productconfigs.VendorPackFortinet,
	productconfigs.VendorPackMikroTik,
	productconfigs.VendorPackHuawei,
	productconfigs.VendorPackH3C,
}

var outboundDACVendorActionNames = []string{
	"policy-update",
	"reauth",
	"role",
	"vlan",
	"acl",
	"qos",
	"quarantine",
	"unquarantine",
	"terminate",
}

type OutboundDACVendorActionReport struct {
	SchemaVersion  int      `json:"schema_version"`
	Status         string   `json:"status"`
	Message        string   `json:"message"`
	Enabled        bool     `json:"enabled"`
	RequirePack    bool     `json:"require_pack"`
	ActivePacks    []string `json:"active_packs"`
	SupportedPacks []string `json:"supported_packs"`
	Actions        []string `json:"actions"`
	Warnings       []string `json:"warnings,omitempty"`
	Blockers       []string `json:"blockers,omitempty"`
	RFCs           []string `json:"rfcs"`
}

type OutboundDACVendorDecision struct {
	SchemaVersion  int                       `json:"schema_version"`
	Status         string                    `json:"status"`
	Action         string                    `json:"action,omitempty"`
	Packs          []string                  `json:"packs,omitempty"`
	Attributes     []db.OutboundDACAttribute `json:"attributes,omitempty"`
	AttributeCount int                       `json:"attribute_count"`
	Warnings       []string                  `json:"warnings,omitempty"`
	Blockers       []string                  `json:"blockers,omitempty"`
	RFCs           []string                  `json:"rfcs"`
}

type outboundDACVendorActionIntent struct {
	Action           string
	Role             string
	FilterID         string
	VLAN             int
	BandwidthProfile string
	DownloadRateKbps int
	UploadRateKbps   int
	ACLName          string
	InboundACL       string
	OutboundACL      string
	ACLRules         []ACLRule
	PolicyTag        string
	PortalProfile    string
}

type outboundDACVendorAttributeWireKind string

const (
	outboundDACVendorWireString  outboundDACVendorAttributeWireKind = "string"
	outboundDACVendorWireInteger outboundDACVendorAttributeWireKind = "integer"
)

type outboundDACVendorAttributeSpec struct {
	Canonical string
	VendorID  uint32
	Type      byte
	Kind      outboundDACVendorAttributeWireKind
}

var outboundDACVendorAttributeSpecs = map[string]outboundDACVendorAttributeSpec{
	"cisco-avpair":                 {Canonical: "Cisco-AVPair", VendorID: 9, Type: 1, Kind: outboundDACVendorWireString},
	"cisco-in-acl":                 {Canonical: "Cisco-In-ACL", VendorID: 9, Type: 57, Kind: outboundDACVendorWireString},
	"cisco-out-acl":                {Canonical: "Cisco-Out-ACL", VendorID: 9, Type: 58, Kind: outboundDACVendorWireString},
	"aruba-user-role":              {Canonical: "Aruba-User-Role", VendorID: 14823, Type: 1, Kind: outboundDACVendorWireString},
	"aruba-user-vlan":              {Canonical: "Aruba-User-Vlan", VendorID: 14823, Type: 2, Kind: outboundDACVendorWireInteger},
	"aruba-nas-filter-rule":        {Canonical: "Aruba-NAS-Filter-Rule", VendorID: 14823, Type: 51, Kind: outboundDACVendorWireString},
	"juniper-local-user-name":      {Canonical: "Juniper-Local-User-Name", VendorID: 2636, Type: 1, Kind: outboundDACVendorWireString},
	"juniper-firewall-filter-name": {Canonical: "Juniper-Firewall-filter-name", VendorID: 2636, Type: 44, Kind: outboundDACVendorWireString},
	"juniper-switching-filter":     {Canonical: "Juniper-Switching-Filter", VendorID: 2636, Type: 48, Kind: outboundDACVendorWireString},
	"juniper-av-pair":              {Canonical: "Juniper-AV-Pair", VendorID: 2636, Type: 52, Kind: outboundDACVendorWireString},
	"ruckus-user-groups":           {Canonical: "Ruckus-User-Groups", VendorID: 25053, Type: 1, Kind: outboundDACVendorWireString},
	"ruckus-vlan-id":               {Canonical: "Ruckus-VLAN-ID", VendorID: 25053, Type: 9, Kind: outboundDACVendorWireInteger},
	"fortinet-group-name":          {Canonical: "Fortinet-Group-Name", VendorID: 12356, Type: 1, Kind: outboundDACVendorWireString},
	"fortinet-access-profile":      {Canonical: "Fortinet-Access-Profile", VendorID: 12356, Type: 6, Kind: outboundDACVendorWireString},
	"mikrotik-rate-limit":          {Canonical: "Mikrotik-Rate-Limit", VendorID: 14988, Type: 8, Kind: outboundDACVendorWireString},
	"mikrotik-address-list":        {Canonical: "Mikrotik-Address-List", VendorID: 14988, Type: 19, Kind: outboundDACVendorWireString},
	"huawei-input-average-rate":    {Canonical: "Huawei-Input-Average-Rate", VendorID: 2011, Type: 2, Kind: outboundDACVendorWireInteger},
	"huawei-output-average-rate":   {Canonical: "Huawei-Output-Average-Rate", VendorID: 2011, Type: 5, Kind: outboundDACVendorWireInteger},
	"huawei-qos-profile-name":      {Canonical: "Huawei-Qos-Profile-Name", VendorID: 2011, Type: 31, Kind: outboundDACVendorWireString},
	"huawei-user-class":            {Canonical: "Huawei-User-Class", VendorID: 2011, Type: 66, Kind: outboundDACVendorWireString},
	"huawei-data-filter":           {Canonical: "Huawei-Data-Filter", VendorID: 2011, Type: 82, Kind: outboundDACVendorWireString},
	"huawei-down-qos-profile-name": {Canonical: "Huawei-Down-QOS-Profile-Name", VendorID: 2011, Type: 182, Kind: outboundDACVendorWireString},
	"huawei-avpair":                {Canonical: "Huawei-AVpair", VendorID: 2011, Type: 188, Kind: outboundDACVendorWireString},
	"h3c-input-average-rate":       {Canonical: "H3C-Input-Average-Rate", VendorID: 25506, Type: 2, Kind: outboundDACVendorWireInteger},
	"h3c-output-average-rate":      {Canonical: "H3C-Output-Average-Rate", VendorID: 25506, Type: 5, Kind: outboundDACVendorWireInteger},
	"h3c-user-group":               {Canonical: "H3C-User-Group", VendorID: 25506, Type: 140, Kind: outboundDACVendorWireString},
	"h3c-user-role":                {Canonical: "H3C-User-Role", VendorID: 25506, Type: 155, Kind: outboundDACVendorWireString},
	"h3c-av-pair":                  {Canonical: "H3C-Av-Pair", VendorID: 25506, Type: 210, Kind: outboundDACVendorWireString},
	"h3c-ita-policy":               {Canonical: "H3C-Ita-Policy", VendorID: 25506, Type: 216, Kind: outboundDACVendorWireString},
}

func BuildOutboundDACVendorActionReport(cfg *config.Config) OutboundDACVendorActionReport {
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	report := OutboundDACVendorActionReport{
		SchemaVersion:  OutboundDACVendorActionSchemaVersion,
		Status:         "ready",
		Message:        "Vendor dynamic-action compiler is ready for typed CoA and Disconnect intents.",
		Enabled:        effective.OutboundVendorActionsEnabled,
		RequirePack:    effective.OutboundVendorActionsRequirePack,
		SupportedPacks: append([]string(nil), outboundDACVendorActionPacks...),
		Actions:        append([]string(nil), outboundDACVendorActionNames...),
		RFCs:           []string{"RFC 2865", "RFC 2868", "RFC 3576", "RFC 3580", "RFC 5176"},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		report.Blockers = append(report.Blockers, "configuration is required")
		return report
	}
	if !effective.OutboundEnabled {
		report.Status = "disabled"
		report.Message = "Outbound dynamic authorization is disabled."
		return report
	}
	if !effective.OutboundVendorActionsEnabled {
		report.Status = "disabled"
		report.Message = "Vendor dynamic-action compilation is disabled."
		return report
	}
	report.ActivePacks = outboundDACSupportedVendorActionPacks(normalizeReplyPackKeys(cfg.Radius.Vendor.CompatibilityPacks))
	if len(report.ActivePacks) == 0 && effective.OutboundVendorActionsRequirePack {
		report.Status = "blocked"
		report.Message = "No NAS-0045 vendor action pack is active."
		report.Blockers = append(report.Blockers, "enable at least one supported radius.vendor.compatibility_packs entry")
		return report
	}
	if len(report.ActivePacks) == 0 {
		report.Status = "degraded"
		report.Message = "No supported vendor action pack is active; explicit vendor_packs are required per request."
		report.Warnings = append(report.Warnings, "supported packs: "+strings.Join(report.SupportedPacks, ", "))
	}
	return report
}

func CompileOutboundDACVendorAction(cfg *config.Config, request OutboundDACRequest, target OutboundDACTarget) OutboundDACVendorDecision {
	request = normalizeOutboundDACRequest(request)
	decision := OutboundDACVendorDecision{
		SchemaVersion: OutboundDACVendorActionSchemaVersion,
		Status:        "not_requested",
		Action:        request.VendorAction,
		RFCs:          []string{"RFC 2865", "RFC 2868", "RFC 3576", "RFC 3580", "RFC 5176"},
	}
	if request.VendorAction == "" {
		return decision
	}
	if cfg == nil {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, "configuration is required for vendor dynamic-action compilation")
		return decision
	}
	effective := config.EffectiveDynamicAuthConfig(dynamicAuthConfig(cfg))
	if !effective.OutboundVendorActionsEnabled {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, "radius.dynamic_auth.outbound_vendor_actions_enabled is false")
		return decision
	}
	if request.VendorAction == "terminate" && request.Action != "disconnect" {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, "vendor_action terminate requires action=disconnect")
		return decision
	}
	if request.VendorAction != "terminate" && request.Action == "disconnect" {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, "vendor policy actions require action=coa; use vendor_action terminate with action=disconnect")
		return decision
	}
	intent, err := outboundDACVendorActionIntentFromRequest(request)
	if err != nil {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, err.Error())
		return decision
	}
	packs, warnings, blockers := outboundDACVendorActionPacksForRequest(cfg, request, target, effective)
	decision.Packs = packs
	decision.Warnings = append(decision.Warnings, warnings...)
	if len(blockers) > 0 {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, blockers...)
		return decision
	}
	if request.VendorAction == "terminate" {
		decision.Status = "standards_only"
		decision.Warnings = append(decision.Warnings, "terminate uses RFC 5176 Disconnect-Request selectors; no portable vendor VSA is required")
		return decision
	}

	appendAttr := func(name, value string) {
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" || value == "" {
			return
		}
		for _, existing := range decision.Attributes {
			if strings.EqualFold(existing.Name, name) && existing.Value == value {
				return
			}
		}
		decision.Attributes = append(decision.Attributes, db.OutboundDACAttribute{Name: name, Value: value})
	}

	for _, pack := range packs {
		before := len(decision.Attributes)
		switch pack {
		case productconfigs.VendorPackStandard:
			compileStandardOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackCisco:
			compileCiscoOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackAruba:
			compileArubaOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackJuniper:
			compileJuniperOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackRuckus:
			compileRuckusOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackFortinet:
			compileFortinetOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackMikroTik:
			compileMikroTikOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackHuawei:
			compileHuaweiOutboundDACVendorAction(intent, appendAttr)
		case productconfigs.VendorPackH3C:
			compileH3COutboundDACVendorAction(intent, appendAttr)
		default:
			decision.Warnings = append(decision.Warnings, fmt.Sprintf("pack %q has no NAS-0045 dynamic-action compiler", pack))
		}
		if len(decision.Attributes) == before && pack != productconfigs.VendorPackStandard {
			decision.Warnings = append(decision.Warnings, fmt.Sprintf("pack %q did not emit vendor-specific attributes for action %q", pack, intent.Action))
		}
	}
	if err := validateOutboundDACVendorDecision(intent, decision.Attributes); err != nil {
		decision.Status = "blocked"
		decision.Blockers = append(decision.Blockers, err.Error())
		return decision
	}
	decision.AttributeCount = len(decision.Attributes)
	if len(decision.Attributes) == 0 {
		decision.Status = "standards_only"
		decision.Warnings = append(decision.Warnings, "vendor action is carried by RFC 5176 selectors only")
		return decision
	}
	decision.Status = "compiled"
	return decision
}

func normalizeOutboundDACVendorAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "none":
		return ""
	case "policy", "policy-update", "update", "change-policy":
		return "policy-update"
	case "reauth", "reauthorize", "reauthenticate":
		return "reauth"
	case "role", "change-role", "role-change":
		return "role"
	case "vlan", "change-vlan", "vlan-change":
		return "vlan"
	case "acl", "dacl", "apply-acl", "downloadable-acl":
		return "acl"
	case "qos", "bandwidth", "rate", "rate-limit", "apply-qos":
		return "qos"
	case "quarantine", "isolate":
		return "quarantine"
	case "unquarantine", "clear-quarantine", "restore":
		return "unquarantine"
	case "terminate", "disconnect", "kill-session":
		return "terminate"
	default:
		return strings.ToLower(strings.TrimSpace(action))
	}
}

func normalizeOutboundDACVendorPacks(packs []string) []string {
	out := make([]string, 0, len(packs))
	seen := map[string]struct{}{}
	for _, pack := range packs {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(pack)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func outboundDACVendorActionIntentFromRequest(request OutboundDACRequest) (outboundDACVendorActionIntent, error) {
	rules, err := NormalizeACLRules(request.ACLRules)
	if err != nil {
		return outboundDACVendorActionIntent{}, err
	}
	intent := outboundDACVendorActionIntent{
		Action:           request.VendorAction,
		Role:             firstNonEmptyString(request.Role, request.FilterID),
		FilterID:         request.FilterID,
		VLAN:             request.VLAN,
		BandwidthProfile: request.BandwidthProfile,
		DownloadRateKbps: request.DownloadRateKbps,
		UploadRateKbps:   request.UploadRateKbps,
		ACLName:          request.ACLName,
		InboundACL:       request.ACLName,
		OutboundACL:      request.ACLName,
		ACLRules:         rules,
		PolicyTag:        request.PolicyTag,
		PortalProfile:    request.PortalProfile,
	}
	switch intent.Action {
	case "policy-update":
		if intent.Role == "" && intent.FilterID == "" && intent.VLAN == 0 && intent.BandwidthProfile == "" &&
			intent.DownloadRateKbps == 0 && intent.UploadRateKbps == 0 && intent.ACLName == "" &&
			len(intent.ACLRules) == 0 && intent.PolicyTag == "" && intent.PortalProfile == "" {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action policy-update requires at least one role, VLAN, ACL, QoS, policy, or portal field")
		}
	case "role":
		if intent.Role == "" {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action role requires role or filter_id")
		}
	case "vlan":
		if intent.VLAN < 1 || intent.VLAN > 4094 {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action vlan requires vlan between 1 and 4094")
		}
	case "acl":
		if intent.ACLName == "" && len(intent.ACLRules) == 0 && intent.PolicyTag == "" {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action acl requires acl_name, acl_rules, or policy_tag")
		}
	case "qos":
		if intent.BandwidthProfile == "" && intent.DownloadRateKbps == 0 && intent.UploadRateKbps == 0 && intent.PolicyTag == "" {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action qos requires bandwidth_profile, download_rate_kbps, upload_rate_kbps, or policy_tag")
		}
	case "quarantine", "unquarantine":
		if intent.Role == "" && intent.PolicyTag == "" && intent.ACLName == "" {
			return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action %s requires role, policy_tag, or acl_name", intent.Action)
		}
	case "reauth", "terminate":
	default:
		return outboundDACVendorActionIntent{}, fmt.Errorf("vendor_action %q is not supported", intent.Action)
	}
	return intent, nil
}

func outboundDACVendorActionPacksForRequest(cfg *config.Config, request OutboundDACRequest, target OutboundDACTarget, effective config.DynamicAuthConfig) ([]string, []string, []string) {
	source := append([]string(nil), request.VendorPacks...)
	warnings := []string{}
	blockers := []string{}
	if len(source) == 0 {
		profile := NormalizeClientNASType(firstNonEmptyString(target.NASType, request.NASType))
		if outboundDACVendorActionPackSupported(profile) {
			source = []string{productconfigs.VendorPackStandard, profile}
		} else if cfg != nil {
			configured := normalizeOutboundDACVendorPacks(cfg.Radius.Vendor.CompatibilityPacks)
			supported := outboundDACSupportedVendorActionPacks(configured)
			switch len(supported) {
			case 0:
				source = []string{productconfigs.VendorPackStandard}
			case 1:
				source = []string{productconfigs.VendorPackStandard, supported[0]}
			default:
				blockers = append(blockers, "vendor_action requires vendor_packs or a target nas_type when multiple supported vendor packs are active")
				source = append([]string{productconfigs.VendorPackStandard}, supported...)
			}
		}
	}
	if len(source) == 0 {
		source = []string{productconfigs.VendorPackStandard}
	}
	packs := normalizeOutboundDACVendorPacks(source)
	out := make([]string, 0, len(packs))
	for _, pack := range packs {
		if !productconfigs.ValidVendorCompatibilityPackKey(pack) {
			blockers = append(blockers, fmt.Sprintf("vendor pack %q is not known", pack))
			continue
		}
		if pack == productconfigs.VendorPackStandard || outboundDACVendorActionPackSupported(pack) {
			out = append(out, pack)
			continue
		}
		warnings = append(warnings, fmt.Sprintf("vendor pack %q is ignored by NAS-0045 dynamic-action compiler", pack))
	}
	out = normalizeReplyPackKeys(out)
	supported := outboundDACSupportedVendorActionPacks(out)
	if len(supported) == 0 && effective.OutboundVendorActionsRequirePack {
		blockers = append(blockers, "no supported NAS-0045 vendor action pack is selected")
	}
	return out, warnings, blockers
}

func outboundDACSupportedVendorActionPacks(packs []string) []string {
	out := []string{}
	for _, pack := range normalizeReplyPackKeys(packs) {
		if outboundDACVendorActionPackSupported(pack) {
			out = append(out, pack)
		}
	}
	return out
}

func outboundDACVendorActionPackSupported(pack string) bool {
	pack = productconfigs.NormalizeVendorCompatibilityPackKey(pack)
	for _, supported := range outboundDACVendorActionPacks {
		if pack == supported {
			return true
		}
	}
	return false
}

func compileStandardOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Filter-Id", firstNonEmptyString(intent.FilterID, intent.Role, intent.PolicyTag, intent.ACLName))
	case "acl":
		for _, rule := range renderNASFilterRules(intent.ACLRules) {
			appendAttr("NAS-Filter-Rule", rule)
		}
	case "reauth", "terminate", "vlan", "qos":
	}
}

func compileCiscoOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "reauth":
		appendAttr("Cisco-AVPair", "subscriber:command=reauthenticate")
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Cisco-AVPair", "shell:roles="+firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "acl":
		appendAttr("Cisco-In-ACL", intent.InboundACL)
		appendAttr("Cisco-Out-ACL", intent.OutboundACL)
		for _, value := range renderCiscoAVPairACLRules(intent.ACLRules) {
			appendAttr("Cisco-AVPair", value)
		}
	case "qos":
		appendAttr("Cisco-AVPair", "ip:qos-policy-in="+firstNonEmptyString(intent.PolicyTag, intent.BandwidthProfile))
	}
}

func compileArubaOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Aruba-User-Role", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "vlan":
		appendAttr("Aruba-User-Vlan", strconv.Itoa(intent.VLAN))
	case "acl":
		for _, rule := range renderNASFilterRules(intent.ACLRules) {
			appendAttr("Aruba-NAS-Filter-Rule", rule)
		}
	case "reauth", "qos":
	}
}

func compileJuniperOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Juniper-Local-User-Name", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "acl":
		filter := firstNonEmptyString(intent.ACLName, intent.PolicyTag, intent.Role)
		appendAttr("Juniper-Firewall-filter-name", filter)
		appendAttr("Juniper-Switching-Filter", filter)
	case "qos":
		appendAttr("Juniper-AV-Pair", "qos-profile="+firstNonEmptyString(intent.PolicyTag, intent.BandwidthProfile))
	case "reauth", "vlan":
	}
}

func compileRuckusOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine", "acl":
		appendAttr("Ruckus-User-Groups", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "vlan":
		appendAttr("Ruckus-VLAN-ID", strconv.Itoa(intent.VLAN))
	case "reauth", "qos":
	}
}

func compileFortinetOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Fortinet-Group-Name", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "acl", "qos":
		appendAttr("Fortinet-Access-Profile", firstNonEmptyString(intent.PolicyTag, intent.ACLName, intent.BandwidthProfile, intent.Role))
	case "reauth", "vlan":
	}
}

func compileMikroTikOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "acl", "quarantine", "unquarantine", "policy-update":
		appendAttr("Mikrotik-Address-List", firstNonEmptyString(intent.ACLName, intent.PolicyTag, intent.Role, intent.FilterID))
	case "qos":
		if intent.DownloadRateKbps > 0 || intent.UploadRateKbps > 0 {
			appendAttr("Mikrotik-Rate-Limit", FormatMikroTikRateLimit(intent.DownloadRateKbps, intent.UploadRateKbps))
		} else {
			appendAttr("Mikrotik-Rate-Limit", intent.BandwidthProfile)
		}
	case "reauth", "role", "vlan":
	}
}

func compileHuaweiOutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("Huawei-User-Class", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "acl":
		appendAttr("Huawei-Data-Filter", firstNonEmptyString(intent.ACLName, intent.PolicyTag))
		for _, rule := range renderNASFilterRules(intent.ACLRules) {
			appendAttr("Huawei-AVpair", "acl="+rule)
		}
	case "qos":
		appendAttr("Huawei-Qos-Profile-Name", firstNonEmptyString(intent.BandwidthProfile, intent.PolicyTag))
		appendAttr("Huawei-Down-QOS-Profile-Name", firstNonEmptyString(intent.BandwidthProfile, intent.PolicyTag))
		if intent.DownloadRateKbps > 0 {
			appendAttr("Huawei-Output-Average-Rate", FormatRateKbps(intent.DownloadRateKbps))
		}
		if intent.UploadRateKbps > 0 {
			appendAttr("Huawei-Input-Average-Rate", FormatRateKbps(intent.UploadRateKbps))
		}
	case "reauth", "vlan":
	}
}

func compileH3COutboundDACVendorAction(intent outboundDACVendorActionIntent, appendAttr func(string, string)) {
	switch intent.Action {
	case "role", "policy-update", "quarantine", "unquarantine":
		appendAttr("H3C-User-Role", firstNonEmptyString(intent.Role, intent.FilterID, intent.PolicyTag, intent.ACLName))
	case "acl":
		appendAttr("H3C-Ita-Policy", firstNonEmptyString(intent.ACLName, intent.PolicyTag))
		for _, rule := range renderNASFilterRules(intent.ACLRules) {
			appendAttr("H3C-Av-Pair", "acl="+rule)
		}
	case "qos":
		appendAttr("H3C-Ita-Policy", firstNonEmptyString(intent.PolicyTag, intent.BandwidthProfile))
		if intent.DownloadRateKbps > 0 {
			appendAttr("H3C-Output-Average-Rate", FormatRateKbps(intent.DownloadRateKbps))
		}
		if intent.UploadRateKbps > 0 {
			appendAttr("H3C-Input-Average-Rate", FormatRateKbps(intent.UploadRateKbps))
		}
	case "reauth", "vlan":
	}
}

func validateOutboundDACVendorDecision(intent outboundDACVendorActionIntent, attrs []db.OutboundDACAttribute) error {
	if len(attrs) > 64 {
		return fmt.Errorf("vendor dynamic-action compiler emitted too many attributes")
	}
	for _, attr := range attrs {
		name := strings.TrimSpace(attr.Name)
		value := strings.TrimSpace(attr.Value)
		if name == "" || value == "" {
			return fmt.Errorf("vendor dynamic-action compiler emitted an empty attribute")
		}
		if len(value) > 253 {
			return fmt.Errorf("vendor dynamic-action attribute %s exceeds 253 bytes", name)
		}
		if spec, ok := outboundDACVendorAttributeSpecs[normalizeOutboundDACAttributeName(name)]; ok && spec.Kind == outboundDACVendorWireInteger {
			value, err := parseOutboundDACVendorUint32(name, value)
			if err != nil {
				return err
			}
			if spec.Canonical == "Aruba-User-Vlan" || spec.Canonical == "Ruckus-VLAN-ID" {
				if value < 1 || value > 4094 {
					return fmt.Errorf("%s VLAN must be between 1 and 4094", spec.Canonical)
				}
			}
		}
	}
	_ = intent
	return nil
}

func parseOutboundDACVendorUint32(name, value string) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned 32-bit integer", name)
	}
	return uint32(parsed), nil
}

func applyOutboundDACVendorAttribute(packet *layehradius.Packet, name, value string) (db.OutboundDACAttribute, bool, error) {
	spec, ok := outboundDACVendorAttributeSpecs[normalizeOutboundDACAttributeName(name)]
	if !ok {
		return db.OutboundDACAttribute{}, false, nil
	}
	value = strings.TrimSpace(value)
	switch spec.Kind {
	case outboundDACVendorWireInteger:
		parsed, err := parseOutboundDACVendorUint32(spec.Canonical, value)
		if err != nil {
			return db.OutboundDACAttribute{}, true, err
		}
		return attrWithCanonicalName(spec.Canonical, strconv.FormatUint(uint64(parsed), 10)), true, addVendorInteger(packet, spec.VendorID, spec.Type, parsed)
	default:
		return attrWithCanonicalName(spec.Canonical, value), true, addVendorString(packet, spec.VendorID, spec.Type, value)
	}
}

func outboundDACAttributeIsVendorSpecific(name string) bool {
	_, ok := outboundDACVendorAttributeSpecs[normalizeOutboundDACAttributeName(name)]
	return ok
}
