package configs

const (
	VendorSemanticRole                  = "access.role"
	VendorSemanticBandwidthProfile      = "access.bandwidth_profile"
	VendorSemanticVLAN                  = "access.vlan"
	VendorSemanticQuarantine            = "access.quarantine"
	VendorSemanticPolicyTag             = "access.policy_tag"
	VendorSemanticSessionTimeout        = "session.timeout_seconds"
	VendorSemanticIdleTimeout           = "session.idle_timeout_seconds"
	VendorSemanticSessionAction         = "session.action"
	VendorSemanticDataQuota             = "session.max_total_octets"
	VendorSemanticPortalProfile         = "guest.portal_profile"
	VendorSemanticDeviceGroup           = "device.group"
	VendorSemanticTenant                = "governance.tenant"
	VendorSemanticDownloadBandwidth     = "qos.download_bandwidth"
	VendorSemanticUploadBandwidth       = "qos.upload_bandwidth"
	VendorSemanticACL                   = "enforcement.acl"
	VendorSemanticDynamicACL            = "enforcement.dynamic_acl"
	VendorSemanticAccountingIdentity    = "accounting.identity"
	VendorSemanticAccountingCounters    = "accounting.counters"
	VendorSemanticCoAReauth             = "coa.reauth"
	VendorSemanticCoADisconnect         = "coa.disconnect"
	VendorSemanticControllerPolicySync  = "controller.policy_sync"
	VendorSemanticControllerHealth      = "controller.sync_health"
	VendorSemanticDevicePosture         = "posture.device_state"
	VendorSemanticGuestLifecycle        = "guest.lifecycle"
	VendorSemanticCertificateOnboarding = "onboarding.certificate"
)

type VendorSemanticCapability struct {
	Key                string   `json:"key"`
	Label              string   `json:"label"`
	Description        string   `json:"description"`
	ValueType          string   `json:"value_type"`
	Directions         []string `json:"directions"`
	ProductAttribute   string   `json:"product_attribute,omitempty"`
	ProductNumber      int      `json:"product_number,omitempty"`
	StandardAttributes []string `json:"standard_attributes,omitempty"`
	HardwareScope      string   `json:"hardware_scope"`
	CompatibilityState string   `json:"compatibility_state"`
	NextStep           string   `json:"next_step,omitempty"`
}

type VendorCompatibilitySummary struct {
	ProductVendorID                    int      `json:"product_vendor_id"`
	ProductVendorName                  string   `json:"product_vendor_name"`
	ProductVendorIDSource              string   `json:"product_vendor_id_source"`
	ProductVendorIDPlaceholder         bool     `json:"product_vendor_id_placeholder"`
	ProductVendorDictionaryFilename    string   `json:"product_vendor_dictionary_filename"`
	ProductVendorDictionaryInstallPath string   `json:"product_vendor_dictionary_install_path"`
	ProductVendorDictionaryInclude     string   `json:"product_vendor_dictionary_include"`
	ProductVendorPENRegistryURL        string   `json:"product_vendor_pen_registry_url"`
	ProductVendorPENApplyURL           string   `json:"product_vendor_pen_apply_url"`
	ProductAttributeCount              int      `json:"product_attribute_count"`
	SemanticCount                      int      `json:"semantic_count"`
	PackCount                          int      `json:"pack_count"`
	ImplementedCount                   int      `json:"implemented_count"`
	PlannedCount                       int      `json:"planned_count"`
	HardwareProfiles                   []string `json:"hardware_profiles"`
	ProductVendorIdentityMode          string   `json:"product_vendor_identity_mode,omitempty"`
	ProductVendorAssignedOrganization  string   `json:"product_vendor_assigned_organization,omitempty"`
	ProductVendorAssignmentVerified    bool     `json:"product_vendor_assignment_verified"`
	ProductVendorAssignmentRecordSHA   string   `json:"product_vendor_assignment_record_sha256,omitempty"`
	ProductVendorLegacyIDs             []int    `json:"product_vendor_legacy_ids,omitempty"`
	ProductVendorLegacyAcceptUntil     string   `json:"product_vendor_legacy_accept_until,omitempty"`
}

type VendorCompatibilityReport struct {
	Catalog            VendorDictionaryCatalog        `json:"catalog"`
	Semantics          []VendorSemanticCapability     `json:"semantics"`
	Packs              []VendorCompatibilityPack      `json:"packs"`
	ActivePacks        []string                       `json:"active_packs,omitempty"`
	DictionaryCoverage VendorDictionaryCoverageReport `json:"dictionary_coverage"`
	Summary            VendorCompatibilitySummary     `json:"summary"`
	Notes              []string                       `json:"notes"`
}

func AegisNASSemanticRegistry() []VendorSemanticCapability {
	return []VendorSemanticCapability{
		{
			Key:                VendorSemanticRole,
			Label:              "Role",
			Description:        "Maps AAA results into an AegisNAS role for access policy, portal state, and session reporting.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Role",
			ProductNumber:      1,
			StandardAttributes: []string{"Filter-Id", "Class"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticBandwidthProfile,
			Label:              "Bandwidth Profile",
			Description:        "Maps AAA hints into local gateway shaping and accounting context.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Bandwidth-Profile",
			ProductNumber:      2,
			HardwareScope:      "all profiles; shaping may degrade on lite hardware",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticVLAN,
			Label:              "VLAN",
			Description:        "Carries dynamic VLAN assignment intent between AAA, controller adapters, and session state.",
			ValueType:          "integer",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-VLAN",
			ProductNumber:      3,
			StandardAttributes: []string{"Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticQuarantine,
			Label:              "Quarantine",
			Description:        "Marks a session or device for restricted access after policy, posture, or operator action.",
			ValueType:          "boolean",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Quarantine",
			ProductNumber:      4,
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticPolicyTag,
			Label:              "Policy Tag",
			Description:        "Carries a policy selector that can map to local firewall, controller, or role behavior.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Policy-Tag",
			ProductNumber:      5,
			StandardAttributes: []string{"Filter-Id"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticSessionTimeout,
			Label:              "Session Timeout",
			Description:        "Limits maximum session lifetime and supports CoA-driven tightening.",
			ValueType:          "integer",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Session-Timeout",
			ProductNumber:      6,
			StandardAttributes: []string{"Session-Timeout"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticIdleTimeout,
			Label:              "Idle Timeout",
			Description:        "Limits idle session lifetime and supports CoA-driven tightening.",
			ValueType:          "integer",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Idle-Timeout",
			ProductNumber:      7,
			StandardAttributes: []string{"Idle-Timeout"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticSessionAction,
			Label:              "Session Action",
			Description:        "Carries reauth, disconnect, quarantine, or allow intent for CoA and controller integrations.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound"},
			ProductAttribute:   "AegisNAS-Session-Action",
			ProductNumber:      8,
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticDataQuota,
			Label:              "Session Data Quota",
			Description:        "Limits the combined input and output octets authorized for a session.",
			ValueType:          "integer",
			Directions:         []string{"inbound", "outbound", "accounting"},
			StandardAttributes: []string{"ChilliSpot-Max-Total-Octets"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticPortalProfile,
			Label:              "Portal Profile",
			Description:        "Selects a guest or captive portal experience from AAA or policy state.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound"},
			ProductAttribute:   "AegisNAS-Portal-Profile",
			ProductNumber:      9,
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticDeviceGroup,
			Label:              "Device Group",
			Description:        "Groups endpoints for IoT, printer, camera, voice, or BYOD policy routing.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound"},
			ProductAttribute:   "AegisNAS-Device-Group",
			ProductNumber:      10,
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticTenant,
			Label:              "Tenant",
			Description:        "Carries tenant context for delegated admin, reporting, and policy isolation.",
			ValueType:          "string",
			Directions:         []string{"inbound", "outbound", "accounting"},
			ProductAttribute:   "AegisNAS-Tenant",
			ProductNumber:      11,
			HardwareScope:      "branch and enterprise first; readable on lite",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticDownloadBandwidth,
			Label:              "Download Bandwidth",
			Description:        "Normalizes vendor bandwidth-rate hints into AegisNAS shaping profiles.",
			ValueType:          "rate",
			Directions:         []string{"inbound", "outbound"},
			StandardAttributes: []string{"WISPr-Bandwidth-Max-Down", "Mikrotik-Rate-Limit"},
			HardwareScope:      "branch and enterprise preferred",
			CompatibilityState: "planned",
			NextStep:           "vendor compatibility packs should map per-vendor rate attributes into bandwidth_profile",
		},
		{
			Key:                VendorSemanticUploadBandwidth,
			Label:              "Upload Bandwidth",
			Description:        "Normalizes vendor upstream-rate hints into AegisNAS shaping profiles.",
			ValueType:          "rate",
			Directions:         []string{"inbound", "outbound"},
			StandardAttributes: []string{"WISPr-Bandwidth-Max-Up", "Mikrotik-Rate-Limit"},
			HardwareScope:      "branch and enterprise preferred",
			CompatibilityState: "planned",
			NextStep:           "vendor compatibility packs should map per-vendor rate attributes into bandwidth_profile",
		},
		{
			Key:                VendorSemanticACL,
			Label:              "ACL",
			Description:        "Represents static permit, deny, redirect, and quarantine rule intent in a vendor-neutral policy form.",
			ValueType:          "policy",
			Directions:         []string{"outbound"},
			StandardAttributes: []string{"Filter-Id", "NAS-Filter-Rule"},
			HardwareScope:      "branch and enterprise preferred",
			CompatibilityState: "implemented",
			NextStep:           "persist reusable ACL policies and connect controller-specific adapters",
		},
		{
			Key:                VendorSemanticDynamicACL,
			Label:              "Dynamic ACL",
			Description:        "Represents downloadable or dynamic ACL payloads where a vendor supports device-side enforcement.",
			ValueType:          "policy",
			Directions:         []string{"outbound"},
			ProductAttribute:   "AegisNAS-ACL-Rule",
			ProductNumber:      13,
			StandardAttributes: []string{"NAS-Filter-Rule", "Cisco-AVPair"},
			HardwareScope:      "enterprise first",
			CompatibilityState: "implemented",
			NextStep:           "add persisted ACL policy library and real hardware smoke tests per vendor",
		},
		{
			Key:                VendorSemanticAccountingIdentity,
			Label:              "Accounting Identity",
			Description:        "Normalizes user, MAC, NAS, called station, session ID, and class identifiers across vendors.",
			ValueType:          "record",
			Directions:         []string{"accounting"},
			StandardAttributes: []string{"User-Name", "Calling-Station-Id", "Called-Station-Id", "NAS-Identifier", "Acct-Session-Id", "Class"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticAccountingCounters,
			Label:              "Accounting Counters",
			Description:        "Normalizes packet, octet, terminate-cause, and session-time counters into operational history.",
			ValueType:          "record",
			Directions:         []string{"accounting"},
			StandardAttributes: []string{"Acct-Input-Octets", "Acct-Output-Octets", "Acct-Input-Gigawords", "Acct-Output-Gigawords", "Acct-Session-Time", "Acct-Terminate-Cause"},
			HardwareScope:      "all profiles; retention can be reduced on lite",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticCoAReauth,
			Label:              "CoA Reauthentication",
			Description:        "Represents the intent to force a client reauthentication after role, VLAN, or policy change.",
			ValueType:          "action",
			Directions:         []string{"inbound"},
			StandardAttributes: []string{"CoA-Request"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticCoADisconnect,
			Label:              "Disconnect",
			Description:        "Represents the intent to terminate a live session from RADIUS dynamic authorization.",
			ValueType:          "action",
			Directions:         []string{"inbound"},
			StandardAttributes: []string{"Disconnect-Request"},
			HardwareScope:      "all profiles",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticControllerPolicySync,
			Label:              "Controller Policy Sync",
			Description:        "Maps AegisNAS policy state into controller-native profiles, groups, or WLAN/site assignments.",
			ValueType:          "sync",
			Directions:         []string{"outbound"},
			HardwareScope:      "branch and enterprise preferred",
			CompatibilityState: "planned",
			NextStep:           "tie semantic registry to controller adapter capability declarations",
		},
		{
			Key:                VendorSemanticControllerHealth,
			Label:              "Controller Health",
			Description:        "Normalizes controller adapter health, drift, and sync errors for reporting.",
			ValueType:          "record",
			Directions:         []string{"inbound"},
			HardwareScope:      "branch and enterprise preferred",
			CompatibilityState: "planned",
			NextStep:           "add per-adapter health counters and drift status",
		},
		{
			Key:                VendorSemanticDevicePosture,
			Label:              "Device Posture",
			Description:        "Carries compliance, risk, or health state from profiling and MDM sources into access policy.",
			ValueType:          "state",
			Directions:         []string{"inbound", "outbound"},
			HardwareScope:      "enterprise first",
			CompatibilityState: "planned",
			NextStep:           "map posture source outputs into role, quarantine, and ACL semantics",
		},
		{
			Key:                VendorSemanticGuestLifecycle,
			Label:              "Guest Lifecycle",
			Description:        "Represents guest invite, approval, redemption, expiry, and sponsor state for reporting and policy.",
			ValueType:          "record",
			Directions:         []string{"inbound"},
			HardwareScope:      "all profiles; analytics depth can be reduced on lite",
			CompatibilityState: "implemented",
		},
		{
			Key:                VendorSemanticCertificateOnboarding,
			Label:              "Certificate Onboarding",
			Description:        "Represents EAP-TLS enrollment and certificate lifecycle state for BYOD flows.",
			ValueType:          "record",
			Directions:         []string{"inbound", "outbound"},
			HardwareScope:      "enterprise first",
			CompatibilityState: "planned",
			NextStep:           "tie certificate inventory, revocation, and EAP-TLS policy into vendor packs",
		},
	}
}

func AegisNASVendorCompatibilityReport() VendorCompatibilityReport {
	catalog := AegisNASVendorDictionaryCatalog()
	semantics := AegisNASSemanticRegistry()
	packs := AegisNASVendorCompatibilityPacks()
	identity := AegisNASVendorIdentity()
	summary := VendorCompatibilitySummary{
		ProductVendorName:                  identity.Name,
		ProductVendorID:                    identity.ID,
		ProductVendorIDSource:              identity.IDSource,
		ProductVendorIDPlaceholder:         identity.Placeholder,
		ProductVendorDictionaryFilename:    identity.DictionaryFilename,
		ProductVendorDictionaryInstallPath: identity.InstallPath,
		ProductVendorDictionaryInclude:     identity.IncludeLine,
		ProductVendorPENRegistryURL:        identity.RegistryURL,
		ProductVendorPENApplyURL:           identity.ApplyURL,
		SemanticCount:                      len(semantics),
		PackCount:                          len(packs),
		HardwareProfiles:                   []string{"lite", "branch", "enterprise", "custom"},
	}
	if vendor, ok := catalog.VendorByName(identity.Name); ok {
		summary.ProductVendorID = vendor.ID
		summary.ProductVendorName = vendor.Name
		summary.ProductAttributeCount = len(vendor.Attributes)
	}
	for _, semantic := range semantics {
		switch semantic.CompatibilityState {
		case "implemented":
			summary.ImplementedCount++
		default:
			summary.PlannedCount++
		}
	}
	report := VendorCompatibilityReport{
		Catalog:            catalog,
		Semantics:          semantics,
		Packs:              packs,
		ActivePacks:        DefaultVendorCompatibilityPackKeys(),
		DictionaryCoverage: BuildVendorDictionaryCoverageReport(catalog, packs, DefaultVendorCompatibilityPackKeys()),
		Summary:            summary,
		Notes: []string{
			"FreeRADIUS dictionaries identify attributes; AegisNAS semantics define product behavior.",
			"Compatibility packs should map vendor-specific attributes into these semantic keys instead of hard-coding vendor behavior.",
			"Lite hardware should prefer local parsing, standards-based replies, short retention, and external AP or switch enforcement.",
		},
	}
	if len(identity.Warnings) > 0 {
		report.Notes = append(report.Notes, identity.Warnings...)
	}
	return report
}
