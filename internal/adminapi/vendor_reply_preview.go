package adminapi

import (
	"net/http"
	"strconv"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

type vendorReplyPreviewRequest struct {
	NASType               string           `json:"nas_type"`
	CompatibilityPacks    []string         `json:"compatibility_packs"`
	Role                  string           `json:"role"`
	BandwidthProfile      string           `json:"bandwidth_profile"`
	FilterID              string           `json:"filter_id"`
	PolicyTag             string           `json:"policy_tag"`
	SessionTimeout        int              `json:"session_timeout"`
	IdleTimeout           int              `json:"idle_timeout"`
	VLAN                  int              `json:"vlan"`
	DownloadKbps          int              `json:"download_kbps"`
	UploadKbps            int              `json:"upload_kbps"`
	MikrotikRateLimit     string           `json:"mikrotik_rate_limit"`
	WISPrBandwidthMaxDown int              `json:"wispr_bandwidth_max_down"`
	WISPrBandwidthMaxUp   int              `json:"wispr_bandwidth_max_up"`
	HasQuarantine         bool             `json:"has_quarantine"`
	Quarantine            bool             `json:"quarantine"`
	PortalProfile         string           `json:"portal_profile"`
	DeviceGroup           string           `json:"device_group"`
	Tenant                string           `json:"tenant"`
	ACLPolicyName         string           `json:"acl_policy_name"`
	InboundACL            string           `json:"inbound_acl"`
	OutboundACL           string           `json:"outbound_acl"`
	ACLRules              []radius.ACLRule `json:"acl_rules"`
}

type vendorReplyPreviewResponse struct {
	NASType            string                              `json:"nas_type"`
	KnownPack          bool                                `json:"known_pack"`
	UsesGlobalPacks    bool                                `json:"uses_global_packs"`
	EffectivePacks     []string                            `json:"effective_packs"`
	Attributes         []vendorReplyPreviewAttributeItem   `json:"attributes"`
	FreeRADIUS         string                              `json:"freeradius"`
	NormalizedACLRules []radius.ACLRule                    `json:"normalized_acl_rules,omitempty"`
	ACLExports         []radius.ACLVendorExport            `json:"acl_exports,omitempty"`
	Warnings           []string                            `json:"warnings,omitempty"`
	Semantics          []vendorReplyPreviewSemanticMapping `json:"semantics,omitempty"`
}

type vendorReplyPreviewAttributeItem struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Quoted bool   `json:"quoted"`
}

type vendorReplyPreviewSemanticMapping struct {
	Semantic  string `json:"semantic"`
	Attribute string `json:"attribute"`
	Pack      string `json:"pack"`
}

func HandlePreviewVendorReply(w http.ResponseWriter, r *http.Request) {
	var req vendorReplyPreviewRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateVendorReplyPreviewRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	vendor := config.RadiusVendorConfig{}
	if cfg != nil {
		vendor = cfg.Radius.Vendor
	}
	if len(req.CompatibilityPacks) > 0 {
		vendor.CompatibilityPacks = req.CompatibilityPacks
	}

	nasType := radius.NormalizeClientNASType(req.NASType)
	effectivePacks := radius.ReplyCompatibilityPacksForNASType(vendor, nasType)
	attrs := vendorReplyPreviewAttributes(req)
	items := radius.BuildReplyAttributeItems(attrs, effectivePacks)
	normalizedACLRules, _ := radius.NormalizeACLRules(attrs.ACLRules)

	warnings := vendorReplyPreviewWarnings(req, nasType, effectivePacks)
	writeJSON(w, http.StatusOK, vendorReplyPreviewResponse{
		NASType:            nasType,
		KnownPack:          productconfigs.ValidVendorCompatibilityPackKey(nasType),
		UsesGlobalPacks:    nasType == "other" || !productconfigs.ValidVendorCompatibilityPackKey(nasType),
		EffectivePacks:     effectivePacks,
		Attributes:         vendorReplyPreviewItems(items),
		FreeRADIUS:         radius.RenderReplyAttributesForPacks(attrs, effectivePacks),
		NormalizedACLRules: normalizedACLRules,
		ACLExports:         radius.BuildACLVendorExports(attrs.ACLPolicyName, attrs.InboundACL, attrs.OutboundACL, attrs.ACLRules, effectivePacks),
		Warnings:           warnings,
		Semantics:          vendorReplyPreviewSemantics(effectivePacks),
	})
}

func validateVendorReplyPreviewRequest(req vendorReplyPreviewRequest) error {
	for _, pack := range req.CompatibilityPacks {
		key := productconfigs.NormalizeVendorCompatibilityPackKey(pack)
		if key == "" {
			return errVendorReplyPreview("compatibility_packs cannot include empty values")
		}
		if !productconfigs.ValidVendorCompatibilityPackKey(key) {
			return errVendorReplyPreview("compatibility_packs includes unknown pack " + strings.TrimSpace(pack))
		}
	}
	switch {
	case req.SessionTimeout < 0:
		return errVendorReplyPreview("session_timeout cannot be negative")
	case req.IdleTimeout < 0:
		return errVendorReplyPreview("idle_timeout cannot be negative")
	case req.VLAN < 0:
		return errVendorReplyPreview("vlan cannot be negative")
	case req.DownloadKbps < 0:
		return errVendorReplyPreview("download_kbps cannot be negative")
	case req.UploadKbps < 0:
		return errVendorReplyPreview("upload_kbps cannot be negative")
	case req.WISPrBandwidthMaxDown < 0:
		return errVendorReplyPreview("wispr_bandwidth_max_down cannot be negative")
	case req.WISPrBandwidthMaxUp < 0:
		return errVendorReplyPreview("wispr_bandwidth_max_up cannot be negative")
	case len(req.ACLRules) > 64:
		return errVendorReplyPreview("acl_rules cannot contain more than 64 rules")
	}
	if err := radius.ValidateACLRules(req.ACLRules); err != nil {
		return errVendorReplyPreview(err.Error())
	}
	return nil
}

type errVendorReplyPreview string

func (e errVendorReplyPreview) Error() string {
	return string(e)
}

func vendorReplyPreviewAttributes(req vendorReplyPreviewRequest) *radius.ReplyAttributes {
	attrs := &radius.ReplyAttributes{
		Role:                  strings.TrimSpace(req.Role),
		BandwidthProfile:      strings.TrimSpace(req.BandwidthProfile),
		FilterID:              strings.TrimSpace(req.FilterID),
		PolicyTag:             strings.TrimSpace(req.PolicyTag),
		SessionTimeout:        req.SessionTimeout,
		IdleTimeout:           req.IdleTimeout,
		VLAN:                  req.VLAN,
		MikrotikRateLimit:     strings.TrimSpace(req.MikrotikRateLimit),
		WISPrBandwidthMaxDown: req.WISPrBandwidthMaxDown,
		WISPrBandwidthMaxUp:   req.WISPrBandwidthMaxUp,
		HasQuarantine:         req.HasQuarantine,
		Quarantine:            req.Quarantine,
		PortalProfile:         strings.TrimSpace(req.PortalProfile),
		DeviceGroup:           strings.TrimSpace(req.DeviceGroup),
		Tenant:                strings.TrimSpace(req.Tenant),
		ACLPolicyName:         strings.TrimSpace(req.ACLPolicyName),
		InboundACL:            strings.TrimSpace(req.InboundACL),
		OutboundACL:           strings.TrimSpace(req.OutboundACL),
		ACLRules:              append([]radius.ACLRule(nil), req.ACLRules...),
	}
	if attrs.VLAN > 0 {
		attrs.TunnelType = "VLAN"
		attrs.TunnelMediumType = "IEEE-802"
		attrs.TunnelPrivateGroupID = intString(attrs.VLAN)
	}
	if attrs.MikrotikRateLimit == "" && req.DownloadKbps > 0 && req.UploadKbps > 0 {
		attrs.MikrotikRateLimit = intString(req.DownloadKbps) + "k/" + intString(req.UploadKbps) + "k"
	}
	if attrs.WISPrBandwidthMaxDown == 0 {
		attrs.WISPrBandwidthMaxDown = req.DownloadKbps
	}
	if attrs.WISPrBandwidthMaxUp == 0 {
		attrs.WISPrBandwidthMaxUp = req.UploadKbps
	}
	return attrs
}

func intString(value int) string {
	return strconv.Itoa(value)
}

func vendorReplyPreviewItems(items []radius.ReplyAttributeItem) []vendorReplyPreviewAttributeItem {
	out := make([]vendorReplyPreviewAttributeItem, 0, len(items))
	for _, item := range items {
		out = append(out, vendorReplyPreviewAttributeItem{
			Name:   item.Name,
			Value:  item.Value,
			Quoted: item.Quoted,
		})
	}
	return out
}

func vendorReplyPreviewWarnings(req vendorReplyPreviewRequest, nasType string, effectivePacks []string) []string {
	var warnings []string
	if strings.TrimSpace(req.NASType) != "" && nasType == "other" && !strings.EqualFold(strings.TrimSpace(req.NASType), "other") {
		warnings = append(warnings, "NAS type was normalized to other")
	}
	if !productconfigs.ValidVendorCompatibilityPackKey(nasType) && nasType != "other" {
		warnings = append(warnings, "unknown NAS type uses global compatibility packs")
	}
	if len(effectivePacks) == 0 {
		warnings = append(warnings, "no effective compatibility packs selected")
	}
	return warnings
}

func vendorReplyPreviewSemantics(packKeys []string) []vendorReplyPreviewSemanticMapping {
	var out []vendorReplyPreviewSemanticMapping
	for _, packKey := range packKeys {
		pack, ok := productconfigs.VendorCompatibilityPackByKey(packKey)
		if !ok {
			continue
		}
		for _, attr := range pack.Attributes {
			if attr.Direction != "outbound_reply" || attr.CompatibilityState != "implemented" {
				continue
			}
			out = append(out, vendorReplyPreviewSemanticMapping{
				Semantic:  attr.Semantic,
				Attribute: attr.Attribute,
				Pack:      pack.Key,
			})
		}
	}
	return out
}
