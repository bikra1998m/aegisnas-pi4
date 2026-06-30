package radius

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// SessionPolicy is the local policy view derived from upstream RADIUS reply
// attributes plus optional identity-source mappings stored in the database.
type SessionPolicy struct {
	Role             string
	IdentitySource   string
	BandwidthProfile string
	FilterID         string
	ACLPolicyName    string
	RadiusClass      string
	VLAN             int
	SessionTimeout   int
	IdleTimeout      int
}

type radiusIdentityConfig struct {
	DefaultRole               string            `json:"default_role"`
	DefaultBandwidthProfile   string            `json:"default_bandwidth_profile"`
	FilterIDRoles             map[string]string `json:"filter_id_roles"`
	FilterIDBandwidthProfiles map[string]string `json:"filter_id_bandwidth_profiles"`
	VLANRoles                 map[string]string `json:"vlan_roles"`
	ClassRoles                map[string]string `json:"class_roles"`
}

// ResolveSessionPolicy maps an Access-Accept to local session policy.
func ResolveSessionPolicy(defaultRole string, auth *BrokerAuthResult) (*SessionPolicy, error) {
	if auth == nil {
		return nil, fmt.Errorf("auth result is required")
	}

	configs, err := loadRadiusIdentityConfigs()
	if err != nil {
		return nil, err
	}

	policy := &SessionPolicy{
		Role:           strings.TrimSpace(auth.VendorRole),
		IdentitySource: "radius",
		FilterID:       strings.TrimSpace(auth.FilterID),
		RadiusClass:    strings.TrimSpace(auth.Class),
	}
	if policy.FilterID == "" {
		policy.FilterID = strings.TrimSpace(auth.VendorPolicyTag)
	}
	if auth.HasVendorQuarantine && auth.VendorQuarantine && policy.FilterID == "" {
		policy.FilterID = "quarantine"
	}
	policy.ACLPolicyName = resolveInboundACLPolicyName(auth.VendorInboundACL, auth.VendorOutboundACL)
	policy.BandwidthProfile = strings.TrimSpace(auth.VendorBandwidthProfile)

	var identityDefaultRole string
	var identityDefaultBandwidthProfile string
	for _, cfg := range configs {
		if identityDefaultRole == "" {
			identityDefaultRole = strings.TrimSpace(cfg.DefaultRole)
		}
		if identityDefaultBandwidthProfile == "" {
			identityDefaultBandwidthProfile = strings.TrimSpace(cfg.DefaultBandwidthProfile)
		}
		if policy.Role == "" && policy.FilterID != "" {
			if mapped := strings.TrimSpace(cfg.FilterIDRoles[policy.FilterID]); mapped != "" {
				policy.Role = mapped
			}
		}
		if policy.Role == "" && policy.RadiusClass != "" {
			if mapped := strings.TrimSpace(cfg.ClassRoles[policy.RadiusClass]); mapped != "" {
				policy.Role = mapped
			}
		}
		if policy.BandwidthProfile == "" && policy.FilterID != "" {
			if mapped := strings.TrimSpace(cfg.FilterIDBandwidthProfiles[policy.FilterID]); mapped != "" {
				policy.BandwidthProfile = mapped
			}
		}
		if policy.Role == "" && auth.HasVLAN {
			if mapped := strings.TrimSpace(cfg.VLANRoles[strconv.Itoa(auth.VLAN)]); mapped != "" {
				policy.Role = mapped
			}
		}
	}

	if policy.Role == "" {
		policy.Role = identityDefaultRole
	}
	if policy.BandwidthProfile == "" {
		policy.BandwidthProfile = identityDefaultBandwidthProfile
	}

	if policy.Role == "" && policy.FilterID != "" && roleExists(policy.FilterID) {
		policy.Role = policy.FilterID
	}
	if policy.BandwidthProfile == "" && policy.FilterID != "" && bandwidthProfileExists(policy.FilterID) {
		policy.BandwidthProfile = policy.FilterID
	}

	if policy.Role == "" {
		policy.Role = strings.TrimSpace(defaultRole)
	}

	rolePolicy, err := lookupRolePolicy(policy.Role)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if rolePolicy.BandwidthProfile != "" && policy.BandwidthProfile == "" {
		policy.BandwidthProfile = rolePolicy.BandwidthProfile
	}
	if policy.ACLPolicyName == "" {
		policy.ACLPolicyName = rolePolicy.ACLPolicyName
	}
	policy.VLAN = rolePolicy.VLAN
	policy.SessionTimeout = rolePolicy.SessionTimeout
	policy.IdleTimeout = rolePolicy.IdleTimeout

	if auth.HasVLAN {
		policy.VLAN = auth.VLAN
	}
	if auth.HasVendorVLAN {
		policy.VLAN = auth.VendorVLAN
	}
	if auth.HasSessionTimeout {
		policy.SessionTimeout = auth.SessionTimeout
	}
	if auth.HasVendorSessionTimeout {
		policy.SessionTimeout = auth.VendorSessionTimeout
	}
	if auth.HasIdleTimeout {
		policy.IdleTimeout = auth.IdleTimeout
	}
	if auth.HasVendorIdleTimeout {
		policy.IdleTimeout = auth.VendorIdleTimeout
	}

	if policy.BandwidthProfile == "" && auth.WISPrBandwidthMaxDown > 0 && auth.WISPrBandwidthMaxUp > 0 {
		if matched := lookupBandwidthProfileByRates(auth.WISPrBandwidthMaxDown, auth.WISPrBandwidthMaxUp); matched != "" {
			policy.BandwidthProfile = matched
		}
	}

	return policy, nil
}

type rolePolicy struct {
	VLAN             int
	BandwidthProfile string
	ACLPolicyName    string
	SessionTimeout   int
	IdleTimeout      int
}

func lookupRolePolicy(role string) (rolePolicy, error) {
	if db.DB == nil || strings.TrimSpace(role) == "" {
		return rolePolicy{}, sql.ErrNoRows
	}
	var (
		vlan      sql.NullInt32
		bw        sql.NullString
		sessionTO sql.NullInt32
		idleTO    sql.NullInt32
		aclPolicy sql.NullString
	)
	err := db.DB.QueryRow(`SELECT vlan, bandwidth_profile, session_timeout, idle_timeout, acl_policy_name FROM roles WHERE name = ?`, role).
		Scan(&vlan, &bw, &sessionTO, &idleTO, &aclPolicy)
	if err != nil {
		return rolePolicy{}, err
	}
	out := rolePolicy{}
	if vlan.Valid {
		out.VLAN = int(vlan.Int32)
	}
	if bw.Valid {
		out.BandwidthProfile = bw.String
	}
	if sessionTO.Valid {
		out.SessionTimeout = int(sessionTO.Int32)
	}
	if idleTO.Valid {
		out.IdleTimeout = int(idleTO.Int32)
	}
	if aclPolicy.Valid {
		out.ACLPolicyName = strings.TrimSpace(aclPolicy.String)
	}
	return out, nil
}

func resolveInboundACLPolicyName(inboundACL, outboundACL string) string {
	inboundACL = strings.TrimSpace(inboundACL)
	outboundACL = strings.TrimSpace(outboundACL)
	if db.DB != nil && (inboundACL != "" || outboundACL != "") {
		var name string
		err := db.DB.QueryRow(`SELECT name FROM acl_policies
			WHERE enabled = 1 AND (name IN (?, ?) OR inbound_acl IN (?, ?) OR outbound_acl IN (?, ?))
			ORDER BY CASE WHEN name IN (?, ?) THEN 0 ELSE 1 END, name LIMIT 1`,
			inboundACL, outboundACL, inboundACL, outboundACL, inboundACL, outboundACL, inboundACL, outboundACL).Scan(&name)
		if err == nil {
			return strings.TrimSpace(name)
		}
	}
	return firstReplyValue(inboundACL, outboundACL)
}

func loadRadiusIdentityConfigs() ([]radiusIdentityConfig, error) {
	if db.DB == nil {
		return nil, nil
	}
	rows, err := db.DB.Query(`SELECT COALESCE(config, '{}') FROM identity_sources WHERE type = 'radius' AND enabled = 1 ORDER BY priority, name`)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()

	var configs []radiusIdentityConfig
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cfg radiusIdentityConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, fmt.Errorf("decode radius identity source config: %w", err)
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

func roleExists(name string) bool {
	if db.DB == nil || strings.TrimSpace(name) == "" {
		return false
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM roles WHERE name = ?`, name).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

func bandwidthProfileExists(name string) bool {
	if db.DB == nil || strings.TrimSpace(name) == "" {
		return false
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM bandwidth_profiles WHERE name = ?`, name).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

func lookupBandwidthProfileByRates(downloadKbps, uploadKbps int) string {
	if db.DB == nil || downloadKbps <= 0 || uploadKbps <= 0 {
		return ""
	}
	var name string
	err := db.DB.QueryRow(`SELECT name FROM bandwidth_profiles WHERE download_rate_kbps = ? AND upload_rate_kbps = ? LIMIT 1`,
		downloadKbps, uploadKbps).Scan(&name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}
