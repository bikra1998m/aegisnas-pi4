package radius

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

// ReplyAttributes contains RADIUS reply attributes for a user.
type ReplyAttributes struct {
	SessionTimeout        int
	IdleTimeout           int
	TunnelType            string // "VLAN"
	TunnelMediumType      string // "IEEE-802"
	TunnelPrivateGroupID  string // VLAN ID as string
	MikrotikRateLimit     string // MikroTik specific, but widely used
	WISPrBandwidthMaxDown int
	WISPrBandwidthMaxUp   int
}

// GetReplyAttributes retrieves attributes based on user role.
func GetReplyAttributes(username, role string) (*ReplyAttributes, error) {
	if db.DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var (
		vlan      sql.NullInt32
		bwProfile sql.NullString
		sessionTO sql.NullInt32
		idleTO    sql.NullInt32
	)

	err := db.DB.QueryRow(`SELECT vlan, bandwidth_profile, session_timeout, idle_timeout
		FROM roles WHERE name = ?`, role).Scan(&vlan, &bwProfile, &sessionTO, &idleTO)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role %s not found", role)
		}
		return nil, err
	}

	attrs := &ReplyAttributes{}
	if vlan.Valid {
		attrs.TunnelType = "VLAN"
		attrs.TunnelMediumType = "IEEE-802"
		attrs.TunnelPrivateGroupID = fmt.Sprintf("%d", vlan.Int32)
	}
	if sessionTO.Valid {
		attrs.SessionTimeout = int(sessionTO.Int32)
	}
	if idleTO.Valid {
		attrs.IdleTimeout = int(idleTO.Int32)
	}
	if bwProfile.Valid {
		// Retrieve bandwidth profile details
		var down, up int
		err = db.DB.QueryRow(`SELECT download_rate_kbps, upload_rate_kbps FROM bandwidth_profiles WHERE name = ?`,
			bwProfile.String).Scan(&down, &up)
		if err == nil {
			attrs.MikrotikRateLimit = fmt.Sprintf("%dk/%dk", down, up)
			attrs.WISPrBandwidthMaxDown = down
			attrs.WISPrBandwidthMaxUp = up
		}
	}
	return attrs, nil
}

// RenderReplyAttributes generates the FreeRADIUS reply items.
func RenderReplyAttributes(attrs *ReplyAttributes) string {
	var sb strings.Builder
	if attrs.SessionTimeout > 0 {
		sb.WriteString(fmt.Sprintf("\tSession-Timeout = %d\n", attrs.SessionTimeout))
	}
	if attrs.IdleTimeout > 0 {
		sb.WriteString(fmt.Sprintf("\tIdle-Timeout = %d\n", attrs.IdleTimeout))
	}
	if attrs.TunnelPrivateGroupID != "" {
		sb.WriteString(fmt.Sprintf("\tTunnel-Type = %s\n", attrs.TunnelType))
		sb.WriteString(fmt.Sprintf("\tTunnel-Medium-Type = %s\n", attrs.TunnelMediumType))
		sb.WriteString(fmt.Sprintf("\tTunnel-Private-Group-Id = \"%s\"\n", attrs.TunnelPrivateGroupID))
	}
	if attrs.MikrotikRateLimit != "" {
		sb.WriteString(fmt.Sprintf("\tMikrotik-Rate-Limit = \"%s\"\n", attrs.MikrotikRateLimit))
	}
	if attrs.WISPrBandwidthMaxDown > 0 {
		sb.WriteString(fmt.Sprintf("\tWISPr-Bandwidth-Max-Down = %d\n", attrs.WISPrBandwidthMaxDown))
	}
	if attrs.WISPrBandwidthMaxUp > 0 {
		sb.WriteString(fmt.Sprintf("\tWISPr-Bandwidth-Max-Up = %d\n", attrs.WISPrBandwidthMaxUp))
	}
	return sb.String()
}
