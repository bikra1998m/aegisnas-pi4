package radius

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const DynamicNASClientsSchemaVersion = 1

type DynamicNASClientReport struct {
	SchemaVersion int                               `json:"schema_version"`
	Enabled       bool                              `json:"enabled"`
	Status        string                            `json:"status"`
	Message       string                            `json:"message"`
	Policy        config.RadiusDynamicClientsConfig `json:"policy"`
	Summary       db.NASClientSummary               `json:"summary"`
	Enrollments   []db.NASClientEnrollment          `json:"enrollments,omitempty"`
	Templates     []db.NASClientCapabilityTemplate  `json:"templates,omitempty"`
	RecentEvents  []db.NASClientEvent               `json:"recent_events,omitempty"`
	Warnings      []string                          `json:"warnings,omitempty"`
	RFCs          []string                          `json:"rfcs"`
}

var (
	nasHeartbeatMu   sync.Mutex
	nasHeartbeatSeen = map[string]time.Time{}
)

func BuildDynamicNASClientReport(cfg *config.Config) DynamicNASClientReport {
	policy := config.EffectiveRadiusDynamicClientsConfig(config.RadiusDynamicClientsConfig{})
	if cfg != nil {
		policy = config.EffectiveRadiusDynamicClientsConfig(cfg.Radius.DynamicClients)
	}
	report := DynamicNASClientReport{
		SchemaVersion: DynamicNASClientsSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "ready",
		Message:       "Dynamic NAS enrollment, approval, capability templates, and lifecycle evidence are available.",
		Policy:        policy,
		RFCs:          []string{"RFC 2865", "RFC 2866", "RFC 5176", "RFC 6614"},
	}
	if !policy.Enabled {
		report.Status = "disabled"
		report.Message = "Dynamic NAS client enrollment is disabled by configuration."
		return report
	}
	if db.DB == nil {
		report.Status = "degraded"
		report.Message = "Dynamic NAS client state is unavailable because the database is not initialized."
		return report
	}
	summary, _ := db.GetNASClientSummary()
	enrollments, _ := db.ListNASClientEnrollments("", 25)
	templates, _ := db.ListNASClientCapabilityTemplates()
	events, _ := db.ListNASClientEvents(25)
	report.Summary = summary
	report.Enrollments = enrollments
	report.Templates = templates
	report.RecentEvents = events
	if summary.Status == "pending" {
		report.Status = "pending"
		report.Message = summary.Message
	}
	if strings.TrimSpace(policy.EnrollmentTokenRef) == "" {
		report.Warnings = append(report.Warnings, "Set radius.dynamic_clients.enrollment_token_ref before using bootstrap enrollment.")
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if policy.DiscoveryEnabled && len(policy.DiscoveryAllowedCIDRs) == 0 {
		report.Warnings = append(report.Warnings, "Packet discovery is enabled for all source networks; restrict radius.dynamic_clients.discovery_allowed_cidrs for production.")
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if !policy.ApprovalRequired {
		report.Warnings = append(report.Warnings, "Automatic approval is enabled; use only with strong bootstrap token controls and secret references.")
		if report.Status == "ready" {
			report.Status = "degraded"
		}
	}
	if cfg != nil && !cfg.Radius.PacketHardening.RequireKnownSource {
		report.Warnings = append(report.Warnings, "RADIUS packet hardening does not require known sources, so enrollment state is not the active source gate.")
		report.Status = "degraded"
	}
	return report
}

func RecordDynamicNASDiscovery(cfg *config.Config, remoteAddr net.Addr, direction, reason string) {
	if cfg == nil || db.DB == nil {
		return
	}
	policy := config.EffectiveRadiusDynamicClientsConfig(cfg.Radius.DynamicClients)
	if !policy.Enabled || !policy.DiscoveryEnabled {
		return
	}
	ip := remoteIP(remoteAddr)
	if ip == nil || !sourceAllowedForDynamicDiscovery(ip, policy.DiscoveryAllowedCIDRs) {
		return
	}
	source := ip.String()
	shortName := "pending-" + safeNASSourceName(source)
	capabilities := map[string]any{
		"radius": map[string]any{
			"observed_packet": true,
			"direction":       strings.TrimSpace(direction),
		},
		"discovery": map[string]any{
			"packet_hardening_reason": strings.TrimSpace(reason),
		},
	}
	_, _ = db.CreateOrRefreshNASClientEnrollment(db.NASClientEnrollmentRequest{
		SourceIP:        source,
		ShortName:       shortName,
		NASType:         policy.DefaultNASType,
		Transport:       policy.DefaultTransport,
		Capabilities:    capabilities,
		TemplateName:    policy.DefaultTemplate,
		DiscoverySource: "packet_hardening",
		LastSeenReason:  strings.TrimSpace(reason),
		ExpiresAt:       time.Now().UTC().Add(time.Duration(policy.EnrollmentTTLSeconds) * time.Second),
		Actor:           "packet-hardening",
	}, policy.MaxPending)
}

func RecordDynamicNASHeartbeat(cfg *config.Config, remoteAddr net.Addr, direction string) {
	if cfg == nil || db.DB == nil {
		return
	}
	policy := config.EffectiveRadiusDynamicClientsConfig(cfg.Radius.DynamicClients)
	if !policy.Enabled {
		return
	}
	ip := remoteIP(remoteAddr)
	if ip == nil {
		return
	}
	source := ip.String()
	now := time.Now().UTC()
	key := source + "|" + strings.TrimSpace(direction)
	nasHeartbeatMu.Lock()
	if last, ok := nasHeartbeatSeen[key]; ok && now.Sub(last) < time.Minute {
		nasHeartbeatMu.Unlock()
		return
	}
	nasHeartbeatSeen[key] = now
	nasHeartbeatMu.Unlock()
	_ = db.RecordNASClientHeartbeat(source, strings.TrimSpace(direction), now)
}

func sourceAllowedForDynamicDiscovery(ip net.IP, values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if allowed := net.ParseIP(value); allowed != nil {
			if allowed.Equal(ip) {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(value); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func safeNASSourceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(".", "-", ":", "-", "/", "-", "[", "-", "]", "-")
	value = replacer.Replace(value)
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}

func DynamicNASClientReadinessSummary(cfg *config.Config) string {
	report := BuildDynamicNASClientReport(cfg)
	if report.Summary.PendingCount > 0 {
		return fmt.Sprintf("%d dynamic NAS enrollment(s) pending approval", report.Summary.PendingCount)
	}
	return report.Message
}
