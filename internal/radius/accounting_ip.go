package radius

import (
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const AccountingIPSchemaVersion = 1

type AccountingIPPolicy struct {
	SchemaVersion          int  `json:"schema_version"`
	Enabled                bool `json:"enabled"`
	IPv6Enabled            bool `json:"ipv6_enabled"`
	RouteAccountingEnabled bool `json:"route_accounting_enabled"`
	DelegatedPrefixEnabled bool `json:"delegated_prefix_enabled"`
	RejectInvalid          bool `json:"reject_invalid"`
	RetentionDays          int  `json:"retention_days"`
}

type AccountingIPReport struct {
	SchemaVersion int                               `json:"schema_version"`
	Enabled       bool                              `json:"enabled"`
	Status        string                            `json:"status"`
	Message       string                            `json:"message"`
	Policy        AccountingIPPolicy                `json:"policy"`
	Summary       db.AccountingIPAssignmentSummary  `json:"summary"`
	Recent        []db.AccountingIPAssignmentRecord `json:"recent,omitempty"`
	Attributes    []string                          `json:"attributes"`
	Vendors       []string                          `json:"vendors"`
	RFCs          []string                          `json:"rfcs"`
	Guarantees    []string                          `json:"guarantees"`
	Warnings      []string                          `json:"warnings,omitempty"`
}

func EffectiveAccountingIPPolicy(cfg *config.Config) AccountingIPPolicy {
	policy := AccountingIPPolicy{SchemaVersion: AccountingIPSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingIPConfig(cfg.Radius.AccountingIP)
	policy.Enabled = raw.Enabled
	policy.IPv6Enabled = raw.IPv6Enabled
	policy.RouteAccountingEnabled = raw.RouteAccountingEnabled
	policy.DelegatedPrefixEnabled = raw.DelegatedPrefixEnabled
	policy.RejectInvalid = raw.RejectInvalid
	policy.RetentionDays = raw.RetentionDays
	return policy
}

func BuildAccountingIPReport(cfg *config.Config) AccountingIPReport {
	policy := EffectiveAccountingIPPolicy(cfg)
	report := AccountingIPReport{
		SchemaVersion: AccountingIPSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "IPv6, delegated-prefix, and route accounting is disabled.",
		Policy:        policy,
		Attributes: []string{
			"Framed-IP-Address",
			"Framed-IPv6-Address",
			"Framed-IPv6-Prefix",
			"Framed-Interface-Id",
			"Delegated-IPv6-Prefix",
			"Framed-Route",
			"Framed-IPv6-Route",
		},
		Vendors: []string{"Standard RADIUS", "Cisco", "Juniper ERX", "Huawei", "Nokia", "BNG/BRAS", "3GPP"},
		RFCs:    []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 6911"},
		Guarantees: []string{
			"IPv4 and IPv6 address attributes are canonicalized before storage",
			"framed and delegated IPv6 prefixes are validated and mirrored to sessions and radacct",
			"IPv4 and IPv6 route destinations are parsed and preserved as ordered route lists",
			"invalid assignment evidence is visible through API, UI, support bundle, and readiness checks",
		},
	}
	if cfg == nil {
		report.Status = "blocked"
		report.Message = "Configuration is not loaded."
		return report
	}
	if !policy.Enabled {
		return report
	}
	if db.DB == nil {
		report.Status = "blocked"
		report.Message = "Database is not initialized; accounting IP assignment evidence cannot be inspected."
		return report
	}
	summary, err := db.GetAccountingIPAssignmentSummary()
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recent, err := db.ListAccountingIPAssignments(25, "", "")
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case !policy.IPv6Enabled && !policy.RouteAccountingEnabled && !policy.DelegatedPrefixEnabled:
		report.Status = "blocked"
		report.Message = "Accounting IP assignment tracking is enabled without any assignment family."
	case policy.IPv6Enabled && !policy.DelegatedPrefixEnabled:
		report.Status = "degraded"
		report.Message = "IPv6 accounting is enabled, but delegated-prefix accounting is disabled."
		report.Warnings = append(report.Warnings, "Enable delegated-prefix accounting before broadband or BNG production use.")
	case summary.InvalidRows > 0 && policy.RejectInvalid:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting IP assignment tracking has %d invalid row(s) and reject_invalid is enabled.", summary.InvalidRows)
	case summary.InvalidRows > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting IP assignment tracking has %d invalid row(s).", summary.InvalidRows)
	default:
		report.Status = "ready"
		report.Message = "IPv6, delegated-prefix, and route accounting assignment tracking is active."
	}
	if summary.AssignmentRows == 0 {
		report.Warnings = append(report.Warnings, "No accounting IP assignment events have been recorded yet.")
	}
	if summary.IPv6RouteRows > 0 || summary.IPv4RouteRows > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d IPv4 and %d IPv6 route assignment row(s) are tracked.", summary.IPv4RouteRows, summary.IPv6RouteRows))
	}
	if summary.LastValidationError != "" {
		report.Warnings = append(report.Warnings, summary.LastValidationError)
	}
	return report
}

func PruneAccountingIPAssignmentEvidence(cfg *config.Config, now time.Time) error {
	policy := EffectiveAccountingIPPolicy(cfg)
	if !policy.Enabled || policy.RetentionDays <= 0 {
		return nil
	}
	return db.PruneAccountingIPAssignments(time.Duration(policy.RetentionDays)*24*time.Hour, now)
}
