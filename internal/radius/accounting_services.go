package radius

import (
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const AccountingServicesSchemaVersion = 1

type AccountingServicesPolicy struct {
	SchemaVersion                int  `json:"schema_version"`
	Enabled                      bool `json:"enabled"`
	CorrelateSubscriberChains    bool `json:"correlate_subscriber_chains"`
	DeriveFromClass              bool `json:"derive_from_class"`
	DeriveFromAcctMultiSessionID bool `json:"derive_from_acct_multi_session_id"`
	RetainUnmatched              bool `json:"retain_unmatched"`
	RetentionDays                int  `json:"retention_days"`
	MaxRecentServices            int  `json:"max_recent_services"`
}

type AccountingServicesReport struct {
	SchemaVersion int                                     `json:"schema_version"`
	Enabled       bool                                    `json:"enabled"`
	Status        string                                  `json:"status"`
	Message       string                                  `json:"message"`
	Policy        AccountingServicesPolicy                `json:"policy"`
	Summary       db.AccountingServiceCorrelationSummary  `json:"summary"`
	Recent        []db.AccountingServiceCorrelationRecord `json:"recent,omitempty"`
	Attributes    []string                                `json:"attributes"`
	Vendors       []string                                `json:"vendors"`
	RFCs          []string                                `json:"rfcs"`
	Guarantees    []string                                `json:"guarantees"`
	Warnings      []string                                `json:"warnings,omitempty"`
}

func EffectiveAccountingServicesPolicy(cfg *config.Config) AccountingServicesPolicy {
	policy := AccountingServicesPolicy{SchemaVersion: AccountingServicesSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingServicesConfig(cfg.Radius.AccountingServices)
	policy.Enabled = raw.Enabled
	policy.CorrelateSubscriberChains = raw.CorrelateSubscriberChains
	policy.DeriveFromClass = raw.DeriveFromClass
	policy.DeriveFromAcctMultiSessionID = raw.DeriveFromAcctMultiSessionID
	policy.RetainUnmatched = raw.RetainUnmatched
	policy.RetentionDays = raw.RetentionDays
	policy.MaxRecentServices = raw.MaxRecentServices
	return policy
}

func BuildAccountingServicesReport(cfg *config.Config) AccountingServicesReport {
	policy := EffectiveAccountingServicesPolicy(cfg)
	report := AccountingServicesReport{
		SchemaVersion: AccountingServicesSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "Multi-service accounting correlation is disabled.",
		Policy:        policy,
		Attributes: []string{
			"Acct-Multi-Session-Id",
			"Acct-Link-Count",
			"Service-Type",
			"Framed-Protocol",
			"Class",
			"Vendor-Specific call, bearer, APN, and service identifiers",
		},
		Vendors: []string{
			"Juniper ERX",
			"Nokia SR",
			"Huawei",
			"Starent/Cisco ASR",
			"Ericsson",
			"BroadSoft",
			"Acme Packet",
			"Cisco voice and VPN",
			"BNG/BRAS",
			"mobile packet core",
		},
		RFCs: []string{"RFC 2865", "RFC 2866", "RFC 5080"},
		Guarantees: []string{
			"accounting events are normalized into parent and child service-leg correlations",
			"Acct-Multi-Session-Id and Acct-Link-Count are preserved for multi-link and parent session joins",
			"Class metadata and Aegis service-chain accounting classes can bind packet accounting to activated policy services",
			"voice call legs, mobile bearers, VPN legs, reauthorization legs, and primary data sessions have distinct normalized categories",
			"correlation conflicts are retained as evidence instead of silently overwriting active service ownership",
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
		report.Message = "Database is not initialized; accounting service correlations cannot be inspected."
		return report
	}
	summary, err := db.GetAccountingServiceCorrelationSummary()
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	recentLimit := policy.MaxRecentServices
	if recentLimit <= 0 {
		recentLimit = 25
	}
	recent, err := db.ListAccountingServiceCorrelations(recentLimit, "", "")
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	report.Recent = recent
	switch {
	case !policy.CorrelateSubscriberChains && !policy.DeriveFromClass && !policy.DeriveFromAcctMultiSessionID:
		report.Status = "blocked"
		report.Message = "Multi-service correlation is enabled without any correlation source."
	case summary.ConflictCorrelations > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Multi-service accounting has %d active conflict correlation(s).", summary.ConflictCorrelations)
	case summary.CorrelationRows == 0:
		report.Status = "ready"
		report.Message = "Multi-service accounting correlation is active with no recorded service-leg evidence yet."
	default:
		report.Status = "ready"
		report.Message = "Multi-service accounting correlation is active."
	}
	if summary.UnmatchedCorrelations > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d correlation row(s) are unmatched to subscriber service-chain evidence.", summary.UnmatchedCorrelations))
	}
	if summary.LinkedSubscriberServices == 0 {
		report.Warnings = append(report.Warnings, "No accounting service legs are linked to subscriber service-chain activation evidence yet.")
	}
	if summary.AcctMultiSessionRows > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d row(s) use Acct-Multi-Session-Id parent correlation.", summary.AcctMultiSessionRows))
	}
	if summary.LastCorrelationError != "" {
		report.Warnings = append(report.Warnings, summary.LastCorrelationError)
	}
	return report
}

func PruneAccountingServiceCorrelationEvidence(cfg *config.Config, now time.Time) error {
	policy := EffectiveAccountingServicesPolicy(cfg)
	if !policy.Enabled || policy.RetentionDays <= 0 {
		return nil
	}
	return db.PruneAccountingServiceCorrelations(time.Duration(policy.RetentionDays)*24*time.Hour, now)
}
