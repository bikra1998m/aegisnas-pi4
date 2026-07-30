package radius

import (
	"fmt"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const AccountingCountersSchemaVersion = 1

type AccountingCountersPolicy struct {
	SchemaVersion    int    `json:"schema_version"`
	Enabled          bool   `json:"enabled"`
	GigawordsEnabled bool   `json:"gigawords_enabled"`
	ResetDetection   bool   `json:"reset_detection_enabled"`
	MaxCounterBits   int    `json:"max_counter_bits"`
	OverflowPolicy   string `json:"overflow_policy"`
	RetentionDays    int    `json:"retention_days"`
}

type AccountingCountersReport struct {
	SchemaVersion int                         `json:"schema_version"`
	Enabled       bool                        `json:"enabled"`
	Status        string                      `json:"status"`
	Message       string                      `json:"message"`
	Policy        AccountingCountersPolicy    `json:"policy"`
	Summary       db.AccountingCounterSummary `json:"summary"`
	Attributes    []string                    `json:"attributes"`
	Vendors       []string                    `json:"vendors"`
	RFCs          []string                    `json:"rfcs"`
	Guarantees    []string                    `json:"guarantees"`
	Warnings      []string                    `json:"warnings,omitempty"`
}

func EffectiveAccountingCountersPolicy(cfg *config.Config) AccountingCountersPolicy {
	policy := AccountingCountersPolicy{SchemaVersion: AccountingCountersSchemaVersion}
	if cfg == nil {
		return policy
	}
	raw := config.EffectiveRadiusAccountingCountersConfig(cfg.Radius.AccountingCounters)
	policy.Enabled = raw.Enabled
	policy.GigawordsEnabled = raw.GigawordsEnabled
	policy.ResetDetection = raw.ResetDetectionEnabled
	policy.MaxCounterBits = raw.MaxCounterBits
	policy.OverflowPolicy = raw.OverflowPolicy
	policy.RetentionDays = raw.RetentionDays
	return policy
}

func BuildAccountingCountersReport(cfg *config.Config) AccountingCountersReport {
	policy := EffectiveAccountingCountersPolicy(cfg)
	report := AccountingCountersReport{
		SchemaVersion: AccountingCountersSchemaVersion,
		Enabled:       policy.Enabled,
		Status:        "disabled",
		Message:       "64-bit accounting counter normalization is disabled.",
		Policy:        policy,
		Attributes: []string{
			"Acct-Input-Octets",
			"Acct-Input-Gigawords",
			"Acct-Output-Octets",
			"Acct-Output-Gigawords",
		},
		Vendors: []string{"Standard RADIUS", "Cisco", "Juniper", "Huawei", "Cambium"},
		RFCs:    []string{"RFC 2866", "RFC 5080"},
		Guarantees: []string{
			"low/high 32-bit accounting octets are normalized into unsigned 64-bit totals",
			"full-width local counters are split into FreeRADIUS-compatible gigawords",
			"counter reset evidence is persisted without reducing accumulated session usage",
			"overflow state is visible through API, UI, support bundle, and readiness checks",
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
		report.Message = "Database is not initialized; accounting counter evidence cannot be inspected."
		return report
	}
	summary, err := db.GetAccountingCounterSummary()
	if err != nil {
		report.Status = "blocked"
		report.Message = err.Error()
		return report
	}
	report.Summary = summary
	switch {
	case !policy.GigawordsEnabled || policy.MaxCounterBits != 64:
		report.Status = "degraded"
		report.Message = "Accounting counters are enabled without full 64-bit gigaword support."
		report.Warnings = append(report.Warnings, "Enable radius.accounting_counters.gigawords_enabled with max_counter_bits=64 before production billing.")
	case !policy.ResetDetection:
		report.Status = "degraded"
		report.Message = "Accounting counters are enabled but reset detection is disabled."
		report.Warnings = append(report.Warnings, "Enable radius.accounting_counters.reset_detection_enabled before production billing.")
	case summary.CounterErrorRows > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("Accounting counter normalization has %d row(s) with overflow or parse errors.", summary.CounterErrorRows)
	default:
		report.Status = "ready"
		report.Message = "64-bit accounting counters and gigaword rollover normalization are active."
	}
	if summary.RolloverEvents > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d accounting event(s) used gigaword rollover normalization.", summary.RolloverEvents))
	}
	if summary.ResetEvents > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d accounting event(s) recorded counter reset evidence.", summary.ResetEvents))
	}
	return report
}

func PruneAccountingCounterEvidence(cfg *config.Config, now time.Time) error {
	policy := EffectiveAccountingCountersPolicy(cfg)
	if !policy.Enabled || policy.RetentionDays <= 0 {
		return nil
	}
	return db.PruneAccountingCounterEvidence(time.Duration(policy.RetentionDays)*24*time.Hour, now)
}
