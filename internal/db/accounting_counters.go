package db

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const accountingCounterLow32Mask uint64 = 0xffffffff

type AccountingCounterSummary struct {
	RadAcctRows        int    `json:"radacct_rows"`
	EventRows          int    `json:"event_rows"`
	GigawordRows       int    `json:"gigaword_rows"`
	RolloverEvents     int    `json:"rollover_events"`
	ResetEvents        int    `json:"reset_events"`
	CounterErrorRows   int    `json:"counter_error_rows"`
	MaxInputOctets64   string `json:"max_input_octets_64"`
	MaxOutputOctets64  string `json:"max_output_octets_64"`
	LastCounterEventAt string `json:"last_counter_event_at,omitempty"`
	LastCounterError   string `json:"last_counter_error,omitempty"`
	LastCounterStatus  string `json:"last_counter_status,omitempty"`
}

type normalizedCounterParts struct {
	Low32     uint64
	Gigawords uint64
	Total     uint64
	Rollover  bool
	Status    string
	Error     string
}

func normalizeCounterParts(rawOctets, rawGigawords uint64) normalizedCounterParts {
	out := normalizedCounterParts{Status: "ok"}
	switch {
	case rawGigawords > accountingCounterLow32Mask:
		out.Low32 = rawOctets & accountingCounterLow32Mask
		out.Gigawords = accountingCounterLow32Mask
		out.Total = ^uint64(0)
		out.Rollover = true
		out.Status = "overflow"
		out.Error = fmt.Sprintf("gigawords value %d exceeds 32-bit high-counter range", rawGigawords)
	case rawGigawords > 0:
		out.Low32 = rawOctets & accountingCounterLow32Mask
		out.Gigawords = rawGigawords
		out.Total = (rawGigawords << 32) + out.Low32
		out.Rollover = true
		out.Status = "gigaword"
	case rawOctets > accountingCounterLow32Mask:
		out.Low32 = rawOctets & accountingCounterLow32Mask
		out.Gigawords = rawOctets >> 32
		out.Total = rawOctets
		out.Rollover = out.Gigawords > 0
		if out.Rollover {
			out.Status = "gigaword"
		}
	default:
		out.Low32 = rawOctets
		out.Total = rawOctets
	}
	return out
}

func NormalizeAccountingCounters(inputOctets, inputGigawords, outputOctets, outputGigawords uint64) (uint64, uint64, string, uint64, uint64, string, string, string, bool) {
	input := normalizeCounterParts(inputOctets, inputGigawords)
	output := normalizeCounterParts(outputOctets, outputGigawords)
	status := combineCounterStatus(input.Status, output.Status)
	errText := firstNonEmptyString(input.Error, output.Error)
	return input.Low32, input.Gigawords, strconv.FormatUint(input.Total, 10),
		output.Low32, output.Gigawords, strconv.FormatUint(output.Total, 10),
		status, errText, input.Rollover || output.Rollover
}

func uint64FromCounterText(value string) uint64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func combineCounterStatus(values ...string) string {
	status := "ok"
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "overflow":
			return "overflow"
		case "reset_detected":
			status = "reset_detected"
		case "gigaword":
			if status == "ok" {
				status = "gigaword"
			}
		}
	}
	return status
}

func GetAccountingCounterSummary() (AccountingCounterSummary, error) {
	if DB == nil {
		return AccountingCounterSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AccountingCounterSummary
	_ = DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN acctinputgigawords > 0 OR acctoutputgigawords > 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN aegis_counter_status IN ('overflow', 'error') THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(aegis_input_octets_64), '0'),
		COALESCE(MAX(aegis_output_octets_64), '0')
		FROM radacct`).Scan(&summary.RadAcctRows, &summary.GigawordRows, &summary.CounterErrorRows,
		&summary.MaxInputOctets64, &summary.MaxOutputOctets64)
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN counter_rollover_detected THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN counter_reset_detected THEN 1 ELSE 0 END), 0),
		COALESCE(MAX(event_time), ''),
		COALESCE((SELECT counter_status FROM radius_accounting_events ORDER BY event_time DESC, id DESC LIMIT 1), ''),
		COALESCE((SELECT counter_error FROM radius_accounting_events WHERE counter_error IS NOT NULL AND counter_error <> '' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_events`).Scan(&summary.EventRows, &summary.RolloverEvents,
		&summary.ResetEvents, &summary.LastCounterEventAt, &summary.LastCounterStatus, &summary.LastCounterError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return AccountingCounterSummary{}, fmt.Errorf("summarize accounting counters: %w", err)
	}
	maxInput, maxOutput := maxAccountingCounterTexts()
	if maxInput != "" {
		summary.MaxInputOctets64 = maxInput
	}
	if maxOutput != "" {
		summary.MaxOutputOctets64 = maxOutput
	}
	return summary, nil
}

func maxAccountingCounterTexts() (string, string) {
	if DB == nil {
		return "", ""
	}
	rows, err := DB.Query(`SELECT COALESCE(aegis_input_octets_64, '0'), COALESCE(aegis_output_octets_64, '0') FROM radacct`)
	if err != nil {
		return "", ""
	}
	defer rows.Close()
	var maxInput, maxOutput uint64
	for rows.Next() {
		var inputText, outputText string
		if err := rows.Scan(&inputText, &outputText); err != nil {
			continue
		}
		if parsed := uint64FromCounterText(inputText); parsed > maxInput {
			maxInput = parsed
		}
		if parsed := uint64FromCounterText(outputText); parsed > maxOutput {
			maxOutput = parsed
		}
	}
	return strconv.FormatUint(maxInput, 10), strconv.FormatUint(maxOutput, 10)
}

func PruneAccountingCounterEvidence(retention time.Duration, now time.Time) error {
	if DB == nil || retention <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := formatAccountingTime(now.Add(-retention))
	_, err := DB.Exec(`UPDATE radius_accounting_events
		SET counter_error = NULL
		WHERE counter_error IS NOT NULL AND event_time < ?`, cutoff)
	if err != nil && !tableMissing(err) {
		return fmt.Errorf("prune accounting counter evidence: %w", err)
	}
	return nil
}
