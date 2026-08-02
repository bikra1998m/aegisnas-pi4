package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const (
	AccountingChargingStatusOpen    = "open"
	AccountingChargingStatusClosed  = "closed"
	AccountingChargingStatusExpired = "expired"

	AccountingChargingRatingUnrated = "unrated"
	AccountingChargingRatingRated   = "rated"
	AccountingChargingRatingError   = "error"

	AccountingChargingExportPending    = "pending"
	AccountingChargingExportExported   = "exported"
	AccountingChargingExportSuppressed = "suppressed"
)

type AccountingChargingRatingPolicy struct {
	RatingEnabled        bool   `json:"rating_enabled"`
	DefaultPlan          string `json:"default_plan"`
	Currency             string `json:"currency"`
	InputMicrosPerGiB    int64  `json:"input_micros_per_gib"`
	OutputMicrosPerGiB   int64  `json:"output_micros_per_gib"`
	SessionMicrosPerHour int64  `json:"session_micros_per_hour"`
	MinimumChargeMicros  int64  `json:"minimum_charge_micros"`
}

type AccountingChargingRecord struct {
	ID                   int    `json:"id"`
	CDRID                string `json:"cdr_id"`
	Status               string `json:"status"`
	RatingStatus         string `json:"rating_status"`
	ExportStatus         string `json:"export_status"`
	Revision             int    `json:"revision"`
	SessionKey           string `json:"session_key"`
	CorrelationID        string `json:"correlation_id,omitempty"`
	AcctUniqueID         string `json:"acct_unique_id,omitempty"`
	AcctSessionID        string `json:"acct_session_id,omitempty"`
	AcctMultiSessionID   string `json:"acct_multi_session_id,omitempty"`
	ServiceKey           string `json:"service_key"`
	ServiceCategory      string `json:"service_category"`
	ServiceLegID         string `json:"service_leg_id"`
	BearerID             string `json:"bearer_id,omitempty"`
	CallID               string `json:"call_id,omitempty"`
	RoamingID            string `json:"roaming_id,omitempty"`
	UsernameHash         string `json:"username_hash,omitempty"`
	CallingStationHash   string `json:"calling_station_hash,omitempty"`
	Realm                string `json:"realm,omitempty"`
	NASIPAddress         string `json:"nas_ip_address,omitempty"`
	NASPortID            string `json:"nas_port_id,omitempty"`
	FramedIPAddress      string `json:"framed_ip_address,omitempty"`
	FramedIPv6Address    string `json:"framed_ipv6_address,omitempty"`
	FramedIPv6Prefix     string `json:"framed_ipv6_prefix,omitempty"`
	DelegatedIPv6Prefix  string `json:"delegated_ipv6_prefix,omitempty"`
	FramedRoute          string `json:"framed_route,omitempty"`
	FramedIPv6Route      string `json:"framed_ipv6_route,omitempty"`
	FirstEventID         string `json:"first_event_id"`
	LastEventID          string `json:"last_event_id"`
	StartTime            string `json:"start_time"`
	LastEventTime        string `json:"last_event_time"`
	StopTime             string `json:"stop_time,omitempty"`
	DurationSeconds      int64  `json:"duration_seconds"`
	InputOctets64        string `json:"input_octets_64"`
	OutputOctets64       string `json:"output_octets_64"`
	TotalOctets64        string `json:"total_octets_64"`
	RatingPlan           string `json:"rating_plan"`
	Currency             string `json:"currency"`
	InputMicrosPerGiB    int64  `json:"input_micros_per_gib"`
	OutputMicrosPerGiB   int64  `json:"output_micros_per_gib"`
	SessionMicrosPerHour int64  `json:"session_micros_per_hour"`
	MinimumChargeMicros  int64  `json:"minimum_charge_micros"`
	RatedAmountMicros    int64  `json:"rated_amount_micros"`
	ChargeableUnitsJSON  string `json:"chargeable_units_json,omitempty"`
	ExportBatchID        string `json:"export_batch_id,omitempty"`
	ExportSHA256         string `json:"export_sha256,omitempty"`
	ExportedAt           string `json:"exported_at,omitempty"`
	IntegritySHA256      string `json:"integrity_sha256"`
	LastError            string `json:"last_error,omitempty"`
	DetailsJSON          string `json:"details_json,omitempty"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
}

type AccountingChargingExport struct {
	ID                     int    `json:"id"`
	ExportID               string `json:"export_id"`
	Format                 string `json:"format"`
	Status                 string `json:"status"`
	RecordCount            int    `json:"record_count"`
	TotalAmountMicros      int64  `json:"total_amount_micros"`
	Currency               string `json:"currency"`
	Payload                string `json:"-"`
	PayloadSHA256          string `json:"payload_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	PreviousManifestSHA256 string `json:"previous_manifest_sha256,omitempty"`
	FirstCDRID             string `json:"first_cdr_id,omitempty"`
	LastCDRID              string `json:"last_cdr_id,omitempty"`
	CreatedBy              string `json:"created_by,omitempty"`
	CreatedAt              string `json:"created_at,omitempty"`
}

type AccountingChargingSummary struct {
	CDRRows              int    `json:"cdr_rows"`
	OpenRecords          int    `json:"open_records"`
	ClosedRecords        int    `json:"closed_records"`
	ExpiredRecords       int    `json:"expired_records"`
	RatedRecords         int    `json:"rated_records"`
	UnratedRecords       int    `json:"unrated_records"`
	RatingErrorRecords   int    `json:"rating_error_records"`
	PendingExportRecords int    `json:"pending_export_records"`
	ExportedRecords      int    `json:"exported_records"`
	ExportBatchRows      int    `json:"export_batch_rows"`
	IntegrityErrorRows   int    `json:"integrity_error_rows"`
	TotalInputOctets64   string `json:"total_input_octets_64"`
	TotalOutputOctets64  string `json:"total_output_octets_64"`
	TotalAmountMicros    int64  `json:"total_amount_micros"`
	LastCDRAt            string `json:"last_cdr_at,omitempty"`
	LastExportAt         string `json:"last_export_at,omitempty"`
	LastExportSHA256     string `json:"last_export_sha256,omitempty"`
	LastError            string `json:"last_error,omitempty"`
}

type AccountingChargingReconcileResult struct {
	Scanned     int    `json:"scanned"`
	Projected   int    `json:"projected"`
	Rated       int    `json:"rated"`
	Errors      int    `json:"errors"`
	LastError   string `json:"last_error,omitempty"`
	GeneratedAt string `json:"generated_at"`
}

type AccountingChargingExportResult struct {
	ExportID               string `json:"export_id,omitempty"`
	Status                 string `json:"status"`
	Message                string `json:"message"`
	Format                 string `json:"format"`
	RecordCount            int    `json:"record_count"`
	TotalAmountMicros      int64  `json:"total_amount_micros"`
	Currency               string `json:"currency"`
	PayloadSHA256          string `json:"payload_sha256,omitempty"`
	ManifestSHA256         string `json:"manifest_sha256,omitempty"`
	PreviousManifestSHA256 string `json:"previous_manifest_sha256,omitempty"`
	CreatedAt              string `json:"created_at,omitempty"`
}

type AccountingChargingRecordQuery struct {
	CDRID        string
	Status       string
	RatingStatus string
	ExportStatus string
	SessionKey   string
	ExportID     string
	Limit        int
}

func ProjectAccountingChargingRecord(ctx context.Context, event AccountingEventRecord) (AccountingChargingRecord, error) {
	if DB == nil {
		return AccountingChargingRecord{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	event = normalizeAccountingEventRecord(event)
	if event.EventID == "" || event.SessionKey == "" {
		return AccountingChargingRecord{}, fmt.Errorf("accounting event id and session key are required")
	}
	switch event.StatusType {
	case "Start", "Interim-Update", "Stop", "Accounting-Off":
	default:
		return AccountingChargingRecord{}, nil
	}
	fields := NormalizeAccountingServiceCorrelationFields(event)
	event.AcctMultiSessionID = fields.AcctMultiSessionID
	event.AcctLinkCount = fields.AcctLinkCount
	event.ParentSessionKey = fields.ParentSessionKey
	event.ServiceKey = fields.ServiceKey
	event.ServiceCategory = fields.ServiceCategory
	event.ServiceLegID = fields.ServiceLegID
	event.BearerID = fields.BearerID
	event.CallID = fields.CallID
	event.RoamingID = fields.RoamingID
	event.CorrelationID = fields.CorrelationID

	cdrID := AccountingChargingCDRID(event)
	existing, err := GetAccountingChargingRecordByCDRID(cdrID)
	if err != nil && err != sql.ErrNoRows {
		return AccountingChargingRecord{}, err
	}
	now := formatAccountingTime(time.Now().UTC())
	eventTime := normalizeAccountingTimeString(event.EventTime)
	if eventTime == "" {
		eventTime = now
	}
	startTime := accountingChargingStartTimeFromEvent(event, eventTime)
	if existing.CDRID != "" {
		startTime = minAccountingTime(existing.StartTime, startTime)
	}
	lastEventTime := eventTime
	if existing.CDRID != "" {
		lastEventTime = maxAccountingTime(existing.LastEventTime, eventTime)
	}
	stopTime := existing.StopTime
	status := firstNonEmptyString(existing.Status, AccountingChargingStatusOpen)
	if event.StatusType == "Stop" || event.StatusType == "Accounting-Off" {
		status = AccountingChargingStatusClosed
		stopTime = maxAccountingTime(stopTime, eventTime)
	}
	inputTotal := maxUint64(uint64FromCounterText(existing.InputOctets64), accountingEventInputTotal64(event))
	outputTotal := maxUint64(uint64FromCounterText(existing.OutputOctets64), accountingEventOutputTotal64(event))
	duration := maxInt64(existing.DurationSeconds, event.AcctSessionTime)
	if stopTime != "" {
		duration = maxInt64(duration, chargingDurationSeconds(startTime, stopTime))
	}
	firstEventID := firstNonEmptyString(existing.FirstEventID, event.EventID)
	if existing.CDRID != "" && normalizeAccountingTimeString(startTime) == normalizeAccountingTimeString(eventTime) {
		firstEventID = event.EventID
	}
	lastEventID := event.EventID
	if existing.CDRID != "" && normalizeAccountingTimeString(lastEventTime) != normalizeAccountingTimeString(eventTime) {
		lastEventID = existing.LastEventID
	}
	record := AccountingChargingRecord{
		CDRID:                cdrID,
		Status:               normalizeAccountingChargingStatus(status),
		RatingStatus:         firstNonEmptyString(existing.RatingStatus, AccountingChargingRatingUnrated),
		ExportStatus:         firstNonEmptyString(existing.ExportStatus, AccountingChargingExportPending),
		Revision:             existing.Revision,
		SessionKey:           event.SessionKey,
		CorrelationID:        event.CorrelationID,
		AcctUniqueID:         event.AcctUniqueID,
		AcctSessionID:        event.AcctSessionID,
		AcctMultiSessionID:   event.AcctMultiSessionID,
		ServiceKey:           firstNonEmptyString(event.ServiceKey, "primary"),
		ServiceCategory:      firstNonEmptyString(event.ServiceCategory, "primary"),
		ServiceLegID:         firstNonEmptyString(event.ServiceLegID, "primary"),
		BearerID:             event.BearerID,
		CallID:               event.CallID,
		RoamingID:            event.RoamingID,
		UsernameHash:         hashAccountingChargingIdentity(event.Username),
		CallingStationHash:   hashAccountingChargingIdentity(event.CallingStationID),
		Realm:                event.Realm,
		NASIPAddress:         event.NASIPAddress,
		NASPortID:            event.NASPortID,
		FramedIPAddress:      event.FramedIPAddress,
		FramedIPv6Address:    event.FramedIPv6Address,
		FramedIPv6Prefix:     event.FramedIPv6Prefix,
		DelegatedIPv6Prefix:  event.DelegatedIPv6Prefix,
		FramedRoute:          event.FramedRoute,
		FramedIPv6Route:      event.FramedIPv6Route,
		FirstEventID:         firstEventID,
		LastEventID:          firstNonEmptyString(lastEventID, event.EventID),
		StartTime:            startTime,
		LastEventTime:        lastEventTime,
		StopTime:             stopTime,
		DurationSeconds:      duration,
		InputOctets64:        strconv.FormatUint(inputTotal, 10),
		OutputOctets64:       strconv.FormatUint(outputTotal, 10),
		TotalOctets64:        strconv.FormatUint(saturatingAddUint64(inputTotal, outputTotal), 10),
		RatingPlan:           firstNonEmptyString(existing.RatingPlan, "standard"),
		Currency:             firstNonEmptyString(existing.Currency, "USD"),
		InputMicrosPerGiB:    existing.InputMicrosPerGiB,
		OutputMicrosPerGiB:   existing.OutputMicrosPerGiB,
		SessionMicrosPerHour: existing.SessionMicrosPerHour,
		MinimumChargeMicros:  existing.MinimumChargeMicros,
		RatedAmountMicros:    existing.RatedAmountMicros,
		ChargeableUnitsJSON:  firstNonEmptyString(existing.ChargeableUnitsJSON, "{}"),
		ExportBatchID:        existing.ExportBatchID,
		ExportSHA256:         existing.ExportSHA256,
		ExportedAt:           existing.ExportedAt,
		LastError:            "",
		DetailsJSON:          accountingChargingDetailsJSON(event, fields),
		CreatedAt:            firstNonEmptyString(existing.CreatedAt, now),
		UpdatedAt:            now,
	}
	if record.Revision <= 0 {
		record.Revision = 1
	}
	changed := existing.CDRID == "" || accountingChargingProjectionChanged(existing, record)
	if changed && existing.CDRID != "" {
		record.Revision = existing.Revision + 1
		record.RatingStatus = AccountingChargingRatingUnrated
		if existing.ExportStatus == AccountingChargingExportExported {
			record.ExportStatus = AccountingChargingExportPending
			record.ExportBatchID = ""
			record.ExportSHA256 = ""
			record.ExportedAt = ""
		}
	}
	record.IntegritySHA256 = AccountingChargingIntegritySHA256(record)
	if existing.CDRID == "" {
		if err := insertAccountingChargingRecord(ctx, record); err != nil {
			return AccountingChargingRecord{}, err
		}
	} else if err := updateAccountingChargingRecord(ctx, record); err != nil {
		return AccountingChargingRecord{}, err
	}
	return GetAccountingChargingRecordByCDRID(cdrID)
}

func ReconcileAccountingChargingFromEvents(ctx context.Context, limit int) (AccountingChargingReconcileResult, error) {
	if DB == nil {
		return AccountingChargingReconcileResult{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 || limit > 50000 {
		limit = 1000
	}
	rows, err := DB.QueryContext(ctx, accountingEventSelectSQL()+`
		WHERE apply_status = 'applied'
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		if tableMissing(err) {
			return AccountingChargingReconcileResult{GeneratedAt: formatAccountingTime(time.Now().UTC())}, nil
		}
		return AccountingChargingReconcileResult{}, fmt.Errorf("load applied accounting events for charging: %w", err)
	}
	events, err := scanAccountingEventRows(rows)
	rows.Close()
	if err != nil {
		return AccountingChargingReconcileResult{}, err
	}
	result := AccountingChargingReconcileResult{Scanned: len(events), GeneratedAt: formatAccountingTime(time.Now().UTC())}
	for _, event := range events {
		if _, err := ProjectAccountingChargingRecord(ctx, event); err != nil {
			result.Errors++
			result.LastError = err.Error()
			continue
		}
		result.Projected++
	}
	return result, nil
}

func RateAccountingChargingRecords(ctx context.Context, policy AccountingChargingRatingPolicy, limit int) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !policy.RatingEnabled {
		return 0, nil
	}
	if limit <= 0 || limit > 50000 {
		limit = 1000
	}
	policy = normalizeAccountingChargingRatingPolicy(policy)
	records, err := listAccountingChargingRecordsForRating(limit)
	if err != nil {
		return 0, err
	}
	rated := 0
	for _, record := range records {
		ratedRecord, err := rateAccountingChargingRecord(record, policy)
		if err != nil {
			_ = markAccountingChargingRatingError(ctx, record.CDRID, err.Error())
			return rated, err
		}
		if err := updateAccountingChargingRating(ctx, ratedRecord); err != nil {
			return rated, err
		}
		rated++
	}
	return rated, nil
}

func ExportAccountingChargingRecords(ctx context.Context, format string, limit int, createdBy string) (AccountingChargingExportResult, error) {
	if DB == nil {
		return AccountingChargingExportResult{}, fmt.Errorf("database not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	format = normalizeAccountingChargingExportFormat(format)
	if limit <= 0 || limit > 100000 {
		limit = 5000
	}
	records, err := listAccountingChargingRecordsForExport(limit)
	if err != nil {
		return AccountingChargingExportResult{}, err
	}
	if len(records) == 0 {
		return AccountingChargingExportResult{
			Status:  "empty",
			Message: "No closed rated charging records are pending export.",
			Format:  format,
		}, nil
	}
	payload, err := accountingChargingExportPayload(format, records)
	if err != nil {
		return AccountingChargingExportResult{}, err
	}
	payloadSHA := sha256Hex(payload)
	previousSHA, err := latestAccountingChargingManifestSHA()
	if err != nil {
		return AccountingChargingExportResult{}, err
	}
	now := time.Now().UTC()
	exportID := accountingChargingExportID(now, payloadSHA)
	totalAmount := int64(0)
	for _, record := range records {
		totalAmount = saturatingAddInt64(totalAmount, record.RatedAmountMicros)
	}
	firstCDR, lastCDR := records[0].CDRID, records[len(records)-1].CDRID
	currency := firstNonEmptyString(records[0].Currency, "USD")
	manifestSHA := accountingChargingManifestSHA(exportID, format, len(records), totalAmount, currency, payloadSHA, previousSHA, firstCDR, lastCDR)
	createdAt := formatAccountingTime(now)
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return AccountingChargingExportResult{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO radius_accounting_charging_exports (
		export_id, format, status, record_count, total_amount_micros, currency,
		payload, payload_sha256, manifest_sha256, previous_manifest_sha256,
		first_cdr_id, last_cdr_id, created_by, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		exportID, format, "complete", len(records), totalAmount, currency, string(payload),
		payloadSHA, manifestSHA, nullIfEmpty(previousSHA), firstCDR, lastCDR, nullIfEmpty(strings.TrimSpace(createdBy)), createdAt); err != nil {
		return AccountingChargingExportResult{}, fmt.Errorf("record charging export: %w", err)
	}
	for _, record := range records {
		exportedRecord := record
		exportedRecord.ExportStatus = AccountingChargingExportExported
		exportedRecord.ExportBatchID = exportID
		exportedRecord.ExportSHA256 = payloadSHA
		exportedRecord.ExportedAt = createdAt
		exportedRecord.IntegritySHA256 = AccountingChargingIntegritySHA256(exportedRecord)
		if _, err := tx.ExecContext(ctx, `INSERT INTO radius_accounting_charging_export_records (
			export_id, cdr_id, record_integrity_sha256, created_at
		) VALUES (?, ?, ?, ?)`, exportID, record.CDRID, exportedRecord.IntegritySHA256, createdAt); err != nil {
			return AccountingChargingExportResult{}, fmt.Errorf("record charging export membership: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE radius_accounting_charging_records
			SET export_status = ?, export_batch_id = ?, export_sha256 = ?, exported_at = ?, integrity_sha256 = ?, updated_at = ?
			WHERE cdr_id = ?`, AccountingChargingExportExported, exportID, payloadSHA, createdAt, exportedRecord.IntegritySHA256, createdAt, record.CDRID); err != nil {
			return AccountingChargingExportResult{}, fmt.Errorf("mark charging record exported: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return AccountingChargingExportResult{}, err
	}
	return AccountingChargingExportResult{
		ExportID:               exportID,
		Status:                 "complete",
		Message:                fmt.Sprintf("Exported %d charging record(s).", len(records)),
		Format:                 format,
		RecordCount:            len(records),
		TotalAmountMicros:      totalAmount,
		Currency:               currency,
		PayloadSHA256:          payloadSHA,
		ManifestSHA256:         manifestSHA,
		PreviousManifestSHA256: previousSHA,
		CreatedAt:              createdAt,
	}, nil
}

func GetAccountingChargingRecordByCDRID(cdrID string) (AccountingChargingRecord, error) {
	if DB == nil {
		return AccountingChargingRecord{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(accountingChargingRecordSelectSQL()+` WHERE cdr_id = ? LIMIT 1`, strings.TrimSpace(cdrID))
	if err != nil {
		return AccountingChargingRecord{}, err
	}
	defer rows.Close()
	records, err := scanAccountingChargingRecordRows(rows)
	if err != nil {
		return AccountingChargingRecord{}, err
	}
	if len(records) == 0 {
		return AccountingChargingRecord{}, sql.ErrNoRows
	}
	return records[0], nil
}

func ListAccountingChargingRecords(query AccountingChargingRecordQuery) ([]AccountingChargingRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	limit := query.Limit
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	sqlText := accountingChargingRecordSelectSQL()
	args := []any{}
	where := []string{}
	if query.CDRID = strings.TrimSpace(query.CDRID); query.CDRID != "" {
		where = append(where, "cdr_id = ?")
		args = append(args, query.CDRID)
	}
	if query.Status = strings.TrimSpace(query.Status); query.Status != "" {
		where = append(where, "status = ?")
		args = append(args, query.Status)
	}
	if query.RatingStatus = strings.TrimSpace(query.RatingStatus); query.RatingStatus != "" {
		where = append(where, "rating_status = ?")
		args = append(args, query.RatingStatus)
	}
	if query.ExportStatus = strings.TrimSpace(query.ExportStatus); query.ExportStatus != "" {
		where = append(where, "export_status = ?")
		args = append(args, query.ExportStatus)
	}
	if query.SessionKey = strings.TrimSpace(query.SessionKey); query.SessionKey != "" {
		where = append(where, "session_key = ?")
		args = append(args, query.SessionKey)
	}
	if query.ExportID = strings.TrimSpace(query.ExportID); query.ExportID != "" {
		where = append(where, "export_batch_id = ?")
		args = append(args, query.ExportID)
	}
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += ` ORDER BY datetime(last_event_time) DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := DB.Query(sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("list charging records: %w", err)
	}
	defer rows.Close()
	return scanAccountingChargingRecordRows(rows)
}

func ListAccountingChargingExports(limit int) ([]AccountingChargingExport, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := DB.Query(accountingChargingExportSelectSQL()+` ORDER BY datetime(created_at) DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list charging exports: %w", err)
	}
	defer rows.Close()
	return scanAccountingChargingExportRows(rows)
}

func GetAccountingChargingExport(exportID string) (AccountingChargingExport, error) {
	if DB == nil {
		return AccountingChargingExport{}, fmt.Errorf("database not initialized")
	}
	rows, err := DB.Query(accountingChargingExportSelectSQL()+` WHERE export_id = ? LIMIT 1`, strings.TrimSpace(exportID))
	if err != nil {
		return AccountingChargingExport{}, err
	}
	defer rows.Close()
	exports, err := scanAccountingChargingExportRows(rows)
	if err != nil {
		return AccountingChargingExport{}, err
	}
	if len(exports) == 0 {
		return AccountingChargingExport{}, sql.ErrNoRows
	}
	return exports[0], nil
}

func GetAccountingChargingSummary() (AccountingChargingSummary, error) {
	if DB == nil {
		return AccountingChargingSummary{}, fmt.Errorf("database not initialized")
	}
	var summary AccountingChargingSummary
	err := DB.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN rating_status = 'rated' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN rating_status = 'unrated' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN rating_status = 'error' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN export_status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN export_status = 'exported' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN last_error LIKE 'integrity:%' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(rated_amount_micros), 0),
		COALESCE(MAX(last_event_time), ''),
		COALESCE((SELECT last_error FROM radius_accounting_charging_records WHERE last_error IS NOT NULL AND last_error <> '' ORDER BY updated_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_charging_records`).Scan(&summary.CDRRows, &summary.OpenRecords,
		&summary.ClosedRecords, &summary.ExpiredRecords, &summary.RatedRecords,
		&summary.UnratedRecords, &summary.RatingErrorRecords, &summary.PendingExportRecords,
		&summary.ExportedRecords, &summary.IntegrityErrorRows, &summary.TotalAmountMicros,
		&summary.LastCDRAt, &summary.LastError)
	if err != nil {
		if tableMissing(err) {
			return summary, nil
		}
		return AccountingChargingSummary{}, fmt.Errorf("summarize charging records: %w", err)
	}
	_ = DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(created_at), ''), COALESCE((SELECT manifest_sha256 FROM radius_accounting_charging_exports ORDER BY created_at DESC, id DESC LIMIT 1), '')
		FROM radius_accounting_charging_exports`).Scan(&summary.ExportBatchRows, &summary.LastExportAt, &summary.LastExportSHA256)
	input, output := accountingChargingTotalOctetTexts()
	summary.TotalInputOctets64 = input
	summary.TotalOutputOctets64 = output
	return summary, nil
}

func VerifyAccountingChargingIntegrity(limit int) (int, error) {
	if DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	if limit <= 0 || limit > 100000 {
		limit = 500
	}
	records, err := ListAccountingChargingRecords(AccountingChargingRecordQuery{Limit: limit})
	if err != nil {
		return 0, err
	}
	mismatches := 0
	now := formatAccountingTime(time.Now().UTC())
	for _, record := range records {
		expected := AccountingChargingIntegritySHA256(record)
		if expected == record.IntegritySHA256 {
			continue
		}
		mismatches++
		_, _ = DB.Exec(`UPDATE radius_accounting_charging_records SET last_error = ?, updated_at = ? WHERE cdr_id = ?`,
			"integrity: stored CDR hash does not match normalized record contents", now, record.CDRID)
	}
	return mismatches, nil
}

func PruneAccountingChargingEvidence(openRetention, closedRetention, exportRetention time.Duration, now time.Time) error {
	if DB == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if openRetention > 0 {
		cutoff := formatAccountingTime(now.Add(-openRetention))
		if _, err := DB.Exec(`UPDATE radius_accounting_charging_records
			SET status = 'expired', updated_at = ?
			WHERE status = 'open' AND last_event_time < ?`, formatAccountingTime(now), cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("expire old open charging records: %w", err)
		}
	}
	if closedRetention > 0 {
		cutoff := formatAccountingTime(now.Add(-closedRetention))
		if _, err := DB.Exec(`DELETE FROM radius_accounting_charging_export_records
			WHERE cdr_id IN (
				SELECT cdr_id FROM radius_accounting_charging_records
				WHERE status IN ('closed', 'expired') AND export_status = 'exported' AND last_event_time < ?
			)`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune charging export memberships: %w", err)
		}
		if _, err := DB.Exec(`DELETE FROM radius_accounting_charging_records
			WHERE status IN ('closed', 'expired') AND export_status = 'exported' AND last_event_time < ?`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune charging records: %w", err)
		}
	}
	if exportRetention > 0 {
		cutoff := formatAccountingTime(now.Add(-exportRetention))
		if _, err := DB.Exec(`DELETE FROM radius_accounting_charging_export_records
			WHERE export_id IN (SELECT export_id FROM radius_accounting_charging_exports WHERE created_at < ?)`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune charging export membership history: %w", err)
		}
		if _, err := DB.Exec(`DELETE FROM radius_accounting_charging_exports WHERE created_at < ?`, cutoff); err != nil && !tableMissing(err) {
			return fmt.Errorf("prune charging exports: %w", err)
		}
	}
	return nil
}

func AccountingChargingCDRID(event AccountingEventRecord) string {
	event = normalizeAccountingEventRecord(event)
	fields := NormalizeAccountingServiceCorrelationFields(event)
	parts := []string{
		event.SessionKey,
		firstNonEmptyString(event.CorrelationID, fields.CorrelationID),
		firstNonEmptyString(event.AcctMultiSessionID, fields.AcctMultiSessionID),
		firstNonEmptyString(event.ServiceKey, fields.ServiceKey, "primary"),
		firstNonEmptyString(event.ServiceLegID, fields.ServiceLegID, "primary"),
		firstNonEmptyString(event.BearerID, fields.BearerID),
		firstNonEmptyString(event.CallID, fields.CallID),
		firstNonEmptyString(event.RoamingID, fields.RoamingID),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "cdr-" + hex.EncodeToString(sum[:])[:24]
}

func AccountingChargingIntegritySHA256(record AccountingChargingRecord) string {
	payload := map[string]any{
		"cdr_id":                    record.CDRID,
		"status":                    record.Status,
		"rating_status":             record.RatingStatus,
		"export_status":             record.ExportStatus,
		"revision":                  record.Revision,
		"session_key":               record.SessionKey,
		"correlation_id":            record.CorrelationID,
		"acct_unique_id":            record.AcctUniqueID,
		"acct_session_id":           record.AcctSessionID,
		"acct_multi_session_id":     record.AcctMultiSessionID,
		"service_key":               record.ServiceKey,
		"service_category":          record.ServiceCategory,
		"service_leg_id":            record.ServiceLegID,
		"bearer_id":                 record.BearerID,
		"call_id":                   record.CallID,
		"roaming_id":                record.RoamingID,
		"username_hash":             record.UsernameHash,
		"calling_station_hash":      record.CallingStationHash,
		"realm":                     record.Realm,
		"nas_ip_address":            record.NASIPAddress,
		"nas_port_id":               record.NASPortID,
		"framed_ip_address":         record.FramedIPAddress,
		"framed_ipv6_address":       record.FramedIPv6Address,
		"framed_ipv6_prefix":        record.FramedIPv6Prefix,
		"delegated_ipv6_prefix":     record.DelegatedIPv6Prefix,
		"framed_route":              record.FramedRoute,
		"framed_ipv6_route":         record.FramedIPv6Route,
		"first_event_id":            record.FirstEventID,
		"last_event_id":             record.LastEventID,
		"start_time":                normalizeAccountingTimeString(record.StartTime),
		"last_event_time":           normalizeAccountingTimeString(record.LastEventTime),
		"stop_time":                 normalizeAccountingTimeString(record.StopTime),
		"duration_seconds":          record.DurationSeconds,
		"input_octets_64":           record.InputOctets64,
		"output_octets_64":          record.OutputOctets64,
		"total_octets_64":           record.TotalOctets64,
		"rating_plan":               record.RatingPlan,
		"currency":                  record.Currency,
		"input_micros_per_gib":      record.InputMicrosPerGiB,
		"output_micros_per_gib":     record.OutputMicrosPerGiB,
		"session_micros_per_hour":   record.SessionMicrosPerHour,
		"minimum_charge_micros":     record.MinimumChargeMicros,
		"rated_amount_micros":       record.RatedAmountMicros,
		"chargeable_units_json":     record.ChargeableUnitsJSON,
		"export_batch_id":           record.ExportBatchID,
		"export_sha256":             record.ExportSHA256,
		"exported_at":               normalizeAccountingTimeString(record.ExportedAt),
		"nas_0041_schema_version":   1,
		"source_accounting_feature": "radius-accounting",
	}
	encoded, _ := json.Marshal(payload)
	return sha256Hex(encoded)
}

func insertAccountingChargingRecord(ctx context.Context, record AccountingChargingRecord) error {
	_, err := DB.ExecContext(ctx, `INSERT INTO radius_accounting_charging_records (
		cdr_id, status, rating_status, export_status, revision, session_key,
		correlation_id, acct_unique_id, acct_session_id, acct_multi_session_id,
		service_key, service_category, service_leg_id, bearer_id, call_id, roaming_id,
		username_hash, calling_station_hash, realm, nas_ip_address, nas_port_id,
		framed_ip_address, framed_ipv6_address, framed_ipv6_prefix, delegated_ipv6_prefix,
		framed_route, framed_ipv6_route, first_event_id, last_event_id, start_time,
		last_event_time, stop_time, duration_seconds, input_octets_64, output_octets_64,
		total_octets_64, rating_plan, currency, input_micros_per_gib,
		output_micros_per_gib, session_micros_per_hour, minimum_charge_micros,
		rated_amount_micros, chargeable_units_json, export_batch_id, export_sha256,
		exported_at, integrity_sha256, last_error, details_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.CDRID, record.Status, record.RatingStatus, record.ExportStatus, record.Revision, record.SessionKey,
		nullIfEmpty(record.CorrelationID), nullIfEmpty(record.AcctUniqueID), nullIfEmpty(record.AcctSessionID), nullIfEmpty(record.AcctMultiSessionID),
		record.ServiceKey, record.ServiceCategory, record.ServiceLegID, nullIfEmpty(record.BearerID), nullIfEmpty(record.CallID), nullIfEmpty(record.RoamingID),
		nullIfEmpty(record.UsernameHash), nullIfEmpty(record.CallingStationHash), nullIfEmpty(record.Realm), nullIfEmpty(record.NASIPAddress), nullIfEmpty(record.NASPortID),
		nullIfEmpty(record.FramedIPAddress), nullIfEmpty(record.FramedIPv6Address), nullIfEmpty(record.FramedIPv6Prefix), nullIfEmpty(record.DelegatedIPv6Prefix),
		nullIfEmpty(record.FramedRoute), nullIfEmpty(record.FramedIPv6Route), record.FirstEventID, record.LastEventID, record.StartTime,
		record.LastEventTime, nullIfEmpty(record.StopTime), record.DurationSeconds, record.InputOctets64, record.OutputOctets64,
		record.TotalOctets64, record.RatingPlan, record.Currency, record.InputMicrosPerGiB,
		record.OutputMicrosPerGiB, record.SessionMicrosPerHour, record.MinimumChargeMicros,
		record.RatedAmountMicros, record.ChargeableUnitsJSON, nullIfEmpty(record.ExportBatchID), nullIfEmpty(record.ExportSHA256),
		nullIfEmpty(record.ExportedAt), record.IntegritySHA256, nullIfEmpty(record.LastError), record.DetailsJSON, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert charging record: %w", err)
	}
	return nil
}

func updateAccountingChargingRecord(ctx context.Context, record AccountingChargingRecord) error {
	_, err := DB.ExecContext(ctx, `UPDATE radius_accounting_charging_records SET
		status = ?, rating_status = ?, export_status = ?, revision = ?, session_key = ?,
		correlation_id = ?, acct_unique_id = ?, acct_session_id = ?, acct_multi_session_id = ?,
		service_key = ?, service_category = ?, service_leg_id = ?, bearer_id = ?, call_id = ?, roaming_id = ?,
		username_hash = ?, calling_station_hash = ?, realm = ?, nas_ip_address = ?, nas_port_id = ?,
		framed_ip_address = ?, framed_ipv6_address = ?, framed_ipv6_prefix = ?, delegated_ipv6_prefix = ?,
		framed_route = ?, framed_ipv6_route = ?, first_event_id = ?, last_event_id = ?,
		start_time = ?, last_event_time = ?, stop_time = ?, duration_seconds = ?,
		input_octets_64 = ?, output_octets_64 = ?, total_octets_64 = ?, rating_plan = ?, currency = ?,
		input_micros_per_gib = ?, output_micros_per_gib = ?, session_micros_per_hour = ?,
		minimum_charge_micros = ?, rated_amount_micros = ?, chargeable_units_json = ?,
		export_batch_id = ?, export_sha256 = ?, exported_at = ?, integrity_sha256 = ?,
		last_error = ?, details_json = ?, updated_at = ?
		WHERE cdr_id = ?`,
		record.Status, record.RatingStatus, record.ExportStatus, record.Revision, record.SessionKey,
		nullIfEmpty(record.CorrelationID), nullIfEmpty(record.AcctUniqueID), nullIfEmpty(record.AcctSessionID), nullIfEmpty(record.AcctMultiSessionID),
		record.ServiceKey, record.ServiceCategory, record.ServiceLegID, nullIfEmpty(record.BearerID), nullIfEmpty(record.CallID), nullIfEmpty(record.RoamingID),
		nullIfEmpty(record.UsernameHash), nullIfEmpty(record.CallingStationHash), nullIfEmpty(record.Realm), nullIfEmpty(record.NASIPAddress), nullIfEmpty(record.NASPortID),
		nullIfEmpty(record.FramedIPAddress), nullIfEmpty(record.FramedIPv6Address), nullIfEmpty(record.FramedIPv6Prefix), nullIfEmpty(record.DelegatedIPv6Prefix),
		nullIfEmpty(record.FramedRoute), nullIfEmpty(record.FramedIPv6Route), record.FirstEventID, record.LastEventID,
		record.StartTime, record.LastEventTime, nullIfEmpty(record.StopTime), record.DurationSeconds,
		record.InputOctets64, record.OutputOctets64, record.TotalOctets64, record.RatingPlan, record.Currency,
		record.InputMicrosPerGiB, record.OutputMicrosPerGiB, record.SessionMicrosPerHour,
		record.MinimumChargeMicros, record.RatedAmountMicros, record.ChargeableUnitsJSON,
		nullIfEmpty(record.ExportBatchID), nullIfEmpty(record.ExportSHA256), nullIfEmpty(record.ExportedAt), record.IntegritySHA256,
		nullIfEmpty(record.LastError), record.DetailsJSON, record.UpdatedAt, record.CDRID)
	if err != nil {
		return fmt.Errorf("update charging record: %w", err)
	}
	return nil
}

func updateAccountingChargingRating(ctx context.Context, record AccountingChargingRecord) error {
	record.IntegritySHA256 = AccountingChargingIntegritySHA256(record)
	_, err := DB.ExecContext(ctx, `UPDATE radius_accounting_charging_records SET
		rating_status = ?, rating_plan = ?, currency = ?, input_micros_per_gib = ?,
		output_micros_per_gib = ?, session_micros_per_hour = ?, minimum_charge_micros = ?,
		rated_amount_micros = ?, chargeable_units_json = ?, integrity_sha256 = ?,
		last_error = NULL, updated_at = ?
		WHERE cdr_id = ?`,
		record.RatingStatus, record.RatingPlan, record.Currency, record.InputMicrosPerGiB,
		record.OutputMicrosPerGiB, record.SessionMicrosPerHour, record.MinimumChargeMicros,
		record.RatedAmountMicros, record.ChargeableUnitsJSON, record.IntegritySHA256,
		formatAccountingTime(time.Now().UTC()), record.CDRID)
	if err != nil {
		return fmt.Errorf("update charging rating: %w", err)
	}
	return nil
}

func markAccountingChargingRatingError(ctx context.Context, cdrID, message string) error {
	_, err := DB.ExecContext(ctx, `UPDATE radius_accounting_charging_records
		SET rating_status = ?, last_error = ?, updated_at = ?
		WHERE cdr_id = ?`, AccountingChargingRatingError, strings.TrimSpace(message), formatAccountingTime(time.Now().UTC()), cdrID)
	return err
}

func listAccountingChargingRecordsForRating(limit int) ([]AccountingChargingRecord, error) {
	rows, err := DB.Query(accountingChargingRecordSelectSQL()+`
		WHERE rating_status IN ('unrated', 'error')
		ORDER BY datetime(last_event_time), id
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("load charging records for rating: %w", err)
	}
	defer rows.Close()
	return scanAccountingChargingRecordRows(rows)
}

func listAccountingChargingRecordsForExport(limit int) ([]AccountingChargingRecord, error) {
	rows, err := DB.Query(accountingChargingRecordSelectSQL()+`
		WHERE status = 'closed' AND rating_status = 'rated' AND export_status = 'pending'
		ORDER BY datetime(stop_time), id
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("load charging records for export: %w", err)
	}
	defer rows.Close()
	return scanAccountingChargingRecordRows(rows)
}

func rateAccountingChargingRecord(record AccountingChargingRecord, policy AccountingChargingRatingPolicy) (AccountingChargingRecord, error) {
	inputBytes := uint64FromCounterText(record.InputOctets64)
	outputBytes := uint64FromCounterText(record.OutputOctets64)
	inputCharge := proportionalMicros(inputBytes, policy.InputMicrosPerGiB, 1<<30)
	outputCharge := proportionalMicros(outputBytes, policy.OutputMicrosPerGiB, 1<<30)
	sessionCharge := proportionalMicros(uint64(maxInt64(record.DurationSeconds, 0)), policy.SessionMicrosPerHour, 3600)
	amount := saturatingAddInt64(saturatingAddInt64(inputCharge, outputCharge), sessionCharge)
	if amount > 0 && policy.MinimumChargeMicros > amount {
		amount = policy.MinimumChargeMicros
	}
	units, _ := json.Marshal(map[string]any{
		"input_octets":             record.InputOctets64,
		"output_octets":            record.OutputOctets64,
		"duration_seconds":         record.DurationSeconds,
		"input_charge_micros":      inputCharge,
		"output_charge_micros":     outputCharge,
		"session_charge_micros":    sessionCharge,
		"minimum_charge_micros":    policy.MinimumChargeMicros,
		"rating_schema_version":    1,
		"rated_from_accounting":    true,
		"export_requires_closed":   true,
		"privacy_identity_fields":  []string{"username_hash", "calling_station_hash"},
		"rating_source_attributes": []string{"Acct-Input-Octets", "Acct-Output-Octets", "Acct-Input-Gigawords", "Acct-Output-Gigawords", "Acct-Session-Time"},
	})
	record.RatingStatus = AccountingChargingRatingRated
	record.RatingPlan = policy.DefaultPlan
	record.Currency = policy.Currency
	record.InputMicrosPerGiB = policy.InputMicrosPerGiB
	record.OutputMicrosPerGiB = policy.OutputMicrosPerGiB
	record.SessionMicrosPerHour = policy.SessionMicrosPerHour
	record.MinimumChargeMicros = policy.MinimumChargeMicros
	record.RatedAmountMicros = amount
	record.ChargeableUnitsJSON = string(units)
	return record, nil
}

func accountingChargingExportPayload(format string, records []AccountingChargingRecord) ([]byte, error) {
	switch normalizeAccountingChargingExportFormat(format) {
	case "csv":
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
		if err := writer.Write([]string{
			"cdr_id", "revision", "status", "session_key", "correlation_id", "service_key",
			"service_category", "service_leg_id", "username_hash", "calling_station_hash",
			"nas_ip_address", "start_time", "stop_time", "duration_seconds", "input_octets_64",
			"output_octets_64", "total_octets_64", "rating_plan", "currency",
			"rated_amount_micros", "integrity_sha256",
		}); err != nil {
			return nil, err
		}
		for _, record := range records {
			if err := writer.Write([]string{
				record.CDRID, strconv.Itoa(record.Revision), record.Status, record.SessionKey,
				record.CorrelationID, record.ServiceKey, record.ServiceCategory, record.ServiceLegID,
				record.UsernameHash, record.CallingStationHash, record.NASIPAddress, record.StartTime,
				record.StopTime, fmt.Sprint(record.DurationSeconds), record.InputOctets64,
				record.OutputOctets64, record.TotalOctets64, record.RatingPlan, record.Currency,
				fmt.Sprint(record.RatedAmountMicros), record.IntegritySHA256,
			}); err != nil {
				return nil, err
			}
		}
		writer.Flush()
		return buffer.Bytes(), writer.Error()
	case "json":
		payload, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(payload, '\n'), nil
	default:
		var buffer bytes.Buffer
		for _, record := range records {
			payload, err := json.Marshal(record)
			if err != nil {
				return nil, err
			}
			buffer.Write(payload)
			buffer.WriteByte('\n')
		}
		return buffer.Bytes(), nil
	}
}

func accountingChargingRecordSelectSQL() string {
	return `SELECT id, cdr_id, status, rating_status, export_status, revision, session_key,
		COALESCE(correlation_id, ''), COALESCE(acct_unique_id, ''), COALESCE(acct_session_id, ''),
		COALESCE(acct_multi_session_id, ''), service_key, service_category, service_leg_id,
		COALESCE(bearer_id, ''), COALESCE(call_id, ''), COALESCE(roaming_id, ''),
		COALESCE(username_hash, ''), COALESCE(calling_station_hash, ''), COALESCE(realm, ''),
		COALESCE(nas_ip_address, ''), COALESCE(nas_port_id, ''), COALESCE(framed_ip_address, ''),
		COALESCE(framed_ipv6_address, ''), COALESCE(framed_ipv6_prefix, ''),
		COALESCE(delegated_ipv6_prefix, ''), COALESCE(framed_route, ''), COALESCE(framed_ipv6_route, ''),
		first_event_id, last_event_id, COALESCE(CAST(start_time AS TEXT), ''),
		COALESCE(CAST(last_event_time AS TEXT), ''), COALESCE(CAST(stop_time AS TEXT), ''),
		duration_seconds, input_octets_64, output_octets_64, total_octets_64, rating_plan, currency,
		input_micros_per_gib, output_micros_per_gib, session_micros_per_hour,
		minimum_charge_micros, rated_amount_micros, chargeable_units_json,
		COALESCE(export_batch_id, ''), COALESCE(export_sha256, ''), COALESCE(CAST(exported_at AS TEXT), ''),
		integrity_sha256, COALESCE(last_error, ''), COALESCE(details_json, '{}'),
		COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
		FROM radius_accounting_charging_records`
}

func scanAccountingChargingRecordRows(rows *sql.Rows) ([]AccountingChargingRecord, error) {
	records := []AccountingChargingRecord{}
	for rows.Next() {
		var item AccountingChargingRecord
		if err := rows.Scan(
			&item.ID, &item.CDRID, &item.Status, &item.RatingStatus, &item.ExportStatus,
			&item.Revision, &item.SessionKey, &item.CorrelationID, &item.AcctUniqueID,
			&item.AcctSessionID, &item.AcctMultiSessionID, &item.ServiceKey,
			&item.ServiceCategory, &item.ServiceLegID, &item.BearerID, &item.CallID,
			&item.RoamingID, &item.UsernameHash, &item.CallingStationHash, &item.Realm,
			&item.NASIPAddress, &item.NASPortID, &item.FramedIPAddress,
			&item.FramedIPv6Address, &item.FramedIPv6Prefix, &item.DelegatedIPv6Prefix,
			&item.FramedRoute, &item.FramedIPv6Route, &item.FirstEventID,
			&item.LastEventID, &item.StartTime, &item.LastEventTime, &item.StopTime,
			&item.DurationSeconds, &item.InputOctets64, &item.OutputOctets64,
			&item.TotalOctets64, &item.RatingPlan, &item.Currency, &item.InputMicrosPerGiB,
			&item.OutputMicrosPerGiB, &item.SessionMicrosPerHour, &item.MinimumChargeMicros,
			&item.RatedAmountMicros, &item.ChargeableUnitsJSON, &item.ExportBatchID,
			&item.ExportSHA256, &item.ExportedAt, &item.IntegritySHA256, &item.LastError,
			&item.DetailsJSON, &item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, item)
	}
	return records, rows.Err()
}

func accountingChargingExportSelectSQL() string {
	return `SELECT id, export_id, format, status, record_count, total_amount_micros, currency,
		payload, payload_sha256, manifest_sha256, COALESCE(previous_manifest_sha256, ''),
		COALESCE(first_cdr_id, ''), COALESCE(last_cdr_id, ''), COALESCE(created_by, ''),
		COALESCE(CAST(created_at AS TEXT), '')
		FROM radius_accounting_charging_exports`
}

func scanAccountingChargingExportRows(rows *sql.Rows) ([]AccountingChargingExport, error) {
	exports := []AccountingChargingExport{}
	for rows.Next() {
		var item AccountingChargingExport
		if err := rows.Scan(&item.ID, &item.ExportID, &item.Format, &item.Status,
			&item.RecordCount, &item.TotalAmountMicros, &item.Currency, &item.Payload,
			&item.PayloadSHA256, &item.ManifestSHA256, &item.PreviousManifestSHA256,
			&item.FirstCDRID, &item.LastCDRID, &item.CreatedBy, &item.CreatedAt); err != nil {
			return nil, err
		}
		exports = append(exports, item)
	}
	return exports, rows.Err()
}

func accountingChargingStartTimeFromEvent(event AccountingEventRecord, eventTime string) string {
	if event.StatusType != "Start" && event.AcctSessionTime > 0 {
		parsed := parseAccountingTime(eventTime)
		if !parsed.IsZero() {
			return formatAccountingTime(parsed.Add(-time.Duration(event.AcctSessionTime) * time.Second))
		}
	}
	return eventTime
}

func chargingDurationSeconds(startTime, stopTime string) int64 {
	start := parseAccountingTime(startTime)
	stop := parseAccountingTime(stopTime)
	if start.IsZero() || stop.IsZero() || stop.Before(start) {
		return 0
	}
	return int64(stop.Sub(start).Seconds())
}

func normalizeAccountingChargingStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AccountingChargingStatusClosed:
		return AccountingChargingStatusClosed
	case AccountingChargingStatusExpired:
		return AccountingChargingStatusExpired
	default:
		return AccountingChargingStatusOpen
	}
}

func normalizeAccountingChargingRatingPolicy(policy AccountingChargingRatingPolicy) AccountingChargingRatingPolicy {
	policy.DefaultPlan = strings.TrimSpace(policy.DefaultPlan)
	if policy.DefaultPlan == "" {
		policy.DefaultPlan = "standard"
	}
	policy.Currency = strings.ToUpper(strings.TrimSpace(policy.Currency))
	if policy.Currency == "" {
		policy.Currency = "USD"
	}
	if policy.InputMicrosPerGiB < 0 {
		policy.InputMicrosPerGiB = 0
	}
	if policy.OutputMicrosPerGiB < 0 {
		policy.OutputMicrosPerGiB = 0
	}
	if policy.SessionMicrosPerHour < 0 {
		policy.SessionMicrosPerHour = 0
	}
	if policy.MinimumChargeMicros < 0 {
		policy.MinimumChargeMicros = 0
	}
	return policy
}

func normalizeAccountingChargingExportFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json", "csv":
		return strings.ToLower(strings.TrimSpace(format))
	default:
		return "jsonl"
	}
}

func accountingChargingProjectionChanged(existing, next AccountingChargingRecord) bool {
	return existing.Status != next.Status ||
		existing.LastEventID != next.LastEventID ||
		normalizeAccountingTimeString(existing.LastEventTime) != normalizeAccountingTimeString(next.LastEventTime) ||
		normalizeAccountingTimeString(existing.StopTime) != normalizeAccountingTimeString(next.StopTime) ||
		existing.DurationSeconds != next.DurationSeconds ||
		existing.InputOctets64 != next.InputOctets64 ||
		existing.OutputOctets64 != next.OutputOctets64 ||
		existing.TotalOctets64 != next.TotalOctets64 ||
		existing.ServiceKey != next.ServiceKey ||
		existing.ServiceCategory != next.ServiceCategory ||
		existing.ServiceLegID != next.ServiceLegID
}

func accountingChargingDetailsJSON(event AccountingEventRecord, fields AccountingServiceCorrelationFields) string {
	details, _ := json.Marshal(map[string]any{
		"feature":                   "NAS-0041",
		"source_event_id":           event.EventID,
		"status_type":               event.StatusType,
		"correlation_id":            fields.CorrelationID,
		"correlation_source":        fields.CorrelationSource,
		"service_key":               fields.ServiceKey,
		"service_category":          fields.ServiceCategory,
		"service_leg_id":            fields.ServiceLegID,
		"standard_attributes":       []string{"Acct-Status-Type", "Acct-Session-Id", "Acct-Unique-Session-Id", "Acct-Session-Time", "Acct-Input-Octets", "Acct-Input-Gigawords", "Acct-Output-Octets", "Acct-Output-Gigawords", "Acct-Multi-Session-Id", "Acct-Link-Count", "Class"},
		"vendor_families":           []string{"3GPP", "3GPP2", "Starent/Cisco ASR", "Ericsson", "Juniper ERX", "Nokia SR", "Huawei", "BNG/BRAS"},
		"privacy_identity_storage":  "hashed",
		"export_integrity_version":  1,
		"charging_record_lifecycle": []string{"open", "closed", "rated", "exported"},
	})
	return string(details)
}

func hashAccountingChargingIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return HashEAPIdentity(value)
}

func proportionalMicros(units uint64, microsPerUnit int64, denominator uint64) int64 {
	if units == 0 || microsPerUnit <= 0 || denominator == 0 {
		return 0
	}
	numerator := new(big.Int).Mul(new(big.Int).SetUint64(units), big.NewInt(microsPerUnit))
	denom := new(big.Int).SetUint64(denominator)
	quotient, remainder := new(big.Int).QuoRem(numerator, denom, new(big.Int))
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return math.MaxInt64
	}
	return quotient.Int64()
}

func accountingChargingTotalOctetTexts() (string, string) {
	rows, err := DB.Query(`SELECT input_octets_64, output_octets_64 FROM radius_accounting_charging_records`)
	if err != nil {
		return "0", "0"
	}
	defer rows.Close()
	var inputTotal, outputTotal big.Int
	for rows.Next() {
		var input, output string
		if err := rows.Scan(&input, &output); err != nil {
			continue
		}
		inputTotal.Add(&inputTotal, new(big.Int).SetUint64(uint64FromCounterText(input)))
		outputTotal.Add(&outputTotal, new(big.Int).SetUint64(uint64FromCounterText(output)))
	}
	return inputTotal.String(), outputTotal.String()
}

func latestAccountingChargingManifestSHA() (string, error) {
	var previous string
	err := DB.QueryRow(`SELECT COALESCE(manifest_sha256, '') FROM radius_accounting_charging_exports
		WHERE status = 'complete'
		ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	return previous, nil
}

func accountingChargingExportID(now time.Time, payloadSHA string) string {
	seed := fmt.Sprintf("%s\x00%s", now.UTC().Format(time.RFC3339Nano), payloadSHA)
	sum := sha256.Sum256([]byte(seed))
	return "cdr-export-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:])[:12]
}

func accountingChargingManifestSHA(exportID, format string, count int, amount int64, currency, payloadSHA, previousSHA, firstCDR, lastCDR string) string {
	manifest := strings.Join([]string{
		exportID,
		format,
		fmt.Sprint(count),
		fmt.Sprint(amount),
		currency,
		payloadSHA,
		previousSHA,
		firstCDR,
		lastCDR,
		"nas-0041",
	}, "\x00")
	return sha256Hex([]byte(manifest))
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func saturatingAddUint64(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func saturatingAddInt64(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}
