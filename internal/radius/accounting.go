package radius

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

// AccountingRecord represents a RADIUS accounting packet.
type AccountingRecord struct {
	SessionID           string
	Username            string
	NASIPAddress        string
	NASPort             int
	AcctStatusType      string // Start, Stop, Interim-Update
	AcctMultiSessionID  string
	AcctLinkCount       int64
	AcctInputOctets     uint64
	AcctOutputOctets    uint64
	AcctSessionTime     int
	CalledStationID     string
	CallingStationID    string
	FramedIPAddress     string
	FramedIPv6Address   string
	FramedIPv6Prefix    string
	FramedInterfaceID   string
	DelegatedIPv6Prefix string
	FramedRoute         string
	FramedIPv6Route     string
	ServiceType         string
	FramedProtocol      string
	StopReason          string
	Role                string
	BandwidthProfile    string
	FilterID            string
	RadiusClass         string
	ParentSessionKey    string
	ServiceKey          string
	ServiceCategory     string
	ServiceLegID        string
	BearerID            string
	CallID              string
	RoamingID           string
	VLAN                int
	SessionTimeout      int
	IdleTimeout         int
	Timestamp           time.Time
}

// ProcessAccounting stores an accounting record in the database.
func ProcessAccounting(rec *AccountingRecord) error {
	logger := zap.L()
	if db.DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if rec == nil {
		return fmt.Errorf("accounting record is required")
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	switch rec.AcctStatusType {
	case "Start", "Stop", "Interim-Update":
	default:
		logger.Info("accounting ignored",
			zap.String("session_id", rec.SessionID),
			zap.String("status", rec.AcctStatusType))
		return nil
	}

	event := accountingEventFromAccounting(rec)
	if cfg := config.Get(); cfg != nil && EffectiveAccountingIngestSpoolPolicy(cfg).Enabled {
		if err := processAccountingWithIngestSpool(context.Background(), cfg, event); err != nil {
			logger.Error("accounting ingest spool processing failed", zap.Error(err))
			return err
		}
		logger.Info("accounting processed",
			zap.String("session_id", rec.SessionID),
			zap.String("status", rec.AcctStatusType),
			zap.String("path", "ingest_spool"))
		return nil
	}

	ingested, err := db.IngestAccountingEvent(context.Background(), event)
	if err != nil {
		logger.Error("accounting event ingest failed", zap.Error(err))
		return err
	}
	applied, err := db.ApplyAccountingEventByID(context.Background(), ingested.Event.EventID)
	if err != nil {
		logger.Error("accounting event apply failed", zap.Error(err))
		return err
	}
	logger.Info("accounting processed",
		zap.String("session_id", rec.SessionID),
		zap.String("status", rec.AcctStatusType),
		zap.String("event_id", ingested.Event.EventID),
		zap.Bool("duplicate", ingested.Duplicate),
		zap.Int("applied", applied.Applied))
	return nil
}

func accountingEventFromAccounting(rec *AccountingRecord) db.AccountingEventRecord {
	record := freeRADIUSRecordFromAccounting(rec)
	return db.AccountingEventRecord{
		AcctSessionID:       record.AcctSessionID,
		AcctUniqueID:        record.AcctUniqueID,
		SessionKey:          strings.TrimSpace(rec.SessionID),
		StatusType:          rec.AcctStatusType,
		AcctMultiSessionID:  rec.AcctMultiSessionID,
		AcctLinkCount:       rec.AcctLinkCount,
		EventTime:           rec.Timestamp.UTC().Format(time.RFC3339Nano),
		ArrivalTime:         time.Now().UTC().Format(time.RFC3339Nano),
		Username:            rec.Username,
		NASIPAddress:        rec.NASIPAddress,
		NASPortID:           record.NASPortID,
		CallingStationID:    rec.CallingStationID,
		CalledStationID:     rec.CalledStationID,
		FramedIPAddress:     rec.FramedIPAddress,
		FramedIPv6Address:   rec.FramedIPv6Address,
		FramedIPv6Prefix:    rec.FramedIPv6Prefix,
		FramedInterfaceID:   rec.FramedInterfaceID,
		DelegatedIPv6Prefix: rec.DelegatedIPv6Prefix,
		FramedRoute:         rec.FramedRoute,
		FramedIPv6Route:     rec.FramedIPv6Route,
		ServiceType:         rec.ServiceType,
		FramedProtocol:      rec.FramedProtocol,
		Class:               rec.RadiusClass,
		AcctInputOctets:     rec.AcctInputOctets,
		AcctOutputOctets:    rec.AcctOutputOctets,
		AcctSessionTime:     int64(rec.AcctSessionTime),
		AcctTerminateCause:  rec.StopReason,
		Source:              "aegis-broker",
		ParentSessionKey:    rec.ParentSessionKey,
		ServiceKey:          rec.ServiceKey,
		ServiceCategory:     rec.ServiceCategory,
		ServiceLegID:        rec.ServiceLegID,
		BearerID:            rec.BearerID,
		CallID:              rec.CallID,
		RoamingID:           rec.RoamingID,
	}
}

func freeRADIUSRecordFromAccounting(rec *AccountingRecord) db.FreeRADIUSAccountingRecord {
	timestamp := rec.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	formatted := timestamp.UTC().Format(time.RFC3339Nano)
	record := db.FreeRADIUSAccountingRecord{
		AcctSessionID:        strings.TrimSpace(rec.SessionID),
		AcctUniqueID:         db.FreeRADIUSAcctUniqueID(rec.SessionID, rec.Username, rec.NASIPAddress, strconv.Itoa(rec.NASPort), rec.CallingStationID),
		Username:             strings.TrimSpace(rec.Username),
		NASIPAddress:         strings.TrimSpace(rec.NASIPAddress),
		NASPortID:            strings.TrimSpace(strconv.Itoa(rec.NASPort)),
		AcctMultiSessionID:   strings.TrimSpace(rec.AcctMultiSessionID),
		AcctLinkCount:        rec.AcctLinkCount,
		AcctSessionTime:      int64(rec.AcctSessionTime),
		AcctAuthentic:        "RADIUS",
		AcctInputOctets:      rec.AcctInputOctets,
		AcctOutputOctets:     rec.AcctOutputOctets,
		CalledStationID:      strings.TrimSpace(rec.CalledStationID),
		CallingStationID:     strings.TrimSpace(rec.CallingStationID),
		AcctTerminateCause:   strings.TrimSpace(rec.StopReason),
		ServiceType:          strings.TrimSpace(rec.ServiceType),
		FramedProtocol:       strings.TrimSpace(rec.FramedProtocol),
		FramedIPAddress:      strings.TrimSpace(rec.FramedIPAddress),
		FramedIPv6Address:    strings.TrimSpace(rec.FramedIPv6Address),
		FramedIPv6Prefix:     strings.TrimSpace(rec.FramedIPv6Prefix),
		FramedInterfaceID:    strings.TrimSpace(rec.FramedInterfaceID),
		DelegatedIPv6Prefix:  strings.TrimSpace(rec.DelegatedIPv6Prefix),
		FramedRoute:          strings.TrimSpace(rec.FramedRoute),
		FramedIPv6Route:      strings.TrimSpace(rec.FramedIPv6Route),
		Class:                strings.TrimSpace(rec.RadiusClass),
		AegisSessionID:       strings.TrimSpace(rec.SessionID),
		AegisSource:          "aegis-broker",
		AegisReconcileStatus: "reconciled",
		AegisReconciledAt:    formatted,
		AegisParentSessionID: strings.TrimSpace(rec.ParentSessionKey),
		AegisServiceKey:      strings.TrimSpace(rec.ServiceKey),
		AegisServiceCategory: strings.TrimSpace(rec.ServiceCategory),
		AegisServiceLegID:    strings.TrimSpace(rec.ServiceLegID),
		AegisBearerID:        strings.TrimSpace(rec.BearerID),
		AegisCallID:          strings.TrimSpace(rec.CallID),
		AegisRoamingID:       strings.TrimSpace(rec.RoamingID),
	}
	switch rec.AcctStatusType {
	case "Start":
		record.AcctStartTime = formatted
		record.AcctUpdateTime = formatted
	case "Stop":
		record.AcctStopTime = formatted
		record.AcctUpdateTime = formatted
	case "Interim-Update":
		record.AcctUpdateTime = formatted
	}
	if rec.NASPort <= 0 {
		record.NASPortID = ""
	}
	return record
}
