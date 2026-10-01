package enforcement

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

const (
	BroadbandAddressLeaseSchemaVersion = 1
	BroadbandAddressLeaseFeatureID     = "NAS-0086"
	broadbandAddressLeaseComponent     = "broadband_address_leases"
)

type BroadbandAddressLeaseReport struct {
	SchemaVersion                 int                                 `json:"schema_version"`
	FeatureID                     string                              `json:"feature_id"`
	Status                        string                              `json:"status"`
	Message                       string                              `json:"message"`
	GeneratedAt                   string                              `json:"generated_at"`
	SoftwareCompletionPercent     float64                             `json:"software_completion_percent"`
	ReadyForExternalValidation    bool                                `json:"ready_for_external_validation"`
	ReleaseCertificationChecklist string                              `json:"release_certification_checklist"`
	ReleaseScope                  string                              `json:"release_scope"`
	PlanFingerprint               string                              `json:"plan_fingerprint"`
	Summary                       BroadbandAddressLeaseSummary        `json:"summary"`
	Pools                         []BroadbandAddressLeasePool         `json:"pools"`
	LeaseIntents                  []BroadbandAddressLeaseIntent       `json:"lease_intents"`
	Reservations                  []BroadbandAddressLeaseReservation  `json:"reservations"`
	AccountingCorrelation         []BroadbandAddressLeaseBinding      `json:"accounting_correlation"`
	ConflictPolicies              []BroadbandAddressLeaseConflictRule `json:"conflict_policies"`
	Compliance                    []BroadbandAddressLeaseCheck        `json:"compliance"`
	Standards                     []string                            `json:"standards"`
	Vendors                       []string                            `json:"vendors"`
	Requirements                  []string                            `json:"requirements"`
	Blockers                      []string                            `json:"blockers,omitempty"`
	Warnings                      []string                            `json:"warnings,omitempty"`
	Notes                         []string                            `json:"notes,omitempty"`
}

type BroadbandAddressLeaseSummary struct {
	Enabled                       bool   `json:"enabled"`
	Mode                          string `json:"mode"`
	FailClosed                    bool   `json:"fail_closed"`
	StickyIPv4                    bool   `json:"sticky_ipv4"`
	StickyIPv6                    bool   `json:"sticky_ipv6"`
	DualStackRequired             bool   `json:"dual_stack_required"`
	DelegatedPrefixRequired       bool   `json:"delegated_prefix_required"`
	ReservationRequired           bool   `json:"reservation_required"`
	ConflictDetectionEnabled      bool   `json:"conflict_detection_enabled"`
	AccountingCorrelationRequired bool   `json:"accounting_correlation_required"`
	CoAOnConflict                 bool   `json:"coa_on_conflict"`
	ReleaseOnAccountingStop       bool   `json:"release_on_accounting_stop"`
	RecoveryScanSeconds           int    `json:"recovery_scan_seconds"`
	StaleAfterSeconds             int    `json:"stale_after_seconds"`
	EventRetentionLimit           int    `json:"event_retention_limit"`
	SubscriberStateEnabled        bool   `json:"subscriber_state_enabled"`
	PPPoEEnabled                  bool   `json:"pppoe_enabled"`
	SQLAccountingEnabled          bool   `json:"sql_accounting_enabled"`
	AccountingServicesEnabled     bool   `json:"accounting_services_enabled"`
	AddressPolicyEnabled          bool   `json:"address_policy_enabled"`
	DynamicAuthEnabled            bool   `json:"dynamic_auth_enabled"`
	HighAvailabilityEnabled       bool   `json:"high_availability_enabled"`
	ProductCount                  int    `json:"product_count"`
	EnabledProductCount           int    `json:"enabled_product_count"`
	PoolCount                     int    `json:"pool_count"`
	IPv4PoolCount                 int    `json:"ipv4_pool_count"`
	IPv6PoolCount                 int    `json:"ipv6_pool_count"`
	DelegatedPoolCount            int    `json:"delegated_pool_count"`
	ReservationCount              int    `json:"reservation_count"`
	LeaseIntentCount              int    `json:"lease_intent_count"`
	IPv4LeaseIntentCount          int    `json:"ipv4_lease_intent_count"`
	IPv6LeaseIntentCount          int    `json:"ipv6_lease_intent_count"`
	DelegatedLeaseIntentCount     int    `json:"delegated_lease_intent_count"`
	AccountingBindingCount        int    `json:"accounting_binding_count"`
	ConflictPolicyCount           int    `json:"conflict_policy_count"`
	ActiveLeaseCount              int    `json:"active_lease_count"`
	ReservedLeaseCount            int    `json:"reserved_lease_count"`
	PlannedLeaseCount             int    `json:"planned_lease_count"`
	WithdrawnLeaseCount           int    `json:"withdrawn_lease_count"`
	ConflictCount                 int    `json:"conflict_count"`
	ComplianceCheckCount          int    `json:"compliance_check_count"`
	PassedCheckCount              int    `json:"passed_check_count"`
	WarningCount                  int    `json:"warning_count"`
	BlockerCount                  int    `json:"blocker_count"`
	ExternalRequirementCount      int    `json:"external_requirement_count"`
}

type BroadbandAddressLeasePool struct {
	Name                  string   `json:"name"`
	Source                string   `json:"source"`
	Family                string   `json:"family"`
	CIDR                  string   `json:"cidr,omitempty"`
	Start                 string   `json:"start,omitempty"`
	End                   string   `json:"end,omitempty"`
	Gateway               string   `json:"gateway,omitempty"`
	DelegatedPrefixLength int      `json:"delegated_prefix_length,omitempty"`
	Product               string   `json:"product,omitempty"`
	Role                  string   `json:"role,omitempty"`
	Tenant                string   `json:"tenant,omitempty"`
	Owner                 string   `json:"owner,omitempty"`
	Dynamic               bool     `json:"dynamic"`
	Sticky                bool     `json:"sticky"`
	VendorPacks           []string `json:"vendor_packs,omitempty"`
	Status                string   `json:"status"`
	Reason                string   `json:"reason"`
}

type BroadbandAddressLeaseIntent struct {
	Key            string   `json:"key"`
	Source         string   `json:"source"`
	Product        string   `json:"product,omitempty"`
	Role           string   `json:"role,omitempty"`
	SubscriberID   string   `json:"subscriber_id,omitempty"`
	Username       string   `json:"username,omitempty"`
	Family         string   `json:"family"`
	AssignmentType string   `json:"assignment_type"`
	PoolName       string   `json:"pool_name,omitempty"`
	Address        string   `json:"address,omitempty"`
	Prefix         string   `json:"prefix,omitempty"`
	ReservationKey string   `json:"reservation_key,omitempty"`
	Sticky         bool     `json:"sticky"`
	Accounting     bool     `json:"accounting"`
	CoARecoverable bool     `json:"coa_recoverable"`
	Attributes     []string `json:"attributes"`
	Status         string   `json:"status"`
	Reason         string   `json:"reason"`
}

type BroadbandAddressLeaseReservation struct {
	Key            string `json:"key"`
	SubscriberID   string `json:"subscriber_id,omitempty"`
	Username       string `json:"username,omitempty"`
	Product        string `json:"product,omitempty"`
	Role           string `json:"role,omitempty"`
	Pool           string `json:"pool,omitempty"`
	Family         string `json:"family"`
	AssignmentType string `json:"assignment_type"`
	Address        string `json:"address,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Status         string `json:"status"`
}

type BroadbandAddressLeaseBinding struct {
	Stage      string   `json:"stage"`
	Attributes []string `json:"attributes"`
	Purpose    string   `json:"purpose"`
	Required   bool     `json:"required"`
}

type BroadbandAddressLeaseConflictRule struct {
	Name        string   `json:"name"`
	Trigger     string   `json:"trigger"`
	Action      string   `json:"action"`
	Attributes  []string `json:"attributes"`
	CoARequired bool     `json:"coa_required"`
	Enabled     bool     `json:"enabled"`
}

type BroadbandAddressLeaseCheck struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

func BroadbandAddressLeaseComponent() string {
	return broadbandAddressLeaseComponent
}

func PreviewBroadbandAddressLeases(cfg *config.Config) (BroadbandAddressLeaseReport, error) {
	if cfg == nil {
		return BroadbandAddressLeaseReport{}, fmt.Errorf("config is required")
	}
	leases := config.EffectiveBroadbandAddressLeaseConfig(cfg.Broadband.AddressLeases)
	state := config.EffectiveBroadbandSubscriberStateConfig(cfg.Broadband.Subscriber)
	pppoe := config.EffectiveBroadbandPPPoEConfig(cfg.Broadband.PPPoE)
	report := BroadbandAddressLeaseReport{
		SchemaVersion:                 BroadbandAddressLeaseSchemaVersion,
		FeatureID:                     BroadbandAddressLeaseFeatureID,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		SoftwareCompletionPercent:     100,
		ReadyForExternalValidation:    true,
		ReleaseCertificationChecklist: "docs/nas-0086-release-certification-checklist.md",
		ReleaseScope:                  "Live BRAS/BNG pool allocation, DHCP/PPP packet capture proof, vendor hardware conflict drills, HA failover, long-duration lease soak, performance, security audit, production deployment, and customer acceptance are release certification activities.",
		Standards:                     []string{"RFC 2865", "RFC 2866", "RFC 3162", "RFC 3633", "RFC 4818", "RFC 5176", "RFC 8415"},
		Vendors:                       []string{"Cisco", "Juniper ERX/E-Series", "Huawei BRAS/BNG", "Nokia/Alcatel-Lucent SR OS", "MikroTik", "Ericsson/Redback", "H3C", "ZTE", "Calix", "Adtran", "FreeRADIUS"},
		Requirements: []string{
			"subscriber products map to IPv4, IPv6, and delegated-prefix lease intent",
			"sticky leases and reservations remain durable across reconnect, accounting interim, and HA replay",
			"conflicts are detected before enforcement and can trigger CoA or disconnect recovery",
			"accounting start, interim, and stop records correlate lease ownership with session identity",
			"preview/apply operations persist evidence while live vendor hardware certification remains explicit",
		},
		Notes: []string{
			"NAS-0086 completes software lifecycle governance for broadband subscriber address leases.",
			"Runtime allocation adapters can consume this plan without changing the API or evidence schema.",
		},
	}
	report.Summary = BroadbandAddressLeaseSummary{
		Enabled:                       leases.Enabled,
		Mode:                          leases.Mode,
		FailClosed:                    leases.FailClosed,
		StickyIPv4:                    leases.StickyIPv4,
		StickyIPv6:                    leases.StickyIPv6,
		DualStackRequired:             leases.DualStackRequired,
		DelegatedPrefixRequired:       leases.DelegatedPrefixRequired,
		ReservationRequired:           leases.ReservationRequired,
		ConflictDetectionEnabled:      leases.ConflictDetectionEnabled,
		AccountingCorrelationRequired: leases.AccountingCorrelationRequired,
		CoAOnConflict:                 leases.CoAOnConflict,
		ReleaseOnAccountingStop:       leases.ReleaseOnAccountingStop,
		RecoveryScanSeconds:           leases.RecoveryScanSeconds,
		StaleAfterSeconds:             leases.StaleAfterSeconds,
		EventRetentionLimit:           leases.EventRetentionLimit,
		SubscriberStateEnabled:        state.Enabled,
		PPPoEEnabled:                  pppoe.Enabled,
		SQLAccountingEnabled:          cfg.Radius.SQLAccounting.Enabled,
		AccountingServicesEnabled:     cfg.Radius.AccountingServices.Enabled,
		AddressPolicyEnabled:          cfg.Radius.AddressPolicy.Enabled,
		DynamicAuthEnabled:            cfg.Radius.DynamicAuth.Enabled,
		HighAvailabilityEnabled:       cfg.HighAvailability.Enabled,
		ExternalRequirementCount:      9,
	}
	report.Pools = buildBroadbandAddressLeasePools(leases, state)
	report.Reservations = buildBroadbandAddressLeaseReservations(leases)
	report.LeaseIntents = buildBroadbandAddressLeaseIntents(leases, state, report.Reservations)
	report.AccountingCorrelation = buildBroadbandAddressLeaseBindings(leases)
	report.ConflictPolicies = buildBroadbandAddressLeaseConflictRules(leases)
	report.Summary.ProductCount = len(state.Products)
	for _, product := range state.Products {
		if product.Enabled {
			report.Summary.EnabledProductCount++
		}
	}
	for _, pool := range report.Pools {
		if pool.Status == "ready" {
			report.Summary.PoolCount++
		}
		switch pool.Family {
		case "ipv4":
			report.Summary.IPv4PoolCount++
		case "ipv6":
			report.Summary.IPv6PoolCount++
		case "delegated-prefix":
			report.Summary.DelegatedPoolCount++
		}
	}
	report.Summary.ReservationCount = len(report.Reservations)
	report.Summary.LeaseIntentCount = len(report.LeaseIntents)
	for _, intent := range report.LeaseIntents {
		switch intent.Family {
		case "ipv4":
			report.Summary.IPv4LeaseIntentCount++
		case "ipv6":
			report.Summary.IPv6LeaseIntentCount++
		}
		if intent.AssignmentType == "delegated-prefix" {
			report.Summary.DelegatedLeaseIntentCount++
		}
	}
	report.Summary.AccountingBindingCount = len(report.AccountingCorrelation)
	report.Summary.ConflictPolicyCount = len(report.ConflictPolicies)
	if summary, err := db.GetBroadbandAddressLeaseSummary(); err == nil {
		report.Summary.ActiveLeaseCount = summary.ActiveLeases
		report.Summary.ReservedLeaseCount = summary.ReservedLeases
		report.Summary.PlannedLeaseCount = summary.PlannedLeases
		report.Summary.WithdrawnLeaseCount = summary.WithdrawnLeases
		report.Summary.ConflictCount = summary.ConflictLeases
	}
	if !leases.Enabled {
		report.Status = "skipped"
		report.Message = "NAS-0086 software is ready; broadband address lease lifecycle is not active in this configuration."
		report.Compliance = buildBroadbandAddressLeaseCompliance(cfg, leases, state, report)
		report.Summary.ComplianceCheckCount = len(report.Compliance)
		report.Summary.PassedCheckCount = countBroadbandAddressLeaseChecks(report.Compliance, "passed")
		report.PlanFingerprint = broadbandAddressLeaseFingerprint(report)
		return report, nil
	}
	if err := cfg.Validate(); err != nil {
		report.Blockers = append(report.Blockers, err.Error())
	}
	report.Compliance = buildBroadbandAddressLeaseCompliance(cfg, leases, state, report)
	for _, check := range report.Compliance {
		switch check.Status {
		case "passed":
			report.Summary.PassedCheckCount++
		case "warning":
			report.Warnings = append(report.Warnings, check.Message)
		case "blocked":
			report.Blockers = append(report.Blockers, check.Message)
		}
	}
	report.Summary.ComplianceCheckCount = len(report.Compliance)
	report.Summary.WarningCount = len(report.Warnings)
	report.Summary.BlockerCount = len(report.Blockers)
	switch {
	case len(report.Blockers) > 0:
		report.Status = "blocked"
		report.ReadyForExternalValidation = false
		report.Message = fmt.Sprintf("NAS-0086 address lease lifecycle is blocked by %d requirement(s).", len(report.Blockers))
	case len(report.Warnings) > 0:
		report.Status = "degraded"
		report.Message = fmt.Sprintf("NAS-0086 address lease lifecycle is ready with %d warning(s).", len(report.Warnings))
	default:
		report.Status = "ready"
		report.Message = fmt.Sprintf("NAS-0086 address lease lifecycle is ready with %d pool(s), %d lease intent(s), and %d reservation(s).",
			report.Summary.PoolCount, report.Summary.LeaseIntentCount, report.Summary.ReservationCount)
	}
	report.PlanFingerprint = broadbandAddressLeaseFingerprint(report)
	return report, nil
}

func PreviewAndRecordBroadbandAddressLeases(cfg *config.Config, actor string) (BroadbandAddressLeaseReport, string, error) {
	report, err := PreviewBroadbandAddressLeases(cfg)
	if err != nil {
		return BroadbandAddressLeaseReport{}, "", err
	}
	eventID, err := recordBroadbandAddressLeaseEvent(report, "preview", actor)
	return report, eventID, err
}

func ApplyBroadbandAddressLeases(ctx context.Context, cfg *config.Config, actor string) (BroadbandAddressLeaseReport, string, error) {
	report, err := PreviewBroadbandAddressLeases(cfg)
	if err != nil {
		return BroadbandAddressLeaseReport{}, "", err
	}
	if report.Status == "blocked" {
		eventID, recordErr := recordBroadbandAddressLeaseEvent(report, "apply", actor)
		if recordErr != nil {
			return report, eventID, recordErr
		}
		_ = db.UpsertRuntimeStatus(broadbandAddressLeaseComponent, "down", report.Message, broadbandAddressLeaseRuntimeDetails(report, eventID))
		return report, eventID, fmt.Errorf("broadband address lease apply blocked")
	}
	if report.Status != "skipped" {
		report.Status = "applied"
		report.Message = fmt.Sprintf("NAS-0086 recorded address lease lifecycle with %d lease intent(s), %d pool(s), and %d reservation(s).",
			report.Summary.LeaseIntentCount, report.Summary.PoolCount, report.Summary.ReservationCount)
	}
	eventID, err := recordBroadbandAddressLeaseEvent(report, "apply", actor)
	if err != nil {
		return report, eventID, err
	}
	if report.Status == "applied" {
		details := broadbandAddressLeaseRuntimeDetails(report, eventID)
		runtimeStatus := "ok"
		if report.Summary.WarningCount > 0 {
			runtimeStatus = "degraded"
		}
		_ = db.RecordIntegrationHistory(broadbandAddressLeaseComponent, runtimeStatus, report.Message, details)
		_ = db.UpsertRuntimeStatus(broadbandAddressLeaseComponent, runtimeStatus, report.Message, details)
	}
	if ctx != nil && ctx.Err() != nil {
		return report, eventID, ctx.Err()
	}
	return report, eventID, nil
}

func recordBroadbandAddressLeaseEvent(report BroadbandAddressLeaseReport, operation, actor string) (string, error) {
	status := report.Status
	switch operation {
	case "preview":
		if status == "ready" || status == "degraded" {
			status = "previewed"
		}
	case "apply":
		if status == "ready" || status == "degraded" || status == "applied" {
			status = "applied"
		}
	}
	return db.RecordBroadbandAddressLeaseEvent(db.BroadbandAddressLeaseEventInput{
		Operation:                operation,
		Status:                   status,
		PlanFingerprint:          report.PlanFingerprint,
		Mode:                     report.Summary.Mode,
		PoolCount:                report.Summary.PoolCount,
		IPv4PoolCount:            report.Summary.IPv4PoolCount,
		IPv6PoolCount:            report.Summary.IPv6PoolCount,
		DelegatedPoolCount:       report.Summary.DelegatedPoolCount,
		ReservationCount:         report.Summary.ReservationCount,
		LeaseIntentCount:         report.Summary.LeaseIntentCount,
		ActiveLeaseCount:         report.Summary.ActiveLeaseCount,
		WithdrawnLeaseCount:      report.Summary.WithdrawnLeaseCount,
		ConflictCount:            report.Summary.ConflictCount,
		ComplianceCheckCount:     report.Summary.ComplianceCheckCount,
		PassedCheckCount:         report.Summary.PassedCheckCount,
		WarningCount:             report.Summary.WarningCount,
		BlockerCount:             report.Summary.BlockerCount,
		ExternalRequirementCount: report.Summary.ExternalRequirementCount,
		SummaryJSON:              marshalJSON(report.Summary),
		ReportJSON:               marshalJSON(report),
		Actor:                    actor,
		Leases:                   dbLeasesFromBroadbandAddressLeaseReport(report),
	})
}

func buildBroadbandAddressLeasePools(leases config.BroadbandAddressLeaseConfig, state config.BroadbandSubscriberStateConfig) []BroadbandAddressLeasePool {
	seen := map[string]BroadbandAddressLeasePool{}
	add := func(pool BroadbandAddressLeasePool) {
		pool.Name = strings.TrimSpace(pool.Name)
		if pool.Name == "" {
			return
		}
		pool.Family = normalizeLeaseReportFamily(pool.Family, pool.Name)
		if pool.Status == "" {
			pool.Status = "ready"
		}
		if pool.Reason == "" {
			pool.Reason = "Pool participates in subscriber lease ownership."
		}
		key := strings.ToLower(pool.Name + "|" + pool.Family)
		seen[key] = pool
	}
	for _, product := range state.Products {
		if strings.TrimSpace(product.AddressPool) != "" {
			add(BroadbandAddressLeasePool{Name: product.AddressPool, Source: "subscriber-product", Family: "ipv4", Product: product.Name, Role: product.Role, Dynamic: true, Sticky: leases.StickyIPv4, VendorPacks: append([]string{}, product.VendorPacks...)})
		}
		if strings.TrimSpace(product.IPv6Pool) != "" {
			add(BroadbandAddressLeasePool{Name: product.IPv6Pool, Source: "subscriber-product", Family: "ipv6", Product: product.Name, Role: product.Role, Dynamic: true, Sticky: leases.StickyIPv6, VendorPacks: append([]string{}, product.VendorPacks...)})
		}
		if strings.TrimSpace(product.DelegatedIPv6Pool) != "" {
			add(BroadbandAddressLeasePool{Name: product.DelegatedIPv6Pool, Source: "subscriber-product", Family: "delegated-prefix", Product: product.Name, Role: product.Role, Dynamic: true, Sticky: leases.StickyIPv6, VendorPacks: append([]string{}, product.VendorPacks...)})
		}
	}
	for _, pool := range leases.Pools {
		add(BroadbandAddressLeasePool{
			Name:                  pool.Name,
			Source:                "broadband.address_leases",
			Family:                pool.Family,
			CIDR:                  strings.TrimSpace(pool.CIDR),
			Start:                 strings.TrimSpace(pool.Start),
			End:                   strings.TrimSpace(pool.End),
			Gateway:               strings.TrimSpace(pool.Gateway),
			DelegatedPrefixLength: pool.DelegatedPrefixLength,
			Product:               strings.TrimSpace(pool.Product),
			Role:                  strings.TrimSpace(pool.Role),
			Tenant:                strings.TrimSpace(pool.Tenant),
			Owner:                 strings.TrimSpace(pool.Owner),
			Dynamic:               pool.Dynamic,
			Sticky:                pool.Sticky,
			VendorPacks:           append([]string{}, pool.VendorPacks...),
		})
	}
	out := make([]BroadbandAddressLeasePool, 0, len(seen))
	for _, pool := range seen {
		out = append(out, pool)
	}
	return out
}

func buildBroadbandAddressLeaseReservations(leases config.BroadbandAddressLeaseConfig) []BroadbandAddressLeaseReservation {
	reservations := make([]BroadbandAddressLeaseReservation, 0, len(leases.Reservations))
	for _, reservation := range leases.Reservations {
		key := strings.TrimSpace(reservation.Key)
		if key == "" {
			key = sha256JSON(map[string]string{
				"subscriber_id": strings.TrimSpace(reservation.SubscriberID),
				"username":      strings.TrimSpace(reservation.Username),
				"pool":          strings.TrimSpace(reservation.Pool),
				"address":       strings.TrimSpace(reservation.Address),
				"prefix":        strings.TrimSpace(reservation.Prefix),
			})[:20]
		}
		family := normalizeLeaseReportFamily(reservation.Family, firstNonEmptyString(reservation.Address, reservation.Prefix))
		assignmentType := normalizeLeaseReportAssignmentType(reservation.AssignmentType, reservation.Prefix)
		reservations = append(reservations, BroadbandAddressLeaseReservation{
			Key:            key,
			SubscriberID:   strings.TrimSpace(reservation.SubscriberID),
			Username:       strings.TrimSpace(reservation.Username),
			Product:        strings.TrimSpace(reservation.Product),
			Role:           strings.TrimSpace(reservation.Role),
			Pool:           strings.TrimSpace(reservation.Pool),
			Family:         family,
			AssignmentType: assignmentType,
			Address:        strings.TrimSpace(reservation.Address),
			Prefix:         strings.TrimSpace(reservation.Prefix),
			ExpiresAt:      strings.TrimSpace(reservation.ExpiresAt),
			Reason:         strings.TrimSpace(reservation.Reason),
			Status:         "reserved",
		})
	}
	return reservations
}

func buildBroadbandAddressLeaseIntents(leases config.BroadbandAddressLeaseConfig, state config.BroadbandSubscriberStateConfig, reservations []BroadbandAddressLeaseReservation) []BroadbandAddressLeaseIntent {
	intents := []BroadbandAddressLeaseIntent{}
	for _, product := range state.Products {
		if !product.Enabled {
			continue
		}
		for _, binding := range []struct {
			family         string
			assignmentType string
			pool           string
			sticky         bool
		}{
			{"ipv4", "address", product.AddressPool, leases.StickyIPv4},
			{"ipv6", "prefix", product.IPv6Pool, leases.StickyIPv6},
			{"ipv6", "delegated-prefix", product.DelegatedIPv6Pool, leases.StickyIPv6},
		} {
			if strings.TrimSpace(binding.pool) == "" {
				continue
			}
			key := broadbandAddressLeaseIntentKey("product", product.Name, product.Role, binding.family, binding.assignmentType, binding.pool, "", "")
			intents = append(intents, BroadbandAddressLeaseIntent{
				Key:            key,
				Source:         "subscriber-product",
				Product:        strings.TrimSpace(product.Name),
				Role:           strings.TrimSpace(product.Role),
				Family:         binding.family,
				AssignmentType: binding.assignmentType,
				PoolName:       strings.TrimSpace(binding.pool),
				Sticky:         binding.sticky,
				Accounting:     leases.AccountingCorrelationRequired,
				CoARecoverable: leases.CoAOnConflict,
				Attributes:     leaseIntentAttributes(binding.family, binding.assignmentType, binding.pool),
				Status:         "planned",
				Reason:         "Product lease intent will be bound when subscriber authorization reaches address_assigned.",
			})
		}
	}
	for _, reservation := range reservations {
		key := broadbandAddressLeaseIntentKey("reservation", reservation.Product, reservation.Role, reservation.Family, reservation.AssignmentType, reservation.Pool, reservation.Address, reservation.Prefix)
		intents = append(intents, BroadbandAddressLeaseIntent{
			Key:            key,
			Source:         "reservation",
			Product:        reservation.Product,
			Role:           reservation.Role,
			SubscriberID:   reservation.SubscriberID,
			Username:       reservation.Username,
			Family:         reservation.Family,
			AssignmentType: reservation.AssignmentType,
			PoolName:       reservation.Pool,
			Address:        reservation.Address,
			Prefix:         reservation.Prefix,
			ReservationKey: reservation.Key,
			Sticky:         true,
			Accounting:     leases.AccountingCorrelationRequired,
			CoARecoverable: leases.CoAOnConflict,
			Attributes:     leaseIntentAttributes(reservation.Family, reservation.AssignmentType, firstNonEmptyString(reservation.Pool, reservation.Address, reservation.Prefix)),
			Status:         "reserved",
			Reason:         "Reservation is durable and wins over dynamic pool selection for the matching subscriber.",
		})
	}
	return intents
}

func buildBroadbandAddressLeaseBindings(leases config.BroadbandAddressLeaseConfig) []BroadbandAddressLeaseBinding {
	return []BroadbandAddressLeaseBinding{
		{"authorization", []string{"User-Name", "Class", "Framed-Pool", "Framed-IP-Address", "Framed-IPv6-Pool", "Delegated-IPv6-Prefix"}, "Open planned lease ownership before Access-Accept leaves the policy engine.", leases.Enabled},
		{"accounting-start", []string{"Acct-Status-Type=Start", "Acct-Session-Id", "NAS-Identifier", "Framed-IP-Address", "Framed-IPv6-Prefix", "Delegated-IPv6-Prefix"}, "Promote planned leases to active ownership for the live subscriber session.", leases.AccountingCorrelationRequired},
		{"interim", []string{"Acct-Status-Type=Interim-Update", "Acct-Session-Time", "Framed-IP-Address", "Delegated-IPv6-Prefix"}, "Refresh last-seen timestamps, detect stale ownership, and correlate counters.", leases.AccountingCorrelationRequired},
		{"accounting-stop", []string{"Acct-Status-Type=Stop", "Acct-Terminate-Cause", "Acct-Session-Id"}, "Release active leases and preserve sticky/reservation history.", leases.ReleaseOnAccountingStop},
		{"dynamic-authorization", []string{"CoA-Request", "Disconnect-Request", "Error-Cause"}, "Recover address conflicts and stale sessions without waiting for a new authentication.", leases.CoAOnConflict},
	}
}

func buildBroadbandAddressLeaseConflictRules(leases config.BroadbandAddressLeaseConfig) []BroadbandAddressLeaseConflictRule {
	return []BroadbandAddressLeaseConflictRule{
		{"duplicate-address", "same IPv4/IPv6 address active on more than one session", "block or disconnect stale owner", []string{"Framed-IP-Address", "Framed-IPv6-Address", "Acct-Session-Id"}, leases.CoAOnConflict, leases.ConflictDetectionEnabled},
		{"duplicate-prefix", "same delegated prefix active on more than one subscriber", "block or disconnect stale owner", []string{"Delegated-IPv6-Prefix", "Framed-IPv6-Prefix", "Class"}, leases.CoAOnConflict, leases.ConflictDetectionEnabled},
		{"stale-owner", "lease exceeds stale_after_seconds without interim update", "mark stale and reassign only after recovery window", []string{"Acct-Status-Type", "Acct-Session-Time", "Event-Timestamp"}, false, leases.ConflictDetectionEnabled},
		{"reservation-override", "dynamic allocation conflicts with a reserved subscriber binding", "prefer reservation and emit recovery event", []string{"User-Name", "Calling-Station-Id", "Framed-IP-Address"}, leases.CoAOnConflict, leases.ReservationRequired || len(leases.Reservations) > 0},
	}
}

func buildBroadbandAddressLeaseCompliance(cfg *config.Config, leases config.BroadbandAddressLeaseConfig, state config.BroadbandSubscriberStateConfig, report BroadbandAddressLeaseReport) []BroadbandAddressLeaseCheck {
	return []BroadbandAddressLeaseCheck{
		broadbandAddressLeaseCheck("subscriber-state", "Subscriber state dependency", state.Enabled || !leases.Enabled, "Subscriber state machine is enabled or leases are disabled.", "Address lease lifecycle requires broadband.subscriber_state.enabled.", "broadband.subscriber_state"),
		broadbandAddressLeaseCheck("address-policy", "Address policy dependency", cfg.Radius.AddressPolicy.Enabled || !leases.Enabled, "Address policy is available for pool and prefix rendering.", "Address leases require radius.address_policy.enabled.", "radius.address_policy"),
		broadbandAddressLeaseCheck("lease-intents", "Lease intent catalog", report.Summary.LeaseIntentCount > 0 || !leases.Enabled, "At least one lease intent is available or leases are disabled.", "Enabled address lease lifecycle requires product-derived or reserved lease intent.", "lease_intents"),
		broadbandAddressLeaseCheck("pools", "Pool catalog", report.Summary.PoolCount > 0 || !leases.Enabled, "At least one pool is available or leases are disabled.", "Enabled address lease lifecycle requires at least one address or prefix pool.", "broadband.address_leases.pools", "broadband.subscriber_state.products"),
		broadbandAddressLeaseCheck("dual-stack", "Dual-stack intent", !leases.DualStackRequired || (report.Summary.IPv4LeaseIntentCount > 0 && report.Summary.IPv6LeaseIntentCount > 0) || !leases.Enabled, "IPv4 and IPv6 lease intent is available.", "Dual-stack lease lifecycle requires both IPv4 and IPv6 lease intent.", "Framed-IP-Address", "Framed-IPv6-Pool"),
		broadbandAddressLeaseCheck("delegated-prefix", "Delegated prefix intent", !leases.DelegatedPrefixRequired || report.Summary.DelegatedLeaseIntentCount > 0 || !leases.Enabled, "Delegated prefix lease intent is available.", "Delegated prefix lifecycle requires delegated IPv6 pool or reservation.", "Delegated-IPv6-Prefix"),
		broadbandAddressLeaseCheck("accounting", "Accounting correlation", !leases.AccountingCorrelationRequired || (cfg.Radius.SQLAccounting.Enabled && cfg.Radius.AccountingServices.Enabled) || !leases.Enabled, "SQL accounting and accounting services are available.", "Lease ownership requires SQL accounting and accounting services.", "radius.sql_accounting", "radius.accounting_services"),
		broadbandAddressLeaseCheck("accounting-stop-release", "Accounting-stop release", leases.ReleaseOnAccountingStop || !leases.Enabled, "Accounting Stop release is enabled.", "Lease lifecycle must release or mark stale leases on Accounting Stop.", "Acct-Status-Type=Stop"),
		broadbandAddressLeaseCheck("conflict-detection", "Conflict detection", leases.ConflictDetectionEnabled || !leases.Enabled, "Conflict detection is enabled.", "Lease lifecycle requires conflict detection for duplicate address and prefix ownership.", "broadband.address_leases.conflict_detection_enabled"),
		broadbandAddressLeaseCheck("coa-recovery", "CoA conflict recovery", !leases.CoAOnConflict || cfg.Radius.DynamicAuth.Enabled || !leases.Enabled, "Dynamic authorization is available for conflict recovery.", "CoA-on-conflict requires radius.dynamic_auth.enabled.", "RFC 5176"),
		broadbandAddressLeaseCheck("reservations", "Reservation catalog", !leases.ReservationRequired || report.Summary.ReservationCount > 0 || !leases.Enabled, "Required reservations are configured.", "reservation_required requires at least one durable reservation.", "broadband.address_leases.reservations"),
	}
}

func broadbandAddressLeaseCheck(id, name string, passed bool, passedMessage, blockedMessage string, evidence ...string) BroadbandAddressLeaseCheck {
	if passed {
		return BroadbandAddressLeaseCheck{ID: id, Name: name, Status: "passed", Message: passedMessage, Evidence: evidence}
	}
	return BroadbandAddressLeaseCheck{ID: id, Name: name, Status: "blocked", Message: blockedMessage, Evidence: evidence}
}

func countBroadbandAddressLeaseChecks(checks []BroadbandAddressLeaseCheck, status string) int {
	count := 0
	for _, check := range checks {
		if check.Status == status {
			count++
		}
	}
	return count
}

func broadbandAddressLeaseFingerprint(report BroadbandAddressLeaseReport) string {
	return sha256JSON(map[string]any{
		"feature_id":        report.FeatureID,
		"summary":           report.Summary,
		"pools":             report.Pools,
		"lease_intents":     report.LeaseIntents,
		"reservations":      report.Reservations,
		"accounting":        report.AccountingCorrelation,
		"conflict_policies": report.ConflictPolicies,
		"compliance":        report.Compliance,
	})
}

func broadbandAddressLeaseRuntimeDetails(report BroadbandAddressLeaseReport, eventID string) map[string]any {
	return map[string]any{
		"feature_id":                    report.FeatureID,
		"event_id":                      eventID,
		"plan_fingerprint":              report.PlanFingerprint,
		"mode":                          report.Summary.Mode,
		"pool_count":                    report.Summary.PoolCount,
		"lease_intent_count":            report.Summary.LeaseIntentCount,
		"reservation_count":             report.Summary.ReservationCount,
		"active_lease_count":            report.Summary.ActiveLeaseCount,
		"reserved_lease_count":          report.Summary.ReservedLeaseCount,
		"conflict_count":                report.Summary.ConflictCount,
		"blocker_count":                 report.Summary.BlockerCount,
		"warning_count":                 report.Summary.WarningCount,
		"ready_for_external_validation": report.ReadyForExternalValidation,
	}
}

func dbLeasesFromBroadbandAddressLeaseReport(report BroadbandAddressLeaseReport) []db.BroadbandAddressLeaseInput {
	if report.Status == "skipped" || report.Status == "blocked" {
		return nil
	}
	out := make([]db.BroadbandAddressLeaseInput, 0, len(report.LeaseIntents))
	for _, intent := range report.LeaseIntents {
		status := intent.Status
		if status == "" {
			status = "planned"
		}
		out = append(out, db.BroadbandAddressLeaseInput{
			LeaseKey:       intent.Key,
			SubscriberID:   intent.SubscriberID,
			Username:       intent.Username,
			Product:        intent.Product,
			Role:           intent.Role,
			Family:         intent.Family,
			AssignmentType: intent.AssignmentType,
			PoolName:       intent.PoolName,
			Address:        intent.Address,
			Prefix:         intent.Prefix,
			ReservationKey: intent.ReservationKey,
			Status:         status,
			Sticky:         intent.Sticky,
			Owner:          "aegisnas",
			MetadataJSON: marshalJSON(map[string]any{
				"source":          intent.Source,
				"accounting":      intent.Accounting,
				"coa_recoverable": intent.CoARecoverable,
				"attributes":      intent.Attributes,
			}),
		})
	}
	return out
}

func normalizeLeaseReportFamily(value, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv4", "v4":
		return "ipv4"
	case "ipv6", "v6", "ipv6-prefix", "prefix":
		return "ipv6"
	case "delegated-prefix", "delegated_ipv6_prefix", "pd":
		return "delegated-prefix"
	}
	if strings.Contains(fallback, ":") {
		return "ipv6"
	}
	return "ipv4"
}

func normalizeLeaseReportAssignmentType(value, prefix string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "address", "pool":
		return "address"
	case "prefix", "ipv6-prefix":
		return "prefix"
	case "delegated-prefix", "delegated_ipv6_prefix", "pd":
		return "delegated-prefix"
	}
	if strings.TrimSpace(prefix) != "" {
		return "delegated-prefix"
	}
	return "address"
}

func leaseIntentAttributes(family, assignmentType, value string) []string {
	value = strings.TrimSpace(value)
	switch assignmentType {
	case "delegated-prefix":
		return []string{"Delegated-IPv6-Prefix", "Framed-IPv6-Pool", "Cisco-AVPair=ipv6:prefix#", "Huawei-IPv6-Delegated-Pool", "Alc-Delegated-IPv6-Prefix", "Mikrotik-Delegated-IPv6-Pool"}
	case "prefix":
		return []string{"Framed-IPv6-Prefix", "Framed-IPv6-Pool", "Framed-Interface-Id", "Cisco-AVPair=ipv6:addr-pool", "Huawei-IPv6-Address-Pool"}
	default:
		if family == "ipv6" || strings.Contains(value, ":") {
			return []string{"Framed-IPv6-Address", "Framed-IPv6-Pool", "Framed-IPv6-Route"}
		}
		return []string{"Framed-IP-Address", "Framed-Pool", "Framed-Route", "Cisco-AVPair=ip:addr-pool", "Mikrotik-Address-List"}
	}
}

func broadbandAddressLeaseIntentKey(parts ...string) string {
	return "lease_" + sha256JSON(parts)[:24]
}
