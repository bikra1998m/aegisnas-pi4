package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type SupplicantLifecycleEvent struct {
	ID                        int64             `json:"id"`
	ObservedAt                time.Time         `json:"observed_at"`
	Protocol                  string            `json:"protocol"`
	Platform                  string            `json:"platform"`
	Decision                  string            `json:"decision"`
	Action                    string            `json:"action"`
	Reason                    string            `json:"reason"`
	UsernameHash              string            `json:"username_hash,omitempty"`
	DeviceIDHash              string            `json:"device_id_hash,omitempty"`
	Tenant                    string            `json:"tenant,omitempty"`
	EAPMethod                 string            `json:"eap_method,omitempty"`
	InnerMethod               string            `json:"inner_method,omitempty"`
	IdentitySource            string            `json:"identity_source,omitempty"`
	PasswordExpired           bool              `json:"password_expired"`
	DaysUntilExpiry           int               `json:"days_until_expiry"`
	PasswordChangeRequested   bool              `json:"password_change_requested"`
	PasswordChangeRequired    bool              `json:"password_change_required"`
	PasswordChanged           bool              `json:"password_changed"`
	OldPasswordVerified       bool              `json:"old_password_verified"`
	NewPasswordMeetsPolicy    bool              `json:"new_password_meets_policy"`
	MFAComplete               bool              `json:"mfa_complete"`
	TLSProtected              bool              `json:"tls_protected"`
	VerifierCompatible        bool              `json:"verifier_compatible"`
	ProfileRequested          bool              `json:"profile_requested"`
	ProfileSigned             bool              `json:"profile_signed"`
	SigningKeyAvailable       bool              `json:"signing_key_available"`
	TrustAnchorPinned         bool              `json:"trust_anchor_pinned"`
	ServerNameMatched         bool              `json:"server_name_matched"`
	DeliveryTokenValid        bool              `json:"delivery_token_valid"`
	DeviceManaged             bool              `json:"device_managed"`
	CertificateLifecycleReady bool              `json:"certificate_lifecycle_ready"`
	PolicyMode                string            `json:"policy_mode,omitempty"`
	LatencyMS                 int               `json:"latency_ms"`
	Details                   map[string]string `json:"details,omitempty"`
}

type SupplicantProfileDelivery struct {
	DeliveryKey          string            `json:"delivery_key"`
	UpdatedAt            time.Time         `json:"updated_at"`
	Status               string            `json:"status"`
	Platform             string            `json:"platform"`
	UsernameHash         string            `json:"username_hash,omitempty"`
	DeviceIDHash         string            `json:"device_id_hash,omitempty"`
	Tenant               string            `json:"tenant,omitempty"`
	SSID                 string            `json:"ssid,omitempty"`
	EAPMethod            string            `json:"eap_method,omitempty"`
	InnerMethod          string            `json:"inner_method,omitempty"`
	ProfileHash          string            `json:"profile_hash,omitempty"`
	SignatureFingerprint string            `json:"signature_fingerprint,omitempty"`
	ContentType          string            `json:"content_type,omitempty"`
	FileExtension        string            `json:"file_extension,omitempty"`
	ExpiresAt            time.Time         `json:"expires_at,omitempty"`
	PolicyMode           string            `json:"policy_mode,omitempty"`
	Details              map[string]string `json:"details,omitempty"`
}

type SupplicantLifecycleEventFilter struct {
	Decision  string
	Platform  string
	EAPMethod string
	Limit     int
}

type SupplicantProfileDeliveryFilter struct {
	Status   string
	Platform string
	Limit    int
}

type SupplicantLifecycleSummary struct {
	TotalEvents            int
	Accepted               int
	Rejected               int
	MonitorAllowed         int
	PasswordChangeRequired int
	PasswordChanged        int
	ProfilesDelivered      int
	UnsignedProfileBlocked int
	TrustPinFailures       int
	VerifierFailures       int
	TLSFailures            int
	ActiveProfiles         int
	ExpiredProfiles        int
	ByDecision             map[string]int
	ByPlatform             map[string]int
	ByEAPMethod            map[string]int
	LastEventAt            string
	LastRejectedReason     string
	LastProfileDeliveredAt string
}

func RecordSupplicantLifecycleEvent(event SupplicantLifecycleEvent, eventRetentionLimit, profileRetentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database is not initialized")
	}
	normalized := normalizeSupplicantLifecycleEvent(event)
	detailsJSON, err := json.Marshal(normalized.Details)
	if err != nil {
		return err
	}
	_, err = DB.Exec(`INSERT INTO supplicant_lifecycle_events (
		observed_at, protocol, platform, decision, action, reason, username_hash, device_id_hash, tenant,
		eap_method, inner_method, identity_source, password_expired, days_until_expiry,
		password_change_requested, password_change_required, password_changed, old_password_verified,
		new_password_meets_policy, mfa_complete, tls_protected, verifier_compatible, profile_requested,
		profile_signed, signing_key_available, trust_anchor_pinned, server_name_matched, delivery_token_valid,
		device_managed, certificate_lifecycle_ready, policy_mode, latency_ms, details_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalized.ObservedAt.UTC(), normalized.Protocol, normalized.Platform, normalized.Decision, normalized.Action,
		normalized.Reason, normalized.UsernameHash, normalized.DeviceIDHash, normalized.Tenant, normalized.EAPMethod,
		normalized.InnerMethod, normalized.IdentitySource, boolToSQLite(normalized.PasswordExpired), normalized.DaysUntilExpiry,
		boolToSQLite(normalized.PasswordChangeRequested), boolToSQLite(normalized.PasswordChangeRequired),
		boolToSQLite(normalized.PasswordChanged), boolToSQLite(normalized.OldPasswordVerified),
		boolToSQLite(normalized.NewPasswordMeetsPolicy), boolToSQLite(normalized.MFAComplete),
		boolToSQLite(normalized.TLSProtected), boolToSQLite(normalized.VerifierCompatible),
		boolToSQLite(normalized.ProfileRequested), boolToSQLite(normalized.ProfileSigned),
		boolToSQLite(normalized.SigningKeyAvailable), boolToSQLite(normalized.TrustAnchorPinned),
		boolToSQLite(normalized.ServerNameMatched), boolToSQLite(normalized.DeliveryTokenValid),
		boolToSQLite(normalized.DeviceManaged), boolToSQLite(normalized.CertificateLifecycleReady),
		normalized.PolicyMode, normalized.LatencyMS, string(detailsJSON))
	if err != nil {
		return err
	}
	if normalized.ProfileRequested && normalized.Decision == "accepted" {
		if err := UpsertSupplicantProfileDelivery(SupplicantProfileDelivery{
			DeliveryKey:  supplicantDeliveryKey(normalized),
			UpdatedAt:    normalized.ObservedAt,
			Status:       "active",
			Platform:     normalized.Platform,
			UsernameHash: normalized.UsernameHash,
			DeviceIDHash: normalized.DeviceIDHash,
			Tenant:       normalized.Tenant,
			EAPMethod:    normalized.EAPMethod,
			InnerMethod:  normalized.InnerMethod,
			PolicyMode:   normalized.PolicyMode,
			Details:      normalized.Details,
		}, profileRetentionLimit); err != nil {
			return err
		}
	}
	return trimSupplicantLifecycleEvents(eventRetentionLimit)
}

func UpsertSupplicantProfileDelivery(item SupplicantProfileDelivery, retentionLimit int) error {
	if DB == nil {
		return fmt.Errorf("database is not initialized")
	}
	normalized := normalizeSupplicantProfileDelivery(item)
	detailsJSON, err := json.Marshal(normalized.Details)
	if err != nil {
		return err
	}
	_, err = DB.Exec(`INSERT INTO supplicant_profile_deliveries (
		delivery_key, updated_at, status, platform, username_hash, device_id_hash, tenant, ssid,
		eap_method, inner_method, profile_hash, signature_fingerprint, content_type, file_extension,
		expires_at, policy_mode, details_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(delivery_key) DO UPDATE SET
		updated_at = excluded.updated_at,
		status = excluded.status,
		platform = excluded.platform,
		username_hash = excluded.username_hash,
		device_id_hash = excluded.device_id_hash,
		tenant = excluded.tenant,
		ssid = excluded.ssid,
		eap_method = excluded.eap_method,
		inner_method = excluded.inner_method,
		profile_hash = excluded.profile_hash,
		signature_fingerprint = excluded.signature_fingerprint,
		content_type = excluded.content_type,
		file_extension = excluded.file_extension,
		expires_at = excluded.expires_at,
		policy_mode = excluded.policy_mode,
		details_json = excluded.details_json`,
		normalized.DeliveryKey, normalized.UpdatedAt.UTC(), normalized.Status, normalized.Platform,
		normalized.UsernameHash, normalized.DeviceIDHash, normalized.Tenant, normalized.SSID,
		normalized.EAPMethod, normalized.InnerMethod, normalized.ProfileHash, normalized.SignatureFingerprint,
		normalized.ContentType, normalized.FileExtension, emptyTimeToNil(normalized.ExpiresAt), normalized.PolicyMode, string(detailsJSON))
	if err != nil {
		return err
	}
	return trimSupplicantProfileDeliveries(retentionLimit)
}

func ListSupplicantLifecycleEvents(filter SupplicantLifecycleEventFilter) ([]SupplicantLifecycleEvent, error) {
	limit := boundedLimit(filter.Limit, 100, 5000)
	query := `SELECT id, observed_at, protocol, platform, decision, action, reason, COALESCE(username_hash, ''),
		COALESCE(device_id_hash, ''), COALESCE(tenant, ''), COALESCE(eap_method, ''), COALESCE(inner_method, ''),
		COALESCE(identity_source, ''), COALESCE(password_expired, 0), COALESCE(days_until_expiry, 0),
		COALESCE(password_change_requested, 0), COALESCE(password_change_required, 0), COALESCE(password_changed, 0),
		COALESCE(old_password_verified, 0), COALESCE(new_password_meets_policy, 0), COALESCE(mfa_complete, 0),
		COALESCE(tls_protected, 0), COALESCE(verifier_compatible, 0), COALESCE(profile_requested, 0),
		COALESCE(profile_signed, 0), COALESCE(signing_key_available, 0), COALESCE(trust_anchor_pinned, 0),
		COALESCE(server_name_matched, 0), COALESCE(delivery_token_valid, 0), COALESCE(device_managed, 0),
		COALESCE(certificate_lifecycle_ready, 0), COALESCE(policy_mode, ''), COALESCE(latency_ms, 0),
		COALESCE(details_json, '{}')
		FROM supplicant_lifecycle_events WHERE 1=1`
	var args []any
	if strings.TrimSpace(filter.Decision) != "" {
		query += " AND decision = ?"
		args = append(args, strings.TrimSpace(filter.Decision))
	}
	if strings.TrimSpace(filter.Platform) != "" {
		query += " AND platform = ?"
		args = append(args, strings.TrimSpace(filter.Platform))
	}
	if strings.TrimSpace(filter.EAPMethod) != "" {
		query += " AND eap_method = ?"
		args = append(args, strings.TrimSpace(filter.EAPMethod))
	}
	query += " ORDER BY observed_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SupplicantLifecycleEvent
	for rows.Next() {
		item, err := scanSupplicantLifecycleEvent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func ListSupplicantProfileDeliveries(filter SupplicantProfileDeliveryFilter) ([]SupplicantProfileDelivery, error) {
	limit := boundedLimit(filter.Limit, 100, 5000)
	query := `SELECT delivery_key, updated_at, status, platform, COALESCE(username_hash, ''), COALESCE(device_id_hash, ''),
		COALESCE(tenant, ''), COALESCE(ssid, ''), COALESCE(eap_method, ''), COALESCE(inner_method, ''),
		COALESCE(profile_hash, ''), COALESCE(signature_fingerprint, ''), COALESCE(content_type, ''),
		COALESCE(file_extension, ''), expires_at, COALESCE(policy_mode, ''), COALESCE(details_json, '{}')
		FROM supplicant_profile_deliveries WHERE 1=1`
	var args []any
	if strings.TrimSpace(filter.Status) != "" {
		query += " AND status = ?"
		args = append(args, strings.TrimSpace(filter.Status))
	}
	if strings.TrimSpace(filter.Platform) != "" {
		query += " AND platform = ?"
		args = append(args, strings.TrimSpace(filter.Platform))
	}
	query += " ORDER BY updated_at DESC, delivery_key DESC LIMIT ?"
	args = append(args, limit)
	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []SupplicantProfileDelivery
	for rows.Next() {
		item, err := scanSupplicantProfileDelivery(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func SummarizeSupplicantLifecycle(limit int) (SupplicantLifecycleSummary, error) {
	events, err := ListSupplicantLifecycleEvents(SupplicantLifecycleEventFilter{Limit: limit})
	if err != nil {
		return SupplicantLifecycleSummary{}, err
	}
	profiles, err := ListSupplicantProfileDeliveries(SupplicantProfileDeliveryFilter{Limit: limit})
	if err != nil {
		return SupplicantLifecycleSummary{}, err
	}
	summary := SupplicantLifecycleSummary{
		ByDecision:  map[string]int{},
		ByPlatform:  map[string]int{},
		ByEAPMethod: map[string]int{},
	}
	now := time.Now()
	for i, event := range events {
		summary.TotalEvents++
		summary.ByDecision[event.Decision]++
		summary.ByPlatform[event.Platform]++
		summary.ByEAPMethod[event.EAPMethod]++
		switch event.Decision {
		case "accepted":
			summary.Accepted++
		case "rejected":
			summary.Rejected++
			if summary.LastRejectedReason == "" {
				summary.LastRejectedReason = event.Reason
			}
		case "monitor_allowed":
			summary.MonitorAllowed++
		case "password_change_required":
			summary.PasswordChangeRequired++
		}
		if event.PasswordChanged {
			summary.PasswordChanged++
		}
		if event.ProfileRequested && event.Decision == "accepted" {
			summary.ProfilesDelivered++
			if summary.LastProfileDeliveredAt == "" {
				summary.LastProfileDeliveredAt = event.ObservedAt.UTC().Format(time.RFC3339)
			}
		}
		reason := strings.ToLower(event.Reason)
		if event.ProfileRequested && event.Decision != "accepted" && strings.Contains(reason, "signed") {
			summary.UnsignedProfileBlocked++
		}
		if event.Decision != "accepted" && strings.Contains(reason, "trust") {
			summary.TrustPinFailures++
		}
		if event.Decision != "accepted" && strings.Contains(reason, "verifier") {
			summary.VerifierFailures++
		}
		if event.Decision != "accepted" && strings.Contains(reason, "tls") {
			summary.TLSFailures++
		}
		if i == 0 && !event.ObservedAt.IsZero() {
			summary.LastEventAt = event.ObservedAt.UTC().Format(time.RFC3339)
		}
	}
	for _, profile := range profiles {
		if profile.Status == "active" && (profile.ExpiresAt.IsZero() || profile.ExpiresAt.After(now)) {
			summary.ActiveProfiles++
			continue
		}
		if profile.Status == "expired" || (!profile.ExpiresAt.IsZero() && !profile.ExpiresAt.After(now)) {
			summary.ExpiredProfiles++
		}
	}
	return summary, nil
}

func SupplicantLifecycleDeliveryKey(usernameHash, deviceHash, platform, ssid string) string {
	raw := strings.ToLower(strings.TrimSpace(usernameHash)) + "\x00" + strings.ToLower(strings.TrimSpace(deviceHash)) + "\x00" + strings.ToLower(strings.TrimSpace(platform)) + "\x00" + strings.TrimSpace(ssid)
	return HashEAPIdentity(raw)
}

func normalizeSupplicantLifecycleEvent(event SupplicantLifecycleEvent) SupplicantLifecycleEvent {
	if event.ObservedAt.IsZero() {
		event.ObservedAt = time.Now().UTC()
	}
	event.Protocol = defaultNonEmpty(strings.ToLower(strings.TrimSpace(event.Protocol)), "api")
	event.Platform = defaultNonEmpty(strings.ToLower(strings.TrimSpace(event.Platform)), "unknown")
	event.Decision = defaultNonEmpty(strings.TrimSpace(event.Decision), "unknown")
	event.Action = defaultNonEmpty(strings.TrimSpace(event.Action), "unknown")
	event.Reason = strings.TrimSpace(event.Reason)
	event.UsernameHash = HashEAPIdentity(event.UsernameHash)
	event.DeviceIDHash = HashEAPIdentity(event.DeviceIDHash)
	event.EAPMethod = strings.ToLower(strings.TrimSpace(event.EAPMethod))
	event.InnerMethod = strings.ToLower(strings.TrimSpace(event.InnerMethod))
	event.IdentitySource = strings.ToLower(strings.TrimSpace(event.IdentitySource))
	event.PolicyMode = strings.ToLower(strings.TrimSpace(event.PolicyMode))
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	return event
}

func normalizeSupplicantProfileDelivery(item SupplicantProfileDelivery) SupplicantProfileDelivery {
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = time.Now().UTC()
	}
	item.DeliveryKey = strings.TrimSpace(item.DeliveryKey)
	if item.DeliveryKey == "" {
		item.DeliveryKey = SupplicantLifecycleDeliveryKey(item.UsernameHash, item.DeviceIDHash, item.Platform, item.SSID)
	}
	item.Status = defaultNonEmpty(strings.ToLower(strings.TrimSpace(item.Status)), "active")
	item.Platform = defaultNonEmpty(strings.ToLower(strings.TrimSpace(item.Platform)), "unknown")
	item.UsernameHash = HashEAPIdentity(item.UsernameHash)
	item.DeviceIDHash = HashEAPIdentity(item.DeviceIDHash)
	item.EAPMethod = strings.ToLower(strings.TrimSpace(item.EAPMethod))
	item.InnerMethod = strings.ToLower(strings.TrimSpace(item.InnerMethod))
	item.PolicyMode = strings.ToLower(strings.TrimSpace(item.PolicyMode))
	if item.Details == nil {
		item.Details = map[string]string{}
	}
	return item
}

func scanSupplicantLifecycleEvent(rows interface {
	Scan(dest ...any) error
}) (SupplicantLifecycleEvent, error) {
	var item SupplicantLifecycleEvent
	var passwordExpired, changeRequested, changeRequired, changed, oldVerified, newMeets, mfa, tlsProtected int
	var verifier, profileRequested, profileSigned, signingKey, trustPinned, serverMatched, tokenValid, managed, certReady int
	var details string
	if err := rows.Scan(
		&item.ID, &item.ObservedAt, &item.Protocol, &item.Platform, &item.Decision, &item.Action, &item.Reason,
		&item.UsernameHash, &item.DeviceIDHash, &item.Tenant, &item.EAPMethod, &item.InnerMethod, &item.IdentitySource,
		&passwordExpired, &item.DaysUntilExpiry, &changeRequested, &changeRequired, &changed, &oldVerified,
		&newMeets, &mfa, &tlsProtected, &verifier, &profileRequested, &profileSigned, &signingKey,
		&trustPinned, &serverMatched, &tokenValid, &managed, &certReady, &item.PolicyMode, &item.LatencyMS, &details,
	); err != nil {
		return item, err
	}
	item.PasswordExpired = passwordExpired != 0
	item.PasswordChangeRequested = changeRequested != 0
	item.PasswordChangeRequired = changeRequired != 0
	item.PasswordChanged = changed != 0
	item.OldPasswordVerified = oldVerified != 0
	item.NewPasswordMeetsPolicy = newMeets != 0
	item.MFAComplete = mfa != 0
	item.TLSProtected = tlsProtected != 0
	item.VerifierCompatible = verifier != 0
	item.ProfileRequested = profileRequested != 0
	item.ProfileSigned = profileSigned != 0
	item.SigningKeyAvailable = signingKey != 0
	item.TrustAnchorPinned = trustPinned != 0
	item.ServerNameMatched = serverMatched != 0
	item.DeliveryTokenValid = tokenValid != 0
	item.DeviceManaged = managed != 0
	item.CertificateLifecycleReady = certReady != 0
	item.Details = parseDetails(details)
	return item, nil
}

func scanSupplicantProfileDelivery(rows interface {
	Scan(dest ...any) error
}) (SupplicantProfileDelivery, error) {
	var item SupplicantProfileDelivery
	var expires sql.NullTime
	var details string
	if err := rows.Scan(
		&item.DeliveryKey, &item.UpdatedAt, &item.Status, &item.Platform, &item.UsernameHash, &item.DeviceIDHash,
		&item.Tenant, &item.SSID, &item.EAPMethod, &item.InnerMethod, &item.ProfileHash, &item.SignatureFingerprint,
		&item.ContentType, &item.FileExtension, &expires, &item.PolicyMode, &details,
	); err != nil {
		return item, err
	}
	if expires.Valid {
		item.ExpiresAt = expires.Time
	}
	item.Details = parseDetails(details)
	return item, nil
}

func parseDetails(raw string) map[string]string {
	details := map[string]string{}
	_ = json.Unmarshal([]byte(raw), &details)
	return details
}

func supplicantDeliveryKey(event SupplicantLifecycleEvent) string {
	return SupplicantLifecycleDeliveryKey(event.UsernameHash, event.DeviceIDHash, event.Platform, event.Details["ssid"])
}

func trimSupplicantLifecycleEvents(limit int) error {
	if limit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM supplicant_lifecycle_events WHERE id NOT IN (
		SELECT id FROM supplicant_lifecycle_events ORDER BY observed_at DESC, id DESC LIMIT ?
	)`, limit)
	return err
}

func trimSupplicantProfileDeliveries(limit int) error {
	if limit <= 0 {
		return nil
	}
	_, err := DB.Exec(`DELETE FROM supplicant_profile_deliveries WHERE delivery_key NOT IN (
		SELECT delivery_key FROM supplicant_profile_deliveries ORDER BY updated_at DESC, delivery_key DESC LIMIT ?
	)`, limit)
	return err
}

func boundedLimit(value, fallback, max int) int {
	if value <= 0 {
		value = fallback
	}
	if value > max {
		value = max
	}
	return value
}

func defaultNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func emptyTimeToNil(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
