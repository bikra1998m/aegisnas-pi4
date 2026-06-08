package db

import (
	"fmt"
	"strings"
	"time"
)

var voucherRedemptionAnalyticsNow = time.Now

type VoucherRedemptionQuery struct {
	Window      time.Duration
	BucketCount int
}

type VoucherRedemptionBucket struct {
	Start              string `json:"start"`
	End                string `json:"end"`
	SessionStartCount  int    `json:"session_start_count"`
	UniqueVoucherCount int    `json:"unique_voucher_count"`
	FirstRedeemedCount int    `json:"first_redeemed_count"`
	EndedCount         int    `json:"ended_count"`
	EndedTrafficTotal  int64  `json:"ended_traffic_total"`
}

type VoucherRedemptionSummary struct {
	WindowHours                    int                       `json:"window_hours"`
	BucketCount                    int                       `json:"bucket_count"`
	BucketMinutes                  int                       `json:"bucket_minutes"`
	TotalVouchers                  int                       `json:"total_vouchers"`
	RedeemedVoucherCount           int                       `json:"redeemed_voucher_count"`
	NeverRedeemedCount             int                       `json:"never_redeemed_count"`
	RedeemedInWindowCount          int                       `json:"redeemed_in_window_count"`
	FirstRedeemedInWindowCount     int                       `json:"first_redeemed_in_window_count"`
	RedeemedOnceCount              int                       `json:"redeemed_once_count"`
	RedeemedRepeatCount            int                       `json:"redeemed_repeat_count"`
	SessionStartCount              int                       `json:"session_start_count"`
	EndedSessionCount              int                       `json:"ended_session_count"`
	ActiveSessionCount             int                       `json:"active_session_count"`
	ActiveVoucherCount             int                       `json:"active_voucher_count"`
	RedeemedWithin24HoursCount     int                       `json:"redeemed_within_24_hours_count"`
	RedeemedWithin7DaysCount       int                       `json:"redeemed_within_7_days_count"`
	AvgSessionsPerRedeemedVoucher  float64                   `json:"avg_sessions_per_redeemed_voucher"`
	AvgFirstRedemptionDelayMinutes int64                     `json:"avg_first_redemption_delay_minutes"`
	MaxFirstRedemptionDelayMinutes int64                     `json:"max_first_redemption_delay_minutes"`
	EndedTrafficTotal              int64                     `json:"ended_traffic_total"`
	AvgEndedSessionSeconds         int64                     `json:"avg_ended_session_seconds"`
	MaxEndedSessionSeconds         int64                     `json:"max_ended_session_seconds"`
	LatestSessionStartAt           string                    `json:"latest_session_start_at"`
	Roles                          []SessionAnalyticsCount   `json:"roles"`
	Buckets                        []VoucherRedemptionBucket `json:"buckets"`
}

type voucherRedemptionVoucher struct {
	Code      string
	Role      string
	CreatedAt time.Time
}

type voucherRedemptionSession struct {
	Username        string
	StartTime       string
	EndTime         string
	BytesIn         int64
	BytesOut        int64
	AcctSessionTime int64
}

type voucherRedemptionState struct {
	SessionCount     int
	FirstStart       time.Time
	LatestStart      time.Time
	RedeemedInWindow bool
}

func GetVoucherRedemptionAnalytics(query VoucherRedemptionQuery) (VoucherRedemptionSummary, error) {
	if DB == nil {
		return VoucherRedemptionSummary{}, fmt.Errorf("database not initialized")
	}

	window := query.Window
	if window <= 0 {
		window = defaultVoucherAnalyticsWindow
	}
	bucketCount := query.BucketCount
	if bucketCount <= 0 {
		bucketCount = defaultVoucherAnalyticsBucketCount
	}
	if bucketCount > maxVoucherAnalyticsBucketCount {
		bucketCount = maxVoucherAnalyticsBucketCount
	}

	now := voucherRedemptionAnalyticsNow().UTC()
	cutoff := now.Add(-window)
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = 24 * time.Hour
	}

	vouchers, err := listVoucherRedemptionVouchers()
	if err != nil {
		return VoucherRedemptionSummary{}, err
	}
	sessions, err := listVoucherRedemptionSessions()
	if err != nil {
		return VoucherRedemptionSummary{}, err
	}

	buckets := make([]VoucherRedemptionBucket, bucketCount)
	bucketVoucherSets := make([]map[string]struct{}, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = VoucherRedemptionBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
		bucketVoucherSets[i] = map[string]struct{}{}
	}

	summary := VoucherRedemptionSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		TotalVouchers: len(vouchers),
		Buckets:       buckets,
	}

	redemptionStates := make(map[string]*voucherRedemptionState, len(vouchers))
	activeVoucherSet := map[string]struct{}{}
	roleCounts := map[string]int{}
	var endedSessionSecondsTotal int64
	var latestSessionStart time.Time

	for _, item := range sessions {
		code := voucherCodeFromSessionUsername(item.Username)
		if code == "" {
			continue
		}
		if _, ok := vouchers[code]; !ok {
			continue
		}

		start := parseSessionAnalyticsTime(item.StartTime)
		if start.IsZero() || start.After(now) {
			continue
		}
		end := parseSessionAnalyticsTime(item.EndTime)

		state := redemptionStates[code]
		if state == nil {
			state = &voucherRedemptionState{}
			redemptionStates[code] = state
		}
		state.SessionCount++
		if state.FirstStart.IsZero() || start.Before(state.FirstStart) {
			state.FirstStart = start
		}
		if state.LatestStart.IsZero() || start.After(state.LatestStart) {
			state.LatestStart = start
		}
		if latestSessionStart.IsZero() || start.After(latestSessionStart) {
			latestSessionStart = start
		}

		if !start.Before(cutoff) {
			state.RedeemedInWindow = true
			summary.SessionStartCount++
			index := bucketIndex(start, cutoff, bucketDuration, bucketCount)
			buckets[index].SessionStartCount++
			bucketVoucherSets[index][code] = struct{}{}
		}

		if end.IsZero() {
			summary.ActiveSessionCount++
			activeVoucherSet[code] = struct{}{}
		}

		sessionSeconds := item.AcctSessionTime
		if sessionSeconds <= 0 && !end.IsZero() && end.After(start) {
			sessionSeconds = int64(end.Sub(start).Seconds())
		}
		if !end.IsZero() && !end.Before(cutoff) {
			endedTraffic := item.BytesIn + item.BytesOut
			summary.EndedSessionCount++
			summary.EndedTrafficTotal += endedTraffic
			endedSessionSecondsTotal += sessionSeconds
			if sessionSeconds > summary.MaxEndedSessionSeconds {
				summary.MaxEndedSessionSeconds = sessionSeconds
			}
			index := bucketIndex(end, cutoff, bucketDuration, bucketCount)
			buckets[index].EndedCount++
			buckets[index].EndedTrafficTotal += endedTraffic
		}

	}

	var totalSessionsAcrossRedeemed int64
	var firstDelayTotalMinutes int64
	var firstDelayCount int64

	for code, voucher := range vouchers {
		state := redemptionStates[code]
		if state == nil || state.SessionCount == 0 {
			summary.NeverRedeemedCount++
			continue
		}

		summary.RedeemedVoucherCount++
		totalSessionsAcrossRedeemed += int64(state.SessionCount)
		roleName := strings.TrimSpace(voucher.Role)
		if roleName == "" {
			roleName = "unassigned"
		}
		roleCounts[roleName]++

		if state.SessionCount == 1 {
			summary.RedeemedOnceCount++
		} else {
			summary.RedeemedRepeatCount++
		}

		if state.RedeemedInWindow {
			summary.RedeemedInWindowCount++
		}

		if !voucher.CreatedAt.IsZero() && !state.FirstStart.IsZero() && !state.FirstStart.Before(voucher.CreatedAt) {
			delayMinutes := int64(state.FirstStart.Sub(voucher.CreatedAt).Minutes())
			firstDelayTotalMinutes += delayMinutes
			firstDelayCount++
			if delayMinutes > summary.MaxFirstRedemptionDelayMinutes {
				summary.MaxFirstRedemptionDelayMinutes = delayMinutes
			}
			if !state.FirstStart.After(voucher.CreatedAt.Add(24 * time.Hour)) {
				summary.RedeemedWithin24HoursCount++
			}
			if !state.FirstStart.After(voucher.CreatedAt.Add(7 * 24 * time.Hour)) {
				summary.RedeemedWithin7DaysCount++
			}
		}

		if !state.FirstStart.IsZero() && !state.FirstStart.Before(cutoff) {
			summary.FirstRedeemedInWindowCount++
			index := bucketIndex(state.FirstStart, cutoff, bucketDuration, bucketCount)
			buckets[index].FirstRedeemedCount++
		}
	}

	for index := range buckets {
		buckets[index].UniqueVoucherCount = len(bucketVoucherSets[index])
	}

	summary.ActiveVoucherCount = len(activeVoucherSet)
	if summary.RedeemedVoucherCount > 0 {
		summary.AvgSessionsPerRedeemedVoucher = float64(totalSessionsAcrossRedeemed) / float64(summary.RedeemedVoucherCount)
	}
	if firstDelayCount > 0 {
		summary.AvgFirstRedemptionDelayMinutes = firstDelayTotalMinutes / firstDelayCount
	}
	if summary.EndedSessionCount > 0 {
		summary.AvgEndedSessionSeconds = endedSessionSecondsTotal / int64(summary.EndedSessionCount)
	}
	if !latestSessionStart.IsZero() {
		summary.LatestSessionStartAt = latestSessionStart.Format(time.RFC3339)
	}
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.Buckets = buckets

	return summary, nil
}

func listVoucherRedemptionVouchers() (map[string]voucherRedemptionVoucher, error) {
	rows, err := DB.Query(`SELECT code, COALESCE(role, ''), COALESCE(created_at, '') FROM vouchers ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list voucher redemption vouchers: %w", err)
	}
	defer rows.Close()

	items := map[string]voucherRedemptionVoucher{}
	for rows.Next() {
		var (
			code         string
			role         string
			createdAtRaw string
		)
		if err := rows.Scan(&code, &role, &createdAtRaw); err != nil {
			return nil, fmt.Errorf("scan voucher redemption voucher: %w", err)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		items[code] = voucherRedemptionVoucher{
			Code:      code,
			Role:      role,
			CreatedAt: parseSessionAnalyticsTime(createdAtRaw),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate voucher redemption vouchers: %w", err)
	}
	return items, nil
}

func listVoucherRedemptionSessions() ([]voucherRedemptionSession, error) {
	rows, err := DB.Query(`SELECT
		COALESCE(username, ''),
		CAST(start_time AS TEXT),
		COALESCE(CAST(end_time AS TEXT), ''),
		COALESCE(bytes_in, 0),
		COALESCE(bytes_out, 0),
		COALESCE(acct_session_time, 0)
		FROM sessions
		WHERE COALESCE(auth_method, '') = 'voucher'
		ORDER BY datetime(start_time) DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list voucher redemption sessions: %w", err)
	}
	defer rows.Close()

	items := []voucherRedemptionSession{}
	for rows.Next() {
		var item voucherRedemptionSession
		if err := rows.Scan(
			&item.Username,
			&item.StartTime,
			&item.EndTime,
			&item.BytesIn,
			&item.BytesOut,
			&item.AcctSessionTime,
		); err != nil {
			return nil, fmt.Errorf("scan voucher redemption session: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate voucher redemption sessions: %w", err)
	}
	return items, nil
}

func voucherCodeFromSessionUsername(username string) string {
	username = strings.TrimSpace(username)
	if !strings.HasPrefix(username, "voucher_") {
		return ""
	}
	code := strings.TrimSpace(strings.TrimPrefix(username, "voucher_"))
	if code == "" {
		return ""
	}
	return code
}
