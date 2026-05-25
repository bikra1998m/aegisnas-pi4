package db

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSessionAnalyticsWindow      = 24 * time.Hour
	defaultSessionAnalyticsBucketCount = 24
	maxSessionAnalyticsBucketCount     = 96
)

type SessionAnalyticsQuery struct {
	Username     string
	AuthMethod   string
	TenantScopes []string
	Window       time.Duration
	BucketCount  int
}

type SessionAnalyticsCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type SessionAnalyticsBucket struct {
	Start                    string `json:"start"`
	End                      string `json:"end"`
	StartedCount             int    `json:"started_count"`
	EndedCount               int    `json:"ended_count"`
	EndedTrafficTotal        int64  `json:"ended_traffic_total"`
	EndedSessionSecondsTotal int64  `json:"ended_session_seconds_total"`
}

type SessionAnalyticsSummary struct {
	WindowHours                 int                      `json:"window_hours"`
	BucketCount                 int                      `json:"bucket_count"`
	BucketMinutes               int                      `json:"bucket_minutes"`
	TotalRecords                int                      `json:"total_records"`
	StartedCount                int                      `json:"started_count"`
	EndedCount                  int                      `json:"ended_count"`
	ActiveNow                   int                      `json:"active_now"`
	UniqueUsersWindow           int                      `json:"unique_users_window"`
	UniqueMACsWindow            int                      `json:"unique_macs_window"`
	UniqueIPsWindow             int                      `json:"unique_ips_window"`
	EndedTrafficTotal           int64                    `json:"ended_traffic_total"`
	EndedSessionSecondsTotal    int64                    `json:"ended_session_seconds_total"`
	AvgEndedSessionSeconds      int64                    `json:"avg_ended_session_seconds"`
	MaxEndedSessionSeconds      int64                    `json:"max_ended_session_seconds"`
	LongestActiveSessionSeconds int64                    `json:"longest_active_session_seconds"`
	PeakConcurrentSessions      int                      `json:"peak_concurrent_sessions"`
	LatestStartAt               string                   `json:"latest_start_at"`
	LatestEndAt                 string                   `json:"latest_end_at"`
	AuthMethods                 []SessionAnalyticsCount  `json:"auth_methods"`
	Roles                       []SessionAnalyticsCount  `json:"roles"`
	VLANs                       []SessionAnalyticsCount  `json:"vlans"`
	Buckets                     []SessionAnalyticsBucket `json:"buckets"`
}

type sessionAnalyticsRow struct {
	Username        string
	MAC             string
	IP              string
	AuthMethod      string
	Role            string
	VLAN            int
	StartTime       string
	LastActivity    string
	EndTime         string
	BytesIn         int64
	BytesOut        int64
	AcctSessionTime int64
}

type sessionAnalyticsEvent struct {
	At    time.Time
	Delta int
}

var sessionAnalyticsNow = time.Now

func GetSessionAnalytics(query SessionAnalyticsQuery) (SessionAnalyticsSummary, error) {
	if DB == nil {
		return SessionAnalyticsSummary{}, fmt.Errorf("database not initialized")
	}

	window := query.Window
	if window <= 0 {
		window = defaultSessionAnalyticsWindow
	}
	bucketCount := query.BucketCount
	if bucketCount <= 0 {
		bucketCount = defaultSessionAnalyticsBucketCount
	}
	if bucketCount > maxSessionAnalyticsBucketCount {
		bucketCount = maxSessionAnalyticsBucketCount
	}

	now := sessionAnalyticsNow().UTC()
	cutoff := now.Add(-window)
	bucketDuration := window / time.Duration(bucketCount)
	if bucketDuration <= 0 {
		bucketDuration = time.Hour
	}

	rows, err := listSessionAnalyticsRows(query, cutoff)
	if err != nil {
		return SessionAnalyticsSummary{}, err
	}

	buckets := make([]SessionAnalyticsBucket, bucketCount)
	for i := range buckets {
		start := cutoff.Add(time.Duration(i) * bucketDuration)
		end := start.Add(bucketDuration)
		if i == bucketCount-1 {
			end = now
		}
		buckets[i] = SessionAnalyticsBucket{
			Start: start.Format(time.RFC3339),
			End:   end.Format(time.RFC3339),
		}
	}

	summary := SessionAnalyticsSummary{
		WindowHours:   int(window.Hours()),
		BucketCount:   bucketCount,
		BucketMinutes: int(bucketDuration.Minutes()),
		Buckets:       buckets,
	}

	userSet := map[string]struct{}{}
	macSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	authCounts := map[string]int{}
	roleCounts := map[string]int{}
	vlanCounts := map[string]int{}
	events := make([]sessionAnalyticsEvent, 0, len(rows)*2)

	for _, item := range rows {
		start := parseSessionAnalyticsTime(item.StartTime)
		if start.IsZero() || start.After(now) {
			continue
		}
		lastActivity := parseSessionAnalyticsTime(item.LastActivity)
		end := parseSessionAnalyticsTime(item.EndTime)

		touchesWindow := end.IsZero() || !start.Before(cutoff) || (!end.IsZero() && !end.Before(cutoff)) || (!lastActivity.IsZero() && !lastActivity.Before(cutoff))
		if !touchesWindow {
			continue
		}

		summary.TotalRecords++
		if username := strings.TrimSpace(item.Username); username != "" {
			userSet[username] = struct{}{}
		}
		if mac := strings.TrimSpace(item.MAC); mac != "" {
			macSet[mac] = struct{}{}
		}
		if ip := strings.TrimSpace(item.IP); ip != "" {
			ipSet[ip] = struct{}{}
		}

		authName := strings.TrimSpace(item.AuthMethod)
		if authName == "" {
			authName = "unknown"
		}
		authCounts[authName]++

		roleName := strings.TrimSpace(item.Role)
		if roleName == "" {
			roleName = "unassigned"
		}
		roleCounts[roleName]++

		vlanName := strconv.Itoa(item.VLAN)
		vlanCounts[vlanName]++

		if !start.Before(cutoff) {
			summary.StartedCount++
			if summary.LatestStartAt == "" || start.Format(time.RFC3339) > summary.LatestStartAt {
				summary.LatestStartAt = start.Format(time.RFC3339)
			}
			buckets[bucketIndex(start, cutoff, bucketDuration, bucketCount)].StartedCount++
		}

		if end.IsZero() {
			summary.ActiveNow++
			activeSeconds := int64(now.Sub(start).Seconds())
			if activeSeconds > summary.LongestActiveSessionSeconds {
				summary.LongestActiveSessionSeconds = activeSeconds
			}
		}

		sessionSeconds := item.AcctSessionTime
		if sessionSeconds <= 0 && !end.IsZero() && end.After(start) {
			sessionSeconds = int64(end.Sub(start).Seconds())
		}

		if !end.IsZero() && !end.Before(cutoff) {
			summary.EndedCount++
			endedTraffic := item.BytesIn + item.BytesOut
			summary.EndedTrafficTotal += endedTraffic
			summary.EndedSessionSecondsTotal += sessionSeconds
			if sessionSeconds > summary.MaxEndedSessionSeconds {
				summary.MaxEndedSessionSeconds = sessionSeconds
			}
			if summary.LatestEndAt == "" || end.Format(time.RFC3339) > summary.LatestEndAt {
				summary.LatestEndAt = end.Format(time.RFC3339)
			}
			idx := bucketIndex(end, cutoff, bucketDuration, bucketCount)
			buckets[idx].EndedCount++
			buckets[idx].EndedTrafficTotal += endedTraffic
			buckets[idx].EndedSessionSecondsTotal += sessionSeconds
		}

		intervalStart := maxSessionAnalyticsTime(start, cutoff)
		intervalEnd := now
		if !end.IsZero() && end.Before(now) {
			intervalEnd = end
		}
		if intervalEnd.After(intervalStart) {
			events = append(events, sessionAnalyticsEvent{At: intervalStart, Delta: 1})
			events = append(events, sessionAnalyticsEvent{At: intervalEnd, Delta: -1})
		}
	}

	summary.UniqueUsersWindow = len(userSet)
	summary.UniqueMACsWindow = len(macSet)
	summary.UniqueIPsWindow = len(ipSet)
	if summary.EndedCount > 0 {
		summary.AvgEndedSessionSeconds = summary.EndedSessionSecondsTotal / int64(summary.EndedCount)
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			return events[i].Delta < events[j].Delta
		}
		return events[i].At.Before(events[j].At)
	})
	currentConcurrent := 0
	for _, event := range events {
		currentConcurrent += event.Delta
		if currentConcurrent > summary.PeakConcurrentSessions {
			summary.PeakConcurrentSessions = currentConcurrent
		}
	}

	summary.AuthMethods = sessionAnalyticsCounts(authCounts)
	summary.Roles = sessionAnalyticsCounts(roleCounts)
	summary.VLANs = sessionAnalyticsCounts(vlanCounts)
	summary.Buckets = buckets

	return summary, nil
}

func listSessionAnalyticsRows(query SessionAnalyticsQuery, cutoff time.Time) ([]sessionAnalyticsRow, error) {
	baseQuery := `SELECT
		COALESCE(username, ''),
		COALESCE(mac, ''),
		COALESCE(ip, ''),
		COALESCE(auth_method, ''),
		COALESCE(role, ''),
		COALESCE(vlan, 0),
		CAST(start_time AS TEXT),
		COALESCE(CAST(last_activity AS TEXT), ''),
		COALESCE(CAST(end_time AS TEXT), ''),
		COALESCE(bytes_in, 0),
		COALESCE(bytes_out, 0),
		COALESCE(acct_session_time, 0)
		FROM sessions`
	clauses, args := sessionHistoryClauses(SessionHistoryQuery{
		Username:     query.Username,
		AuthMethod:   query.AuthMethod,
		TenantScopes: query.TenantScopes,
	})
	clauses = append(clauses, `(end_time IS NULL OR datetime(start_time) >= datetime(?) OR datetime(COALESCE(end_time, '')) >= datetime(?) OR datetime(COALESCE(last_activity, '')) >= datetime(?))`)
	cutoffText := cutoff.Format(time.RFC3339)
	args = append(args, cutoffText, cutoffText, cutoffText)
	if len(clauses) > 0 {
		baseQuery += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	baseQuery += ` ORDER BY datetime(start_time) DESC, id DESC`

	rows, err := DB.Query(baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list session analytics rows: %w", err)
	}
	defer rows.Close()

	items := []sessionAnalyticsRow{}
	for rows.Next() {
		var item sessionAnalyticsRow
		if err := rows.Scan(
			&item.Username,
			&item.MAC,
			&item.IP,
			&item.AuthMethod,
			&item.Role,
			&item.VLAN,
			&item.StartTime,
			&item.LastActivity,
			&item.EndTime,
			&item.BytesIn,
			&item.BytesOut,
			&item.AcctSessionTime,
		); err != nil {
			return nil, fmt.Errorf("scan session analytics row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session analytics rows: %w", err)
	}
	return items, nil
}

func sessionAnalyticsCounts(values map[string]int) []SessionAnalyticsCount {
	counts := make([]SessionAnalyticsCount, 0, len(values))
	for name, count := range values {
		counts = append(counts, SessionAnalyticsCount{Name: name, Count: count})
	}
	sort.SliceStable(counts, func(i, j int) bool {
		if counts[i].Count == counts[j].Count {
			return counts[i].Name < counts[j].Name
		}
		return counts[i].Count > counts[j].Count
	})
	return counts
}

func bucketIndex(at, cutoff time.Time, bucketDuration time.Duration, bucketCount int) int {
	if bucketCount <= 1 || bucketDuration <= 0 {
		return 0
	}
	if at.Before(cutoff) {
		return 0
	}
	index := int(at.Sub(cutoff) / bucketDuration)
	if index < 0 {
		return 0
	}
	if index >= bucketCount {
		return bucketCount - 1
	}
	return index
}

func parseSessionAnalyticsTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	if index := strings.Index(value, " m="); index >= 0 {
		value = value[:index]
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700 -0700",
		"2006-01-02 15:04:05 -0700 -0700",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func maxSessionAnalyticsTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
