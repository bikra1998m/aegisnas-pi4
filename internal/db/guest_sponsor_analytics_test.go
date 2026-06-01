package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGuestSponsorApprovalAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "guest-sponsor-analytics-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	originalNow := guestLifecycleNow
	guestLifecycleNow = func() time.Time {
		return time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		guestLifecycleNow = originalNow
	}()

	_, err = DB.Exec(`INSERT INTO guest_registrations (
		id, status, tenant, full_name, email, phone, company,
		sponsor_name, sponsor_email, sponsor_phone, role,
		guest_token_hash, approval_delivery_status, invite_delivery_status,
		created_at, approved_at, rejected_at, completed_at, expires_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "pending", "tenant-a", "Alice Guest", "alice@example.test", "1111111111", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-basic",
		"hash-1", "pending", "queued",
		"2026-05-25T11:20:00Z", "", "", "", "2026-05-26T11:20:00Z",

		"guest-2", "approved", "tenant-a", "Bob Visitor", "bob@example.test", "2222222222", "LabCo",
		"Taylor Sponsor", "taylor@example.test", "", "guest-basic",
		"hash-2", "sent", "sent",
		"2026-05-25T10:05:00Z", "2026-05-25T10:25:00Z", "", "", "2026-05-26T10:05:00Z",

		"guest-3", "rejected", "tenant-b", "Carla Declined", "carla@example.test", "3333333333", "Visitors Inc",
		"Jordan Sponsor", "jordan@example.test", "", "guest-standard",
		"hash-3", "failed", "not_requested",
		"2026-05-25T09:10:00Z", "", "2026-05-25T09:20:00Z", "", "2026-05-26T09:10:00Z",

		"guest-4", "completed", "tenant-a", "Dylan Complete", "dylan@example.test", "4444444444", "Guests United",
		"Pat Sponsor", "pat@example.test", "", "guest-vip",
		"hash-4", "sent", "sent",
		"2026-05-25T08:15:00Z", "2026-05-25T08:25:00Z", "", "2026-05-25T08:55:00Z", "2026-05-26T08:15:00Z",

		"guest-5", "pending", "tenant-a", "Eli Aging", "eli@example.test", "5555555555", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-standard",
		"hash-5", "sent", "queued",
		"2026-05-24T06:00:00Z", "", "", "", "2026-05-25T06:00:00Z",

		"guest-6", "pending", "tenant-a", "Fran Escalation", "fran@example.test", "6666666666", "Visitors Inc",
		"Taylor Sponsor", "taylor@example.test", "", "guest-standard",
		"hash-6", "sent", "queued",
		"2026-05-25T06:30:00Z", "", "", "", "2026-05-26T06:30:00Z",
	)
	require.NoError(t, err)

	summary, err := GetGuestSponsorApprovalAnalytics(GuestLifecycleQuery{
		Window:      48 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 48, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 720, summary.BucketMinutes)
	assert.Equal(t, 6, summary.TotalRecords)
	assert.Equal(t, 6, summary.SponsorApprovalRequiredCount)
	assert.Equal(t, 3, summary.PendingSponsorApprovalCount)
	assert.Equal(t, 3, summary.PendingOlderThan30MinutesCount)
	assert.Equal(t, 2, summary.PendingOlderThan4HoursCount)
	assert.Equal(t, 1, summary.PendingOlderThan24HoursCount)
	assert.Equal(t, 1, summary.ApprovedWithSponsorCount)
	assert.Equal(t, 1, summary.RejectedWithSponsorCount)
	assert.Equal(t, 1, summary.CompletedWithSponsorCount)
	assert.Equal(t, 4, summary.UniqueSponsorsWindow)
	assert.Equal(t, 3, summary.UniqueCompaniesWindow)
	assert.Equal(t, int64(15), summary.AvgApprovalMinutes)
	assert.Equal(t, int64(20), summary.MaxApprovalMinutes)
	assert.Equal(t, int64(723), summary.AvgPendingApprovalMinutes)
	assert.Equal(t, int64(1800), summary.MaxPendingApprovalMinutes)
	assert.Equal(t, "2026-05-25T11:20:00Z", summary.LatestSubmittedAt)
	assert.Equal(t, "2026-05-25T10:25:00Z", summary.LatestApprovedAt)
	assert.Equal(t, "2026-05-25T09:20:00Z", summary.LatestRejectedAt)
	require.Len(t, summary.Sponsors, 4)
	assert.Equal(t, "sam@example.test", summary.Sponsors[0].Name)
	assert.Equal(t, 2, summary.Sponsors[0].PendingCount)
	assert.Equal(t, 1, summary.Sponsors[0].OlderThan24HoursCount)
	assert.Equal(t, "taylor@example.test", summary.Sponsors[1].Name)
	assert.Equal(t, 1, summary.Sponsors[1].PendingCount)
	assert.Equal(t, 1, summary.Sponsors[1].ApprovedCount)
	assert.Equal(t, int64(20), summary.Sponsors[1].AvgApprovalMinutes)
	require.Len(t, summary.Companies, 3)
	assert.Equal(t, "LabCo", summary.Companies[0].Name)
	assert.Equal(t, 3, summary.Companies[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 0, summary.Buckets[0].SubmittedCount)
	assert.Equal(t, 1, summary.Buckets[1].SubmittedCount)
	assert.Equal(t, 1, summary.Buckets[1].PendingSponsorApprovalCount)
	assert.Equal(t, 1, summary.Buckets[1].PendingOlderThan24HoursCount)
	assert.Equal(t, 5, summary.Buckets[3].SubmittedCount)
	assert.Equal(t, 2, summary.Buckets[3].PendingSponsorApprovalCount)
	assert.Equal(t, 2, summary.Buckets[3].PendingOlderThan30MinutesCount)
	assert.Equal(t, 1, summary.Buckets[3].PendingOlderThan4HoursCount)
	assert.Equal(t, 2, summary.Buckets[3].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[3].RejectedCount)
	assert.Equal(t, 1, summary.Buckets[3].CompletedCount)

	tenantOnly, err := GetGuestSponsorApprovalAnalytics(GuestLifecycleQuery{
		TenantScopes: []string{"tenant-a"},
		Window:       48 * time.Hour,
		BucketCount:  4,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, tenantOnly.TotalRecords)
	assert.Equal(t, 0, tenantOnly.RejectedWithSponsorCount)
	assert.Equal(t, 3, tenantOnly.PendingSponsorApprovalCount)
	assert.Equal(t, 3, tenantOnly.UniqueSponsorsWindow)
}
