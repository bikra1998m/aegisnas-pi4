package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGuestLifecycleSummary(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "guest-lifecycle-*.db")
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
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "pending", "tenant-a", "Alice Guest", "alice@example.test", "1111111111", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-basic",
		"hash-1", "sent", "queued",
		"2026-05-25T11:30:00Z", "", "", "", "2026-05-26T11:30:00Z",

		"guest-2", "approved", "tenant-a", "Bob Visitor", "bob@example.test", "2222222222", "LabCo",
		"Taylor Sponsor", "taylor@example.test", "", "guest-basic",
		"hash-2", "sent", "sent",
		"2026-05-25T10:05:00Z", "2026-05-25T10:25:00Z", "", "", "2026-05-26T10:05:00Z",

		"guest-3", "rejected", "tenant-b", "Carla Declined", "carla@example.test", "3333333333", "Visitors Inc",
		"Jordan Sponsor", "jordan@example.test", "", "guest-standard",
		"hash-3", "failed", "not_requested",
		"2026-05-25T09:10:00Z", "", "2026-05-25T09:20:00Z", "", "2026-05-26T09:10:00Z",

		"guest-4", "completed", "tenant-a", "Dylan Complete", "dylan@example.test", "4444444444", "Guests United",
		"", "", "", "guest-vip",
		"hash-4", "not_required", "sent",
		"2026-05-25T08:15:00Z", "2026-05-25T08:25:00Z", "", "2026-05-25T08:55:00Z", "2026-05-26T08:15:00Z",
	)
	require.NoError(t, err)

	summary, err := GetGuestLifecycleSummary(GuestLifecycleQuery{
		Window:      4 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 4, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 60, summary.BucketMinutes)
	assert.Equal(t, 4, summary.TotalRecords)
	assert.Equal(t, 1, summary.PendingCount)
	assert.Equal(t, 1, summary.ApprovedCount)
	assert.Equal(t, 1, summary.RejectedCount)
	assert.Equal(t, 1, summary.CompletedCount)
	assert.Equal(t, 3, summary.SponsorApprovalRequiredCount)
	assert.Equal(t, 0, summary.ApprovalDeliveryPendingCount)
	assert.Equal(t, 2, summary.ApprovalDeliverySentCount)
	assert.Equal(t, 1, summary.ApprovalDeliveryFailedCount)
	assert.Equal(t, 1, summary.InviteQueuedCount)
	assert.Equal(t, 2, summary.InviteSentCount)
	assert.Equal(t, 0, summary.InviteFailedCount)
	assert.Equal(t, 4, summary.UniqueGuestsWindow)
	assert.Equal(t, 3, summary.UniqueSponsorsWindow)
	assert.Equal(t, 3, summary.UniqueCompaniesWindow)
	assert.Equal(t, int64(15), summary.AvgApprovalMinutes)
	assert.Equal(t, int64(40), summary.AvgCompletionMinutes)
	assert.Equal(t, "2026-05-25T11:30:00Z", summary.LatestSubmittedAt)
	assert.Equal(t, "2026-05-25T10:25:00Z", summary.LatestApprovedAt)
	assert.Equal(t, "2026-05-25T09:20:00Z", summary.LatestRejectedAt)
	assert.Equal(t, "2026-05-25T08:55:00Z", summary.LatestCompletedAt)
	require.Len(t, summary.Roles, 3)
	assert.Equal(t, "guest-basic", summary.Roles[0].Name)
	assert.Equal(t, 2, summary.Roles[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 1, summary.Buckets[0].SubmittedCount)
	assert.Equal(t, 1, summary.Buckets[0].ApprovedCount)
	assert.Equal(t, 0, summary.Buckets[0].RejectedCount)
	assert.Equal(t, 1, summary.Buckets[0].CompletedCount)
	assert.Equal(t, 1, summary.Buckets[1].SubmittedCount)
	assert.Equal(t, 0, summary.Buckets[1].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[1].RejectedCount)
	assert.Equal(t, 1, summary.Buckets[2].SubmittedCount)
	assert.Equal(t, 1, summary.Buckets[2].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[3].SubmittedCount)

	tenantOnly, err := GetGuestLifecycleSummary(GuestLifecycleQuery{
		TenantScopes: []string{"tenant-a"},
		Window:       4 * time.Hour,
		BucketCount:  4,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, tenantOnly.TotalRecords)
	assert.Equal(t, 1, tenantOnly.PendingCount)
	assert.Equal(t, 1, tenantOnly.ApprovedCount)
	assert.Equal(t, 0, tenantOnly.RejectedCount)
	assert.Equal(t, 1, tenantOnly.CompletedCount)
	assert.Equal(t, 2, tenantOnly.UniqueCompaniesWindow)
}
