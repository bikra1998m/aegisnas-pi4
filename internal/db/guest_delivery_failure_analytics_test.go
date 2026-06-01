package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGuestDeliveryFailureAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "guest-delivery-failure-analytics-*.db")
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
		guest_token_hash, approval_delivery_status, approval_delivery_error,
		invite_delivery_status, invite_delivery_error,
		created_at, updated_at, approved_at, rejected_at, completed_at, expires_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "pending", "tenant-a", "Alice Guest", "alice@example.test", "1111111111", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-basic",
		"hash-1", "sent", "", "queued", "",
		"2026-05-25T11:30:00Z", "2026-05-25T11:40:00Z", "", "", "", "2026-05-26T11:30:00Z",

		"guest-2", "approved", "tenant-a", "Bob Visitor", "bob@example.test", "2222222222", "Visitors Inc",
		"Taylor Sponsor", "taylor@example.test", "", "guest-basic",
		"hash-2", "sent", "", "failed", "smtp timeout",
		"2026-05-25T10:05:00Z", "2026-05-25T10:45:00Z", "2026-05-25T10:25:00Z", "", "", "2026-05-26T10:05:00Z",

		"guest-3", "rejected", "tenant-b", "Carla Declined", "carla@example.test", "3333333333", "Visitors Inc",
		"Jordan Sponsor", "jordan@example.test", "", "guest-standard",
		"hash-3", "failed", "smtp bounce", "not_requested", "",
		"2026-05-25T09:10:00Z", "2026-05-25T09:20:00Z", "", "2026-05-25T09:20:00Z", "", "2026-05-26T09:10:00Z",

		"guest-4", "approved", "tenant-a", "Dylan Complete", "dylan@example.test", "4444444444", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-vip",
		"hash-4", "failed", "", "failed", "",
		"2026-05-25T08:15:00Z", "2026-05-25T08:40:00Z", "2026-05-25T08:25:00Z", "", "", "2026-05-26T08:15:00Z",
	)
	require.NoError(t, err)

	summary, err := GetGuestDeliveryFailureAnalytics(GuestLifecycleQuery{
		Window:      4 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 4, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 60, summary.BucketMinutes)
	assert.Equal(t, 4, summary.TotalRecords)
	assert.Equal(t, 4, summary.DeliveryIssueRecordsCount)
	assert.Equal(t, 2, summary.ApprovalDeliveryFailedCount)
	assert.Equal(t, 2, summary.InviteFailedCount)
	assert.Equal(t, 1, summary.PendingInviteQueueCount)
	assert.Equal(t, 4, summary.TotalFailureCount)
	assert.Equal(t, 3, summary.UniqueSponsorsWindow)
	assert.Equal(t, 2, summary.UniqueCompaniesWindow)
	assert.Equal(t, int64(30), summary.AvgPendingInviteQueueMinutes)
	assert.Equal(t, int64(30), summary.MaxPendingInviteQueueMinutes)
	assert.Equal(t, "2026-05-25T09:20:00Z", summary.LatestApprovalFailureAt)
	assert.Equal(t, "2026-05-25T10:45:00Z", summary.LatestInviteFailureAt)
	assert.Equal(t, "2026-05-25T11:30:00Z", summary.LatestQueuedInviteAt)
	require.Len(t, summary.ApprovalErrors, 2)
	approvalErrors := map[string]int{}
	for _, item := range summary.ApprovalErrors {
		approvalErrors[item.Name] = item.Count
	}
	assert.Equal(t, map[string]int{
		"smtp bounce": 1,
		"unspecified": 1,
	}, approvalErrors)
	require.Len(t, summary.InviteErrors, 2)
	inviteErrors := map[string]int{}
	for _, item := range summary.InviteErrors {
		inviteErrors[item.Name] = item.Count
	}
	assert.Equal(t, map[string]int{
		"smtp timeout": 1,
		"unspecified":  1,
	}, inviteErrors)
	require.NotEmpty(t, summary.Sponsors)
	assert.Equal(t, "sam@example.test", summary.Sponsors[0].Name)
	assert.Equal(t, 2, summary.Sponsors[0].TotalFailureCount)
	assert.Equal(t, 1, summary.Sponsors[0].PendingInviteQueueCount)
	assert.Equal(t, int64(30), summary.Sponsors[0].AvgPendingInviteQueueMinutes)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 1, summary.Buckets[0].ApprovalDeliveryFailedCount)
	assert.Equal(t, 1, summary.Buckets[0].InviteFailedCount)
	assert.Equal(t, 2, summary.Buckets[0].TotalFailureCount)
	assert.Equal(t, 1, summary.Buckets[1].ApprovalDeliveryFailedCount)
	assert.Equal(t, 0, summary.Buckets[1].InviteFailedCount)
	assert.Equal(t, 1, summary.Buckets[1].TotalFailureCount)
	assert.Equal(t, 1, summary.Buckets[2].InviteFailedCount)
	assert.Equal(t, 1, summary.Buckets[2].TotalFailureCount)
	assert.Equal(t, 1, summary.Buckets[3].PendingInviteQueueCount)

	tenantOnly, err := GetGuestDeliveryFailureAnalytics(GuestLifecycleQuery{
		TenantScopes: []string{"tenant-a"},
		Window:       4 * time.Hour,
		BucketCount:  4,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, tenantOnly.TotalRecords)
	assert.Equal(t, 1, tenantOnly.ApprovalDeliveryFailedCount)
	assert.Equal(t, 2, tenantOnly.InviteFailedCount)
	assert.Equal(t, 1, tenantOnly.PendingInviteQueueCount)
}
