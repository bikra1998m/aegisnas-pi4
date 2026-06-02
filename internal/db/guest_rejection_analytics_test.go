package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGuestRejectionAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "guest-rejection-analytics-*.db")
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
		sponsor_name, sponsor_email, sponsor_phone, role, rejection_reason,
		guest_token_hash, approval_delivery_status, invite_delivery_status,
		created_at, updated_at, approved_at, rejected_at, completed_at, expires_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "rejected", "tenant-a", "Alice Guest", "alice@example.test", "1111111111", "LabCo",
		"Sam Sponsor", "sam@example.test", "", "guest-basic", "Policy mismatch",
		"hash-1", "sent", "not_requested",
		"2026-05-25T10:00:00Z", "2026-05-25T10:20:00Z", "2026-05-25T10:10:00Z", "2026-05-25T10:20:00Z", "", "2026-05-26T10:00:00Z",

		"guest-2", "rejected", "tenant-a", "Bob Visitor", "bob@example.test", "2222222222", "Visitors Inc",
		"", "", "", "guest-standard", "Incomplete identity",
		"hash-2", "pending", "not_requested",
		"2026-05-25T11:00:00Z", "2026-05-25T11:12:00Z", "", "2026-05-25T11:12:00Z", "", "2026-05-26T11:00:00Z",

		"guest-3", "rejected", "tenant-b", "Carla Declined", "carla@example.test", "3333333333", "Visitors Inc",
		"Jordan Sponsor", "jordan@example.test", "", "guest-standard", "",
		"hash-3", "failed", "failed",
		"2026-05-25T08:30:00Z", "2026-05-25T08:45:00Z", "", "2026-05-25T08:45:00Z", "", "2026-05-26T08:30:00Z",

		"guest-4", "pending", "tenant-a", "Dylan Waiting", "dylan@example.test", "4444444444", "Guests United",
		"Pat Sponsor", "pat@example.test", "", "guest-vip", "",
		"hash-4", "sent", "queued",
		"2026-05-25T11:30:00Z", "2026-05-25T11:35:00Z", "", "", "", "2026-05-26T11:30:00Z",
	)
	require.NoError(t, err)

	summary, err := GetGuestRejectionAnalytics(GuestLifecycleQuery{
		Window:      24 * time.Hour,
		BucketCount: 4,
	})
	require.NoError(t, err)

	assert.Equal(t, 24, summary.WindowHours)
	assert.Equal(t, 4, summary.BucketCount)
	assert.Equal(t, 360, summary.BucketMinutes)
	assert.Equal(t, 4, summary.TotalRecords)
	assert.Equal(t, 3, summary.RejectedCount)
	assert.Equal(t, 2, summary.RejectedWithSponsorCount)
	assert.Equal(t, 1, summary.RejectedWithoutSponsorCount)
	assert.Equal(t, 1, summary.RejectedAfterApprovalCount)
	assert.Equal(t, 2, summary.RejectedBeforeApprovalCount)
	assert.Equal(t, 3, summary.UniqueRejectionReasonsWindow)
	assert.Equal(t, 2, summary.UniqueSponsorsWindow)
	assert.Equal(t, 2, summary.UniqueCompaniesWindow)
	assert.Equal(t, int64(15), summary.AvgSubmitToRejectionMinutes)
	assert.Equal(t, int64(20), summary.MaxSubmitToRejectionMinutes)
	assert.Equal(t, "2026-05-25T11:12:00Z", summary.LatestRejectedAt)
	require.Len(t, summary.RejectionReasons, 3)
	assert.Equal(t, "Incomplete identity", summary.RejectionReasons[0].Name)
	assert.Equal(t, 1, summary.RejectionReasons[0].Count)
	assert.Equal(t, "unspecified", summary.RejectionReasons[2].Name)
	require.Len(t, summary.Sponsors, 2)
	assert.Equal(t, "jordan@example.test", summary.Sponsors[0].Name)
	assert.Equal(t, 1, summary.Sponsors[0].Count)
	require.Len(t, summary.Roles, 2)
	assert.Equal(t, "guest-standard", summary.Roles[0].Name)
	assert.Equal(t, 2, summary.Roles[0].Count)
	require.Len(t, summary.Buckets, 4)
	assert.Equal(t, 0, summary.Buckets[0].RejectedCount)
	assert.Equal(t, 0, summary.Buckets[1].RejectedCount)
	assert.Equal(t, 0, summary.Buckets[1].RejectedWithSponsorCount)
	assert.Equal(t, 0, summary.Buckets[1].RejectedAfterApprovalCount)
	assert.Equal(t, 3, summary.Buckets[3].RejectedCount)
	assert.Equal(t, 2, summary.Buckets[3].RejectedWithSponsorCount)
	assert.Equal(t, 1, summary.Buckets[3].RejectedWithoutSponsorCount)
	assert.Equal(t, 1, summary.Buckets[3].RejectedAfterApprovalCount)

	tenantOnly, err := GetGuestRejectionAnalytics(GuestLifecycleQuery{
		TenantScopes: []string{"tenant-a"},
		Window:       24 * time.Hour,
		BucketCount:  4,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, tenantOnly.TotalRecords)
	assert.Equal(t, 2, tenantOnly.RejectedCount)
	assert.Equal(t, 1, tenantOnly.RejectedWithSponsorCount)
	assert.Equal(t, 1, tenantOnly.RejectedWithoutSponsorCount)
}
