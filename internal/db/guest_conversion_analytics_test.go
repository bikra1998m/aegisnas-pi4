package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGuestConversionAnalytics(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "guest-conversion-analytics-*.db")
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
		id, status, tenant, full_name, email, company,
		sponsor_name, sponsor_email, role, guest_token_hash,
		approval_delivery_status, invite_delivery_status, invite_delivery_error,
		created_at, updated_at, approved_at, rejected_at, completed_at, expires_at
	) VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"guest-1", "approved", "tenant-a", "Alice Queue", "alice@example.test", "LabCo",
		"Sam Sponsor", "sam@example.test", "guest-basic", "hash-1",
		"sent", "queued", "",
		"2026-05-25T11:00:00Z", "2026-05-25T11:12:00Z", "2026-05-25T11:10:00Z", "", "", "2026-05-26T11:00:00Z",

		"guest-2", "approved", "tenant-a", "Bob Sent", "bob@example.test", "Visitors Inc",
		"Taylor Sponsor", "taylor@example.test", "guest-basic", "hash-2",
		"sent", "sent", "",
		"2026-05-25T10:00:00Z", "2026-05-25T10:35:00Z", "2026-05-25T10:20:00Z", "", "", "2026-05-26T10:00:00Z",

		"guest-3", "completed", "tenant-b", "Carla Done", "carla@example.test", "LabCo",
		"Sam Sponsor", "sam@example.test", "guest-vip", "hash-3",
		"sent", "sent", "",
		"2026-05-25T09:00:00Z", "2026-05-25T09:25:00Z", "2026-05-25T09:10:00Z", "", "2026-05-25T10:00:00Z", "2026-05-26T09:00:00Z",

		"guest-4", "approved", "tenant-b", "Dylan Failed", "dylan@example.test", "Visitors Inc",
		"Jordan Sponsor", "jordan@example.test", "guest-standard", "hash-4",
		"sent", "failed", "smtp timeout",
		"2026-05-25T08:00:00Z", "2026-05-25T08:40:00Z", "2026-05-25T08:15:00Z", "", "", "2026-05-26T08:00:00Z",

		"guest-5", "rejected", "tenant-b", "Eva Skip", "eva@example.test", "Other Co",
		"Jordan Sponsor", "jordan@example.test", "guest-standard", "hash-5",
		"failed", "not_requested", "",
		"2026-05-25T07:30:00Z", "2026-05-25T07:40:00Z", "", "2026-05-25T07:40:00Z", "", "2026-05-26T07:30:00Z",
	)
	require.NoError(t, err)

	summary, err := GetGuestConversionAnalytics(GuestLifecycleQuery{
		Window:      5 * time.Hour,
		BucketCount: 5,
	})
	require.NoError(t, err)

	assert.Equal(t, 5, summary.WindowHours)
	assert.Equal(t, 5, summary.BucketCount)
	assert.Equal(t, 60, summary.BucketMinutes)
	assert.Equal(t, 5, summary.TotalRecords)
	assert.Equal(t, 0, summary.OpenPendingCount)
	assert.Equal(t, 5, summary.SponsorApprovalRequiredCount)
	assert.Equal(t, 4, summary.ApprovedStageCount)
	assert.Equal(t, 1, summary.RejectedStageCount)
	assert.Equal(t, 1, summary.InviteQueuedCount)
	assert.Equal(t, 2, summary.InviteSentCount)
	assert.Equal(t, 1, summary.InviteFailedCount)
	assert.Equal(t, 1, summary.CompletedStageCount)
	assert.Equal(t, 2, summary.ApprovedWithoutSuccessfulInviteCount)
	assert.Equal(t, 1, summary.InvitedNotCompletedCount)
	assert.Equal(t, 1, summary.CompletedAfterInviteCount)
	assert.Equal(t, 5, summary.UniqueGuestsWindow)
	assert.Equal(t, 3, summary.UniqueSponsorsWindow)
	assert.Equal(t, 3, summary.UniqueCompaniesWindow)
	assert.Equal(t, 80, summary.ApprovalRatePercent)
	assert.Equal(t, 50, summary.InviteSendRatePercent)
	assert.Equal(t, 50, summary.InviteCompletionRatePercent)
	assert.Equal(t, 20, summary.EndToEndCompletionRatePercent)
	assert.Equal(t, int64(13), summary.AvgSubmitToApprovalMinutes)
	assert.Equal(t, int64(20), summary.MaxSubmitToApprovalMinutes)
	assert.Equal(t, int64(30), summary.AvgSubmitToInviteMinutes)
	assert.Equal(t, int64(35), summary.MaxSubmitToInviteMinutes)
	assert.Equal(t, int64(60), summary.AvgSubmitToCompletionMinutes)
	assert.Equal(t, int64(60), summary.MaxSubmitToCompletionMinutes)
	assert.Equal(t, "2026-05-25T11:00:00Z", summary.LatestSubmittedAt)
	assert.Equal(t, "2026-05-25T11:10:00Z", summary.LatestApprovedAt)
	assert.Equal(t, "2026-05-25T10:35:00Z", summary.LatestInviteSentAt)
	assert.Equal(t, "2026-05-25T10:00:00Z", summary.LatestCompletedAt)
	require.Len(t, summary.Roles, 3)
	require.Len(t, summary.Buckets, 5)
	assert.Equal(t, 1, summary.Buckets[0].RejectedCount)
	assert.Equal(t, 1, summary.Buckets[1].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[2].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[2].InviteSentCount)
	assert.Equal(t, 1, summary.Buckets[3].ApprovedCount)
	assert.Equal(t, 1, summary.Buckets[3].InviteSentCount)
	assert.Equal(t, 1, summary.Buckets[3].CompletedCount)
	assert.Equal(t, 1, summary.Buckets[4].SubmittedCount)
	assert.Equal(t, 1, summary.Buckets[4].ApprovedCount)
}
