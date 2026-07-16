package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActiveDirectoryEventCacheAndHealthSummaries(t *testing.T) {
	setupActiveDirectoryDB(t)
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	require.NoError(t, RecordActiveDirectoryEvent(ActiveDirectoryEvent{
		ObservedAt:    now.Format(time.RFC3339),
		Domain:        "corp.example.com",
		Realm:         "CORP.EXAMPLE.COM",
		SourceName:    "active-directory",
		UsernameHash:  HashIdentityUsername("alice@example.com"),
		PrincipalHash: HashActiveDirectoryPrincipal("alice@CORP.EXAMPLE.COM"),
		AuthMethod:    "ldap_bind",
		Decision:      "accepted",
		Reason:        "credentials accepted",
		LatencyMS:     12,
		Role:          "employee",
		Groups:        []string{"Domain Users", "Domain Users", "AegisNAS-Employees"},
		CacheUsed:     false,
	}, map[string]any{"request": "portal"}, 10))
	require.NoError(t, RecordActiveDirectoryEvent(ActiveDirectoryEvent{
		ObservedAt:    now.Add(time.Second).Format(time.RFC3339),
		Domain:        "corp.example.com",
		Realm:         "CORP.EXAMPLE.COM",
		SourceName:    "active-directory",
		UsernameHash:  HashIdentityUsername("bob@example.com"),
		PrincipalHash: HashActiveDirectoryPrincipal("bob@CORP.EXAMPLE.COM"),
		AuthMethod:    "ldap_bind",
		Decision:      "rejected",
		Reason:        "invalid credentials",
		LatencyMS:     7,
		CacheUsed:     true,
	}, nil, 10))

	events, err := ListActiveDirectoryEvents("active-directory", "accepted", 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.NotContains(t, events[0].UsernameHash, "alice")
	assert.Equal(t, []string{"Domain Users", "AegisNAS-Employees"}, events[0].Groups)

	eventSummary, err := GetActiveDirectoryEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 2, eventSummary.TotalRecords)
	assert.Equal(t, 1, eventSummary.AcceptedCount)
	assert.Equal(t, 1, eventSummary.RejectedCount)
	assert.Equal(t, 1, eventSummary.CacheHitCount)
	assert.Equal(t, "rejected", eventSummary.LastDecision)

	require.NoError(t, UpsertActiveDirectoryGroupCache("active-directory", "alice@example.com", "alice@CORP.EXAMPLE.COM", "corp.example.com", "CORP.EXAMPLE.COM", "employee", []string{"AegisNAS-Employees"}, 60, now))
	cache, ok, err := GetActiveDirectoryGroupCache("active-directory", "alice@example.com", now.Add(30*time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "employee", cache.Role)
	assert.Equal(t, []string{"AegisNAS-Employees"}, cache.Groups)

	_, ok, err = GetActiveDirectoryGroupCache("active-directory", "alice@example.com", now.Add(2*time.Minute))
	require.NoError(t, err)
	assert.False(t, ok)

	cacheSummary, err := GetActiveDirectoryGroupCacheSummary(now.Add(2 * time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 1, cacheSummary.TotalEntries)
	assert.Equal(t, 1, cacheSummary.ExpiredEntries)

	require.NoError(t, RecordActiveDirectoryHealthCheck(ActiveDirectoryHealthCheck{
		CheckedAt: now.Format(time.RFC3339),
		Domain:    "corp.example.com",
		Realm:     "CORP.EXAMPLE.COM",
		Component: "configuration",
		Status:    "ok",
		Message:   "configuration executable",
		LatencyMS: 3,
	}, map[string]any{"mode": "enforce"}, 10))
	health, err := ListActiveDirectoryHealthChecks("configuration", 10)
	require.NoError(t, err)
	require.Len(t, health, 1)
	assert.Equal(t, "ok", health[0].Status)

	healthSummary, err := GetActiveDirectoryHealthSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, healthSummary.TotalRecords)
	assert.Equal(t, 1, healthSummary.OKCount)
	assert.Equal(t, "configuration", healthSummary.LastComponent)
}

func setupActiveDirectoryDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "active-directory-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, Init(dbPath))
	require.NoError(t, Migrate())
}
