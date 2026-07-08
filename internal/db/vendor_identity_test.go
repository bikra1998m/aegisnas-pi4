package db

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorIdentityMigrationLifecycle(t *testing.T) {
	handle, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer handle.Close()
	require.NoError(t, MigrateHandle(handle))

	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	migration := VendorIdentityMigration{
		ID: "migration-1", Status: "previewed", FromVendorName: "AegisNAS", FromPEN: 55555,
		ToVendorName: "AegisNAS", ToPEN: 424242, Organization: "AegisNAS Systems Ltd.",
		EvidenceJSON: `{}`, BeforeJSON: `{}`, AfterJSON: `{}`, ConfigChecksum: strings.Repeat("a", 64),
		ConfirmationSHA256: strings.Repeat("b", 64), ExpiresAt: now.Add(15 * time.Minute),
		CreatedBy: "admin", CreatedAt: now,
	}
	require.NoError(t, CreateVendorIdentityMigration(handle, migration))
	stored, err := GetVendorIdentityMigration(handle, migration.ID)
	require.NoError(t, err)
	assert.Equal(t, "previewed", stored.Status)

	claimed, err := ClaimVendorIdentityMigration(handle, migration.ID, now)
	require.NoError(t, err)
	assert.True(t, claimed)
	claimed, err = ClaimVendorIdentityMigration(handle, migration.ID, now)
	require.NoError(t, err)
	assert.False(t, claimed)

	assignment := VendorIdentityAssignment{
		PEN: 424242, VendorName: "AegisNAS", Organization: migration.Organization,
		RegistryURL:         "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt",
		RegistryLastUpdated: "2026-07-06", RegistrySHA256: strings.Repeat("c", 64),
		RecordSHA256: strings.Repeat("d", 64), EvidenceJSON: `{}`, VerifiedAt: now,
	}
	require.NoError(t, CompleteVendorIdentityMigration(handle, migration, assignment, now))
	active, err := ActiveVendorIdentityAssignment(handle)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.EqualValues(t, 424242, active.PEN)

	require.NoError(t, RollbackVendorIdentityMigration(handle, migration.ID, 55555, 424242, now.Add(time.Minute)))
	active, err = ActiveVendorIdentityAssignment(handle)
	require.NoError(t, err)
	assert.Nil(t, active)
	stored, err = GetVendorIdentityMigration(handle, migration.ID)
	require.NoError(t, err)
	assert.Equal(t, "rolled_back", stored.Status)

	metrics, err := VendorIdentityMetrics(handle)
	require.NoError(t, err)
	assert.EqualValues(t, 1, metrics.RolledBack)
	assert.NotNil(t, metrics.LastEvent)
}

func TestVendorIdentityMigrationExpiryAndFailure(t *testing.T) {
	handle, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer handle.Close()
	require.NoError(t, MigrateHandle(handle))
	now := time.Now().UTC()
	migration := VendorIdentityMigration{
		ID: "expired", Status: "previewed", FromVendorName: "AegisNAS", FromPEN: 55555,
		ToVendorName: "AegisNAS", ToPEN: 424242, Organization: "AegisNAS Systems Ltd.",
		EvidenceJSON: `{}`, BeforeJSON: `{}`, AfterJSON: `{}`, ConfigChecksum: strings.Repeat("a", 64),
		ConfirmationSHA256: strings.Repeat("b", 64), ExpiresAt: now.Add(-time.Second), CreatedAt: now.Add(-time.Hour),
	}
	require.NoError(t, CreateVendorIdentityMigration(handle, migration))
	claimed, err := ClaimVendorIdentityMigration(handle, migration.ID, now)
	require.NoError(t, err)
	assert.False(t, claimed)
	require.NoError(t, FailVendorIdentityMigration(handle, migration.ID, "expired"))
	stored, err := GetVendorIdentityMigration(handle, migration.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", stored.Status)
	assert.Equal(t, "expired", stored.Failure)
}
