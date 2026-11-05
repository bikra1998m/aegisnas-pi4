package ha

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestPostgreSQLRejectsSQLiteReplicationBeforeFileAccess(t *testing.T) {
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres"}}
	_, _, err := CreateReplicationPackage(cfg)
	require.ErrorIs(t, err, ErrSQLiteReplicationOnly)
	_, err = ImportReplicationPackage(cfg, []byte("untrusted fixture"), "test")
	require.ErrorIs(t, err, ErrSQLiteReplicationOnly)
	_, err = ActivateStagedReplicationPackage(cfg, "not-present", "test")
	require.ErrorIs(t, err, ErrSQLiteReplicationOnly)
}
