package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgreSQLTimeRewriteProtectsSQLData(t *testing.T) {
	for _, query := range []string{
		`SELECT 'datetime(''now'')', "datetime('now')", $$datetime('now')$$, $body$datetime(?)$body$`,
		"SELECT 1 -- datetime('now')\n/* datetime(updated_at) */",
		`SELECT E'escaped\' datetime(?)', /* outer /* nested */ datetime(?) */ 1`,
		`SELECT mydatetime(value), datetime(value, 'unsupported'), datetime(`,
	} {
		require.Equal(t, query, rewriteSQLiteTimeFunctions(query))
		require.Equal(t, query, rewritePostgreSQLQuery(query))
	}
}

func TestPostgreSQLTimeRewriteNestedBindings(t *testing.T) {
	query := rewritePostgreSQLQuery(`SELECT datetime(COALESCE(updated_at, ?)), DATETIME (?), datetime('now', '-7 days'), datetime(?, '+2 hours')`)
	require.Contains(t, query, "CAST(NULLIF(CAST(COALESCE(updated_at, $1) AS TEXT), '') AS TIMESTAMPTZ)")
	require.Contains(t, query, "CAST(NULLIF(CAST($2 AS TEXT), '') AS TIMESTAMPTZ)")
	require.Contains(t, query, "(CURRENT_TIMESTAMP - INTERVAL '7 days')")
	require.Contains(t, query, "CAST(NULLIF(CAST($3 AS TEXT), '') AS TIMESTAMPTZ) + INTERVAL '2 hours'")
	require.NotContains(t, strings.ToLower(query), "datetime(")
}
