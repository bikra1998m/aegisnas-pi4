package db

import (
	"regexp"
	"strings"
)

func SQLForDialect(raw string, dialect Dialect) string {
	switch dialect {
	case DialectPostgreSQL:
		return PostgreSQLSchemaSQL(raw)
	default:
		return raw
	}
}

func PostgreSQLSchemaSQL(raw string) string {
	out := raw
	replacements := []struct {
		from string
		to   string
	}{
		{"INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"},
		{"DATETIME", "TIMESTAMPTZ"},
		{"BOOLEAN NOT NULL DEFAULT 0", "BOOLEAN NOT NULL DEFAULT FALSE"},
		{"BOOLEAN NOT NULL DEFAULT 1", "BOOLEAN NOT NULL DEFAULT TRUE"},
		{"BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE"},
		{"BOOLEAN DEFAULT 1", "BOOLEAN DEFAULT TRUE"},
		{"WHERE active = 1", "WHERE active = TRUE"},
	}
	for _, replacement := range replacements {
		out = strings.ReplaceAll(out, replacement.from, replacement.to)
	}
	out = rewriteSQLiteTimeFunctions(out)
	out = rewriteSchemaInsertOrIgnore(out)
	return out
}

var schemaInsertOrIgnoreRE = regexp.MustCompile(`(?is)\bINSERT\s+OR\s+IGNORE\s+INTO\s+(.+?)\s+VALUES\s*(\(.+?\))\s*;`)

func rewriteSchemaInsertOrIgnore(query string) string {
	return schemaInsertOrIgnoreRE.ReplaceAllString(query, "INSERT INTO $1 VALUES $2 ON CONFLICT DO NOTHING;")
}
