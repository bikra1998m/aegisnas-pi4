package db

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

var migrationTableName = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

// SQLite INTEGER is signed 64-bit. Earlier PostgreSQL schemas used int4,
// rejecting ordinary accounting counters above 2 GiB. Limit the upgrade to
// tables declared by our migrations in the connection's current schema.
func widenPostgreSQLIntegers(tx *sql.Tx, schemas []string) error {
	owned := map[string]bool{}
	for _, schema := range schemas {
		for _, match := range migrationTableName.FindAllStringSubmatch(schema, -1) {
			owned[match[1]] = true
		}
	}
	rows, err := tx.Query(`SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND data_type = 'integer'
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		return err
	}
	var statements []string
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			rows.Close()
			return err
		}
		if owned[table] {
			quote := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
			statements = append(statements, fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s TYPE BIGINT", quote(table), quote(column)))
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}
