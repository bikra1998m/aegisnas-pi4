package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type conversionColumn struct{ name, kind string }
type conversionLayout struct {
	name    string
	columns []conversionColumn
	keys    []string
}

func conversionTables(ctx context.Context, handle *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := handle.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read conversion table inventory")
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read conversion table name")
		}
		names = append(names, name)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("read conversion table inventory failed")
	}
	sort.Strings(names)
	return names, nil
}

func conversionLayouts(ctx context.Context, source, target *sql.DB, schema string) ([]conversionLayout, error) {
	sourceNames, err := conversionTables(ctx, source, "SELECT name FROM sqlite_master WHERE type='table' AND substr(name,1,7) <> 'sqlite_'")
	if err != nil {
		return nil, err
	}
	targetNames, err := conversionTables(ctx, target, "SELECT table_name FROM information_schema.tables WHERE table_schema=? AND table_type='BASE TABLE'", schema)
	if err != nil {
		return nil, err
	}
	if len(sourceNames) == 0 || !reflect.DeepEqual(sourceNames, targetNames) {
		return nil, fmt.Errorf("source and migrated target table sets differ; custom or missing tables cannot be discarded")
	}
	layouts := make([]conversionLayout, 0, len(sourceNames))
	for _, name := range sourceNames {
		layout := conversionLayout{name: name}
		rows, err := target.QueryContext(ctx, "SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position", schema, name)
		if err != nil {
			return nil, fmt.Errorf("read target column layout")
		}
		for rows.Next() {
			var column conversionColumn
			if err := rows.Scan(&column.name, &column.kind); err != nil {
				rows.Close()
				return nil, fmt.Errorf("read target column metadata")
			}
			layout.columns = append(layout.columns, column)
		}
		scanErr := rows.Err()
		rows.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read target columns failed")
		}
		rows, err = source.QueryContext(ctx, "PRAGMA table_info("+conversionQuote(name)+")")
		if err != nil {
			return nil, fmt.Errorf("read source columns")
		}
		columns := map[string]bool{}
		keys := map[int]string{}
		for rows.Next() {
			var id, notNull, pk int
			var column, kind string
			var defaultValue any
			if err := rows.Scan(&id, &column, &kind, &notNull, &defaultValue, &pk); err != nil {
				rows.Close()
				return nil, fmt.Errorf("read source column metadata")
			}
			columns[column] = true
			if pk > 0 {
				keys[pk] = column
			}
		}
		scanErr = rows.Err()
		rows.Close()
		if scanErr != nil || len(columns) != len(layout.columns) || len(keys) == 0 {
			return nil, fmt.Errorf("table %s has incompatible columns or no primary key", name)
		}
		for _, column := range layout.columns {
			if !columns[column.name] {
				return nil, fmt.Errorf("table %s has incompatible columns", name)
			}
		}
		for i := 1; i <= len(keys); i++ {
			key, ok := keys[i]
			if !ok {
				return nil, fmt.Errorf("invalid primary key layout")
			}
			layout.keys = append(layout.keys, key)
		}
		rows, err = target.QueryContext(ctx, `SELECT k.column_name FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k
		 ON k.constraint_catalog=c.constraint_catalog AND k.constraint_schema=c.constraint_schema AND k.constraint_name=c.constraint_name AND k.table_name=c.table_name
		 WHERE c.table_schema=? AND c.table_name=? AND c.constraint_type='PRIMARY KEY' ORDER BY k.ordinal_position`, schema, name)
		if err != nil {
			return nil, fmt.Errorf("read target primary key")
		}
		var targetKeys []string
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return nil, fmt.Errorf("read target key metadata")
			}
			targetKeys = append(targetKeys, key)
		}
		scanErr = rows.Err()
		rows.Close()
		if scanErr != nil || !reflect.DeepEqual(layout.keys, targetKeys) {
			return nil, fmt.Errorf("table %s has incompatible primary keys", name)
		}
		layouts = append(layouts, layout)
	}
	return layouts, nil
}

func convertSnapshotRows(ctx context.Context, source, target *sql.DB, options ConversionOptions, report *ConversionReport) error {
	layouts, err := conversionLayouts(ctx, source, target, options.TargetSchema)
	if err != nil {
		return err
	}
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin conversion import")
	}
	defer tx.Rollback()
	restoreConstraints, err := deferConversionConstraints(ctx, tx, options.TargetSchema)
	if err != nil {
		return err
	}
	var tables []string
	for _, layout := range layouts {
		tables = append(tables, conversionQuote(options.TargetSchema)+"."+conversionQuote(layout.name))
	}
	// All tables belong to the schema created by this invocation. Delete the few
	// bootstrap rows transactionally; TRUNCATE would rewrite every empty table
	// and index and exceeded the normal statement timeout on the real VM.
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear new schema bootstrap rows")
		}
	}
	for _, layout := range layouts {
		qualified := conversionQuote(options.TargetSchema) + "." + conversionQuote(layout.name)
		var names, placeholders []string
		for range layout.columns {
			placeholders = append(placeholders, "?")
		}
		for _, column := range layout.columns {
			names = append(names, conversionQuote(column.name))
		}
		statement, err := tx.PrepareContext(ctx, "INSERT INTO "+qualified+" ("+strings.Join(names, ",")+") VALUES ("+strings.Join(placeholders, ",")+")")
		if err != nil {
			return fmt.Errorf("prepare conversion table %s", layout.name)
		}
		rows, err := source.QueryContext(ctx, conversionSelect(layout, "", false))
		if err != nil {
			statement.Close()
			return fmt.Errorf("read conversion table %s", layout.name)
		}
		count, hash, err := conversionRows(ctx, rows, layout, options, report, func(values []any) error {
			if _, err := statement.ExecContext(ctx, values...); err != nil {
				return fmt.Errorf("insert conversion table %s failed; row values withheld", layout.name)
			}
			return nil
		})
		statement.Close()
		if err != nil {
			return err
		}
		rows, err = tx.QueryContext(ctx, conversionSelect(layout, options.TargetSchema, true))
		if err != nil {
			return fmt.Errorf("verify conversion table %s", layout.name)
		}
		targetCount, targetHash, err := conversionRows(ctx, rows, layout, ConversionOptions{}, &ConversionReport{}, nil)
		if err != nil {
			return err
		}
		if count != targetCount || hash != targetHash {
			return fmt.Errorf("table %s row count or canonical content digest mismatch", layout.name)
		}
		report.Tables = append(report.Tables, ConversionTable{Name: layout.name, Rows: count, SourceSHA256: hash, TargetSHA256: targetHash})
		if err := conversionSequences(ctx, source, tx, options.TargetSchema, layout, report); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return fmt.Errorf("converted foreign-key validation failed")
	}
	for _, statement := range restoreConstraints {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("restore target foreign-key enforcement mode")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit conversion import failed; inspect private target before retry")
	}
	return nil
}

func conversionSelect(layout conversionLayout, schema string, postgres bool) string {
	var names, keys []string
	for _, column := range layout.columns {
		names = append(names, conversionQuote(column.name))
	}
	for _, key := range layout.keys {
		value := conversionQuote(key)
		for _, column := range layout.columns {
			if column.name == key && (column.kind == "text" || column.kind == "character varying") {
				if postgres {
					value += ` COLLATE "C"`
				} else {
					value += " COLLATE BINARY"
				}
			}
		}
		keys = append(keys, value)
	}
	table := conversionQuote(layout.name)
	if schema != "" {
		table = conversionQuote(schema) + "." + table
	}
	return "SELECT " + strings.Join(names, ",") + " FROM " + table + " ORDER BY " + strings.Join(keys, ",")
}

func conversionRows(ctx context.Context, rows *sql.Rows, layout conversionLayout, options ConversionOptions, report *ConversionReport, insert func([]any) error) (int64, string, error) {
	defer rows.Close()
	hash := sha256.New()
	var count int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		values := make([]any, len(layout.columns))
		pointers := make([]any, len(values))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return 0, "", fmt.Errorf("scan table %s; row values withheld", layout.name)
		}
		for i, column := range layout.columns {
			var err error
			values[i], err = conversionValue(values[i], column.kind, options, report)
			if err != nil {
				return 0, "", fmt.Errorf("table %s column %s: %s", layout.name, column.name, err)
			}
		}
		if insert != nil {
			if err := insert(values); err != nil {
				return 0, "", err
			}
		}
		data, err := json.Marshal(values)
		if err != nil {
			return 0, "", fmt.Errorf("encode conversion row digest")
		}
		hash.Write(data)
		hash.Write([]byte{'\n'})
		count++
	}
	if rows.Err() != nil {
		return 0, "", fmt.Errorf("read conversion table %s failed", layout.name)
	}
	return count, hex.EncodeToString(hash.Sum(nil)), nil
}

func deferConversionConstraints(ctx context.Context, tx *sql.Tx, schema string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT t.relname,c.conname,c.condeferrable,c.condeferred FROM pg_constraint c
	 JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=? AND c.contype='f' ORDER BY t.relname,c.conname`, schema)
	if err != nil {
		return nil, fmt.Errorf("inventory target foreign keys")
	}
	var alter, restore []string
	for rows.Next() {
		var table, name string
		var deferrable, deferred bool
		if err := rows.Scan(&table, &name, &deferrable, &deferred); err != nil {
			rows.Close()
			return nil, fmt.Errorf("read target foreign key")
		}
		base := "ALTER TABLE " + conversionQuote(schema) + "." + conversionQuote(table) + " ALTER CONSTRAINT " + conversionQuote(name)
		alter = append(alter, base+" DEFERRABLE INITIALLY DEFERRED")
		mode := " NOT DEFERRABLE INITIALLY IMMEDIATE"
		if deferrable {
			mode = " DEFERRABLE INITIALLY IMMEDIATE"
			if deferred {
				mode = " DEFERRABLE INITIALLY DEFERRED"
			}
		}
		restore = append(restore, base+mode)
	}
	scanErr := rows.Err()
	rows.Close()
	if scanErr != nil {
		return nil, fmt.Errorf("read target foreign keys failed")
	}
	for _, statement := range alter {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return nil, fmt.Errorf("defer conversion foreign keys")
		}
	}
	return restore, nil
}

func conversionSequences(ctx context.Context, source *sql.DB, target *sql.Tx, schema string, layout conversionLayout, report *ConversionReport) error {
	qualified := conversionQuote(schema) + "." + conversionQuote(layout.name)
	for _, column := range layout.columns {
		var sequence sql.NullString
		if err := target.QueryRowContext(ctx, "SELECT pg_get_serial_sequence(?,?)", qualified, column.name).Scan(&sequence); err != nil {
			return fmt.Errorf("inspect conversion sequence")
		}
		if !sequence.Valid {
			continue
		}
		var maximum, highwater int64
		if err := source.QueryRowContext(ctx, "SELECT COALESCE(MAX("+conversionQuote(column.name)+"),0) FROM "+conversionQuote(layout.name)).Scan(&maximum); err != nil {
			return fmt.Errorf("read conversion ID maximum")
		}
		err := source.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name=?", layout.name).Scan(&highwater)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("read SQLite ID high-water mark")
		}
		next := max(maximum, highwater, int64(0))
		if next == math.MaxInt64 {
			return fmt.Errorf("conversion sequence is exhausted")
		}
		next++
		// Obtain the server-owned sequence name as separate catalog fields rather
		// than treating a returned regclass string as SQL.
		var sequenceSchema, sequenceName string
		if err := target.QueryRowContext(ctx, "SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=CAST(? AS regclass)", sequence.String).Scan(&sequenceSchema, &sequenceName); err != nil || sequenceSchema != schema {
			return fmt.Errorf("sequence escaped private conversion schema")
		}
		if _, err := target.ExecContext(ctx, "ALTER SEQUENCE "+conversionQuote(schema)+"."+conversionQuote(sequenceName)+" RESTART WITH "+strconv.FormatInt(next, 10)); err != nil {
			return fmt.Errorf("restart converted sequence")
		}
		report.Sequences[layout.name+"."+column.name] = next
	}
	return nil
}
