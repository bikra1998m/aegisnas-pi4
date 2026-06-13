package db

import (
	"database/sql"
	"fmt"
	"strings"
)

func CurrentSchemaVersionHandle(handle *sql.DB) (int, error) {
	if handle == nil {
		return 0, fmt.Errorf("database handle is required")
	}
	var version int
	err := handle.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return 0, nil
		}
		return 0, err
	}
	return version, nil
}

func CurrentSchemaVersion() (int, error) {
	return CurrentSchemaVersionHandle(GetDB())
}

func MigrateHandle(handle *sql.DB) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}

	_, err := handle.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	currentVersion, err := CurrentSchemaVersionHandle(handle)
	if err != nil {
		return fmt.Errorf("get current schema version: %w", err)
	}

	migrations := []struct {
		version int
		sql     string
	}{
		{1, schemaV1},
		{2, schemaV2},
		{3, schemaV3},
		{4, schemaV4},
		{5, schemaV5},
		{6, schemaV6},
		{7, schemaV7},
		{8, schemaV8},
		{9, schemaV9},
		{LatestSchemaVersion(), schemaV10},
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}
		if _, err := handle.Exec(m.sql); err != nil {
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if _, err := handle.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
	}

	if err := ensureRadiusClientCompatibilityColumns(handle); err != nil {
		return fmt.Errorf("repair radius client schema: %w", err)
	}

	return nil
}

func ensureRadiusClientCompatibilityColumns(handle *sql.DB) error {
	exists, err := tableExists(handle, "radius_clients")
	if err != nil || !exists {
		return err
	}

	hasNASType, err := tableHasColumn(handle, "radius_clients", "nas_type")
	if err != nil || hasNASType {
		return err
	}
	_, err = handle.Exec(`ALTER TABLE radius_clients ADD COLUMN nas_type TEXT DEFAULT 'other'`)
	return err
}

func tableExists(handle *sql.DB, table string) (bool, error) {
	var count int
	err := handle.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
	return count > 0, err
}

func tableHasColumn(handle *sql.DB, table, column string) (bool, error) {
	rows, err := handle.Query(fmt.Sprintf("PRAGMA table_info('%s')", strings.ReplaceAll(table, "'", "''")))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}
