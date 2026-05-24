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

	return nil
}
