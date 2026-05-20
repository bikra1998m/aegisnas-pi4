package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func Open(dataSourceName string) (*sql.DB, error) {
	dir := filepath.Dir(dataSourceName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	handle, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err = handle.Ping(); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err = handle.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = handle.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	return handle, nil
}

func Init(dataSourceName string) error {
	handle, err := Open(dataSourceName)
	if err != nil {
		return err
	}
	DB = handle
	return nil
}

func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

func GetDB() *sql.DB {
	if DB == nil {
		panic("database not initialized")
	}
	return DB
}
