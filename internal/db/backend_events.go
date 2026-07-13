package db

import (
	"encoding/json"
	"fmt"
)

type BackendEventDetail struct {
	Driver         string `json:"driver"`
	Dialect        string `json:"dialect"`
	DSNRefSet      bool   `json:"dsn_ref_set"`
	InlineDSNSet   bool   `json:"inline_dsn_set"`
	DSNFingerprint string `json:"dsn_fingerprint,omitempty"`
	SSLMode        string `json:"sslmode,omitempty"`
	TLSRequired    bool   `json:"tls_required"`
	PoolMaxOpen    int    `json:"pool_max_open"`
	PoolMaxIdle    int    `json:"pool_max_idle"`
	LocalStatePath string `json:"local_state_path,omitempty"`
}

func RecordBackendEvent(status string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	version, err := CurrentSchemaVersion()
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	info := ActiveConnectionInfo()
	if info.Backend == "" {
		info.Backend = string(DialectForHandle(DB))
	}
	detail := BackendEventDetail{
		Driver:         info.Driver,
		Dialect:        info.Dialect,
		DSNRefSet:      info.DSNRefSet,
		InlineDSNSet:   info.InlineDSNSet,
		DSNFingerprint: info.DSNFingerprint,
		SSLMode:        info.SSLMode,
		TLSRequired:    info.TLSRequired,
		PoolMaxOpen:    info.Pool.MaxOpenConns,
		PoolMaxIdle:    info.Pool.MaxIdleConns,
		LocalStatePath: info.LocalStatePath,
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal backend event detail: %w", err)
	}
	if _, err := DB.Exec(`INSERT INTO database_backend_events (backend, status, schema_version, detail_json)
		VALUES (?, ?, ?, ?)`, info.Backend, status, version, string(payload)); err != nil {
		return fmt.Errorf("record database backend event: %w", err)
	}
	return nil
}
