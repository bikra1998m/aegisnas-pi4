package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

type RuntimeStatus struct {
	Component string         `json:"component"`
	Status    string         `json:"status"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	UpdatedAt string         `json:"updated_at"`
}

func UpsertRuntimeStatus(component, status, message string, details map[string]any) error {
	if DB == nil {
		return nil
	}
	component = strings.TrimSpace(component)
	status = strings.TrimSpace(status)
	if component == "" || status == "" {
		return fmt.Errorf("component and status are required")
	}
	payload := "{}"
	if len(details) > 0 {
		encoded, err := json.Marshal(details)
		if err != nil {
			return err
		}
		payload = string(encoded)
	}
	_, err := DB.Exec(`INSERT INTO runtime_status (component, status, message, details, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(component) DO UPDATE SET
			status = excluded.status,
			message = excluded.message,
			details = excluded.details,
			updated_at = CURRENT_TIMESTAMP`,
		component, status, message, payload)
	return err
}

func GetRuntimeStatuses() ([]RuntimeStatus, error) {
	if DB == nil {
		return nil, nil
	}
	rows, err := DB.Query(`SELECT component, status, COALESCE(message, ''), COALESCE(details, '{}'), updated_at
		FROM runtime_status ORDER BY component`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []RuntimeStatus
	for rows.Next() {
		var (
			status  RuntimeStatus
			details string
		)
		if err := rows.Scan(&status.Component, &status.Status, &status.Message, &details, &status.UpdatedAt); err != nil {
			return nil, err
		}
		if strings.TrimSpace(details) != "" && details != "{}" {
			_ = json.Unmarshal([]byte(details), &status.Details)
		}
		statuses = append(statuses, status)
	}
	return statuses, rows.Err()
}

func GetRuntimeStatus(component string) (*RuntimeStatus, error) {
	if DB == nil {
		return nil, nil
	}
	component = strings.TrimSpace(component)
	if component == "" {
		return nil, fmt.Errorf("component is required")
	}

	var (
		status  RuntimeStatus
		details string
	)
	err := DB.QueryRow(`SELECT component, status, COALESCE(message, ''), COALESCE(details, '{}'), updated_at
		FROM runtime_status WHERE component = ?`, component).
		Scan(&status.Component, &status.Status, &status.Message, &details, &status.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(details) != "" && details != "{}" {
		_ = json.Unmarshal([]byte(details), &status.Details)
	}
	return &status, nil
}
