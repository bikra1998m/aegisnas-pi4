package upgrade

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type MigrationRehearsal struct {
	Ran                  bool   `json:"ran"`
	Succeeded            bool   `json:"succeeded"`
	StartedSchemaVersion int    `json:"started_schema_version"`
	ResultSchemaVersion  int    `json:"result_schema_version"`
	DurationMilliseconds int64  `json:"duration_milliseconds"`
	Error                string `json:"error,omitempty"`
}

type ReadinessReport struct {
	GeneratedAt           string             `json:"generated_at"`
	ConfigPath            string             `json:"config_path"`
	DatabasePath          string             `json:"database_path"`
	DatabaseExists        bool               `json:"database_exists"`
	DatabaseSizeBytes     int64              `json:"database_size_bytes"`
	CurrentSchemaVersion  int                `json:"current_schema_version"`
	TargetSchemaVersion   int                `json:"target_schema_version"`
	ConfigValid           bool               `json:"config_valid"`
	ConfigValidationError string             `json:"config_validation_error,omitempty"`
	DeploymentProfile     string             `json:"deployment_profile,omitempty"`
	DeploymentForm        string             `json:"deployment_form,omitempty"`
	Rehearsal             MigrationRehearsal `json:"rehearsal"`
	Recommendations       []string           `json:"recommendations,omitempty"`
}

func AssessReadiness(cfg *config.Config, configPath string) (ReadinessReport, error) {
	report := ReadinessReport{
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		ConfigPath:          strings.TrimSpace(configPath),
		TargetSchemaVersion: db.LatestSchemaVersion(),
	}
	if cfg == nil {
		return report, fmt.Errorf("configuration not loaded")
	}

	report.DatabasePath = cfg.Database.Path
	report.DeploymentProfile = cfg.Deployment.Profile
	report.DeploymentForm = cfg.Deployment.Form

	if err := cfg.Validate(); err != nil {
		report.ConfigValid = false
		report.ConfigValidationError = err.Error()
		report.Recommendations = append(report.Recommendations, "Fix configuration validation errors before attempting an appliance upgrade.")
	} else {
		report.ConfigValid = true
	}

	info, err := os.Stat(cfg.Database.Path)
	if err != nil {
		if os.IsNotExist(err) {
			report.Recommendations = append(report.Recommendations, "Database file is missing; initialize or restore the appliance database before upgrade rehearsal.")
			return report, nil
		}
		return report, fmt.Errorf("inspect database path: %w", err)
	}

	report.DatabaseExists = true
	report.DatabaseSizeBytes = info.Size()

	currentHandle, err := db.Open(cfg.Database.Path)
	if err != nil {
		return report, fmt.Errorf("open current database: %w", err)
	}
	currentSchemaVersion, schemaErr := db.CurrentSchemaVersionHandle(currentHandle)
	_ = currentHandle.Close()
	if schemaErr != nil {
		return report, fmt.Errorf("read current schema version: %w", schemaErr)
	}
	report.CurrentSchemaVersion = currentSchemaVersion

	rehearsal, err := rehearseMigration(cfg.Database.Path)
	if err != nil {
		return report, err
	}
	report.Rehearsal = rehearsal

	if !report.Rehearsal.Succeeded {
		report.Recommendations = append(report.Recommendations, "Resolve migration rehearsal failures before applying this upgrade on a live appliance.")
	}
	if report.CurrentSchemaVersion < report.TargetSchemaVersion {
		report.Recommendations = append(report.Recommendations, fmt.Sprintf("Database schema is behind the current software target (%d -> %d).", report.CurrentSchemaVersion, report.TargetSchemaVersion))
	}
	if report.Rehearsal.Succeeded && report.ConfigValid {
		report.Recommendations = append(report.Recommendations, "Upgrade rehearsal passed; capture a support bundle and current backups before production rollout.")
	}

	return report, nil
}

func rehearseMigration(databasePath string) (MigrationRehearsal, error) {
	result := MigrationRehearsal{}
	sourcePath := strings.TrimSpace(databasePath)
	if sourcePath == "" {
		result.Error = "database path is not configured"
		return result, nil
	}

	tempDir, err := os.MkdirTemp("", "aegisnas-upgrade-rehearsal-*")
	if err != nil {
		return result, fmt.Errorf("create rehearsal temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	tempDBPath := filepath.Join(tempDir, filepath.Base(sourcePath))
	if err := copyFile(sourcePath, tempDBPath); err != nil {
		return result, fmt.Errorf("copy database into rehearsal workspace: %w", err)
	}

	handle, err := db.Open(tempDBPath)
	if err != nil {
		return result, fmt.Errorf("open rehearsal database: %w", err)
	}
	defer handle.Close()

	startedVersion, err := db.CurrentSchemaVersionHandle(handle)
	if err != nil {
		return result, fmt.Errorf("read rehearsal schema version: %w", err)
	}

	result.Ran = true
	result.StartedSchemaVersion = startedVersion

	startedAt := time.Now()
	migrationErr := db.MigrateHandle(handle)
	result.DurationMilliseconds = time.Since(startedAt).Milliseconds()
	if migrationErr != nil {
		result.Error = migrationErr.Error()
		return result, nil
	}

	finalVersion, err := db.CurrentSchemaVersionHandle(handle)
	if err != nil {
		return result, fmt.Errorf("read rehearsal result schema version: %w", err)
	}

	result.Succeeded = true
	result.ResultSchemaVersion = finalVersion
	return result, nil
}

func copyFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()

	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	output, err := os.Create(target)
	if err != nil {
		return err
	}
	defer output.Close()

	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return output.Close()
}
