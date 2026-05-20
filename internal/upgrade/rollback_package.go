package upgrade

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"gopkg.in/yaml.v3"
)

const rollbackPackageVersion = "1"
const rollbackRestoreConfirmationText = "RESTORE UPGRADE ROLLBACK"

type RollbackPackageManifest struct {
	PackageVersion       string `json:"package_version"`
	GeneratedAt          string `json:"generated_at"`
	ConfigPath           string `json:"config_path"`
	DatabasePath         string `json:"database_path"`
	CurrentSchemaVersion int    `json:"current_schema_version"`
	TargetSchemaVersion  int    `json:"target_schema_version"`
	DeploymentProfile    string `json:"deployment_profile,omitempty"`
	DeploymentForm       string `json:"deployment_form,omitempty"`
	DatabaseCopyMode     string `json:"database_copy_mode"`
	ContainsSecrets      bool   `json:"contains_secrets"`
}

type RollbackPackageContents struct {
	Manifest         RollbackPackageManifest
	ConfigYAML       []byte
	SystemSettings   []byte
	Database         []byte
	PackageSizeBytes int64
}

type RollbackPackageInspection struct {
	Manifest                    RollbackPackageManifest `json:"manifest"`
	PackageSizeBytes            int64                   `json:"package_size_bytes"`
	HasConfigYAML               bool                    `json:"has_config_yaml"`
	HasSystemSettings           bool                    `json:"has_system_settings"`
	HasDatabase                 bool                    `json:"has_database"`
	CurrentRuntimeSchemaVersion int                     `json:"current_runtime_schema_version"`
	RuntimeTargetSchemaVersion  int                     `json:"runtime_target_schema_version"`
	ConfigValid                 bool                    `json:"config_valid"`
	ConfigValidationError       string                  `json:"config_validation_error,omitempty"`
	DatabasePathMatches         bool                    `json:"database_path_matches"`
	CompatibilityStatus         string                  `json:"compatibility_status"`
	OnlineRestoreSupported      bool                    `json:"online_restore_supported"`
	Warnings                    []string                `json:"warnings,omitempty"`
	RestoreSteps                []string                `json:"restore_steps,omitempty"`
	RequiredConfirmationText    string                  `json:"required_confirmation_text,omitempty"`
}

type RollbackRestoreResult struct {
	Inspection         RollbackPackageInspection `json:"inspection"`
	SafetyPackagePath  string                    `json:"safety_package_path"`
	DatabaseBackupPath string                    `json:"database_backup_path"`
	RestartRequired    bool                      `json:"restart_required"`
}

func CreateRollbackPackage(cfg *config.Config, configPath string) ([]byte, string, RollbackPackageManifest, error) {
	manifest := RollbackPackageManifest{
		PackageVersion:      rollbackPackageVersion,
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		ConfigPath:          strings.TrimSpace(configPath),
		TargetSchemaVersion: db.LatestSchemaVersion(),
		ContainsSecrets:     true,
	}
	if cfg == nil {
		return nil, "", manifest, fmt.Errorf("configuration not loaded")
	}

	manifest.DatabasePath = cfg.Database.Path
	manifest.DeploymentProfile = cfg.Deployment.Profile
	manifest.DeploymentForm = cfg.Deployment.Form

	handle, err := db.Open(cfg.Database.Path)
	if err != nil {
		return nil, "", manifest, fmt.Errorf("open database for rollback packaging: %w", err)
	}
	defer handle.Close()

	currentSchemaVersion, err := db.CurrentSchemaVersionHandle(handle)
	if err != nil {
		return nil, "", manifest, fmt.Errorf("read current schema version: %w", err)
	}
	manifest.CurrentSchemaVersion = currentSchemaVersion

	tempDir, err := os.MkdirTemp("", "aegisnas-rollback-package-*")
	if err != nil {
		return nil, "", manifest, fmt.Errorf("create rollback package temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	dbCopyPath := filepath.Join(tempDir, "data.db")
	if err := vacuumInto(handle, dbCopyPath); err != nil {
		return nil, "", manifest, fmt.Errorf("copy database into rollback package workspace: %w", err)
	}
	manifest.DatabaseCopyMode = "vacuum_into"

	configBytes, configErr := readRollbackConfigBytes(cfg, configPath)
	if configErr != nil {
		return nil, "", manifest, configErr
	}
	settingsJSON, err := json.MarshalIndent(config.SettingsSnapshot(), "", "  ")
	if err != nil {
		return nil, "", manifest, fmt.Errorf("marshal settings snapshot: %w", err)
	}
	dbCopyBytes, err := os.ReadFile(dbCopyPath)
	if err != nil {
		return nil, "", manifest, fmt.Errorf("read packaged database copy: %w", err)
	}

	buffer := &bytes.Buffer{}
	archive := zip.NewWriter(buffer)
	addBytes := func(name string, data []byte) error {
		entry, err := archive.Create(name)
		if err != nil {
			return err
		}
		_, err = entry.Write(data)
		return err
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, "", manifest, fmt.Errorf("marshal rollback package manifest: %w", err)
	}

	if err := addBytes("manifest.json", append(manifestJSON, '\n')); err != nil {
		return nil, "", manifest, fmt.Errorf("write manifest: %w", err)
	}
	if err := addBytes("config/config.yaml", configBytes); err != nil {
		return nil, "", manifest, fmt.Errorf("write config file: %w", err)
	}
	if err := addBytes("config/system-settings.json", append(settingsJSON, '\n')); err != nil {
		return nil, "", manifest, fmt.Errorf("write settings snapshot: %w", err)
	}
	if err := addBytes("database/data.db", dbCopyBytes); err != nil {
		return nil, "", manifest, fmt.Errorf("write database copy: %w", err)
	}

	if err := archive.Close(); err != nil {
		return nil, "", manifest, fmt.Errorf("close rollback package archive: %w", err)
	}

	filename := fmt.Sprintf("aegisnas-upgrade-rollback-%s.zip", time.Now().UTC().Format("20060102-150405Z"))
	return buffer.Bytes(), filename, manifest, nil
}

func readRollbackConfigBytes(cfg *config.Config, configPath string) ([]byte, error) {
	if trimmed := strings.TrimSpace(configPath); trimmed != "" {
		if data, err := os.ReadFile(trimmed); err == nil {
			if len(data) > 0 && data[len(data)-1] != '\n' {
				data = append(data, '\n')
			}
			return data, nil
		}
	}

	payload, err := yaml.Marshal(config.SettingsSnapshot())
	if err != nil {
		return nil, fmt.Errorf("marshal config settings as YAML fallback: %w", err)
	}
	return payload, nil
}

func vacuumInto(handle *sql.DB, target string) error {
	if handle == nil {
		return fmt.Errorf("database handle is required")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	_ = os.Remove(target)
	sqlTarget := strings.ReplaceAll(target, "'", "''")
	if _, err := handle.Exec(fmt.Sprintf("VACUUM INTO '%s'", sqlTarget)); err != nil {
		return err
	}
	return nil
}

func InspectRollbackPackage(reader io.ReaderAt, size int64) (RollbackPackageManifest, error) {
	var manifest RollbackPackageManifest
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return manifest, err
	}
	for _, file := range archive.File {
		if file.Name != "manifest.json" {
			continue
		}
		handle, err := file.Open()
		if err != nil {
			return manifest, err
		}
		defer handle.Close()
		if err := json.NewDecoder(handle).Decode(&manifest); err != nil {
			return manifest, err
		}
		return manifest, nil
	}
	return manifest, fmt.Errorf("manifest.json not found in rollback package")
}

func ReadRollbackPackage(reader io.ReaderAt, size int64) (RollbackPackageContents, error) {
	var contents RollbackPackageContents
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return contents, err
	}
	contents.PackageSizeBytes = size
	for _, file := range archive.File {
		handle, err := file.Open()
		if err != nil {
			return contents, err
		}
		data, err := io.ReadAll(handle)
		_ = handle.Close()
		if err != nil {
			return contents, err
		}
		switch file.Name {
		case "manifest.json":
			if err := json.Unmarshal(data, &contents.Manifest); err != nil {
				return contents, fmt.Errorf("decode rollback package manifest: %w", err)
			}
		case "config/config.yaml":
			contents.ConfigYAML = data
		case "config/system-settings.json":
			contents.SystemSettings = data
		case "database/data.db":
			contents.Database = data
		}
	}
	if contents.Manifest.PackageVersion == "" {
		return contents, fmt.Errorf("manifest.json not found in rollback package")
	}
	return contents, nil
}

func InspectRollbackPackageBytes(packageBytes []byte, cfg *config.Config, configPath string) (RollbackPackageInspection, error) {
	contents, err := ReadRollbackPackage(bytes.NewReader(packageBytes), int64(len(packageBytes)))
	if err != nil {
		return RollbackPackageInspection{}, err
	}
	return inspectRollbackPackageContents(contents, cfg, configPath)
}

func inspectRollbackPackageContents(contents RollbackPackageContents, cfg *config.Config, configPath string) (RollbackPackageInspection, error) {
	inspection := RollbackPackageInspection{
		Manifest:                   contents.Manifest,
		PackageSizeBytes:           contents.PackageSizeBytes,
		HasConfigYAML:              len(contents.ConfigYAML) > 0,
		HasSystemSettings:          len(contents.SystemSettings) > 0,
		HasDatabase:                len(contents.Database) > 0,
		RuntimeTargetSchemaVersion: db.LatestSchemaVersion(),
		DatabasePathMatches:        false,
		ConfigValid:                false,
		CompatibilityStatus:        "invalid",
	}
	if cfg == nil {
		inspection.Warnings = append(inspection.Warnings, "Current appliance configuration is not loaded.")
		return inspection, nil
	}

	currentSchemaVersion := 0
	handle, err := db.Open(cfg.Database.Path)
	if err == nil {
		currentSchemaVersion, _ = db.CurrentSchemaVersionHandle(handle)
		_ = handle.Close()
	}
	inspection.CurrentRuntimeSchemaVersion = currentSchemaVersion

	if len(contents.ConfigYAML) == 0 {
		inspection.Warnings = append(inspection.Warnings, "Rollback package is missing config/config.yaml.")
	}
	if len(contents.SystemSettings) == 0 {
		inspection.Warnings = append(inspection.Warnings, "Rollback package is missing config/system-settings.json, so config validation cannot run.")
	}
	if len(contents.Database) == 0 {
		inspection.Warnings = append(inspection.Warnings, "Rollback package is missing database/data.db.")
	}

	if len(contents.SystemSettings) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(contents.SystemSettings, &payload); err != nil {
			inspection.ConfigValidationError = fmt.Sprintf("settings snapshot JSON is invalid: %v", err)
		} else {
			restoredCfg, evalErr := config.EvaluateSettingsMap(payload)
			if evalErr != nil {
				inspection.ConfigValidationError = evalErr.Error()
			} else {
				inspection.ConfigValid = true
				inspection.DatabasePathMatches = strings.TrimSpace(restoredCfg.Database.Path) == strings.TrimSpace(cfg.Database.Path)
				if !inspection.DatabasePathMatches {
					inspection.Warnings = append(inspection.Warnings, fmt.Sprintf("Package database path %s does not match current appliance database path %s.", restoredCfg.Database.Path, cfg.Database.Path))
				}
			}
		}
	}

	onlineSupported := len(contents.ConfigYAML) > 0 &&
		len(contents.SystemSettings) > 0 &&
		len(contents.Database) > 0 &&
		inspection.ConfigValid &&
		inspection.DatabasePathMatches &&
		contents.Manifest.TargetSchemaVersion == db.LatestSchemaVersion() &&
		contents.Manifest.CurrentSchemaVersion == inspection.CurrentRuntimeSchemaVersion

	inspection.OnlineRestoreSupported = onlineSupported
	inspection.RequiredConfirmationText = rollbackRestoreConfirmationText
	if onlineSupported {
		inspection.CompatibilityStatus = "online_supported"
		inspection.RestoreSteps = []string{
			"Download a fresh support bundle and current rollback package before restoring.",
			fmt.Sprintf("Confirm the restore with the exact phrase %q.", rollbackRestoreConfirmationText),
			"Apply the rollback package, then restart AegisNAS services or rerun the local bootstrap flow.",
		}
		return inspection, nil
	}

	inspection.CompatibilityStatus = "offline_required"
	if contents.Manifest.TargetSchemaVersion != db.LatestSchemaVersion() {
		inspection.Warnings = append(inspection.Warnings, fmt.Sprintf("Package target schema version %d does not match this runtime target schema version %d.", contents.Manifest.TargetSchemaVersion, db.LatestSchemaVersion()))
	}
	if contents.Manifest.CurrentSchemaVersion != inspection.CurrentRuntimeSchemaVersion {
		inspection.Warnings = append(inspection.Warnings, fmt.Sprintf("Package current schema version %d does not match the live appliance schema version %d.", contents.Manifest.CurrentSchemaVersion, inspection.CurrentRuntimeSchemaVersion))
	}
	inspection.RestoreSteps = []string{
		"Use a version-matched AegisNAS build for this rollback package before attempting a live restore.",
		"Stop the appliance services or boot a maintenance environment before replacing the database when schema versions differ.",
		"After restoring, rerun validation and health checks before returning the node to service.",
	}
	return inspection, nil
}

func RestoreRollbackPackage(cfg *config.Config, configPath string, packageBytes []byte, confirmationText string) (RollbackRestoreResult, error) {
	result := RollbackRestoreResult{}
	if strings.TrimSpace(confirmationText) != rollbackRestoreConfirmationText {
		return result, fmt.Errorf("confirmation text must match %q", rollbackRestoreConfirmationText)
	}
	if cfg == nil {
		return result, fmt.Errorf("configuration not loaded")
	}

	contents, err := ReadRollbackPackage(bytes.NewReader(packageBytes), int64(len(packageBytes)))
	if err != nil {
		return result, err
	}
	inspection, err := inspectRollbackPackageContents(contents, cfg, configPath)
	if err != nil {
		return result, err
	}
	result.Inspection = inspection
	if !inspection.OnlineRestoreSupported {
		return result, fmt.Errorf("rollback package is not eligible for online restore; compatibility status is %s", inspection.CompatibilityStatus)
	}

	safetyDir := filepath.Join(filepath.Dir(cfg.Database.Path), "upgrade-rollback", "safety")
	if err := os.MkdirAll(safetyDir, 0755); err != nil {
		return result, fmt.Errorf("create safety package dir: %w", err)
	}
	safetyBytes, safetyFilename, _, err := CreateRollbackPackage(cfg, configPath)
	if err != nil {
		return result, fmt.Errorf("create safety rollback package: %w", err)
	}
	safetyPath := filepath.Join(safetyDir, safetyFilename)
	if err := os.WriteFile(safetyPath, safetyBytes, 0600); err != nil {
		return result, fmt.Errorf("write safety rollback package: %w", err)
	}
	result.SafetyPackagePath = safetyPath

	currentConfigPath := strings.TrimSpace(configPath)
	if currentConfigPath == "" {
		currentConfigPath = strings.TrimSpace(contents.Manifest.ConfigPath)
	}
	if currentConfigPath == "" {
		return result, fmt.Errorf("current config path is not available for restore")
	}
	if err := os.MkdirAll(filepath.Dir(currentConfigPath), 0755); err != nil {
		return result, fmt.Errorf("create config dir for restore: %w", err)
	}
	if err := os.WriteFile(currentConfigPath, contents.ConfigYAML, 0640); err != nil {
		return result, fmt.Errorf("write restored config file: %w", err)
	}

	dbBackupPath := fmt.Sprintf("%s.pre-rollback-%s.bak", cfg.Database.Path, time.Now().UTC().Format("20060102-150405Z"))
	if source, err := os.Open(cfg.Database.Path); err == nil {
		defer source.Close()
		if backup, createErr := os.Create(dbBackupPath); createErr == nil {
			if _, copyErr := io.Copy(backup, source); copyErr == nil {
				result.DatabaseBackupPath = dbBackupPath
			}
			_ = backup.Close()
		}
	}

	_ = db.Close()
	if err := os.WriteFile(cfg.Database.Path, contents.Database, 0600); err != nil {
		return result, fmt.Errorf("write restored database file: %w", err)
	}
	if _, err := config.Load(currentConfigPath); err != nil {
		return result, fmt.Errorf("reload restored config: %w", err)
	}
	if err := db.Init(cfg.Database.Path); err != nil {
		return result, fmt.Errorf("reopen restored database: %w", err)
	}

	result.RestartRequired = true
	return result, nil
}
