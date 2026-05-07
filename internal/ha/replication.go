package ha

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/network"
	_ "modernc.org/sqlite"
)

const ReplicationRuntimeComponent = "ha_replication"

type ReplicationManifest struct {
	PackageType      string            `json:"package_type"`
	GeneratedAt      string            `json:"generated_at"`
	SourceNode       string            `json:"source_node"`
	SourceRole       string            `json:"source_role"`
	SchemaVersion    int               `json:"schema_version"`
	ConfigPath       string            `json:"config_path"`
	DatabasePath     string            `json:"database_path"`
	NetworkStatePath string            `json:"network_state_path,omitempty"`
	Files            map[string]string `json:"files"`
}

type StagedReplicationPackage struct {
	ID                  string              `json:"id"`
	ImportedAt          string              `json:"imported_at"`
	ImportedBy          string              `json:"imported_by"`
	ImportedSource      string              `json:"imported_source,omitempty"`
	ActivatedAt         string              `json:"activated_at,omitempty"`
	ActivatedBy         string              `json:"activated_by,omitempty"`
	Ready               bool                `json:"ready"`
	Status              string              `json:"status"`
	Summary             string              `json:"summary"`
	ConfigValid         bool                `json:"config_valid"`
	DatabaseValid       bool                `json:"database_valid"`
	NetworkStatePresent bool                `json:"network_state_present"`
	PackageChecksum     string              `json:"package_checksum,omitempty"`
	ContentFingerprint  string              `json:"content_fingerprint,omitempty"`
	ActivationBackup    string              `json:"activation_backup,omitempty"`
	Manifest            ReplicationManifest `json:"manifest"`
}

type ActivationResult struct {
	ID               string   `json:"id"`
	BackupPath       string   `json:"backup_path"`
	RestartScheduled bool     `json:"restart_scheduled"`
	RestartServices  []string `json:"restart_services"`
	Summary          string   `json:"summary"`
}

func CreateReplicationPackage(cfg *config.Config) ([]byte, ReplicationManifest, error) {
	if cfg == nil {
		return nil, ReplicationManifest{}, errors.New("ha replication export requires a config")
	}
	configPath := strings.TrimSpace(config.Path())
	if configPath == "" {
		return nil, ReplicationManifest{}, errors.New("config path is not available")
	}
	if _, err := os.Stat(configPath); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("stat config file: %w", err)
	}
	if _, err := os.Stat(cfg.Database.Path); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("stat database file: %w", err)
	}

	schemaVersion, err := currentSchemaVersion(cfg.Database.Path)
	if err != nil {
		return nil, ReplicationManifest{}, err
	}

	nodeName, _ := os.Hostname()
	manifest := ReplicationManifest{
		PackageType:   "aegisnas-ha-replication",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		SourceNode:    strings.TrimSpace(nodeName),
		SourceRole:    strings.TrimSpace(cfg.HighAvailability.Role),
		SchemaVersion: schemaVersion,
		ConfigPath:    configPath,
		DatabasePath:  cfg.Database.Path,
		Files:         map[string]string{},
	}

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)

	if err := addFileToArchive(tarWriter, configPath, "config.yaml", manifest.Files); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("add config: %w", err)
	}
	if err := addFileToArchive(tarWriter, cfg.Database.Path, "data.db", manifest.Files); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("add database: %w", err)
	}

	networkStatePath := network.StatePath(cfg)
	if _, err := os.Stat(networkStatePath); err == nil {
		manifest.NetworkStatePath = networkStatePath
		if err := addFileToArchive(tarWriter, networkStatePath, "network-state.json", manifest.Files); err != nil {
			return nil, ReplicationManifest{}, fmt.Errorf("add network state: %w", err)
		}
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("marshal manifest: %w", err)
	}
	if err := addBytesToArchive(tarWriter, manifestBytes, "manifest.json", 0644); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("add manifest: %w", err)
	}

	if err := tarWriter.Close(); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, ReplicationManifest{}, fmt.Errorf("close gzip writer: %w", err)
	}
	return buffer.Bytes(), manifest, nil
}

func SaveReplicationPackage(path string, packageBytes []byte) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return errors.New("replication package path is required")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("create replication package dir: %w", err)
	}
	if err := os.WriteFile(target, packageBytes, 0640); err != nil {
		return fmt.Errorf("write replication package: %w", err)
	}
	return nil
}

func ImportReplicationPackage(cfg *config.Config, packageBytes []byte, importedBy string) (StagedReplicationPackage, error) {
	return importReplicationPackage(cfg, packageBytes, importedBy, "upload")
}

func importReplicationPackage(cfg *config.Config, packageBytes []byte, importedBy, importedSource string) (StagedReplicationPackage, error) {
	if cfg == nil {
		return StagedReplicationPackage{}, errors.New("ha replication import requires a config")
	}
	if len(packageBytes) == 0 {
		return StagedReplicationPackage{}, errors.New("replication package is empty")
	}
	stage := StagedReplicationPackage{
		ID:              time.Now().UTC().Format("20060102T150405Z"),
		ImportedAt:      time.Now().UTC().Format(time.RFC3339),
		ImportedBy:      strings.TrimSpace(importedBy),
		ImportedSource:  strings.TrimSpace(importedSource),
		Status:          "degraded",
		Summary:         "Replication package import did not complete.",
		PackageChecksum: checksumBytes(packageBytes),
	}
	if stage.ImportedBy == "" {
		stage.ImportedBy = "unknown"
	}
	if stage.ImportedSource == "" {
		stage.ImportedSource = "upload"
	}

	stageDir := stagedPackageDir(cfg, stage.ID)
	contentDir := filepath.Join(stageDir, "content")
	archivePath := filepath.Join(stageDir, "package.tar.gz")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return stage, fmt.Errorf("create staged replication dir: %w", err)
	}
	if err := os.WriteFile(archivePath, packageBytes, 0640); err != nil {
		return stage, fmt.Errorf("write staged replication archive: %w", err)
	}
	if err := extractTarGzBytes(packageBytes, contentDir); err != nil {
		return stage, fmt.Errorf("extract replication package: %w", err)
	}

	manifest, err := loadManifest(filepath.Join(contentDir, "manifest.json"))
	if err != nil {
		return stage, err
	}
	if err := verifyManifest(contentDir, manifest); err != nil {
		return stage, err
	}

	importedCfg, err := config.LoadCandidate(filepath.Join(contentDir, "config.yaml"))
	if err != nil {
		return stage, fmt.Errorf("validate imported config: %w", err)
	}
	if err := importedCfg.Validate(); err != nil {
		return stage, fmt.Errorf("validate imported config: %w", err)
	}

	if err := verifyDatabase(filepath.Join(contentDir, "data.db")); err != nil {
		return stage, fmt.Errorf("verify imported database: %w", err)
	}
	if manifest.SchemaVersion > db.LatestSchemaVersion() {
		return stage, fmt.Errorf("replication package schema version %d is newer than this node supports (%d)", manifest.SchemaVersion, db.LatestSchemaVersion())
	}

	stage.Manifest = manifest
	stage.ConfigValid = true
	stage.DatabaseValid = true
	stage.ContentFingerprint = contentFingerprintForManifest(manifest)

	networkStatePath := filepath.Join(contentDir, "network-state.json")
	if _, err := os.Stat(networkStatePath); err == nil {
		if _, err := network.LoadState(networkStatePath); err != nil {
			return stage, fmt.Errorf("validate imported network state: %w", err)
		}
		stage.NetworkStatePresent = true
	}

	stage.Ready = true
	stage.Status = "ready"
	stage.Summary = fmt.Sprintf("Replication package from %s is staged and validated for standby activation.", manifest.SourceNode)
	if err := writeStageMetadata(stageDir, stage); err != nil {
		return stage, err
	}
	_ = db.RecordHAHistory("replication_stage", "staged", stage.Summary, strings.TrimSpace(cfg.HighAvailability.Role), stage.ImportedBy, map[string]any{
		"stage_id":            stage.ID,
		"source_node":         manifest.SourceNode,
		"source_role":         manifest.SourceRole,
		"schema_version":      manifest.SchemaVersion,
		"network_present":     stage.NetworkStatePresent,
		"package_type":        manifest.PackageType,
		"package_checksum":    stage.PackageChecksum,
		"content_fingerprint": stage.ContentFingerprint,
		"imported_source":     stage.ImportedSource,
	})
	_ = db.UpsertRuntimeStatus(ReplicationRuntimeComponent, "ok", stage.Summary, map[string]any{
		"staged_id":           stage.ID,
		"source_node":         manifest.SourceNode,
		"source_role":         manifest.SourceRole,
		"imported_at":         stage.ImportedAt,
		"network_present":     stage.NetworkStatePresent,
		"package_checksum":    stage.PackageChecksum,
		"content_fingerprint": stage.ContentFingerprint,
		"imported_source":     stage.ImportedSource,
	})
	return stage, nil
}

func FindStagedReplicationPackageByChecksum(cfg *config.Config, checksum string) (StagedReplicationPackage, bool, error) {
	if cfg == nil {
		return StagedReplicationPackage{}, false, errors.New("ha staged replication lookup requires a config")
	}
	checksum = strings.TrimSpace(checksum)
	if checksum == "" {
		return StagedReplicationPackage{}, false, nil
	}
	packages, err := ListStagedReplicationPackages(cfg)
	if err != nil {
		return StagedReplicationPackage{}, false, err
	}
	for _, stage := range packages {
		if strings.EqualFold(strings.TrimSpace(stage.PackageChecksum), checksum) {
			return stage, true, nil
		}
	}
	return StagedReplicationPackage{}, false, nil
}

func FindStagedReplicationPackageByContentFingerprint(cfg *config.Config, fingerprint string) (StagedReplicationPackage, bool, error) {
	if cfg == nil {
		return StagedReplicationPackage{}, false, errors.New("ha staged replication fingerprint lookup requires a config")
	}
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return StagedReplicationPackage{}, false, nil
	}
	packages, err := ListStagedReplicationPackages(cfg)
	if err != nil {
		return StagedReplicationPackage{}, false, err
	}
	for _, stage := range packages {
		stageFingerprint := strings.TrimSpace(stage.ContentFingerprint)
		if stageFingerprint == "" {
			stageFingerprint = strings.TrimSpace(stage.PackageChecksum)
		}
		if strings.EqualFold(stageFingerprint, fingerprint) {
			return stage, true, nil
		}
	}
	return StagedReplicationPackage{}, false, nil
}

func ListStagedReplicationPackages(cfg *config.Config) ([]StagedReplicationPackage, error) {
	root := stagedRootDir(cfg)
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("create staged replication root: %w", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read staged replication root: %w", err)
	}
	packages := make([]StagedReplicationPackage, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stage, err := readStageMetadata(filepath.Join(root, entry.Name()))
		if err != nil {
			continue
		}
		packages = append(packages, stage)
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].ImportedAt > packages[j].ImportedAt
	})
	return packages, nil
}

func ActivateStagedReplicationPackage(cfg *config.Config, id, activatedBy string) (ActivationResult, error) {
	if cfg == nil {
		return ActivationResult{}, errors.New("ha replication activation requires a config")
	}
	if !cfg.HighAvailability.Enabled {
		return ActivationResult{}, errors.New("high availability is not enabled on this node")
	}
	if strings.TrimSpace(cfg.HighAvailability.Role) != "standby" {
		return ActivationResult{}, errors.New("replication package activation is only allowed on standby nodes")
	}
	stageDir := stagedPackageDir(cfg, strings.TrimSpace(id))
	stage, err := readStageMetadata(stageDir)
	if err != nil {
		return ActivationResult{}, err
	}
	if !stage.Ready {
		return ActivationResult{}, errors.New("staged replication package is not ready to activate")
	}

	contentDir := filepath.Join(stageDir, "content")
	importedCfg, err := config.LoadCandidate(filepath.Join(contentDir, "config.yaml"))
	if err != nil {
		return ActivationResult{}, fmt.Errorf("load staged config: %w", err)
	}
	importedCfg.HighAvailability = cfg.HighAvailability
	importedCfg.Database.Path = cfg.Database.Path
	if err := importedCfg.Validate(); err != nil {
		return ActivationResult{}, fmt.Errorf("validate merged standby config: %w", err)
	}

	backupBytes, _, err := CreateReplicationPackage(cfg)
	if err != nil {
		return ActivationResult{}, fmt.Errorf("create standby safety backup: %w", err)
	}
	backupPath := filepath.Join(backupsRootDir(cfg), fmt.Sprintf("replication-rollback-%s.tar.gz", time.Now().UTC().Format("20060102T150405Z")))
	if err := SaveReplicationPackage(backupPath, backupBytes); err != nil {
		return ActivationResult{}, fmt.Errorf("save standby safety backup: %w", err)
	}

	currentDBPath := strings.TrimSpace(cfg.Database.Path)
	if currentDBPath != "" {
		_ = db.Close()
	}
	if err := replaceFileFromSource(filepath.Join(contentDir, "data.db"), importedCfg.Database.Path, 0640); err != nil {
		if currentDBPath != "" {
			_ = db.Init(currentDBPath)
		}
		return ActivationResult{}, fmt.Errorf("write standby database: %w", err)
	}
	if currentDBPath != "" {
		if err := db.Init(importedCfg.Database.Path); err != nil {
			return ActivationResult{}, fmt.Errorf("reopen standby database: %w", err)
		}
		if err := db.Migrate(); err != nil {
			return ActivationResult{}, fmt.Errorf("migrate reopened standby database: %w", err)
		}
	}
	if err := replaceConfigFile(config.Path(), importedCfg); err != nil {
		return ActivationResult{}, fmt.Errorf("write standby config: %w", err)
	}

	stage.ActivatedAt = time.Now().UTC().Format(time.RFC3339)
	stage.ActivatedBy = strings.TrimSpace(activatedBy)
	if stage.ActivatedBy == "" {
		stage.ActivatedBy = "unknown"
	}
	stage.ActivationBackup = backupPath
	stage.Status = "activated"
	stage.Summary = "Replication package activated on standby. Service restart is required to begin using the imported state."
	if err := writeStageMetadata(stageDir, stage); err != nil {
		return ActivationResult{}, err
	}
	services := []string{
		"dnsmasq",
		"freeradius",
		"nftables",
		"aegis-gateway",
		"aegis-radius",
		"aegis-portal",
		"aegis-session",
		"aegis-policy",
		"aegis-ai-lite",
		"aegis-telemetry",
		"aegis-admin-api",
	}
	_ = db.RecordHAHistory("replication_activate", "activated", stage.Summary, strings.TrimSpace(cfg.HighAvailability.Role), stage.ActivatedBy, map[string]any{
		"stage_id":            stage.ID,
		"activation_backup":   backupPath,
		"restart_services":    services,
		"source_node":         stage.Manifest.SourceNode,
		"source_role":         stage.Manifest.SourceRole,
		"schema_version":      stage.Manifest.SchemaVersion,
		"content_fingerprint": stage.ContentFingerprint,
	})
	_ = db.UpsertRuntimeStatus(ReplicationRuntimeComponent, "pending", stage.Summary, map[string]any{
		"staged_id":           stage.ID,
		"activated_at":        stage.ActivatedAt,
		"activated_by":        stage.ActivatedBy,
		"activation_backup":   backupPath,
		"restart_services":    services,
		"content_fingerprint": stage.ContentFingerprint,
	})
	return ActivationResult{
		ID:               stage.ID,
		BackupPath:       backupPath,
		RestartScheduled: true,
		RestartServices:  services,
		Summary:          stage.Summary,
	}, nil
}

func stagedRootDir(cfg *config.Config) string {
	return filepath.Join(replicationRootDir(cfg), "staged")
}

func backupsRootDir(cfg *config.Config) string {
	return filepath.Join(replicationRootDir(cfg), "backups")
}

func replicationRootDir(cfg *config.Config) string {
	root := "/var/lib/aegisnas/ha"
	if cfg != nil && strings.TrimSpace(cfg.HighAvailability.SharedStateDir) != "" {
		root = strings.TrimSpace(cfg.HighAvailability.SharedStateDir)
	}
	return filepath.Join(root, "replication")
}

func stagedPackageDir(cfg *config.Config, id string) string {
	return filepath.Join(stagedRootDir(cfg), strings.TrimSpace(id))
}

func addFileToArchive(tw *tar.Writer, path, archiveName string, manifest map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	manifest[archiveName] = hex.EncodeToString(sum[:])
	return addBytesToArchive(tw, data, archiveName, 0640)
}

func addBytesToArchive(tw *tar.Writer, data []byte, name string, mode int64) error {
	header := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func extractTarGzBytes(data []byte, dest string) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		cleanName := filepath.Clean(header.Name)
		if cleanName == "." || cleanName == ".." || filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe archive path: %s", header.Name)
		}
		targetPath := filepath.Join(dest, cleanName)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		out, err := os.Create(targetPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tarReader); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}

func loadManifest(path string) (ReplicationManifest, error) {
	var manifest ReplicationManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, fmt.Errorf("read replication manifest: %w", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("decode replication manifest: %w", err)
	}
	if manifest.PackageType != "aegisnas-ha-replication" {
		return manifest, fmt.Errorf("unexpected replication package type %q", manifest.PackageType)
	}
	if len(manifest.Files) == 0 {
		return manifest, errors.New("replication manifest does not contain files")
	}
	return manifest, nil
}

func verifyManifest(contentDir string, manifest ReplicationManifest) error {
	for name, expectedChecksum := range manifest.Files {
		actual, err := fileChecksum(filepath.Join(contentDir, name))
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		if actual != expectedChecksum {
			return fmt.Errorf("checksum mismatch for %s", name)
		}
	}
	return nil
}

func fileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func contentFingerprintForManifest(manifest ReplicationManifest) string {
	parts := make([]string, 0, len(manifest.Files)+2)
	parts = append(parts, fmt.Sprintf("schema:%d", manifest.SchemaVersion))
	if manifest.NetworkStatePath != "" {
		parts = append(parts, "network:true")
	} else {
		parts = append(parts, "network:false")
	}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s:%s", name, manifest.Files[name]))
	}
	return checksumBytes([]byte(strings.Join(parts, "\n")))
}

func verifyDatabase(path string) error {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer sqlDB.Close()
	var result string
	if err := sqlDB.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("run integrity check: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(result), "ok") {
		return fmt.Errorf("integrity check returned %q", result)
	}
	return nil
}

func currentSchemaVersion(path string) (int, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return 0, fmt.Errorf("open database: %w", err)
	}
	defer sqlDB.Close()
	var version int
	if err := sqlDB.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return version, nil
}

func writeStageMetadata(stageDir string, stage StagedReplicationPackage) error {
	if err := os.MkdirAll(stageDir, 0755); err != nil {
		return fmt.Errorf("create stage dir: %w", err)
	}
	data, err := json.MarshalIndent(stage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal stage metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "status.json"), data, 0644); err != nil {
		return fmt.Errorf("write stage metadata: %w", err)
	}
	return nil
}

func readStageMetadata(stageDir string) (StagedReplicationPackage, error) {
	var stage StagedReplicationPackage
	data, err := os.ReadFile(filepath.Join(stageDir, "status.json"))
	if err != nil {
		return stage, fmt.Errorf("read staged replication metadata: %w", err)
	}
	if err := json.Unmarshal(data, &stage); err != nil {
		return stage, fmt.Errorf("decode staged replication metadata: %w", err)
	}
	return stage, nil
}

func replaceConfigFile(target string, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	tempDir, err := os.MkdirTemp("", "aegis-ha-config-*")
	if err != nil {
		return fmt.Errorf("create config temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	tempPath := filepath.Join(tempDir, "config.yaml")
	if err := config.WriteFile(tempPath, cfg); err != nil {
		return err
	}
	return replaceFileFromSource(tempPath, target, 0640)
}

func replaceFileFromSource(source, target string, perm os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}
	tempPath := target + ".incoming"
	if err := os.WriteFile(tempPath, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	backupPath := target + ".rollback"
	_ = os.Remove(backupPath)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, backupPath); err != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("stage existing file backup: %w", err)
		}
	}
	if err := os.Rename(tempPath, target); err != nil {
		_ = os.Remove(tempPath)
		if _, statErr := os.Stat(backupPath); statErr == nil {
			_ = os.Rename(backupPath, target)
		}
		return fmt.Errorf("replace target file: %w", err)
	}
	_ = os.Remove(backupPath)
	return nil
}
