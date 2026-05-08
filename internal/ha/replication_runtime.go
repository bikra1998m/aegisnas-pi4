package ha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

const (
	defaultReplicationInterval = 300 * time.Second
)

type SharedReplicationStatus struct {
	Present             bool   `json:"present"`
	PackagePath         string `json:"package_path"`
	MetadataPath        string `json:"metadata_path"`
	PublishedAt         string `json:"published_at,omitempty"`
	GeneratedAt         string `json:"generated_at,omitempty"`
	SourceNode          string `json:"source_node,omitempty"`
	SourceRole          string `json:"source_role,omitempty"`
	SchemaVersion       int    `json:"schema_version,omitempty"`
	PackageSizeBytes    int64  `json:"package_size_bytes,omitempty"`
	PackageChecksum     string `json:"package_checksum,omitempty"`
	ContentFingerprint  string `json:"content_fingerprint,omitempty"`
	EncryptionAlgorithm string `json:"encryption_algorithm,omitempty"`
	EncryptionStatus    string `json:"encryption_status,omitempty"`
	Signature           string `json:"signature,omitempty"`
	SignatureAlgorithm  string `json:"signature_algorithm,omitempty"`
	SignatureStatus     string `json:"signature_status,omitempty"`
	NetworkStatePresent bool   `json:"network_state_present,omitempty"`
}

type replicationMonitor struct {
	cfg                *config.Config
	logger             *zap.Logger
	now                func() time.Time
	nodeName           string
	lastFreshnessState string
	lastPublishStatus  string
}

func StartContinuousReplication(ctx context.Context, cfg *config.Config, logger *zap.Logger) {
	monitor := newReplicationMonitor(cfg, logger)
	monitor.run(ctx)
}

func newReplicationMonitor(cfg *config.Config, logger *zap.Logger) *replicationMonitor {
	nodeName, _ := os.Hostname()
	return &replicationMonitor{
		cfg:      cfg,
		logger:   logger,
		now:      time.Now,
		nodeName: strings.TrimSpace(nodeName),
	}
}

func (m *replicationMonitor) run(ctx context.Context) {
	m.tick()
	if m.cfg == nil || !m.cfg.HighAvailability.Enabled {
		return
	}

	ticker := time.NewTicker(effectiveReplicationInterval(m.cfg))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *replicationMonitor) tick() {
	status, message, details := m.probe()
	if err := db.UpsertRuntimeStatus(ReplicationRuntimeComponent, status, message, details); err != nil && m.logger != nil {
		m.logger.Warn("failed to update HA replication runtime status", zap.Error(err))
	}
}

func (m *replicationMonitor) probe() (string, string, map[string]any) {
	details := map[string]any{
		"role":                            "",
		"shared_state_dir":                "",
		"replication_interval_seconds":    0,
		"replication_stale_after_seconds": 0,
		"auto_stage_enabled":              false,
		"auto_stage_status":               "disabled",
	}
	if m.cfg == nil {
		return "disabled", "Configuration is unavailable.", details
	}

	role := strings.ToLower(strings.TrimSpace(m.cfg.HighAvailability.Role))
	details["role"] = role
	details["node_name"] = m.nodeName
	details["shared_state_dir"] = strings.TrimSpace(m.cfg.HighAvailability.SharedStateDir)
	details["replication_interval_seconds"] = int(effectiveReplicationInterval(m.cfg) / time.Second)
	details["replication_stale_after_seconds"] = int(effectiveReplicationStaleAfter(m.cfg) / time.Second)
	details["auto_stage_enabled"] = m.cfg.HighAvailability.AutoStageSharedPackage
	details["package_path"] = sharedPackagePath(m.cfg)
	details["metadata_path"] = sharedMetadataPath(m.cfg)

	if !m.cfg.HighAvailability.Enabled {
		return "disabled", "Continuous HA replication is disabled in config.", details
	}
	if !highAvailabilityConfigured(m.cfg) {
		return "degraded", "High availability is enabled, but replication prerequisites are incomplete.", details
	}

	if role == "active" {
		shared, err := PublishSharedReplicationPackage(m.cfg)
		if err != nil {
			m.recordPublishEvent("failed", "Publishing the shared HA replication package failed.", map[string]any{
				"error": err.Error(),
			})
			details["last_error"] = err.Error()
			return "degraded", "Publishing the shared HA replication package failed.", details
		}
		mergeSharedReplicationDetails(details, shared, m.cfg, m.now().UTC())
		details["published_by_this_node"] = true
		m.recordPublishEvent("success", "Published shared HA replication package.", map[string]any{
			"source_node":         shared.SourceNode,
			"source_role":         shared.SourceRole,
			"schema_version":      shared.SchemaVersion,
			"package_checksum":    shared.PackageChecksum,
			"content_fingerprint": shared.ContentFingerprint,
			"package_size_bytes":  shared.PackageSizeBytes,
		})
		return "ok", "Published shared HA replication package for standby sync.", details
	}

	shared, err := LoadSharedReplicationStatus(m.cfg)
	if err != nil {
		details["last_error"] = err.Error()
		return "degraded", "Reading the shared HA replication package failed.", details
	}
	if !shared.Present {
		return "pending", "No shared HA replication package has been published yet.", details
	}

	mergeSharedReplicationDetails(details, shared, m.cfg, m.now().UTC())
	if stale, _ := details["stale"].(bool); stale {
		if m.cfg.HighAvailability.AutoStageSharedPackage && role == "standby" {
			details["auto_stage_status"] = "waiting_fresh"
		}
		m.recordFreshnessEvent("stale", "Shared HA replication package is stale.", details)
		return "degraded", "Shared HA replication package is stale.", details
	}
	autoStageMessage, err := m.maybeAutoStageSharedPackage(role, shared, details)
	if err != nil {
		details["last_error"] = err.Error()
		return "degraded", "Shared HA replication package is fresh, but standby auto-stage failed.", details
	}
	m.recordFreshnessEvent("fresh", "Observed fresh shared HA replication package.", details)
	if autoStageMessage != "" {
		return "ok", autoStageMessage, details
	}
	return "ok", "Observed fresh shared HA replication package.", details
}

func (m *replicationMonitor) recordPublishEvent(status, summary string, details map[string]any) {
	if strings.TrimSpace(status) == "" {
		return
	}
	if status == "failed" && m.lastPublishStatus == "failed" {
		return
	}
	_ = db.RecordHAHistory("replication_publish", status, summary, strings.TrimSpace(m.cfg.HighAvailability.Role), "", details)
	m.lastPublishStatus = status
}

func (m *replicationMonitor) recordFreshnessEvent(status, summary string, details map[string]any) {
	if strings.TrimSpace(status) == "" || m.lastFreshnessState == status {
		return
	}
	_ = db.RecordHAHistory("replication_freshness", status, summary, strings.TrimSpace(m.cfg.HighAvailability.Role), "", details)
	m.lastFreshnessState = status
}

func (m *replicationMonitor) maybeAutoStageSharedPackage(role string, shared SharedReplicationStatus, details map[string]any) (string, error) {
	if details == nil {
		details = map[string]any{}
	}
	if !m.cfg.HighAvailability.AutoStageSharedPackage {
		details["auto_stage_status"] = "disabled"
		return "", nil
	}
	if role != "standby" {
		details["auto_stage_status"] = "not_applicable"
		return "", nil
	}
	if !shared.Present {
		details["auto_stage_status"] = "waiting_shared_package"
		return "", nil
	}

	fingerprint := strings.TrimSpace(shared.ContentFingerprint)
	if fingerprint == "" {
		fingerprint = strings.TrimSpace(shared.PackageChecksum)
	}
	existing, found, err := FindStagedReplicationPackageByContentFingerprint(m.cfg, fingerprint)
	if err != nil {
		details["auto_stage_status"] = "failed"
		return "", fmt.Errorf("check staged package fingerprint: %w", err)
	}
	if found {
		details["auto_stage_status"] = "ready"
		details["auto_stage_stage_id"] = existing.ID
		details["auto_stage_imported_at"] = existing.ImportedAt
		details["auto_stage_imported_source"] = existing.ImportedSource
		details["auto_stage_package_checksum"] = existing.PackageChecksum
		details["auto_stage_content_fingerprint"] = existing.ContentFingerprint
		details["auto_stage_summary"] = existing.Summary
		return fmt.Sprintf("Observed fresh shared HA replication package. Standby auto-stage is ready with package %s.", existing.ID), nil
	}

	packageBytes, err := os.ReadFile(shared.PackagePath)
	if err != nil {
		details["auto_stage_status"] = "failed"
		return "", fmt.Errorf("read shared package for auto-stage: %w", err)
	}
	stage, err := importReplicationPackage(m.cfg, packageBytes, "ha-auto-stage", "shared-auto")
	if err != nil {
		details["auto_stage_status"] = "failed"
		return "", fmt.Errorf("auto-stage shared package: %w", err)
	}
	details["auto_stage_status"] = "staged"
	details["auto_stage_stage_id"] = stage.ID
	details["auto_stage_imported_at"] = stage.ImportedAt
	details["auto_stage_imported_source"] = stage.ImportedSource
	details["auto_stage_package_checksum"] = stage.PackageChecksum
	details["auto_stage_content_fingerprint"] = stage.ContentFingerprint
	details["auto_stage_summary"] = stage.Summary
	return fmt.Sprintf("Observed fresh shared HA replication package. Standby auto-staged package %s.", stage.ID), nil
}

func PublishSharedReplicationPackage(cfg *config.Config) (SharedReplicationStatus, error) {
	if cfg == nil {
		return SharedReplicationStatus{}, errors.New("ha shared replication publish requires a config")
	}
	packageBytes, manifest, err := CreateReplicationPackage(cfg)
	if err != nil {
		return SharedReplicationStatus{}, err
	}

	status := SharedReplicationStatus{
		Present:             true,
		PackagePath:         sharedPackagePath(cfg),
		MetadataPath:        sharedMetadataPath(cfg),
		PublishedAt:         time.Now().UTC().Format(time.RFC3339),
		GeneratedAt:         manifest.GeneratedAt,
		SourceNode:          manifest.SourceNode,
		SourceRole:          manifest.SourceRole,
		SchemaVersion:       manifest.SchemaVersion,
		PackageSizeBytes:    int64(len(packageBytes)),
		PackageChecksum:     checksumBytes(packageBytes),
		ContentFingerprint:  manifest.ContentFingerprint,
		EncryptionStatus:    "unencrypted",
		Signature:           manifest.Signature,
		SignatureAlgorithm:  manifest.SignatureAlgorithm,
		SignatureStatus:     "unsigned",
		NetworkStatePresent: manifest.NetworkStatePath != "",
	}
	if len(replicationEncryptionKey(cfg)) > 0 {
		status.EncryptionStatus = "encrypted"
		status.EncryptionAlgorithm = replicationEncryptionAlgorithm
	}
	if strings.TrimSpace(manifest.Signature) != "" {
		status.SignatureStatus = "signed"
	}

	if err := writeAtomicFile(status.PackagePath, packageBytes, 0640); err != nil {
		return SharedReplicationStatus{}, fmt.Errorf("write shared replication package: %w", err)
	}
	metadataBytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return SharedReplicationStatus{}, fmt.Errorf("marshal shared replication metadata: %w", err)
	}
	if err := writeAtomicFile(status.MetadataPath, metadataBytes, 0644); err != nil {
		return SharedReplicationStatus{}, fmt.Errorf("write shared replication metadata: %w", err)
	}
	return status, nil
}

func LoadSharedReplicationStatus(cfg *config.Config) (SharedReplicationStatus, error) {
	if cfg == nil {
		return SharedReplicationStatus{}, errors.New("ha shared replication status requires a config")
	}
	status := SharedReplicationStatus{
		PackagePath:  sharedPackagePath(cfg),
		MetadataPath: sharedMetadataPath(cfg),
	}

	data, err := os.ReadFile(status.MetadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		return status, fmt.Errorf("read shared replication metadata: %w", err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return status, fmt.Errorf("decode shared replication metadata: %w", err)
	}
	status.Present = true
	status.PackagePath = sharedPackagePath(cfg)
	status.MetadataPath = sharedMetadataPath(cfg)

	info, err := os.Stat(status.PackagePath)
	if err != nil {
		return SharedReplicationStatus{}, fmt.Errorf("stat shared replication package: %w", err)
	}
	if status.PackageSizeBytes == 0 {
		status.PackageSizeBytes = info.Size()
	}
	return status, nil
}

func StageLatestSharedReplicationPackage(cfg *config.Config, importedBy string) (StagedReplicationPackage, error) {
	if cfg == nil {
		return StagedReplicationPackage{}, errors.New("ha shared replication staging requires a config")
	}
	shared, err := LoadSharedReplicationStatus(cfg)
	if err != nil {
		return StagedReplicationPackage{}, err
	}
	if !shared.Present {
		return StagedReplicationPackage{}, errors.New("no shared HA replication package has been published yet")
	}
	packageBytes, err := os.ReadFile(shared.PackagePath)
	if err != nil {
		return StagedReplicationPackage{}, fmt.Errorf("read shared replication package: %w", err)
	}
	return importReplicationPackage(cfg, packageBytes, importedBy, "shared-live")
}

func mergeSharedReplicationDetails(details map[string]any, shared SharedReplicationStatus, cfg *config.Config, observedAt time.Time) {
	if details == nil {
		return
	}
	details["shared_package_present"] = shared.Present
	details["package_path"] = shared.PackagePath
	details["metadata_path"] = shared.MetadataPath
	details["latest_published_at"] = shared.PublishedAt
	details["latest_generated_at"] = shared.GeneratedAt
	details["latest_source_node"] = shared.SourceNode
	details["latest_source_role"] = shared.SourceRole
	details["latest_schema_version"] = shared.SchemaVersion
	details["latest_package_size_bytes"] = shared.PackageSizeBytes
	details["latest_package_checksum"] = shared.PackageChecksum
	details["latest_content_fingerprint"] = shared.ContentFingerprint
	details["latest_encryption_status"] = shared.EncryptionStatus
	details["latest_encryption_algorithm"] = shared.EncryptionAlgorithm
	details["latest_signature_status"] = shared.SignatureStatus
	details["latest_network_state_present"] = shared.NetworkStatePresent
	if shared.PublishedAt == "" {
		return
	}
	publishedAt, err := time.Parse(time.RFC3339, shared.PublishedAt)
	if err != nil {
		details["latest_age_seconds"] = 0
		details["stale"] = true
		details["last_error"] = fmt.Sprintf("parse shared replication published_at: %v", err)
		return
	}
	age := observedAt.Sub(publishedAt)
	if age < 0 {
		age = 0
	}
	details["latest_age_seconds"] = int(age / time.Second)
	details["stale"] = age > effectiveReplicationStaleAfter(cfg)
}

func effectiveReplicationInterval(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.HighAvailability.ReplicationIntervalSeconds <= 0 {
		return defaultReplicationInterval
	}
	return time.Duration(cfg.HighAvailability.ReplicationIntervalSeconds) * time.Second
}

func effectiveReplicationStaleAfter(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.HighAvailability.ReplicationStaleAfterSeconds > 0 {
		return time.Duration(cfg.HighAvailability.ReplicationStaleAfterSeconds) * time.Second
	}
	return effectiveReplicationInterval(cfg) * 3
}

func sharedReplicationRootDir(cfg *config.Config) string {
	return filepath.Join(replicationRootDir(cfg), "live")
}

func sharedPackagePath(cfg *config.Config) string {
	return filepath.Join(sharedReplicationRootDir(cfg), "latest.tar.gz")
}

func sharedMetadataPath(cfg *config.Config) string {
	return filepath.Join(sharedReplicationRootDir(cfg), "latest.json")
}

func checksumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeAtomicFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, perm); err != nil {
		return err
	}
	backupPath := path + ".bak"
	_ = os.Remove(backupPath)
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, backupPath); err != nil {
			_ = os.Remove(tempPath)
			return err
		}
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		if _, statErr := os.Stat(backupPath); statErr == nil {
			_ = os.Rename(backupPath, path)
		}
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}
